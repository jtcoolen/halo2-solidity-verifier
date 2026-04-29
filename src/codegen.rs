use crate::codegen::{
    evaluator::Evaluator,
    template::{Halo2Verifier, Halo2VerifyingKey, UserPhase},
    util::{fe_to_u256, g1_to_u256s, g2_to_u256s, ConstraintSystemMeta, Data, Ptr},
};
// midnight-proofs migration: VerifyingKey is generic over (F, CS), where F
// = midnight_curves::Fq (BLS12-381 scalar) and CS = KZGCommitmentScheme<Bls12>.
// All embedded commitments are now `G1Projective`; we convert them to
// affine before EIP-2537 packing. ParamsKZG carries the SRS in the same
// form as halo2 v0.4 (bare G1/G2 fields), but the public accessors only
// expose `g_lagrange()`, `g2()`, `s_g2()`. The G1 generator is read from
// `G1Affine::generator()` directly.
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve};
use itertools::chain;
use midnight_curves::{Bls12, Fq, G1Affine, G1Projective, G2Affine};
use midnight_proofs::{
    plonk::VerifyingKey,
    poly::{
        kzg::{params::ParamsKZG, KZGCommitmentScheme},
        Rotation,
    },
};
use ruint::aliases::U256;
use sha3::{Digest, Keccak256};
use std::fmt::{self, Debug};

mod evaluator;
mod pcs;
mod template;
pub(crate) mod util;

pub use pcs::BatchOpenScheme;

/// Solidity verifier generator for midnight-proofs (logup + trash + KZG
/// multi-prepare PCS) on BLS12-381 EIP-2537.
///
/// **Migration status (Steps 1-3, 2026-04-26)**: this struct now binds to
/// `midnight_proofs::plonk::VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>`
/// and `ParamsKZG<Bls12>` instead of halo2-proofs v0.4 + halo2curves
/// `bls12381::Bls12381`. The generated Yul still reflects the old halo2
/// schema (no logup helpers / trashcans / multi-prepare PCS); Steps 4-9
/// of MIGRATION.md track the Yul rewrite.
#[derive(Debug)]
pub struct SolidityGenerator<'a> {
    params: &'a ParamsKZG<Bls12>,
    vk: &'a VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    scheme: BatchOpenScheme,
    num_instances: usize,
    /// Number of instance columns whose values are *committed* in the
    /// proof transcript rather than read directly from `instances` and
    /// Lagrange-interpolated by the verifier. Defaults to 0 for the
    /// poseidon example.
    num_committed_instances: usize,
    acc_encoding: Option<AccumulatorEncoding>,
    meta: ConstraintSystemMeta,
}

/// KZG accumulator encoding information.
#[derive(Clone, Copy, Debug)]
pub struct AccumulatorEncoding {
    /// Offset of accumulator limbs in instances.
    pub offset: usize,
    /// Number of limbs per base field element.
    pub num_limbs: usize,
    /// Number of bits per limb.
    pub num_limb_bits: usize,
}

impl AccumulatorEncoding {
    /// Return a new `AccumulatorEncoding`.
    pub fn new(offset: usize, num_limbs: usize, num_limb_bits: usize) -> Self {
        Self {
            offset,
            num_limbs,
            num_limb_bits,
        }
    }
}

impl<'a> SolidityGenerator<'a> {
    /// Return a new `SolidityGenerator`.
    pub fn new(
        params: &'a ParamsKZG<Bls12>,
        vk: &'a VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
        scheme: BatchOpenScheme,
        num_instances: usize,
    ) -> Self {
        assert_ne!(vk.cs().num_advice_columns(), 0);
        // midnight-proofs ZkStdLib always allocates two instance columns
        // (one committed, one non-committed), so the v0.4 `<= 1`
        // tightness no longer applies. We accept up to 2 here and let
        // `set_num_committed_instances` handle the split.
        assert!(
            vk.cs().num_instance_columns() <= 2,
            "More than two instance columns is not yet implemented"
        );
        assert!(
            !vk.cs()
                .instance_queries()
                .iter()
                .any(|(_, rotation)| *rotation != Rotation::cur()),
            "Rotated query to instance column is not yet implemented"
        );

        let num_committed_instances = 0;
        let meta = ConstraintSystemMeta::new(vk.cs(), num_committed_instances);

        Self {
            params,
            vk,
            scheme,
            num_instances,
            num_committed_instances,
            acc_encoding: None,
            meta,
        }
    }

    /// Set `AccumulatorEncoding`.
    pub fn set_acc_encoding(mut self, acc_encoding: Option<AccumulatorEncoding>) -> Self {
        self.acc_encoding = acc_encoding;
        self
    }

    /// Number of instance columns committed to in the transcript (vs read
    /// from `instances` and Lagrange-interpolated locally). Surfacing the
    /// value here so that downstream callers (drivers, debugging
    /// examples) can configure committed-instance proofs without having
    /// to plumb through a constructor argument.
    pub fn set_num_committed_instances(mut self, n: usize) -> Self {
        self.num_committed_instances = n;
        self.meta = ConstraintSystemMeta::new(self.vk.cs(), n);
        self
    }
}

impl<'a> SolidityGenerator<'a> {
    /// Render `Halo2Verifier.sol` with verifying key embedded into writer.
    ///
    /// The default render path emits trace/log branches when the crate
    /// is compiled with `--features solidity-trace`, and LOG1 gas
    /// checkpoints when compiled with `--features
    /// solidity-gas-checkpoints`.
    pub fn render_into(&self, verifier_writer: &mut impl fmt::Write) -> Result<(), fmt::Error> {
        self.generate_verifier(
            false,
            crate::SOLIDITY_TRACE_ENABLED,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
        )
        .render(verifier_writer)
    }

    /// Render `Halo2Verifier.sol` with verifying key embedded and return it as `String`.
    pub fn render(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render a trace-enabled `Halo2Verifier.sol` with verifying key embedded into writer.
    pub fn render_trace_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(false, true, crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED)
            .render(verifier_writer)
    }

    /// Render a trace-enabled `Halo2Verifier.sol` with verifying key embedded and return it as a
    /// `String`.
    pub fn render_trace(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_trace_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` (with VK
    /// embedded) into writer. Emits LOG1 events at section boundaries
    /// regardless of the `solidity-gas-checkpoints` feature flag.
    pub fn render_with_gas_checkpoints_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(false, crate::SOLIDITY_TRACE_ENABLED, true)
            .render(verifier_writer)
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` (with VK
    /// embedded) and return it as `String`.
    pub fn render_with_gas_checkpoints(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_with_gas_checkpoints_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` into writers.
    ///
    /// The default render path emits trace/log branches when the crate
    /// is compiled with `--features solidity-trace`, and LOG1 gas
    /// checkpoints when compiled with `--features
    /// solidity-gas-checkpoints`.
    pub fn render_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            true,
            crate::SOLIDITY_TRACE_ENABLED,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
        )
        .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        Ok(())
    }

    /// Render `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` and return them as `String`.
    pub fn render_separately(&self) -> Result<(String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        self.render_separately_into(&mut verifier_output, &mut vk_output)?;
        Ok((verifier_output, vk_output))
    }

    /// Render a trace-enabled `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` into writers.
    pub fn render_trace_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(true, true, crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED)
            .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        Ok(())
    }

    /// Render a trace-enabled `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` and return them as
    /// `String`s.
    pub fn render_trace_separately(&self) -> Result<(String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        self.render_trace_separately_into(&mut verifier_output, &mut vk_output)?;
        Ok((verifier_output, vk_output))
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` and
    /// `Halo2VerifyingKey.sol` into writers. Emits LOG1 events at
    /// section boundaries regardless of the
    /// `solidity-gas-checkpoints` feature flag.
    pub fn render_with_gas_checkpoints_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(true, crate::SOLIDITY_TRACE_ENABLED, true)
            .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        Ok(())
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` and
    /// `Halo2VerifyingKey.sol` and return them as `String`s.
    pub fn render_with_gas_checkpoints_separately(&self) -> Result<(String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        self.render_with_gas_checkpoints_separately_into(&mut verifier_output, &mut vk_output)?;
        Ok((verifier_output, vk_output))
    }

    fn generate_vk(&self) -> Halo2VerifyingKey {
        let mut constants: Vec<(&'static str, U256)> = Vec::new();
        {
            let domain = self.vk.get_domain();
            // BLS12-381 scalar Fq is 32 bytes wide (256 bits) so the same
            // little-endian-to-u256 conversion that worked for BN254 Fr
            // also works here: the verifier reads each scalar from
            // calldata into a single 32-byte word.
            let vk_digest = fe_to_u256::<Fq>(&self.vk.transcript_repr());
            let num_instances = U256::from(self.num_instances);
            let k = U256::from(domain.k());
            let n_inv = fe_to_u256::<Fq>(&Fq::from(1u64 << domain.k()).invert().unwrap());
            let omega = fe_to_u256::<Fq>(&domain.get_omega());
            let omega_inv = fe_to_u256::<Fq>(&domain.get_omega_inv());
            let omega_inv_to_l = {
                let l = self.meta.rotation_last.unsigned_abs() as u64;
                fe_to_u256::<Fq>(&domain.get_omega_inv().pow_vartime([l]))
            };
            let has_accumulator = U256::from(self.acc_encoding.is_some() as usize);
            let acc_offset = self
                .acc_encoding
                .map(|acc_encoding| U256::from(acc_encoding.offset))
                .unwrap_or_default();
            let num_acc_limbs = self
                .acc_encoding
                .map(|acc_encoding| U256::from(acc_encoding.num_limbs))
                .unwrap_or_default();
            let num_acc_limb_bits = self
                .acc_encoding
                .map(|acc_encoding| U256::from(acc_encoding.num_limb_bits))
                .unwrap_or_default();
            // EIP-2537 padded encodings come from `g1_to_u256s` / `g2_to_u256s`
            // (4 / 8 u256 words respectively). We cannot read `params.g[0]`
            // directly (the field is crate-private in midnight-proofs), so
            // we use the canonical BLS12-381 generator.
            let g1_pt: G1Affine = G1Affine::generator();
            let g2_pt: G2Affine = self.params.g2().to_affine();
            let neg_s_g2_pt: G2Affine = (-self.params.s_g2()).to_affine();
            let g1 = g1_to_u256s(&g1_pt);
            let g2 = g2_to_u256s(&g2_pt);
            let neg_s_g2 = g2_to_u256s(&neg_s_g2_pt);

            constants.extend([
                ("vk_digest", vk_digest),
                ("num_instances", num_instances),
                ("k", k),
                ("n_inv", n_inv),
                ("omega", omega),
                ("omega_inv", omega_inv),
                ("omega_inv_to_l", omega_inv_to_l),
                ("has_accumulator", has_accumulator),
                ("acc_offset", acc_offset),
                ("num_acc_limbs", num_acc_limbs),
                ("num_acc_limb_bits", num_acc_limb_bits),
            ]);
            constants.extend([
                ("g1_x_hi", g1[0]),
                ("g1_x_lo", g1[1]),
                ("g1_y_hi", g1[2]),
                ("g1_y_lo", g1[3]),
            ]);
            constants.extend([
                ("g2_x_c0_hi", g2[0]),
                ("g2_x_c0_lo", g2[1]),
                ("g2_x_c1_hi", g2[2]),
                ("g2_x_c1_lo", g2[3]),
                ("g2_y_c0_hi", g2[4]),
                ("g2_y_c0_lo", g2[5]),
                ("g2_y_c1_hi", g2[6]),
                ("g2_y_c1_lo", g2[7]),
            ]);
            constants.extend([
                ("neg_s_g2_x_c0_hi", neg_s_g2[0]),
                ("neg_s_g2_x_c0_lo", neg_s_g2[1]),
                ("neg_s_g2_x_c1_hi", neg_s_g2[2]),
                ("neg_s_g2_x_c1_lo", neg_s_g2[3]),
                ("neg_s_g2_y_c0_hi", neg_s_g2[4]),
                ("neg_s_g2_y_c0_lo", neg_s_g2[5]),
                ("neg_s_g2_y_c1_hi", neg_s_g2[6]),
                ("neg_s_g2_y_c1_lo", neg_s_g2[7]),
            ]);
        }

        // Convert each commitment from G1Projective to G1Affine before
        // EIP-2537 packing.
        let to_affine = |g: &G1Projective| -> G1Affine { g.to_affine() };
        let fixed_comms = chain![self.vk.fixed_commitments()]
            .map(to_affine)
            .map(g1_to_u256s)
            .map(|[a, b, c, d]| (a, b, c, d))
            .collect();
        let permutation_comms = chain![self.vk.permutation().commitments()]
            .map(to_affine)
            .map(g1_to_u256s)
            .map(|[a, b, c, d]| (a, b, c, d))
            .collect();
        Halo2VerifyingKey {
            constants,
            fixed_comms,
            permutation_comms,
        }
    }

    fn generate_verifier(
        &self,
        separate: bool,
        trace: bool,
        gas_checkpoints: bool,
    ) -> Halo2Verifier {
        let proof_cptr = Ptr::calldata(0x64);

        let vk = self.generate_vk();
        let expected_vk_codehash = separate.then(|| {
            let digest: [u8; 32] = Keccak256::digest(vk.bytes()).into();
            U256::from_be_bytes(digest)
        });
        let vk_len = vk.len();
        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));

        // ------------------------------------------------------------------
        // Phase 3 / fewer-point-sets two-pass `Data` construction.
        //
        // Pass 1: build `Data` against the *raw* meta (no dummy evals).
        //   This gives us the raw query list whose commitment identity
        //   structure feeds `compute_dummy_queries`.
        //
        // Pass 2: bump meta.num_evals by the dummy count (so the
        //   memory layout - REVERSED_EVALS_MPTR buffer + downstream
        //   comms_mptr_base - grows to fit the dummies), rebuild Data,
        //   and populate the dummy eval Words.
        //
        // When the `fewer-point-sets` Cargo feature is OFF, the dummy
        // count is forced to zero; pass 2 collapses to "rebuild Data
        // against unchanged meta", and the result is byte-identical
        // to the pre-Phase-3 single-pass path.
        // ------------------------------------------------------------------
        let raw_data = Data::new(&self.meta, &vk, vk_mptr, proof_cptr);
        let mut meta = self.meta.clone();
        let n_dummy = if cfg!(feature = "fewer-point-sets") {
            BatchOpenScheme::num_dummy_queries(&meta, &raw_data)
        } else {
            0
        };
        let main_evals = meta.num_evals;
        meta.set_num_dummy_evals(n_dummy);
        let mut data = Data::new(&meta, &vk, vk_mptr, proof_cptr);
        if n_dummy > 0 {
            data.set_dummy_eval_words(main_evals, n_dummy);
        }

        meta.set_num_point_sets(BatchOpenScheme::num_point_sets(&meta, &data));

        let evaluator = Evaluator::new(self.vk.cs(), &meta, &data);

        // Build the merged identity list, tagging each item with its
        // simple-selector fixed column (if any) so we can route gate
        // contributions to the correct accumulator. Permutation,
        // lookup, and trash identities are always `None`-bucket.
        let gate_items = evaluator.gate_computations_tagged();
        let perm_items = evaluator.permutation_computations();
        let lookup_items = evaluator.lookup_computations();
        let trash_items = evaluator.trashcan_computations();

        let mut sorted_simple: Vec<usize> = meta.simple_selector_cols.iter().copied().collect();
        sorted_simple.sort_unstable();
        let sel_var = |col: usize| format!("sel_acc_{col}");

        let lookup_helper_chunks_total: usize = meta.lookup_chunks.iter().sum();
        let total_advices: usize = meta.num_user_advices.iter().sum();
        let comm_g1_count = total_advices
            + meta.num_lookups
            + meta.num_permutation_zs
            + lookup_helper_chunks_total
            + meta.num_lookups
            + meta.num_trashcans
            + meta.num_quotients;
        let after_comms = data.comms_mptr_base.value().as_usize() + comm_g1_count * 0x80;
        let selector_acc_mptr = after_comms.next_multiple_of(0x20);
        let batch_invert_scratch_mptr = selector_acc_mptr;

        let mut quotient_eval_numer_computations: Vec<Vec<String>> = Vec::new();

        // Step 0: declare and zero-init all accumulators.
        {
            let mut init_lines = Vec::new();
            init_lines.push("let quotient_eval_numer := 0".to_string());
            for &col in &sorted_simple {
                init_lines.push(format!("let {} := 0", sel_var(col)));
            }
            quotient_eval_numer_computations.push(init_lines);
        }

        // Helper that emits a self-contained Horner-fold step for one
        // identity. The eval is computed inside its own `{}` scope
        // (so per-block `v0..vN` locals don't collide with siblings)
        // and exported via a small per-step shim. We compute the
        // eval inside the block, store its value at scratch, and then
        // perform the Horner update at the outer scope. Using
        // mstore/mload here is wasteful but lets us keep the existing
        // `evaluate` contract untouched.
        // Scratch slot for piping each identity's eval out of its
        // inner `{}` block back to the outer Horner accumulator. Must
        // not overlap the generated verifier's VK, challenge, proof
        // commitment, simple-selector, or scalar-inversion regions.
        const EVAL_SCRATCH_SLOT: usize = 0x9000;
        let make_block = |lines: Vec<String>, var: String, sel_idx: Option<usize>| -> Vec<String> {
            let mut block = Vec::with_capacity(lines.len() + 6);
            // Inner block: compute the eval and stash it in a scratch slot.
            block.push("{".to_string());
            for l in lines {
                block.push(l);
            }
            block.push(format!("mstore({EVAL_SCRATCH_SLOT:#x}, {var})"));
            block.push("}".to_string());
            // Outer Horner update (re-loads from the scratch slot).
            block.push("quotient_eval_numer := mulmod(quotient_eval_numer, y, r)".to_string());
            for &col in &sorted_simple {
                block.push(format!(
                    "{name} := mulmod({name}, y, r)",
                    name = sel_var(col)
                ));
            }
            let target = match sel_idx {
                Some(col) => sel_var(col),
                None => "quotient_eval_numer".to_string(),
            };
            block.push(format!(
                "{target} := addmod({target}, mload({EVAL_SCRATCH_SLOT:#x}), r)"
            ));
            block
        };

        for (lines, var, sel_idx) in gate_items {
            quotient_eval_numer_computations.push(make_block(lines, var, sel_idx));
        }
        for (lines, var) in perm_items {
            quotient_eval_numer_computations.push(make_block(lines, var, None));
        }
        for (lines, var) in lookup_items {
            quotient_eval_numer_computations.push(make_block(lines, var, None));
        }
        for (lines, var) in trash_items {
            quotient_eval_numer_computations.push(make_block(lines, var, None));
        }

        // Tail block: store each simple-selector accumulator at a
        // dedicated scratch slot so the linearization-MSM emitter can
        // pick them up. The base is placed after the decompressed proof
        // commitments; later PCS scratch tables may reuse it after the
        // linearization MSM has consumed these values.
        if !sorted_simple.is_empty() {
            let mut tail = Vec::new();
            for (i, &col) in sorted_simple.iter().enumerate() {
                tail.push(format!(
                    "mstore(add(SELECTOR_ACC_MPTR, {:#x}), {})",
                    i * 0x20,
                    sel_var(col)
                ));
            }
            quotient_eval_numer_computations.push(tail);
        }

        let pcs_computations =
            self.scheme
                .computations(&meta, &data, cfg!(feature = "truncated-challenges"));

        // Per-user-phase breakdown (advices + user challenges).
        let mut challenge_offset = 0usize;
        let user_phases: Vec<UserPhase> = meta
            .num_user_advices
            .iter()
            .zip(meta.num_user_challenges.iter())
            .map(|(&n_a, &n_c)| {
                let phase = UserPhase {
                    num_advices: n_a,
                    num_challenges: n_c,
                    challenge_offset,
                };
                challenge_offset += n_c;
                phase
            })
            .collect();
        let num_user_challenges: usize = meta.num_user_challenges.iter().sum();
        let lookup_h_plus_acc: usize = meta.lookup_chunks.iter().sum::<usize>() + meta.num_lookups;

        // Compute VK / accumulator layout helpers before moving vk into
        // the template struct.
        let fixed_comm_mptr_byte = (vk_mptr + vk.constants.len()).value().as_usize();
        let permutation_comm_mptr_byte = fixed_comm_mptr_byte + vk.fixed_comms.len() * 0x80;
        let g1_base_mptr_byte = (vk_mptr + 11).value().as_usize();

        let mut acc_fixed_bases: Vec<(String, usize, bool)> = Vec::new();
        if let Some(acc_encoding) = self.acc_encoding {
            let limbs_per_instance = (254 / acc_encoding.num_limb_bits).max(1);
            let coord_words = acc_encoding.num_limbs.div_ceil(limbs_per_instance);
            let point_and_scalar_words = 4 * coord_words + 2;
            let fixed_scalar_count = self
                .num_instances
                .checked_sub(acc_encoding.offset + point_and_scalar_words)
                .expect("accumulator public input exceeds num_instances");
            // A fully-collapsed public accumulator has no fixed-base scalar
            // tail: just (lhs point, lhs scalar=1, rhs point, rhs scalar=1).
            // Older partially-collapsed accumulators still expose the RHS
            // fixed scalars for -G, fixed commitments, and permutation
            // commitments in BTreeMap key order.
            if fixed_scalar_count != 0 {
                let num_perm_bases = vk.permutation_comms.len();
                let num_fixed_bases = fixed_scalar_count
                    .checked_sub(1 + num_perm_bases)
                    .expect("accumulator fixed scalar count is smaller than -G + permutations");

                acc_fixed_bases.push(("-G".to_string(), g1_base_mptr_byte, true));
                for i in 0..num_fixed_bases {
                    acc_fixed_bases.push((
                        format!("self_vk_fixed_com_{i}"),
                        fixed_comm_mptr_byte + i * 0x80,
                        false,
                    ));
                }
                for i in 0..num_perm_bases {
                    acc_fixed_bases.push((
                        format!("self_vk_perm_com_{i}"),
                        permutation_comm_mptr_byte + i * 0x80,
                        false,
                    ));
                }
            }
        }
        acc_fixed_bases.sort_by(|a, b| a.0.cmp(&b.0));
        let acc_fixed_bases: Vec<(usize, bool)> = acc_fixed_bases
            .into_iter()
            .map(|(_, mptr, negate)| (mptr, negate))
            .collect();

        let acc_msm_scratch = after_comms.max(0x7000).next_multiple_of(0x20);

        Halo2Verifier {
            scheme: self.scheme,
            trace,
            gas_checkpoints,
            embedded_vk: (!separate).then_some(vk),
            expected_vk_codehash,
            vk_len,
            vk_mptr,
            num_neg_lagranges: meta.rotation_last.unsigned_abs() as usize,
            user_phases,
            num_user_challenges,
            num_lookups: meta.num_lookups,
            num_permutation_zs: meta.num_permutation_zs,
            lookup_h_plus_acc,
            num_trashcans: meta.num_trashcans,
            num_quotients: meta.num_quotients,
            num_evals: meta.num_evals,
            num_point_sets: meta.num_point_sets,
            total_advices,
            lookup_helper_chunks_total,
            lookup_chunks: meta.lookup_chunks.clone(),
            comms_mptr_base: data.comms_mptr_base,
            reversed_evals_mptr: data.reversed_evals_mptr,
            selector_acc_mptr,
            batch_invert_scratch_mptr,
            proof_cptr,
            num_instance_cptr: proof_cptr.value().as_usize() + meta.proof_len(self.scheme),
            instance_cptr: proof_cptr.value().as_usize() + meta.proof_len(self.scheme) + 0x20,
            quotient_comm_cptr: data.quotient_comm_cptr,
            proof_len: meta.proof_len(self.scheme),
            challenge_mptr: data.challenge_mptr,
            theta_mptr: data.theta_mptr,
            quotient_eval_numer_computations,
            pcs_computations,
            simple_selector_cols: sorted_simple.clone(),
            fixed_comm_mptr: fixed_comm_mptr_byte,
            truncated_challenges: cfg!(feature = "truncated-challenges"),
            fewer_point_sets: cfg!(feature = "fewer-point-sets"),
            num_dummy_evals: meta.num_dummy_evals,
            acc_fixed_bases,
            acc_msm_scratch,
        }
    }

    /// Repack a midnight-proofs proof from the on-the-wire compressed
    /// form (each G1 = 48 bytes ZCash compressed) into the EIP-2537
    /// padded form (each G1 = 4 × 32-byte BE words) the rendered
    /// Solidity verifier reads from calldata.
    ///
    /// This is the off-chain repack step the verifier expects: the
    /// EVM does **not** run the modexp-based BLS12-381 decompression
    /// at every G1 site (which would cost ~80 kg / commitment); the
    /// caller pays that cost off-chain once.
    ///
    /// The walk is driven entirely by the bound `&self.vk` /
    /// `&self.meta` (so it correctly handles the non-trivial proof
    /// shapes the codegen produces: per-phase advices, lookup
    /// multiplicities + chunked helpers + accumulators, perm Z
    /// products, trashcans, quotient limbs, eval block, dummy evals
    /// from `fewer-point-sets`, f_com, q_evals per point set, pi).
    ///
    /// # Panics
    /// - Panics if any G1 in the input fails to decompress (off-curve
    ///   / bad subgroup / malformed compressed encoding).
    /// - Panics if `compressed` is shorter than the schema requires.
    pub fn repack_compressed_proof(&self, compressed: &[u8]) -> Vec<u8> {
        use group::prime::PrimeCurveAffine;
        use group::GroupEncoding;

        // ----------------------------------------------------------
        // Re-run the same num_dummy_evals / num_point_sets simulation
        // `generate_verifier` runs, so the repack walks the **exact**
        // proof layout the rendered Solidity body reads.
        // ----------------------------------------------------------
        let proof_cptr = Ptr::calldata(0x64);
        let vk = self.generate_vk();
        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));

        let raw_data = Data::new(&self.meta, &vk, vk_mptr, proof_cptr);
        let mut meta = self.meta.clone();
        let n_dummy = if cfg!(feature = "fewer-point-sets") {
            BatchOpenScheme::num_dummy_queries(&meta, &raw_data)
        } else {
            0
        };
        let main_evals = meta.num_evals;
        meta.set_num_dummy_evals(n_dummy);
        let mut data = Data::new(&meta, &vk, vk_mptr, proof_cptr);
        if n_dummy > 0 {
            data.set_dummy_eval_words(main_evals, n_dummy);
        }
        let n_point_sets = BatchOpenScheme::num_point_sets(&meta, &data);

        // ----------------------------------------------------------
        // Build the prefix-G1 group counts in transcript order.
        // (Mirrors the ordering used by the codegen and tested in
        // `tests/poseidon_fixture.rs`.)
        // ----------------------------------------------------------
        let cs = self.vk.cs();
        let perm_chunks = cs.permutation().columns.chunks(cs.degree() - 2).count();
        let mut g1_groups: Vec<usize> = Vec::new();

        // User phases: each phase contributes its advice columns.
        let advice_phase = cs.advice_column_phase();
        let max_phase = *advice_phase.iter().max().unwrap_or(&0);
        for phase in 0..=max_phase {
            let n = advice_phase.iter().filter(|p| **p == phase).count();
            if n != 0 {
                g1_groups.push(n);
            }
        }
        if !cs.lookups().is_empty() {
            g1_groups.push(cs.lookups().len());
        }
        if perm_chunks != 0 {
            g1_groups.push(perm_chunks);
        }
        for l in cs.lookups().iter() {
            let nb_chunks = l.chunk_by_degree(cs.degree()).num_chunks();
            g1_groups.push(nb_chunks);
            g1_groups.push(1);
        }
        if !cs.trashcans().is_empty() {
            g1_groups.push(cs.trashcans().len());
        }
        let num_quotients = cs.degree() - 1;
        g1_groups.push(num_quotients);
        let prefix_g1_count: usize = g1_groups.iter().sum();

        let total_evals = meta.num_evals; // already includes dummy evals
        let expected_compressed_len =
            prefix_g1_count * 48 + total_evals * 32 + 48 + n_point_sets * 32 + 48;
        assert_eq!(
            compressed.len(),
            expected_compressed_len,
            "compressed proof length mismatch: expected {expected_compressed_len} bytes (prefix_g1={prefix_g1_count}, num_evals={total_evals}, num_point_sets={n_point_sets}, +f_com+pi), got {}",
            compressed.len()
        );

        let mut out: Vec<u8> = Vec::with_capacity(
            prefix_g1_count * 128 + total_evals * 32 + 128 + n_point_sets * 32 + 128,
        );
        let mut cursor = 0usize;
        let push_g1 = |cursor: &mut usize, out: &mut Vec<u8>| {
            let mut comp = <G1Affine as GroupEncoding>::Repr::default();
            comp.as_mut()
                .copy_from_slice(&compressed[*cursor..*cursor + 48]);
            let cur = *cursor;
            *cursor += 48;
            let pt: G1Affine = Option::from(<G1Affine as GroupEncoding>::from_bytes(&comp))
                .unwrap_or_else(|| {
                    panic!(
                        "decompress failed at compressed[{cur}..{}]: bytes = 0x{}",
                        cur + 48,
                        hex::encode(comp.as_ref())
                    )
                });
            if bool::from(pt.is_identity()) {
                out.extend_from_slice(&[0u8; 128]);
                return;
            }
            let x_be = pt.x().to_bytes_be();
            let y_be = pt.y().to_bytes_be();
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&x_be[0..16]);
            out.extend_from_slice(&x_be[16..48]);
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&y_be[0..16]);
            out.extend_from_slice(&y_be[16..48]);
        };
        for &n in &g1_groups {
            for _ in 0..n {
                push_g1(&mut cursor, &mut out);
            }
        }
        // evals (Fr 32-byte LE) - pass through (incl. dummy slots).
        out.extend_from_slice(&compressed[cursor..cursor + total_evals * 32]);
        cursor += total_evals * 32;
        // f_com
        push_g1(&mut cursor, &mut out);
        // q_evals
        out.extend_from_slice(&compressed[cursor..cursor + n_point_sets * 32]);
        cursor += n_point_sets * 32;
        // pi
        push_g1(&mut cursor, &mut out);
        assert_eq!(
            cursor,
            compressed.len(),
            "compressed proof not fully consumed"
        );
        out
    }

    fn static_working_memory_size(&self, vk: &Halo2VerifyingKey, proof_cptr: Ptr) -> usize {
        let pcs_computation = {
            let mock_vk_mptr = Ptr::memory(0x100000);
            let mock = Data::new(&self.meta, vk, mock_vk_mptr, proof_cptr);
            self.scheme.static_working_memory_size(&self.meta, &mock)
        };

        // The Step 6 transcript model is a streaming Keccak256 buffer at
        // memory `[0..buf_len)`. The buffer monotonically grows between
        // two challenge squeezes and is reset to 64 bytes after each
        // squeeze, so the *peak* buf_len equals the longest absorb run
        // between two consecutive squeezes. For midnight-proofs verifiers
        // the dominating run is whichever of the following is largest:
        //   (a) initial absorbs (vk_digest + committed_pi + num_instances
        //       + all instance scalars + all phase-1 advices) before the
        //       first user-phase challenge squeeze (`theta`), or
        //   (b) the evaluation block (all `num_evals` scalars) absorbed
        //       after the `y` squeeze and before the next squeeze.
        //
        // We compute a per-run conservative upper bound for each and
        // take the max, then add the 64-byte post-squeeze seed cushion.
        //
        // Per-absorb costs in the patched (uncompressed-G1) emitter:
        //   - PREFIX_COMMON || word        = 33 bytes  (`common_word`)
        //   - PREFIX_COMMON || 128 bytes   = 129 bytes (`common_uncompressed_g1`)
        //   - PREFIX_CHALLENGE || forks    = 64 bytes  (post-squeeze seed)
        // The earlier (compressed-G1) emitter used 49 bytes per G1; the
        // 49 used here is wrong now that the verifier hashes the 128-byte
        // EIP-2537 padded form, so we use 129. Mismatching the bound
        // causes the keccak buffer to overrun `VK_MPTR` mid-verify and
        // silently corrupt `K_MPTR`, `OMEGA_MPTR`, etc., producing a
        // multi-billion-gas spin in the Lagrange block.
        let transcript_words: usize = {
            // (a) initial run: vk_digest (33) + committed_pi (129)
            //     + num_instances scalar (33) + num_instances * 33
            //     + phase_1_advices * 129 + 64 cushion.
            let phase_1_advices = self.meta.num_user_advices.first().copied().unwrap_or(0);
            let initial_run = 33                      // vk_digest
                + 129                                 // committed_pi
                + 33                                  // num_instances scalar
                + self.num_instances * 33             // committed instances
                + phase_1_advices * 129               // phase-1 advices
                + 64; // post-squeeze seed cushion

            // (b) eval-block run: quotient_limbs (Keccak common_uncompressed
            //     of each quotient G1) + num_evals scalars + num_point_sets
            //     scalars + 64 cushion.
            let eval_run = self.meta.num_quotients * 129
                + self.meta.num_evals * 33
                + self.meta.num_point_sets * 33
                + 64;

            // Catch-all: any other phase. We bound it by every G1 + every
            // scalar absorbed across the whole transcript; this is a
            // strict overestimate but cheap and finite.
            let total_g1: usize = self.meta.num_user_advices.iter().sum::<usize>()
                + self.meta.num_lookups
                + self.meta.num_permutation_zs
                + self.meta.lookup_chunks.iter().sum::<usize>()
                + self.meta.num_lookups
                + self.meta.num_trashcans
                + self.meta.num_quotients
                + 2; // f_com + pi
            let total_scalar = self.meta.num_evals + self.meta.num_point_sets + 32;
            let total_run = 64 + total_g1 * 129 + total_scalar * 33 + 64;

            let peak = initial_run.max(eval_run).max(total_run);
            peak.div_ceil(0x20)
        };

        itertools::max([
            // Transcript buffer (streaming Keccak256). The buffer must
            // fit *below* `VK_MPTR` because every `mload(VK_MPTR + ...)`
            // assumes the VK contract bytes copied via `extcodecopy`
            // remain intact, and the buffer would otherwise overwrite
            // them as it grows past the start of the VK area.
            transcript_words,
            // PCS computation scratch
            pcs_computation,
            // Pairing: 2 G1 points (4 words each) + 2 G2 points (8 words each)
            // = 24 words, plus 1-word output buffer.
            25,
            // Modexp scratch for decompression (240 bytes input + 48
            // bytes output = 9 words; we round up to 16 to leave room
            // for separate scratch areas).
            16,
        ])
        .unwrap()
            * 0x20
    }
}

/// Encode a midnight-proofs proof + instances into Halo2Verifier calldata.
///
/// In the midnight-proofs schema each G1 commitment in the proof byte
/// stream is the **48-byte compressed** BLS12-381 form. The Solidity
/// verifier decompresses internally and feeds EIP-2537 the padded
/// uncompressed form, so the calldata stays a flat byte concatenation
/// of `(compressed-G1 | scalars | compressed-G1 | scalars | ...)` with
/// the exact layout `parse_trace` consumes. This helper just wraps
/// `encode_calldata` so callers don't have to import `evm`.
pub fn encode_calldata_bls_padded(
    _generator: &SolidityGenerator<'_>,
    proof: &[u8],
    instances: &[Fq],
) -> Vec<u8> {
    crate::evm::encode_calldata(proof, instances)
}
