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
    pub fn render_into(&self, verifier_writer: &mut impl fmt::Write) -> Result<(), fmt::Error> {
        self.generate_verifier(false, false).render(verifier_writer)
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
        self.generate_verifier(false, true).render(verifier_writer)
    }

    /// Render a trace-enabled `Halo2Verifier.sol` with verifying key embedded and return it as a
    /// `String`.
    pub fn render_trace(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_trace_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` into writers.
    pub fn render_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(true, false)
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
        self.generate_verifier(true, true).render(verifier_writer)?;
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
            let n_inv = fe_to_u256::<Fq>(
                &Fq::from(1u64 << domain.k()).invert().unwrap(),
            );
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

    fn generate_verifier(&self, separate: bool, trace: bool) -> Halo2Verifier {
        let proof_cptr = Ptr::calldata(0x64);

        let vk = self.generate_vk();
        let expected_vk_codehash = separate.then(|| {
            let digest: [u8; 32] = Keccak256::digest(vk.bytes()).into();
            U256::from_be_bytes(digest)
        });
        let vk_len = vk.len();
        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));
        let data = Data::new(&self.meta, &vk, vk_mptr, proof_cptr);

        // Run the codegen-time `construct_intermediate_sets` simulation
        // and bake `num_point_sets` into a local meta clone. This makes
        // `meta.proof_len()` and `meta.batch_open_extra_evals()` report
        // the correct calldata size (which depends on the number of
        // distinct point sets emitted by the multi-prepare PCS).
        let mut meta = self.meta.clone();
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
        // eval inside the block, store its value at scratch slot
        // 0x4400 (which sits between THETA_MPTR area and quotient
        // limb base), and then perform the Horner update at the
        // outer scope. Using mstore/mload here is wasteful but lets
        // us keep the existing `evaluate` contract untouched.
        // Scratch slot for piping each identity's eval out of its
        // inner `{}` block back to the outer Horner accumulator. Must
        // not overlap any other region:
        //   * 0x4340..~0x4540 — QUOTIENT_LIMB_COMMS (4 limbs * 4 words)
        //   * 0x5000..0x5080 — simple-selector accumulator dump (used
        //                       below by the linearization MSM)
        //   * 0x6000+        — scalar_inv modexp scratch
        // We park it at 0x5800 which falls in the 0x5080..0x5fff hole.
        const EVAL_SCRATCH_SLOT: usize = 0x5800;
        let make_block = |lines: Vec<String>, var: String, sel_idx: Option<usize>| -> Vec<String> {
            let mut block = Vec::with_capacity(lines.len() + 6);
            // Inner block: compute the eval and stash it in a scratch slot.
            block.push("{".to_string());
            for l in lines {
                block.push(l);
            }
            block.push(format!(
                "mstore({EVAL_SCRATCH_SLOT:#x}, {var})"
            ));
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
        // dedicated memory slot so the linearization-MSM emitter can
        // pick them up. We park them at consecutive 32-byte slots
        // starting at `0x4400` (well above THETA_MPTR/y/x and below
        // QUOTIENT_LIMB_COMMS_MPTR_BASE = 0x42c0+...).
        // TODO: wire a proper named MPTR via Data instead of hardcoding.
        if !sorted_simple.is_empty() {
            let mut tail = Vec::new();
            for (i, &col) in sorted_simple.iter().enumerate() {
                let off = 0x5000 + i * 0x20;
                tail.push(format!(
                    "mstore({off:#x}, {})",
                    sel_var(col)
                ));
            }
            quotient_eval_numer_computations.push(tail);
        }

        let pcs_computations = self.scheme.computations(&meta, &data);

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
        let lookup_h_plus_acc: usize =
            meta.lookup_chunks.iter().sum::<usize>() + meta.num_lookups;
        let total_advices: usize = user_phases.iter().map(|p| p.num_advices).sum();
        let lookup_helper_chunks_total: usize = meta.lookup_chunks.iter().sum();

        // Compute fixed_comm_mptr before moving vk into the struct.
        let fixed_comm_mptr_byte = (vk_mptr + vk.constants.len()).value().as_usize();

        Halo2Verifier {
            scheme: self.scheme,
            trace,
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
        }
    }

    fn static_working_memory_size(&self, vk: &Halo2VerifyingKey, proof_cptr: Ptr) -> usize {
        let pcs_computation = {
            let mock_vk_mptr = Ptr::memory(0x100000);
            let mock = Data::new(&self.meta, vk, mock_vk_mptr, proof_cptr);
            self.scheme.static_working_memory_size(&self.meta, &mock)
        };

        // The Step 6 transcript model is a streaming Keccak256 buffer at
        // offset 0x40 onward. Peak buffer length is bounded by the
        // pre-squeeze byte count between two challenges; we estimate the
        // worst case as `(absorbed_g1 * 49 + absorbed_scalar * 33 + 64)`
        // words and round up. A generous static lower bound of 0x800
        // bytes (64 words) suffices for the poseidon fixture and small
        // circuits; larger circuits will scale this up.
        let transcript_words: usize = {
            // The streaming Keccak256 buffer at memory `[0..buf_len)`
            // grows monotonically between two challenge squeezes and is
            // reset to 64 bytes after each squeeze, so the actual peak
            // is the longest distance between consecutive squeezes —
            // dominated by the evaluation block (`num_evals` scalars)
            // since none of the user phases interleave more than a
            // dozen G1 reads. We bound it by the absorption cost of
            // *all* G1s (49 bytes each) and *all* scalars (33 bytes
            // each) plus a 64-byte cushion for the post-squeeze seed.
            // This is conservative but always safe.
            let total_g1: usize = self.meta.num_user_advices.iter().sum::<usize>()
                + self.meta.num_lookups
                + self.meta.num_permutation_zs
                + self
                    .meta
                    .lookup_chunks
                    .iter()
                    .sum::<usize>()
                + self.meta.num_lookups
                + self.meta.num_trashcans
                + self.meta.num_quotients
                + 2; // f_com + pi
            // `num_point_sets` is computed only AFTER this function
            // returns (it depends on the codegen-side
            // `construct_intermediate_sets` simulation which itself
            // needs `vk_mptr`), so we approximate it with a generous
            // upper bound — `num_evals` is always at least as large as
            // the number of opening sets, and adding 32 extra slots of
            // headroom guarantees the buffer stays clear of `VK_MPTR`
            // even for circuits with unusual rotation patterns.
            let total_scalar = self.meta.num_evals + self.meta.num_point_sets + 32;
            let bytes = 64 + total_g1 * 49 + total_scalar * 33 + 64;
            bytes.div_ceil(0x20)
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
