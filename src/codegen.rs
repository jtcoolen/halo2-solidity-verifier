use crate::codegen::{
    evaluator::Evaluator,
    template::{Halo2Verifier, Halo2VerifyingKey},
    util::{fe_to_u256, g1_to_u256s, g2_to_u256s, ConstraintSystemMeta, Data, Ptr},
};

pub use crate::codegen::template::BenchToggles;
// halo2 v0.4 transitively pulls halo2curves 0.7, which ships native
// BLS12-381 support including `bls12381::Bls12381 : pairing::Engine`. We
// take the BLS12-381 prover types directly so the proofs and VK embed real
// BLS curve points and the EIP-2537 pairing precompile actually accepts
// them. Fr is 32 bytes (same as BN254 Fr); Fq is 48 bytes per coordinate
// (split per EIP-2537 into 16-byte hi + 32-byte lo halves).
use halo2_proofs::{
    halo2curves::{bls12381 as bls12_381, ff::Field},
    plonk::VerifyingKey,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG, Rotation},
};
use itertools::chain;
use ruint::aliases::U256;
use sha3::{Digest, Keccak256};
use std::fmt::{self, Debug};

mod evaluator;
mod pcs;
mod template;
pub(crate) mod util;

pub use pcs::BatchOpenScheme;

/// Solidity verifier generator for halo2 proofs with KZG polynomial commitment
/// scheme. Emits Solidity that uses the BLS12-381 EIP-2537 precompiles.
///
/// As of Stage C-final, this takes a `ParamsKZG<bls12381::Bls12381>` and
/// `VerifyingKey<bls12381::G1Affine>` directly. The embedded G1/G2 commitments
/// are real BLS12-381 curve points laid out in the EIP-2537 padded format
/// (4 u256 words per G1, 8 per G2). The Solidity verifier therefore feeds
/// well-formed inputs to the 0x0b/0x0c/0x0f precompiles and the pairing
/// check returns 1 for valid proofs.
#[derive(Debug)]
pub struct SolidityGenerator<'a> {
    params: &'a ParamsKZG<bls12_381::Bls12381>,
    vk: &'a VerifyingKey<bls12_381::G1Affine>,
    scheme: BatchOpenScheme,
    num_instances: usize,
    acc_encoding: Option<AccumulatorEncoding>,
    meta: ConstraintSystemMeta,
}

/// KZG accumulator encoding information.
/// Limbs of each field element are assumed to be least significant limb first.
///
/// Given instances and `AccumulatorEncoding`, the accumulator is reconstructed
/// the same way as the BN254 version, except both `acc_lhs` and `acc_rhs` are
/// `bls12_381::G1Affine` and the base field is the 381-bit `bls12_381::Fq`.
/// Each base-field element decomposes into `num_limbs` little-endian limbs of
/// `num_limb_bits` bits, so for a typical `num_limbs = 4`, `num_limb_bits = 96`
/// you need `4 * 4 * 4 = 64` instance slots (4 coordinates x 4 limbs each, but
/// then x4 because each limb is itself padded into a u256 from the instance
/// scalar field). The Solidity verifier reconstructs the (hi, lo) split
/// expected by EIP-2537.
///
/// In the end of `verifyProof`, the accumulator is used to do batched pairing
/// with the pairing input of the incoming proof.
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
        params: &'a ParamsKZG<bls12_381::Bls12381>,
        vk: &'a VerifyingKey<bls12_381::G1Affine>,
        scheme: BatchOpenScheme,
        num_instances: usize,
    ) -> Self {
        assert_ne!(vk.cs().num_advice_columns(), 0);
        assert!(
            vk.cs().num_instance_columns() <= 1,
            "Multiple instance columns is not yet implemented"
        );
        assert!(
            !vk.cs()
                .instance_queries()
                .iter()
                .any(|(_, rotation)| *rotation != Rotation::cur()),
            "Rotated query to instance column is not yet implemented"
        );

        Self {
            params,
            vk,
            scheme,
            num_instances,
            acc_encoding: None,
            meta: ConstraintSystemMeta::new(vk.cs()),
        }
    }

    /// Set `AccumulatorEncoding`.
    pub fn set_acc_encoding(mut self, acc_encoding: Option<AccumulatorEncoding>) -> Self {
        self.acc_encoding = acc_encoding;
        self
    }
}

impl<'a> SolidityGenerator<'a> {
    /// Render `Halo2Verifier.sol` with verifying key embedded into writer.
    pub fn render_into(&self, verifier_writer: &mut impl fmt::Write) -> Result<(), fmt::Error> {
        self.generate_verifier(false, false, BenchToggles::default())
            .render(verifier_writer)
    }

    /// Render `Halo2Verifier.sol` with verifying key embedded and return it as `String`.
    pub fn render(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render a benchmarking variant of `Halo2Verifier.sol` with the
    /// expensive blocks listed in `bench` elided. The output is **not**
    /// a sound verifier; it exists so a harness can attribute gas to
    /// individual stages by toggling one flag at a time. See
    /// `examples/bench.rs`.
    pub fn render_bench(&self, bench: BenchToggles) -> Result<String, fmt::Error> {
        let mut output = String::new();
        self.generate_verifier(false, false, bench).render(&mut output)?;
        Ok(output)
    }

    /// Render a trace-enabled `Halo2Verifier.sol` with verifying key embedded into writer.
    pub fn render_trace_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(false, true, BenchToggles::default())
            .render(verifier_writer)
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
        self.generate_verifier(true, false, BenchToggles::default())
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
        self.generate_verifier(true, true, BenchToggles::default())
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

    /// Re-encode a native BLS12-381 halo2 proof byte-stream into the
    /// EIP-2537 padded layout the Solidity verifier expects.
    ///
    /// What halo2's `create_proof` writes (per `Keccak256Transcript`):
    /// ```text
    /// [G1 commitments:    sum(num_advices) * 96 bytes]   // 48-byte BE x | 48-byte BE y
    /// [Fr evaluations:    num_evals        * 32 bytes]
    /// [G1 W,W' / ws:      trailing_g1_count* 96 bytes]
    /// ```
    /// EIP-2537 G1 layout is 128 bytes per point: each 48-byte coordinate
    /// is preceded by 16 zero bytes (so each coord lives in the low 48
    /// bytes of a 64-byte slot). We therefore prepend 16 zero bytes before
    /// each 48-byte half. Fr evaluations stay at 32 bytes (BLS12-381 Fr
    /// fits in a u256 word).
    pub fn proof_to_bls_padded(&self, bls_proof: &[u8]) -> Vec<u8> {
        let early_g1_count: usize = self.meta.num_advices().iter().sum();
        let trailing_g1_count = self.scheme.num_trailing_g1_points(&self.meta);
        let evals_bytes = self.meta.num_evals * 0x20;

        // Native BLS proof has 96 bytes per G1 (48 + 48 BE).
        let bls_g1_raw = 0x60usize;
        // EIP-2537-padded G1 stride is 128 bytes (4 u256 words).
        let bls_g1_padded = 0x80usize;
        let expected = early_g1_count * bls_g1_raw + evals_bytes + trailing_g1_count * bls_g1_raw;
        assert_eq!(
            bls_proof.len(),
            expected,
            "proof byte length {} does not match expected BLS layout {} (advice G1 = {}, \
             evals = {} bytes, trailing G1 = {})",
            bls_proof.len(),
            expected,
            early_g1_count,
            evals_bytes,
            trailing_g1_count,
        );

        let mut out = Vec::with_capacity(
            early_g1_count * bls_g1_padded + evals_bytes + trailing_g1_count * bls_g1_padded,
        );
        let mut cursor = 0usize;
        for _ in 0..early_g1_count {
            extend_with_padded_g1(&mut out, &bls_proof[cursor..cursor + bls_g1_raw]);
            cursor += bls_g1_raw;
        }
        out.extend_from_slice(&bls_proof[cursor..cursor + evals_bytes]);
        cursor += evals_bytes;
        for _ in 0..trailing_g1_count {
            extend_with_padded_g1(&mut out, &bls_proof[cursor..cursor + bls_g1_raw]);
            cursor += bls_g1_raw;
        }
        debug_assert_eq!(cursor, bls_proof.len());
        out
    }

    fn generate_vk(&self) -> Halo2VerifyingKey {
        let mut constants: Vec<(&'static str, U256)> = Vec::new();
        {
            let domain = self.vk.get_domain();
            // BLS12-381 Fr is 32 bytes wide (256 bits) so the same
            // little-endian-to-u256 conversion that worked for BN254 Fr
            // also works here: the verifier reads each scalar from
            // calldata into a single 32-byte word.
            let vk_digest = fe_to_u256::<bls12_381::Fr>(&self.vk.transcript_repr());
            let num_instances = U256::from(self.num_instances);
            let k = U256::from(domain.k());
            let n_inv = fe_to_u256::<bls12_381::Fr>(
                &bls12_381::Fr::from(1 << domain.k()).invert().unwrap(),
            );
            let omega = fe_to_u256::<bls12_381::Fr>(&domain.get_omega());
            let omega_inv = fe_to_u256::<bls12_381::Fr>(&domain.get_omega_inv());
            let omega_inv_to_l = {
                let l = self.meta.rotation_last.unsigned_abs() as u64;
                fe_to_u256::<bls12_381::Fr>(&domain.get_omega_inv().pow_vartime([l]))
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
            // EIP-2537 padded encodings: G1 = 4 words (16-byte zero-pad |
            // 16-byte hi | 32-byte lo, repeated for x and y), G2 = 8 words
            // (same shape applied to each Fq2 coefficient of x and y).
            // `g1_to_u256s` / `g2_to_u256s` walk halo2curves' BLS12-381
            // affine points into that layout directly.
            let g1_pt = self.params.g()[0];
            let g2_pt = self.params.g2();
            let neg_s_g2_pt = -self.params.s_g2();
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

        let fixed_comms = chain![self.vk.fixed_commitments()]
            .map(g1_to_u256s)
            .map(|[a, b, c, d]| (a, b, c, d))
            .collect();
        let permutation_comms = chain![self.vk.permutation().commitments()]
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
        bench: BenchToggles,
    ) -> Halo2Verifier {
        let proof_cptr = Ptr::calldata(0x64);

        let vk = self.generate_vk();
        let expected_vk_codehash = separate.then(|| {
            let digest: [u8; 32] = Keccak256::digest(vk.bytes()).into();
            U256::from_be_bytes(digest)
        });
        let vk_len = vk.len();
        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));
        let data = Data::new(&self.meta, &vk, vk_mptr, proof_cptr);

        let evaluator = Evaluator::new(self.vk.cs(), &self.meta, &data);
        let quotient_eval_numer_computations = chain![
            evaluator.gate_computations(),
            evaluator.permutation_computations(),
            evaluator.lookup_computations()
        ]
        .enumerate()
        .map(|(idx, (mut lines, var))| {
            let line = if idx == 0 {
                format!("quotient_eval_numer := {var}")
            } else {
                format!(
                    "quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), {var}, r)"
                )
            };
            lines.push(line);
            lines
        })
        .collect();

        let pcs_computations = self.scheme.computations(&self.meta, &data);

        Halo2Verifier {
            scheme: self.scheme,
            trace,
            bench,
            embedded_vk: (!separate).then_some(vk),
            expected_vk_codehash,
            vk_len,
            vk_mptr,
            num_neg_lagranges: self.meta.rotation_last.unsigned_abs() as usize,
            num_advices: self.meta.num_advices(),
            num_challenges: self.meta.num_challenges(),
            num_rotations: self.meta.num_rotations,
            num_evals: self.meta.num_evals,
            num_quotients: self.meta.num_quotients,
            proof_cptr,
            quotient_comm_cptr: data.quotient_comm_cptr,
            proof_len: self.meta.proof_len(self.scheme),
            challenge_mptr: data.challenge_mptr,
            theta_mptr: data.theta_mptr,
            quotient_eval_numer_computations,
            pcs_computations,
        }
    }

    fn static_working_memory_size(&self, vk: &Halo2VerifyingKey, proof_cptr: Ptr) -> usize {
        let pcs_computation = {
            let mock_vk_mptr = Ptr::memory(0x100000);
            let mock = Data::new(&self.meta, vk, mock_vk_mptr, proof_cptr);
            self.scheme.static_working_memory_size(&self.meta, &mock)
        };

        itertools::max([
            // Keccak256 input (can overwrite vk)
            itertools::max(chain![
                self.meta.num_advices().into_iter().map(|n| n * 2 + 1),
                [self.meta.num_evals + 1],
            ])
            .unwrap()
            .saturating_sub(vk.len() / 0x20),
            // PCS computation
            pcs_computation,
            // Pairing: 2 G1 points (4 words each) + 2 G2 points (8 words each)
            // = 24 words, plus 1-word output buffer.
            25,
        ])
        .unwrap()
            * 0x20
    }
}

// ----------------------------------------------------------------------------
// Native BLS12-381 -> EIP-2537 padded encoding helpers.
//
// halo2's `Keccak256Transcript::write_point` writes each G1 point as
// `(x_be || y_be)` with each coordinate in raw BLS12-381 Fp big-endian
// form (48 bytes per coord, 96 bytes per point). The EIP-2537 precompile
// inputs want the same coordinates but each coord prefixed with 16 zero
// bytes so it lands in the low 48 bytes of a 64-byte slot. We rebuild the
// proof bytestream with that padding so the Solidity verifier can DMA
// straight into the pairing precompile.
// ----------------------------------------------------------------------------

/// Append one BLS12-381 G1 point in EIP-2537 padded form (128 bytes) to
/// `out`. Input is 96 bytes raw `(x_be || y_be)`. Output is
/// `(16 zero | 48 x_be | 16 zero | 48 y_be)`.
fn extend_with_padded_g1(out: &mut Vec<u8>, raw_g1: &[u8]) {
    debug_assert_eq!(raw_g1.len(), 0x60);
    let mut chunk = [0u8; 0x80];
    // First 64-byte slot: 16 zero | 48-byte x_be.
    chunk[16..64].copy_from_slice(&raw_g1[0..48]);
    // Second 64-byte slot: 16 zero | 48-byte y_be.
    chunk[80..128].copy_from_slice(&raw_g1[48..96]);
    out.extend_from_slice(&chunk);
}

/// `encode_calldata` variant that takes a native BLS12-381 proof and
/// re-encodes the embedded G1 commitments into the EIP-2537 padded layout
/// the Solidity verifier reads.
pub fn encode_calldata_bls_padded(
    generator: &SolidityGenerator<'_>,
    bls_proof: &[u8],
    instances: &[bls12_381::Fr],
) -> Vec<u8> {
    let padded = generator.proof_to_bls_padded(bls_proof);
    crate::evm::encode_calldata(&padded, instances)
}
