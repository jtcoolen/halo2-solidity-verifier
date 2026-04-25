use crate::codegen::{
    evaluator::Evaluator,
    template::{Halo2Verifier, Halo2VerifyingKey},
    util::{
        bls_g1_pad_from_bn254_bytes, bls_g2_pad_from_bn254_bytes, fr_to_u256,
        ConstraintSystemMeta, Data, Ptr,
    },
};
// We keep VerifyingKey<bn256::G1Affine> as the input type so the existing
// halo2_proofs v0.3 prover keeps compiling. The codegen converts each
// commitment to the BLS12-381/EIP-2537 byte shape at the boundary -- see
// PORTING_NOTES.md for the cryptographic caveats (this is shape-correct;
// a real end-to-end BLS port also needs a halo2 KZG-BLS prover backend).
use halo2_proofs::{
    halo2curves::{bn256, ff::Field},
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
/// IMPORTANT: this generator currently takes a halo2_proofs v0.3 BN254 VK and
/// `ParamsKZG<Bn256>` because that's the only KZG backend halo2_proofs v0.3
/// ships with. The BN254 byte representation is mechanically re-shaped into
/// the EIP-2537 BLS12-381 encoding (4 words per G1 point, 8 per G2). The
/// resulting Solidity is *shape-correct* -- compiles, deploys, accepts the
/// right calldata length, and exercises the correct precompile addresses --
/// but the embedded curve points are not valid BLS12-381 points so the
/// pairing check will fail at runtime. End-to-end verification requires
/// regenerating the VK and proof against a halo2 KZG-BLS backend; until one
/// is wired in, the heavy integration tests are marked #[ignore]. See
/// PORTING_NOTES.md.
#[derive(Debug)]
pub struct SolidityGenerator<'a> {
    params: &'a ParamsKZG<bn256::Bn256>,
    vk: &'a VerifyingKey<bn256::G1Affine>,
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
        params: &'a ParamsKZG<bn256::Bn256>,
        vk: &'a VerifyingKey<bn256::G1Affine>,
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

    /// Re-encode a halo2 BN254 proof byte-stream into the EIP-2537 padded
    /// layout the BLS Solidity verifier expects.
    ///
    /// The halo2 proof layout (BN254 shape, what `create_proof` writes) is:
    /// ```text
    /// [G1 commitments: sum(num_advices) * 64 bytes]
    /// [Fr evaluations: num_evals * 32 bytes]
    /// [G1 W, W' (Bdfg21)  /  G1 ws (Gwc19): batch_open_proof_len * 64 bytes]
    /// ```
    /// In BLS shape every G1 chunk doubles to 128 bytes (16 zero bytes +
    /// 32-byte BN254 coord + 16 zero bytes + 32-byte BN254 coord, twice for
    /// x and y). Fr evaluations stay at 32 bytes since the BN254 and
    /// BLS12-381 scalar fields are both 256 bits wide.
    ///
    /// This method does NOT do any cryptographic conversion -- the curve
    /// points still live in BN254-land numerically and the pairing will
    /// ultimately fail. Its only job is to make the calldata length and
    /// per-G1 stride match what the BLS Solidity verifier reads. End-to-end
    /// success requires regenerating the proof against a real BLS-KZG
    /// prover backend (see PORTING_NOTES.md).
    pub fn proof_to_bls_padded(&self, bn254_proof: &[u8]) -> Vec<u8> {
        let early_g1_count: usize = self.meta.num_advices().iter().sum();
        let trailing_g1_count = self.scheme.num_trailing_g1_points(&self.meta);
        let evals_bytes = self.meta.num_evals * 0x20;

        let expected = early_g1_count * 0x40 + evals_bytes + trailing_g1_count * 0x40;
        assert_eq!(
            bn254_proof.len(),
            expected,
            "proof byte length {} does not match expected BN254 layout {} (advice G1 = {}, \
             evals = {} bytes, trailing G1 = {})",
            bn254_proof.len(),
            expected,
            early_g1_count,
            evals_bytes,
            trailing_g1_count,
        );

        let mut out = Vec::with_capacity(early_g1_count * 0x80 + evals_bytes + trailing_g1_count * 0x80);
        let mut cursor = 0usize;
        // Section A: early G1 commitments.
        for _ in 0..early_g1_count {
            extend_with_padded_g1(&mut out, &bn254_proof[cursor..cursor + 0x40]);
            cursor += 0x40;
        }
        // Section B: Fr evaluations (unchanged).
        out.extend_from_slice(&bn254_proof[cursor..cursor + evals_bytes]);
        cursor += evals_bytes;
        // Section C: trailing G1 (W / W' for Bdfg21, ws for Gwc19).
        for _ in 0..trailing_g1_count {
            extend_with_padded_g1(&mut out, &bn254_proof[cursor..cursor + 0x40]);
            cursor += 0x40;
        }
        debug_assert_eq!(cursor, bn254_proof.len());
        out
    }

    fn generate_vk(&self) -> Halo2VerifyingKey {
        let mut constants: Vec<(&'static str, U256)> = Vec::new();
        {
            let domain = self.vk.get_domain();
            // The scalar field of BN254 and BLS12-381 are different but the
            // same byte width (32). At the codegen layer we treat the VK
            // scalar bytes as opaque u256s -- they get pasted into the
            // Solidity verifier verbatim. When a real BLS prover backend
            // lands the same code path will produce semantically correct
            // values; until then this is a shape-only convenience.
            let vk_digest = fr_to_bn254_u256(&self.vk.transcript_repr());
            let num_instances = U256::from(self.num_instances);
            let k = U256::from(domain.k());
            let n_inv = fr_to_bn254_u256(
                &bn256::Fr::from(1 << domain.k()).invert().unwrap(),
            );
            let omega = fr_to_bn254_u256(&domain.get_omega());
            let omega_inv = fr_to_bn254_u256(&domain.get_omega_inv());
            let omega_inv_to_l = {
                let l = self.meta.rotation_last.unsigned_abs() as u64;
                fr_to_bn254_u256(&domain.get_omega_inv().pow_vartime([l]))
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
            // EIP-2537 padded encodings: G1 = 4 words, G2 = 8 words. The
            // BN254 32-byte coordinates are zero-extended to 48 bytes and
            // then split per EIP-2537. See bls_g1_pad_from_bn254_bytes.
            let g1_pt = self.params.g()[0];
            let g2_pt = self.params.g2();
            let neg_s_g2_pt = -self.params.s_g2();
            let g1 = bls_g1_pad_from_bn254_bytes(&g1_pt);
            let g2 = bls_g2_pad_from_bn254_bytes(&g2_pt);
            let neg_s_g2 = bls_g2_pad_from_bn254_bytes(&neg_s_g2_pt);

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
            .map(bls_g1_pad_from_bn254_bytes)
            .map(|[a, b, c, d]| (a, b, c, d))
            .collect();
        let permutation_comms = chain![self.vk.permutation().commitments()]
            .map(bls_g1_pad_from_bn254_bytes)
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
// BN254 -> BLS-shape conversion helpers (shape-only; see PORTING_NOTES.md).
//
// These take BN254 field/curve elements (because halo2_proofs v0.3 only knows
// how to produce those) and return the EIP-2537 BLS12-381 padded layout. The
// resulting bytes are *not* valid BLS curve points; the Solidity verifier
// will accept the calldata shape but the BLS pairing will revert. This lets
// us iterate on the verifier template / codegen / calldata pipeline without
// needing a halo2 BLS-KZG fork installed.
// ----------------------------------------------------------------------------

fn fr_to_bn254_u256(fr: &bn256::Fr) -> U256 {
    fr_to_u256(fr)
}

/// Append the EIP-2537 padded encoding of one BN254-shape G1 point (64 bytes
/// raw: 32-byte x followed by 32-byte y) to `out`. The output is 128 bytes:
/// `(16 zero | 16 zero | 32 x_be | 16 zero | 16 zero | 32 y_be)`. Any
/// "y-coord-doesn't-fit-in-381-bits" failure is deferred to the EIP-2537
/// precompile.
fn extend_with_padded_g1(out: &mut Vec<u8>, raw_g1_bn254: &[u8]) {
    debug_assert_eq!(raw_g1_bn254.len(), 0x40);
    let mut chunk = [0u8; 0x80];
    // x: 16 zeros, then... wait, BN254 fits in 32 bytes so we need 32 zero
    // bytes total of padding (top 16 of word 0 + all of nothing in word 0
    // since BN254 is 254 bits => fits in lower 32 bytes of EIP-2537's
    // 64-byte slot). EIP-2537 layout per coord: 16 zero bytes + 48-byte
    // value. BN254 (254 bits) fits in 32 bytes => prepend 16 more zero
    // bytes to land at 48 bytes => prepend another 16 zeros for the
    // top-of-word zero-pad, total 32 zeros + 32 BN254 bytes per coord.
    // Slot 0..32: top 16 zeros of x (16) + first 16 of value (zero pad) = all zeros
    // Slot 32..64: 32-byte BN254 x BE
    chunk[0..32].fill(0);
    chunk[32..64].copy_from_slice(&raw_g1_bn254[0..32]);
    chunk[64..96].fill(0);
    chunk[96..128].copy_from_slice(&raw_g1_bn254[32..64]);
    out.extend_from_slice(&chunk);
}

/// `encode_calldata` variant that takes a BN254-shape proof and re-encodes
/// the embedded G1 commitments into the EIP-2537 padded layout that the
/// BLS Solidity verifier reads.
///
/// The resulting calldata length matches what the verifier's CPTR constants
/// expect (128 bytes per G1, 32 bytes per Fr eval), so the dispatch will
/// not revert with malformed-length errors. The pairing check still fails
/// because the embedded points are BN254 numerically; that's fixed by
/// Stage C (real BLS-KZG prover backend).
pub fn encode_calldata_bls_padded(
    generator: &SolidityGenerator<'_>,
    bn254_proof: &[u8],
    instances: &[bn256::Fr],
) -> Vec<u8> {
    let bls_proof = generator.proof_to_bls_padded(bn254_proof);
    crate::evm::encode_calldata(&bls_proof, instances)
}
