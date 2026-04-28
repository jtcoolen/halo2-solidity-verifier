#![allow(dead_code)]

use crate::codegen::{pcs::BatchOpenScheme, util::Ptr};
use askama::{Error, Template};
use ruint::aliases::U256;
use std::fmt;

// BLS12-381 base field modulus p, big-endian.
//
// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624
//     1eabfffeb153ffffb9feffffffffaaab
//
// Verified against midnight-curves' Fp::MODULUS_REPR.
pub(crate) const BLS_P_TOP32: U256 = U256::from_be_slice(&[
    0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
    0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
]);
// Bottom 16 bytes of p, left-aligned in a 32-byte word so an `mstore` of
// this value at the right offset lands the 16 BE bytes in bytes 32..48
// of the 48-byte modulus block.
pub(crate) const BLS_P_BOT16_LEFT: U256 = U256::from_be_slice(&[
    0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

/// (p+1)/4 -- the sqrt exponent for BLS12-381 base field (p mod 4 == 3, so
/// sqrt(z) = z^((p+1)/4) mod p whenever z is a QR). Encoded as 48
/// big-endian bytes split into a top-32 / bottom-16-left-aligned pair.
///
/// (p+1)/4 = 0x0680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9cc34a83dac3d89
///           07aaffffac54ffffee7fbfffffffeaab
pub(crate) const BLS_SQRT_EXP_TOP32: U256 = U256::from_be_slice(&[
    0x06, 0x80, 0x44, 0x7a, 0x8e, 0x5f, 0xf9, 0xa6, 0x92, 0xc6, 0xe9, 0xed, 0x90, 0xd2, 0xeb, 0x35,
    0xd9, 0x1d, 0xd2, 0xe1, 0x3c, 0xe1, 0x44, 0xaf, 0xd9, 0xcc, 0x34, 0xa8, 0x3d, 0xac, 0x3d, 0x89,
]);
pub(crate) const BLS_SQRT_EXP_BOT16_LEFT: U256 = U256::from_be_slice(&[
    0x07, 0xaa, 0xff, 0xff, 0xac, 0x54, 0xff, 0xff, 0xee, 0x7f, 0xbf, 0xff, 0xff, 0xff, 0xea, 0xab,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

/// G1 point in EIP-2537 padded encoding: (x_hi, x_lo, y_hi, y_lo).
pub(crate) type G1Words = (U256, U256, U256, U256);

#[derive(Template)]
#[template(path = "Halo2VerifyingKey.sol")]
pub(crate) struct Halo2VerifyingKey {
    pub(crate) constants: Vec<(&'static str, U256)>,
    pub(crate) fixed_comms: Vec<G1Words>,
    pub(crate) permutation_comms: Vec<G1Words>,
}

impl Halo2VerifyingKey {
    pub(crate) fn len(&self) -> usize {
        // 32 bytes per scalar constant + 128 bytes per G1 point (EIP-2537 padded).
        (self.constants.len() * 0x20)
            + (self.fixed_comms.len() + self.permutation_comms.len()) * 0x80
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.constants
            .iter()
            .map(|(_, value)| *value)
            .chain(
                self.fixed_comms
                    .iter()
                    .flat_map(|(a, b, c, d)| [*a, *b, *c, *d]),
            )
            .chain(
                self.permutation_comms
                    .iter()
                    .flat_map(|(a, b, c, d)| [*a, *b, *c, *d]),
            )
            .flat_map(|value| value.to_be_bytes::<32>())
            .collect()
    }
}

/// Per-user-phase summary: how many advice commitments to absorb in this
/// phase, how many challenges to squeeze afterwards, and the index of
/// the first challenge within `CHALLENGE_MPTR[..]`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct UserPhase {
    pub(crate) num_advices: usize,
    pub(crate) num_challenges: usize,
    /// Starting offset (in 32-byte words) into the CHALLENGE_MPTR area
    /// where this phase's challenges should be written.
    pub(crate) challenge_offset: usize,
}

#[derive(Template)]
#[template(path = "Halo2Verifier.sol")]
pub(crate) struct Halo2Verifier {
    #[allow(dead_code)]
    pub(crate) scheme: BatchOpenScheme,
    pub(crate) trace: bool,
    /// When true, the rendered verifier emits LOG1 gas() checkpoints at
    /// section boundaries. See SOLIDITY_GAS_CHECKPOINTS_ENABLED.
    pub(crate) gas_checkpoints: bool,
    pub(crate) embedded_vk: Option<Halo2VerifyingKey>,
    pub(crate) expected_vk_codehash: Option<U256>,
    pub(crate) vk_len: usize,
    pub(crate) proof_len: usize,
    pub(crate) vk_mptr: Ptr,
    pub(crate) challenge_mptr: Ptr,
    pub(crate) theta_mptr: Ptr,
    pub(crate) proof_cptr: Ptr,
    /// Calldata byte offset of the `num_instances` length-prefix word
    /// that ABI-encodes the `instances` array. Equals
    /// `proof_cptr + proof_len` (in bytes). Materialised as a separate
    /// field because `proof_len` is not always a multiple of 32 once
    /// G1 commitments are 48-byte compressed; computing it via Ptr
    /// arithmetic in Askama would word-align and silently drop bytes.
    pub(crate) num_instance_cptr: usize,
    /// Calldata byte offset of the first instance value (immediately
    /// after `num_instance_cptr`).
    pub(crate) instance_cptr: usize,
    pub(crate) quotient_comm_cptr: Ptr,
    pub(crate) num_neg_lagranges: usize,
    /// Per-user-phase advice + user-challenge counts (excludes theta).
    pub(crate) user_phases: Vec<UserPhase>,
    pub(crate) num_user_challenges: usize,
    pub(crate) num_lookups: usize,
    pub(crate) num_permutation_zs: usize,
    pub(crate) lookup_h_plus_acc: usize,
    pub(crate) num_trashcans: usize,
    pub(crate) num_quotients: usize,
    pub(crate) num_evals: usize,
    pub(crate) num_point_sets: usize,
    /// Sum of `user_phases[i].num_advices` (total advice commitments).
    pub(crate) total_advices: usize,
    /// Sum of `meta.lookup_chunks` (total per-lookup helper commitments,
    /// excluding the lookup accumulator itself).
    pub(crate) lookup_helper_chunks_total: usize,
    /// Per-lookup helper-chunk count (mirrors `meta.lookup_chunks`). The
    /// proof emits commitments per-lookup as `(chunks helpers, 1 acc)`,
    /// so the proof-reading loop iterates this vector to dispatch each
    /// G1 to its correct MPTR.
    pub(crate) lookup_chunks: Vec<usize>,
    /// Word offset (relative to memory base) of the first decompressed
    /// advice commitment. The remaining categories (lookup_m, perm_z,
    /// lookup_helper, lookup_z, trashcan, quotient_limb) are laid out
    /// contiguously after this base with a 4-word stride per G1.
    pub(crate) comms_mptr_base: Ptr,
    /// Memory base of the pre-reversed-evals buffer (Optimisation H3).
    /// The transcript-side `evaluations` loop spills the byte-reversed
    /// `eval_le` value to this buffer so that every later eval
    /// reference renders as `mload(...)` (3 gas) instead of
    /// `byte_reverse_32(calldataload(...))` (~145 gas).
    pub(crate) reversed_evals_mptr: Ptr,
    /// Scratch base for simple-selector linearization accumulators.
    /// These values are needed only between quotient-eval emission and
    /// the linearization MSM, so the region may be reused by later PCS
    /// scratch tables.
    pub(crate) selector_acc_mptr: usize,
    /// Scratch base for the Lagrange batch-inversion prefix products.
    /// The public-instance vector can be wide, so the helper must not
    /// spill its temporary prefix products immediately above X_N_MPTR
    /// where they would overlap the permanent eval/commitment regions.
    pub(crate) batch_invert_scratch_mptr: usize,
    pub(crate) quotient_eval_numer_computations: Vec<Vec<String>>,
    pub(crate) pcs_computations: Vec<Vec<String>>,
    /// Sorted simple-selector fixed-column indices. Each is rendered
    /// into a Yul snippet that adds `S_i_com * sel_acc_i` to the
    /// linearization commitment after Q_folded is scaled by (1-x^n).
    pub(crate) simple_selector_cols: Vec<usize>,
    /// Memory pointer base for the embedded VK fixed commitments. Used
    /// to resolve per-column G1 offsets in the simple-selector MSM.
    pub(crate) fixed_comm_mptr: usize,
    /// When true, mirrors midnight-proofs/truncated-challenges:
    ///   - x3 is masked to 128 bits immediately after squeeze
    ///   - x1 / x4 powers are masked to 128 bits at use, with the
    ///     internal full-precision accumulator preserved
    /// Driven by `cfg!(feature = "truncated-challenges")` in
    /// `SolidityGenerator::generate_verifier`.
    pub(crate) truncated_challenges: bool,
    /// When true, mirrors midnight-proofs/fewer-point-sets: the
    /// transcript reads `num_dummy_evals` extra Fr scalars after the
    /// main eval block, and the codegen-side query list is augmented
    /// with the corresponding dummy queries before construct_intermediate_sets.
    /// Driven by `cfg!(feature = "fewer-point-sets")`.
    pub(crate) fewer_point_sets: bool,
    /// Number of dummy evals appended to the proof's eval block when
    /// `fewer_point_sets` is enabled. Zero otherwise.
    pub(crate) num_dummy_evals: usize,
    /// Fixed bases serialized by `AssignedAccumulator<S>::as_public_input`
    /// for the RHS accumulator MSM, in the exact lexicographic
    /// `BTreeMap` order used by midnight-circuits. This is the public
    /// accumulator's fixed-scalar width, not necessarily every fixed
    /// commitment stored in the VK contract. Each tuple is
    /// `(point_mptr, negate_scalar)`: `-G` is represented as the
    /// regular generator with the scalar negated modulo Fr.
    pub(crate) acc_fixed_bases: Vec<(usize, bool)>,
    /// Scratch base for staging the accumulator MSM input. Chosen
    /// after the verifier's permanent memory map so the variable-size
    /// `(point, scalar)` table cannot clobber VK/challenge state.
    pub(crate) acc_msm_scratch: usize,
}

impl Halo2VerifyingKey {
    pub(crate) fn render(&self, writer: &mut impl fmt::Write) -> Result<(), fmt::Error> {
        self.render_into(writer).map_err(|err| match err {
            Error::Fmt(err) => err,
            _ => unreachable!(),
        })
    }
}

impl Halo2Verifier {
    pub(crate) fn render(&self, writer: &mut impl fmt::Write) -> Result<(), fmt::Error> {
        self.render_into(writer).map_err(|err| match err {
            Error::Fmt(err) => err,
            _ => unreachable!(),
        })
    }
}

mod filters {
    use std::fmt::LowerHex;

    pub fn hex(value: impl LowerHex) -> ::askama::Result<String> {
        let value = format!("{value:x}");
        Ok(if value.len() % 2 == 1 {
            format!("0x0{value}")
        } else {
            format!("0x{value}")
        })
    }

    pub fn hex_padded(value: impl LowerHex, pad: usize) -> ::askama::Result<String> {
        let string = format!("0x{value:0pad$x}");
        if string == "0x0" {
            Ok(format!("0x{}", "0".repeat(pad)))
        } else {
            Ok(string)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{G1Words, Halo2VerifyingKey};
    use ruint::aliases::U256;

    fn synthetic_vk(num_fixed: usize, num_perm: usize) -> Halo2VerifyingKey {
        // 11 named scalars + 4 g1 + 8 g2 + 8 neg_s_g2 = 31 entries (the
        // exact layout the verifier expects for the Step 6 named
        // VK_DIGEST_MPTR / G1_BASE_MPTR / G2_BASE_MPTR / NEG_S_G2_BASE_MPTR
        // slots).
        let mut constants: Vec<(&'static str, U256)> = vec![
            ("vk_digest", U256::from(0xde_u64)),
            ("num_instances", U256::from(1u64)),
            ("k", U256::from(8u64)),
            ("n_inv", U256::from(0x1234u64)),
            ("omega", U256::from(0x5678u64)),
            ("omega_inv", U256::from(0x9abcu64)),
            ("omega_inv_to_l", U256::from(0xdef0u64)),
            ("has_accumulator", U256::from(0u64)),
            ("acc_offset", U256::from(0u64)),
            ("num_acc_limbs", U256::from(0u64)),
            ("num_acc_limb_bits", U256::from(0u64)),
        ];
        constants.extend([
            ("g1_x_hi", U256::from(0x10u64)),
            ("g1_x_lo", U256::from(0x11u64)),
            ("g1_y_hi", U256::from(0x12u64)),
            ("g1_y_lo", U256::from(0x13u64)),
        ]);
        constants.extend([
            ("g2_x_c0_hi", U256::from(0x20u64)),
            ("g2_x_c0_lo", U256::from(0x21u64)),
            ("g2_x_c1_hi", U256::from(0x22u64)),
            ("g2_x_c1_lo", U256::from(0x23u64)),
            ("g2_y_c0_hi", U256::from(0x24u64)),
            ("g2_y_c0_lo", U256::from(0x25u64)),
            ("g2_y_c1_hi", U256::from(0x26u64)),
            ("g2_y_c1_lo", U256::from(0x27u64)),
        ]);
        constants.extend([
            ("neg_s_g2_x_c0_hi", U256::from(0x30u64)),
            ("neg_s_g2_x_c0_lo", U256::from(0x31u64)),
            ("neg_s_g2_x_c1_hi", U256::from(0x32u64)),
            ("neg_s_g2_x_c1_lo", U256::from(0x33u64)),
            ("neg_s_g2_y_c0_hi", U256::from(0x34u64)),
            ("neg_s_g2_y_c0_lo", U256::from(0x35u64)),
            ("neg_s_g2_y_c1_hi", U256::from(0x36u64)),
            ("neg_s_g2_y_c1_lo", U256::from(0x37u64)),
        ]);

        let fixed_comms: Vec<G1Words> = (0..num_fixed)
            .map(|i| {
                let base = U256::from(0x40_u64 + i as u64 * 4);
                (
                    base,
                    base + U256::from(1u64),
                    base + U256::from(2u64),
                    base + U256::from(3u64),
                )
            })
            .collect();
        let permutation_comms: Vec<G1Words> = (0..num_perm)
            .map(|i| {
                let base = U256::from(0x80_u64 + i as u64 * 4);
                (
                    base,
                    base + U256::from(1u64),
                    base + U256::from(2u64),
                    base + U256::from(3u64),
                )
            })
            .collect();
        Halo2VerifyingKey {
            constants,
            fixed_comms,
            permutation_comms,
        }
    }

    #[test]
    fn vk_layout_byte_consistency() {
        // For a synthetic VK with 31 named scalars + N=2 fixed + M=3
        // permutation commitments, expect:
        //   len() = 31*32 + (2+3)*4*32 = 31*32 + 20*32 = 51*32 = 1632 bytes
        //   bytes().len() == len()
        let vk = synthetic_vk(2, 3);
        let expected_len = 31 * 32 + (2 + 3) * 4 * 32;
        assert_eq!(vk.len(), expected_len);
        assert_eq!(vk.bytes().len(), expected_len);

        // The first 32 bytes of bytes() should encode `vk_digest`.
        let head = &vk.bytes()[..32];
        let mut buf = [0u8; 32];
        buf.copy_from_slice(head);
        let head_u256 = U256::from_be_bytes(buf);
        assert_eq!(head_u256, U256::from(0xde_u64));

        // Word index of NEG_S_G2_BASE_MPTR = 23 (vk_mptr + 23).
        // Verify the corresponding bytes match the synthetic value 0x30.
        let off = 23 * 32;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&vk.bytes()[off..off + 32]);
        let neg_s_g2_x_c0_hi = U256::from_be_bytes(buf);
        assert_eq!(neg_s_g2_x_c0_hi, U256::from(0x30_u64));

        // First fixed_comm starts at word 31.
        let off = 31 * 32;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&vk.bytes()[off..off + 32]);
        assert_eq!(U256::from_be_bytes(buf), U256::from(0x40_u64));

        // First permutation_comm starts at word 31 + 4*N_FIXED = 39.
        let off = 39 * 32;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&vk.bytes()[off..off + 32]);
        assert_eq!(U256::from_be_bytes(buf), U256::from(0x80_u64));
    }

    #[test]
    fn vk_renders_and_returns_correct_length() {
        let vk = synthetic_vk(2, 3);
        let mut s = String::new();
        vk.render(&mut s).expect("VK render");
        // The constructor must `return(0, len)` with the exact byte length
        // the verifier loads via `extcodecopy`. Our `hex` filter
        // left-pads odd-length hex literals with a leading zero, so 0x660
        // (3 hex digits) renders as "0x0660".
        let raw_hex = format!("{:x}", vk.len());
        let padded_hex = if raw_hex.len() % 2 == 1 {
            format!("0{raw_hex}")
        } else {
            raw_hex
        };
        let expected_return = format!("return(0, 0x{padded_hex})");
        assert!(
            s.contains(&expected_return),
            "rendered VK missing expected return statement {expected_return} in:\n{s}"
        );
        // It should `mstore` the very first scalar (vk_digest) at offset 0.
        assert!(s.contains("mstore(0x0000,"), "vk_digest mstore at offset 0");
        // The first permutation commitment is at byte offset 0x4e0
        // (39 * 32 = 1248 = 0x4e0).
        assert!(
            s.contains("mstore(0x04e0,"),
            "permutation_comms[0].x_hi at byte offset 0x4e0"
        );
    }
}
