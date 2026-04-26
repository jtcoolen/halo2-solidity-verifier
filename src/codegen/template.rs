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
///           07aaffffac54ffffee7fbfffffffffeaab
pub(crate) const BLS_SQRT_EXP_TOP32: U256 = U256::from_be_slice(&[
    0x06, 0x80, 0x44, 0x7a, 0x8e, 0x5f, 0xf9, 0xa6, 0x92, 0xc6, 0xe9, 0xed, 0x90, 0xd2, 0xeb, 0x35,
    0xd9, 0x1d, 0xd2, 0xe1, 0x3c, 0xe1, 0x44, 0xaf, 0xd9, 0xcc, 0x34, 0xa8, 0x3d, 0xac, 0x3d, 0x89,
]);
pub(crate) const BLS_SQRT_EXP_BOT16_LEFT: U256 = U256::from_be_slice(&[
    0x07, 0xaa, 0xff, 0xff, 0xac, 0x54, 0xff, 0xff, 0xee, 0x7f, 0xbf, 0xff, 0xff, 0xff, 0xfe, 0xab,
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
    pub(crate) embedded_vk: Option<Halo2VerifyingKey>,
    pub(crate) expected_vk_codehash: Option<U256>,
    pub(crate) vk_len: usize,
    pub(crate) proof_len: usize,
    pub(crate) vk_mptr: Ptr,
    pub(crate) challenge_mptr: Ptr,
    pub(crate) theta_mptr: Ptr,
    pub(crate) proof_cptr: Ptr,
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
    pub(crate) quotient_eval_numer_computations: Vec<Vec<String>>,
    pub(crate) pcs_computations: Vec<Vec<String>>,
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
