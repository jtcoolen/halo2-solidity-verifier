use crate::codegen::{
    pcs::BatchOpenScheme::{self, Gwc19},
    util::Ptr,
};
use askama::{Error, Template};
use ruint::aliases::U256;
use std::fmt;

/// G1 point in EIP-2537 padded encoding: (x_hi, x_lo, y_hi, y_lo).
pub(crate) type G1Words = (U256, U256, U256, U256);

/// Compile-time toggles that elide expensive sections of the verifier
/// from the generated Solidity. Used by `examples/bench.rs` to attribute
/// gas to individual stages: render the verifier with `..Default::default()`
/// for the baseline (everything on) and with one `skip_*` flag flipped at a
/// time to measure the marginal cost of that stage.
///
/// All toggles are pure cosmetic helpers for benchmarking — flipping any
/// of them produces a verifier that no longer enforces full proof validity
/// and **must not** be deployed. The auditing public API only exposes
/// these via `SolidityGenerator::render_bench`.
#[derive(Clone, Copy, Debug, Default)]
pub struct BenchToggles {
    /// Skip the final `BLS12_PAIRING_CHECK` (`0x0f`) call. Dominant cost.
    pub skip_pairing: bool,
    /// Skip the random linear combination of the accumulator into the
    /// pairing inputs (the keccak + 2 G1MSMs + 2 G1ADDs in that block).
    pub skip_random_combine: bool,
    /// Skip the entire PCS computation block (the chain of G1MSM/G1ADD
    /// ops that constructs PAIRING_LHS / PAIRING_RHS).
    pub skip_pcs: bool,
    /// Skip the Horner fold over the quotient commitments.
    pub skip_quotient_fold: bool,
    /// Skip the quotient-evaluation numerator computation (the long
    /// `mulmod` chain over Fr).
    pub skip_quotient_eval: bool,
    /// Skip the Lagrange & instance-evaluation block (`batch_invert` over
    /// modexp `0x05` plus the `mulmod` sweep over instances).
    pub skip_lagrange: bool,
    /// Skip the `(hi, lo) < p` range check in `read_g1_point` (added in
    /// audit fix #2). Useful for measuring the amortized cost of the
    /// extra check across the proof.
    pub skip_g1_range_check: bool,
}

impl BenchToggles {
    /// True iff *any* skip flag is set, meaning the rendered verifier is
    /// a bench variant rather than a sound one. Used by the template to
    /// emit a force-observe XOR sink at the end of `verifyProof` so the
    /// solc optimizer can't dead-code-eliminate stages whose downstream
    /// consumer was skipped.
    pub fn is_active(&self) -> bool {
        self.skip_pairing
            || self.skip_random_combine
            || self.skip_pcs
            || self.skip_quotient_fold
            || self.skip_quotient_eval
            || self.skip_lagrange
            || self.skip_g1_range_check
    }
}

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

#[derive(Template)]
#[template(path = "Halo2Verifier.sol")]
pub(crate) struct Halo2Verifier {
    #[allow(dead_code)]
    pub(crate) scheme: BatchOpenScheme,
    pub(crate) trace: bool,
    pub(crate) bench: BenchToggles,
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
    pub(crate) num_advices: Vec<usize>,
    pub(crate) num_challenges: Vec<usize>,
    pub(crate) num_rotations: usize,
    pub(crate) num_evals: usize,
    pub(crate) num_quotients: usize,
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
