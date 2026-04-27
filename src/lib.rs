//! Solidity verifier generator for [`halo2`] proof with KZG polynomial commitment scheme on BN254.
//!
//! [`halo2`]: http://github.com/privacy-scaling-explorations/halo2

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![deny(rustdoc::broken_intra_doc_links)]

mod codegen;
mod evm;
mod transcript;

#[cfg(test)]
mod test;

pub use codegen::{
    encode_calldata_bls_padded, AccumulatorEncoding, BatchOpenScheme, BenchToggles,
    SolidityGenerator,
};
pub use evm::{encode_calldata, FN_SIG_VERIFY_PROOF};
pub use transcript::Keccak256Transcript;

#[cfg(feature = "evm")]
pub use evm::test::{compile_solidity, compile_solidity_with, revm, CallOutcome, Evm};

/// Test-only helper that exposes the internal BLS12-381 G1 to EIP-2537
/// hi/lo encoder so debugging examples can re-encode host-computed
/// points using the exact same pipeline the Solidity verifier consumes.
#[doc(hidden)]
pub fn __test_only_g1_to_u256s(
    point: &halo2_proofs::halo2curves::bls12381::G1Affine,
) -> [ruint::aliases::U256; 4] {
    crate::codegen::util::g1_to_u256s(point)
}
