//! Solidity verifier generator for midnight-proofs with KZG polynomial
//! commitment scheme on BLS12-381 / EIP-2537.
//!
//! Migration in progress (Steps 1-3, 2026-04-26): see `MIGRATION.md` for
//! the full plan and remaining steps.

#![deny(missing_debug_implementations)]
#![deny(rustdoc::broken_intra_doc_links)]

mod codegen;
mod evm;
mod transcript;

#[cfg(all(test, feature = "evm"))]
mod test;

pub use codegen::{
    encode_calldata_bls_padded, AccumulatorEncoding, BatchOpenScheme, ProofEvaluationCounts,
    SolidityGenerator,
};
pub use evm::{encode_calldata, FN_SIG_VERIFY_PROOF};
pub use transcript::Keccak256Transcript;

/// Whether the default Solidity renderer emits trace logs.
///
/// Enable with `--features solidity-trace`. The explicit
/// `render_trace*` helpers still force trace output regardless of this
/// flag.
pub const SOLIDITY_TRACE_ENABLED: bool = cfg!(feature = "solidity-trace");

/// Whether the default Solidity renderer emits LOG1 gas() checkpoints
/// at section boundaries. The host-side test parses these into per-
/// section gas deltas (see `dump_gas_checkpoints` in
/// `tests/poseidon_fixture.rs`).
///
/// Enable with `--features solidity-gas-checkpoints`. The explicit
/// `render_with_gas_checkpoints*` helpers still force checkpoint
/// emission regardless of this flag.
pub const SOLIDITY_GAS_CHECKPOINTS_ENABLED: bool = cfg!(feature = "solidity-gas-checkpoints");

/// Whether the generated Solidity verifier expects the outer proof to use
/// the fewer-point-sets dummy-query PCS layout.
///
/// This is intentionally separate from recursive/in-circuit verifier proofs:
/// the IVC benchmark can keep fewer point sets for proofs checked inside the
/// decider circuit while emitting the final Solidity-facing proof without the
/// extra dummy eval scalars.
pub const OUTER_FEWER_POINT_SETS_ENABLED: bool = cfg!(feature = "outer-fewer-point-sets");

#[cfg(feature = "evm")]
pub use evm::test::{
    compile_solidity, compile_solidity_with_runs, revm, CallOutcome, Evm, DEFAULT_OPTIMIZE_RUNS,
};

/// Test-only helper that exposes the internal BLS12-381 G1 to EIP-2537
/// hi/lo encoder so debugging examples can re-encode host-computed
/// points using the exact same pipeline the Solidity verifier consumes.
#[doc(hidden)]
pub fn __test_only_g1_to_u256s(point: &midnight_curves::G1Affine) -> [ruint::aliases::U256; 4] {
    crate::codegen::util::g1_to_u256s(point)
}
