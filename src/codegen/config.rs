//! Environment-driven knobs for experimental code-generation paths.
//!
//! These options are intentionally read at generation time instead of becoming
//! public API surface. Most of them select equivalent representations of the
//! quotient numerator path so gas, bytecode size, and compiler behavior can be
//! compared without changing call sites.

use super::{QuotientProgramEncoding, QuotientStructuredTailMode};

// Keep a small direct prefix as the default gas-capped compact VM path:
// it avoids running the entire numerator through the interpreter while staying
// below the external quotient evaluator size budget. Set
// HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=0 for the smaller
// compile-stable fallback.
pub(super) const DEFAULT_HYBRID_QUOTIENT_INLINE_IDENTITIES: usize = 4;
pub(super) const HYBRID_QUOTIENT_INLINE_IDENTITIES_ENV: &str =
    "HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES";

// Spend a bounded slice of quotient-evaluator bytecode headroom on native VM
// callbacks. After the direct prefix, up to N remaining gate identities are
// emitted as VM opcodes that call generated Yul blocks; everything else stays
// in the compact interpreter. Selection is a gas/byte knapsack under an
// estimated native callback byte budget. Tune the max count with
// HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=N and override the estimated byte budget
// with HALO2_SOLIDITY_QUOTIENT_NATIVE_GATE_BYTE_BUDGET=N.
pub(super) const DEFAULT_QUOTIENT_NATIVE_GATES: usize = 4;
pub(super) const QUOTIENT_NATIVE_GATES_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES";
pub(super) const QUOTIENT_NATIVE_GATE_BYTE_BUDGET_ENV: &str =
    "HALO2_SOLIDITY_QUOTIENT_NATIVE_GATE_BYTE_BUDGET";
pub(super) const QUOTIENT_ENCODING_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_ENCODING";
// The compact quotient VM path is the default size-oriented emitter: it stores
// identity arithmetic as data in the VK and interprets it from one small Yul
// loop. Emit the final trash suffix as structured Yul by default to save
// dispatch gas. Set HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=off for the smaller
// compile-stable fallback, HALO2_SOLIDITY_QUOTIENT_STRUCTURED_LOOPS=1 for the
// larger fully structured experiment, or HALO2_SOLIDITY_QUOTIENT_CSE=1 for
// fully inline CSE gas measurement.
pub(super) const QUOTIENT_CSE_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_CSE";
pub(super) const QUOTIENT_VM_CSE_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_VM_CSE";
pub(super) const QUOTIENT_YUL_HELPERS_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_YUL_HELPERS";
pub(super) const QUOTIENT_STRUCTURED_LOOPS_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_STRUCTURED_LOOPS";
pub(super) const QUOTIENT_STRUCTURED_TAIL_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL";
pub(super) const QUOTIENT_NATIVE_PERMUTATION_ENV: &str =
    "HALO2_SOLIDITY_QUOTIENT_NATIVE_PERMUTATION";
pub(super) const QUOTIENT_NATIVE_LOOKUP_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_NATIVE_LOOKUP";
// Limb-aware VM superinstructions are part of the default byte-oriented
// pinned-VK lowering: they structurally compress recurring 7-limb
// foreign-field expressions while preserving the compact quotient interpreter.
// Set HALO2_SOLIDITY_QUOTIENT_LIMB_VM_OPS=0 to compare the generic VM fallback.
pub(super) const DEFAULT_QUOTIENT_LIMB_VM_OPS: bool = true;
pub(super) const QUOTIENT_LIMB_VM_OPS_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_LIMB_VM_OPS";
pub(super) const QUOTIENT_SHAPE_PROFILE_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_SHAPE_PROFILE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CodegenOptions {
    /// Number of gate identities kept as direct Yul before the compact VM.
    pub(super) hybrid_quotient_inline_identities: usize,
    /// Number of remaining heavy gate identities emitted as native callbacks.
    pub(super) quotient_native_gates: usize,
    /// Optional estimated native callback byte budget for gate selection.
    pub(super) quotient_native_gate_byte_budget: Option<usize>,
    /// Physical encoding used for the compact quotient VM program.
    pub(super) quotient_encoding: QuotientProgramEncoding,
    /// Whether the direct quotient path stores repeated expressions in memory.
    pub(super) quotient_inline_cse: bool,
    /// Whether the compact VM may use persistent temp slots.
    pub(super) quotient_vm_cse: bool,
    /// Whether direct Yul quotient emission can call local helper functions.
    pub(super) quotient_yul_helpers: bool,
    /// Whether full gate/permutation/lookup/trash structured-loop mode is used.
    pub(super) quotient_structured_loops: bool,
    /// Which suffix identities, if any, should bypass the VM as structured Yul.
    pub(super) quotient_structured_tail: QuotientStructuredTailMode,
    /// Whether permutation identities can be replaced by a native VM callback.
    pub(super) quotient_native_permutation: bool,
    /// Whether lookup identities can be replaced by a native VM callback.
    pub(super) quotient_native_lookup: bool,
    /// Whether byte-oriented VM emission may use limb-specialized opcodes.
    pub(super) quotient_limb_vm_ops: bool,
    /// Whether limb recognizer counters are printed to stderr.
    pub(super) quotient_shape_profile: bool,
}

impl CodegenOptions {
    /// Parse all supported environment variables, applying production defaults.
    pub(super) fn from_env() -> Self {
        let quotient_encoding = parse_quotient_encoding();
        let default_limb_vm_ops =
            DEFAULT_QUOTIENT_LIMB_VM_OPS && quotient_encoding == QuotientProgramEncoding::Bytes;
        Self {
            hybrid_quotient_inline_identities: parse_usize_env(
                HYBRID_QUOTIENT_INLINE_IDENTITIES_ENV,
                DEFAULT_HYBRID_QUOTIENT_INLINE_IDENTITIES,
            ),
            quotient_native_gates: parse_usize_env(
                QUOTIENT_NATIVE_GATES_ENV,
                DEFAULT_QUOTIENT_NATIVE_GATES,
            ),
            quotient_native_gate_byte_budget: parse_optional_usize_env(
                QUOTIENT_NATIVE_GATE_BYTE_BUDGET_ENV,
            ),
            quotient_encoding,
            quotient_inline_cse: parse_bool_env(QUOTIENT_CSE_ENV, false, "0/1", &["cse"]),
            quotient_vm_cse: parse_bool_env(QUOTIENT_VM_CSE_ENV, true, "0/1", &["cse"]),
            quotient_yul_helpers: parse_bool_env(
                QUOTIENT_YUL_HELPERS_ENV,
                false,
                "0/1",
                &["helpers"],
            ),
            quotient_structured_loops: parse_bool_env(
                QUOTIENT_STRUCTURED_LOOPS_ENV,
                false,
                "0/1",
                &["loops"],
            ),
            quotient_structured_tail: parse_structured_tail(),
            quotient_native_permutation: parse_bool_env(
                QUOTIENT_NATIVE_PERMUTATION_ENV,
                true,
                "0/1",
                &["native"],
            ),
            quotient_native_lookup: parse_bool_env(
                QUOTIENT_NATIVE_LOOKUP_ENV,
                true,
                "0/1",
                &["native"],
            ),
            quotient_limb_vm_ops: parse_bool_env(
                QUOTIENT_LIMB_VM_OPS_ENV,
                default_limb_vm_ops,
                "0/1",
                &["limb", "limbs"],
            ),
            quotient_shape_profile: parse_bool_env(
                QUOTIENT_SHAPE_PROFILE_ENV,
                false,
                "0/1",
                &["profile"],
            ),
        }
    }
}

/// Parse an unsigned integer environment variable or return `default`.
fn parse_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

/// Parse an optional unsigned integer environment variable.
fn parse_optional_usize_env(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
}

/// Parse a boolean/toggle environment variable with optional named aliases.
///
/// The `expected` string is used only for a panic message so bad tuning values
/// fail loudly during code generation instead of silently selecting a default.
fn parse_bool_env(name: &str, default: bool, expected: &str, true_aliases: &[&str]) -> bool {
    let Ok(value) = std::env::var(name) else {
        return default;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => false,
        "1" | "true" | "on" | "yes" => true,
        other if true_aliases.contains(&other) => true,
        other => panic!("unsupported {name}={other}; use {expected}"),
    }
}

/// Parse the compact quotient VM physical encoding.
fn parse_quotient_encoding() -> QuotientProgramEncoding {
    let Ok(value) = std::env::var(QUOTIENT_ENCODING_ENV) else {
        return QuotientProgramEncoding::Bytes;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "bytes" | "byte" | "varbytes" | "compact" => QuotientProgramEncoding::Bytes,
        "3" | "option3" | "packed32" | "packed-32" | "u32" => QuotientProgramEncoding::Packed32,
        other => panic!("unsupported {QUOTIENT_ENCODING_ENV}={other}; use bytes or packed32"),
    }
}

/// Parse the structured suffix mode for quotient identity emission.
fn parse_structured_tail() -> QuotientStructuredTailMode {
    let Ok(value) = std::env::var(QUOTIENT_STRUCTURED_TAIL_ENV) else {
        return QuotientStructuredTailMode::Trash;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => QuotientStructuredTailMode::Off,
        "1" | "true" | "on" | "yes" | "tail" | "trash" => QuotientStructuredTailMode::Trash,
        other => panic!("unsupported {QUOTIENT_STRUCTURED_TAIL_ENV}={other}; use off or trash"),
    }
}
