use super::{QuotientProgramEncoding, QuotientStructuredTailMode};

// Keep the default monolithic verifier on the most compile-stable compact VM
// path. Direct native quotient snippets are still available for local gas
// experiments via HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=N, but the
// default must survive solc's via-IR stack allocator across embedded/separate
// verifier variants.
pub(super) const DEFAULT_HYBRID_QUOTIENT_INLINE_IDENTITIES: usize = 0;
pub(super) const HYBRID_QUOTIENT_INLINE_IDENTITIES_ENV: &str =
    "HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES";

// Spend a bounded slice of quotient-evaluator bytecode headroom on native VM
// callbacks. After the direct prefix, the heaviest N remaining gate identities
// are emitted as VM opcodes that call generated Yul blocks; everything else
// stays in the compact interpreter. The default keeps the heaviest callbacks
// native while leaving the direct prefix and structured tail off for solc
// compile stability. Tune with HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=N.
pub(super) const DEFAULT_QUOTIENT_NATIVE_GATES: usize = 4;
pub(super) const QUOTIENT_NATIVE_GATES_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES";
pub(super) const QUOTIENT_ENCODING_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_ENCODING";
// The compact quotient VM path is the default size-oriented emitter: it stores
// identity arithmetic as data in the VK and interprets it from one small Yul
// loop. Keep the structured tail off by default so the monolithic verifier
// compiles under pinned solc; set HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=trash,
// HALO2_SOLIDITY_QUOTIENT_STRUCTURED_LOOPS=1, or HALO2_SOLIDITY_QUOTIENT_CSE=1
// for local gas/size experiments.
pub(super) const QUOTIENT_CSE_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_CSE";
pub(super) const QUOTIENT_VM_CSE_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_VM_CSE";
pub(super) const QUOTIENT_YUL_HELPERS_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_YUL_HELPERS";
pub(super) const QUOTIENT_STRUCTURED_LOOPS_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_STRUCTURED_LOOPS";
pub(super) const QUOTIENT_STRUCTURED_TAIL_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL";
pub(super) const QUOTIENT_NATIVE_PERMUTATION_ENV: &str =
    "HALO2_SOLIDITY_QUOTIENT_NATIVE_PERMUTATION";
pub(super) const QUOTIENT_LIMB_VM_OPS_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_LIMB_VM_OPS";
pub(super) const QUOTIENT_SHAPE_PROFILE_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_SHAPE_PROFILE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CodegenOptions {
    pub(super) hybrid_quotient_inline_identities: usize,
    pub(super) quotient_native_gates: usize,
    pub(super) quotient_encoding: QuotientProgramEncoding,
    pub(super) quotient_inline_cse: bool,
    pub(super) quotient_vm_cse: bool,
    pub(super) quotient_yul_helpers: bool,
    pub(super) quotient_structured_loops: bool,
    pub(super) quotient_structured_tail: QuotientStructuredTailMode,
    pub(super) quotient_native_permutation: bool,
    pub(super) quotient_limb_vm_ops: bool,
    pub(super) quotient_shape_profile: bool,
}

impl CodegenOptions {
    pub(super) fn from_env() -> Self {
        Self {
            hybrid_quotient_inline_identities: parse_usize_env(
                HYBRID_QUOTIENT_INLINE_IDENTITIES_ENV,
                DEFAULT_HYBRID_QUOTIENT_INLINE_IDENTITIES,
            ),
            quotient_native_gates: parse_usize_env(
                QUOTIENT_NATIVE_GATES_ENV,
                DEFAULT_QUOTIENT_NATIVE_GATES,
            ),
            quotient_encoding: parse_quotient_encoding(),
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
            quotient_limb_vm_ops: parse_bool_env(
                QUOTIENT_LIMB_VM_OPS_ENV,
                false,
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

fn parse_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

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

fn parse_structured_tail() -> QuotientStructuredTailMode {
    let Ok(value) = std::env::var(QUOTIENT_STRUCTURED_TAIL_ENV) else {
        return QuotientStructuredTailMode::Off;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => QuotientStructuredTailMode::Off,
        "1" | "true" | "on" | "yes" | "tail" | "trash" => QuotientStructuredTailMode::Trash,
        other => panic!("unsupported {QUOTIENT_STRUCTURED_TAIL_ENV}={other}; use off or trash"),
    }
}
