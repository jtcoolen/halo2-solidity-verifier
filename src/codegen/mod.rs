use crate::codegen::{
    artifact::{PackedProgramCodec, PayloadSectionKind, VkPayloadLayout},
    evaluator::Evaluator,
    memory::{VerifierMemoryLayout, VerifierMemoryLayoutConfig, G1_BYTES, WORD_BYTES},
    template::{
        Halo2QuotientEvaluator, Halo2Verifier, Halo2VerifyingKey, QuotientExternal,
        QuotientProgram, UserPhase,
    },
    util::{
        fe_to_u256, g1_to_u256s, g2_to_u256s, ConstraintSystemMeta, Data, Location, Ptr, Value,
        Word,
    },
};
// midnight-proofs migration: VerifyingKey is generic over (F, CS), where F
// = midnight_curves::Fq (BLS12-381 scalar) and CS = KZGCommitmentScheme<Bls12>.
// All embedded commitments are now `G1Projective`; we convert them to
// affine before EIP-2537 packing. ParamsKZG carries the SRS in the same
// form as halo2 v0.4 (bare G1/G2 fields), but the public accessors only
// expose `g_lagrange()`, `g2()`, `s_g2()`. The G1 generator is read from
// `G1Affine::generator()` directly.
use ff::{Field, PrimeField};
use group::{prime::PrimeCurveAffine, Curve};
use itertools::chain;
use midnight_curves::{Bls12, Fq, G1Affine, G1Projective, G2Affine};
use midnight_proofs::{
    plonk::{Expression, Selector, VerifyingKey},
    poly::{
        kzg::{params::ParamsKZG, KZGCommitmentScheme},
        Rotation,
    },
};
use ruint::aliases::U256;
use sha3::{Digest, Keccak256};
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Debug},
};

mod artifact;
mod config;
mod evaluator;
mod generator;
mod memory;
mod pcs;
mod protocol;
mod quotient;
mod template;
pub(crate) mod util;

use config::*;
pub use pcs::BatchOpenScheme;
#[cfg(test)]
pub(crate) use quotient::RepackedProofScalarLayout;
use quotient::*;

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

/// Errors returned when a constraint system is outside the currently
/// supported Midfall Solidity verifier shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneratorError {
    /// A verifier with no advice commitments has no proof commitment phase to
    /// bind into the Fiat-Shamir transcript.
    NoAdviceColumns,
    /// The current proof layout supports at most one committed and one
    /// non-committed instance column.
    TooManyInstanceColumns { actual: usize, max: usize },
    /// Instance columns are read as direct public inputs and locally
    /// Lagrange-interpolated only at the current row.
    RotatedInstanceQuery { column: usize, rotation: i32 },
}

impl fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAdviceColumns => {
                write!(f, "at least one advice column is required")
            }
            Self::TooManyInstanceColumns { actual, max } => write!(
                f,
                "too many instance columns: got {actual}, maximum supported is {max}"
            ),
            Self::RotatedInstanceQuery { column, rotation } => write!(
                f,
                "rotated instance query is not supported: column {column}, rotation {rotation}"
            ),
        }
    }
}

impl std::error::Error for GeneratorError {}

/// Field-evaluation counts for the proof layout consumed by the generated
/// Solidity verifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProofEvaluationCounts {
    /// Committed instance-query evaluations read from the proof.
    pub committed_instance: usize,
    /// Non-committed instance-query evaluations reconstructed from calldata
    /// public inputs, not read from the proof.
    pub computed_instance: usize,
    /// Advice-query evaluations read from the proof.
    pub advice: usize,
    /// Non-simple fixed-column evaluations read from the proof.
    pub fixed: usize,
    /// Simple selector fixed columns synthesized/handled via selector
    /// commitments instead of proof eval scalars.
    pub simple_selector_fixed: usize,
    /// Permutation common/sigma evaluations read from the proof.
    pub permutation_common: usize,
    /// Permutation product evaluations (`z_cur`, `z_next`, and non-final
    /// `z_last`) read from the proof.
    pub permutation_product: usize,
    /// Number of permutation product sets.
    pub permutation_sets: usize,
    /// Lookup multiplicity evaluations read from the proof.
    pub lookup_multiplicity: usize,
    /// Lookup helper evaluations read from the proof.
    pub lookup_helper: usize,
    /// Lookup accumulator evaluations (`z`, `z_next`) read from the proof.
    pub lookup_accumulator: usize,
    /// Trash argument evaluations read from the proof.
    pub trash: usize,
    /// Dummy eval scalars appended for the `fewer-point-sets` PCS layout.
    pub dummy: usize,
}

impl ProofEvaluationCounts {
    /// Main proof eval scalars, excluding dummy PCS evals.
    pub fn proof_main_total(&self) -> usize {
        self.committed_instance
            + self.advice
            + self.fixed
            + self.permutation_common
            + self.permutation_product
            + self.lookup_multiplicity
            + self.lookup_helper
            + self.lookup_accumulator
            + self.trash
    }

    /// All proof eval scalars consumed by the generated Solidity verifier.
    pub fn proof_total(&self) -> usize {
        self.proof_main_total() + self.dummy
    }

    /// Instance evals available to identity reconstruction, including those
    /// computed locally from public inputs.
    pub fn instance_total_for_identities(&self) -> usize {
        self.committed_instance + self.computed_instance
    }

    /// Total permutation eval scalars read from the proof.
    pub fn permutation_total(&self) -> usize {
        self.permutation_common + self.permutation_product
    }

    /// Total lookup eval scalars read from the proof.
    pub fn lookup_total(&self) -> usize {
        self.lookup_multiplicity + self.lookup_helper + self.lookup_accumulator
    }
}
/// callers don't have to import `evm`.
pub fn encode_calldata_bls_padded(
    _generator: &SolidityGenerator<'_>,
    proof: &[u8],
    instances: &[Fq],
) -> Vec<u8> {
    crate::evm::encode_calldata(proof, instances)
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_proofs::{
        plonk::{ConstraintSystem, Constraints, FirstPhase},
        poly::Rotation,
    };
    use std::collections::HashMap;

    #[derive(Default)]
    struct TestQuotientExpressionEnv {
        fixed: HashMap<(usize, i32), QuotientExpr>,
        advice: HashMap<(usize, i32), QuotientExpr>,
        instance: HashMap<(usize, i32), QuotientExpr>,
        challenges: HashMap<usize, QuotientExpr>,
    }

    impl QuotientExpressionEnv for TestQuotientExpressionEnv {
        fn selector(&self, _selector: Selector) -> QuotientExpr {
            panic!("test expression should not contain selectors")
        }

        fn fixed(&self, column_index: usize, rotation: i32) -> QuotientExpr {
            self.fixed[&(column_index, rotation)].clone()
        }

        fn advice(&self, column_index: usize, rotation: i32) -> QuotientExpr {
            self.advice[&(column_index, rotation)].clone()
        }

        fn instance(&self, column_index: usize, rotation: i32) -> QuotientExpr {
            self.instance[&(column_index, rotation)].clone()
        }

        fn challenge(&self, index: usize) -> QuotientExpr {
            self.challenges[&index].clone()
        }
    }

    #[test]
    fn scalar_le_to_be_word_reverses_exactly_one_word() {
        let mut le = [0u8; 32];
        le[0] = 0x01;
        le[1] = 0x23;
        le[30] = 0xab;
        le[31] = 0xcd;

        let be = scalar_le_to_be_word(&le);
        assert_eq!(be[0], 0xcd);
        assert_eq!(be[1], 0xab);
        assert_eq!(be[30], 0x23);
        assert_eq!(be[31], 0x01);
    }

    #[test]
    fn external_quotient_frame_covers_vk_and_eval_memory() {
        let frame =
            SolidityGenerator::quotient_external_frame_from_bounds(0x1000, 0x300, 0x1400, 7, 3);
        assert_eq!(frame.frame_base, 0x1000);
        assert_eq!(frame.frame_len, 0x4e0);
        assert_eq!(frame.output_len, 0xa0);
        assert_eq!(frame.magic, QUOTIENT_EXTERNAL_MAGIC);
    }

    #[test]
    fn compact_quotient_default_matches_gas_capped_ivc_setting() {
        assert_eq!(DEFAULT_QUOTIENT_NATIVE_GATES, 4);

        let docs = include_str!("../../docs/QUOTIENT_NUMERATOR_EVALUATOR.md");
        assert!(
            docs.contains("total gas: `1,614,572`"),
            "quotient evaluator docs should record the gas-capped compact default bench"
        );
        assert!(
            docs.contains("quotient runtime: `21,774` bytes"),
            "quotient evaluator docs should record the compact default runtime"
        );
        assert!(
            docs.contains("HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=N"),
            "quotient evaluator docs should describe the experimental tuning hook"
        );
    }

    #[test]
    fn quotient_forward_y_batch_matches_rust_reverse_fold() {
        let y = Fq::from(17u64);
        let evals = [
            Fq::from(3u64),
            Fq::from(5u64),
            Fq::from(7u64),
            Fq::from(11u64),
            Fq::from(13u64),
        ];

        let solidity_forward = evals.iter().fold(Fq::ZERO, |acc, eval| acc * y + eval);

        let mut rust_reverse = Fq::ZERO;
        let mut y_pow = Fq::ONE;
        for eval in evals.iter().rev() {
            rust_reverse += *eval * y_pow;
            y_pow *= y;
        }

        assert_eq!(solidity_forward, rust_reverse);
    }

    #[test]
    fn quotient_selector_inverse_fold_matches_final_scale() {
        let y = Fq::from(19u64);
        let y_inv = y.invert().unwrap();
        let evals = [
            Fq::from(2u64),
            Fq::from(0u64),
            Fq::from(23u64),
            Fq::from(29u64),
        ];
        let selector_positions = [true, false, true, true];

        let mut scale = Fq::ONE;
        let mut inv_scale = Fq::ONE;
        let mut selector_acc = Fq::ZERO;
        for (eval, selected) in evals.iter().zip(selector_positions) {
            scale *= y;
            inv_scale *= y_inv;
            if selected {
                selector_acc += *eval * inv_scale;
            }
        }
        let solidity_selector_acc = selector_acc * scale;

        let mut rust_selector_acc = Fq::ZERO;
        let mut y_pow = Fq::ONE;
        for (eval, selected) in evals.iter().zip(selector_positions).rev() {
            if selected {
                rust_selector_acc += *eval * y_pow;
            }
            y_pow *= y;
        }

        assert_eq!(solidity_selector_acc, rust_selector_acc);
    }

    #[test]
    fn limb7_linear_chain_is_recognized_as_native_helper_call() {
        let lines = [
            "let c0 := 0x100000000000000",
            "let m0 := mulmod(c0, x1, r)",
            "let a0 := addmod(x0, m0, r)",
            "let m1 := mulmod(0x10000000000000000000000000000, x2, r)",
            "let a1 := addmod(a0, m1, r)",
            "let m2 := mulmod(0x400000000, x3, r)",
            "let a2 := addmod(a1, m2, r)",
            "let m3 := mulmod(0x40000000000000000000000, x4, r)",
            "let a3 := addmod(a2, m3, r)",
            "let m4 := mulmod(0x1000, x5, r)",
            "let a4 := addmod(a3, m4, r)",
            "let m5 := mulmod(0x100000000000000000, x6, r)",
            "let a5 := addmod(a4, m5, r)",
        ]
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

        let specialized = SolidityGenerator::specialize_limb7_chains(&lines);

        assert_eq!(
            specialized,
            vec![
                "let c0 := 0x100000000000000".to_string(),
                "let a5 := q_limb7(x0, x1, x2, x3, x4, x5, x6)".to_string(),
            ]
        );
    }

    #[test]
    fn transcript_memory_bound_handles_wide_bls_advice_phase() {
        let mut cs = ConstraintSystem::default();
        let mut advices = Vec::new();
        for _ in 0..64 {
            advices.push(cs.advice_column());
        }
        cs.create_gate("open wide advice phase", |meta| {
            let acc = advices
                .iter()
                .fold(Expression::Constant(Fq::ZERO), |acc, col| {
                    acc + meta.query_advice(*col, Rotation::cur())
                });
            Constraints::without_selector(vec![("open wide advice phase", acc)])
        });
        let meta = ConstraintSystemMeta::new(&cs, 0);

        let words = SolidityGenerator::transcript_buffer_words_bound(&meta, 0);

        // Regression for the BN254-era `n * 2 + 1` sizing bug: the BLS
        // transcript absorbs each proof commitment as a 128-byte
        // EIP-2537-padded G1, so 64 first-phase advice commitments need
        // vk_digest + committed_pi + num_instances + 64 G1s + squeeze seed.
        let first_phase_run = 32 + 128 + 32 + 64 * 128 + 32;
        assert!(words * 0x20 >= first_phase_run);
        assert!(
            words > 64 * 2 + 1,
            "transcript memory bound must not regress to the BN254 stride"
        );
    }

    #[test]
    fn eip2537_calls_use_bounded_gas_helpers() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let pcs_codegen = include_str!("pcs/gwc19.rs");

        for source in [verifier_template, pcs_codegen] {
            assert!(
                !source.contains("staticcall(gas(), 0x0b"),
                "G1ADD calls must use bounded gas caps"
            );
            assert!(
                !source.contains("staticcall(gas(), 0x0c"),
                "G1MSM calls must use bounded gas caps"
            );
            assert!(
                !source.contains("staticcall(gas(), 0x0f"),
                "pairing calls must use bounded gas caps"
            );
        }

        assert!(verifier_template.contains("function g1add_gas_cap()"));
        assert!(verifier_template.contains("function g1msm_gas_cap(input_len)"));
        assert!(verifier_template.contains("function pairing_gas_cap(input_len)"));
        assert!(pcs_codegen.contains("g1msm_gas_cap"));
        assert!(pcs_codegen.contains("g1add_gas_cap"));
    }

    #[test]
    fn failed_success_paths_do_not_enter_ec_precompiles() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let pcs_codegen = include_str!("pcs/gwc19.rs");

        assert!(
            verifier_template.contains("if iszero(success) { revert(0, 0) }\n            }\n\n            {%- if self.gas_checkpoints %}\n            gas_checkpoint(2)"),
            "ABI/proof length/instance shape checks should fail before transcript parsing"
        );
        assert!(
            verifier_template.contains(
                "if iszero(success) { revert(0, 0) }\n\n            {%- match quotient_external %}"
            ),
            "failed Lagrange/common-polynomial setup should fail before quotient reconstruction"
        );
        for source in [verifier_template, pcs_codegen] {
            assert!(
                !source.contains("and(success, staticcall"),
                "Yul does not short-circuit and(success, staticcall(...)); guard precompile calls with if success"
            );
            assert!(
                !source.contains("and(\n                            success,\n                            staticcall"),
                "multi-line and(success, staticcall(...)) must not reappear"
            );
        }
        assert!(
            verifier_template.contains("ret := success\n                if iszero(ret) { leave }"),
            "ec_pairing should leave before staging/calling the pairing precompile when success is false"
        );
        assert!(
            pcs_codegen.contains("if success {")
                && pcs_codegen.contains("success := staticcall(g1msm_gas_cap")
                && pcs_codegen.contains("success := staticcall(g1add_gas_cap"),
            "PCS emitter should guard final MSM/add precompile calls with if success"
        );
    }

    #[test]
    fn verifier_constructor_smoke_tests_eip2537_precompiles() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        assert!(
            verifier_template.contains("function require_eip2537_precompiles() private view"),
            "generated verifier should include a deployment-time EIP-2537 smoke test"
        );
        for required in [
            "G1ADD(identity, identity) -> identity",
            "G1MSM([(identity, 0)]) -> identity",
            "PAIRING_CHECK([(identity_g1, identity_g2)]) -> true",
            "staticcall(50000, 0x0b",
            "staticcall(60000, 0x0c",
            "staticcall(120000, 0x0f",
            "eq(returndatasize(), 0x80)",
            "eq(returndatasize(), 0x20)",
        ] {
            assert!(
                verifier_template.contains(required),
                "constructor precompile smoke test missing expected check: {required}"
            );
        }
        assert_eq!(
            verifier_template
                .matches("require_eip2537_precompiles();")
                .count(),
            4,
            "every generated constructor shape should run the precompile smoke test"
        );
        assert!(
            verifier_template.contains("support MCOPY and EIP-2537"),
            "generated source should state the target-chain opcode/precompile requirement"
        );
    }

    #[test]
    fn external_quotient_template_has_no_unpinned_fallback() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        assert!(
            !verifier_template.contains("AUTHORIZED_QUOTIENT_CODEHASH"),
            "external quotient builds must use generated expected length/hash constants"
        );
        assert!(
            !verifier_template.contains("authorizedQuotient.code.length != 0"),
            "constructor must not pin whichever quotient address the deployer passed"
        );
    }

    #[test]
    fn accumulator_schema_is_checked_against_instance_count() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        assert!(
            verifier_template.contains("let acc_expected_words :="),
            "accumulator verifier must compute the generated public-input schema width"
        );
        assert!(
            verifier_template.contains("eq(mload(NUM_INSTANCES_MPTR), acc_expected_words)"),
            "accumulator verifier must reject extra or missing accumulator tail words"
        );
        assert!(
            verifier_template.contains("RHS layout for this generated verifier is fully collapsed"),
            "no-tail accumulator renders must explicitly document that no fixed-base scalar tail exists"
        );
        assert!(
            verifier_template.contains("RHS layout for this generated verifier is partially"),
            "tail accumulator renders must explicitly document fixed-base scalar tail semantics"
        );
        assert!(
            verifier_template.contains("{%- if acc_fixed_bases.len() > 0 %}"),
            "fixed-base scalar tail parsing should only render when generated bases exist"
        );
    }

    #[test]
    fn accumulator_vk_header_is_checked_against_codegen_metadata() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        for expected_check in [
            "eq(mload(HAS_ACCUMULATOR_MPTR)",
            "eq(mload(ACC_OFFSET_MPTR)",
            "eq(mload(NUM_ACC_LIMBS_MPTR)",
            "eq(mload(NUM_ACC_LIMB_BITS_MPTR)",
        ] {
            assert!(
                verifier_template.contains(expected_check),
                "verifier must check VK accumulator metadata against generated codegen constants: {expected_check}"
            );
        }
        assert!(
            verifier_template.contains("the VK header agrees"),
            "template should document why accumulator metadata is checked before instance decoding"
        );
    }

    #[test]
    fn accumulator_limb_packing_is_checked_before_decoding() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        assert!(
            verifier_template.contains("function check_acc_coord_packing"),
            "accumulator decoder must reject unused high bits in packed limb words"
        );
        assert!(
            verifier_template
                .contains("ok := check_acc_coord_packing(src, bits, n, limbs_per_word)"),
            "accumulator coordinate decoding must apply packing canonicality before masking limbs"
        );
    }

    #[test]
    fn generated_solidity_pragmas_require_mcopy_capable_compiler() {
        for (name, source) in [
            (
                "Halo2Verifier.sol",
                include_str!("../../templates/Halo2Verifier.sol"),
            ),
            (
                "Halo2VerifyingKey.sol",
                include_str!("../../templates/Halo2VerifyingKey.sol"),
            ),
            (
                "Halo2QuotientEvaluator.sol",
                include_str!("../../templates/Halo2QuotientEvaluator.sol"),
            ),
        ] {
            assert!(
                source.contains("pragma solidity ^0.8.24;"),
                "{name} must require Solidity 0.8.24+ for Cancun Yul opcodes"
            );
        }
    }

    #[test]
    fn verifier_checks_canonical_dynamic_abi_heads() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        assert!(
            verifier_template.contains("eq(calldataload(0x04), 0x40)"),
            "verifier must read the proof dynamic ABI head"
        );
        assert!(
            verifier_template.contains("eq(calldataload(0x24), sub(NUM_INSTANCE_CPTR, 4))"),
            "verifier must read the instances dynamic ABI head"
        );
    }

    #[test]
    fn generated_comments_describe_padded_g1_calldata() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        for stale in [
            "zcash-compressed form",
            "decompressed inline",
            "Helpers: modexp, decompress",
            "Each compressed G1 absorbed",
            "Per-category bases for decompressed G1 commitments",
        ] {
            assert!(
                !verifier_template.contains(stale),
                "generated verifier comments must not describe the old compressed-G1 calldata path: {stale}"
            );
        }

        assert!(
            verifier_template
                .contains("proof shim repacks midnight-proofs' native compressed stream"),
            "generated verifier comments should document the off-chain repacking boundary"
        );
        assert!(
            verifier_template.contains("validates and absorbs that 128-byte form"),
            "generated verifier comments should describe the current EIP-2537-padded G1 path"
        );
    }

    #[test]
    fn point_validation_boundary_is_documented_and_plan_checked() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let protocol_source = include_str!("protocol.rs");
        let test_source = include_str!("../test.rs");

        assert!(
            verifier_template.contains("This helper does not run an independent curve/subgroup"),
            "common_uncompressed_g1 should document that curve/subgroup checks are delegated"
        );
        assert!(
            verifier_template.contains("consumed by an EIP-2537 G1MSM or pairing path"),
            "generated comments should name the subgroup-checking precompile paths"
        );
        assert!(
            protocol_source.contains("Every proof G1 commitment absorbed into Fiat-Shamir"),
            "ProtocolPlan validation should document absorbed-point PCS/precompile coverage"
        );
        assert!(
            protocol_source.contains("absorbed but never opened by PCS"),
            "ProtocolPlan validation should reject absorbed unopened advice commitments"
        );
        for required_test in [
            "every_proof_g1_rejects_noncanonical_coordinates",
            "every_proof_g1_rejects_off_curve_coordinates",
        ] {
            assert!(
                test_source.contains(required_test),
                "negative proof-G1 mutation coverage should include {required_test}"
            );
        }
    }

    #[test]
    fn trace_u256_uses_planned_memory_slot() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let quotient_template = include_str!("../../templates/Halo2QuotientEvaluator.sol");
        let memory_source = include_str!("memory.rs");

        for source in [verifier_template, quotient_template] {
            assert!(
                source.contains("TRACE_U256_MPTR"),
                "trace_u256 should write through a planned memory slot"
            );
            assert!(
                !source.contains("0x5e00"),
                "trace_u256 must not use the old hard-coded scratch word"
            );
        }
        assert!(
            memory_source.contains("trace_u256_log_word"),
            "memory planner should register the trace_u256 log buffer"
        );
    }

    #[test]
    fn batch_invert_handles_empty_and_singleton_ranges() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        assert!(
            verifier_template.contains("let count_bytes := sub(mptr_end, mptr_start)"),
            "batch inversion must compute the requested range length"
        );
        assert!(
            verifier_template.contains("if iszero(count_bytes) { leave }"),
            "empty batch inversion ranges should be a no-op"
        );
        assert!(
            verifier_template.contains("if eq(count_bytes, 0x20)"),
            "singleton batch inversion ranges need a dedicated path"
        );
        assert!(
            verifier_template.contains("if ret { mstore(mptr_start, mload(single_scratch)) }"),
            "singleton batch inversion must store the single inverse in place"
        );
    }

    #[test]
    fn production_verifier_documents_revert_or_true_policy() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        assert!(
            verifier_template.contains("success-or-revert"),
            "verifyProof NatSpec must document invalid-proof failure semantics"
        );
        assert!(
            verifier_template.contains("error InvalidVerifierDependency();"),
            "pinned dependency failures should use an explicit custom error"
        );
        assert!(
            verifier_template.contains("revert InvalidVerifierDependency();"),
            "pinned dependency preflight failures should revert, not return false"
        );
        assert!(
            !verifier_template.contains("return false;"),
            "generated verifier should not mix false returns with revert-on-invalid semantics"
        );
    }

    #[test]
    fn templates_use_planned_memory_slots_for_theta_and_commitment_layout() {
        for (name, source) in [
            (
                "Halo2Verifier",
                include_str!("../../templates/Halo2Verifier.sol"),
            ),
            (
                "Halo2QuotientEvaluator",
                include_str!("../../templates/Halo2QuotientEvaluator.sol"),
            ),
        ] {
            assert!(
                !source.contains("theta_mptr +"),
                "{name} should render named planned theta-relative slots"
            );
            assert!(
                !source.contains("comms_mptr_base +"),
                "{name} should render named planned commitment bases"
            );
        }
    }

    #[test]
    fn final_msm_pair_count_is_a_codegen_assertion() {
        let source = include_str!("pcs/gwc19.rs");

        assert!(
            source.contains("pair_idx, final_msm_terms"),
            "PCS emission should compare emitted final MSM pairs with the planned shape"
        );
        assert!(
            source.contains("final MSM input term count changed during emission"),
            "PCS emission should fail loudly if final MSM shape and Yul emission diverge"
        );
        assert!(
            !source.contains("debug_assert_eq!(\n            pair_idx, final_msm_terms"),
            "final MSM shape mismatches must not be debug-only"
        );
    }

    #[test]
    fn verify_proof_natspec_requires_application_binding() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        for required in [
            "checks only that `proof` verifies for the supplied public",
            "Application contracts must",
            "state roots",
            "program",
            "expected IVC outputs",
            "chain/domain separation",
        ] {
            assert!(
                verifier_template.contains(required),
                "verifyProof NatSpec must document application binding requirement: {required}"
            );
        }
    }

    #[test]
    fn production_verifier_entrypoint_is_external_view() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        assert!(
            verifier_template.contains(") external {%- if self.trace || self.gas_checkpoints %} returns (bool) {%- else %} view returns (bool) {%- endif %}"),
            "generated verifyProof entrypoint should render as external view in production"
        );
        assert!(
            !verifier_template.contains(") public {%- if self.trace || self.gas_checkpoints %}"),
            "production verifier should not expose the calldata entrypoint as public"
        );
    }

    #[test]
    fn gas_checkpoints_are_debug_only_template_paths() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let lib_source = include_str!("../lib.rs");

        assert!(
            verifier_template.contains("{%- if self.gas_checkpoints %}\n            // Section-boundary gas-attribution checkpoint"),
            "gas checkpoint helper must be guarded by the gas-checkpoint template flag"
        );
        assert_eq!(
            verifier_template.matches("gas_checkpoint(").count(),
            verifier_template
                .matches("{%- if self.gas_checkpoints")
                .count(),
            "every gas_checkpoint definition/call should have its own self.gas_checkpoints guard"
        );
        assert!(
            verifier_template.contains(") external {%- if self.trace || self.gas_checkpoints %} returns (bool) {%- else %} view returns (bool) {%- endif %}"),
            "production renders should stay external view unless trace/gas logs are enabled"
        );
        assert!(
            lib_source.contains("pub const SOLIDITY_GAS_CHECKPOINTS_ENABLED"),
            "gas checkpoints should remain an explicit feature flag"
        );
        assert!(
            lib_source.contains("render_with_gas_checkpoints*"),
            "docs should call out the explicit benchmarking render helpers"
        );
    }

    #[test]
    fn truncated_challenge_comments_cover_x1_x4_power_masks() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let gwc19_codegen = include_str!("pcs/gwc19.rs");

        assert!(
            verifier_template.contains("x1 and x4 remain full squeezed Fr words"),
            "x3 squeeze comment must clarify that x1/x4 are handled by truncated powers"
        );
        assert!(
            verifier_template.contains("truncate(x1^i) and truncate(x4^i)"),
            "verifier template should document the PCS power truncation rule"
        );
        assert!(
            gwc19_codegen.contains("proofs/src/poly/kzg/mod.rs computes"),
            "x1 power generation should point back to the Rust verifier source"
        );
        assert!(
            gwc19_codegen.contains("power[i] = truncate(x1^i)"),
            "x1 power generation should document truncated_powers(x1)"
        );
        assert!(
            gwc19_codegen.contains("truncated_powers(x4)[i] = truncate(x4^i)"),
            "x4 power generation should document truncated_powers(x4)"
        );
        assert!(
            gwc19_codegen.contains("mstore(p, and(acc, {TRUNC_MASK_128}))"),
            "x1 emitted powers must be masked under truncated-challenges"
        );
        assert!(
            gwc19_codegen.contains("let x4_pow_{s} := and(x4_pow_full, {TRUNC_MASK_128})"),
            "x4 emitted powers must be masked under truncated-challenges"
        );
    }

    #[test]
    fn generated_heavy_assemblies_keep_memory_safe_for_via_ir() {
        for (name, source) in [
            (
                "Halo2Verifier.sol",
                include_str!("../../templates/Halo2Verifier.sol"),
            ),
            (
                "Halo2QuotientEvaluator.sol",
                include_str!("../../templates/Halo2QuotientEvaluator.sol"),
            ),
        ] {
            assert!(
                source.contains("assembly (\"memory-safe\")"),
                "{name} needs memory-safe assembly annotations for solc via-IR stack allocation"
            );
        }
    }

    #[test]
    fn generator_restriction_errors_are_typed() {
        assert_eq!(
            GeneratorError::TooManyInstanceColumns { actual: 3, max: 2 }.to_string(),
            "too many instance columns: got 3, maximum supported is 2"
        );
        assert_eq!(
            GeneratorError::RotatedInstanceQuery {
                column: 1,
                rotation: -1,
            }
            .to_string(),
            "rotated instance query is not supported: column 1, rotation -1"
        );
        let stale = ["not", " yet ", "implemented"].concat();
        assert!(
            !include_str!("mod.rs").contains(&stale),
            "unsupported verifier shapes should be surfaced as GeneratorError values"
        );
    }

    #[test]
    fn permutation_delta_literal_is_computed_from_field_constant() {
        let computed = u256_string(fe_to_u256::<Fq>(&Fq::DELTA));

        assert_eq!(fr_delta_literal(), computed);
        assert!(
            !include_str!("mod.rs").contains(&computed),
            "codegen source should not hard-code the current Fr::DELTA decimal/hex literal"
        );
    }

    #[test]
    fn verifier_template_omits_dead_constants_and_ec_helpers() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        for stale in [
            "FIRST_QUOTIENT_X_CPTR",
            "LAST_QUOTIENT_X_CPTR",
            "G1_SCALAR_MPTR",
            "function ec_add_acc",
            "function ec_mul_acc",
            "function ec_add_tmp",
            "function ec_mul_tmp",
        ] {
            assert!(
                !verifier_template.contains(stale),
                "production verifier template should not keep dead helper/constant: {stale}"
            );
        }
    }

    #[test]
    fn expression_lowering_matches_quotient_vm_eval() {
        let mut cs = ConstraintSystem::default();
        let advice = cs.advice_column();
        let fixed = cs.fixed_column();
        let instance = cs.instance_column();
        let challenge = cs.challenge_usable_after(FirstPhase);
        cs.create_gate("typed lowering", |meta| {
            let a = meta.query_advice(advice, Rotation::next());
            let f = meta.query_fixed(fixed, Rotation::prev());
            let i = meta.query_instance(instance, Rotation::cur());
            let c = meta.query_challenge(challenge);
            let seven = Expression::Constant(Fq::from(7u64));
            Constraints::without_selector(vec![(
                "typed lowering",
                a.clone() * f.clone() + i.clone() * c.clone() + seven * a - f,
            )])
        });
        let expr = cs.gates()[0].polynomials()[0].clone();

        let mut values = HashMap::new();
        values.insert(0x100, Fq::from(11u64));
        values.insert(0x120, Fq::from(13u64));
        values.insert(0x140, Fq::from(17u64));
        values.insert(0x160, Fq::from(19u64));

        let mut env = TestQuotientExpressionEnv::default();
        env.advice.insert(
            (advice.index(), 1),
            QuotientExpr::Mem(QuotientMem::Literal(0x100)),
        );
        env.fixed.insert(
            (fixed.index(), -1),
            QuotientExpr::Mem(QuotientMem::Literal(0x120)),
        );
        env.instance.insert(
            (instance.index(), 0),
            QuotientExpr::Mem(QuotientMem::Literal(0x140)),
        );
        env.challenges.insert(
            challenge.index(),
            QuotientExpr::Mem(QuotientMem::Literal(0x160)),
        );

        let expected = expr.evaluate(
            &|scalar| scalar,
            &|_| panic!("test expression should not contain selectors"),
            &|_query| values[&0x120],
            &|query| {
                assert_eq!(query.rotation(), Rotation::next());
                values[&0x100]
            },
            &|query| {
                assert_eq!(query.rotation(), Rotation::cur());
                values[&0x140]
            },
            &|_| values[&0x160],
            &|inner| -inner,
            &|lhs, rhs| lhs + rhs,
            &|lhs, rhs| lhs * rhs,
            &|inner, scalar| inner * scalar,
        );

        let lowered = quotient_expr_from_expression(&env, &expr);
        let mut builder = QuotientProgramBuilder::default();
        builder.emit_expr(&lowered);
        let actual = eval_quotient_vm_for_test(&builder.bytes, &builder.consts, &values);
        assert_eq!(actual, expected);
    }

    #[test]
    fn quotient_vm_lin7_matches_direct_expr_eval() {
        let mut values = HashMap::new();
        let mut expr = QuotientExpr::Const(U256::ZERO);
        for i in 0..7u32 {
            let ptr = 0x300 + i * 0x20;
            values.insert(ptr, Fq::from(11 + i as u64));
            expr = quotient_add_expr(
                expr,
                quotient_scale_expr(
                    Fq::from(3 + i as u64),
                    QuotientExpr::Mem(QuotientMem::Literal(ptr)),
                ),
            );
        }

        let expected = eval_quotient_expr_for_test(&expr, &values);
        let mut builder = QuotientProgramBuilder::with_limb_vm_ops(true);
        builder.emit_expr(&expr);

        assert_eq!(builder.bytes[0], Q_OP_LIN7);
        assert_eq!(
            eval_quotient_vm_for_test(&builder.bytes, &builder.consts, &values),
            expected
        );
    }

    #[test]
    fn quotient_vm_bilin7_row_matches_direct_expr_eval() {
        let lhs = 0x440;
        let mut values = HashMap::new();
        values.insert(lhs, Fq::from(29u64));
        let mut expr = QuotientExpr::Const(U256::ZERO);
        for i in 0..7u32 {
            let rhs = 0x500 + i * 0x20;
            values.insert(rhs, Fq::from(37 + i as u64));
            expr = quotient_add_expr(
                expr,
                quotient_scale_expr(
                    Fq::from(5 + i as u64),
                    quotient_mul_expr(
                        QuotientExpr::Mem(QuotientMem::Literal(lhs)),
                        QuotientExpr::Mem(QuotientMem::Literal(rhs)),
                    ),
                ),
            );
        }

        let expected = eval_quotient_expr_for_test(&expr, &values);
        let mut builder = QuotientProgramBuilder::with_limb_vm_ops(true);
        builder.emit_expr(&expr);

        assert_eq!(builder.bytes[0], Q_OP_BILIN7_ROW);
        assert_eq!(
            eval_quotient_vm_for_test(&builder.bytes, &builder.consts, &values),
            expected
        );
    }

    #[test]
    fn quotient_vm_bilin7_pairwise_matches_direct_expr_eval() {
        let lhs_base = 0x620;
        let rhs_base = 0x820;
        let mut values = HashMap::new();
        for i in 0..7u32 {
            values.insert(lhs_base + i * 0x20, Fq::from(41 + i as u64));
            values.insert(rhs_base + i * 0x20, Fq::from(71 + i as u64));
        }

        let mut expr = QuotientExpr::Const(U256::ZERO);
        for i in 0..7u32 {
            for j in 0..7u32 {
                expr = quotient_add_expr(
                    expr,
                    quotient_scale_expr(
                        Fq::from(9 + i as u64 + j as u64),
                        quotient_mul_expr(
                            QuotientExpr::Mem(QuotientMem::Literal(lhs_base + i * 0x20)),
                            QuotientExpr::Mem(QuotientMem::Literal(rhs_base + j * 0x20)),
                        ),
                    ),
                );
            }
        }

        let expected = eval_quotient_expr_for_test(&expr, &values);
        let mut builder = QuotientProgramBuilder::with_limb_vm_ops(true);
        builder.emit_expr(&expr);

        assert_eq!(builder.bytes[0], Q_OP_BILIN7_PAIRWISE);
        assert_eq!(
            eval_quotient_vm_for_test(&builder.bytes, &builder.consts, &values),
            expected
        );
    }

    #[test]
    fn unmatched_limb_shape_falls_back_to_existing_vm_ops() {
        let mut values = HashMap::new();
        let mut expr = QuotientExpr::Const(U256::ZERO);
        for i in 0..6u32 {
            let ptr = 0x980 + i * 0x20;
            values.insert(ptr, Fq::from(101 + i as u64));
            expr = quotient_add_expr(
                expr,
                quotient_scale_expr(
                    Fq::from(17 + i as u64),
                    QuotientExpr::Mem(QuotientMem::Literal(ptr)),
                ),
            );
        }

        let expected = eval_quotient_expr_for_test(&expr, &values);
        let mut builder = QuotientProgramBuilder::with_limb_vm_ops(true);
        builder.emit_expr(&expr);

        assert_ne!(builder.bytes[0], Q_OP_LIN7);
        assert_eq!(
            eval_quotient_vm_for_test(&builder.bytes, &builder.consts, &values),
            expected
        );
    }

    #[test]
    fn native_arithmetic_linear_next_run_stays_structured() {
        let run = (0..3usize)
            .map(|idx| {
                let off = idx * 0x20;
                (
                    vec![
                        "let var0 := 0x1".to_string(),
                        format!("let a := mload({:#x})", 0x1000 + off),
                        format!("let f := mload({:#x})", 0x2000 + off),
                        "let sum := addmod(a, f, r)".to_string(),
                        format!("let next := mload({:#x})", 0x3000 + off),
                        "let neg_next := sub(r, next)".to_string(),
                        "let eval := addmod(sum, neg_next, r)".to_string(),
                        "let out := mulmod(var0, eval, r)".to_string(),
                    ],
                    "out".to_string(),
                )
            })
            .collect::<Vec<_>>();

        let (count, block) =
            SolidityGenerator::selector_linear_next_loop_block(&run).expect("linear run");

        assert_eq!(count, 3);
        assert!(
            block.iter().any(|line| line.contains("q_gate_lin_i")),
            "arith/parallel-add linear-next identities should keep the existing loop lowering"
        );
    }

    fn quotient_add_expr(lhs: QuotientExpr, rhs: QuotientExpr) -> QuotientExpr {
        QuotientExpr::Add(Box::new(lhs), Box::new(rhs))
    }

    fn quotient_mul_expr(lhs: QuotientExpr, rhs: QuotientExpr) -> QuotientExpr {
        QuotientExpr::Mul(Box::new(lhs), Box::new(rhs))
    }

    fn quotient_scale_expr(coeff: Fq, expr: QuotientExpr) -> QuotientExpr {
        QuotientExpr::Mul(
            Box::new(QuotientExpr::Const(fe_to_u256::<Fq>(&coeff))),
            Box::new(expr),
        )
    }

    fn eval_quotient_expr_for_test(expr: &QuotientExpr, mem: &HashMap<u32, Fq>) -> Fq {
        match expr {
            QuotientExpr::Const(value) => fq_from_u256(*value),
            QuotientExpr::Mem(QuotientMem::Literal(ptr)) => mem[ptr],
            QuotientExpr::Mem(QuotientMem::Token(_))
            | QuotientExpr::Mem(QuotientMem::TokenOffset(_, _)) => {
                panic!("test expressions use literal memory only")
            }
            QuotientExpr::Add(lhs, rhs) => {
                eval_quotient_expr_for_test(lhs, mem) + eval_quotient_expr_for_test(rhs, mem)
            }
            QuotientExpr::Mul(lhs, rhs) => {
                eval_quotient_expr_for_test(lhs, mem) * eval_quotient_expr_for_test(rhs, mem)
            }
            QuotientExpr::Neg(inner) => -eval_quotient_expr_for_test(inner, mem),
        }
    }

    fn eval_quotient_vm_for_test(bytes: &[u8], consts: &[U256], mem: &HashMap<u32, Fq>) -> Fq {
        let mut idx = 0usize;
        let mut stack: Vec<Fq> = Vec::new();

        while idx < bytes.len() {
            match bytes[idx] {
                Q_OP_PUSH_CONST => {
                    let slot = read_u16(bytes, idx + 1) as usize;
                    stack.push(fq_from_u256(consts[slot]));
                    idx += 3;
                }
                Q_OP_PUSH_CONST_U8 => {
                    let slot = bytes[idx + 1] as usize;
                    stack.push(fq_from_u256(consts[slot]));
                    idx += 2;
                }
                Q_OP_PUSH_MEM_U16 => {
                    let ptr = read_u16(bytes, idx + 1) as u32;
                    stack.push(mem[&ptr]);
                    idx += 3;
                }
                Q_OP_PUSH_MEM_LITERAL => {
                    let ptr = read_u32(bytes, idx + 1);
                    stack.push(mem[&ptr]);
                    idx += 5;
                }
                Q_OP_ADD => {
                    let rhs = stack.pop().expect("rhs");
                    let lhs = stack.pop().expect("lhs");
                    stack.push(lhs + rhs);
                    idx += 1;
                }
                Q_OP_MUL => {
                    let rhs = stack.pop().expect("rhs");
                    let lhs = stack.pop().expect("lhs");
                    stack.push(lhs * rhs);
                    idx += 1;
                }
                Q_OP_NEG => {
                    let value = stack.pop().expect("value");
                    stack.push(-value);
                    idx += 1;
                }
                Q_OP_ADD_CONST_U8 => {
                    let slot = bytes[idx + 1] as usize;
                    let acc = stack.pop().expect("acc");
                    stack.push(acc + fq_from_u256(consts[slot]));
                    idx += 2;
                }
                Q_OP_MUL_CONST_U8 => {
                    let slot = bytes[idx + 1] as usize;
                    let acc = stack.pop().expect("acc");
                    stack.push(acc * fq_from_u256(consts[slot]));
                    idx += 2;
                }
                Q_OP_ADD_CONST => {
                    let slot = read_u16(bytes, idx + 1) as usize;
                    let acc = stack.pop().expect("acc");
                    stack.push(acc + fq_from_u256(consts[slot]));
                    idx += 3;
                }
                Q_OP_MUL_CONST => {
                    let slot = read_u16(bytes, idx + 1) as usize;
                    let acc = stack.pop().expect("acc");
                    stack.push(acc * fq_from_u256(consts[slot]));
                    idx += 3;
                }
                Q_OP_ADD_MEM_U16 => {
                    let ptr = read_u16(bytes, idx + 1) as u32;
                    let acc = stack.pop().expect("acc");
                    stack.push(acc + mem[&ptr]);
                    idx += 3;
                }
                Q_OP_MUL_MEM_U16 => {
                    let ptr = read_u16(bytes, idx + 1) as u32;
                    let acc = stack.pop().expect("acc");
                    stack.push(acc * mem[&ptr]);
                    idx += 3;
                }
                Q_OP_ADD_MUL_MEM_MEM_CONST_U8 => {
                    let lhs = read_u16(bytes, idx + 1) as u32;
                    let rhs = read_u16(bytes, idx + 3) as u32;
                    let slot = bytes[idx + 5] as usize;
                    let acc = stack.pop().expect("acc");
                    stack.push(acc + mem[&lhs] * mem[&rhs] * fq_from_u256(consts[slot]));
                    idx += 6;
                }
                Q_OP_ADD_MUL_CONST_U8_MEM_U16 => {
                    let ptr = read_u16(bytes, idx + 1) as u32;
                    let slot = bytes[idx + 3] as usize;
                    let acc = stack.pop().expect("acc");
                    stack.push(acc + fq_from_u256(consts[slot]) * mem[&ptr]);
                    idx += 4;
                }
                Q_OP_ADD_MUL_MEM_MEM => {
                    let lhs = read_u16(bytes, idx + 1) as u32;
                    let rhs = read_u16(bytes, idx + 3) as u32;
                    let acc = stack.pop().expect("acc");
                    stack.push(acc + mem[&lhs] * mem[&rhs]);
                    idx += 5;
                }
                Q_OP_LIN7 => {
                    let mut acc = Fq::ZERO;
                    idx += 1;
                    for _ in 0..7 {
                        let slot = bytes[idx] as usize;
                        let ptr = read_u16(bytes, idx + 1) as u32;
                        acc += fq_from_u256(consts[slot]) * mem[&ptr];
                        idx += 3;
                    }
                    stack.push(acc);
                }
                Q_OP_BILIN7_ROW => {
                    let lhs = read_u16(bytes, idx + 1) as u32;
                    let lhs_value = mem[&lhs];
                    let mut acc = Fq::ZERO;
                    idx += 3;
                    for _ in 0..7 {
                        let slot = bytes[idx] as usize;
                        let rhs = read_u16(bytes, idx + 1) as u32;
                        acc += lhs_value * mem[&rhs] * fq_from_u256(consts[slot]);
                        idx += 3;
                    }
                    stack.push(acc);
                }
                Q_OP_BILIN7_PAIRWISE => {
                    let lhs_base = read_u16(bytes, idx + 1) as u32;
                    let rhs_base = read_u16(bytes, idx + 3) as u32;
                    let coeff_idx = idx + 5;
                    let mut acc = Fq::ZERO;
                    for i in 0..7 {
                        let lhs = mem[&(lhs_base + i * 0x20)];
                        for j in 0..7 {
                            let rhs = mem[&(rhs_base + j * 0x20)];
                            let slot = bytes[coeff_idx + i as usize + j as usize] as usize;
                            acc += lhs * rhs * fq_from_u256(consts[slot]);
                        }
                    }
                    idx += 18;
                    stack.push(acc);
                }
                op => panic!("unsupported test quotient VM op {op:#x} at byte {idx}"),
            }
        }

        assert_eq!(stack.len(), 1, "test VM should leave one result");
        stack.pop().unwrap()
    }

    fn fq_from_u256(value: U256) -> Fq {
        let bytes = value.to_le_bytes::<32>();
        let repr = <Fq as PrimeField>::Repr::from(bytes);
        Option::<Fq>::from(Fq::from_repr(repr)).expect("canonical field element")
    }
}
