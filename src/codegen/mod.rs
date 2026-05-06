use crate::codegen::{
    artifact::{PackedProgramCodec, PayloadSectionKind, VkPayloadLayout},
    evaluator::Evaluator,
    memory::{
        VerifierMemoryLayout, VerifierMemoryLayoutConfig, VkConstructorMemoryLayout, G1_BYTES,
        WORD_BYTES,
    },
    proof_layout::{ProofCalldataLayout, TranscriptBufferLayout},
    template::{
        Halo2QuotientEvaluator, Halo2Verifier, Halo2VerifyingKey, QuotientExternal,
        QuotientProgram, QuotientSelectorTail, QuotientVmMemUsage, QuotientVmOpcodeUsage,
        UserPhase, VerifierCodegenLayout,
    },
    util::{
        fe_to_u256, g1_to_u256s, g2_to_u256s, ConstraintSystemMeta, Data, Location, Ptr, Value,
        Word,
    },
};
// Midnight verifier inputs are generic over (F, CS), where F =
// midnight_curves::Fq and CS = KZGCommitmentScheme<Bls12>. Embedded
// commitments are converted to affine form before EIP-2537 packing. The SRS
// accessors expose `g_lagrange()`, `g2()`, and `s_g2()`; the G1 generator is
// read from `G1Affine::generator()` directly.
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
mod layout;
mod memory;
mod pcs;
mod proof_layout;
mod protocol;
mod quotient;
mod template;
pub(crate) mod util;

use config::*;
#[cfg(test)]
pub(crate) use quotient::RepackedProofScalarLayout;
use quotient::*;

/// Solidity verifier generator for midnight-proofs (logup + trash + KZG
/// multi-prepare PCS) on BLS12-381 EIP-2537.
///
/// The supported protocol shape is intentionally narrow: Midfall/Midnight
/// KZG proofs with one committed identity instance column and one
/// non-committed public-input column.
#[derive(Debug)]
pub struct SolidityGenerator<'a> {
    params: &'a ParamsKZG<Bls12>,
    vk: &'a VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
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
///
/// Accumulator verification is opt-in. A generated verifier only batches a
/// public accumulator pairing equation into the final PLONK/KZG pairing when
/// [`SolidityGenerator::set_acc_encoding`] or
/// [`SolidityGenerator::try_set_acc_encoding`] is called with `Some`.
///
/// The accumulator is encoded as a tail of the non-committed public-input
/// vector, starting at [`Self::offset`]. The default Solidity decoder supports
/// Midnight's fully-collapsed BLS12-381 accumulator layout:
///
/// ```text
/// lhs point coordinates, lhs scalar, rhs point coordinates, rhs scalar
/// ```
///
/// with each BLS12-381 base-field coordinate represented as seven radix-2^56
/// limbs, packed four limbs per public-input field element. Any public-input
/// words after the fixed accumulator payload are interpreted as the optional
/// RHS fixed-base scalar tail for partially collapsed accumulators.
#[derive(Clone, Copy, Debug)]
pub struct AccumulatorEncoding {
    /// Offset of accumulator limbs in instances.
    pub offset: usize,
    /// Number of limbs per base field element.
    pub num_limbs: usize,
    /// Number of bits per limb.
    pub num_limb_bits: usize,
    /// Public-input accumulator layout.
    pub kind: AccumulatorEncodingKind,
}

/// Public-input layouts supported by the generated accumulator checker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccumulatorEncodingKind {
    /// `AssignedAccumulator<S>::as_public_input`: lhs point, lhs scalar, rhs
    /// point, rhs scalar, followed by an optional fixed-base scalar tail.
    PointAndScalar,
    /// Already collapsed point-pair layout: lhs point, rhs point. The generated
    /// verifier treats both carried scalars as one and does not accept a
    /// fixed-base scalar tail.
    PointPair,
}

impl AccumulatorEncoding {
    /// Supported limb count for one BLS12-381 base-field coordinate.
    pub const SUPPORTED_NUM_LIMBS: usize = layout::accumulator::LIMBS;
    /// Supported bits per accumulator limb.
    pub const SUPPORTED_NUM_LIMB_BITS: usize = layout::accumulator::LIMB_BITS;
    /// Public-input words required by the fully collapsed accumulator form.
    pub const FULLY_COLLAPSED_PUBLIC_INPUT_WORDS: usize = 10;
    /// Public-input words required by an already collapsed `(lhs, rhs)` point pair.
    pub const POINT_PAIR_PUBLIC_INPUT_WORDS: usize = 8;

    /// Return a new `AccumulatorEncoding`.
    pub fn new(offset: usize, num_limbs: usize, num_limb_bits: usize) -> Self {
        Self {
            offset,
            num_limbs,
            num_limb_bits,
            kind: AccumulatorEncodingKind::PointAndScalar,
        }
    }

    /// Return a point-pair accumulator encoding with implicit unit scalars.
    pub fn point_pair(offset: usize, num_limbs: usize, num_limb_bits: usize) -> Self {
        Self {
            offset,
            num_limbs,
            num_limb_bits,
            kind: AccumulatorEncodingKind::PointPair,
        }
    }

    /// Number of public-input words needed for one base-field coordinate.
    fn coordinate_words(self) -> usize {
        let limbs_per_instance = (254 / self.num_limb_bits).max(1);
        self.num_limbs.div_ceil(limbs_per_instance)
    }

    /// Number of public-input words for two G1 coordinates.
    fn point_pair_words(self) -> usize {
        4 * self.coordinate_words()
    }

    fn has_carried_scalars(self) -> bool {
        matches!(self.kind, AccumulatorEncodingKind::PointAndScalar)
    }

    /// Number of public-input words occupied by the fixed accumulator payload.
    fn fixed_payload_words(self) -> usize {
        self.point_pair_words()
            + if self.has_carried_scalars() {
                layout::accumulator::CARRIED_SCALARS
            } else {
                0
            }
    }

    /// Minimum number of public-input words occupied by the accumulator tail,
    /// excluding any optional fixed-base scalar tail.
    pub fn fully_collapsed_public_input_words(self) -> Result<usize, GeneratorError> {
        self.validate_for_num_instances(usize::MAX)?;
        Ok(self.fixed_payload_words())
    }

    /// Validate this encoding against the generated verifier's supported schema.
    fn validate_for_num_instances(self, num_instances: usize) -> Result<(), GeneratorError> {
        if self.num_limbs != Self::SUPPORTED_NUM_LIMBS
            || self.num_limb_bits != Self::SUPPORTED_NUM_LIMB_BITS
        {
            return Err(GeneratorError::UnsupportedAccumulatorEncoding {
                offset: self.offset,
                num_limbs: self.num_limbs,
                num_limb_bits: self.num_limb_bits,
                num_instances,
                reason: "expected 7 radix-2^56 limbs per BLS12-381 base-field coordinate",
            });
        }

        let required_words = self.fixed_payload_words();
        if self.offset.saturating_add(required_words) > num_instances {
            return Err(GeneratorError::UnsupportedAccumulatorEncoding {
                offset: self.offset,
                num_limbs: self.num_limbs,
                num_limb_bits: self.num_limb_bits,
                num_instances,
                reason: "accumulator public-input tail exceeds num_instances",
            });
        }

        Ok(())
    }

    /// Number of optional fixed-base accumulator scalars after the fixed payload.
    fn fixed_scalar_count(self, num_instances: usize) -> Result<usize, GeneratorError> {
        self.validate_for_num_instances(num_instances)?;
        let tail = num_instances - (self.offset + self.fixed_payload_words());
        if self.kind == AccumulatorEncodingKind::PointPair && tail != 0 {
            return Err(GeneratorError::UnsupportedAccumulatorEncoding {
                offset: self.offset,
                num_limbs: self.num_limbs,
                num_limb_bits: self.num_limb_bits,
                num_instances,
                reason: "point-pair accumulator encoding does not support a fixed-base scalar tail",
            });
        }
        Ok(tail)
    }
}

/// Stable diagnostic view of the identities folded into the quotient numerator.
///
/// This is not part of the Solidity verifier ABI. It is a host-side inspection
/// API for confirming which custom gates and argument identities a generated
/// verifier will evaluate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientIdentityManifest {
    /// Identities in the exact global `y`-batch order used by the verifier.
    pub entries: Vec<QuotientIdentityManifestEntry>,
    /// Number of normal custom-gate polynomial identities.
    pub gate_identities: usize,
    /// Number of permutation identities.
    pub permutation_identities: usize,
    /// Number of lookup identities.
    pub lookup_identities: usize,
    /// Number of trash argument identities.
    pub trash_identities: usize,
    /// Fixed-column indices for simple selector buckets, sorted by column.
    pub simple_selector_cols: Vec<usize>,
}

/// One identity in the quotient numerator manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientIdentityManifestEntry {
    /// Position in the global `y`-batch.
    pub global_index: usize,
    /// Source family and source-local metadata.
    pub source: QuotientIdentitySource,
    /// Accumulation target for this identity.
    pub target: QuotientIdentityManifestTarget,
}

/// Source family for a quotient numerator identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotientIdentitySource {
    /// A normal custom-gate polynomial from `vk.cs().gates()`.
    Gate {
        /// Index in `ConstraintSystem::gates()`.
        gate_index: usize,
        /// Gate name recorded by `create_gate`.
        gate_name: String,
        /// Constraint/polynomial index inside the gate.
        constraint_index: usize,
        /// Constraint name recorded by the gate builder.
        constraint_name: String,
        /// Polynomial index inside the gate.
        polynomial_index: usize,
    },
    /// A permutation argument identity.
    Permutation {
        /// Identity index inside the permutation family.
        identity_index: usize,
    },
    /// A LogUp lookup argument identity.
    Lookup {
        /// Identity index inside the lookup family.
        identity_index: usize,
        /// Lookup argument index.
        lookup_index: usize,
        /// Lookup name recorded by the constraint system.
        lookup_name: String,
    },
    /// A trash argument identity.
    Trash {
        /// Trash argument index.
        trash_index: usize,
        /// Trash argument name, usually the source additive-selector gate name.
        trash_name: String,
    },
}

/// Destination of one manifest identity after its `y` position is consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientIdentityManifestTarget {
    /// Fully evaluated identity accumulated into the quotient numerator scalar.
    Main,
    /// Simple-selector identity accumulated into a selector commitment bucket.
    Selector {
        /// Bucket index in the sorted simple-selector list.
        selector_index: usize,
        /// Fixed column backing that simple selector.
        fixed_column: usize,
    },
}

/// Errors returned when a constraint system is outside the currently
/// supported Midfall Solidity verifier shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneratorError {
    /// A verifier with no advice commitments has no proof commitment phase to
    /// bind into the Fiat-Shamir transcript.
    NoAdviceColumns,
    /// The generated transcript and instance-evaluation path currently
    /// supports exactly one committed identity column and one non-committed
    /// public-input column.
    UnsupportedInstanceColumnShape {
        total: usize,
        committed: usize,
        expected_committed: usize,
        expected_non_committed: usize,
    },
    /// Instance columns are read as direct public inputs and locally
    /// Lagrange-interpolated only at the current row.
    RotatedInstanceQuery { column: usize, rotation: i32 },
    /// The optional public accumulator pairing batch currently supports only
    /// the Midnight BLS12-381 public-input encoding used by the IVC decider
    /// fixtures.
    UnsupportedAccumulatorEncoding {
        offset: usize,
        num_limbs: usize,
        num_limb_bits: usize,
        num_instances: usize,
        reason: &'static str,
    },
}

impl fmt::Display for GeneratorError {
    /// Format typed generator errors as caller-facing diagnostics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAdviceColumns => {
                write!(f, "at least one advice column is required")
            }
            Self::UnsupportedInstanceColumnShape {
                total,
                committed,
                expected_committed,
                expected_non_committed,
            } => {
                let non_committed = total.checked_sub(*committed).map_or_else(
                    || format!("invalid: committed {committed} exceeds total {total}"),
                    |n| n.to_string(),
                );
                write!(
                    f,
                    "unsupported instance column shape: got total={total}, committed={committed}, non_committed={non_committed}; expected exactly {expected_committed} committed and {expected_non_committed} non-committed"
                )
            }
            Self::RotatedInstanceQuery { column, rotation } => write!(
                f,
                "rotated instance query is not supported: column {column}, rotation {rotation}"
            ),
            Self::UnsupportedAccumulatorEncoding {
                offset,
                num_limbs,
                num_limb_bits,
                num_instances,
                reason,
            } => write!(
                f,
                "unsupported accumulator encoding: offset={offset}, num_limbs={num_limbs}, num_limb_bits={num_limb_bits}, num_instances={num_instances}; {reason}"
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
/// Encode verifier calldata for an EIP-2537-padded proof and public instances.
///
/// This is a small API bridge so callers do not need to import `evm` directly.
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
    fn compact_quotient_default_matches_gas_capped_setting() {
        assert_eq!(DEFAULT_HYBRID_QUOTIENT_INLINE_IDENTITIES, 4);
        assert_eq!(DEFAULT_QUOTIENT_NATIVE_GATES, 4);
        assert!(DEFAULT_QUOTIENT_LIMB_VM_OPS);

        let docs = include_str!("../../docs/QUOTIENT_NUMERATOR_EVALUATOR.md");
        assert!(
            docs.contains("direct inline identities: 4"),
            "quotient evaluator docs should record the gas-capped compact default"
        );
        assert!(
            docs.contains("structured trash suffix: on"),
            "quotient evaluator docs should record the gas-capped structured-tail default"
        );
        assert!(
            docs.contains("limb VM ops: on"),
            "quotient evaluator docs should record the limb-op default"
        );
        assert!(
            docs.contains("HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=N"),
            "quotient evaluator docs should describe the experimental tuning hook"
        );
        assert!(
            docs.contains("HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=N"),
            "quotient evaluator docs should describe the direct-inline tuning hook"
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
    fn quotient_selector_gap_fold_matches_rust_reverse_fold() {
        let y = Fq::from(19u64);
        let evals = [
            Fq::from(2u64),
            Fq::from(0u64),
            Fq::from(23u64),
            Fq::from(29u64),
        ];
        let selector_positions = [true, false, true, true];

        let mut y_powers = vec![Fq::ONE; evals.len()];
        for idx in 1..y_powers.len() {
            y_powers[idx] = y_powers[idx - 1] * y;
        }

        let mut previous = None;
        let mut selector_acc = Fq::ZERO;
        for (idx, (eval, selected)) in evals.iter().zip(selector_positions).enumerate() {
            if selected {
                let gap = previous.map_or(0, |prev| idx - prev);
                selector_acc *= y_powers[gap];
                selector_acc += *eval;
                previous = Some(idx);
            }
        }
        let tail = evals.len() - 1 - previous.expect("selector identity present");
        let solidity_selector_acc = selector_acc * y_powers[tail];

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
    fn quotient_identity_manifest_preserves_order_and_metadata() {
        let gate_source = QuotientIdentitySource::Gate {
            gate_index: 2,
            gate_name: "custom_gate".to_string(),
            constraint_index: 1,
            constraint_name: "constraint_b".to_string(),
            polynomial_index: 1,
        };
        let parts = QuotientIdentityParts {
            gates: vec![test_quotient_identity(
                0,
                gate_source.clone(),
                QuotientTarget::Selector(0),
            )],
            permutation: vec![test_quotient_identity(
                1,
                QuotientIdentitySource::Permutation { identity_index: 0 },
                QuotientTarget::Main,
            )],
            lookup: vec![test_quotient_identity(
                2,
                QuotientIdentitySource::Lookup {
                    identity_index: 0,
                    lookup_index: 0,
                    lookup_name: "lookup_0".to_string(),
                },
                QuotientTarget::Main,
            )],
            trash: vec![test_quotient_identity(
                3,
                QuotientIdentitySource::Trash {
                    trash_index: 0,
                    trash_name: "partial_round_gate".to_string(),
                },
                QuotientTarget::Main,
            )],
            sorted_simple: vec![42],
        };

        let manifest = parts.manifest();

        assert_eq!(manifest.gate_identities, 1);
        assert_eq!(manifest.permutation_identities, 1);
        assert_eq!(manifest.lookup_identities, 1);
        assert_eq!(manifest.trash_identities, 1);
        assert_eq!(
            manifest
                .entries
                .iter()
                .map(|entry| entry.global_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(manifest.entries[0].source, gate_source);
        assert_eq!(
            manifest.entries[0].target,
            QuotientIdentityManifestTarget::Selector {
                selector_index: 0,
                fixed_column: 42,
            }
        );
        assert!(matches!(
            manifest.entries[3].source,
            QuotientIdentitySource::Trash { ref trash_name, .. } if trash_name == "partial_round_gate"
        ));
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
    fn eip2537_calls_use_bounded_gas_literals() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let pcs_codegen = include_str!("pcs.rs");

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

        assert!(!verifier_template.contains("function g1add_gas_cap()"));
        assert!(!verifier_template.contains("function g1msm_gas_cap(input_len)"));
        assert!(!verifier_template.contains("function pairing_gas_cap(input_len)"));
        assert!(
            verifier_template.contains("{{ g1msm_single_gas_cap }}")
                && verifier_template.contains("{{ final_pairing_gas_cap }}"),
            "main verifier template should render generated gas-cap literals"
        );
        assert!(
            pcs_codegen.contains("layout::precompile::g1msm_gas_cap")
                && pcs_codegen.contains("layout::precompile::G1ADD_GAS_CAP"),
            "PCS emitter should compute static EIP-2537 caps at codegen time"
        );
    }

    #[test]
    fn failed_success_paths_do_not_enter_ec_precompiles() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let pcs_codegen = include_str!("pcs.rs");

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
            verifier_template.contains(
                "if iszero(success) { revert(0, 0) }\n            success := ec_pairing(success, PAIRING_RHS_MPTR, PAIRING_LHS_MPTR)"
            ),
            "final pairing block should revert before staging/calling the pairing precompile when success is already false"
        );
        assert!(
            pcs_codegen.contains("if success {")
                && pcs_codegen.contains("success := staticcall({final_msm_gas_cap}")
                && pcs_codegen.contains("success := staticcall({}, 0x0b"),
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
            "template_constants.eip2537.g1add_gas_cap",
            "template_constants.eip2537.g1msm_smoke_gas_cap",
            "template_constants.eip2537.pairing_smoke_gas_cap",
            "template_constants.eip2537.g1add_address",
            "template_constants.eip2537.g1msm_address",
            "template_constants.eip2537.pairing_address",
            "eq(returndatasize(), {{ template_constants.g1_bytes|hex() }})",
            "eq(returndatasize(), {{ template_constants.word_bytes|hex() }})",
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
    fn pinned_dependencies_are_rechecked_during_verification() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        for required in [
            "eq(extcodesize(vk), EXPECTED_VK_LENGTH)",
            "eq(extcodehash(vk), EXPECTED_VK_CODEHASH)",
            "extcodecopy(vk, VK_MPTR, 0x00, EXPECTED_VK_LENGTH)",
            "eq(extcodesize(quotientEvaluator), EXPECTED_QUOTIENT_LENGTH)",
            "eq(extcodehash(quotientEvaluator), EXPECTED_QUOTIENT_CODEHASH)",
            "Re-check the pinned VK dependency on every proof",
            "Re-check the pinned runtime before every",
        ] {
            assert!(
                verifier_template.contains(required),
                "template should re-check pinned dependency at verification time: {required}"
            );
        }
    }

    #[test]
    fn accumulator_schema_is_checked_against_instance_count() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let spec = include_str!("../../docs/HALO2_MIDNIGHT_VERIFIER_SPEC.md");

        assert!(
            verifier_template.contains("eq({{ num_instances }}, calldataload(NUM_INSTANCE_CPTR))"),
            "verifier must check calldata instance length against the generated public-input width"
        );
        assert!(
            verifier_template.contains("add(INSTANCE_CPTR, {{ (num_instances * 32)|hex() }})"),
            "verifier must reject extra trailing calldata after the generated instance vector"
        );
        assert!(
            verifier_template.contains("RHS layout for this generated verifier is fully collapsed"),
            "no-tail accumulator renders must explicitly document that no fixed-base scalar tail exists"
        );
        assert!(
            verifier_template.contains("collapsed point pair"),
            "point-pair accumulator renders must explicitly document implicit scalar semantics"
        );
        assert!(
            verifier_template.contains("RHS layout for this generated verifier is partially"),
            "tail accumulator renders must explicitly document fixed-base scalar tail semantics"
        );
        assert!(
            verifier_template.contains("{%- if acc_fixed_bases.len() > 0 %}"),
            "fixed-base scalar tail parsing should only render when generated bases exist"
        );
        for required in [
            "try_set_acc_encoding",
            "The accumulator is not passed through a separate ABI argument",
            "checked tail convention",
        ] {
            assert!(
                spec.contains(required),
                "accumulator activation/layout docs should mention: {required}"
            );
        }
    }

    #[test]
    fn accumulator_vk_header_is_specialized_at_codegen() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        for expected_check in [
            "eq(mload(HAS_ACCUMULATOR_MPTR)",
            "eq(mload(ACC_OFFSET_MPTR)",
            "eq(mload(NUM_ACC_LIMBS_MPTR)",
            "eq(mload(NUM_ACC_LIMB_BITS_MPTR)",
        ] {
            assert!(
                !verifier_template.contains(expected_check),
                "pinned verifier should not reread VK accumulator metadata at runtime: {expected_check}"
            );
        }
        assert!(
            verifier_template.contains("schema\n                // values such as instance count and accumulator layout are\n                // rendered as constants"),
            "template should document why VK schema values are generated constants"
        );
        assert!(
            verifier_template.contains("{%- if self.expected_has_accumulator %}")
                && verifier_template.contains("let bits := {{ self.expected_num_acc_limb_bits }}")
                && verifier_template.contains("let n := {{ self.expected_num_acc_limbs }}"),
            "accumulator decoding should be rendered only for generated accumulator VKs"
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
    fn accumulator_points_are_prevalidated_before_transcript_work() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        for required in [
            "function validate_public_accumulator(success, r) -> out",
            "Fail malformed accumulator public inputs before transcript",
            "success := validate_public_accumulator(success, r)",
            "gas_checkpoint(2) // after VK loading + accumulator public-input precheck",
            "Batch the prevalidated public IVC accumulator pairing equation",
        ] {
            assert!(
                verifier_template.contains(required),
                "accumulator validation should be split into early precheck and late pairing batch: {required}"
            );
        }
    }

    #[test]
    fn accumulator_decoder_rejects_noncanonical_infinity() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");

        for required in [
            "EIP-2537 reserves affine (0,0) for the point",
            "let decoded_zero := iszero(or(or(x_hi, x_lo), or(y_hi, y_lo)))",
            "ok := and(ok, iszero(decoded_zero))",
            "is_acc_encoded_identity(src)",
        ] {
            assert!(
                verifier_template.contains(required),
                "accumulator decoder should reject non-canonical infinity encodings: {required}"
            );
        }
    }

    #[test]
    fn accumulator_encoding_validation_rejects_dead_configs() {
        let fully_collapsed = AccumulatorEncoding::new(4, 7, 56);
        assert_eq!(
            fully_collapsed.fully_collapsed_public_input_words(),
            Ok(AccumulatorEncoding::FULLY_COLLAPSED_PUBLIC_INPUT_WORDS)
        );
        assert!(fully_collapsed.validate_for_num_instances(14).is_ok());
        assert_eq!(fully_collapsed.fixed_scalar_count(14), Ok(0));
        assert_eq!(fully_collapsed.fixed_scalar_count(17), Ok(3));

        let point_pair = AccumulatorEncoding::point_pair(4, 7, 56);
        assert_eq!(
            point_pair.fully_collapsed_public_input_words(),
            Ok(AccumulatorEncoding::POINT_PAIR_PUBLIC_INPUT_WORDS)
        );
        assert!(point_pair.validate_for_num_instances(12).is_ok());
        assert_eq!(point_pair.fixed_scalar_count(12), Ok(0));
        assert!(matches!(
            point_pair.fixed_scalar_count(13),
            Err(GeneratorError::UnsupportedAccumulatorEncoding {
                reason: "point-pair accumulator encoding does not support a fixed-base scalar tail",
                ..
            })
        ));

        let wrong_limb_shape = AccumulatorEncoding::new(4, 8, 32);
        assert!(matches!(
            wrong_limb_shape.validate_for_num_instances(14),
            Err(GeneratorError::UnsupportedAccumulatorEncoding {
                num_limbs: 8,
                num_limb_bits: 32,
                ..
            })
        ));

        let out_of_bounds = AccumulatorEncoding::new(5, 7, 56);
        assert!(matches!(
            out_of_bounds.validate_for_num_instances(14),
            Err(GeneratorError::UnsupportedAccumulatorEncoding {
                offset: 5,
                reason: "accumulator public-input tail exceeds num_instances",
                ..
            })
        ));
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
            verifier_template.contains(
                "eq(calldataload({{ abi_selector_bytes|hex() }}), {{ abi_proof_head_offset|hex() }})"
            ),
            "verifier must read the proof dynamic ABI head"
        );
        assert!(
            verifier_template.contains(
                "eq(calldataload({{ abi_instances_head_cptr|hex() }}), sub(NUM_INSTANCE_CPTR, {{ abi_selector_bytes|hex() }}))"
            ),
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
    fn differential_trace_hooks_cover_expected_categories() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let pcs_source = include_str!("pcs.rs");

        for (name, needle) in [
            (
                "user transcript challenges",
                "1000 + phase.challenge_offset + j",
            ),
            ("quotient numerator", "trace_u256(36,"),
            ("f_eval", "trace_u256(31,"),
            ("final MSM commitment", "trace_point(33,"),
            ("pairing lhs input", "trace_point(27,"),
            ("pairing rhs input", "trace_point(28,"),
            ("final result", "trace_u256(35,"),
            ("selector folds", "selector_trace_base + loop.index0"),
        ] {
            assert!(
                verifier_template.contains(needle),
                "verifier template missing {name} trace hook"
            );
        }

        for (name, needle) in [
            (
                "serialized PCS point sets",
                "trace::PCS_SERIALIZED_POINT_SET_BASE + set_idx as u64",
            ),
            ("PCS q_com commitments", "40000 + set_idx"),
        ] {
            assert!(
                pcs_source.contains(needle),
                "PCS emitter missing {name} trace hook"
            );
        }
    }

    #[test]
    fn quotient_vm_opcode_and_token_tables_match_template_cases() {
        let quotient_template = include_str!("../../templates/QuotientNumeratorBlock.yul");

        for spec in QUOTIENT_VM_SPEC.opcodes {
            let name = spec.name;
            let needle = [
                "case {{ template_constants.quotient_vm.op.",
                name,
                "|hex() }}",
            ]
            .concat();
            assert!(
                quotient_template.contains(&needle),
                "quotient VM template missing opcode {name} template constant"
            );
        }
        assert!(
            !quotient_template.contains("case 0x1a"),
            "stale native-trash opcode must not remain in quotient VM template"
        );

        for spec in QUOTIENT_VM_SPEC.mem_tokens {
            let name = spec.name;
            let field = match name {
                "L_0_MPTR" => "l0",
                "L_LAST_MPTR" => "l_last",
                "L_BLIND_MPTR" => "l_blind",
                "BETA_MPTR" => "beta",
                "GAMMA_MPTR" => "gamma",
                "X_MPTR" => "x",
                "THETA_MPTR" => "theta",
                "TRASH_CHALLENGE_MPTR" => "trash_challenge",
                "INSTANCE_EVAL_MPTR" => "instance_eval",
                _ => panic!("unmapped quotient VM memory token {name}"),
            };
            let needle = [
                "case {{ template_constants.quotient_vm.mem.",
                field,
                "|hex() }} { q_ptr := ",
                name,
            ]
            .concat();
            assert!(
                quotient_template.contains(&needle),
                "quotient VM template missing memory token {name} template constant"
            );
        }
        assert_eq!(QUOTIENT_VM_SPEC.limb_count, layout::quotient_limb::LIMBS);
        assert_eq!(
            QUOTIENT_VM_SPEC.limb_pairwise_terms,
            layout::quotient_limb::PAIRWISE_TERMS
        );
        assert_eq!(
            QUOTIENT_VM_SPEC.limb_pairwise_coeffs,
            layout::quotient_limb::PAIRWISE_COEFFS
        );
    }

    #[test]
    fn quotient_vm_lengths_are_derived_from_opcode_spec() {
        for spec in QUOTIENT_VM_SPEC.opcodes {
            if spec.byte_len == 0 {
                continue;
            }
            let bytes = vec![spec.opcode; spec.byte_len];
            assert_eq!(
                quotient_op_len(&bytes, 0),
                spec.byte_len,
                "opcode {} length should come from QuotientVmSpec",
                spec.name
            );
        }
    }

    #[test]
    fn normalized_yul_assignment_parser_tolerates_formatting_variants() {
        assert_eq!(
            yul_let_assignment("  let   z:=addmod(a, b, r)  "),
            Some(("z".to_string(), "addmod(a, b, r)".to_string()))
        );
        assert_eq!(
            yul_addmod_assignment("let z := addmod ( a, mulmod(b, c, r), r )"),
            Some((
                "z".to_string(),
                "a".to_string(),
                "mulmod(b, c, r)".to_string()
            ))
        );
        assert_eq!(
            yul_mulmod_assignment("let z:=mulmod(a,b,r)"),
            Some(("z".to_string(), "a".to_string(), "b".to_string()))
        );
    }

    #[test]
    fn field_negations_used_by_traces_are_canonical() {
        let quotient_helpers = include_str!("../../templates/QuotientHelpers.yul");
        let quotient_template = include_str!("../../templates/QuotientNumeratorBlock.yul");
        let evaluator_source = include_str!("evaluator.rs");
        let pcs_source = include_str!("pcs.rs");
        let quotient_source = include_str!("quotient/mod.rs");

        for (name, source, needle) in [
            (
                "q_neg helper",
                quotient_helpers,
                "z := addmod(0, sub(FR_MODULUS, a), FR_MODULUS)",
            ),
            (
                "packed quotient VM negation",
                quotient_template,
                "q_top := addmod(0, sub(r, q_top), r)",
            ),
            (
                "linearization expected eval",
                quotient_template,
                "let linearization_expected_eval := addmod(0, sub(r, quotient_eval_numer), r)",
            ),
            (
                "structured quotient linearization expected eval",
                quotient_template,
                "let linearization_expected_eval := addmod(0, sub(r, mload({{ program.eval_numer_mptr|hex() }})), r)",
            ),
            (
                "native evaluator negation",
                evaluator_source,
                "addmod(0, sub(r, {var}), r)",
            ),
            (
                "quotient inline CSE negation",
                quotient_source,
                "addmod(0, sub(r, {inner}), r)",
            ),
            (
                "final pairing negative v scalar",
                pcs_source,
                "addmod(0, sub(r, mload(V_MPTR)), r)",
            ),
        ] {
            assert!(
                source.contains(needle),
                "{name} should canonicalize zero negations with addmod"
            );
        }
    }

    #[test]
    fn quotient_helper_definitions_live_in_shared_partial() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let quotient_evaluator_template =
            include_str!("../../templates/Halo2QuotientEvaluator.sol");
        let quotient_helpers = include_str!("../../templates/QuotientHelpers.yul");

        assert!(
            verifier_template.contains(
                "{%- when None %}\n            {%- include \"QuotientHelpers.yul\" %}\n            {%- include \"QuotientNumeratorBlock.yul\" %}"
            ),
            "monolithic verifier quotient path should include helpers beside the numerator block"
        );
        assert!(
            quotient_evaluator_template.contains(
                "{%- include \"QuotientHelpers.yul\" %}\n            {%- include \"QuotientNumeratorBlock.yul\" %}"
            ),
            "external evaluator should include helpers beside the numerator block"
        );
        for helper in [
            "function q_pow5(",
            "function q_limb7(",
            "function q_limb7_wide(",
            "function q_add(",
        ] {
            assert!(
                quotient_helpers.contains(helper),
                "quotient helper partial should define {helper}"
            );
            assert!(
                !verifier_template.contains(helper),
                "main verifier template should not carry duplicate quotient helper body {helper}"
            );
            assert!(
                !quotient_evaluator_template.contains(helper),
                "external evaluator template should not carry duplicate quotient helper body {helper}"
            );
        }
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
            !verifier_template.contains("InvalidVerifierDependency"),
            "constructor pinning removes per-call dependency preflight code"
        );
        assert!(
            !verifier_template.contains("return false;"),
            "generated verifier should not mix false returns with revert-on-invalid semantics"
        );
        assert!(
            !verifier_template.contains("mstore(0x00, success)"),
            "generated verifier must not return a false boolean on invalid proofs"
        );
        assert!(
            verifier_template.contains("function ec_pairing(success, lhs_mptr, rhs_mptr) -> ret")
                && verifier_template
                    .contains("ret := success\n                if iszero(ret) { leave }")
                && verifier_template.contains(
                    "ret := and(ret, mload(scratch))\n                if iszero(ret) { revert(0, 0) }\n                ret := 1",
                ),
            "final pairing helper must revert on pairing failure and normalize success to one"
        );
        assert!(
            verifier_template
                .contains("success := ec_pairing(success, PAIRING_RHS_MPTR, PAIRING_LHS_MPTR)"),
            "final epilogue must route the pairing check through the reverting helper"
        );
        assert!(
            !verifier_template.contains("return(0x00, 0x20)\n            {%- else %}"),
            "trace and production epilogues must not diverge into false-return semantics"
        );
        assert!(
            verifier_template
                .contains("mstore(RETURN_MPTR, 1)\n            return(RETURN_MPTR, 0x20)"),
            "generated verifier must only return literal true after the reverting pairing helper"
        );
    }

    #[test]
    fn templates_do_not_write_solidity_reserved_memory_slots() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let quotient_template = include_str!("../../templates/Halo2QuotientEvaluator.sol");
        let quotient_helpers = include_str!("../../templates/QuotientHelpers.yul");
        let vk_template = include_str!("../../templates/Halo2VerifyingKey.sol");
        let pcs_source = include_str!("pcs.rs");

        for (name, source) in [
            ("Halo2Verifier.sol", verifier_template),
            ("Halo2QuotientEvaluator.sol", quotient_template),
            ("QuotientHelpers.yul", quotient_helpers),
            ("Halo2VerifyingKey.sol", vk_template),
        ] {
            for needle in [
                "mstore(0x00,",
                "mstore(0x20,",
                "mstore(0x40,",
                "mstore(0x60,",
                "mstore(add(0x00,",
                "mstore(add(0x20,",
                "mstore(add(0x40,",
                "mstore(add(0x60,",
                "mcopy(0x00,",
                "mcopy(0x20,",
                "mcopy(0x40,",
                "mcopy(0x60,",
                "calldatacopy(0x00,",
                "calldatacopy(0x20,",
                "calldatacopy(0x40,",
                "calldatacopy(0x60,",
                "return(0x00,",
            ] {
                assert!(
                    !source.contains(needle),
                    "{name} must not write or return from Solidity-reserved memory words: found {needle}"
                );
            }
        }
        assert!(
            !pcs_source.contains("mcopy(0x0,")
                && !pcs_source.contains(", 0x00, {G1_MSM_PAIR_BYTES:#x}")
                && !pcs_source.contains(", 0x00, {G1ADD_INPUT_BYTES:#x}"),
            "generated PCS helper scratch must not be rooted at memory 0"
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
        let source = include_str!("pcs.rs");

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
        for required in [
            "/// @param proof Solidity-facing proof bytes",
            "/// @param instances Public instance scalars",
            "/// @return Always `true`",
        ] {
            assert!(
                verifier_template.contains(required),
                "verifyProof NatSpec must include ABI documentation: {required}"
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
    fn midfall_comment_corpus_is_source_indexed_and_attributed() {
        let corpus = include_str!("../../docs/MIDFALL_PROOFS_COMMENT_CORPUS.md");
        let extractor = include_str!("../../scripts/extract_midfall_comments.py");

        for required in [
            "# Midfall Proofs Comment Corpus",
            "Rust source files: `57`",
            "Comment lines: `3597`",
            "## `plonk/verifier.rs`",
            "## `plonk/linearization/verifier.rs`",
            "## `poly/kzg/mod.rs`",
            "## `transcript/implementors.rs`",
            "SPDX-License-Identifier: Apache-2.0",
            "License And Attribution",
        ] {
            assert!(
                corpus.contains(required),
                "Midfall comment corpus missing expected source-indexed content: {required}"
            );
        }

        for required in [
            "COMMENT_RE",
            "--check",
            "--write",
            "Git commit",
            "CommentBlock",
        ] {
            assert!(
                extractor.contains(required),
                "comment extractor should remain deterministic/checkable: {required}"
            );
        }
    }

    #[test]
    fn solidity_templates_have_required_natspec_surface() {
        let verifier = include_str!("../../templates/Halo2Verifier.sol");
        let vk = include_str!("../../templates/Halo2VerifyingKey.sol");
        let quotient = include_str!("../../templates/Halo2QuotientEvaluator.sol");

        for (name, source, contract) in [
            ("verifier", verifier, "contract Halo2Verifier"),
            ("verifying key", vk, "contract Halo2VerifyingKey"),
            (
                "quotient evaluator",
                quotient,
                "contract Halo2QuotientEvaluator",
            ),
        ] {
            assert!(
                source.contains("/// @title")
                    && source.contains("/// @notice")
                    && source.contains("/// @dev"),
                "{name} template should have contract-level NatSpec"
            );
            assert!(
                source.contains(contract),
                "{name} template should still declare {contract}"
            );
        }

        for required in [
            "/// @notice Verifying-key contract address",
            "checked at construction time",
            "/// @notice Quotient evaluator contract",
            "/// @param authorizedVk",
            "/// @param authorizedQuotient",
            "/// @return Always `true`",
        ] {
            assert!(
                verifier.contains(required),
                "verifier NatSpec missing required declaration docs: {required}"
            );
        }
        assert!(
            vk.contains("/// @notice Deploy the verifying-key payload"),
            "VK constructor should have NatSpec"
        );
        assert!(
            quotient.contains("/// @notice Evaluate the generated quotient numerator block"),
            "quotient fallback should have NatSpec"
        );
    }

    #[test]
    fn midfall_comment_ports_reference_rust_sources() {
        let verifier = include_str!("../../templates/Halo2Verifier.sol");
        let quotient = include_str!("../../templates/Halo2QuotientEvaluator.sol");
        let quotient_helpers = include_str!("../../templates/QuotientHelpers.yul");
        let numerator = include_str!("../../templates/QuotientNumeratorBlock.yul");
        let transcript = include_str!("../transcript.rs");
        let generator = include_str!("generator.rs");
        let evaluator = include_str!("evaluator.rs");
        let protocol = include_str!("protocol.rs");
        let pcs = include_str!("pcs.rs");
        let spec = include_str!("../../docs/HALO2_MIDNIGHT_VERIFIER_SPEC.md");

        for required in [
            "midfall/proofs/src/plonk/verifier.rs",
            "midfall/proofs/src/transcript/implementors.rs",
            "midfall/proofs/src/poly/kzg/mod.rs",
        ] {
            assert!(
                verifier.contains(required) || spec.contains(required),
                "verifier docs should reference upstream Rust source: {required}"
            );
        }
        for required in [
            "midfall/proofs/src/plonk/mod.rs::partially_evaluate_identities",
            "midfall/proofs/src/plonk/linearization/verifier.rs::compute_linearization_commitment",
            "selectors do not appear as normal proof eval scalars",
        ] {
            assert!(
                quotient.contains(required)
                    || quotient_helpers.contains(required)
                    || numerator.contains(required),
                "quotient docs should carry adapted upstream comments: {required}"
            );
        }
        assert!(
            transcript.contains("Hashable<Keccak256> for G1Projective"),
            "transcript docs should reference upstream point hashing comments"
        );
        assert!(
            protocol.contains("counterpart of the iterator-heavy verifier"),
            "protocol plan should document the Midfall verifier-flow port"
        );
        for required in [
            "committed instances and normal (non-committed) instances",
            "(num_fixed_columns - num_simple_selectors) fixed evals",
            "absorbs this `transcript_repr` digest",
        ] {
            assert!(
                generator.contains(required),
                "generator should carry adapted verifier comment: {required}"
            );
        }
        for required in [
            "Hash the prover's advice commitments",
            "Read commitment(s) to the quotient polynomial h(X)=nu(X)/(X^n-1)",
            "Queries corresponding to simple, multiplicative selectors need not be",
            "omega^rotation*x",
        ] {
            assert!(
                protocol.contains(required),
                "protocol plan should carry adapted verifier comment: {required}"
            );
        }
        for required in [
            "partially_evaluate_identities",
            "LogUp emitter",
            "Permutation emitter",
            "Trashcan emitter",
        ] {
            assert!(
                evaluator.contains(required),
                "quotient evaluator codegen should carry adapted verifier comment: {required}"
            );
        }
        assert!(
            pcs.contains("Upstream comments ported here")
                && pcs.contains("Sort point sets by ascending cardinality")
                && pcs.contains("Sample a challenge x_3")
                && pcs.contains("Scale z*pi - vG"),
            "PCS emitter should document the KZG comment port"
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
            lib_source.contains("cfg!(all(")
                && lib_source.contains("feature = \"solidity-gas-checkpoints\"")
                && lib_source.contains("feature = \"solidity-trace\""),
            "default renders should only enable gas checkpoints in trace/profiling builds"
        );
        assert!(
            lib_source.contains("render_with_gas_checkpoints*"),
            "docs should call out the explicit benchmarking render helpers"
        );
    }

    #[test]
    fn trash_challenge_is_squeezed_even_without_trash_arguments() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let squeeze = verifier_template
            .find("buf_len := squeeze_to(buf_len, TRASH_CHALLENGE_MPTR)")
            .expect("trash challenge squeeze should be rendered");
        let trash_guard = verifier_template
            .find("{%- if num_trashcans != 0 %}\n            // ---- trashcans ----")
            .expect("trashcan commitment reads should still be guarded");

        assert!(
            squeeze < trash_guard,
            "Midnight squeezes trash_challenge unconditionally; only trashcan commitment reads may be guarded"
        );
    }

    #[test]
    fn truncated_challenge_comments_cover_x1_x4_power_masks() {
        let verifier_template = include_str!("../../templates/Halo2Verifier.sol");
        let pcs_codegen = include_str!("pcs.rs");

        assert!(
            verifier_template.contains("x1 and x4 remain full squeezed Fr words"),
            "x3 squeeze comment must clarify that x1/x4 are handled by truncated powers"
        );
        assert!(
            verifier_template.contains("truncate(x1^i) and truncate(x4^i)"),
            "verifier template should document the PCS power truncation rule"
        );
        assert!(
            pcs_codegen.contains("proofs/src/poly/kzg/mod.rs computes"),
            "x1 power generation should point back to the Rust verifier source"
        );
        assert!(
            pcs_codegen.contains("power[i] = truncate(x1^i)"),
            "x1 power generation should document truncated_powers(x1)"
        );
        assert!(
            pcs_codegen.contains("truncated_powers(x4)[i] = truncate(x4^i)"),
            "x4 power generation should document truncated_powers(x4)"
        );
        assert!(
            pcs_codegen.contains("mstore(p, and(acc, {TRUNC_MASK_128}))"),
            "x1 emitted powers must be masked under truncated-challenges"
        );
        assert!(
            pcs_codegen.contains("let x4_pow_{s} := and(x4_pow_full, {TRUNC_MASK_128})"),
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
            GeneratorError::UnsupportedInstanceColumnShape {
                total: 2,
                committed: 0,
                expected_committed: 1,
                expected_non_committed: 1,
            }
            .to_string(),
            "unsupported instance column shape: got total=2, committed=0, non_committed=2; expected exactly 1 committed and 1 non-committed"
        );
        assert_eq!(
            GeneratorError::UnsupportedInstanceColumnShape {
                total: 1,
                committed: 2,
                expected_committed: 1,
                expected_non_committed: 1,
            }
            .to_string(),
            "unsupported instance column shape: got total=1, committed=2, non_committed=invalid: committed 2 exceeds total 1; expected exactly 1 committed and 1 non-committed"
        );
        assert_eq!(
            GeneratorError::RotatedInstanceQuery {
                column: 1,
                rotation: -1,
            }
            .to_string(),
            "rotated instance query is not supported: column 1, rotation -1"
        );
        assert_eq!(
            GeneratorError::UnsupportedAccumulatorEncoding {
                offset: 5,
                num_limbs: 7,
                num_limb_bits: 56,
                num_instances: 14,
                reason: "accumulator public-input tail exceeds num_instances",
            }
            .to_string(),
            "unsupported accumulator encoding: offset=5, num_limbs=7, num_limb_bits=56, num_instances=14; accumulator public-input tail exceeds num_instances"
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
    fn quotient_vm_pow5_matches_direct_expr_eval() {
        let ptr = 0xa20;
        let mut values = HashMap::new();
        values.insert(ptr, Fq::from(131u64));
        let base = QuotientExpr::Mem(QuotientMem::Literal(ptr));
        let expr = quotient_mul_expr(
            quotient_mul_expr(base.clone(), base.clone()),
            quotient_mul_expr(base.clone(), quotient_mul_expr(base.clone(), base)),
        );

        let expected = eval_quotient_expr_for_test(&expr, &values);
        let mut builder = QuotientProgramBuilder::default();
        builder.emit_expr(&expr);

        assert_eq!(builder.bytes[3], Q_OP_POW5);
        assert_eq!(
            eval_quotient_vm_for_test(&builder.bytes, &builder.consts, &values),
            expected
        );
    }

    #[test]
    fn quotient_vm_limb_subshape_matches_direct_expr_eval() {
        let mut values = HashMap::new();
        let mut expr = QuotientExpr::Const(U256::ZERO);
        let residue = quotient_mul_expr(
            QuotientExpr::Mem(QuotientMem::Literal(0xc00)),
            quotient_mul_expr(
                QuotientExpr::Mem(QuotientMem::Literal(0xc20)),
                QuotientExpr::Mem(QuotientMem::Literal(0xc40)),
            ),
        );
        values.insert(0xc00, Fq::from(211u64));
        values.insert(0xc20, Fq::from(223u64));
        values.insert(0xc40, Fq::from(227u64));

        for i in 0..7u32 {
            let ptr = 0xb00 + i * 0x20;
            values.insert(ptr, Fq::from(151 + i as u64));
            if i == 1 {
                expr = quotient_add_expr(expr, QuotientExpr::Const(U256::from(9u64)));
            }
            if i == 4 {
                expr = quotient_add_expr(expr, residue.clone());
            }
            expr = quotient_add_expr(
                expr,
                quotient_scale_expr(
                    Fq::from(19 + i as u64),
                    QuotientExpr::Mem(QuotientMem::Literal(ptr)),
                ),
            );
        }

        let expected = eval_quotient_expr_for_test(&expr, &values);
        let mut builder = QuotientProgramBuilder::with_limb_vm_ops(true);
        builder.emit_expr(&expr);

        assert!(
            builder.bytes.contains(&Q_OP_LIN7),
            "larger affine sums should still extract LIN7 subshapes"
        );
        assert_eq!(
            eval_quotient_vm_for_test(&builder.bytes, &builder.consts, &values),
            expected
        );
    }

    #[test]
    fn quotient_vm_limb_subshape_inside_conditional_product_matches_direct_expr_eval() {
        let mut values = HashMap::new();
        let cond_ptr = 0xd00;
        values.insert(cond_ptr, Fq::from(3u64));
        let mut inner = QuotientExpr::Const(U256::ZERO);
        for i in 0..7u32 {
            let ptr = 0xe00 + i * 0x20;
            values.insert(ptr, Fq::from(251 + i as u64));
            if i == 2 {
                inner = quotient_add_expr(inner, QuotientExpr::Const(U256::from(17u64)));
            }
            inner = quotient_add_expr(
                inner,
                quotient_scale_expr(
                    Fq::from(31 + i as u64),
                    QuotientExpr::Mem(QuotientMem::Literal(ptr)),
                ),
            );
        }
        let expr = quotient_mul_expr(QuotientExpr::Mem(QuotientMem::Literal(cond_ptr)), inner);

        let expected = eval_quotient_expr_for_test(&expr, &values);
        let mut builder = QuotientProgramBuilder::with_limb_vm_ops(true);
        builder.emit_expr(&expr);

        assert!(
            builder.bytes.contains(&Q_OP_MODARITH7),
            "conditional affine factors should collapse into the fused mod-arith opcode"
        );
        assert_eq!(
            eval_quotient_vm_for_test(&builder.bytes, &builder.consts, &values),
            expected
        );
    }

    #[test]
    fn quotient_vm_modarith7_mixed_affine_matches_direct_expr_eval() {
        let lhs_base = 0xf00;
        let rhs_base = 0x1100;
        let lin_base = 0x1300;
        let factored_lin_base = 0x1700;
        let cond = 0x1500;
        let scalar = 0x1520;
        let product_lhs = 0x1540;
        let product_rhs = 0x1560;
        let mut values = HashMap::new();
        values.insert(cond, Fq::from(3u64));
        values.insert(scalar, Fq::from(5u64));
        values.insert(product_lhs, Fq::from(11u64));
        values.insert(product_rhs, Fq::from(13u64));
        for i in 0..7u32 {
            values.insert(lhs_base + i * WORD_BYTES as u32, Fq::from(7 + i as u64));
            values.insert(rhs_base + i * WORD_BYTES as u32, Fq::from(17 + i as u64));
            values.insert(lin_base + i * WORD_BYTES as u32, Fq::from(29 + i as u64));
            values.insert(
                factored_lin_base + i * WORD_BYTES as u32,
                Fq::from(31 + i as u64),
            );
        }

        let mut inner = QuotientExpr::Const(U256::from(41u64));
        for i in 0..7u32 {
            inner = quotient_add_expr(
                inner,
                quotient_scale_expr(
                    Fq::from(43 + i as u64),
                    QuotientExpr::Mem(QuotientMem::Literal(lin_base + i * WORD_BYTES as u32)),
                ),
            );
        }
        let mut factored_lin = QuotientExpr::Const(U256::ZERO);
        for i in 0..7u32 {
            factored_lin = quotient_add_expr(
                factored_lin,
                quotient_scale_expr(
                    Fq::from(47 + i as u64),
                    QuotientExpr::Mem(QuotientMem::Literal(
                        factored_lin_base + i * WORD_BYTES as u32,
                    )),
                ),
            );
        }
        inner = quotient_add_expr(
            inner,
            quotient_mul_expr(QuotientExpr::Mem(QuotientMem::Literal(cond)), factored_lin),
        );
        for i in 0..7u32 {
            for j in 0..7u32 {
                inner = quotient_add_expr(
                    inner,
                    quotient_scale_expr(
                        Fq::from(53 + i as u64 + j as u64),
                        quotient_mul_expr(
                            QuotientExpr::Mem(QuotientMem::Literal(
                                lhs_base + i * WORD_BYTES as u32,
                            )),
                            QuotientExpr::Mem(QuotientMem::Literal(
                                rhs_base + j * WORD_BYTES as u32,
                            )),
                        ),
                    ),
                );
            }
        }
        inner = quotient_add_expr(
            inner,
            quotient_scale_expr(
                Fq::from(97u64),
                QuotientExpr::Mem(QuotientMem::Literal(scalar)),
            ),
        );
        inner = quotient_add_expr(
            inner,
            quotient_scale_expr(
                Fq::from(101u64),
                quotient_mul_expr(
                    QuotientExpr::Mem(QuotientMem::Literal(product_lhs)),
                    QuotientExpr::Mem(QuotientMem::Literal(product_rhs)),
                ),
            ),
        );
        let expr = quotient_mul_expr(QuotientExpr::Mem(QuotientMem::Literal(cond)), inner);

        let expected = eval_quotient_expr_for_test(&expr, &values);
        let mut builder = QuotientProgramBuilder::with_limb_vm_ops(true);
        builder.emit_expr(&expr);

        assert_eq!(builder.bytes[0], Q_OP_MODARITH7);
        assert_eq!(quotient_op_len(&builder.bytes, 0), builder.bytes.len());
        let (ops, mem_tokens) =
            quotient_program_usage(&builder.bytes, QuotientProgramEncoding::Bytes);
        assert_eq!(ops, vec![Q_OP_MODARITH7]);
        assert!(mem_tokens.is_empty());
        assert_eq!(
            eval_quotient_vm_for_test(&builder.bytes, &builder.consts, &values),
            expected
        );
    }

    #[test]
    fn quotient_vm_modarith7_sparse_affine_product_matches_direct_expr_eval() {
        let cond = 0x1800;
        let linear = 0x1820;
        let lhs0 = 0x1840;
        let rhs0 = 0x1860;
        let lhs1 = 0x1880;
        let rhs1 = 0x18a0;
        let factored0 = 0x18c0;
        let factored1 = 0x18e0;
        let mut values = HashMap::new();
        values.insert(cond, Fq::from(3u64));
        values.insert(linear, Fq::from(5u64));
        values.insert(lhs0, Fq::from(7u64));
        values.insert(rhs0, Fq::from(11u64));
        values.insert(lhs1, Fq::from(13u64));
        values.insert(rhs1, Fq::from(17u64));
        values.insert(factored0, Fq::from(19u64));
        values.insert(factored1, Fq::from(23u64));

        let mut inner = QuotientExpr::Const(U256::from(19u64));
        inner = quotient_add_expr(
            inner,
            quotient_scale_expr(
                Fq::from(23u64),
                QuotientExpr::Mem(QuotientMem::Literal(linear)),
            ),
        );
        inner = quotient_add_expr(
            inner,
            quotient_scale_expr(
                Fq::from(29u64),
                quotient_mul_expr(
                    QuotientExpr::Mem(QuotientMem::Literal(lhs0)),
                    QuotientExpr::Mem(QuotientMem::Literal(rhs0)),
                ),
            ),
        );
        inner = quotient_add_expr(
            inner,
            quotient_scale_expr(
                Fq::from(31u64),
                quotient_mul_expr(
                    QuotientExpr::Mem(QuotientMem::Literal(lhs1)),
                    QuotientExpr::Mem(QuotientMem::Literal(rhs1)),
                ),
            ),
        );
        let factored = quotient_add_expr(
            QuotientExpr::Const(U256::from(37u64)),
            quotient_add_expr(
                quotient_scale_expr(
                    Fq::from(41u64),
                    QuotientExpr::Mem(QuotientMem::Literal(factored0)),
                ),
                quotient_scale_expr(
                    Fq::from(43u64),
                    QuotientExpr::Mem(QuotientMem::Literal(factored1)),
                ),
            ),
        );
        inner = quotient_add_expr(
            inner,
            quotient_scale_expr(
                Fq::from(47u64),
                quotient_mul_expr(QuotientExpr::Mem(QuotientMem::Literal(cond)), factored),
            ),
        );
        let expr = quotient_mul_expr(QuotientExpr::Mem(QuotientMem::Literal(cond)), inner);

        let expected = eval_quotient_expr_for_test(&expr, &values);
        let mut builder = QuotientProgramBuilder::with_limb_vm_ops(true);
        builder.emit_expr(&expr);

        assert_eq!(builder.bytes[0], Q_OP_MODARITH7);
        assert_eq!(quotient_op_len(&builder.bytes, 0), builder.bytes.len());
        let (ops, mem_tokens) =
            quotient_program_usage(&builder.bytes, QuotientProgramEncoding::Bytes);
        assert_eq!(ops, vec![Q_OP_MODARITH7]);
        assert!(mem_tokens.is_empty());
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
    fn quotient_program_usage_tracks_byte_ops_and_tokens() {
        let bytes = vec![
            Q_OP_PUSH_MEM_TOKEN,
            Q_MEM_THETA,
            Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16,
            0x00,
            0x02,
            0x00,
            0x20,
            0x03,
            0x00,
            0x40,
            0x04,
            Q_OP_FOLD_MAIN,
        ];

        let (ops, mem_tokens) = quotient_program_usage(&bytes, QuotientProgramEncoding::Bytes);

        assert!(ops.contains(&Q_OP_PUSH_MEM_TOKEN));
        assert!(ops.contains(&Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16));
        assert!(ops.contains(&Q_OP_FOLD_MAIN));
        assert!(!ops.contains(&Q_OP_ADD_MUL_CONST_U8_MEM_U16));
        assert_eq!(mem_tokens, vec![Q_MEM_THETA]);
    }

    #[test]
    fn quotient_program_usage_tracks_packed_extra_words_and_token_offsets() {
        let mut bytes = Vec::new();
        push_packed_quotient_op(
            &mut bytes,
            Q_OP_PUSH_MEM_TOKEN_OFFSET,
            ((Q_MEM_X as u32) << 16) | 0x40,
        );
        push_packed_quotient_op(&mut bytes, Q_OP_ADD_MUL_MEM_MEM_CONST_U8, 7);
        bytes.extend_from_slice(&((0x120u32 << 16) | 0x140).to_be_bytes());
        push_packed_quotient_op(&mut bytes, Q_OP_FOLD_MAIN, 0);

        let (ops, mem_tokens) = quotient_program_usage(&bytes, QuotientProgramEncoding::Packed32);

        assert!(ops.contains(&Q_OP_PUSH_MEM_TOKEN_OFFSET));
        assert!(ops.contains(&Q_OP_ADD_MUL_MEM_MEM_CONST_U8));
        assert!(ops.contains(&Q_OP_FOLD_MAIN));
        assert_eq!(mem_tokens, vec![Q_MEM_X]);
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

    fn test_quotient_identity(
        global_index: usize,
        source: QuotientIdentitySource,
        target: QuotientTarget,
    ) -> QuotientIdentity {
        QuotientIdentity {
            meta: QuotientIdentityMetadata {
                global_index,
                source,
            },
            lines: Vec::new(),
            var: "eval".to_string(),
            target,
            expr: Some(QuotientExpr::Const(U256::ZERO)),
        }
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
                Q_OP_POW5 => {
                    let value = stack.pop().expect("value");
                    let value2 = value * value;
                    stack.push(value * value2 * value2);
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
                Q_OP_MODARITH7 => {
                    idx += 1;
                    let flags = bytes[idx];
                    idx += 1;
                    let cond = if flags & 0x01 != 0 {
                        let ptr = read_u16(bytes, idx) as u32;
                        idx += 2;
                        Some(ptr)
                    } else {
                        None
                    };

                    let mut acc = Fq::ZERO;
                    if flags & 0x02 != 0 {
                        let slot = bytes[idx] as usize;
                        idx += 1;
                        acc += fq_from_u256(consts[slot]);
                    }

                    let lin_count = bytes[idx] as usize;
                    let row_count = bytes[idx + 1] as usize;
                    let pairwise_count = bytes[idx + 2] as usize;
                    let mem_count = bytes[idx + 3] as usize;
                    let product_count = bytes[idx + 4] as usize;
                    idx += 5;

                    for _ in 0..lin_count {
                        for _ in 0..7 {
                            let slot = bytes[idx] as usize;
                            let ptr = read_u16(bytes, idx + 1) as u32;
                            acc += fq_from_u256(consts[slot]) * mem[&ptr];
                            idx += 3;
                        }
                    }
                    for _ in 0..row_count {
                        let lhs = read_u16(bytes, idx) as u32;
                        let lhs_value = mem[&lhs];
                        idx += 2;
                        for _ in 0..7 {
                            let slot = bytes[idx] as usize;
                            let rhs = read_u16(bytes, idx + 1) as u32;
                            acc += lhs_value * mem[&rhs] * fq_from_u256(consts[slot]);
                            idx += 3;
                        }
                    }
                    for _ in 0..pairwise_count {
                        let lhs_base = read_u16(bytes, idx) as u32;
                        let rhs_base = read_u16(bytes, idx + 2) as u32;
                        idx += 4;
                        let coeff_idx = idx;
                        idx += 13;
                        for i in 0..7u32 {
                            let lhs = mem[&(lhs_base + i * WORD_BYTES as u32)];
                            for j in 0..7u32 {
                                let rhs = mem[&(rhs_base + j * WORD_BYTES as u32)];
                                let slot = bytes[coeff_idx + i as usize + j as usize] as usize;
                                acc += lhs * rhs * fq_from_u256(consts[slot]);
                            }
                        }
                    }
                    for _ in 0..mem_count {
                        let slot = bytes[idx] as usize;
                        let ptr = read_u16(bytes, idx + 1) as u32;
                        acc += fq_from_u256(consts[slot]) * mem[&ptr];
                        idx += 3;
                    }
                    for _ in 0..product_count {
                        let slot = bytes[idx] as usize;
                        let lhs = read_u16(bytes, idx + 1) as u32;
                        let rhs = read_u16(bytes, idx + 3) as u32;
                        acc += fq_from_u256(consts[slot]) * mem[&lhs] * mem[&rhs];
                        idx += 5;
                    }

                    if let Some(cond) = cond {
                        acc *= mem[&cond];
                    }
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
