//! Producer-side implementation of the compact quotient-numerator VM.
//!
//! The verifier does not ask the proof for a trusted evaluation of the
//! quotient polynomial `h(x)`. Instead it reconstructs the batched numerator
//! `nu_y(x)` from the polynomial evaluations that were already read after the
//! Fiat-Shamir challenge `x`, and then opens the linearized commitment at the
//! scalar `-nu_y(x)`. The commitment side contributes
//! `(1 - x^n) * sum_i x_split^i * Q_i` for the quotient limbs, so the scalar
//! stored in verifier memory is deliberately the negated numerator, not
//! `h(x) = nu_y(x) / (x^n - 1)`.
//!
//! This module is the Rust producer for that reconstruction. It lowers Halo2
//! quotient identities into a compact bytecode stream plus a constant table;
//! `templates/QuotientNumeratorBlock.yul` is the only runtime consumer. The VM
//! is therefore an ABI between generated VK data and generated Solidity: opcode
//! numbers, operand widths, memory tokens, stack discipline, fold order, and
//! native callback markers must change in lockstep with the Yul template and
//! the tests that compare the tables.
//!
//! Correctness comes from preserving the same identity stream used by
//! `midnight_proofs::plonk::partially_evaluate_identities` and
//! `compute_linearization_commitment`:
//!
//! ```text
//! identities: e_0, e_1, ..., e_(m-1)
//! main accumulator scan: acc <- acc * y + e_i
//! final main scalar: sum_i e_i * y^(m - 1 - i)
//! ```
//!
//! The Rust linearization code computes the same scalar by reverse-folding
//! powers of `y`; the Yul VM scans forward with Horner's rule because that is
//! cheaper and streaming-friendly. A simple-selector identity still advances
//! the global `y` position, but its value is sent to the selector commitment
//! bucket instead of the fully evaluated numerator. The selector positions are
//! known at code generation time, so each selector bucket is advanced only by
//! the gap since the previous identity for the same selector, then by its final
//! tail. That preserves the same `y^(m-1-i)` powers without computing `y^-1`
//! or updating every selector bucket position on unrelated identities.
//!
//! The VM is intentionally small rather than general-purpose. It has only Fr
//! arithmetic, memory loads from generated verifier addresses, a deduplicated
//! VK-resident constant table, optional common-subexpression temporaries, and a
//! few fused opcodes for shapes that dominate Midfall quotient identities.
//! Whole-family native markers, such as permutation and lookup callbacks, are
//! domain-shaped superinstructions: they preserve identity order while moving
//! regular product-loop arithmetic out of the interpreter. The limb-aware
//! opcodes are justified as structural compression of foreign-field limb
//! expressions; they do not change the source of truth and they still evaluate
//! the resulting PLONK identity over BLS12-381 Fr.
//!
//! Finalized bytecode is decoded again after run compaction or packed32
//! lowering. That safety pass rejects unknown opcodes, truncated operands,
//! unknown memory tokens, stack underflow, and identity-boundary stack leaks
//! before the bytes can be pinned into a VK runtime.

use super::*;

/// Destination of one evaluated quotient identity.
///
/// Each identity occupies exactly one position in the global `y` batch. The
/// target only decides where the evaluated scalar is accumulated after that
/// position has been consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuotientTarget {
    /// Fully evaluated identity.
    ///
    /// The value contributes to the reconstructed numerator scalar. After the
    /// whole stream has been consumed, the Yul runtime stores the negation in
    /// `QUOTIENT_EVAL_MPTR`.
    Main,
    /// Simple-selector identity.
    ///
    /// The `usize` is an index into the sorted simple-selector column list,
    /// not the fixed-column index itself. The value is accumulated into the
    /// matching selector commitment bucket while still advancing the global
    /// `y` batch.
    Selector(usize),
}

/// Source metadata for one internal quotient identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct QuotientIdentityMetadata {
    /// Position in the global `y`-batch.
    pub(super) global_index: usize,
    /// Source family and source-local metadata.
    pub(super) source: QuotientIdentitySource,
}

/// Complete VM artifact emitted into the generated verifying-key payload.
///
/// The generator memory planner uses this to reserve constant, bytecode, stack,
/// and temporary regions; the Yul template uses the same values to interpret
/// the program. The build is intentionally self-contained so the external
/// quotient evaluator can execute with only the copied verifier frame plus VK
/// payload data.
#[derive(Debug)]
pub(super) struct QuotientProgramBuild {
    /// Encoded bytecode.
    ///
    /// This is either byte-oriented or packed32, depending on `packed32`.
    pub(super) bytes: Vec<u8>,
    /// Deduplicated Fr constants addressed by `PUSH_CONST` and fused opcodes.
    pub(super) consts: Vec<U256>,
    /// Maximum operand-stack depth of the pure interpreted bytecode.
    ///
    /// Native callbacks may reuse the same stack base as structured scratch,
    /// so the generator folds their scratch requirement into the final
    /// allocation separately.
    pub(super) max_stack: usize,
    /// Whether `bytes` is packed32 rather than byte-oriented.
    pub(super) packed32: bool,
    /// Number of temporary words addressed by `PUSH_TEMP` and `STORE_TEMP`.
    ///
    /// Persistent VM state slots are laid out immediately after these temps.
    pub(super) cse_temps: usize,
    /// Opcode bytes actually present in the finalized physical program.
    ///
    /// The template uses this to render only the interpreter cases reachable
    /// by this VK-specialized quotient program.
    pub(super) used_ops: Vec<u8>,
    /// Memory-token operands actually present in the finalized physical program.
    pub(super) used_mem_tokens: Vec<u8>,
}

/// One Halo2 quotient identity in both legacy-Yul and VM-ready forms.
///
/// The normal evaluator still emits assignment lines because direct inline
/// paths and native callbacks reuse them. The compact VM prefers `expr` when it
/// is available because typed lowering avoids parsing generated Yul. For
/// permutation, lookup, and trash identities the module can still reconstruct a
/// `QuotientExpr` from `lines` and `var`.
#[derive(Clone, Debug)]
pub(super) struct QuotientIdentity {
    /// Host-side diagnostic metadata for this identity.
    pub(super) meta: QuotientIdentityMetadata,
    /// Yul assignment lines emitted by the existing evaluator.
    pub(super) lines: Vec<String>,
    /// Name of the Yul variable holding the final identity evaluation.
    pub(super) var: String,
    /// Accumulator target for this identity.
    pub(super) target: QuotientTarget,
    /// Typed expression form used by the VM when available.
    pub(super) expr: Option<QuotientExpr>,
}

#[cfg(test)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RepackedProofScalarLayout {
    pub(crate) eval_offset: usize,
    pub(crate) num_evals: usize,
    pub(crate) q_eval_offset: usize,
    pub(crate) num_point_sets: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct RepackedProofLayoutPlan {
    /// Counts of compressed G1 commitments read before scalar evaluations.
    pub(crate) g1_groups: Vec<usize>,
    /// Number of ordinary evaluation scalars.
    pub(crate) num_evals: usize,
    /// Number of quotient-opening point-set scalars.
    pub(crate) num_point_sets: usize,
}

impl RepackedProofLayoutPlan {
    /// Build a proof repacking plan from the typed Solidity calldata layout.
    pub(crate) fn from_proof_layout(
        layout: &crate::codegen::proof_layout::ProofCalldataLayout,
    ) -> Self {
        Self {
            g1_groups: layout.commitment_read_groups(),
            num_evals: layout.evals.item_count,
            num_point_sets: layout.q_evals.item_count,
        }
    }

    /// Number of compressed G1 points before the scalar eval block.
    pub(crate) fn prefix_g1_count(&self) -> usize {
        self.g1_groups.iter().sum()
    }

    /// Native compressed proof byte length expected by the repacker.
    pub(crate) fn compressed_len(&self) -> usize {
        self.prefix_g1_count() * crate::codegen::layout::G1_COMPRESSED_BYTES
            + self.num_evals * crate::codegen::layout::WORD_BYTES
            + crate::codegen::layout::G1_COMPRESSED_BYTES
            + self.num_point_sets * crate::codegen::layout::WORD_BYTES
            + crate::codegen::layout::G1_COMPRESSED_BYTES
    }

    /// Solidity-facing EIP-2537-padded proof byte length after repacking.
    pub(crate) fn repacked_len(&self) -> usize {
        self.prefix_g1_count() * crate::codegen::layout::G1_BYTES
            + self.num_evals * crate::codegen::layout::WORD_BYTES
            + crate::codegen::layout::G1_BYTES
            + self.num_point_sets * crate::codegen::layout::WORD_BYTES
            + crate::codegen::layout::G1_BYTES
    }

    #[cfg(test)]
    #[allow(dead_code)]
    /// Return scalar offsets within the repacked proof for tests.
    pub(crate) fn scalar_layout(&self) -> RepackedProofScalarLayout {
        let eval_offset = self.prefix_g1_count() * crate::codegen::layout::G1_BYTES;
        let q_eval_offset = eval_offset
            + self.num_evals * crate::codegen::layout::WORD_BYTES
            + crate::codegen::layout::G1_BYTES;
        RepackedProofScalarLayout {
            eval_offset,
            num_evals: self.num_evals,
            q_eval_offset,
            num_point_sets: self.num_point_sets,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct QuotientIdentityParts {
    /// Gate identities, in the order returned by the upstream constraint system.
    pub(super) gates: Vec<QuotientIdentity>,
    /// Permutation identities, after gates.
    pub(super) permutation: Vec<QuotientIdentity>,
    /// Lookup identities, after permutation.
    pub(super) lookup: Vec<QuotientIdentity>,
    /// Trashcan identities, after lookup.
    pub(super) trash: Vec<QuotientIdentity>,
    /// Sorted fixed-column indices for simple selectors.
    ///
    /// VM selector targets use positions in this vector so generated memory
    /// buckets are stable even if fixed-column numbers are sparse.
    pub(super) sorted_simple: Vec<usize>,
}

impl QuotientIdentityParts {
    /// Return every identity in global y-batch order.
    pub(super) fn all_identities(&self) -> Vec<QuotientIdentity> {
        self.gates
            .iter()
            .chain(self.permutation.iter())
            .chain(self.lookup.iter())
            .chain(self.trash.iter())
            .cloned()
            .collect()
    }

    /// Return the host-side manifest for these identities.
    #[cfg(test)]
    pub(super) fn manifest(&self) -> QuotientIdentityManifest {
        let entries = self
            .gates
            .iter()
            .chain(self.permutation.iter())
            .chain(self.lookup.iter())
            .chain(self.trash.iter())
            .map(|identity| QuotientIdentityManifestEntry {
                global_index: identity.meta.global_index,
                source: identity.meta.source.clone(),
                target: quotient_manifest_target(identity.target, &self.sorted_simple),
            })
            .collect();

        QuotientIdentityManifest {
            entries,
            gate_identities: self.gates.len(),
            permutation_identities: self.permutation.len(),
            lookup_identities: self.lookup.len(),
            trash_identities: self.trash.len(),
            simple_selector_cols: self.sorted_simple.clone(),
        }
    }
}

#[cfg(test)]
fn quotient_manifest_target(
    target: QuotientTarget,
    sorted_simple: &[usize],
) -> QuotientIdentityManifestTarget {
    match target {
        QuotientTarget::Main => QuotientIdentityManifestTarget::Main,
        QuotientTarget::Selector(selector_index) => QuotientIdentityManifestTarget::Selector {
            selector_index,
            fixed_column: sorted_simple[selector_index],
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuotientStructuredTailMode {
    /// Emit all non-inline identities through the selected VM/direct path.
    Off,
    /// Emit the trash identity suffix as structured Yul after the VM program.
    Trash,
}

/// Logical stream item before final bytecode lowering.
///
/// Native items are not arithmetic opcodes in the Rust builder. They are
/// identity-position markers; the Yul template replaces them with generated
/// callback blocks that perform their own evaluation and fold at exactly the
/// same point in the global `y` batch.
#[derive(Clone, Debug)]
pub(super) enum QuotientProgramItem {
    /// Identity interpreted by the compact VM.
    Identity(QuotientIdentity),
    /// Generated callback for the whole permutation identity block.
    NativePermutation,
    /// Generated callback for the whole lookup identity block.
    NativeLookup,
    /// Generated callback for a selected heavy gate identity.
    NativeIdentity(usize),
}

/// Hybrid execution plan for quotient numerator reconstruction.
///
/// A small prefix may stay inline, most identities become VM bytecode, and
/// selected expensive shapes can become native callbacks. The plan is a
/// representation choice only: it must preserve the original identity order and
/// the target of every identity.
#[derive(Clone, Debug)]
pub(super) struct QuotientProgramPlan {
    /// Gate prefix emitted directly before the VM loop.
    pub(super) inline_identities: Vec<QuotientIdentity>,
    /// VM/native stream after the inline prefix.
    pub(super) items: Vec<QuotientProgramItem>,
    /// Bodies for `NativeIdentity` markers, addressed by marker index.
    pub(super) native_identities: Vec<QuotientIdentity>,
    /// Shared selector-column ordering.
    pub(super) sorted_simple: Vec<usize>,
    /// Whether the stream contains a native permutation callback marker.
    pub(super) has_native_permutation: bool,
    /// Whether the stream contains a native lookup callback marker.
    pub(super) has_native_lookup: bool,
    /// Gap exponents for simple-selector buckets in the global y-batch.
    pub(super) selector_fold: SelectorFoldPlan,
}

/// Codegen-time selector-bucket schedule for gap-based forward folding.
///
/// Fully evaluated identities still use the ordinary Horner scan. Selector
/// identities are sparse in that global stream, so each selector bucket only
/// needs to be advanced across the gap since the previous identity for the same
/// selector and then across the final tail after the stream ends.
#[derive(Clone, Debug, Default)]
pub(super) struct SelectorFoldPlan {
    /// `Some(gap)` for selector identities by global identity index.
    pub(super) gaps_by_identity: Vec<Option<usize>>,
    /// Final y-power tail for each selector bucket.
    pub(super) tail_exponents: Vec<usize>,
    /// Largest exponent referenced by either gaps or tails.
    pub(super) max_power: usize,
}

impl SelectorFoldPlan {
    pub(super) fn gap_for(&self, identity: &QuotientIdentity) -> Option<usize> {
        self.gaps_by_identity
            .get(identity.meta.global_index)
            .copied()
            .flatten()
    }
}

pub(super) const QUOTIENT_EXTERNAL_MAGIC: u64 = 0x5155_4556_414c_0001;
// Coefficients used by generated limb helper snippets in direct/native Yul
// paths. The VM limb opcodes do not hard-code these values; they load the
// corresponding Fr constants from the VK payload so the bytecode remains a
// representation of the actual lowered expression.
pub(super) const LIMB7_YUL_COEFFS: [&str; layout::quotient_limb::LIN_COEFFS] = [
    "0x100000000000000",
    "0x10000000000000000000000000000",
    "0x400000000",
    "0x40000000000000000000000",
    "0x1000",
    "0x100000000000000000",
];
pub(super) const WIDE_LIMB7_YUL_COEFFS: [&str; layout::quotient_limb::LIN_COEFFS] = [
    "0x100000000000000",
    "0x10000000000000000000000000000",
    "0x1000000000000000000000000000000000000000000",
    "0x100000000000000000000000000000000000000000000000000000000",
    "0x6bc66e553973f396854f5626172ba135587d41e37a68209402355093fdcaaf6c",
    "0x63f31e3f446953960c9d6964474300df43ab29179970f642a28e39d6c883c74b",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuotientProgramEncoding {
    /// Variable-length byte stream.
    ///
    /// This is the only encoding that supports limb-aware opcodes and
    /// run-compacted fused add-mul instructions.
    Bytes,
    /// Four-byte instruction words.
    ///
    /// The high byte is the opcode and the low 24 bits are the primary
    /// operand. It is easier to decode in Yul, but not every opcode shape fits
    /// this format.
    Packed32,
}

pub(super) const QUOTIENT_VM_PACKED_INSTRUCTION_BYTES: usize = 4;
pub(super) const QUOTIENT_VM_PACKED_ARG_BITS: usize = 24;
pub(super) const QUOTIENT_VM_PACKED_ARG_MASK: u32 = 0x00ff_ffff;
pub(super) const QUOTIENT_VM_RUN_COMPACTION_MIN_LEN: usize = 4;
pub(super) const QUOTIENT_VM_BYTE_U16_BYTES: usize = 2;
pub(super) const QUOTIENT_VM_BYTE_U24_BYTES: usize = 3;
pub(super) const QUOTIENT_VM_BYTE_U32_BYTES: usize = 4;
pub(super) const QUOTIENT_VM_LIMBS: usize = layout::quotient_limb::LIMBS;
pub(super) const QUOTIENT_VM_PAIRWISE_TERMS: usize = layout::quotient_limb::PAIRWISE_TERMS;
pub(super) const QUOTIENT_VM_PAIRWISE_COEFFS: usize = layout::quotient_limb::PAIRWISE_COEFFS;

// Opcode assignments are part of the verifier/VK ABI.
//
// Stack convention:
//   * push opcodes place a value in q_top, spilling the previous top to the
//     memory stack when needed;
//   * generic ADD/MUL consume one spilled operand and q_top, leaving q_top;
//   * accumulator opcodes mutate q_top in place and have zero stack effect;
//   * FOLD_* consumes q_top and advances the quotient y-batch;
//   * native callback markers require an empty stack at identity boundaries.
//
// The numeric assignments are intentionally sparse. Keep 0x1a reserved:
// historical builds used it for an experimental native trash callback, but the
// current VM intentionally has no operation at that value.
pub(super) const Q_OP_PUSH_CONST: u8 = 0x01;
pub(super) const Q_OP_PUSH_MEM_LITERAL: u8 = 0x02;
pub(super) const Q_OP_PUSH_MEM_TOKEN: u8 = 0x03;
pub(super) const Q_OP_PUSH_MEM_TOKEN_OFFSET: u8 = 0x04;
pub(super) const Q_OP_PUSH_MEM_U16: u8 = 0x05;
pub(super) const Q_OP_ADD: u8 = 0x06;
pub(super) const Q_OP_MUL: u8 = 0x07;
pub(super) const Q_OP_NEG: u8 = 0x08;
pub(super) const Q_OP_PUSH_CONST_U8: u8 = 0x09;
pub(super) const Q_OP_FOLD_MAIN: u8 = 0x0a;
pub(super) const Q_OP_FOLD_SELECTOR: u8 = 0x0b;
pub(super) const Q_OP_ADD_CONST_U8: u8 = 0x0c;
pub(super) const Q_OP_MUL_CONST_U8: u8 = 0x0d;
pub(super) const Q_OP_ADD_CONST: u8 = 0x0e;
pub(super) const Q_OP_MUL_CONST: u8 = 0x0f;
pub(super) const Q_OP_ADD_MEM_U16: u8 = 0x10;
pub(super) const Q_OP_MUL_MEM_U16: u8 = 0x11;
pub(super) const Q_OP_ADD_MUL_MEM_MEM_CONST_U8: u8 = 0x12;
pub(super) const Q_OP_ADD_MUL_CONST_U8_MEM_U16: u8 = 0x13;
pub(super) const Q_OP_ADD_MUL_MEM_MEM: u8 = 0x14;
pub(super) const Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8: u8 = 0x15;
pub(super) const Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16: u8 = 0x16;
pub(super) const Q_OP_PUSH_TEMP: u8 = 0x17;
pub(super) const Q_OP_STORE_TEMP: u8 = 0x18;
pub(super) const Q_OP_NATIVE_PERMUTATION: u8 = 0x19;
pub(super) const Q_OP_NATIVE_IDENTITY: u8 = 0x1b;
pub(super) const Q_OP_LIN7: u8 = 0x1c;
pub(super) const Q_OP_BILIN7_ROW: u8 = 0x1d;
pub(super) const Q_OP_BILIN7_PAIRWISE: u8 = 0x1e;
pub(super) const Q_OP_NATIVE_LOOKUP: u8 = 0x1f;
pub(super) const Q_OP_POW5: u8 = 0x20;
pub(super) const Q_OP_MODARITH7: u8 = 0x21;

const Q_MODARITH7_FLAG_COND: u8 = 0x01;
const Q_MODARITH7_FLAG_CONST: u8 = 0x02;

// Memory tokens compress generated Yul symbols whose concrete addresses depend
// on the memory planner. Literal pointers are used for most proof/VK evals;
// tokens cover shared challenge/common-polynomial locations that are easier and
// safer to address symbolically in generated code.
pub(super) const Q_MEM_L0: u8 = 0x01;
pub(super) const Q_MEM_L_LAST: u8 = 0x02;
pub(super) const Q_MEM_L_BLIND: u8 = 0x03;
pub(super) const Q_MEM_BETA: u8 = 0x04;
pub(super) const Q_MEM_GAMMA: u8 = 0x05;
pub(super) const Q_MEM_X: u8 = 0x06;
pub(super) const Q_MEM_THETA: u8 = 0x07;
pub(super) const Q_MEM_TRASH_CHALLENGE: u8 = 0x08;
pub(super) const Q_MEM_INSTANCE_EVAL: u8 = 0x09;

/// Operand decoder classes shared by tests and docs.
///
/// The Yul template is the runtime decoder; this enum is the compile-time/spec
/// view of the same ABI. Encodings with zero fixed byte length are dynamic
/// byte-only forms and are rejected by packed32 lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuotientOpcodeEncoding {
    None,
    U8,
    U16,
    U24,
    U32,
    TokenOffset,
    AddMulMemMemConstU8,
    AddMulConstU8MemU16,
    AddMulMemMem,
    RunAddMulMemMemConstU8,
    RunAddMulConstU8MemU16,
    LimbLin,
    LimbBilinRow,
    LimbBilinPairwise,
    LimbModarith7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuotientOpcodeSpec {
    /// Stable snake-case name rendered into template constants.
    pub(super) name: &'static str,
    /// Stable opcode byte.
    pub(super) opcode: u8,
    /// Byte length in byte-oriented encoding, or zero for dynamic run forms.
    pub(super) byte_len: usize,
    /// Operand decoding class.
    pub(super) encoding: QuotientOpcodeEncoding,
    /// Whether this logical opcode can be represented in packed32 form.
    pub(super) packed32: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuotientMemTokenSpec {
    /// Generated Yul memory symbol.
    pub(super) name: &'static str,
    /// Stable compact token used by VM bytecode.
    pub(super) token: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuotientVmSpec {
    /// Complete opcode table, used by template constants and ABI tests.
    pub(super) opcodes: &'static [QuotientOpcodeSpec],
    /// Complete memory-token table, used by template constants and ABI tests.
    pub(super) mem_tokens: &'static [QuotientMemTokenSpec],
    /// Packed32 instruction width.
    pub(super) packed_instruction_bytes: usize,
    /// Number of packed32 operand bits.
    pub(super) packed_arg_bits: usize,
    /// Packed32 operand mask.
    pub(super) packed_arg_mask: u32,
    /// Minimum adjacent fused-op run length worth compacting.
    pub(super) run_compaction_min_len: usize,
    /// Number of foreign-field limbs recognized by limb opcodes.
    pub(super) limb_count: usize,
    /// Number of products in a 7-by-7 pairwise convolution.
    pub(super) limb_pairwise_terms: usize,
    /// Number of distinct `i + j` coefficients in that convolution.
    pub(super) limb_pairwise_coeffs: usize,
}

pub(super) const QUOTIENT_OPCODE_TABLE: &[QuotientOpcodeSpec] = &[
    QuotientOpcodeSpec {
        name: "push_const",
        opcode: Q_OP_PUSH_CONST,
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::U16,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "push_mem_literal",
        opcode: Q_OP_PUSH_MEM_LITERAL,
        byte_len: 1 + QUOTIENT_VM_BYTE_U32_BYTES,
        encoding: QuotientOpcodeEncoding::U32,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "push_mem_token",
        opcode: Q_OP_PUSH_MEM_TOKEN,
        byte_len: 1 + 1,
        encoding: QuotientOpcodeEncoding::U8,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "push_mem_token_offset",
        opcode: Q_OP_PUSH_MEM_TOKEN_OFFSET,
        byte_len: 1 + 1 + QUOTIENT_VM_BYTE_U32_BYTES,
        encoding: QuotientOpcodeEncoding::TokenOffset,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "push_mem_u16",
        opcode: Q_OP_PUSH_MEM_U16,
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::U16,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "add",
        opcode: Q_OP_ADD,
        byte_len: 1,
        encoding: QuotientOpcodeEncoding::None,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "mul",
        opcode: Q_OP_MUL,
        byte_len: 1,
        encoding: QuotientOpcodeEncoding::None,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "neg",
        opcode: Q_OP_NEG,
        byte_len: 1,
        encoding: QuotientOpcodeEncoding::None,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "push_const_u8",
        opcode: Q_OP_PUSH_CONST_U8,
        byte_len: 1 + 1,
        encoding: QuotientOpcodeEncoding::U8,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "fold_main",
        opcode: Q_OP_FOLD_MAIN,
        byte_len: 1,
        encoding: QuotientOpcodeEncoding::None,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "fold_selector",
        opcode: Q_OP_FOLD_SELECTOR,
        byte_len: 1 + QUOTIENT_VM_BYTE_U24_BYTES,
        encoding: QuotientOpcodeEncoding::U24,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "add_const_u8",
        opcode: Q_OP_ADD_CONST_U8,
        byte_len: 1 + 1,
        encoding: QuotientOpcodeEncoding::U8,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "mul_const_u8",
        opcode: Q_OP_MUL_CONST_U8,
        byte_len: 1 + 1,
        encoding: QuotientOpcodeEncoding::U8,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "add_const",
        opcode: Q_OP_ADD_CONST,
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::U16,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "mul_const",
        opcode: Q_OP_MUL_CONST,
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::U16,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "add_mem_u16",
        opcode: Q_OP_ADD_MEM_U16,
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::U16,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "mul_mem_u16",
        opcode: Q_OP_MUL_MEM_U16,
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::U16,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "add_mul_mem_mem_const_u8",
        opcode: Q_OP_ADD_MUL_MEM_MEM_CONST_U8,
        byte_len: 1 + 2 * QUOTIENT_VM_BYTE_U16_BYTES + 1,
        encoding: QuotientOpcodeEncoding::AddMulMemMemConstU8,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "add_mul_const_u8_mem_u16",
        opcode: Q_OP_ADD_MUL_CONST_U8_MEM_U16,
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES + 1,
        encoding: QuotientOpcodeEncoding::AddMulConstU8MemU16,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "add_mul_mem_mem",
        opcode: Q_OP_ADD_MUL_MEM_MEM,
        byte_len: 1 + 2 * QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::AddMulMemMem,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "run_add_mul_mem_mem_const_u8",
        opcode: Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8,
        byte_len: 0,
        encoding: QuotientOpcodeEncoding::RunAddMulMemMemConstU8,
        packed32: false,
    },
    QuotientOpcodeSpec {
        name: "run_add_mul_const_u8_mem_u16",
        opcode: Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16,
        byte_len: 0,
        encoding: QuotientOpcodeEncoding::RunAddMulConstU8MemU16,
        packed32: false,
    },
    QuotientOpcodeSpec {
        name: "push_temp",
        opcode: Q_OP_PUSH_TEMP,
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::U16,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "store_temp",
        opcode: Q_OP_STORE_TEMP,
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::U16,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "native_permutation",
        opcode: Q_OP_NATIVE_PERMUTATION,
        byte_len: 1,
        encoding: QuotientOpcodeEncoding::None,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "native_lookup",
        opcode: Q_OP_NATIVE_LOOKUP,
        byte_len: 1,
        encoding: QuotientOpcodeEncoding::None,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "native_identity",
        opcode: Q_OP_NATIVE_IDENTITY,
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::U16,
        packed32: true,
    },
    QuotientOpcodeSpec {
        name: "lin7",
        opcode: Q_OP_LIN7,
        byte_len: 1 + QUOTIENT_VM_LIMBS * (1 + QUOTIENT_VM_BYTE_U16_BYTES),
        encoding: QuotientOpcodeEncoding::LimbLin,
        packed32: false,
    },
    QuotientOpcodeSpec {
        name: "bilin7_row",
        opcode: Q_OP_BILIN7_ROW,
        byte_len: 1
            + QUOTIENT_VM_BYTE_U16_BYTES
            + QUOTIENT_VM_LIMBS * (1 + QUOTIENT_VM_BYTE_U16_BYTES),
        encoding: QuotientOpcodeEncoding::LimbBilinRow,
        packed32: false,
    },
    QuotientOpcodeSpec {
        name: "bilin7_pairwise",
        opcode: Q_OP_BILIN7_PAIRWISE,
        byte_len: 1 + 2 * QUOTIENT_VM_BYTE_U16_BYTES + QUOTIENT_VM_PAIRWISE_COEFFS,
        encoding: QuotientOpcodeEncoding::LimbBilinPairwise,
        packed32: false,
    },
    QuotientOpcodeSpec {
        name: "modarith7",
        opcode: Q_OP_MODARITH7,
        byte_len: 0,
        encoding: QuotientOpcodeEncoding::LimbModarith7,
        packed32: false,
    },
    QuotientOpcodeSpec {
        name: "pow5",
        opcode: Q_OP_POW5,
        byte_len: 1,
        encoding: QuotientOpcodeEncoding::None,
        packed32: true,
    },
];

pub(super) const QUOTIENT_MEM_TOKEN_TABLE: &[QuotientMemTokenSpec] = &[
    QuotientMemTokenSpec {
        name: "L_0_MPTR",
        token: Q_MEM_L0,
    },
    QuotientMemTokenSpec {
        name: "L_LAST_MPTR",
        token: Q_MEM_L_LAST,
    },
    QuotientMemTokenSpec {
        name: "L_BLIND_MPTR",
        token: Q_MEM_L_BLIND,
    },
    QuotientMemTokenSpec {
        name: "BETA_MPTR",
        token: Q_MEM_BETA,
    },
    QuotientMemTokenSpec {
        name: "GAMMA_MPTR",
        token: Q_MEM_GAMMA,
    },
    QuotientMemTokenSpec {
        name: "X_MPTR",
        token: Q_MEM_X,
    },
    QuotientMemTokenSpec {
        name: "THETA_MPTR",
        token: Q_MEM_THETA,
    },
    QuotientMemTokenSpec {
        name: "TRASH_CHALLENGE_MPTR",
        token: Q_MEM_TRASH_CHALLENGE,
    },
    QuotientMemTokenSpec {
        name: "INSTANCE_EVAL_MPTR",
        token: Q_MEM_INSTANCE_EVAL,
    },
];

pub(super) const QUOTIENT_VM_SPEC: QuotientVmSpec = QuotientVmSpec {
    opcodes: QUOTIENT_OPCODE_TABLE,
    mem_tokens: QUOTIENT_MEM_TOKEN_TABLE,
    packed_instruction_bytes: QUOTIENT_VM_PACKED_INSTRUCTION_BYTES,
    packed_arg_bits: QUOTIENT_VM_PACKED_ARG_BITS,
    packed_arg_mask: QUOTIENT_VM_PACKED_ARG_MASK,
    run_compaction_min_len: QUOTIENT_VM_RUN_COMPACTION_MIN_LEN,
    limb_count: QUOTIENT_VM_LIMBS,
    limb_pairwise_terms: QUOTIENT_VM_PAIRWISE_TERMS,
    limb_pairwise_coeffs: QUOTIENT_VM_PAIRWISE_COEFFS,
};

/// Return the VM opcode spec for a stable opcode byte.
pub(super) fn quotient_opcode_spec(opcode: u8) -> Option<&'static QuotientOpcodeSpec> {
    QUOTIENT_VM_SPEC
        .opcodes
        .iter()
        .find(|spec| spec.opcode == opcode)
}

/// Return the fixed byte length of an opcode in byte-oriented encoding.
///
/// Dynamic run opcodes intentionally return `None`; callers that need to walk
/// bytecode containing those forms must decode the run count and operand width.
pub(super) fn quotient_opcode_byte_len(opcode: u8) -> Option<usize> {
    quotient_opcode_spec(opcode).and_then(|spec| (spec.byte_len != 0).then_some(spec.byte_len))
}

/// Convert a little-endian proof scalar into the big-endian 32-byte EVM word.
///
/// Proof calldata uses scalar-byte order from the host encoding; EVM `mstore`
/// and arithmetic consume canonical big-endian words.
pub(super) fn scalar_le_to_be_word(bytes: &[u8]) -> [u8; 32] {
    assert_eq!(bytes.len(), 32, "scalar proof element must be 32 bytes");
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(bytes);
    scalar.reverse();
    scalar
}

/// Field-expression AST accepted by the quotient VM builder.
///
/// This is a deliberately tiny subset of Halo2 expressions and generated Yul:
/// constants, verifier-memory loads, and Fr addition/multiplication/negation.
/// Keeping the tree this small makes bytecode lowering auditable and lets the
/// structural limb recognizers operate without depending on gate names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum QuotientExpr {
    /// Native Fr constant encoded as a `U256`.
    Const(U256),
    /// Memory-backed verifier value.
    Mem(QuotientMem),
    /// Fr addition modulo the scalar field.
    Add(Box<QuotientExpr>, Box<QuotientExpr>),
    /// Fr multiplication modulo the scalar field.
    Mul(Box<QuotientExpr>, Box<QuotientExpr>),
    /// Fr negation modulo the scalar field.
    Neg(Box<QuotientExpr>),
}

/// Optional instrumentation counters for limb-specialized lowering.
///
/// The profile is emitted only under the tuning env flag; it is not part of
/// the generated verifier ABI.
#[derive(Clone, Debug, Default)]
pub(super) struct QuotientShapeProfile {
    /// Number of whole affine foreign-field/ECC identities emitted.
    pub(super) modarith7: usize,
    /// Number of `LIN7` expressions emitted.
    pub(super) lin7: usize,
    /// Number of `BILIN7_ROW` expressions emitted.
    pub(super) bilin7_row: usize,
    /// Number of `BILIN7_PAIRWISE` expressions emitted.
    pub(super) bilin7_pairwise: usize,
    /// Number of `POW5` expressions emitted.
    pub(super) pow5: usize,
    /// Fallback non-limb VM operations emitted while limb profiling is active.
    pub(super) fallback_vm_ops: usize,
}

/// Structural foreign-field limb shapes compressed by dedicated opcodes.
///
/// These are recognized from the expression tree alone. That constraint is
/// important: adding a limb opcode must never make correctness depend on a
/// gate label or on a hand-maintained list of circuit gadgets. If a shape is
/// not recognized exactly, the builder falls back to ordinary Fr VM opcodes.
#[derive(Clone, Debug)]
pub(super) enum QuotientLimbShape {
    // Structural forms from the Midfall foreign-field chips, not gate-name
    // dispatch. Rust source shapes:
    //   circuits/src/field/foreign/util.rs::sum_exprs
    //   circuits/src/field/foreign/util.rs::pair_wise_prod
    //   circuits/src/field/foreign/params.rs::base_powers
    //   circuits/src/field/foreign/params.rs::double_base_powers
    //
    // These expressions emulate arithmetic modulo a foreign modulus `m`
    // inside the circuit, but the verifier still evaluates the resulting
    // PLONK identity polynomial over the native BLS12-381 scalar field Fr.
    // The coefficients are Fr encodings of base^i mod m or base^(i+j) mod m.
    Lin7 {
        terms: Vec<(U256, u16)>,
    },
    Bilin7Row {
        lhs: u16,
        terms: Vec<(U256, u16)>,
    },
    Bilin7Pairwise {
        lhs_base: u16,
        rhs_base: u16,
        coeffs: Vec<U256>,
    },
}

/// One fused foreign-field/ECC affine identity.
///
/// This is a bundled version of the same structural limb blocks as
/// `QuotientLimbShape`, plus scalar memory terms and an optional outer
/// condition. It deliberately remains expression-shaped rather than
/// gate-name-shaped:
///
/// ```text
/// maybe_cond * (
///     c
///   + sum lin7 blocks
///   + sum row-bilinear blocks
///   + sum pairwise-bilinear blocks
///   + sum scalar_coeff_i * mload(ptr_i)
///   + sum product_coeff_i * mload(lhs_i) * mload(rhs_i)
/// )
/// ```
///
/// Some first-modulus residues reduce to sparse affine product identities with
/// no dense seven-limb block left. Those are still encoded here when they are
/// conditionally gated, which keeps the opcode tied to ModArith-style custom
/// gate checks rather than tiny generic arithmetic snippets.
#[derive(Clone, Debug)]
pub(super) struct QuotientModarith7Shape {
    cond: Option<u16>,
    constant: U256,
    lin: Vec<Vec<(U256, u16)>>,
    rows: Vec<(u16, Vec<(U256, u16)>)>,
    pairwise: Vec<(u16, u16, Vec<U256>)>,
    mem_terms: Vec<(U256, u16)>,
    product_terms: Vec<(U256, u16, u16)>,
}

#[derive(Debug, Default)]
pub(super) struct QuotientCseState {
    // Expression key -> temp slot chosen before emission. Slots are stable
    // across the whole VM program, so repeated subexpressions can be shared
    // between identities rather than only within one identity.
    pub(super) slots: HashMap<String, u16>,
    // Expression key -> temp slot already materialized in bytecode. This
    // prevents recursive emit from generating the same STORE_TEMP repeatedly.
    pub(super) emitted: HashMap<String, u16>,
}

impl QuotientCseState {
    /// Pre-compute VM temporary slots for profitable repeated subexpressions.
    ///
    /// Slot assignment is deterministic: expressions are sorted by estimated
    /// bytecode savings and then by key. That keeps VK bytecode stable across
    /// hash-map iteration order and makes generated verifier hashes reproducible.
    pub(super) fn from_exprs(exprs: &[QuotientExpr]) -> Self {
        let mut counts = HashMap::new();
        let mut costs = HashMap::new();
        for expr in exprs {
            count_quotient_exprs(expr, &mut counts, &mut costs);
        }

        let mut keyed_counts = counts
            .iter()
            .filter_map(|(key, &count)| {
                let cost = costs.get(key).copied().unwrap_or_default();
                if quotient_cse_candidate(count, cost) {
                    Some((key.clone(), count, cost))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        keyed_counts.sort_by(|(lhs, lhs_count, lhs_cost), (rhs, rhs_count, rhs_cost)| {
            quotient_cse_sort_key(lhs, *lhs_count, *lhs_cost)
                .cmp(&quotient_cse_sort_key(rhs, *rhs_count, *rhs_cost))
        });

        let mut slots = HashMap::new();
        for (key, _, _) in keyed_counts {
            let slot = slots.len();
            assert!(slot <= u16::MAX as usize, "too many quotient CSE temps");
            slots.insert(key, slot as u16);
        }

        Self {
            slots,
            emitted: HashMap::new(),
        }
    }
}

/// Compact reference to a verifier memory word.
///
/// Literal pointers are encoded directly when they fit. Tokens represent
/// generated Yul symbols whose concrete address can change with the memory
/// layout; token offsets support structured regions rooted at those symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum QuotientMem {
    /// Absolute memory pointer.
    Literal(u32),
    /// Generated memory symbol token.
    Token(u8),
    /// Generated memory symbol token plus byte offset.
    TokenOffset(u8, u32),
}

/// Straight-line Yul CSE plan for the direct inline quotient path.
///
/// This is separate from VM CSE because it stores real generated Yul
/// expressions rather than bytecode temps. The cost model is intentionally
/// conservative: inline CSE increases memory traffic, so it is used only when
/// duplicated arithmetic is large enough to pay for the extra `mstore` and
/// `mload` instructions.
#[derive(Debug)]
pub(super) struct QuotientInlineCsePlan {
    /// Expression key to temp slot.
    pub(super) slots: HashMap<String, u16>,
    /// Expression key to expression body used to materialize the slot.
    pub(super) exprs: HashMap<String, QuotientExpr>,
}

impl QuotientInlineCsePlan {
    /// Build a deterministic inline-CSE plan from identity expressions.
    pub(super) fn new(exprs: &[QuotientExpr]) -> Self {
        let mut counts = HashMap::new();
        let mut costs = HashMap::new();
        let mut keyed_exprs = HashMap::new();
        for expr in exprs {
            collect_quotient_expr_stats(expr, &mut counts, &mut costs, &mut keyed_exprs);
        }

        let mut keyed_counts = counts
            .iter()
            .filter_map(|(key, &count)| {
                let cost = costs.get(key).copied().unwrap_or_default();
                if quotient_inline_cse_candidate(count, cost) {
                    Some((key.clone(), count, cost))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        keyed_counts.sort_by(|(lhs, lhs_count, lhs_cost), (rhs, rhs_count, rhs_cost)| {
            quotient_cse_sort_key(lhs, *lhs_count, *lhs_cost)
                .cmp(&quotient_cse_sort_key(rhs, *rhs_count, *rhs_cost))
        });

        let mut slots = HashMap::new();
        let mut exprs = HashMap::new();
        for (key, _, _) in keyed_counts {
            let slot = slots.len();
            assert!(
                slot <= u16::MAX as usize,
                "too many quotient inline CSE temps"
            );
            let expr = keyed_exprs
                .get(&key)
                .cloned()
                .expect("CSE expression present");
            slots.insert(key.clone(), slot as u16);
            exprs.insert(key, expr);
        }

        Self { slots, exprs }
    }
}

/// Emits direct Yul for `QuotientExpr` with optional CSE helpers.
///
/// This is used by non-VM modes and by small inline prefixes. The emitted code
/// must obey the same Fr semantics and y-fold snippets as the VM path, so the
/// representation choice does not change the linearization scalar.
pub(super) struct QuotientInlineCseEmitter<'a> {
    /// Chosen CSE plan.
    pub(super) plan: &'a QuotientInlineCsePlan,
    /// Base memory pointer for inline CSE temps.
    pub(super) cse_mptr: usize,
    /// Whether to call local helper functions such as `q_add` and `q_mul`.
    pub(super) helpers: bool,
    /// CSE keys already materialized.
    pub(super) emitted: HashSet<String>,
    /// CSE keys currently being materialized, used to catch accidental cycles.
    pub(super) emitting: HashSet<String>,
    /// Monotonic suffix for generated temporary variable names.
    pub(super) next_var: usize,
}

impl<'a> QuotientInlineCseEmitter<'a> {
    /// Create a direct-Yul CSE emitter.
    pub(super) fn new(plan: &'a QuotientInlineCsePlan, cse_mptr: usize, helpers: bool) -> Self {
        Self {
            plan,
            cse_mptr,
            helpers,
            emitted: HashSet::new(),
            emitting: HashSet::new(),
            next_var: 0,
        }
    }

    /// Emit an identity expression and return the Yul variable holding it.
    pub(super) fn emit_identity(&mut self, expr: &QuotientExpr, out: &mut Vec<String>) -> String {
        self.emit_expr(expr, out, None)
    }

    /// Emit a quotient expression, recursively materializing CSE temps as needed.
    pub(super) fn emit_expr(
        &mut self,
        expr: &QuotientExpr,
        out: &mut Vec<String>,
        current_cse_key: Option<&str>,
    ) -> String {
        let key = quotient_expr_key(expr);
        if Some(key.as_str()) != current_cse_key && self.plan.slots.contains_key(&key) {
            self.ensure_cse(&key, out);
            return self.cse_load(&key);
        }

        match expr {
            QuotientExpr::Const(value) => u256_string(*value),
            QuotientExpr::Mem(mem) => quotient_mem_load_expr(*mem),
            QuotientExpr::Add(lhs, rhs) => {
                if self.helpers {
                    if let QuotientExpr::Mul(mul_lhs, mul_rhs) = lhs.as_ref() {
                        let a = self.emit_expr(mul_lhs, out, current_cse_key);
                        let b = self.emit_expr(mul_rhs, out, current_cse_key);
                        let c = self.emit_expr(rhs, out, current_cse_key);
                        let var = self.fresh_var();
                        out.push(format!("let {var} := q_madd({a}, {b}, {c})"));
                        return var;
                    }
                    if let QuotientExpr::Mul(mul_lhs, mul_rhs) = rhs.as_ref() {
                        let a = self.emit_expr(lhs, out, current_cse_key);
                        let b = self.emit_expr(mul_lhs, out, current_cse_key);
                        let c = self.emit_expr(mul_rhs, out, current_cse_key);
                        let var = self.fresh_var();
                        out.push(format!("let {var} := q_addmul({a}, {b}, {c})"));
                        return var;
                    }
                }
                let lhs = self.emit_expr(lhs, out, current_cse_key);
                let rhs = self.emit_expr(rhs, out, current_cse_key);
                let var = self.fresh_var();
                if self.helpers {
                    out.push(format!("let {var} := q_add({lhs}, {rhs})"));
                } else {
                    out.push(format!("let {var} := addmod({lhs}, {rhs}, r)"));
                }
                var
            }
            QuotientExpr::Mul(lhs, rhs) => {
                let lhs = self.emit_expr(lhs, out, current_cse_key);
                let rhs = self.emit_expr(rhs, out, current_cse_key);
                let var = self.fresh_var();
                if self.helpers {
                    out.push(format!("let {var} := q_mul({lhs}, {rhs})"));
                } else {
                    out.push(format!("let {var} := mulmod({lhs}, {rhs}, r)"));
                }
                var
            }
            QuotientExpr::Neg(inner) => {
                let inner = self.emit_expr(inner, out, current_cse_key);
                let var = self.fresh_var();
                if self.helpers {
                    out.push(format!("let {var} := q_neg({inner})"));
                } else {
                    out.push(format!("let {var} := addmod(0, sub(r, {inner}), r)"));
                }
                var
            }
        }
    }

    /// Ensure a selected CSE expression has been stored to its temp slot.
    fn ensure_cse(&mut self, key: &str, out: &mut Vec<String>) {
        if self.emitted.contains(key) {
            return;
        }
        assert!(
            self.emitting.insert(key.to_string()),
            "cyclic quotient CSE expression"
        );
        let expr = self
            .plan
            .exprs
            .get(key)
            .cloned()
            .expect("CSE expression present");

        out.push("{".to_string());
        let value = self.emit_expr(&expr, out, Some(key));
        out.push(format!("mstore({}, {value})", self.cse_ptr(key)));
        out.push("}".to_string());

        self.emitting.remove(key);
        self.emitted.insert(key.to_string());
    }

    /// Render an `mload` from a CSE temp slot.
    fn cse_load(&self, key: &str) -> String {
        format!("mload({})", self.cse_ptr(key))
    }

    /// Render the pointer for a CSE temp slot.
    fn cse_ptr(&self, key: &str) -> String {
        let slot = self.plan.slots[key] as usize;
        format!("{:#x}", self.cse_mptr + slot * layout::WORD_BYTES)
    }

    /// Allocate the next direct-Yul temporary name.
    fn fresh_var(&mut self) -> String {
        let var = format!("q_cse_var_{}", self.next_var);
        self.next_var += 1;
        var
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum QuotientLeaf {
    /// Constant leaf.
    Const(U256),
    /// Memory leaf.
    Mem(QuotientMem),
}

/// Fused `top += product` forms recognized during expression emission.
///
/// These are the most common small arithmetic kernels after sum/product
/// flattening. Encoding them as accumulator operations avoids push/load/mul/add
/// sequences and is still easy to reason about because the VM stack effect is
/// exactly zero.
#[derive(Clone, Copy, Debug)]
pub(super) enum QuotientProductAdd {
    /// `top += mload(lhs) * mload(rhs) * const`.
    MemMemConstU8 { lhs: u16, rhs: u16, scalar: U256 },
    /// `top += const * mload(ptr)`.
    ConstU8Mem { scalar: U256, ptr: u16 },
    /// `top += mload(lhs) * mload(rhs)`.
    MemMem { lhs: u16, rhs: u16 },
}

/// Lowers quotient identities into VM bytecode and a constant table.
///
/// The builder owns stack-depth accounting and all byte-level encoding. It
/// emits an expression as an isolated stack computation followed by exactly one
/// fold opcode, so identity boundaries are explicit and native callback markers
/// can be interleaved safely.
#[derive(Default)]
pub(super) struct QuotientProgramBuilder {
    // Raw byte-oriented program before optional run compaction or packed32
    // repacking. All stack-depth accounting happens against this stream.
    pub(super) bytes: Vec<u8>,
    pub(super) consts: Vec<U256>,
    pub(super) const_slots: HashMap<U256, u16>,
    pub(super) vars: HashMap<String, QuotientExpr>,
    pub(super) stack_depth: usize,
    pub(super) max_stack: usize,
    pub(super) limb_vm_ops: bool,
    pub(super) profile: QuotientShapeProfile,
}

impl QuotientProgramBuilder {
    /// Create a builder, optionally enabling limb-specialized opcode emission.
    pub(super) fn with_limb_vm_ops(enabled: bool) -> Self {
        Self {
            limb_vm_ops: enabled,
            ..Default::default()
        }
    }

    /// Emit one complete quotient identity and its fold target.
    ///
    /// The operand stack is reset at the start and must be empty at the end.
    /// That invariant is the reason callbacks can share the same stream: the
    /// Yul interpreter is allowed to clear `q_top` and reuse `q_sp` whenever a
    /// native marker appears between identities.
    pub(super) fn identity_expr(
        &mut self,
        expr: &QuotientExpr,
        target: QuotientTarget,
        selector_gap: Option<usize>,
        cse: Option<&mut QuotientCseState>,
    ) {
        // Each identity is emitted as an isolated stack expression followed by
        // one fold opcode. Native callbacks assert the same empty-stack
        // boundary, which lets the Yul interpreter reset q_sp before them.
        self.vars.clear();
        self.stack_depth = 0;

        if let Some(cse) = cse {
            self.emit_expr_cse(expr, cse);
        } else {
            self.emit_expr(expr);
        }
        self.fold_identity(target, selector_gap);

        assert_eq!(self.stack_depth, 0, "quotient VM stack leak");
    }

    /// Emit the fold opcode for the completed top-of-stack identity value.
    fn fold_identity(&mut self, target: QuotientTarget, selector_gap: Option<usize>) {
        // Mirrors the Rust `compute_linearization_commitment` y-batch:
        // every emitted identity is first absorbed into the same running
        // power of y, then either accumulated into the fully-evaluated
        // numerator or into the simple-selector bucket.
        match target {
            QuotientTarget::Main => self.op0(Q_OP_FOLD_MAIN),
            QuotientTarget::Selector(idx) => {
                let gap = selector_gap.expect("selector fold gap for selector identity");
                assert!(
                    idx <= u8::MAX as usize,
                    "selector fold selector index exceeds 8 bits"
                );
                assert!(
                    gap <= u16::MAX as usize,
                    "selector fold gap exceeds 16 bits"
                );
                self.bytes.push(Q_OP_FOLD_SELECTOR);
                self.u24((idx << 16) | gap);
                self.pop_stack();
            }
        }
        if matches!(target, QuotientTarget::Main) {
            self.pop_stack();
        }
    }

    /// Emit the native permutation marker.
    ///
    /// The generated Yul callback evaluates the whole permutation block and
    /// performs the same fold side effects that interpreted identities would
    /// have performed one by one at this position.
    pub(super) fn native_permutation(&mut self) {
        assert_eq!(
            self.stack_depth, 0,
            "native permutation expects empty VM stack"
        );
        // The callback is not an arithmetic stack op: it is a placeholder in
        // the y-batched identity stream. The generated Yul block performs its
        // own scratch writes and fold calls at this exact program position.
        self.bytes.push(Q_OP_NATIVE_PERMUTATION);
    }

    /// Emit the native lookup marker.
    ///
    /// The generated Yul callback evaluates every LogUp lookup identity
    /// (boundary, helper chunks, accumulator) and folds each one in the same
    /// order as the interpreted identity stream.
    pub(super) fn native_lookup(&mut self) {
        assert_eq!(self.stack_depth, 0, "native lookup expects empty VM stack");
        // Like native permutation, this is a domain-shaped superinstruction:
        // the opcode marks one family in the y-batched stream while the
        // generated callback performs all per-identity arithmetic and folds.
        self.bytes.push(Q_OP_NATIVE_LOOKUP);
    }

    /// Emit a native heavy-identity marker addressed by `native_idx`.
    ///
    /// The marker is an execution-plan choice, not a different identity. Its
    /// callback body is generated from the same `QuotientIdentity` and must
    /// trace and fold exactly once.
    pub(super) fn native_identity(&mut self, native_idx: usize) {
        assert_eq!(
            self.stack_depth, 0,
            "native identity expects empty VM stack"
        );
        // Native identity callbacks are a bytecode/gas trade: recognized
        // heavy gates stay as generated Yul kernels while the remaining gates
        // fall back to the compact VM program stored in the VK payload.
        self.bytes.push(Q_OP_NATIVE_IDENTITY);
        self.u16(native_idx);
    }

    /// Finalize bytecode into the requested physical encoding.
    ///
    /// The logical operation stream is emitted in byte-oriented form first so
    /// stack accounting and CSE temp discovery have one canonical input.
    /// `Bytes` may compact adjacent fused add-mul runs; `Packed32` repacks the
    /// un-compacted stream into fixed 4-byte instruction words.
    pub(super) fn finish(self, encoding: QuotientProgramEncoding) -> QuotientProgramBuild {
        // `max_stack` is the pure VM operand-stack high-water mark. The memory
        // planner adds callback scratch requirements when callbacks share the
        // same base pointer.
        let cse_temps = self.cse_temps();
        if encoding == QuotientProgramEncoding::Packed32
            && quotient_program_uses_limb_ops(&self.bytes)
        {
            panic!(
                "{QUOTIENT_LIMB_VM_OPS_ENV}=1 is only supported with {QUOTIENT_ENCODING_ENV}=bytes"
            );
        }
        let bytes = match encoding {
            QuotientProgramEncoding::Bytes => compact_quotient_runs(&self.bytes),
            QuotientProgramEncoding::Packed32 => pack_quotient_u32_program(&self.bytes),
        };
        let validated_max_stack = validate_quotient_program(&bytes, encoding)
            .unwrap_or_else(|err| panic!("invalid finalized quotient VM program: {err}"));
        assert_eq!(
            validated_max_stack, self.max_stack,
            "quotient VM physical program stack depth diverged from builder accounting"
        );
        let (used_ops, used_mem_tokens) = quotient_program_usage(&bytes, encoding);
        let profile = self.profile;
        if quotient_shape_profile_enabled() {
            eprintln!(
                "quotient shape profile: modarith7={} lin7={} bilin7_row={} bilin7_pairwise={} pow5={} fallback_vm_ops={} raw_program_bytes={} compact_program_bytes={} consts={}",
                profile.modarith7,
                profile.lin7,
                profile.bilin7_row,
                profile.bilin7_pairwise,
                profile.pow5,
                profile.fallback_vm_ops,
                self.bytes.len(),
                bytes.len(),
                self.consts.len(),
            );
        }
        QuotientProgramBuild {
            bytes,
            consts: self.consts,
            max_stack: self.max_stack,
            packed32: encoding == QuotientProgramEncoding::Packed32,
            cse_temps,
            used_ops,
            used_mem_tokens,
        }
    }

    /// Parse and remember one generated Yul assignment.
    ///
    /// This is the bridge for identities that do not yet have typed
    /// `Expression<Fq>` lowering. Only the evaluator's simple arithmetic subset
    /// is accepted; unsupported syntax is rejected during code generation.
    pub(super) fn assignment(&mut self, line: &str) {
        let assignment = yul_assignment(line)
            .unwrap_or_else(|| panic!("unsupported quotient assignment: {}", line.trim()));
        let expr = self.parse_expr(&assignment.expr);
        self.vars.insert(assignment.dst, expr);
    }

    /// Parse a generated Yul expression into `QuotientExpr`.
    ///
    /// Supported operations are exactly the Fr operations emitted by
    /// `Evaluator`: `addmod(_, _, r)`, `mulmod(_, _, r)`, `sub(r, _)`,
    /// `mload(_)`, literals, and previously assigned variables.
    pub(super) fn parse_expr(&self, expr: &str) -> QuotientExpr {
        let expr = expr.trim();
        if let Some(args) = call_args(expr, "addmod") {
            assert_eq!(args.len(), 3, "addmod arity");
            assert_eq!(args[2].trim(), "r", "addmod modulus");
            QuotientExpr::Add(
                Box::new(self.parse_expr(&args[0])),
                Box::new(self.parse_expr(&args[1])),
            )
        } else if let Some(args) = call_args(expr, "mulmod") {
            assert_eq!(args.len(), 3, "mulmod arity");
            assert_eq!(args[2].trim(), "r", "mulmod modulus");
            QuotientExpr::Mul(
                Box::new(self.parse_expr(&args[0])),
                Box::new(self.parse_expr(&args[1])),
            )
        } else if let Some(args) = call_args(expr, "sub") {
            assert_eq!(args.len(), 2, "sub arity");
            assert_eq!(args[0].trim(), "r", "only sub(r, x) is supported");
            QuotientExpr::Neg(Box::new(self.parse_expr(&args[1])))
        } else if let Some(args) = call_args(expr, "mload") {
            assert_eq!(args.len(), 1, "mload arity");
            QuotientExpr::Mem(parse_mem(&args[0]))
        } else if is_literal(expr) {
            QuotientExpr::Const(parse_u256(expr))
        } else {
            self.vars
                .get(expr)
                .cloned()
                .unwrap_or_else(|| panic!("unknown quotient variable: {expr}"))
        }
    }

    /// Emit a `QuotientExpr` using ordinary VM bytecode plus local peepholes.
    ///
    /// The method leaves the expression value on top of the VM stack. It first
    /// tries structural limb compression, then falls back to accumulator-leaf
    /// and fused product-add opcodes before using generic stack add/mul/neg.
    pub(super) fn emit_expr(&mut self, expr: &QuotientExpr) {
        if self.try_emit_pow5(expr) {
            return;
        }
        if self.try_emit_modarith7_shape(expr) {
            return;
        }
        if self.try_emit_limb_shape(expr) {
            return;
        }
        if self.try_emit_limb_decomposition(expr) {
            return;
        }

        match expr {
            QuotientExpr::Const(value) => {
                self.emit_const(*value);
                self.push_stack();
            }
            QuotientExpr::Mem(QuotientMem::Literal(ptr)) => {
                self.emit_mem_literal(*ptr);
                self.push_stack();
            }
            QuotientExpr::Mem(QuotientMem::Token(token)) => {
                self.bytes.push(Q_OP_PUSH_MEM_TOKEN);
                self.bytes.push(*token);
                self.push_stack();
            }
            QuotientExpr::Mem(QuotientMem::TokenOffset(token, offset)) => {
                self.bytes.push(Q_OP_PUSH_MEM_TOKEN_OFFSET);
                self.bytes.push(*token);
                self.u32(*offset);
                self.push_stack();
            }
            QuotientExpr::Add(lhs, rhs) => {
                if !self.try_emit_add_product(lhs, rhs) && !self.try_emit_add_product(rhs, lhs) {
                    self.emit_binary_expr(
                        lhs,
                        rhs,
                        Q_OP_ADD,
                        Q_OP_ADD_CONST_U8,
                        Q_OP_ADD_CONST,
                        Q_OP_ADD_MEM_U16,
                    );
                }
            }
            QuotientExpr::Mul(lhs, rhs) => {
                self.emit_binary_expr(
                    lhs,
                    rhs,
                    Q_OP_MUL,
                    Q_OP_MUL_CONST_U8,
                    Q_OP_MUL_CONST,
                    Q_OP_MUL_MEM_U16,
                );
            }
            QuotientExpr::Neg(expr) => {
                self.emit_expr(expr);
                self.op0(Q_OP_NEG);
            }
        }
    }

    /// Emit an expression with cross-identity VM CSE enabled.
    ///
    /// The first use of a selected expression materializes it and stores the
    /// top-of-stack into a temp slot. Later uses load the temp directly. The
    /// stored value remains on the stack after `STORE_TEMP`, matching the
    /// expression result expected by the caller.
    fn emit_expr_cse(&mut self, expr: &QuotientExpr, cse: &mut QuotientCseState) {
        let key = quotient_expr_key(expr);
        if let Some(slot) = cse.slots.get(&key).copied() {
            if cse.emitted.contains_key(&key) {
                self.bytes.push(Q_OP_PUSH_TEMP);
                self.u16(slot as usize);
                self.push_stack();
                return;
            }

            cse.emitted.insert(key, slot);
            self.emit_expr_cse_inner(expr, cse);
            self.bytes.push(Q_OP_STORE_TEMP);
            self.u16(slot as usize);
            return;
        }

        self.emit_expr_cse_inner(expr, cse);
    }

    /// Recursive CSE emitter once the current expression has been ruled out as
    /// an already-materialized temp.
    fn emit_expr_cse_inner(&mut self, expr: &QuotientExpr, cse: &mut QuotientCseState) {
        if self.try_emit_pow5_cse(expr, cse) {
            return;
        }
        if self.try_emit_modarith7_shape(expr) {
            return;
        }
        if self.try_emit_limb_shape(expr) {
            return;
        }
        if self.try_emit_limb_decomposition_cse(expr, cse) {
            return;
        }

        match expr {
            QuotientExpr::Const(value) => {
                self.emit_const(*value);
                self.push_stack();
            }
            QuotientExpr::Mem(QuotientMem::Literal(ptr)) => {
                self.emit_mem_literal(*ptr);
                self.push_stack();
            }
            QuotientExpr::Mem(QuotientMem::Token(token)) => {
                self.bytes.push(Q_OP_PUSH_MEM_TOKEN);
                self.bytes.push(*token);
                self.push_stack();
            }
            QuotientExpr::Mem(QuotientMem::TokenOffset(token, offset)) => {
                self.bytes.push(Q_OP_PUSH_MEM_TOKEN_OFFSET);
                self.bytes.push(*token);
                self.u32(*offset);
                self.push_stack();
            }
            QuotientExpr::Add(lhs, rhs) => {
                if !self.try_emit_add_product_cse(lhs, rhs, cse)
                    && !self.try_emit_add_product_cse(rhs, lhs, cse)
                {
                    self.emit_binary_expr_cse(
                        lhs,
                        rhs,
                        Q_OP_ADD,
                        Q_OP_ADD_CONST_U8,
                        Q_OP_ADD_CONST,
                        Q_OP_ADD_MEM_U16,
                        cse,
                    );
                }
            }
            QuotientExpr::Mul(lhs, rhs) => {
                self.emit_binary_expr_cse(
                    lhs,
                    rhs,
                    Q_OP_MUL,
                    Q_OP_MUL_CONST_U8,
                    Q_OP_MUL_CONST,
                    Q_OP_MUL_MEM_U16,
                    cse,
                );
            }
            QuotientExpr::Neg(expr) => {
                self.emit_expr_cse(expr, cse);
                self.op0(Q_OP_NEG);
            }
        }
    }

    /// Try to replace a repeated-factor fifth power with one opcode.
    fn try_emit_pow5(&mut self, expr: &QuotientExpr) -> bool {
        let Some(base) = quotient_pow5_base(expr) else {
            return false;
        };
        self.emit_expr(base);
        self.bytes.push(Q_OP_POW5);
        self.profile.pow5 += 1;
        true
    }

    /// CSE-aware variant of `try_emit_pow5`.
    fn try_emit_pow5_cse(&mut self, expr: &QuotientExpr, cse: &mut QuotientCseState) -> bool {
        let Some(base) = quotient_pow5_base(expr) else {
            return false;
        };
        self.emit_expr_cse(base, cse);
        self.bytes.push(Q_OP_POW5);
        self.profile.pow5 += 1;
        true
    }

    /// Try to extract one limb-specialized subexpression from a larger sum.
    fn try_emit_limb_decomposition(&mut self, expr: &QuotientExpr) -> bool {
        if !self.limb_vm_ops {
            return false;
        }
        let Some((shape, residue)) = quotient_limb_subshape(expr) else {
            return false;
        };
        if !self.limb_shape_has_u8_const_slots(&shape) {
            return false;
        }
        self.emit_expr(&residue);
        self.emit_limb_shape(shape);
        self.op_binary(Q_OP_ADD);
        true
    }

    /// CSE-aware variant of `try_emit_limb_decomposition`.
    fn try_emit_limb_decomposition_cse(
        &mut self,
        expr: &QuotientExpr,
        cse: &mut QuotientCseState,
    ) -> bool {
        if !self.limb_vm_ops {
            return false;
        }
        let Some((shape, residue)) = quotient_limb_subshape(expr) else {
            return false;
        };
        if !self.limb_shape_has_u8_const_slots(&shape) {
            return false;
        }
        self.emit_expr_cse(&residue, cse);
        self.emit_limb_shape(shape);
        self.op_binary(Q_OP_ADD);
        true
    }

    /// Try to replace a full expression with one limb-specialized opcode.
    ///
    /// The const-slot preflight is part of the ABI justification: limb opcodes
    /// carry coefficient slots as single bytes, so either every coefficient can
    /// be addressed by `u8` after deterministic insertion or the expression
    /// must use the generic VM path.
    fn try_emit_limb_shape(&mut self, expr: &QuotientExpr) -> bool {
        if !self.limb_vm_ops {
            return false;
        }

        let Some(shape) = quotient_limb_shape(expr) else {
            return false;
        };
        if !self.limb_shape_has_u8_const_slots(&shape) {
            return false;
        }

        self.emit_limb_shape(shape);
        true
    }

    /// Try to replace a whole affine foreign-field/ECC identity with one
    /// dynamic byte-only opcode.
    fn try_emit_modarith7_shape(&mut self, expr: &QuotientExpr) -> bool {
        if !self.limb_vm_ops {
            return false;
        }

        let Some(shape) = quotient_modarith7_shape(expr) else {
            return false;
        };
        if !self.modarith7_shape_has_u8_const_slots(&shape) {
            return false;
        }

        self.emit_modarith7_shape(shape);
        true
    }

    /// Check whether all coefficients of a fused affine limb identity fit
    /// one-byte constant-table slots without mutating the builder.
    fn modarith7_shape_has_u8_const_slots(&self, shape: &QuotientModarith7Shape) -> bool {
        self.peek_u8_const_slots(&modarith7_coeffs(shape)).is_some()
    }

    /// Check whether all coefficients of a recognized limb shape fit `u8`
    /// constant slots without mutating the builder.
    fn limb_shape_has_u8_const_slots(&self, shape: &QuotientLimbShape) -> bool {
        let coeffs = match shape {
            QuotientLimbShape::Lin7 { terms } => terms.iter().map(|(coeff, _)| *coeff).collect(),
            QuotientLimbShape::Bilin7Row { terms, .. } => {
                terms.iter().map(|(coeff, _)| *coeff).collect()
            }
            QuotientLimbShape::Bilin7Pairwise { coeffs, .. } => coeffs.clone(),
        };
        self.peek_u8_const_slots(&coeffs).is_some()
    }

    /// Emit the byte-level representation of a pre-validated limb shape.
    fn emit_limb_shape(&mut self, shape: QuotientLimbShape) {
        match shape {
            QuotientLimbShape::Lin7 { terms } => {
                // LIN7 is the VM encoding of:
                //   sum_exprs(base_powers, limbs)
                // from foreign-field normalization/multiplication and EC
                // gates. It packs seven limb-evaluation loads and their
                // generated Fr coefficients into one interpreter opcode.
                self.bytes.push(Q_OP_LIN7);
                for (coeff, ptr) in terms {
                    let slot = self.const_slot(coeff);
                    let slot = u8::try_from(slot).expect("lin7 const slot checked");
                    self.bytes.push(slot);
                    self.u16(ptr as usize);
                }
                self.profile.lin7 += 1;
            }
            QuotientLimbShape::Bilin7Row { lhs, terms } => {
                // BILIN7_ROW captures the repeated row shape
                // lhs * sum_i coeff[i] * rhs[i]. It appears after lowering
                // pair_wise_prod slices in foreign-field multiplication and
                // EC slope/tangent/on-curve/lambda-squared identities.
                self.bytes.push(Q_OP_BILIN7_ROW);
                self.u16(lhs as usize);
                for (coeff, rhs) in terms {
                    let slot = self.const_slot(coeff);
                    let slot = u8::try_from(slot).expect("bilin7 row const slot checked");
                    self.bytes.push(slot);
                    self.u16(rhs as usize);
                }
                self.profile.bilin7_row += 1;
            }
            QuotientLimbShape::Bilin7Pairwise {
                lhs_base,
                rhs_base,
                coeffs,
            } => {
                // BILIN7_PAIRWISE captures the full 7-by-7 convolution:
                //   sum_{i,j} coeff[i+j] * lhs[i] * rhs[j]
                // matching sum_exprs(double_base_powers,
                // pair_wise_prod(lhs, rhs)).
                self.bytes.push(Q_OP_BILIN7_PAIRWISE);
                self.u16(lhs_base as usize);
                self.u16(rhs_base as usize);
                for coeff in coeffs {
                    let slot = self.const_slot(coeff);
                    let slot = u8::try_from(slot).expect("bilin7 pairwise const slot checked");
                    self.bytes.push(slot);
                }
                self.profile.bilin7_pairwise += 1;
            }
        }
        self.push_stack();
    }

    /// Emit the dynamic byte-level representation of one fused affine
    /// foreign-field/ECC identity.
    fn emit_modarith7_shape(&mut self, shape: QuotientModarith7Shape) {
        self.bytes.push(Q_OP_MODARITH7);

        let mut flags = 0u8;
        if shape.cond.is_some() {
            flags |= Q_MODARITH7_FLAG_COND;
        }
        if shape.constant != U256::ZERO {
            flags |= Q_MODARITH7_FLAG_CONST;
        }
        self.bytes.push(flags);

        if let Some(cond) = shape.cond {
            self.u16(cond as usize);
        }
        if shape.constant != U256::ZERO {
            let slot = self.const_slot(shape.constant);
            let slot = u8::try_from(slot).expect("modarith7 const slot checked");
            self.bytes.push(slot);
        }

        let lin_count = u8::try_from(shape.lin.len()).expect("modarith7 lin count checked");
        let row_count = u8::try_from(shape.rows.len()).expect("modarith7 row count checked");
        let pairwise_count =
            u8::try_from(shape.pairwise.len()).expect("modarith7 pairwise count checked");
        let mem_count = u8::try_from(shape.mem_terms.len()).expect("modarith7 mem count checked");
        let product_count =
            u8::try_from(shape.product_terms.len()).expect("modarith7 product count checked");
        self.bytes.push(lin_count);
        self.bytes.push(row_count);
        self.bytes.push(pairwise_count);
        self.bytes.push(mem_count);
        self.bytes.push(product_count);

        for terms in shape.lin {
            for (coeff, ptr) in terms {
                let slot = self.const_slot(coeff);
                let slot = u8::try_from(slot).expect("modarith7 lin const slot checked");
                self.bytes.push(slot);
                self.u16(ptr as usize);
            }
        }
        for (lhs, terms) in shape.rows {
            self.u16(lhs as usize);
            for (coeff, rhs) in terms {
                let slot = self.const_slot(coeff);
                let slot = u8::try_from(slot).expect("modarith7 row const slot checked");
                self.bytes.push(slot);
                self.u16(rhs as usize);
            }
        }
        for (lhs_base, rhs_base, coeffs) in shape.pairwise {
            self.u16(lhs_base as usize);
            self.u16(rhs_base as usize);
            for coeff in coeffs {
                let slot = self.const_slot(coeff);
                let slot = u8::try_from(slot).expect("modarith7 pairwise const slot checked");
                self.bytes.push(slot);
            }
        }
        for (coeff, ptr) in shape.mem_terms {
            let slot = self.const_slot(coeff);
            let slot = u8::try_from(slot).expect("modarith7 mem const slot checked");
            self.bytes.push(slot);
            self.u16(ptr as usize);
        }
        for (coeff, lhs, rhs) in shape.product_terms {
            let slot = self.const_slot(coeff);
            let slot = u8::try_from(slot).expect("modarith7 product const slot checked");
            self.bytes.push(slot);
            self.u16(lhs as usize);
            self.u16(rhs as usize);
        }

        self.profile.modarith7 += 1;
        self.push_stack();
    }

    /// Emit a constant load, choosing the shortest constant-slot operand.
    fn emit_const(&mut self, value: U256) {
        self.record_fallback_vm_op();
        let slot = self.const_slot(value);
        if let Ok(slot) = u8::try_from(slot) {
            self.bytes.push(Q_OP_PUSH_CONST_U8);
            self.bytes.push(slot);
        } else {
            self.bytes.push(Q_OP_PUSH_CONST);
            self.u16(slot as usize);
        }
    }

    /// Emit a memory load, choosing the shortest literal-pointer operand.
    fn emit_mem_literal(&mut self, ptr: u32) {
        self.record_fallback_vm_op();
        if let Ok(ptr) = u16::try_from(ptr) {
            self.bytes.push(Q_OP_PUSH_MEM_U16);
            self.u16(ptr as usize);
        } else {
            self.bytes.push(Q_OP_PUSH_MEM_LITERAL);
            self.u32(ptr);
        }
    }

    /// Try to emit `base + product` as a fused accumulator opcode.
    fn try_emit_add_product(&mut self, base: &QuotientExpr, product: &QuotientExpr) -> bool {
        let mut leaves = Vec::new();
        if !collect_product_leaves(product, &mut leaves) {
            return false;
        }
        let Some(product) = self.product_add_macro(&leaves) else {
            return false;
        };

        self.emit_expr(base);
        self.emit_product_add(product);
        true
    }

    /// CSE-aware variant of `try_emit_add_product`.
    fn try_emit_add_product_cse(
        &mut self,
        base: &QuotientExpr,
        product: &QuotientExpr,
        cse: &mut QuotientCseState,
    ) -> bool {
        let mut leaves = Vec::new();
        if !collect_product_leaves(product, &mut leaves) {
            return false;
        }
        let Some(product) = self.product_add_macro(&leaves) else {
            return false;
        };

        self.emit_expr_cse(base, cse);
        self.emit_product_add(product);
        true
    }

    /// Recognize product leaves that can be encoded as one fused add-mul op.
    ///
    /// The fused forms require literal `u16` memory pointers and, where a
    /// constant is present, a coefficient that can fit a `u8` const slot. Token
    /// memory is kept on the generic path because the fused byte layout stores
    /// raw pointers only.
    fn product_add_macro(&self, leaves: &[QuotientLeaf]) -> Option<QuotientProductAdd> {
        let mut mems = Vec::new();
        let mut consts = Vec::new();
        for leaf in leaves {
            match *leaf {
                QuotientLeaf::Mem(QuotientMem::Literal(ptr)) => {
                    mems.push(u16::try_from(ptr).ok()?);
                }
                QuotientLeaf::Const(value) => {
                    if !self.const_fits_u8_slot(value) {
                        return None;
                    }
                    consts.push(value);
                }
                QuotientLeaf::Mem(QuotientMem::Token(_))
                | QuotientLeaf::Mem(QuotientMem::TokenOffset(_, _)) => return None,
            }
        }

        match (mems.as_slice(), consts.as_slice()) {
            ([lhs, rhs], [scalar]) => Some(QuotientProductAdd::MemMemConstU8 {
                lhs: *lhs,
                rhs: *rhs,
                scalar: *scalar,
            }),
            ([ptr], [scalar]) => Some(QuotientProductAdd::ConstU8Mem {
                scalar: *scalar,
                ptr: *ptr,
            }),
            ([lhs, rhs], []) => Some(QuotientProductAdd::MemMem {
                lhs: *lhs,
                rhs: *rhs,
            }),
            _ => None,
        }
    }

    /// Emit one fused add-mul accumulator operation.
    fn emit_product_add(&mut self, product: QuotientProductAdd) {
        self.record_fallback_vm_op();
        match product {
            QuotientProductAdd::MemMemConstU8 { lhs, rhs, scalar } => {
                let slot = self.const_slot(scalar);
                let slot = u8::try_from(slot).expect("const slot checked");
                self.bytes.push(Q_OP_ADD_MUL_MEM_MEM_CONST_U8);
                self.u16(lhs as usize);
                self.u16(rhs as usize);
                self.bytes.push(slot);
            }
            QuotientProductAdd::ConstU8Mem { scalar, ptr } => {
                let slot = self.const_slot(scalar);
                let slot = u8::try_from(slot).expect("const slot checked");
                self.bytes.push(Q_OP_ADD_MUL_CONST_U8_MEM_U16);
                self.u16(ptr as usize);
                self.bytes.push(slot);
            }
            QuotientProductAdd::MemMem { lhs, rhs } => {
                self.bytes.push(Q_OP_ADD_MUL_MEM_MEM);
                self.u16(lhs as usize);
                self.u16(rhs as usize);
            }
        }
    }

    /// Emit a binary expression with accumulator-leaf peepholes.
    ///
    /// If one side is a constant or short memory load, the VM can update the
    /// other side's top-of-stack directly with `ADD_CONST`, `MUL_MEM_U16`, and
    /// related opcodes. Otherwise both operands are pushed and a generic stack
    /// operation combines them.
    fn emit_binary_expr(
        &mut self,
        lhs: &QuotientExpr,
        rhs: &QuotientExpr,
        stack_op: u8,
        const_u8_op: u8,
        const_op: u8,
        mem_u16_op: u8,
    ) {
        if let Some(leaf) = quotient_leaf(rhs) {
            self.emit_expr(lhs);
            if self.emit_acc_leaf(leaf, const_u8_op, const_op, mem_u16_op) {
                return;
            }
            self.emit_expr(rhs);
            self.op_binary(stack_op);
            return;
        }
        if let Some(leaf) = quotient_leaf(lhs) {
            self.emit_expr(rhs);
            if self.emit_acc_leaf(leaf, const_u8_op, const_op, mem_u16_op) {
                return;
            }
            self.emit_expr(lhs);
            self.op_binary(stack_op);
            return;
        }

        self.emit_expr(lhs);
        self.emit_expr(rhs);
        self.op_binary(stack_op);
    }

    #[allow(clippy::too_many_arguments)]
    /// CSE-aware variant of `emit_binary_expr`.
    fn emit_binary_expr_cse(
        &mut self,
        lhs: &QuotientExpr,
        rhs: &QuotientExpr,
        stack_op: u8,
        const_u8_op: u8,
        const_op: u8,
        mem_u16_op: u8,
        cse: &mut QuotientCseState,
    ) {
        if let Some(leaf) = quotient_leaf(rhs) {
            self.emit_expr_cse(lhs, cse);
            if self.emit_acc_leaf(leaf, const_u8_op, const_op, mem_u16_op) {
                return;
            }
            self.emit_expr_cse(rhs, cse);
            self.op_binary(stack_op);
            return;
        }
        if let Some(leaf) = quotient_leaf(lhs) {
            self.emit_expr_cse(rhs, cse);
            if self.emit_acc_leaf(leaf, const_u8_op, const_op, mem_u16_op) {
                return;
            }
            self.emit_expr_cse(lhs, cse);
            self.op_binary(stack_op);
            return;
        }

        self.emit_expr_cse(lhs, cse);
        self.emit_expr_cse(rhs, cse);
        self.op_binary(stack_op);
    }

    /// Try to apply a constant or short-memory accumulator opcode to `q_top`.
    fn emit_acc_leaf(
        &mut self,
        leaf: QuotientLeaf,
        const_u8_op: u8,
        const_op: u8,
        mem_u16_op: u8,
    ) -> bool {
        match leaf {
            QuotientLeaf::Const(value) => {
                let slot = self.const_slot(value);
                if let Ok(slot) = u8::try_from(slot) {
                    self.bytes.push(const_u8_op);
                    self.bytes.push(slot);
                } else {
                    self.bytes.push(const_op);
                    self.u16(slot as usize);
                }
                true
            }
            QuotientLeaf::Mem(QuotientMem::Literal(ptr)) => {
                if let Ok(ptr) = u16::try_from(ptr) {
                    self.bytes.push(mem_u16_op);
                    self.u16(ptr as usize);
                    true
                } else {
                    false
                }
            }
            QuotientLeaf::Mem(QuotientMem::Token(_))
            | QuotientLeaf::Mem(QuotientMem::TokenOffset(_, _)) => false,
        }
    }

    /// Emit a zero-operand opcode and count it in the fallback profile.
    fn op0(&mut self, op: u8) {
        self.record_fallback_vm_op();
        self.bytes.push(op);
    }

    /// Emit a binary stack opcode and update stack-depth accounting.
    fn op_binary(&mut self, op: u8) {
        self.record_fallback_vm_op();
        self.bytes.push(op);
        self.pop_stack();
    }

    /// Count non-limb opcodes when shape profiling is enabled.
    fn record_fallback_vm_op(&mut self) {
        if self.limb_vm_ops {
            self.profile.fallback_vm_ops += 1;
        }
    }

    /// Record one pushed stack value and update the high-water mark.
    fn push_stack(&mut self) {
        self.stack_depth += 1;
        self.max_stack = self.max_stack.max(self.stack_depth);
    }

    /// Record one consumed stack value.
    fn pop_stack(&mut self) {
        self.stack_depth = self
            .stack_depth
            .checked_sub(1)
            .expect("quotient VM stack underflow");
    }

    /// Append a big-endian `u16` operand.
    fn u16(&mut self, value: usize) {
        assert!(value <= u16::MAX as usize, "quotient VM u16 overflow");
        self.bytes.extend_from_slice(&(value as u16).to_be_bytes());
    }

    /// Append a big-endian 24-bit operand.
    fn u24(&mut self, value: usize) {
        assert!(
            value <= QUOTIENT_VM_PACKED_ARG_MASK as usize,
            "quotient VM u24 overflow"
        );
        self.bytes
            .extend_from_slice(&(value as u32).to_be_bytes()[1..]);
    }

    /// Append a big-endian `u32` operand.
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Return the stable constant-table slot for `value`, inserting if needed.
    fn const_slot(&mut self, value: U256) -> u16 {
        if let Some(slot) = self.const_slots.get(&value) {
            *slot
        } else {
            let slot = self.consts.len();
            assert!(slot <= u16::MAX as usize, "too many quotient constants");
            self.consts.push(value);
            self.const_slots.insert(value, slot as u16);
            slot as u16
        }
    }

    /// Check whether `value` can be addressed by a one-byte constant slot.
    fn const_fits_u8_slot(&self, value: U256) -> bool {
        self.const_slots
            .get(&value)
            .is_some_and(|slot| u8::try_from(*slot).is_ok())
            || (!self.const_slots.contains_key(&value) && self.consts.len() <= u8::MAX as usize)
    }

    /// Predict one-byte constant slots for a batch of values without insertion.
    ///
    /// This lets limb opcode recognition fail cleanly before mutating the
    /// constant table, so fallback lowering sees the same builder state it
    /// would have seen if recognition had never been attempted.
    fn peek_u8_const_slots(&self, values: &[U256]) -> Option<Vec<u8>> {
        let mut next_slot = self.consts.len();
        let mut pending = HashMap::new();
        let mut slots = Vec::with_capacity(values.len());
        for value in values {
            let slot = if let Some(slot) = self.const_slots.get(value).copied() {
                slot as usize
            } else if let Some(slot) = pending.get(value).copied() {
                slot
            } else {
                let slot = next_slot;
                next_slot += 1;
                pending.insert(*value, slot);
                slot
            };
            slots.push(u8::try_from(slot).ok()?);
        }
        Some(slots)
    }

    /// Recover the number of VM temp slots actually referenced by bytecode.
    fn cse_temps(&self) -> usize {
        if !quotient_vm_cse_enabled() {
            return 0;
        }
        // Temp slots are encoded directly in the bytecode, so recover the high
        // watermark from STORE/PUSH_TEMP operands after all identities have
        // been emitted.
        let mut idx = 0usize;
        let mut temps = 0usize;
        while idx < self.bytes.len() {
            match self.bytes[idx] {
                Q_OP_PUSH_TEMP | Q_OP_STORE_TEMP => {
                    temps = temps.max(read_u16(&self.bytes, idx + 1) as usize + 1);
                    idx += quotient_op_len(&self.bytes, idx);
                }
                _ => idx += quotient_op_len(&self.bytes, idx),
            }
        }
        temps
    }
}

/// Compact long adjacent fused-op runs in byte-oriented VM encoding.
pub(super) fn compact_quotient_runs(bytes: &[u8]) -> Vec<u8> {
    // Run compaction is only a byte-encoding optimization. It preserves the
    // logical operation stream by replacing long adjacent fused add-mul ops
    // with one counted opcode followed by the same operands.
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        let op = bytes[idx];
        if matches!(
            op,
            Q_OP_ADD_MUL_MEM_MEM_CONST_U8 | Q_OP_ADD_MUL_CONST_U8_MEM_U16
        ) {
            let len = quotient_op_len(bytes, idx);
            let run_operands_len = len - 1;
            let run_op = match op {
                Q_OP_ADD_MUL_MEM_MEM_CONST_U8 => Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8,
                Q_OP_ADD_MUL_CONST_U8_MEM_U16 => Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16,
                _ => unreachable!(),
            };

            let run_start = idx;
            let mut run_len = 0usize;
            while idx < bytes.len() && bytes[idx] == op && run_len < u16::MAX as usize {
                idx += len;
                run_len += 1;
            }

            if run_len >= QUOTIENT_VM_SPEC.run_compaction_min_len {
                out.push(run_op);
                out.extend_from_slice(&(run_len as u16).to_be_bytes());
                for term in 0..run_len {
                    let term_start = run_start + term * len + 1;
                    out.extend_from_slice(&bytes[term_start..term_start + run_operands_len]);
                }
            } else {
                out.extend_from_slice(&bytes[run_start..idx]);
            }
        } else {
            let len = quotient_op_len(bytes, idx);
            out.extend_from_slice(&bytes[idx..idx + len]);
            idx += len;
        }
    }
    out
}

/// Repack byte-oriented quotient bytecode into packed32 encoding.
///
/// Packed32 is a physical encoding optimization only. It is allowed only for
/// fixed-size opcodes whose operands can be represented in a primary 24-bit
/// word plus, for two-pointer fused forms, one extra packed pair word.
pub(super) fn pack_quotient_u32_program(bytes: &[u8]) -> Vec<u8> {
    // Packed32 is a second physical encoding of the same logical VM. Base
    // instructions become one word `(opcode << 24) | operand`; opcodes with
    // two memory operands append one extra packed pair word.
    if quotient_program_uses_limb_ops(bytes) {
        panic!("{QUOTIENT_LIMB_VM_OPS_ENV}=1 is only supported with {QUOTIENT_ENCODING_ENV}=bytes");
    }

    let mut out = Vec::with_capacity(
        bytes
            .len()
            .next_multiple_of(QUOTIENT_VM_SPEC.packed_instruction_bytes),
    );
    let mut idx = 0usize;
    while idx < bytes.len() {
        let op = bytes[idx];
        match op {
            Q_OP_PUSH_CONST | Q_OP_ADD_CONST | Q_OP_MUL_CONST | Q_OP_PUSH_MEM_U16
            | Q_OP_ADD_MEM_U16 | Q_OP_MUL_MEM_U16 | Q_OP_PUSH_TEMP | Q_OP_STORE_TEMP
            | Q_OP_NATIVE_IDENTITY => {
                push_packed_quotient_op(&mut out, op, read_u16(bytes, idx + 1) as u32);
                idx += 3;
            }
            Q_OP_FOLD_SELECTOR => {
                push_packed_quotient_op(&mut out, op, read_u24(bytes, idx + 1));
                idx += 4;
            }
            Q_OP_PUSH_MEM_LITERAL => {
                let ptr = read_u32(bytes, idx + 1);
                assert!(
                    ptr <= QUOTIENT_VM_SPEC.packed_arg_mask,
                    "packed quotient VM literal pointer exceeds 24-bit operand"
                );
                push_packed_quotient_op(&mut out, op, ptr);
                idx += 5;
            }
            Q_OP_PUSH_MEM_TOKEN => {
                push_packed_quotient_op(&mut out, op, bytes[idx + 1] as u32);
                idx += 2;
            }
            Q_OP_PUSH_MEM_TOKEN_OFFSET => {
                let token = bytes[idx + 1] as u32;
                let offset = read_u32(bytes, idx + 2);
                assert!(
                    offset <= u16::MAX as u32,
                    "packed quotient VM token offset exceeds 16-bit operand"
                );
                push_packed_quotient_op(&mut out, op, (token << 16) | offset);
                idx += 6;
            }
            Q_OP_PUSH_CONST_U8 | Q_OP_ADD_CONST_U8 | Q_OP_MUL_CONST_U8 => {
                push_packed_quotient_op(&mut out, op, bytes[idx + 1] as u32);
                idx += 2;
            }
            Q_OP_ADD
            | Q_OP_MUL
            | Q_OP_NEG
            | Q_OP_POW5
            | Q_OP_FOLD_MAIN
            | Q_OP_NATIVE_PERMUTATION
            | Q_OP_NATIVE_LOOKUP => {
                push_packed_quotient_op(&mut out, op, 0);
                idx += 1;
            }
            Q_OP_ADD_MUL_MEM_MEM_CONST_U8 => {
                let lhs = read_u16(bytes, idx + 1) as u32;
                let rhs = read_u16(bytes, idx + 3) as u32;
                let scalar = bytes[idx + 5] as u32;
                push_packed_quotient_op(&mut out, op, scalar);
                out.extend_from_slice(&((lhs << 16) | rhs).to_be_bytes());
                idx += 6;
            }
            Q_OP_ADD_MUL_CONST_U8_MEM_U16 => {
                let ptr = read_u16(bytes, idx + 1) as u32;
                let scalar = bytes[idx + 3] as u32;
                push_packed_quotient_op(&mut out, op, (scalar << 16) | ptr);
                idx += 4;
            }
            Q_OP_ADD_MUL_MEM_MEM => {
                let lhs = read_u16(bytes, idx + 1) as u32;
                let rhs = read_u16(bytes, idx + 3) as u32;
                push_packed_quotient_op(&mut out, op, 0);
                out.extend_from_slice(&((lhs << 16) | rhs).to_be_bytes());
                idx += 5;
            }
            Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8
            | Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16
            | Q_OP_MODARITH7 => {
                panic!("packed quotient VM expects un-compacted quotient op stream")
            }
            op => panic!("unknown quotient op {op:#x} at byte {idx}"),
        }
    }
    out
}

/// Return whether the logical byte stream contains byte-only limb opcodes.
pub(super) fn quotient_program_uses_limb_ops(bytes: &[u8]) -> bool {
    let mut idx = 0usize;
    while idx < bytes.len() {
        if matches!(
            bytes[idx],
            Q_OP_LIN7 | Q_OP_BILIN7_ROW | Q_OP_BILIN7_PAIRWISE | Q_OP_MODARITH7
        ) {
            return true;
        }
        idx += quotient_op_len(bytes, idx);
    }
    false
}

/// Return opcode and memory-token usage for a finalized quotient program.
///
/// This is a code-size optimization for the VK-specialized interpreter. The
/// generated evaluator only needs switch arms for opcodes that can actually
/// occur in its embedded program; malformed external frames still hit the
/// default revert branch.
pub(super) fn quotient_program_usage(
    bytes: &[u8],
    encoding: QuotientProgramEncoding,
) -> (Vec<u8>, Vec<u8>) {
    let mut ops = Vec::new();
    let mut mem_tokens = Vec::new();

    match encoding {
        QuotientProgramEncoding::Bytes => {
            let mut idx = 0usize;
            while idx < bytes.len() {
                let op = bytes[idx];
                push_unique_u8(&mut ops, op);
                match op {
                    Q_OP_PUSH_MEM_TOKEN => {
                        push_unique_u8(&mut mem_tokens, bytes[idx + 1]);
                        idx += 2;
                    }
                    Q_OP_PUSH_MEM_TOKEN_OFFSET => {
                        push_unique_u8(&mut mem_tokens, bytes[idx + 1]);
                        idx += 1 + 1 + QUOTIENT_VM_BYTE_U32_BYTES;
                    }
                    Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8 => {
                        let run_len = read_u16(bytes, idx + 1) as usize;
                        idx += 1
                            + QUOTIENT_VM_BYTE_U16_BYTES
                            + run_len * (2 * QUOTIENT_VM_BYTE_U16_BYTES + 1);
                    }
                    Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16 => {
                        let run_len = read_u16(bytes, idx + 1) as usize;
                        idx += 1
                            + QUOTIENT_VM_BYTE_U16_BYTES
                            + run_len * (QUOTIENT_VM_BYTE_U16_BYTES + 1);
                    }
                    Q_OP_LIN7 => {
                        idx += 1 + QUOTIENT_VM_LIMBS * (1 + QUOTIENT_VM_BYTE_U16_BYTES);
                    }
                    Q_OP_BILIN7_ROW => {
                        idx += 1
                            + QUOTIENT_VM_BYTE_U16_BYTES
                            + QUOTIENT_VM_LIMBS * (1 + QUOTIENT_VM_BYTE_U16_BYTES);
                    }
                    Q_OP_BILIN7_PAIRWISE => {
                        idx += 1 + 2 * QUOTIENT_VM_BYTE_U16_BYTES + QUOTIENT_VM_PAIRWISE_COEFFS;
                    }
                    _ => idx += quotient_op_len(bytes, idx),
                }
            }
        }
        QuotientProgramEncoding::Packed32 => {
            let mut idx = 0usize;
            while idx < bytes.len() {
                let word = read_u32(bytes, idx);
                let op = (word >> QUOTIENT_VM_PACKED_ARG_BITS) as u8;
                let arg = word & QUOTIENT_VM_PACKED_ARG_MASK;
                push_unique_u8(&mut ops, op);
                match op {
                    Q_OP_PUSH_MEM_TOKEN => {
                        push_unique_u8(&mut mem_tokens, arg as u8);
                        idx += QUOTIENT_VM_PACKED_INSTRUCTION_BYTES;
                    }
                    Q_OP_PUSH_MEM_TOKEN_OFFSET => {
                        push_unique_u8(&mut mem_tokens, (arg >> 16) as u8);
                        idx += QUOTIENT_VM_PACKED_INSTRUCTION_BYTES;
                    }
                    Q_OP_ADD_MUL_MEM_MEM_CONST_U8 | Q_OP_ADD_MUL_MEM_MEM => {
                        idx += 2 * QUOTIENT_VM_PACKED_INSTRUCTION_BYTES;
                    }
                    _ => idx += QUOTIENT_VM_PACKED_INSTRUCTION_BYTES,
                }
            }
        }
    }

    (ops, mem_tokens)
}

fn push_unique_u8(values: &mut Vec<u8>, value: u8) {
    if !values.contains(&value) {
        values.push(value);
        values.sort_unstable();
    }
}

/// Decode a finalized physical quotient program and verify stack safety.
///
/// This is an offline safety check for the VK-pinned program, not a runtime
/// verifier feature. The Yul VM stays lean and assumes codegen emitted a valid
/// stream; this pass proves that assumption before the program is embedded.
pub(super) fn validate_quotient_program(
    bytes: &[u8],
    encoding: QuotientProgramEncoding,
) -> Result<usize, String> {
    let mut idx = 0usize;
    let mut depth = 0usize;
    let mut max_stack = 0usize;

    if encoding == QuotientProgramEncoding::Packed32
        && bytes.len() % QUOTIENT_VM_PACKED_INSTRUCTION_BYTES != 0
    {
        return Err(format!(
            "packed32 quotient program length {} is not a multiple of {}",
            bytes.len(),
            QUOTIENT_VM_PACKED_INSTRUCTION_BYTES
        ));
    }

    while idx < bytes.len() {
        let (op, len) = match encoding {
            QuotientProgramEncoding::Bytes => decode_byte_quotient_instruction(bytes, idx)?,
            QuotientProgramEncoding::Packed32 => decode_packed_quotient_instruction(bytes, idx)?,
        };
        apply_quotient_stack_effect(op, idx, &mut depth, &mut max_stack)?;
        idx += len;
    }

    if depth != 0 {
        return Err(format!(
            "quotient VM stack leak at end of program: {depth} value(s) remain"
        ));
    }

    Ok(max_stack)
}

fn decode_byte_quotient_instruction(bytes: &[u8], idx: usize) -> Result<(u8, usize), String> {
    require_quotient_bytes(bytes, idx, 1, "opcode")?;
    let op = bytes[idx];
    let spec = quotient_opcode_spec(op)
        .ok_or_else(|| format!("unknown quotient VM opcode {op:#x} at byte {idx}"))?;
    let len = quotient_byte_instruction_len_checked(bytes, idx)?;

    match op {
        Q_OP_PUSH_MEM_TOKEN => {
            let token = bytes[idx + 1];
            validate_quotient_mem_token(token, idx)?;
        }
        Q_OP_PUSH_MEM_TOKEN_OFFSET => {
            let token = bytes[idx + 1];
            validate_quotient_mem_token(token, idx)?;
        }
        _ => {}
    }

    if len == 0 {
        return Err(format!(
            "quotient VM opcode {} ({op:#x}) decoded to zero length at byte {idx}",
            spec.name
        ));
    }
    Ok((op, len))
}

fn decode_packed_quotient_instruction(bytes: &[u8], idx: usize) -> Result<(u8, usize), String> {
    require_quotient_bytes(
        bytes,
        idx,
        QUOTIENT_VM_PACKED_INSTRUCTION_BYTES,
        "packed32 instruction",
    )?;
    let word = read_u32(bytes, idx);
    let op = (word >> QUOTIENT_VM_PACKED_ARG_BITS) as u8;
    let arg = word & QUOTIENT_VM_PACKED_ARG_MASK;
    let spec = quotient_opcode_spec(op)
        .ok_or_else(|| format!("unknown quotient VM opcode {op:#x} at byte {idx}"))?;
    if !spec.packed32 {
        return Err(format!(
            "opcode {} ({op:#x}) is not supported by packed32 encoding at byte {idx}",
            spec.name
        ));
    }

    match op {
        Q_OP_PUSH_MEM_TOKEN => {
            let token = u8::try_from(arg).map_err(|_| {
                format!("packed32 PUSH_MEM_TOKEN operand {arg:#x} exceeds u8 at byte {idx}")
            })?;
            validate_quotient_mem_token(token, idx)?;
        }
        Q_OP_PUSH_MEM_TOKEN_OFFSET => {
            validate_quotient_mem_token((arg >> 16) as u8, idx)?;
        }
        Q_OP_ADD_MUL_MEM_MEM_CONST_U8 | Q_OP_ADD_MUL_MEM_MEM => {
            require_quotient_bytes(
                bytes,
                idx,
                2 * QUOTIENT_VM_PACKED_INSTRUCTION_BYTES,
                "packed32 fused two-pointer instruction",
            )?;
            return Ok((op, 2 * QUOTIENT_VM_PACKED_INSTRUCTION_BYTES));
        }
        _ => {}
    }

    Ok((op, QUOTIENT_VM_PACKED_INSTRUCTION_BYTES))
}

fn quotient_byte_instruction_len_checked(bytes: &[u8], idx: usize) -> Result<usize, String> {
    let op = bytes[idx];
    let len = match op {
        Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8 => {
            require_quotient_bytes(bytes, idx, 1 + QUOTIENT_VM_BYTE_U16_BYTES, "run count")?;
            let count = read_u16(bytes, idx + 1) as usize;
            if count == 0 {
                return Err(format!("zero-length quotient VM run at byte {idx}"));
            }
            let payload_len =
                checked_quotient_len_mul(count, 2 * QUOTIENT_VM_BYTE_U16_BYTES + 1, op, idx)?;
            checked_quotient_len_add(1 + QUOTIENT_VM_BYTE_U16_BYTES, payload_len, op, idx)?
        }
        Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16 => {
            require_quotient_bytes(bytes, idx, 1 + QUOTIENT_VM_BYTE_U16_BYTES, "run count")?;
            let count = read_u16(bytes, idx + 1) as usize;
            if count == 0 {
                return Err(format!("zero-length quotient VM run at byte {idx}"));
            }
            let payload_len =
                checked_quotient_len_mul(count, QUOTIENT_VM_BYTE_U16_BYTES + 1, op, idx)?;
            checked_quotient_len_add(1 + QUOTIENT_VM_BYTE_U16_BYTES, payload_len, op, idx)?
        }
        Q_OP_MODARITH7 => quotient_modarith7_op_len_checked(bytes, idx)?,
        _ => quotient_opcode_byte_len(op)
            .ok_or_else(|| format!("unknown quotient VM opcode {op:#x} at byte {idx}"))?,
    };
    require_quotient_bytes(bytes, idx, len, "instruction")?;
    Ok(len)
}

fn quotient_modarith7_op_len_checked(bytes: &[u8], idx: usize) -> Result<usize, String> {
    let op = Q_OP_MODARITH7;
    let mut cursor = idx;
    advance_quotient_cursor(bytes, &mut cursor, 1, op, idx)?; // opcode
    require_quotient_bytes(bytes, cursor, 1, "MODARITH7 flags")?;
    let flags = bytes[cursor];
    if flags & !(Q_MODARITH7_FLAG_COND | Q_MODARITH7_FLAG_CONST) != 0 {
        return Err(format!(
            "MODARITH7 has unknown flag bits {flags:#x} at byte {idx}"
        ));
    }
    advance_quotient_cursor(bytes, &mut cursor, 1, op, idx)?;
    if flags & Q_MODARITH7_FLAG_COND != 0 {
        advance_quotient_cursor(bytes, &mut cursor, QUOTIENT_VM_BYTE_U16_BYTES, op, idx)?;
    }
    if flags & Q_MODARITH7_FLAG_CONST != 0 {
        advance_quotient_cursor(bytes, &mut cursor, 1, op, idx)?;
    }

    require_quotient_bytes(bytes, cursor, 5, "MODARITH7 count header")?;
    let lin_count = bytes[cursor] as usize;
    let row_count = bytes[cursor + 1] as usize;
    let pairwise_count = bytes[cursor + 2] as usize;
    let mem_count = bytes[cursor + 3] as usize;
    let product_count = bytes[cursor + 4] as usize;
    advance_quotient_cursor(bytes, &mut cursor, 5, op, idx)?;

    advance_quotient_cursor(
        bytes,
        &mut cursor,
        checked_quotient_len_mul(
            lin_count,
            QUOTIENT_VM_LIMBS * (1 + QUOTIENT_VM_BYTE_U16_BYTES),
            op,
            idx,
        )?,
        op,
        idx,
    )?;
    advance_quotient_cursor(
        bytes,
        &mut cursor,
        checked_quotient_len_mul(
            row_count,
            QUOTIENT_VM_BYTE_U16_BYTES + QUOTIENT_VM_LIMBS * (1 + QUOTIENT_VM_BYTE_U16_BYTES),
            op,
            idx,
        )?,
        op,
        idx,
    )?;
    advance_quotient_cursor(
        bytes,
        &mut cursor,
        checked_quotient_len_mul(
            pairwise_count,
            2 * QUOTIENT_VM_BYTE_U16_BYTES + QUOTIENT_VM_PAIRWISE_COEFFS,
            op,
            idx,
        )?,
        op,
        idx,
    )?;
    advance_quotient_cursor(
        bytes,
        &mut cursor,
        checked_quotient_len_mul(mem_count, 1 + QUOTIENT_VM_BYTE_U16_BYTES, op, idx)?,
        op,
        idx,
    )?;
    advance_quotient_cursor(
        bytes,
        &mut cursor,
        checked_quotient_len_mul(product_count, 1 + 2 * QUOTIENT_VM_BYTE_U16_BYTES, op, idx)?,
        op,
        idx,
    )?;

    Ok(cursor - idx)
}

fn apply_quotient_stack_effect(
    op: u8,
    idx: usize,
    depth: &mut usize,
    max_stack: &mut usize,
) -> Result<(), String> {
    match op {
        Q_OP_PUSH_CONST
        | Q_OP_PUSH_MEM_LITERAL
        | Q_OP_PUSH_MEM_TOKEN
        | Q_OP_PUSH_MEM_TOKEN_OFFSET
        | Q_OP_PUSH_MEM_U16
        | Q_OP_PUSH_CONST_U8
        | Q_OP_PUSH_TEMP
        | Q_OP_LIN7
        | Q_OP_BILIN7_ROW
        | Q_OP_BILIN7_PAIRWISE
        | Q_OP_MODARITH7 => {
            *depth = depth
                .checked_add(1)
                .ok_or_else(|| format!("quotient VM stack depth overflow at byte {idx}"))?;
            *max_stack = (*max_stack).max(*depth);
        }
        Q_OP_ADD | Q_OP_MUL => {
            require_quotient_stack_depth(op, idx, *depth, 2)?;
            *depth -= 1;
        }
        Q_OP_NEG
        | Q_OP_ADD_CONST_U8
        | Q_OP_MUL_CONST_U8
        | Q_OP_ADD_CONST
        | Q_OP_MUL_CONST
        | Q_OP_ADD_MEM_U16
        | Q_OP_MUL_MEM_U16
        | Q_OP_ADD_MUL_MEM_MEM_CONST_U8
        | Q_OP_ADD_MUL_CONST_U8_MEM_U16
        | Q_OP_ADD_MUL_MEM_MEM
        | Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8
        | Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16
        | Q_OP_STORE_TEMP
        | Q_OP_POW5 => {
            require_quotient_stack_depth(op, idx, *depth, 1)?;
        }
        Q_OP_FOLD_MAIN | Q_OP_FOLD_SELECTOR => {
            if *depth != 1 {
                return Err(format!(
                    "quotient VM stack boundary error at byte {idx}: opcode {op:#x} requires exactly 1 stack value, found {depth}"
                ));
            }
            *depth = 0;
        }
        Q_OP_NATIVE_PERMUTATION | Q_OP_NATIVE_LOOKUP | Q_OP_NATIVE_IDENTITY => {
            if *depth != 0 {
                return Err(format!(
                    "quotient VM native callback at byte {idx}: opcode {op:#x} requires an empty stack, found {depth}"
                ));
            }
        }
        _ => {
            return Err(format!(
                "unknown quotient VM opcode {op:#x} reached stack validator at byte {idx}"
            ));
        }
    }
    Ok(())
}

fn require_quotient_stack_depth(
    op: u8,
    idx: usize,
    depth: usize,
    required: usize,
) -> Result<(), String> {
    if depth < required {
        return Err(format!(
            "quotient VM stack underflow at byte {idx}: opcode {op:#x} requires {required} stack value(s), found {depth}"
        ));
    }
    Ok(())
}

fn validate_quotient_mem_token(token: u8, idx: usize) -> Result<(), String> {
    if QUOTIENT_VM_SPEC
        .mem_tokens
        .iter()
        .any(|spec| spec.token == token)
    {
        Ok(())
    } else {
        Err(format!(
            "unknown quotient VM memory token {token:#x} at byte {idx}"
        ))
    }
}

fn require_quotient_bytes(
    bytes: &[u8],
    idx: usize,
    len: usize,
    context: &str,
) -> Result<(), String> {
    let end = idx
        .checked_add(len)
        .ok_or_else(|| format!("quotient VM {context} length overflows at byte {idx}"))?;
    if end > bytes.len() {
        return Err(format!(
            "truncated quotient VM {context} at byte {idx}: need {len} byte(s), program has {} byte(s) remaining",
            bytes.len().saturating_sub(idx)
        ));
    }
    Ok(())
}

fn advance_quotient_cursor(
    bytes: &[u8],
    cursor: &mut usize,
    amount: usize,
    op: u8,
    op_idx: usize,
) -> Result<(), String> {
    require_quotient_bytes(bytes, *cursor, amount, "dynamic instruction operand")?;
    *cursor = cursor.checked_add(amount).ok_or_else(|| {
        format!("quotient VM opcode {op:#x} length overflows while decoding byte {op_idx}")
    })?;
    Ok(())
}

fn checked_quotient_len_mul(lhs: usize, rhs: usize, op: u8, idx: usize) -> Result<usize, String> {
    lhs.checked_mul(rhs).ok_or_else(|| {
        format!("quotient VM opcode {op:#x} length multiplication overflows at byte {idx}")
    })
}

fn checked_quotient_len_add(lhs: usize, rhs: usize, op: u8, idx: usize) -> Result<usize, String> {
    lhs.checked_add(rhs).ok_or_else(|| {
        format!("quotient VM opcode {op:#x} length addition overflows at byte {idx}")
    })
}

/// Append one packed32 instruction word.
pub(super) fn push_packed_quotient_op(out: &mut Vec<u8>, op: u8, arg: u32) {
    assert!(
        arg <= QUOTIENT_VM_SPEC.packed_arg_mask,
        "packed quotient VM operand exceeds 24 bits"
    );
    out.extend_from_slice(&(((op as u32) << 24) | arg).to_be_bytes());
}

/// Read a big-endian `u16` operand from bytecode.
pub(super) fn read_u16(bytes: &[u8], idx: usize) -> u16 {
    u16::from_be_bytes(
        bytes[idx..idx + 2]
            .try_into()
            .expect("u16 quotient operand"),
    )
}

/// Read a big-endian 24-bit operand from bytecode.
pub(super) fn read_u24(bytes: &[u8], idx: usize) -> u32 {
    let bytes: [u8; 3] = bytes[idx..idx + 3]
        .try_into()
        .expect("u24 quotient operand");
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
}

/// Read a big-endian `u32` operand from bytecode.
pub(super) fn read_u32(bytes: &[u8], idx: usize) -> u32 {
    u32::from_be_bytes(
        bytes[idx..idx + 4]
            .try_into()
            .expect("u32 quotient operand"),
    )
}

/// Configured number of leading identities emitted as direct Yul.
pub(super) fn hybrid_quotient_inline_count(identities: &[QuotientIdentity]) -> usize {
    identities
        .len()
        .min(config::CodegenOptions::from_env().hybrid_quotient_inline_identities)
}

/// Configured number of gate identities selected for native callbacks.
pub(super) fn quotient_native_gate_count(gates: &[QuotientIdentity]) -> usize {
    gates
        .len()
        .min(config::CodegenOptions::from_env().quotient_native_gates)
}

/// Optional estimated native callback byte budget for gate selection.
pub(super) fn quotient_native_gate_byte_budget() -> Option<usize> {
    config::CodegenOptions::from_env().quotient_native_gate_byte_budget
}

/// Configured physical VM encoding.
pub(super) fn quotient_program_encoding() -> QuotientProgramEncoding {
    config::CodegenOptions::from_env().quotient_encoding
}

/// Whether the direct inline quotient path uses memory-backed CSE.
pub(super) fn quotient_inline_cse_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_inline_cse
}

/// Whether compact VM bytecode may use `PUSH_TEMP` and `STORE_TEMP`.
pub(super) fn quotient_vm_cse_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_vm_cse
}

/// Whether direct Yul emission may call local quotient helper functions.
pub(super) fn quotient_yul_helpers_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_yul_helpers
}

/// Whether recognized identity runs may become structured loops.
pub(super) fn quotient_structured_loops_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_structured_loops
}

/// Configured structured suffix mode.
pub(super) fn quotient_structured_tail_mode() -> QuotientStructuredTailMode {
    config::CodegenOptions::from_env().quotient_structured_tail
}

/// Whether the permutation identity block may be a native VM callback.
pub(super) fn quotient_native_permutation_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_native_permutation
}

/// Whether lookup identities should be emitted as one native VM callback.
pub(super) fn quotient_native_lookup_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_native_lookup
}

/// Whether byte-oriented VM lowering may emit limb-specialized opcodes.
pub(super) fn quotient_limb_vm_ops_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_limb_vm_ops
}

/// Whether codegen prints limb-shape profile counters to stderr.
pub(super) fn quotient_shape_profile_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_shape_profile
}

/// Count expression occurrences and estimate bytecode cost for VM CSE.
///
/// The cost is measured in byte-oriented VM bytes, not gas. That is the right
/// proxy because VM CSE's main job is reducing generated VK payload size while
/// keeping interpreter behavior identical.
pub(super) fn count_quotient_exprs(
    expr: &QuotientExpr,
    counts: &mut HashMap<String, usize>,
    costs: &mut HashMap<String, usize>,
) -> usize {
    let key = quotient_expr_key(expr);
    *counts.entry(key.clone()).or_default() += 1;

    let cost = match expr {
        QuotientExpr::Const(_) => 2,
        QuotientExpr::Mem(QuotientMem::Literal(ptr)) => {
            if u16::try_from(*ptr).is_ok() {
                3
            } else {
                5
            }
        }
        QuotientExpr::Mem(QuotientMem::Token(_)) => 2,
        QuotientExpr::Mem(QuotientMem::TokenOffset(_, _)) => 6,
        QuotientExpr::Add(lhs, rhs) | QuotientExpr::Mul(lhs, rhs) => {
            count_quotient_exprs(lhs, counts, costs) + count_quotient_exprs(rhs, counts, costs) + 1
        }
        QuotientExpr::Neg(inner) => count_quotient_exprs(inner, counts, costs) + 1,
    };
    costs.entry(key).or_insert(cost);
    cost
}

/// Count expression occurrences, costs, and bodies for inline Yul CSE.
pub(super) fn collect_quotient_expr_stats(
    expr: &QuotientExpr,
    counts: &mut HashMap<String, usize>,
    costs: &mut HashMap<String, usize>,
    exprs: &mut HashMap<String, QuotientExpr>,
) -> usize {
    let key = quotient_expr_key(expr);
    *counts.entry(key.clone()).or_default() += 1;
    exprs.entry(key.clone()).or_insert_with(|| expr.clone());

    let cost = match expr {
        QuotientExpr::Const(_) => 2,
        QuotientExpr::Mem(QuotientMem::Literal(ptr)) => {
            if u16::try_from(*ptr).is_ok() {
                3
            } else {
                5
            }
        }
        QuotientExpr::Mem(QuotientMem::Token(_)) => 2,
        QuotientExpr::Mem(QuotientMem::TokenOffset(_, _)) => 6,
        QuotientExpr::Add(lhs, rhs) | QuotientExpr::Mul(lhs, rhs) => {
            collect_quotient_expr_stats(lhs, counts, costs, exprs)
                + collect_quotient_expr_stats(rhs, counts, costs, exprs)
                + 1
        }
        QuotientExpr::Neg(inner) => collect_quotient_expr_stats(inner, counts, costs, exprs) + 1,
    };
    costs.entry(key).or_insert(cost);
    cost
}

/// Decide whether a repeated expression is worth a VM temp slot.
pub(super) fn quotient_cse_candidate(count: usize, cost: usize) -> bool {
    if count <= 1 || cost <= 3 {
        return false;
    }
    // First use pays the original expression plus STORE_TEMP; each later use
    // becomes PUSH_TEMP. Keep only cases with an estimated bytecode win.
    (count - 1) * (cost - 3) > 3
}

/// Decide whether a repeated expression is worth an inline Yul CSE slot.
pub(super) fn quotient_inline_cse_candidate(count: usize, cost: usize) -> bool {
    if count <= 1 || cost <= 6 {
        return false;
    }
    // Straight-line CSE stores the first evaluation in memory and replaces
    // every use with an mload. Keep only expressions with enough estimated
    // duplicated arithmetic to pay for the mstore/mload bytecode.
    (count - 1) * cost > 12
}

/// Deterministic sort key for CSE slot assignment.
///
/// Better estimated savings sort first, then larger individual expressions,
/// then the canonical expression key for reproducibility.
pub(super) fn quotient_cse_sort_key(key: &str, count: usize, cost: usize) -> (usize, usize, &str) {
    let score = count.saturating_sub(1).saturating_mul(cost);
    (
        usize::MAX.saturating_sub(score),
        usize::MAX.saturating_sub(cost),
        key,
    )
}

/// Canonical key for CSE and deduplication.
///
/// Addition and multiplication are keyed commutatively because all arithmetic
/// is over Fr and these rewrites do not alter evaluation order side effects:
/// `QuotientExpr` has no side effects.
pub(super) fn quotient_expr_key(expr: &QuotientExpr) -> String {
    match expr {
        QuotientExpr::Const(value) => format!("c:{value:x}"),
        QuotientExpr::Mem(QuotientMem::Literal(ptr)) => format!("m:{ptr:x}"),
        QuotientExpr::Mem(QuotientMem::Token(token)) => format!("t:{token:x}"),
        QuotientExpr::Mem(QuotientMem::TokenOffset(token, offset)) => {
            format!("to:{token:x}:{offset:x}")
        }
        QuotientExpr::Add(lhs, rhs) => quotient_commutative_expr_key("a", lhs, rhs),
        QuotientExpr::Mul(lhs, rhs) => quotient_commutative_expr_key("u", lhs, rhs),
        QuotientExpr::Neg(inner) => format!("n:{}", quotient_expr_key(inner)),
    }
}

/// Render a memory reference as a Yul `mload` expression.
pub(super) fn quotient_mem_load_expr(mem: QuotientMem) -> String {
    format!("mload({})", quotient_mem_ptr_expr(mem))
}

/// Render a memory reference as a Yul pointer expression.
pub(super) fn quotient_mem_ptr_expr(mem: QuotientMem) -> String {
    match mem {
        QuotientMem::Literal(ptr) => format!("{ptr:#x}"),
        QuotientMem::Token(token) => quotient_mem_token_name(token).to_string(),
        QuotientMem::TokenOffset(token, offset) => {
            format!("add({}, {offset:#x})", quotient_mem_token_name(token))
        }
    }
}

/// Resolve a memory token to the generated Yul symbol name.
pub(super) fn quotient_mem_token_name(token: u8) -> &'static str {
    QUOTIENT_MEM_TOKEN_TABLE
        .iter()
        .find_map(|spec| (spec.token == token).then_some(spec.name))
        .unwrap_or_else(|| panic!("unknown quotient memory token {token:#x}"))
}

/// Resolve a generated Yul memory symbol name to its compact token.
pub(super) fn quotient_mem_token_from_name(name: &str) -> Option<u8> {
    QUOTIENT_MEM_TOKEN_TABLE
        .iter()
        .find_map(|spec| (spec.name == name).then_some(spec.token))
}

/// Environment needed to lower Halo2 `Expression<Fq>` leaves.
///
/// The VM lowerer is independent of the concrete verifier memory layout; this
/// trait supplies the memory-backed expression for each kind of query.
pub(super) trait QuotientExpressionEnv {
    /// Lower a selector leaf.
    fn selector(&self, selector: Selector) -> QuotientExpr;
    /// Lower a fixed-column query leaf.
    fn fixed(&self, column_index: usize, rotation: i32) -> QuotientExpr;
    /// Lower an advice-column query leaf.
    fn advice(&self, column_index: usize, rotation: i32) -> QuotientExpr;
    /// Lower an instance-column query leaf.
    fn instance(&self, column_index: usize, rotation: i32) -> QuotientExpr;
    /// Lower a challenge leaf.
    fn challenge(&self, index: usize) -> QuotientExpr;
}

/// Lower a Halo2 expression into the compact quotient AST.
pub(super) fn quotient_expr_from_expression<E: QuotientExpressionEnv>(
    env: &E,
    expression: &Expression<Fq>,
) -> QuotientExpr {
    expression.evaluate(
        &|scalar| QuotientExpr::Const(fe_to_u256::<Fq>(&scalar)),
        &|selector| env.selector(selector),
        &|query| env.fixed(query.column_index(), query.rotation().0),
        &|query| env.advice(query.column_index(), query.rotation().0),
        &|query| env.instance(query.column_index(), query.rotation().0),
        &|challenge| env.challenge(challenge.index()),
        &|inner| QuotientExpr::Neg(Box::new(inner)),
        &|lhs, rhs| QuotientExpr::Add(Box::new(lhs), Box::new(rhs)),
        &|lhs, rhs| QuotientExpr::Mul(Box::new(lhs), Box::new(rhs)),
        &|inner, scalar| {
            QuotientExpr::Mul(
                Box::new(inner),
                Box::new(QuotientExpr::Const(fe_to_u256::<Fq>(&scalar))),
            )
        },
    )
}

/// Production expression environment backed by generated verifier data.
pub(super) struct DataQuotientExpressionEnv<'a> {
    /// Constraint-system metadata used to classify selectors and instances.
    pub(super) meta: &'a ConstraintSystemMeta,
    /// Concrete generated memory locations for proof/VK/challenge values.
    pub(super) data: &'a Data,
}

impl QuotientExpressionEnv for DataQuotientExpressionEnv<'_> {
    /// Reject virtual selectors after selector-to-fixed conversion.
    fn selector(&self, _selector: Selector) -> QuotientExpr {
        panic!("virtual selectors must be removed before quotient lowering")
    }

    /// Lower a fixed query, synthesizing simple selectors as constant one.
    fn fixed(&self, column_index: usize, rotation: i32) -> QuotientExpr {
        if self.meta.simple_selector_cols.contains(&column_index) {
            QuotientExpr::Const(U256::from(1u64))
        } else {
            word_to_quotient_expr(
                *self
                    .data
                    .fixed_evals
                    .get(&(column_index, rotation))
                    .expect("fixed eval present"),
            )
        }
    }

    /// Lower an advice query to a memory-backed eval word.
    fn advice(&self, column_index: usize, rotation: i32) -> QuotientExpr {
        word_to_quotient_expr(
            *self
                .data
                .advice_evals
                .get(&(column_index, rotation))
                .expect("advice eval present"),
        )
    }

    /// Lower an instance query from proof evals or local instance evaluation.
    fn instance(&self, column_index: usize, rotation: i32) -> QuotientExpr {
        if column_index < self.meta.num_committed_instances {
            word_to_quotient_expr(
                *self
                    .data
                    .committed_instance_evals
                    .get(&(column_index, rotation))
                    .expect("committed instance eval present"),
            )
        } else {
            word_to_quotient_expr(self.data.instance_eval)
        }
    }

    /// Lower a user challenge to its memory-backed word.
    fn challenge(&self, index: usize) -> QuotientExpr {
        word_to_quotient_expr(self.data.challenges[index])
    }
}

/// Convert a memory-backed `Word` into a quotient memory load expression.
pub(super) fn word_to_quotient_expr(word: Word) -> QuotientExpr {
    assert_eq!(
        word.loc(),
        Location::Memory,
        "quotient expressions can only load memory-backed words"
    );
    QuotientExpr::Mem(ptr_to_quotient_mem(word.ptr()))
}

/// Convert a generated memory pointer into the compact VM pointer form.
pub(super) fn ptr_to_quotient_mem(ptr: Ptr) -> QuotientMem {
    assert_eq!(
        ptr.loc(),
        Location::Memory,
        "quotient expressions can only load memory-backed words"
    );
    match ptr.value() {
        Value::Integer(offset) => {
            assert!(offset >= 0, "negative quotient memory pointer");
            QuotientMem::Literal(offset as u32)
        }
        Value::Identifier(name, offset) => {
            assert!(offset >= 0, "negative quotient memory token offset");
            let token = quotient_mem_token_from_name(name)
                .unwrap_or_else(|| panic!("unsupported quotient memory token: {name}"));
            if offset == 0 {
                QuotientMem::Token(token)
            } else {
                QuotientMem::TokenOffset(token, offset as u32)
            }
        }
    }
}

/// Canonical key helper for commutative binary operations.
pub(super) fn quotient_commutative_expr_key(
    op: &str,
    lhs: &QuotientExpr,
    rhs: &QuotientExpr,
) -> String {
    let lhs = quotient_expr_key(lhs);
    let rhs = quotient_expr_key(rhs);
    if lhs <= rhs {
        format!("{op}:{lhs}:{rhs}")
    } else {
        format!("{op}:{rhs}:{lhs}")
    }
}

/// Byte length of the opcode at `idx`.
///
/// Fixed-width opcodes are read from the spec table; byte-only run and
/// MODARITH7 opcodes decode their embedded counts.
pub(super) fn quotient_op_len(bytes: &[u8], idx: usize) -> usize {
    let op = bytes[idx];
    match op {
        Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8 => {
            1 + QUOTIENT_VM_BYTE_U16_BYTES
                + (read_u16(bytes, idx + 1) as usize) * (2 * QUOTIENT_VM_BYTE_U16_BYTES + 1)
        }
        Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16 => {
            1 + QUOTIENT_VM_BYTE_U16_BYTES
                + (read_u16(bytes, idx + 1) as usize) * (QUOTIENT_VM_BYTE_U16_BYTES + 1)
        }
        Q_OP_MODARITH7 => quotient_modarith7_op_len(bytes, idx),
        _ => quotient_opcode_byte_len(op)
            .unwrap_or_else(|| panic!("unknown quotient op {op:#x} at byte {idx}")),
    }
}

fn quotient_modarith7_op_len(bytes: &[u8], idx: usize) -> usize {
    let mut cursor = idx + 1;
    let flags = bytes[cursor];
    cursor += 1;
    if flags & Q_MODARITH7_FLAG_COND != 0 {
        cursor += QUOTIENT_VM_BYTE_U16_BYTES;
    }
    if flags & Q_MODARITH7_FLAG_CONST != 0 {
        cursor += 1;
    }
    let lin_count = bytes[cursor] as usize;
    let row_count = bytes[cursor + 1] as usize;
    let pairwise_count = bytes[cursor + 2] as usize;
    let mem_count = bytes[cursor + 3] as usize;
    let product_count = bytes[cursor + 4] as usize;
    cursor += 5;
    cursor += lin_count * QUOTIENT_VM_LIMBS * (1 + QUOTIENT_VM_BYTE_U16_BYTES);
    cursor += row_count
        * (QUOTIENT_VM_BYTE_U16_BYTES + QUOTIENT_VM_LIMBS * (1 + QUOTIENT_VM_BYTE_U16_BYTES));
    cursor += pairwise_count * (2 * QUOTIENT_VM_BYTE_U16_BYTES + QUOTIENT_VM_PAIRWISE_COEFFS);
    cursor += mem_count * (1 + QUOTIENT_VM_BYTE_U16_BYTES);
    cursor += product_count * (1 + 2 * QUOTIENT_VM_BYTE_U16_BYTES);
    cursor - idx
}

/// Return the leaf form of an expression, if it has no arithmetic children.
pub(super) fn quotient_leaf(expr: &QuotientExpr) -> Option<QuotientLeaf> {
    match expr {
        QuotientExpr::Const(value) => Some(QuotientLeaf::Const(*value)),
        QuotientExpr::Mem(mem) => Some(QuotientLeaf::Mem(*mem)),
        QuotientExpr::Add(_, _) | QuotientExpr::Mul(_, _) | QuotientExpr::Neg(_) => None,
    }
}

/// Flatten a pure multiplication tree into constant/memory leaves.
///
/// This intentionally rejects sums and negations. Additive structure is handled
/// by sum collection or by the generic emitter; fused product-add opcodes need
/// a product that can be encoded directly.
pub(super) fn collect_product_leaves(expr: &QuotientExpr, leaves: &mut Vec<QuotientLeaf>) -> bool {
    match expr {
        QuotientExpr::Mul(lhs, rhs) => {
            collect_product_leaves(lhs, leaves) && collect_product_leaves(rhs, leaves)
        }
        QuotientExpr::Const(_) | QuotientExpr::Mem(_) => {
            if let Some(leaf) = quotient_leaf(expr) {
                leaves.push(leaf);
                true
            } else {
                false
            }
        }
        QuotientExpr::Add(_, _) | QuotientExpr::Neg(_) => false,
    }
}

fn collect_product_expr_factors<'a>(expr: &'a QuotientExpr, factors: &mut Vec<&'a QuotientExpr>) {
    match expr {
        QuotientExpr::Mul(lhs, rhs) => {
            collect_product_expr_factors(lhs, factors);
            collect_product_expr_factors(rhs, factors);
        }
        QuotientExpr::Const(_)
        | QuotientExpr::Mem(_)
        | QuotientExpr::Add(_, _)
        | QuotientExpr::Neg(_) => {
            factors.push(expr);
        }
    }
}

fn quotient_sum_expr(lhs: QuotientExpr, rhs: QuotientExpr) -> QuotientExpr {
    QuotientExpr::Add(Box::new(lhs), Box::new(rhs))
}

fn quotient_scaled_term_expr(coeff: Fq, expr: QuotientExpr) -> QuotientExpr {
    if coeff == Fq::ONE {
        expr
    } else {
        QuotientExpr::Mul(
            Box::new(QuotientExpr::Const(quotient_fq_to_u256(coeff))),
            Box::new(expr),
        )
    }
}

/// Recognize any supported seven-limb foreign-field quotient shape.
pub(super) fn quotient_limb_shape(expr: &QuotientExpr) -> Option<QuotientLimbShape> {
    // Recover foreign-field limb algebra from the generic `QuotientExpr`
    // tree. This deliberately does not look at gate names: the Rust verifier
    // source of truth remains proofs/src/plonk/mod.rs::partially_evaluate_identities,
    // which evaluates `vk.cs.gates` expression trees in order. The recognizer
    // only changes how obvious `sum_exprs` / `pair_wise_prod` shapes are
    // encoded for Solidity.
    let mut terms = Vec::new();
    if !collect_quotient_sum_terms(expr, Fq::ONE, &mut terms) {
        return None;
    }
    terms.retain(|(coeff, _)| *coeff != Fq::ZERO);

    try_quotient_bilin7_pairwise_shape(&terms)
        .or_else(|| try_quotient_bilin7_row_shape(&terms))
        .or_else(|| try_quotient_lin7_shape(&terms))
}

/// Return the repeated base for a structural fifth power.
pub(super) fn quotient_pow5_base(expr: &QuotientExpr) -> Option<&QuotientExpr> {
    let mut factors = Vec::with_capacity(5);
    collect_product_expr_factors(expr, &mut factors);
    if factors.len() != 5 {
        return None;
    }
    let first_key = quotient_expr_key(factors[0]);
    factors
        .iter()
        .all(|factor| quotient_expr_key(factor) == first_key)
        .then_some(factors[0])
}

/// Extract one limb shape from a larger affine sum and return the residue.
pub(super) fn quotient_limb_subshape(
    expr: &QuotientExpr,
) -> Option<(QuotientLimbShape, QuotientExpr)> {
    let mut terms = Vec::new();
    let mut constant = Fq::ZERO;
    if !collect_quotient_affine_terms(expr, Fq::ONE, &mut terms, &mut constant) {
        return None;
    }
    terms.retain(|(coeff, _)| *coeff != Fq::ZERO);
    if terms.len() <= QUOTIENT_VM_LIMBS && constant == Fq::ZERO {
        return None;
    }

    let (shape, used) = try_quotient_bilin7_pairwise_subshape(&terms)
        .or_else(|| try_quotient_bilin7_row_subshape(&terms))
        .or_else(|| try_quotient_lin7_subshape(&terms))?;
    if used.is_empty() || (used.len() == terms.len() && constant == Fq::ZERO) {
        return None;
    }

    let used = used.into_iter().collect::<HashSet<_>>();
    let mut residue = QuotientExpr::Const(quotient_fq_to_u256(constant));
    for (idx, (coeff, term)) in terms.into_iter().enumerate() {
        if used.contains(&idx) {
            continue;
        }
        residue = quotient_sum_expr(residue, quotient_scaled_term_expr(coeff, (*term).clone()));
    }
    Some((shape, residue))
}

/// Recognize a whole affine foreign-field/ECC identity that can be evaluated
/// by the dynamic `MODARITH7` opcode.
pub(super) fn quotient_modarith7_shape(expr: &QuotientExpr) -> Option<QuotientModarith7Shape> {
    if let Some((cond, inner)) = quotient_condition_factor(expr) {
        if let Some(shape) = quotient_modarith7_affine_shape(Some(cond), &inner) {
            return Some(shape);
        }
    }
    quotient_modarith7_affine_shape(None, expr)
}

/// Split `cond * inner` when `cond` is a literal memory load, moving any scalar
/// factor attached to `cond` into `inner`.
fn quotient_condition_factor(expr: &QuotientExpr) -> Option<(u16, QuotientExpr)> {
    let QuotientExpr::Mul(lhs, rhs) = expr else {
        return None;
    };

    if let Some((coeff, ptr)) = quotient_mem_term(lhs) {
        return Some((ptr, quotient_scaled_term_expr(coeff, rhs.as_ref().clone())));
    }
    if let Some((coeff, ptr)) = quotient_mem_term(rhs) {
        return Some((ptr, quotient_scaled_term_expr(coeff, lhs.as_ref().clone())));
    }
    None
}

fn quotient_modarith7_affine_shape(
    cond: Option<u16>,
    expr: &QuotientExpr,
) -> Option<QuotientModarith7Shape> {
    let mut terms = Vec::new();
    let mut constant = Fq::ZERO;
    if !collect_quotient_affine_terms(expr, Fq::ONE, &mut terms, &mut constant) {
        return None;
    }
    terms.retain(|(coeff, _)| *coeff != Fq::ZERO);

    let mut lin = Vec::new();
    let mut rows = Vec::new();
    let mut pairwise = Vec::new();

    loop {
        if let Some((shape, used)) = try_quotient_bilin7_pairwise_subshape(&terms) {
            if used.is_empty() {
                break;
            }
            if let QuotientLimbShape::Bilin7Pairwise {
                lhs_base,
                rhs_base,
                coeffs,
            } = shape
            {
                pairwise.push((lhs_base, rhs_base, coeffs));
            } else {
                unreachable!("pairwise recognizer returned non-pairwise shape");
            }
            remove_quotient_terms(&mut terms, &used);
            continue;
        }
        if let Some((shape, used)) = try_quotient_factored_bilin7_row_subshape(&terms) {
            if used.is_empty() {
                break;
            }
            if let QuotientLimbShape::Bilin7Row { lhs, terms } = shape {
                rows.push((lhs, terms));
            } else {
                unreachable!("factored row recognizer returned non-row shape");
            }
            remove_quotient_terms(&mut terms, &used);
            continue;
        }
        if let Some((shape, used)) = try_quotient_bilin7_row_subshape(&terms) {
            if used.is_empty() {
                break;
            }
            if let QuotientLimbShape::Bilin7Row { lhs, terms } = shape {
                rows.push((lhs, terms));
            } else {
                unreachable!("row recognizer returned non-row shape");
            }
            remove_quotient_terms(&mut terms, &used);
            continue;
        }
        if let Some((shape, used)) = try_quotient_lin7_subshape(&terms) {
            if used.is_empty() {
                break;
            }
            if let QuotientLimbShape::Lin7 { terms } = shape {
                lin.push(terms);
            } else {
                unreachable!("linear recognizer returned non-linear shape");
            }
            remove_quotient_terms(&mut terms, &used);
            continue;
        }
        break;
    }

    if lin.len() > u8::MAX as usize
        || rows.len() > u8::MAX as usize
        || pairwise.len() > u8::MAX as usize
    {
        return None;
    }

    let mut grouped_mem = Vec::<(u16, Fq)>::new();
    let mut grouped_products = Vec::<(u16, u16, Fq)>::new();
    for (coeff, term) in terms {
        if let Some((inner_coeff, ptr)) = quotient_mem_term(term) {
            add_grouped_limb_coeff(&mut grouped_mem, ptr, coeff * inner_coeff);
        } else if let Some((inner_coeff, lhs, rhs)) = quotient_product_mem_pair(term) {
            add_grouped_product_coeff(&mut grouped_products, lhs, rhs, coeff * inner_coeff);
        } else if add_factored_affine_product_terms(
            &mut grouped_mem,
            &mut grouped_products,
            coeff,
            term,
        )
        .is_none()
        {
            return None;
        }
    }
    grouped_mem.retain(|(_, coeff)| *coeff != Fq::ZERO);
    grouped_mem.sort_by_key(|(ptr, _)| *ptr);
    grouped_products.retain(|(_, _, coeff)| *coeff != Fq::ZERO);
    grouped_products.sort_by_key(|(lhs, rhs, _)| (*lhs, *rhs));
    if grouped_mem.len() > u8::MAX as usize || grouped_products.len() > u8::MAX as usize {
        return None;
    }

    let nonzero_constant = usize::from(constant != Fq::ZERO);
    let component_count = lin.len()
        + rows.len()
        + pairwise.len()
        + grouped_mem.len()
        + grouped_products.len()
        + nonzero_constant;
    if component_count == 0 {
        return None;
    }
    let has_limb_component = !lin.is_empty() || !rows.is_empty() || !pairwise.is_empty();
    let has_sparse_conditional_products =
        cond.is_some() && !grouped_products.is_empty() && component_count >= 2;
    if !has_limb_component && !has_sparse_conditional_products {
        return None;
    }
    if cond.is_none() && component_count < 2 {
        return None;
    }

    Some(QuotientModarith7Shape {
        cond,
        constant: quotient_fq_to_u256(constant),
        lin,
        rows,
        pairwise,
        mem_terms: grouped_mem
            .into_iter()
            .map(|(ptr, coeff)| (quotient_fq_to_u256(coeff), ptr))
            .collect(),
        product_terms: grouped_products
            .into_iter()
            .map(|(lhs, rhs, coeff)| (quotient_fq_to_u256(coeff), lhs, rhs))
            .collect(),
    })
}

fn remove_quotient_terms<'a>(terms: &mut Vec<(Fq, &'a QuotientExpr)>, used: &[usize]) {
    let used = used.iter().copied().collect::<HashSet<_>>();
    let mut idx = 0usize;
    terms.retain(|_| {
        let keep = !used.contains(&idx);
        idx += 1;
        keep
    });
}

fn add_grouped_product_coeff(grouped: &mut Vec<(u16, u16, Fq)>, lhs: u16, rhs: u16, coeff: Fq) {
    let (lhs, rhs) = if lhs <= rhs { (lhs, rhs) } else { (rhs, lhs) };
    if let Some((_, _, existing)) = grouped
        .iter_mut()
        .find(|(existing_lhs, existing_rhs, _)| *existing_lhs == lhs && *existing_rhs == rhs)
    {
        *existing += coeff;
    } else {
        grouped.push((lhs, rhs, coeff));
    }
}

fn add_factored_affine_product_terms(
    grouped_mem: &mut Vec<(u16, Fq)>,
    grouped_products: &mut Vec<(u16, u16, Fq)>,
    term_coeff: Fq,
    expr: &QuotientExpr,
) -> Option<()> {
    let mut factors = Vec::new();
    collect_product_expr_factors(expr, &mut factors);
    if factors.len() < 2 {
        return None;
    }

    let mut coeff = term_coeff;
    let mut lhs = None;
    let mut affine_expr = None;
    for factor in factors {
        match factor {
            QuotientExpr::Const(value) => coeff *= quotient_fq_from_u256(*value)?,
            QuotientExpr::Mem(QuotientMem::Literal(ptr)) => {
                if lhs.replace(u16::try_from(*ptr).ok()?).is_some() {
                    return None;
                }
            }
            QuotientExpr::Mem(QuotientMem::Token(_))
            | QuotientExpr::Mem(QuotientMem::TokenOffset(_, _)) => return None,
            QuotientExpr::Add(_, _) | QuotientExpr::Mul(_, _) | QuotientExpr::Neg(_) => {
                if affine_expr.replace(factor).is_some() {
                    return None;
                }
            }
        }
    }

    let lhs = lhs?;
    let affine_expr = affine_expr?;
    let mut terms = Vec::new();
    let mut constant = Fq::ZERO;
    if !collect_quotient_affine_terms(affine_expr, Fq::ONE, &mut terms, &mut constant) {
        return None;
    }
    if constant != Fq::ZERO {
        add_grouped_limb_coeff(grouped_mem, lhs, coeff * constant);
    }
    for (inner_coeff, term) in terms {
        let (mem_coeff, rhs) = quotient_mem_term(term)?;
        add_grouped_product_coeff(grouped_products, lhs, rhs, coeff * inner_coeff * mem_coeff);
    }
    Some(())
}

fn try_quotient_factored_bilin7_row_subshape(
    terms: &[(Fq, &QuotientExpr)],
) -> Option<(QuotientLimbShape, Vec<usize>)> {
    for (idx, (coeff, expr)) in terms.iter().enumerate() {
        if let Some(shape) = quotient_factored_bilin7_row_shape(*coeff, expr) {
            return Some((shape, vec![idx]));
        }
    }
    None
}

fn quotient_factored_bilin7_row_shape(
    term_coeff: Fq,
    expr: &QuotientExpr,
) -> Option<QuotientLimbShape> {
    let mut factors = Vec::new();
    collect_product_expr_factors(expr, &mut factors);
    if factors.len() < 2 {
        return None;
    }

    let mut coeff = term_coeff;
    let mut lhs = None;
    let mut lin_expr = None;
    for factor in factors {
        match factor {
            QuotientExpr::Const(value) => coeff *= quotient_fq_from_u256(*value)?,
            QuotientExpr::Mem(QuotientMem::Literal(ptr)) => {
                if lhs.replace(u16::try_from(*ptr).ok()?).is_some() {
                    return None;
                }
            }
            QuotientExpr::Mem(QuotientMem::Token(_))
            | QuotientExpr::Mem(QuotientMem::TokenOffset(_, _)) => return None,
            QuotientExpr::Add(_, _) | QuotientExpr::Mul(_, _) | QuotientExpr::Neg(_) => {
                if lin_expr.replace(factor).is_some() {
                    return None;
                }
            }
        }
    }

    let lhs = lhs?;
    let lin_expr = lin_expr?;
    let mut lin_terms = Vec::new();
    if !collect_quotient_sum_terms(lin_expr, coeff, &mut lin_terms) {
        return None;
    }
    match try_quotient_lin7_shape(&lin_terms)? {
        QuotientLimbShape::Lin7 { terms } => Some(QuotientLimbShape::Bilin7Row { lhs, terms }),
        QuotientLimbShape::Bilin7Row { .. } | QuotientLimbShape::Bilin7Pairwise { .. } => None,
    }
}

fn modarith7_coeffs(shape: &QuotientModarith7Shape) -> Vec<U256> {
    let mut coeffs = Vec::new();
    if shape.constant != U256::ZERO {
        coeffs.push(shape.constant);
    }
    for terms in &shape.lin {
        coeffs.extend(terms.iter().map(|(coeff, _)| *coeff));
    }
    for (_, terms) in &shape.rows {
        coeffs.extend(terms.iter().map(|(coeff, _)| *coeff));
    }
    for (_, _, terms) in &shape.pairwise {
        coeffs.extend(terms.iter().copied());
    }
    coeffs.extend(shape.mem_terms.iter().map(|(coeff, _)| *coeff));
    coeffs.extend(shape.product_terms.iter().map(|(coeff, _, _)| *coeff));
    coeffs
}

/// Collect additive terms for subshape extraction, preserving constants as the
/// residue instead of rejecting the whole affine identity.
fn collect_quotient_affine_terms<'a>(
    expr: &'a QuotientExpr,
    coeff: Fq,
    terms: &mut Vec<(Fq, &'a QuotientExpr)>,
    constant: &mut Fq,
) -> bool {
    if coeff == Fq::ZERO {
        return true;
    }

    match expr {
        QuotientExpr::Add(lhs, rhs) => {
            collect_quotient_affine_terms(lhs, coeff, terms, constant)
                && collect_quotient_affine_terms(rhs, coeff, terms, constant)
        }
        QuotientExpr::Neg(inner) => collect_quotient_affine_terms(inner, -coeff, terms, constant),
        QuotientExpr::Mul(lhs, rhs) => {
            if let QuotientExpr::Const(value) = lhs.as_ref() {
                let Some(value) = quotient_fq_from_u256(*value) else {
                    return false;
                };
                collect_quotient_affine_terms(rhs, coeff * value, terms, constant)
            } else if let QuotientExpr::Const(value) = rhs.as_ref() {
                let Some(value) = quotient_fq_from_u256(*value) else {
                    return false;
                };
                collect_quotient_affine_terms(lhs, coeff * value, terms, constant)
            } else {
                terms.push((coeff, expr));
                true
            }
        }
        QuotientExpr::Const(value) => {
            let Some(value) = quotient_fq_from_u256(*value) else {
                return false;
            };
            *constant += coeff * value;
            true
        }
        QuotientExpr::Mem(_) => {
            terms.push((coeff, expr));
            true
        }
    }
}

/// Collect additive terms as `(coefficient, expression)` pairs over Fr.
///
/// Constant-only terms must reduce to zero for a limb shape to match; non-zero
/// standalone constants would require an additional VM add and therefore are
/// left to the generic emitter.
pub(super) fn collect_quotient_sum_terms<'a>(
    expr: &'a QuotientExpr,
    coeff: Fq,
    terms: &mut Vec<(Fq, &'a QuotientExpr)>,
) -> bool {
    if coeff == Fq::ZERO {
        return true;
    }

    match expr {
        QuotientExpr::Add(lhs, rhs) => {
            collect_quotient_sum_terms(lhs, coeff, terms)
                && collect_quotient_sum_terms(rhs, coeff, terms)
        }
        QuotientExpr::Neg(inner) => collect_quotient_sum_terms(inner, -coeff, terms),
        QuotientExpr::Mul(lhs, rhs) => {
            if let QuotientExpr::Const(value) = lhs.as_ref() {
                let Some(value) = quotient_fq_from_u256(*value) else {
                    return false;
                };
                collect_quotient_sum_terms(rhs, coeff * value, terms)
            } else if let QuotientExpr::Const(value) = rhs.as_ref() {
                let Some(value) = quotient_fq_from_u256(*value) else {
                    return false;
                };
                collect_quotient_sum_terms(lhs, coeff * value, terms)
            } else {
                terms.push((coeff, expr));
                true
            }
        }
        QuotientExpr::Const(value) => {
            let Some(value) = quotient_fq_from_u256(*value) else {
                return false;
            };
            coeff * value == Fq::ZERO
        }
        QuotientExpr::Mem(_) => {
            terms.push((coeff, expr));
            true
        }
    }
}

/// Recognize a seven-limb linear combination.
///
/// The resulting terms are sorted by memory pointer so equivalent expressions
/// have deterministic bytecode even when the source expression tree orders
/// additions differently.
pub(super) fn try_quotient_lin7_shape(terms: &[(Fq, &QuotientExpr)]) -> Option<QuotientLimbShape> {
    // Matches:
    //   circuits/src/field/foreign/gates/norm.rs
    //     sum_exprs(base_powers, shifted_x) - sum_exprs(base_powers, zs)
    //   circuits/src/field/foreign/gates/mul.rs
    //     sum_exprs(base_powers, xs/ys/zs)
    // and the same base-power sums reused by ECC foreign gates.
    let mut grouped = Vec::<(u16, Fq)>::new();
    for (coeff, expr) in terms {
        let (inner_coeff, ptr) = quotient_mem_term(expr)?;
        add_grouped_limb_coeff(&mut grouped, ptr, *coeff * inner_coeff);
    }
    grouped.retain(|(_, coeff)| *coeff != Fq::ZERO);
    if grouped.len() != QUOTIENT_VM_LIMBS {
        return None;
    }
    grouped.sort_by_key(|(ptr, _)| *ptr);
    Some(QuotientLimbShape::Lin7 {
        terms: grouped
            .into_iter()
            .map(|(ptr, coeff)| (quotient_fq_to_u256(coeff), ptr))
            .collect(),
    })
}

/// Recognize one limb multiplied across a seven-limb vector.
///
/// The recognizer tries both sides of the first pair as the repeated limb so it
/// is insensitive to multiplication commutativity in the lowered expression.
pub(super) fn try_quotient_bilin7_row_shape(
    terms: &[(Fq, &QuotientExpr)],
) -> Option<QuotientLimbShape> {
    // Matches one fixed limb multiplied across a 7-limb vector. This is a
    // local slice of the `pair_wise_prod` formulas in:
    //   circuits/src/field/foreign/gates/mul.rs
    //   circuits/src/ecc/foreign/gates/{on_curve,slope,tangent,lambda_squared}.rs
    let mut pairs = Vec::with_capacity(terms.len());
    for (coeff, expr) in terms {
        let (inner_coeff, lhs, rhs) = quotient_product_mem_pair(expr)?;
        pairs.push((*coeff * inner_coeff, lhs, rhs));
    }
    if pairs.len() != QUOTIENT_VM_LIMBS {
        return None;
    }

    for candidate in [pairs[0].1, pairs[0].2] {
        let mut grouped = Vec::<(u16, Fq)>::new();
        let mut ok = true;
        for (coeff, lhs, rhs) in &pairs {
            let other = if *lhs == candidate {
                *rhs
            } else if *rhs == candidate {
                *lhs
            } else {
                ok = false;
                break;
            };
            add_grouped_limb_coeff(&mut grouped, other, *coeff);
        }
        grouped.retain(|(_, coeff)| *coeff != Fq::ZERO);
        if ok && grouped.len() == QUOTIENT_VM_LIMBS {
            grouped.sort_by_key(|(ptr, _)| *ptr);
            return Some(QuotientLimbShape::Bilin7Row {
                lhs: candidate,
                terms: grouped
                    .into_iter()
                    .map(|(ptr, coeff)| (quotient_fq_to_u256(coeff), ptr))
                    .collect(),
            });
        }
    }

    None
}

/// Recognize a full seven-by-seven foreign-field product convolution.
///
/// The memory pointers must contain two contiguous seven-word limb vectors. For
/// each product term the coefficient is accumulated into its row-major slot and
/// then checked to depend only on `i + j`, exactly matching the
/// `double_base_powers` shape. If any slot is missing or coefficients disagree,
/// the shape is rejected and the generic VM remains the source of truth.
pub(super) fn try_quotient_bilin7_pairwise_shape(
    terms: &[(Fq, &QuotientExpr)],
) -> Option<QuotientLimbShape> {
    // Matches the full foreign-field product convolution:
    //   sum_exprs(double_base_powers, pair_wise_prod(lhs, rhs))
    // where double_base_powers[k] = base^k mod m. The Rust helper
    // pair_wise_prod emits 49 terms in row-major order; after collection we
    // require coefficients with the same i+j to agree, exactly the
    // base^(i+j) pattern documented in foreign/params.rs.
    let mut pairs = Vec::with_capacity(terms.len());
    let mut ptrs = HashSet::new();
    for (coeff, expr) in terms {
        let (inner_coeff, lhs, rhs) = quotient_product_mem_pair(expr)?;
        pairs.push((*coeff * inner_coeff, lhs, rhs));
        ptrs.insert(lhs);
        ptrs.insert(rhs);
    }
    if pairs.len() != QUOTIENT_VM_PAIRWISE_TERMS {
        return None;
    }

    let bases = limb7_base_candidates(&ptrs);
    for lhs_base in &bases {
        for rhs_base in &bases {
            let mut coeffs = vec![Fq::ZERO; QUOTIENT_VM_PAIRWISE_TERMS];
            let mut seen = vec![false; QUOTIENT_VM_PAIRWISE_TERMS];
            let mut ok = true;

            for (coeff, lhs, rhs) in &pairs {
                let direct = limb7_index(*lhs_base, *lhs).zip(limb7_index(*rhs_base, *rhs));
                let swapped = limb7_index(*lhs_base, *rhs).zip(limb7_index(*rhs_base, *lhs));
                let Some((i, j)) = direct.or(swapped) else {
                    ok = false;
                    break;
                };
                let idx = i * QUOTIENT_VM_LIMBS + j;
                coeffs[idx] += *coeff;
                seen[idx] = true;
            }

            if !ok || seen.iter().any(|seen| !seen) {
                continue;
            }

            let mut by_sum = vec![None; QUOTIENT_VM_PAIRWISE_COEFFS];
            for i in 0..QUOTIENT_VM_LIMBS {
                for j in 0..QUOTIENT_VM_LIMBS {
                    let coeff = coeffs[i * QUOTIENT_VM_LIMBS + j];
                    let slot = &mut by_sum[i + j];
                    if let Some(expected) = slot {
                        if *expected != coeff {
                            ok = false;
                            break;
                        }
                    } else {
                        *slot = Some(coeff);
                    }
                }
                if !ok {
                    break;
                }
            }

            if ok {
                return Some(QuotientLimbShape::Bilin7Pairwise {
                    lhs_base: *lhs_base,
                    rhs_base: *rhs_base,
                    coeffs: by_sum
                        .into_iter()
                        .map(|coeff| quotient_fq_to_u256(coeff.expect("pairwise sum coefficient")))
                        .collect(),
                });
            }
        }
    }

    None
}

fn try_quotient_lin7_subshape(
    terms: &[(Fq, &QuotientExpr)],
) -> Option<(QuotientLimbShape, Vec<usize>)> {
    let mut mem_terms = Vec::<(usize, u16, Fq)>::new();
    for (idx, (coeff, expr)) in terms.iter().enumerate() {
        if let Some((inner_coeff, ptr)) = quotient_mem_term(expr) {
            mem_terms.push((idx, ptr, *coeff * inner_coeff));
        }
    }

    let ptrs = mem_terms
        .iter()
        .map(|(_, ptr, _)| *ptr)
        .collect::<HashSet<_>>();
    for base in limb7_base_candidates(&ptrs) {
        let mut grouped = Vec::<(u16, Fq)>::new();
        let mut used = Vec::with_capacity(QUOTIENT_VM_LIMBS);
        for limb in 0..QUOTIENT_VM_LIMBS {
            let ptr = base + (limb as u16) * WORD_BYTES as u16;
            let mut coeff = Fq::ZERO;
            let mut found = false;
            for (idx, term_ptr, term_coeff) in &mem_terms {
                if *term_ptr == ptr {
                    coeff += *term_coeff;
                    used.push(*idx);
                    found = true;
                }
            }
            if !found {
                used.clear();
                break;
            }
            grouped.push((ptr, coeff));
        }
        grouped.retain(|(_, coeff)| *coeff != Fq::ZERO);
        if grouped.len() == QUOTIENT_VM_LIMBS && used.len() >= QUOTIENT_VM_LIMBS {
            grouped.sort_by_key(|(ptr, _)| *ptr);
            return Some((
                QuotientLimbShape::Lin7 {
                    terms: grouped
                        .into_iter()
                        .map(|(ptr, coeff)| (quotient_fq_to_u256(coeff), ptr))
                        .collect(),
                },
                used,
            ));
        }
    }
    None
}

fn try_quotient_bilin7_row_subshape(
    terms: &[(Fq, &QuotientExpr)],
) -> Option<(QuotientLimbShape, Vec<usize>)> {
    let mut pairs = Vec::<(usize, Fq, u16, u16)>::new();
    let mut ptrs = HashSet::new();
    for (idx, (coeff, expr)) in terms.iter().enumerate() {
        if let Some((inner_coeff, lhs, rhs)) = quotient_product_mem_pair(expr) {
            pairs.push((idx, *coeff * inner_coeff, lhs, rhs));
            ptrs.insert(lhs);
            ptrs.insert(rhs);
        }
    }

    let mut candidates = ptrs.into_iter().collect::<Vec<_>>();
    candidates.sort_unstable();
    for candidate in candidates {
        let mut grouped = Vec::<(u16, Fq)>::new();
        let mut used = Vec::with_capacity(QUOTIENT_VM_LIMBS);
        for (idx, coeff, lhs, rhs) in &pairs {
            let other = if *lhs == candidate {
                Some(*rhs)
            } else if *rhs == candidate {
                Some(*lhs)
            } else {
                None
            };
            if let Some(other) = other {
                add_grouped_limb_coeff(&mut grouped, other, *coeff);
                used.push(*idx);
            }
        }
        grouped.retain(|(_, coeff)| *coeff != Fq::ZERO);
        if grouped.len() == QUOTIENT_VM_LIMBS && used.len() >= QUOTIENT_VM_LIMBS {
            grouped.sort_by_key(|(ptr, _)| *ptr);
            return Some((
                QuotientLimbShape::Bilin7Row {
                    lhs: candidate,
                    terms: grouped
                        .into_iter()
                        .map(|(ptr, coeff)| (quotient_fq_to_u256(coeff), ptr))
                        .collect(),
                },
                used,
            ));
        }
    }
    None
}

fn try_quotient_bilin7_pairwise_subshape(
    terms: &[(Fq, &QuotientExpr)],
) -> Option<(QuotientLimbShape, Vec<usize>)> {
    let mut pairs = Vec::<(usize, Fq, u16, u16)>::new();
    let mut ptrs = HashSet::new();
    for (idx, (coeff, expr)) in terms.iter().enumerate() {
        if let Some((inner_coeff, lhs, rhs)) = quotient_product_mem_pair(expr) {
            pairs.push((idx, *coeff * inner_coeff, lhs, rhs));
            ptrs.insert(lhs);
            ptrs.insert(rhs);
        }
    }

    let bases = limb7_base_candidates(&ptrs);
    for lhs_base in &bases {
        for rhs_base in &bases {
            let mut coeffs = vec![Fq::ZERO; QUOTIENT_VM_PAIRWISE_TERMS];
            let mut seen = vec![false; QUOTIENT_VM_PAIRWISE_TERMS];
            let mut used = Vec::with_capacity(QUOTIENT_VM_PAIRWISE_TERMS);
            for (idx, coeff, lhs, rhs) in &pairs {
                let direct = limb7_index(*lhs_base, *lhs).zip(limb7_index(*rhs_base, *rhs));
                let swapped = limb7_index(*lhs_base, *rhs).zip(limb7_index(*rhs_base, *lhs));
                let Some((i, j)) = direct.or(swapped) else {
                    continue;
                };
                let term_idx = i * QUOTIENT_VM_LIMBS + j;
                coeffs[term_idx] += *coeff;
                seen[term_idx] = true;
                used.push(*idx);
            }
            if seen.iter().any(|seen| !seen) {
                continue;
            }

            let mut by_sum = vec![None; QUOTIENT_VM_PAIRWISE_COEFFS];
            let mut ok = true;
            for i in 0..QUOTIENT_VM_LIMBS {
                for j in 0..QUOTIENT_VM_LIMBS {
                    let coeff = coeffs[i * QUOTIENT_VM_LIMBS + j];
                    let slot = &mut by_sum[i + j];
                    if let Some(expected) = slot {
                        if *expected != coeff {
                            ok = false;
                            break;
                        }
                    } else {
                        *slot = Some(coeff);
                    }
                }
                if !ok {
                    break;
                }
            }
            if ok && used.len() >= QUOTIENT_VM_PAIRWISE_TERMS {
                return Some((
                    QuotientLimbShape::Bilin7Pairwise {
                        lhs_base: *lhs_base,
                        rhs_base: *rhs_base,
                        coeffs: by_sum
                            .into_iter()
                            .map(|coeff| {
                                quotient_fq_to_u256(coeff.expect("pairwise sum coefficient"))
                            })
                            .collect(),
                    },
                    used,
                ));
            }
        }
    }
    None
}

/// Return `(coefficient, ptr)` for a product with exactly one memory factor.
pub(super) fn quotient_mem_term(expr: &QuotientExpr) -> Option<(Fq, u16)> {
    let (coeff, ptrs) = quotient_product_mem_factors(expr)?;
    if ptrs.len() == 1 {
        Some((coeff, ptrs[0]))
    } else {
        None
    }
}

/// Return `(coefficient, lhs_ptr, rhs_ptr)` for a product with two memory factors.
pub(super) fn quotient_product_mem_pair(expr: &QuotientExpr) -> Option<(Fq, u16, u16)> {
    let (coeff, ptrs) = quotient_product_mem_factors(expr)?;
    if ptrs.len() == 2 {
        Some((coeff, ptrs[0], ptrs[1]))
    } else {
        None
    }
}

/// Factor a product into its Fr coefficient and literal memory pointers.
///
/// Token memory references are rejected because limb opcodes and fused product
/// forms store compact literal `u16` pointers.
pub(super) fn quotient_product_mem_factors(expr: &QuotientExpr) -> Option<(Fq, Vec<u16>)> {
    let mut leaves = Vec::new();
    if !collect_product_leaves(expr, &mut leaves) {
        return None;
    }

    let mut coeff = Fq::ONE;
    let mut ptrs = Vec::new();
    for leaf in leaves {
        match leaf {
            QuotientLeaf::Const(value) => coeff *= quotient_fq_from_u256(value)?,
            QuotientLeaf::Mem(QuotientMem::Literal(ptr)) => ptrs.push(u16::try_from(ptr).ok()?),
            QuotientLeaf::Mem(QuotientMem::Token(_))
            | QuotientLeaf::Mem(QuotientMem::TokenOffset(_, _)) => return None,
        }
    }
    Some((coeff, ptrs))
}

/// Add a coefficient into a grouped limb term.
pub(super) fn add_grouped_limb_coeff(grouped: &mut Vec<(u16, Fq)>, ptr: u16, coeff: Fq) {
    if let Some((_, existing)) = grouped.iter_mut().find(|(existing, _)| *existing == ptr) {
        *existing += coeff;
    } else {
        grouped.push((ptr, coeff));
    }
}

/// Find all base pointers that cover a contiguous seven-limb vector.
pub(super) fn limb7_base_candidates(ptrs: &HashSet<u16>) -> Vec<u16> {
    let mut bases = ptrs
        .iter()
        .copied()
        .filter(|base| {
            (0..QUOTIENT_VM_LIMBS).all(|idx| {
                base.checked_add((idx * layout::WORD_BYTES) as u16)
                    .is_some_and(|ptr| ptrs.contains(&ptr))
            })
        })
        .collect::<Vec<_>>();
    bases.sort_unstable();
    bases.dedup();
    bases
}

/// Return the limb index of `ptr` relative to `base`, if it is in the vector.
pub(super) fn limb7_index(base: u16, ptr: u16) -> Option<usize> {
    let diff = ptr.checked_sub(base)?;
    let word_bytes = layout::WORD_BYTES as u16;
    if diff % word_bytes != 0 {
        return None;
    }
    let idx = (diff / word_bytes) as usize;
    (idx < QUOTIENT_VM_LIMBS).then_some(idx)
}

/// Interpret a `U256` as a canonical BLS12-381 scalar field element.
///
/// Values outside the field modulus are rejected; that is important when
/// folding parsed Yul literals back into Fr coefficients for shape recognition.
pub(super) fn quotient_fq_from_u256(value: U256) -> Option<Fq> {
    let bytes = value.to_le_bytes::<32>();
    let repr = <Fq as PrimeField>::Repr::from(bytes);
    Option::<Fq>::from(Fq::from_repr(repr))
}

/// Encode a BLS12-381 scalar field element as a `U256`.
pub(super) fn quotient_fq_to_u256(value: Fq) -> U256 {
    fe_to_u256::<Fq>(&value)
}

/// Parse a generated Yul memory pointer expression into a VM memory reference.
pub(super) fn parse_mem(ptr: &str) -> QuotientMem {
    let ptr = ptr.trim();
    if let Some(value) = parse_u32_literal(ptr) {
        QuotientMem::Literal(value)
    } else if let Some(token) = mem_token(ptr) {
        QuotientMem::Token(token)
    } else if let Some(args) = call_args(ptr, "add") {
        assert_eq!(args.len(), 2, "add pointer arity");
        let token = mem_token(args[0].trim())
            .unwrap_or_else(|| panic!("unsupported quotient mload base: {}", args[0]));
        let offset = parse_u32_literal(args[1].trim())
            .unwrap_or_else(|| panic!("unsupported quotient mload offset: {}", args[1]));
        QuotientMem::TokenOffset(token, offset)
    } else {
        panic!("unsupported quotient mload pointer: {ptr}");
    }
}

/// Return whether a string is a decimal or hexadecimal integer literal.
pub(super) fn is_literal(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("0x")
        || value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit())
}

/// Parse a decimal or hexadecimal `U256` literal.
pub(super) fn parse_u256(value: &str) -> U256 {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        U256::from_str_radix(hex, 16)
            .unwrap_or_else(|err| panic!("valid hex U256 `{value}`: {err:?}"))
    } else {
        U256::from_str_radix(value, 10)
            .unwrap_or_else(|err| panic!("valid decimal U256 `{value}`: {err:?}"))
    }
}

/// Render a `U256` as the shortest stable hexadecimal Yul literal.
pub(super) fn u256_string(value: U256) -> String {
    if value.bit_len() < 64 {
        format!("0x{:x}", value.as_limbs()[0])
    } else {
        format!("0x{value:x}")
    }
}

/// Render BLS12-381 Fr `DELTA` for legacy/direct Yul paths.
pub(super) fn fr_delta_literal() -> String {
    u256_string(fe_to_u256::<Fq>(&Fq::DELTA))
}

/// Parse a literal if it fits in `u32`.
pub(super) fn parse_u32_literal(value: &str) -> Option<u32> {
    if !is_literal(value) {
        return None;
    }
    let parsed = parse_u256(value);
    parsed.try_into().ok()
}

/// Parse a literal if it fits in `usize`.
pub(super) fn parse_usize_literal(value: &str) -> Option<usize> {
    if !is_literal(value) {
        return None;
    }
    let parsed = parse_u256(value);
    parsed.try_into().ok()
}

/// Resolve a generated Yul memory symbol to a VM token.
pub(super) fn mem_token(name: &str) -> Option<u8> {
    quotient_mem_token_from_name(name)
}

/// Parsed form of the simple Yul assignments emitted by `Evaluator`.
///
/// The parser is deliberately shallow. It is not a Yul parser; it accepts only
/// assignment syntax that this generator emits, which makes unsupported changes
/// fail loudly during code generation instead of silently changing verifier
/// semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct YulAssignment {
    /// Destination variable name.
    pub(super) dst: String,
    /// Right-hand expression as source text.
    pub(super) expr: String,
    /// Whether the assignment was introduced with `let`.
    pub(super) has_let: bool,
}

/// Parse a generated Yul assignment line.
pub(super) fn yul_assignment(line: &str) -> Option<YulAssignment> {
    let line = line.trim();
    let (has_let, rest) = if let Some(rest) = line.strip_prefix("let") {
        if !rest.starts_with(char::is_whitespace) {
            return None;
        }
        (true, rest.trim_start())
    } else {
        (false, line)
    };
    let (dst, expr) = rest.split_once(":=")?;
    let dst = dst.trim();
    let expr = expr.trim();
    if dst.is_empty() || expr.is_empty() {
        return None;
    }
    Some(YulAssignment {
        dst: dst.to_string(),
        expr: expr.to_string(),
        has_let,
    })
}

/// Parse a generated `let dst := expr` assignment.
pub(super) fn yul_let_assignment(line: &str) -> Option<(String, String)> {
    let assignment = yul_assignment(line)?;
    assignment
        .has_let
        .then_some((assignment.dst, assignment.expr))
}

/// Resolve a literal or previously bound constant variable to canonical text.
pub(super) fn yul_const_value(value: &str, const_vars: &HashMap<String, String>) -> Option<String> {
    let value = value.trim();
    if is_literal(value) {
        Some(u256_string(parse_u256(value)))
    } else {
        const_vars.get(value).cloned()
    }
}

/// Parse `let dst := mulmod(lhs, rhs, r)`.
pub(super) fn yul_mulmod_assignment(line: &str) -> Option<(String, String, String)> {
    let (dst, expr) = yul_let_assignment(line)?;
    let args = call_args(&expr, "mulmod")?;
    if args.len() == 3 && args[2].trim() == "r" {
        Some((dst, args[0].trim().to_string(), args[1].trim().to_string()))
    } else {
        None
    }
}

/// Parse `let dst := addmod(lhs, rhs, r)`.
pub(super) fn yul_addmod_assignment(line: &str) -> Option<(String, String, String)> {
    let (dst, expr) = yul_let_assignment(line)?;
    let args = call_args(&expr, "addmod")?;
    if args.len() == 3 && args[2].trim() == "r" {
        Some((dst, args[0].trim().to_string(), args[1].trim().to_string()))
    } else {
        None
    }
}

/// Parse `let dst := mload(literal_ptr)`.
pub(super) fn yul_mload_literal_assignment(line: &str) -> Option<(String, usize)> {
    let (dst, expr) = yul_let_assignment(line)?;
    Some((dst, yul_mload_literal_expr(&expr)?))
}

/// Parse `mload(literal_ptr)`.
pub(super) fn yul_mload_literal_expr(expr: &str) -> Option<usize> {
    let args = call_args(expr.trim(), "mload")?;
    if args.len() == 1 {
        parse_usize_literal(args[0].trim())
    } else {
        None
    }
}

/// Parse `let dst := sub(r, value)`, the evaluator's negation form.
pub(super) fn yul_sub_r_assignment(line: &str) -> Option<(String, String)> {
    let (dst, expr) = yul_let_assignment(line)?;
    let args = call_args(&expr, "sub")?;
    if args.len() == 2 && args[0].trim() == "r" {
        Some((dst, args[1].trim().to_string()))
    } else {
        None
    }
}

/// Return top-level comma-separated call arguments for `name(...)`.
pub(super) fn call_args(expr: &str, name: &str) -> Option<Vec<String>> {
    let expr = expr.trim();
    let rest = expr.strip_prefix(name)?.trim_start();
    let rest = rest.strip_prefix('(')?;
    if !rest.ends_with(')') {
        return None;
    }
    Some(split_top_level(&rest[..rest.len() - 1]))
}

/// Split a comma-separated argument list while respecting nested calls.
pub(super) fn split_top_level(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (idx, ch) in input.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.checked_sub(1).expect("balanced quotient expression"),
            ',' if depth == 0 => {
                args.push(input[start..idx].trim().to_string());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    args.push(input[start..].trim().to_string());
    args
}
