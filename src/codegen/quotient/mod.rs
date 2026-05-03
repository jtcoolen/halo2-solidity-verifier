use super::*;

// Producer-side definition of the compact quotient VM.
//
// `partially_evaluate_identities` still decides the actual Halo2 identities;
// this module only changes the representation used by generated Solidity.
// The Rust builder below lowers those identities into a VK-resident bytecode
// stream, and `templates/QuotientNumeratorBlock.yul` interprets that stream at
// verification time. Any opcode, operand, memory-token, or fold-order change
// must therefore be made in lockstep across this module, the Yul template, the
// spec docs, and the VM tests.
#[derive(Clone, Copy, Debug)]
pub(super) enum QuotientTarget {
    // Fully evaluated identity. Its value contributes to the scalar stored in
    // QUOTIENT_EVAL_MPTR after the final negation.
    Main,
    // Simple-selector identity. Its value is accumulated into the matching
    // selector commitment bucket while still advancing the global y-batch.
    Selector(usize),
}

// Complete artifact produced by `QuotientProgramBuilder` and consumed by the
// generator memory planner plus the Yul VM template.
#[derive(Debug)]
pub(super) struct QuotientProgramBuild {
    // Encoded bytecode. This is either byte-oriented or packed32, depending on
    // `packed32`.
    pub(super) bytes: Vec<u8>,
    // Deduplicated Fr constants addressed by PUSH_CONST and fused opcodes.
    pub(super) consts: Vec<U256>,
    // Maximum operand-stack depth of the pure interpreted bytecode. The
    // generator folds native-callback scratch into the allocated stack region
    // when such callbacks share the same base pointer.
    pub(super) max_stack: usize,
    pub(super) packed32: bool,
    // Number of temporary words addressed by PUSH_TEMP/STORE_TEMP when VM CSE
    // is enabled. State slots live immediately after these words.
    pub(super) cse_temps: usize,
}

// One Halo2 quotient identity after the normal evaluator has emitted its Yul
// assignment lines. `expr` is the parsed form used by the compact VM; `lines`
// and `var` remain available for native/direct Yul paths.
#[derive(Clone, Debug)]
pub(super) struct QuotientIdentity {
    pub(super) lines: Vec<String>,
    pub(super) var: String,
    pub(super) target: QuotientTarget,
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
    pub(crate) g1_groups: Vec<usize>,
    pub(crate) num_evals: usize,
    pub(crate) num_point_sets: usize,
}

impl RepackedProofLayoutPlan {
    pub(crate) fn from_proof_layout(
        layout: &crate::codegen::proof_layout::ProofCalldataLayout,
    ) -> Self {
        Self {
            g1_groups: layout.commitment_read_groups(),
            num_evals: layout.evals.item_count,
            num_point_sets: layout.q_evals.item_count,
        }
    }

    pub(crate) fn prefix_g1_count(&self) -> usize {
        self.g1_groups.iter().sum()
    }

    pub(crate) fn compressed_len(&self) -> usize {
        self.prefix_g1_count() * crate::codegen::layout::G1_COMPRESSED_BYTES
            + self.num_evals * crate::codegen::layout::WORD_BYTES
            + crate::codegen::layout::G1_COMPRESSED_BYTES
            + self.num_point_sets * crate::codegen::layout::WORD_BYTES
            + crate::codegen::layout::G1_COMPRESSED_BYTES
    }

    pub(crate) fn repacked_len(&self) -> usize {
        self.prefix_g1_count() * crate::codegen::layout::G1_BYTES
            + self.num_evals * crate::codegen::layout::WORD_BYTES
            + crate::codegen::layout::G1_BYTES
            + self.num_point_sets * crate::codegen::layout::WORD_BYTES
            + crate::codegen::layout::G1_BYTES
    }

    #[cfg(test)]
    #[allow(dead_code)]
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
    pub(super) gates: Vec<QuotientIdentity>,
    pub(super) permutation: Vec<QuotientIdentity>,
    pub(super) lookup: Vec<QuotientIdentity>,
    pub(super) trash: Vec<QuotientIdentity>,
    pub(super) sorted_simple: Vec<usize>,
}

impl QuotientIdentityParts {
    pub(super) fn all_identities(&self) -> Vec<QuotientIdentity> {
        self.gates
            .iter()
            .chain(self.permutation.iter())
            .chain(self.lookup.iter())
            .chain(self.trash.iter())
            .cloned()
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuotientStructuredTailMode {
    Off,
    Trash,
}

// Logical stream item before final bytecode lowering. Native items are markers
// in the same identity order as interpreted items; the template replaces them
// with generated Yul callbacks at runtime.
#[derive(Clone, Debug)]
pub(super) enum QuotientProgramItem {
    Identity(QuotientIdentity),
    NativePermutation,
    NativeIdentity(usize),
}

// Hybrid execution plan for quotient numerator reconstruction. A small prefix
// may stay inline, most identities become VM bytecode, and selected expensive
// shapes can become native callbacks while preserving the original y-order.
#[derive(Clone, Debug)]
pub(super) struct QuotientProgramPlan {
    pub(super) inline_identities: Vec<QuotientIdentity>,
    pub(super) items: Vec<QuotientProgramItem>,
    pub(super) native_identities: Vec<QuotientIdentity>,
    pub(super) sorted_simple: Vec<usize>,
    pub(super) has_native_permutation: bool,
}

pub(super) const QUOTIENT_EXTERNAL_MAGIC: u64 = 0x5155_4556_414c_0001;
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
    // Variable-length byte stream. This is the only encoding that supports the
    // limb-aware opcodes and run-compacted fused add-mul instructions.
    Bytes,
    // Four-byte instruction words: high byte opcode, low 24 bits operand.
    // Easier to decode in Yul, but not every opcode shape fits this format.
    Packed32,
}

pub(super) const QUOTIENT_VM_PACKED_INSTRUCTION_BYTES: usize = 4;
pub(super) const QUOTIENT_VM_PACKED_ARG_BITS: usize = 24;
pub(super) const QUOTIENT_VM_PACKED_ARG_MASK: u32 = 0x00ff_ffff;
pub(super) const QUOTIENT_VM_RUN_COMPACTION_MIN_LEN: usize = 4;
pub(super) const QUOTIENT_VM_BYTE_U16_BYTES: usize = 2;
pub(super) const QUOTIENT_VM_BYTE_U32_BYTES: usize = 4;
pub(super) const QUOTIENT_VM_LIMBS: usize = layout::quotient_limb::LIMBS;
pub(super) const QUOTIENT_VM_PAIRWISE_TERMS: usize = layout::quotient_limb::PAIRWISE_TERMS;
pub(super) const QUOTIENT_VM_PAIRWISE_COEFFS: usize = layout::quotient_limb::PAIRWISE_COEFFS;

// Opcode assignments are part of the verifier/VK ABI. Keep 0x1a reserved:
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

pub(super) const Q_MEM_L0: u8 = 0x01;
pub(super) const Q_MEM_L_LAST: u8 = 0x02;
pub(super) const Q_MEM_L_BLIND: u8 = 0x03;
pub(super) const Q_MEM_BETA: u8 = 0x04;
pub(super) const Q_MEM_GAMMA: u8 = 0x05;
pub(super) const Q_MEM_X: u8 = 0x06;
pub(super) const Q_MEM_THETA: u8 = 0x07;
pub(super) const Q_MEM_TRASH_CHALLENGE: u8 = 0x08;
pub(super) const Q_MEM_INSTANCE_EVAL: u8 = 0x09;

// Operand decoder classes shared by tests and docs. The Yul template is the
// runtime decoder; this table is the compile-time/spec view of the same ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuotientOpcodeEncoding {
    None,
    U8,
    U16,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuotientOpcodeSpec {
    pub(super) name: &'static str,
    pub(super) opcode: u8,
    pub(super) byte_len: usize,
    pub(super) encoding: QuotientOpcodeEncoding,
    pub(super) packed32: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuotientMemTokenSpec {
    pub(super) name: &'static str,
    pub(super) token: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuotientVmSpec {
    pub(super) opcodes: &'static [QuotientOpcodeSpec],
    pub(super) mem_tokens: &'static [QuotientMemTokenSpec],
    pub(super) packed_instruction_bytes: usize,
    pub(super) packed_arg_bits: usize,
    pub(super) packed_arg_mask: u32,
    pub(super) run_compaction_min_len: usize,
    pub(super) limb_count: usize,
    pub(super) limb_pairwise_terms: usize,
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
        byte_len: 1 + QUOTIENT_VM_BYTE_U16_BYTES,
        encoding: QuotientOpcodeEncoding::U16,
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

pub(super) fn quotient_opcode_spec(opcode: u8) -> Option<&'static QuotientOpcodeSpec> {
    QUOTIENT_VM_SPEC
        .opcodes
        .iter()
        .find(|spec| spec.opcode == opcode)
}

pub(super) fn quotient_opcode_byte_len(opcode: u8) -> Option<usize> {
    quotient_opcode_spec(opcode).and_then(|spec| (spec.byte_len != 0).then_some(spec.byte_len))
}

pub(super) fn scalar_le_to_be_word(bytes: &[u8]) -> [u8; 32] {
    assert_eq!(bytes.len(), 32, "scalar proof element must be 32 bytes");
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(bytes);
    scalar.reverse();
    scalar
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum QuotientExpr {
    Const(U256),
    Mem(QuotientMem),
    Add(Box<QuotientExpr>, Box<QuotientExpr>),
    Mul(Box<QuotientExpr>, Box<QuotientExpr>),
    Neg(Box<QuotientExpr>),
}

#[derive(Clone, Debug, Default)]
pub(super) struct QuotientShapeProfile {
    pub(super) lin7: usize,
    pub(super) bilin7_row: usize,
    pub(super) bilin7_pairwise: usize,
    pub(super) fallback_vm_ops: usize,
}

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

#[derive(Debug, Default)]
pub(super) struct QuotientCseState {
    // Expression key -> temp slot chosen before emission. Slots are stable
    // across the whole VM program, so repeated subexpressions can be shared
    // between identities rather than only within one identity.
    pub(super) slots: HashMap<String, u16>,
    // Expression key -> temp slot already materialized in bytecode. This
    // prevents recursive emit from generating the same STORE_TEMP repeatedly.
    pub(super) emitted: HashMap<String, u16>,
    // Expression keys whose STORE_TEMP has not yet been emitted. Used to
    // detect cyclic CSE expressions (impossible for the current tree-shaped
    // QuotientExpr, but mirrors the inline emitter's defensive check).
    pub(super) emitting: HashSet<String>,
}

impl QuotientCseState {
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
            emitting: HashSet::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum QuotientMem {
    Literal(u32),
    Token(u8),
    TokenOffset(u8, u32),
}

#[derive(Debug)]
pub(super) struct QuotientInlineCsePlan {
    pub(super) slots: HashMap<String, u16>,
    pub(super) exprs: HashMap<String, QuotientExpr>,
}

impl QuotientInlineCsePlan {
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

pub(super) struct QuotientInlineCseEmitter<'a> {
    pub(super) plan: &'a QuotientInlineCsePlan,
    pub(super) cse_mptr: usize,
    pub(super) helpers: bool,
    pub(super) emitted: HashSet<String>,
    pub(super) emitting: HashSet<String>,
    pub(super) next_var: usize,
}

impl<'a> QuotientInlineCseEmitter<'a> {
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

    pub(super) fn emit_identity(&mut self, expr: &QuotientExpr, out: &mut Vec<String>) -> String {
        self.emit_expr(expr, out, None)
    }

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

    fn cse_load(&self, key: &str) -> String {
        format!("mload({})", self.cse_ptr(key))
    }

    fn cse_ptr(&self, key: &str) -> String {
        let slot = self.plan.slots[key] as usize;
        format!("{:#x}", self.cse_mptr + slot * layout::WORD_BYTES)
    }

    fn fresh_var(&mut self) -> String {
        let var = format!("q_cse_var_{}", self.next_var);
        self.next_var += 1;
        var
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum QuotientLeaf {
    Const(U256),
    Mem(QuotientMem),
}

#[derive(Clone, Copy, Debug)]
pub(super) enum QuotientProductAdd {
    MemMemConstU8 { lhs: u16, rhs: u16, scalar: U256 },
    ConstU8Mem { scalar: U256, ptr: u16 },
    MemMem { lhs: u16, rhs: u16 },
}

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
    pub(super) fn with_limb_vm_ops(enabled: bool) -> Self {
        Self {
            limb_vm_ops: enabled,
            ..Default::default()
        }
    }

    pub(super) fn identity_expr(
        &mut self,
        expr: &QuotientExpr,
        target: QuotientTarget,
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
        self.fold_identity(target);

        assert_eq!(self.stack_depth, 0, "quotient VM stack leak");
    }

    fn fold_identity(&mut self, target: QuotientTarget) {
        // Mirrors the Rust `compute_linearization_commitment` y-batch:
        // every emitted identity is first absorbed into the same running
        // power of y, then either accumulated into the fully-evaluated
        // numerator or into the simple-selector bucket. Both fold variants
        // consume exactly one stack item and count toward the fallback-op
        // shape profile.
        self.record_fallback_vm_op();
        match target {
            QuotientTarget::Main => self.bytes.push(Q_OP_FOLD_MAIN),
            QuotientTarget::Selector(idx) => {
                self.bytes.push(Q_OP_FOLD_SELECTOR);
                self.u16(idx);
            }
        }
        self.pop_stack();
    }

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
        let profile = self.profile;
        if quotient_shape_profile_enabled() {
            eprintln!(
                "quotient shape profile: lin7={} bilin7_row={} bilin7_pairwise={} fallback_vm_ops={} raw_program_bytes={} compact_program_bytes={} consts={}",
                profile.lin7,
                profile.bilin7_row,
                profile.bilin7_pairwise,
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
        }
    }

    #[allow(dead_code)]
    pub(super) fn assignment(&mut self, line: &str) {
        let assignment = yul_assignment(line)
            .unwrap_or_else(|| panic!("unsupported quotient assignment: {}", line.trim()));
        let expr = self.parse_expr(&assignment.expr);
        self.vars.insert(assignment.dst, expr);
    }

    #[allow(dead_code)]
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

    pub(super) fn emit_expr(&mut self, expr: &QuotientExpr) {
        if self.try_emit_limb_shape(expr) {
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

    fn emit_expr_cse(&mut self, expr: &QuotientExpr, cse: &mut QuotientCseState) {
        let key = quotient_expr_key(expr);
        if let Some(slot) = cse.slots.get(&key).copied() {
            if cse.emitted.contains_key(&key) {
                self.bytes.push(Q_OP_PUSH_TEMP);
                self.u16(slot as usize);
                self.push_stack();
                return;
            }

            assert!(
                cse.emitting.insert(key.clone()),
                "cyclic quotient VM CSE expression"
            );
            self.emit_expr_cse_inner(expr, cse);
            cse.emitting.remove(&key);
            cse.emitted.insert(key, slot);
            self.bytes.push(Q_OP_STORE_TEMP);
            self.u16(slot as usize);
            return;
        }

        self.emit_expr_cse_inner(expr, cse);
    }

    fn emit_expr_cse_inner(&mut self, expr: &QuotientExpr, cse: &mut QuotientCseState) {
        if self.try_emit_limb_shape(expr) {
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

    fn op0(&mut self, op: u8) {
        self.record_fallback_vm_op();
        self.bytes.push(op);
    }

    fn op_binary(&mut self, op: u8) {
        self.record_fallback_vm_op();
        self.bytes.push(op);
        self.pop_stack();
    }

    fn record_fallback_vm_op(&mut self) {
        if self.limb_vm_ops {
            self.profile.fallback_vm_ops += 1;
        }
    }

    fn push_stack(&mut self) {
        self.stack_depth += 1;
        self.max_stack = self.max_stack.max(self.stack_depth);
    }

    fn pop_stack(&mut self) {
        self.stack_depth = self
            .stack_depth
            .checked_sub(1)
            .expect("quotient VM stack underflow");
    }

    fn u16(&mut self, value: usize) {
        assert!(value <= u16::MAX as usize, "quotient VM u16 overflow");
        self.bytes.extend_from_slice(&(value as u16).to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

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

    fn const_fits_u8_slot(&self, value: U256) -> bool {
        self.const_slots
            .get(&value)
            .is_some_and(|slot| u8::try_from(*slot).is_ok())
            || (!self.const_slots.contains_key(&value) && self.consts.len() <= u8::MAX as usize)
    }

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
            Q_OP_PUSH_CONST | Q_OP_FOLD_SELECTOR | Q_OP_ADD_CONST | Q_OP_MUL_CONST
            | Q_OP_PUSH_MEM_U16 | Q_OP_ADD_MEM_U16 | Q_OP_MUL_MEM_U16 | Q_OP_PUSH_TEMP
            | Q_OP_STORE_TEMP | Q_OP_NATIVE_IDENTITY => {
                push_packed_quotient_op(&mut out, op, read_u16(bytes, idx + 1) as u32);
                idx += 3;
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
            Q_OP_ADD | Q_OP_MUL | Q_OP_NEG | Q_OP_FOLD_MAIN | Q_OP_NATIVE_PERMUTATION => {
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
            Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8 | Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16 => {
                panic!("packed quotient VM expects un-compacted quotient op stream")
            }
            op => panic!("unknown quotient op {op:#x} at byte {idx}"),
        }
    }
    out
}

pub(super) fn quotient_program_uses_limb_ops(bytes: &[u8]) -> bool {
    // Limb opcodes are only ever emitted in the raw bytecode stream and
    // never appear inside a run-compacted block (run compaction only fuses
    // ADD_MUL_* fallback opcodes). The walk supports both pre- and
    // post-compaction streams so callers don't have to reason about the
    // ordering between compaction and limb-op detection.
    let mut idx = 0usize;
    while idx < bytes.len() {
        let op = bytes[idx];
        if matches!(op, Q_OP_LIN7 | Q_OP_BILIN7_ROW | Q_OP_BILIN7_PAIRWISE) {
            return true;
        }
        idx = match op {
            Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8 => {
                let count = read_u16(bytes, idx + 1) as usize;
                idx + 3 + count * 5
            }
            Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16 => {
                let count = read_u16(bytes, idx + 1) as usize;
                idx + 3 + count * 3
            }
            _ => idx + quotient_op_len(bytes, idx),
        };
    }
    false
}

pub(super) fn push_packed_quotient_op(out: &mut Vec<u8>, op: u8, arg: u32) {
    assert!(
        arg <= QUOTIENT_VM_SPEC.packed_arg_mask,
        "packed quotient VM operand exceeds 24 bits"
    );
    out.extend_from_slice(&(((op as u32) << 24) | arg).to_be_bytes());
}

pub(super) fn read_u16(bytes: &[u8], idx: usize) -> u16 {
    u16::from_be_bytes(
        bytes[idx..idx + 2]
            .try_into()
            .expect("u16 quotient operand"),
    )
}

pub(super) fn read_u32(bytes: &[u8], idx: usize) -> u32 {
    u32::from_be_bytes(
        bytes[idx..idx + 4]
            .try_into()
            .expect("u32 quotient operand"),
    )
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct QuotientProgramValidator;

impl QuotientProgramValidator {
    pub(super) fn validate(
        build: &QuotientProgramBuild,
        native_identity_count: usize,
        selector_count: usize,
    ) -> Result<(), String> {
        let mut state = QuotientProgramValidationState::default();
        if build.packed32 {
            Self::validate_packed32(build, native_identity_count, selector_count, &mut state)?;
        } else {
            Self::validate_bytes(build, native_identity_count, selector_count, &mut state)?;
        }
        if state.stack_depth != 0 {
            return Err(format!(
                "quotient VM stack leak: final depth={}",
                state.stack_depth
            ));
        }
        if state.max_stack != build.max_stack {
            return Err(format!(
                "quotient VM max-stack mismatch: validated={} build={}",
                state.max_stack, build.max_stack
            ));
        }
        Ok(())
    }

    fn validate_bytes(
        build: &QuotientProgramBuild,
        native_identity_count: usize,
        selector_count: usize,
        state: &mut QuotientProgramValidationState,
    ) -> Result<(), String> {
        let bytes = build.bytes.as_slice();
        let mut idx = 0usize;
        while idx < bytes.len() {
            let op = bytes[idx];
            match op {
                Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8 => {
                    let count = read_u16_checked(bytes, idx + 1, idx)? as usize;
                    if count == 0 {
                        return Err(format!("empty quotient VM run at byte {idx}"));
                    }
                    let len = 3 + count * 5;
                    check_bounds(bytes, idx, len)?;
                    for term in 0..count {
                        let term_idx = idx + 3 + term * 5;
                        let scalar = bytes[term_idx + 4] as usize;
                        validate_const_index(build, scalar, term_idx + 4)?;
                    }
                    state.apply(op, idx, selector_count)?;
                    idx += len;
                }
                Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16 => {
                    let count = read_u16_checked(bytes, idx + 1, idx)? as usize;
                    if count == 0 {
                        return Err(format!("empty quotient VM run at byte {idx}"));
                    }
                    let len = 3 + count * 3;
                    check_bounds(bytes, idx, len)?;
                    for term in 0..count {
                        let term_idx = idx + 3 + term * 3;
                        let scalar = bytes[term_idx + 2] as usize;
                        validate_const_index(build, scalar, term_idx + 2)?;
                    }
                    state.apply(op, idx, selector_count)?;
                    idx += len;
                }
                _ => {
                    let spec = quotient_opcode_spec(op).ok_or_else(|| {
                        format!("unknown quotient VM opcode {op:#x} at byte {idx}")
                    })?;
                    if spec.byte_len == 0 {
                        return Err(format!(
                            "opcode {} has dynamic length but no validator at byte {idx}",
                            spec.name
                        ));
                    }
                    check_bounds(bytes, idx, spec.byte_len)?;
                    Self::validate_byte_operands(
                        build,
                        op,
                        idx,
                        native_identity_count,
                        selector_count,
                    )?;
                    state.apply(op, idx, selector_count)?;
                    idx += spec.byte_len;
                }
            }
        }
        Ok(())
    }

    fn validate_byte_operands(
        build: &QuotientProgramBuild,
        op: u8,
        idx: usize,
        native_identity_count: usize,
        selector_count: usize,
    ) -> Result<(), String> {
        let bytes = build.bytes.as_slice();
        match op {
            Q_OP_PUSH_CONST | Q_OP_ADD_CONST | Q_OP_MUL_CONST => {
                validate_const_index(build, read_u16_checked(bytes, idx + 1, idx)? as usize, idx)
            }
            Q_OP_PUSH_CONST_U8 | Q_OP_ADD_CONST_U8 | Q_OP_MUL_CONST_U8 => {
                validate_const_index(build, bytes[idx + 1] as usize, idx)
            }
            Q_OP_FOLD_SELECTOR => {
                let selector = read_u16_checked(bytes, idx + 1, idx)? as usize;
                if selector >= selector_count {
                    return Err(format!(
                        "quotient VM selector index {selector} out of range {selector_count} at byte {idx}"
                    ));
                }
                Ok(())
            }
            Q_OP_PUSH_TEMP | Q_OP_STORE_TEMP => {
                validate_temp_index(build, read_u16_checked(bytes, idx + 1, idx)? as usize, idx)
            }
            Q_OP_NATIVE_IDENTITY => {
                let native = read_u16_checked(bytes, idx + 1, idx)? as usize;
                if native >= native_identity_count {
                    return Err(format!(
                        "quotient VM native identity index {native} out of range {native_identity_count} at byte {idx}"
                    ));
                }
                Ok(())
            }
            Q_OP_PUSH_MEM_TOKEN => validate_mem_token(bytes[idx + 1], idx),
            Q_OP_PUSH_MEM_TOKEN_OFFSET => validate_mem_token(bytes[idx + 1], idx),
            Q_OP_ADD_MUL_MEM_MEM_CONST_U8 => {
                validate_const_index(build, bytes[idx + 5] as usize, idx)
            }
            Q_OP_ADD_MUL_CONST_U8_MEM_U16 => {
                validate_const_index(build, bytes[idx + 3] as usize, idx)
            }
            Q_OP_LIN7 => {
                for limb in 0..QUOTIENT_VM_LIMBS {
                    validate_const_index(build, bytes[idx + 1 + limb * 3] as usize, idx)?;
                }
                Ok(())
            }
            Q_OP_BILIN7_ROW => {
                let coeff_base = idx + 1 + QUOTIENT_VM_BYTE_U16_BYTES;
                for limb in 0..QUOTIENT_VM_LIMBS {
                    validate_const_index(build, bytes[coeff_base + limb * 3] as usize, idx)?;
                }
                Ok(())
            }
            Q_OP_BILIN7_PAIRWISE => {
                let coeff_base = idx + 1 + 2 * QUOTIENT_VM_BYTE_U16_BYTES;
                for coeff in 0..QUOTIENT_VM_PAIRWISE_COEFFS {
                    validate_const_index(build, bytes[coeff_base + coeff] as usize, idx)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn validate_packed32(
        build: &QuotientProgramBuild,
        native_identity_count: usize,
        selector_count: usize,
        state: &mut QuotientProgramValidationState,
    ) -> Result<(), String> {
        if build.bytes.len() % QUOTIENT_VM_PACKED_INSTRUCTION_BYTES != 0 {
            return Err(format!(
                "packed quotient VM bytecode length {} is not 4-byte aligned",
                build.bytes.len()
            ));
        }
        let mut idx = 0usize;
        while idx < build.bytes.len() {
            let word = read_u32_checked(&build.bytes, idx, idx)?;
            let op = (word >> 24) as u8;
            let arg = word & QUOTIENT_VM_PACKED_ARG_MASK;
            let spec = quotient_opcode_spec(op).ok_or_else(|| {
                format!("unknown packed quotient VM opcode {op:#x} at byte {idx}")
            })?;
            if !spec.packed32 {
                return Err(format!(
                    "opcode {} is not valid in packed32 quotient VM at byte {idx}",
                    spec.name
                ));
            }

            match op {
                Q_OP_PUSH_CONST | Q_OP_ADD_CONST | Q_OP_MUL_CONST => {
                    validate_const_index(build, arg as usize, idx)?;
                }
                Q_OP_PUSH_CONST_U8 | Q_OP_ADD_CONST_U8 | Q_OP_MUL_CONST_U8 => {
                    validate_const_index(build, arg as usize, idx)?;
                }
                Q_OP_FOLD_SELECTOR => {
                    let selector = arg as usize;
                    if selector >= selector_count {
                        return Err(format!(
                            "packed quotient VM selector index {selector} out of range {selector_count} at byte {idx}"
                        ));
                    }
                }
                Q_OP_PUSH_TEMP | Q_OP_STORE_TEMP => {
                    validate_temp_index(build, arg as usize, idx)?;
                }
                Q_OP_NATIVE_IDENTITY => {
                    let native = arg as usize;
                    if native >= native_identity_count {
                        return Err(format!(
                            "packed quotient VM native identity index {native} out of range {native_identity_count} at byte {idx}"
                        ));
                    }
                }
                Q_OP_PUSH_MEM_TOKEN => validate_mem_token(arg as u8, idx)?,
                Q_OP_PUSH_MEM_TOKEN_OFFSET => validate_mem_token((arg >> 16) as u8, idx)?,
                Q_OP_ADD_MUL_MEM_MEM_CONST_U8 => {
                    validate_const_index(build, arg as usize, idx)?;
                    check_bounds(&build.bytes, idx, 2 * QUOTIENT_VM_PACKED_INSTRUCTION_BYTES)?;
                    idx += QUOTIENT_VM_PACKED_INSTRUCTION_BYTES;
                }
                Q_OP_ADD_MUL_CONST_U8_MEM_U16 => {
                    validate_const_index(build, (arg >> 16) as usize, idx)?;
                }
                Q_OP_ADD_MUL_MEM_MEM => {
                    check_bounds(&build.bytes, idx, 2 * QUOTIENT_VM_PACKED_INSTRUCTION_BYTES)?;
                    idx += QUOTIENT_VM_PACKED_INSTRUCTION_BYTES;
                }
                _ => {}
            }
            state.apply(op, idx, selector_count)?;
            idx += QUOTIENT_VM_PACKED_INSTRUCTION_BYTES;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct QuotientProgramValidationState {
    stack_depth: usize,
    max_stack: usize,
}

impl QuotientProgramValidationState {
    fn apply(&mut self, op: u8, idx: usize, selector_count: usize) -> Result<(), String> {
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
            | Q_OP_BILIN7_PAIRWISE => {
                self.stack_depth += 1;
                self.max_stack = self.max_stack.max(self.stack_depth);
            }
            Q_OP_ADD | Q_OP_MUL => {
                if self.stack_depth < 2 {
                    return Err(format!(
                        "quotient VM stack underflow at byte {idx}: binary op with depth {}",
                        self.stack_depth
                    ));
                }
                self.stack_depth -= 1;
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
            | Q_OP_STORE_TEMP => {
                if self.stack_depth == 0 {
                    return Err(format!(
                        "quotient VM stack underflow at byte {idx}: op requires a top value"
                    ));
                }
            }
            Q_OP_FOLD_MAIN | Q_OP_FOLD_SELECTOR => {
                if self.stack_depth != 1 {
                    return Err(format!(
                        "quotient VM fold at byte {idx} expects depth 1, got {}",
                        self.stack_depth
                    ));
                }
                if matches!(op, Q_OP_FOLD_SELECTOR) && selector_count == 0 {
                    return Err(format!(
                        "quotient VM selector fold at byte {idx} but no selectors are planned"
                    ));
                }
                self.stack_depth = 0;
            }
            Q_OP_NATIVE_PERMUTATION | Q_OP_NATIVE_IDENTITY => {
                if self.stack_depth != 0 {
                    return Err(format!(
                        "quotient VM native callback at byte {idx} expects empty stack, got {}",
                        self.stack_depth
                    ));
                }
            }
            _ => return Err(format!("unknown quotient VM opcode {op:#x} at byte {idx}")),
        }
        Ok(())
    }
}

fn check_bounds(bytes: &[u8], idx: usize, len: usize) -> Result<(), String> {
    if idx + len > bytes.len() {
        return Err(format!(
            "truncated quotient VM instruction at byte {idx}: len={len} remaining={}",
            bytes.len().saturating_sub(idx)
        ));
    }
    Ok(())
}

fn read_u16_checked(bytes: &[u8], idx: usize, op_idx: usize) -> Result<u16, String> {
    check_bounds(bytes, idx, QUOTIENT_VM_BYTE_U16_BYTES).map_err(|err| {
        format!("truncated quotient VM u16 operand for instruction at byte {op_idx}: {err}")
    })?;
    Ok(u16::from_be_bytes(
        bytes[idx..idx + QUOTIENT_VM_BYTE_U16_BYTES]
            .try_into()
            .expect("bounds checked"),
    ))
}

fn read_u32_checked(bytes: &[u8], idx: usize, op_idx: usize) -> Result<u32, String> {
    check_bounds(bytes, idx, QUOTIENT_VM_BYTE_U32_BYTES).map_err(|err| {
        format!("truncated quotient VM u32 operand for instruction at byte {op_idx}: {err}")
    })?;
    Ok(u32::from_be_bytes(
        bytes[idx..idx + QUOTIENT_VM_BYTE_U32_BYTES]
            .try_into()
            .expect("bounds checked"),
    ))
}

fn validate_const_index(
    build: &QuotientProgramBuild,
    index: usize,
    idx: usize,
) -> Result<(), String> {
    if index >= build.consts.len() {
        return Err(format!(
            "quotient VM const index {index} out of range {} at byte {idx}",
            build.consts.len()
        ));
    }
    Ok(())
}

fn validate_temp_index(
    build: &QuotientProgramBuild,
    index: usize,
    idx: usize,
) -> Result<(), String> {
    if index >= build.cse_temps {
        return Err(format!(
            "quotient VM temp index {index} out of range {} at byte {idx}",
            build.cse_temps
        ));
    }
    Ok(())
}

fn validate_mem_token(token: u8, idx: usize) -> Result<(), String> {
    if !QUOTIENT_MEM_TOKEN_TABLE
        .iter()
        .any(|spec| spec.token == token)
    {
        return Err(format!(
            "quotient VM memory token {token:#x} is unknown at byte {idx}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod validator_tests {
    use super::*;

    fn build(
        bytes: Vec<u8>,
        const_count: usize,
        max_stack: usize,
        cse_temps: usize,
    ) -> QuotientProgramBuild {
        QuotientProgramBuild {
            bytes,
            consts: vec![U256::ZERO; const_count],
            max_stack,
            packed32: false,
            cse_temps,
        }
    }

    #[test]
    fn quotient_vm_validator_accepts_minimal_identity() {
        let build = build(vec![Q_OP_PUSH_CONST_U8, 0, Q_OP_FOLD_MAIN], 1, 1, 0);
        assert!(QuotientProgramValidator::validate(&build, 0, 0).is_ok());
    }

    #[test]
    fn quotient_vm_validator_rejects_unknown_opcode() {
        let build = build(vec![0xff], 0, 0, 0);
        assert!(QuotientProgramValidator::validate(&build, 0, 0)
            .unwrap_err()
            .contains("unknown"));
    }

    #[test]
    fn quotient_vm_validator_rejects_stack_underflow() {
        let build = build(vec![Q_OP_ADD], 0, 0, 0);
        assert!(QuotientProgramValidator::validate(&build, 0, 0)
            .unwrap_err()
            .contains("underflow"));
    }

    #[test]
    fn quotient_vm_validator_rejects_invalid_const_and_temp_indices() {
        let invalid_const = build(vec![Q_OP_PUSH_CONST_U8, 1, Q_OP_FOLD_MAIN], 1, 1, 0);
        assert!(QuotientProgramValidator::validate(&invalid_const, 0, 0)
            .unwrap_err()
            .contains("const index"));

        let invalid_temp = build(vec![Q_OP_PUSH_TEMP, 0, 0, Q_OP_FOLD_MAIN], 0, 1, 0);
        assert!(QuotientProgramValidator::validate(&invalid_temp, 0, 0)
            .unwrap_err()
            .contains("temp index"));
    }

    #[test]
    fn quotient_vm_validator_rejects_invalid_selector_and_native_indices() {
        let invalid_selector = build(
            vec![Q_OP_PUSH_CONST_U8, 0, Q_OP_FOLD_SELECTOR, 0, 0],
            1,
            1,
            0,
        );
        assert!(QuotientProgramValidator::validate(&invalid_selector, 0, 0)
            .unwrap_err()
            .contains("selector"));

        let invalid_native = build(vec![Q_OP_NATIVE_IDENTITY, 0, 0], 0, 0, 0);
        assert!(QuotientProgramValidator::validate(&invalid_native, 0, 0)
            .unwrap_err()
            .contains("native identity"));
    }
}

pub(super) fn hybrid_quotient_inline_count(identities: &[QuotientIdentity]) -> usize {
    identities
        .len()
        .min(config::CodegenOptions::from_env().hybrid_quotient_inline_identities)
}

pub(super) fn quotient_native_gate_count(gates: &[QuotientIdentity]) -> usize {
    gates
        .len()
        .min(config::CodegenOptions::from_env().quotient_native_gates)
}

pub(super) fn quotient_program_encoding() -> QuotientProgramEncoding {
    config::CodegenOptions::from_env().quotient_encoding
}

pub(super) fn quotient_inline_cse_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_inline_cse
}

pub(super) fn quotient_vm_cse_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_vm_cse
}

pub(super) fn quotient_yul_helpers_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_yul_helpers
}

pub(super) fn quotient_structured_loops_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_structured_loops
}

pub(super) fn quotient_structured_tail_mode() -> QuotientStructuredTailMode {
    config::CodegenOptions::from_env().quotient_structured_tail
}

pub(super) fn quotient_native_permutation_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_native_permutation
}

pub(super) fn quotient_limb_vm_ops_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_limb_vm_ops
}

pub(super) fn quotient_shape_profile_enabled() -> bool {
    config::CodegenOptions::from_env().quotient_shape_profile
}

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

pub(super) fn quotient_cse_candidate(count: usize, cost: usize) -> bool {
    if count <= 1 || cost <= 3 {
        return false;
    }
    // First use pays the original expression plus STORE_TEMP; each later use
    // becomes PUSH_TEMP. Keep only cases with an estimated bytecode win.
    (count - 1) * (cost - 3) > 3
}

pub(super) fn quotient_inline_cse_candidate(count: usize, cost: usize) -> bool {
    if count <= 1 || cost <= 6 {
        return false;
    }
    // Straight-line CSE stores the first evaluation in memory (~6 bytes for
    // the mstore) and replaces every later use with an mload (~6 bytes).
    // Net byte savings:
    //     count * cost  -  (cost + 6 + (count - 1) * 6)
    //   = (count - 1) * cost  -  6 * count
    // Keep only expressions where this is strictly positive.
    (count - 1) * cost > 6 * count
}

pub(super) fn quotient_cse_sort_key(key: &str, count: usize, cost: usize) -> (usize, usize, &str) {
    let score = count.saturating_sub(1).saturating_mul(cost);
    (
        usize::MAX.saturating_sub(score),
        usize::MAX.saturating_sub(cost),
        key,
    )
}

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

pub(super) fn quotient_mem_load_expr(mem: QuotientMem) -> String {
    format!("mload({})", quotient_mem_ptr_expr(mem))
}

pub(super) fn quotient_mem_ptr_expr(mem: QuotientMem) -> String {
    match mem {
        QuotientMem::Literal(ptr) => format!("{ptr:#x}"),
        QuotientMem::Token(token) => quotient_mem_token_name(token).to_string(),
        QuotientMem::TokenOffset(token, offset) => {
            format!("add({}, {offset:#x})", quotient_mem_token_name(token))
        }
    }
}

pub(super) fn quotient_mem_token_name(token: u8) -> &'static str {
    QUOTIENT_MEM_TOKEN_TABLE
        .iter()
        .find_map(|spec| (spec.token == token).then_some(spec.name))
        .unwrap_or_else(|| panic!("unknown quotient memory token {token:#x}"))
}

pub(super) fn quotient_mem_token_from_name(name: &str) -> Option<u8> {
    QUOTIENT_MEM_TOKEN_TABLE
        .iter()
        .find_map(|spec| (spec.name == name).then_some(spec.token))
}

pub(super) trait QuotientExpressionEnv {
    fn selector(&self, selector: Selector) -> QuotientExpr;
    fn fixed(&self, column_index: usize, rotation: i32) -> QuotientExpr;
    fn advice(&self, column_index: usize, rotation: i32) -> QuotientExpr;
    fn instance(&self, column_index: usize, rotation: i32) -> QuotientExpr;
    fn challenge(&self, index: usize) -> QuotientExpr;
}

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

pub(super) struct DataQuotientExpressionEnv<'a> {
    pub(super) meta: &'a ConstraintSystemMeta,
    pub(super) data: &'a Data,
}

impl QuotientExpressionEnv for DataQuotientExpressionEnv<'_> {
    fn selector(&self, _selector: Selector) -> QuotientExpr {
        panic!("virtual selectors must be removed before quotient lowering")
    }

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

    fn advice(&self, column_index: usize, rotation: i32) -> QuotientExpr {
        word_to_quotient_expr(
            *self
                .data
                .advice_evals
                .get(&(column_index, rotation))
                .expect("advice eval present"),
        )
    }

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

    fn challenge(&self, index: usize) -> QuotientExpr {
        word_to_quotient_expr(self.data.challenges[index])
    }
}

pub(super) fn word_to_quotient_expr(word: Word) -> QuotientExpr {
    assert_eq!(
        word.loc(),
        Location::Memory,
        "quotient expressions can only load memory-backed words"
    );
    QuotientExpr::Mem(ptr_to_quotient_mem(word.ptr()))
}

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

pub(super) fn quotient_op_len(bytes: &[u8], idx: usize) -> usize {
    let op = bytes[idx];
    quotient_opcode_byte_len(op)
        .unwrap_or_else(|| panic!("unknown quotient op {op:#x} at byte {idx}"))
}

pub(super) fn quotient_leaf(expr: &QuotientExpr) -> Option<QuotientLeaf> {
    match expr {
        QuotientExpr::Const(value) => Some(QuotientLeaf::Const(*value)),
        QuotientExpr::Mem(mem) => Some(QuotientLeaf::Mem(*mem)),
        QuotientExpr::Add(_, _) | QuotientExpr::Mul(_, _) | QuotientExpr::Neg(_) => None,
    }
}

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

pub(super) fn quotient_mem_term(expr: &QuotientExpr) -> Option<(Fq, u16)> {
    let (coeff, ptrs) = quotient_product_mem_factors(expr)?;
    if ptrs.len() == 1 {
        Some((coeff, ptrs[0]))
    } else {
        None
    }
}

pub(super) fn quotient_product_mem_pair(expr: &QuotientExpr) -> Option<(Fq, u16, u16)> {
    let (coeff, ptrs) = quotient_product_mem_factors(expr)?;
    if ptrs.len() == 2 {
        Some((coeff, ptrs[0], ptrs[1]))
    } else {
        None
    }
}

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

pub(super) fn add_grouped_limb_coeff(grouped: &mut Vec<(u16, Fq)>, ptr: u16, coeff: Fq) {
    if let Some((_, existing)) = grouped.iter_mut().find(|(existing, _)| *existing == ptr) {
        *existing += coeff;
    } else {
        grouped.push((ptr, coeff));
    }
}

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

pub(super) fn limb7_index(base: u16, ptr: u16) -> Option<usize> {
    let diff = ptr.checked_sub(base)?;
    let word_bytes = layout::WORD_BYTES as u16;
    if diff % word_bytes != 0 {
        return None;
    }
    let idx = (diff / word_bytes) as usize;
    (idx < QUOTIENT_VM_LIMBS).then_some(idx)
}

pub(super) fn quotient_fq_from_u256(value: U256) -> Option<Fq> {
    let bytes = value.to_le_bytes::<32>();
    let repr = <Fq as PrimeField>::Repr::from(bytes);
    Option::<Fq>::from(Fq::from_repr(repr))
}

pub(super) fn quotient_fq_to_u256(value: Fq) -> U256 {
    fe_to_u256::<Fq>(&value)
}

#[allow(dead_code)]
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

pub(super) fn is_literal(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("0x")
        || value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit())
}

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

pub(super) fn u256_string(value: U256) -> String {
    if value.bit_len() < 64 {
        format!("0x{:x}", value.as_limbs()[0])
    } else {
        format!("0x{value:x}")
    }
}

pub(super) fn fr_delta_literal() -> String {
    u256_string(fe_to_u256::<Fq>(&Fq::DELTA))
}

#[allow(dead_code)]
pub(super) fn parse_u32_literal(value: &str) -> Option<u32> {
    if !is_literal(value) {
        return None;
    }
    let parsed = parse_u256(value);
    parsed.try_into().ok()
}

pub(super) fn parse_usize_literal(value: &str) -> Option<usize> {
    if !is_literal(value) {
        return None;
    }
    let parsed = parse_u256(value);
    parsed.try_into().ok()
}

#[allow(dead_code)]
pub(super) fn mem_token(name: &str) -> Option<u8> {
    quotient_mem_token_from_name(name)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct YulAssignment {
    pub(super) dst: String,
    pub(super) expr: String,
    pub(super) has_let: bool,
}

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

pub(super) fn yul_let_assignment(line: &str) -> Option<(String, String)> {
    let assignment = yul_assignment(line)?;
    assignment
        .has_let
        .then_some((assignment.dst, assignment.expr))
}

pub(super) fn yul_const_value(value: &str, const_vars: &HashMap<String, String>) -> Option<String> {
    let value = value.trim();
    if is_literal(value) {
        Some(u256_string(parse_u256(value)))
    } else {
        const_vars.get(value).cloned()
    }
}

pub(super) fn yul_mulmod_assignment(line: &str) -> Option<(String, String, String)> {
    let (dst, expr) = yul_let_assignment(line)?;
    let args = call_args(&expr, "mulmod")?;
    if args.len() == 3 && args[2].trim() == "r" {
        Some((dst, args[0].trim().to_string(), args[1].trim().to_string()))
    } else {
        None
    }
}

pub(super) fn yul_addmod_assignment(line: &str) -> Option<(String, String, String)> {
    let (dst, expr) = yul_let_assignment(line)?;
    let args = call_args(&expr, "addmod")?;
    if args.len() == 3 && args[2].trim() == "r" {
        Some((dst, args[0].trim().to_string(), args[1].trim().to_string()))
    } else {
        None
    }
}

pub(super) fn yul_mload_literal_assignment(line: &str) -> Option<(String, usize)> {
    let (dst, expr) = yul_let_assignment(line)?;
    Some((dst, yul_mload_literal_expr(&expr)?))
}

pub(super) fn yul_mload_literal_expr(expr: &str) -> Option<usize> {
    let args = call_args(expr.trim(), "mload")?;
    if args.len() == 1 {
        parse_usize_literal(args[0].trim())
    } else {
        None
    }
}

pub(super) fn yul_sub_r_assignment(line: &str) -> Option<(String, String)> {
    let (dst, expr) = yul_let_assignment(line)?;
    let args = call_args(&expr, "sub")?;
    if args.len() == 2 && args[0].trim() == "r" {
        Some((dst, args[1].trim().to_string()))
    } else {
        None
    }
}

pub(super) fn call_args(expr: &str, name: &str) -> Option<Vec<String>> {
    let expr = expr.trim();
    let rest = expr.strip_prefix(name)?.trim_start();
    let rest = rest.strip_prefix('(')?;
    if !rest.ends_with(')') {
        return None;
    }
    Some(split_top_level(&rest[..rest.len() - 1]))
}

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
