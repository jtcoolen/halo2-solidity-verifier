use crate::codegen::{
    evaluator::Evaluator,
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

mod evaluator;
mod pcs;
mod protocol;
mod template;
pub(crate) mod util;

pub use pcs::BatchOpenScheme;

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

// Compact quotient-identity bytecode interpreted by the generated Yul verifier.
// The identities are still derived from the same evaluator output; this only
// changes how the arithmetic is represented in deployed bytecode.
#[derive(Clone, Copy, Debug)]
enum QuotientTarget {
    Main,
    Selector(usize),
}

#[derive(Debug)]
struct QuotientProgramBuild {
    bytes: Vec<u8>,
    consts: Vec<U256>,
    max_stack: usize,
    packed32: bool,
    cse_temps: usize,
}

#[derive(Clone, Debug)]
struct QuotientIdentity {
    lines: Vec<String>,
    var: String,
    target: QuotientTarget,
    expr: Option<QuotientExpr>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RepackedProofScalarLayout {
    pub(crate) eval_offset: usize,
    pub(crate) num_evals: usize,
    pub(crate) q_eval_offset: usize,
    pub(crate) num_point_sets: usize,
}

#[derive(Clone, Debug)]
struct QuotientIdentityParts {
    gates: Vec<QuotientIdentity>,
    permutation: Vec<QuotientIdentity>,
    lookup: Vec<QuotientIdentity>,
    trash: Vec<QuotientIdentity>,
    sorted_simple: Vec<usize>,
}

impl QuotientIdentityParts {
    fn all_identities(&self) -> Vec<QuotientIdentity> {
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
enum QuotientStructuredTailMode {
    Off,
    Trash,
}

#[derive(Clone, Debug)]
enum QuotientProgramItem {
    Identity(QuotientIdentity),
    NativePermutation,
    NativeIdentity(usize),
}

#[derive(Clone, Debug)]
struct QuotientProgramPlan {
    inline_identities: Vec<QuotientIdentity>,
    items: Vec<QuotientProgramItem>,
    native_identities: Vec<QuotientIdentity>,
    sorted_simple: Vec<usize>,
    has_native_permutation: bool,
}

// Keep a small direct prefix as the correctness anchor for the hybrid VM path:
// it is the most-tested shape and avoids running the entire numerator through
// the interpreter. Tune with HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=N.
const DEFAULT_HYBRID_QUOTIENT_INLINE_IDENTITIES: usize = 4;
const HYBRID_QUOTIENT_INLINE_IDENTITIES_ENV: &str =
    "HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES";

// Spend a bounded slice of quotient-evaluator bytecode headroom on native VM callbacks.
// After the direct prefix, the heaviest N remaining gate identities are emitted
// as VM opcodes that call generated Yul blocks; everything else stays in the
// compact interpreter. Tune with HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=N.
const DEFAULT_QUOTIENT_NATIVE_GATES: usize = 5;
const QUOTIENT_NATIVE_GATES_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES";
const QUOTIENT_ENCODING_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_ENCODING";
// The compact quotient VM path is the default size-oriented emitter: it stores
// identity arithmetic as data in the VK and interprets it from one small Yul
// loop. By default only the final trash suffix is emitted as structured Yul,
// which saves dispatch gas while preserving the IVC size budget. Set
// HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=off to disable this,
// HALO2_SOLIDITY_QUOTIENT_STRUCTURED_LOOPS=1 for the larger fully structured
// experiment, or HALO2_SOLIDITY_QUOTIENT_CSE=1 for fully inline CSE gas
// measurement.
const QUOTIENT_CSE_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_CSE";
const QUOTIENT_VM_CSE_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_VM_CSE";
const QUOTIENT_YUL_HELPERS_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_YUL_HELPERS";
const QUOTIENT_STRUCTURED_LOOPS_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_STRUCTURED_LOOPS";
const QUOTIENT_STRUCTURED_TAIL_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL";
const QUOTIENT_NATIVE_PERMUTATION_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_NATIVE_PERMUTATION";
const QUOTIENT_EXTERNAL_MAGIC: u64 = 0x5155_4556_414c_0001;
const LIMB7_YUL_COEFFS: [&str; 6] = [
    "0x100000000000000",
    "0x10000000000000000000000000000",
    "0x400000000",
    "0x40000000000000000000000",
    "0x1000",
    "0x100000000000000000",
];
const WIDE_LIMB7_YUL_COEFFS: [&str; 6] = [
    "0x100000000000000",
    "0x10000000000000000000000000000",
    "0x1000000000000000000000000000000000000000000",
    "0x100000000000000000000000000000000000000000000000000000000",
    "0x6bc66e553973f396854f5626172ba135587d41e37a68209402355093fdcaaf6c",
    "0x63f31e3f446953960c9d6964474300df43ab29179970f642a28e39d6c883c74b",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuotientProgramEncoding {
    Bytes,
    Packed32,
}

const Q_OP_PUSH_CONST: u8 = 0x01;
const Q_OP_PUSH_MEM_LITERAL: u8 = 0x02;
const Q_OP_PUSH_MEM_TOKEN: u8 = 0x03;
const Q_OP_PUSH_MEM_TOKEN_OFFSET: u8 = 0x04;
const Q_OP_PUSH_MEM_U16: u8 = 0x05;
const Q_OP_ADD: u8 = 0x06;
const Q_OP_MUL: u8 = 0x07;
const Q_OP_NEG: u8 = 0x08;
const Q_OP_PUSH_CONST_U8: u8 = 0x09;
const Q_OP_FOLD_MAIN: u8 = 0x0a;
const Q_OP_FOLD_SELECTOR: u8 = 0x0b;
const Q_OP_ADD_CONST_U8: u8 = 0x0c;
const Q_OP_MUL_CONST_U8: u8 = 0x0d;
const Q_OP_ADD_CONST: u8 = 0x0e;
const Q_OP_MUL_CONST: u8 = 0x0f;
const Q_OP_ADD_MEM_U16: u8 = 0x10;
const Q_OP_MUL_MEM_U16: u8 = 0x11;
const Q_OP_ADD_MUL_MEM_MEM_CONST_U8: u8 = 0x12;
const Q_OP_ADD_MUL_CONST_U8_MEM_U16: u8 = 0x13;
const Q_OP_ADD_MUL_MEM_MEM: u8 = 0x14;
const Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8: u8 = 0x15;
const Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16: u8 = 0x16;
const Q_OP_PUSH_TEMP: u8 = 0x17;
const Q_OP_STORE_TEMP: u8 = 0x18;
const Q_OP_NATIVE_PERMUTATION: u8 = 0x19;
const Q_OP_NATIVE_IDENTITY: u8 = 0x1b;

const Q_MEM_L0: u8 = 0x01;
const Q_MEM_L_LAST: u8 = 0x02;
const Q_MEM_L_BLIND: u8 = 0x03;
const Q_MEM_BETA: u8 = 0x04;
const Q_MEM_GAMMA: u8 = 0x05;
const Q_MEM_X: u8 = 0x06;
const Q_MEM_THETA: u8 = 0x07;
const Q_MEM_TRASH_CHALLENGE: u8 = 0x08;
const Q_MEM_INSTANCE_EVAL: u8 = 0x09;

fn scalar_le_to_be_word(bytes: &[u8]) -> [u8; 32] {
    assert_eq!(bytes.len(), 32, "scalar proof element must be 32 bytes");
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(bytes);
    scalar.reverse();
    scalar
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum QuotientExpr {
    Const(U256),
    Mem(QuotientMem),
    Add(Box<QuotientExpr>, Box<QuotientExpr>),
    Mul(Box<QuotientExpr>, Box<QuotientExpr>),
    Neg(Box<QuotientExpr>),
}

#[derive(Debug, Default)]
struct QuotientCseState {
    slots: HashMap<String, u16>,
    emitted: HashMap<String, u16>,
}

impl QuotientCseState {
    fn from_exprs(exprs: &[QuotientExpr]) -> Self {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum QuotientMem {
    Literal(u32),
    Token(u8),
    TokenOffset(u8, u32),
}

#[derive(Debug)]
struct QuotientInlineCsePlan {
    slots: HashMap<String, u16>,
    exprs: HashMap<String, QuotientExpr>,
}

impl QuotientInlineCsePlan {
    fn new(exprs: &[QuotientExpr]) -> Self {
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

struct QuotientInlineCseEmitter<'a> {
    plan: &'a QuotientInlineCsePlan,
    cse_mptr: usize,
    helpers: bool,
    emitted: HashSet<String>,
    emitting: HashSet<String>,
    next_var: usize,
}

impl<'a> QuotientInlineCseEmitter<'a> {
    fn new(plan: &'a QuotientInlineCsePlan, cse_mptr: usize, helpers: bool) -> Self {
        Self {
            plan,
            cse_mptr,
            helpers,
            emitted: HashSet::new(),
            emitting: HashSet::new(),
            next_var: 0,
        }
    }

    fn emit_identity(&mut self, expr: &QuotientExpr, out: &mut Vec<String>) -> String {
        self.emit_expr(expr, out, None)
    }

    fn emit_expr(
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
                    out.push(format!("let {var} := sub(r, {inner})"));
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
        format!("{:#x}", self.cse_mptr + slot * 0x20)
    }

    fn fresh_var(&mut self) -> String {
        let var = format!("q_cse_var_{}", self.next_var);
        self.next_var += 1;
        var
    }
}

#[derive(Clone, Copy, Debug)]
enum QuotientLeaf {
    Const(U256),
    Mem(QuotientMem),
}

#[derive(Clone, Copy, Debug)]
enum QuotientProductAdd {
    MemMemConstU8 { lhs: u16, rhs: u16, scalar: U256 },
    ConstU8Mem { scalar: U256, ptr: u16 },
    MemMem { lhs: u16, rhs: u16 },
}

#[derive(Default)]
struct QuotientProgramBuilder {
    bytes: Vec<u8>,
    consts: Vec<U256>,
    const_slots: HashMap<U256, u16>,
    vars: HashMap<String, QuotientExpr>,
    stack_depth: usize,
    max_stack: usize,
}

impl QuotientProgramBuilder {
    fn identity_expr(
        &mut self,
        expr: &QuotientExpr,
        target: QuotientTarget,
        cse: Option<&mut QuotientCseState>,
    ) {
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
        match target {
            QuotientTarget::Main => self.op0(Q_OP_FOLD_MAIN),
            QuotientTarget::Selector(idx) => {
                self.bytes.push(Q_OP_FOLD_SELECTOR);
                self.u16(idx);
                self.pop_stack();
            }
        }
        if matches!(target, QuotientTarget::Main) {
            self.pop_stack();
        }
    }

    fn native_permutation(&mut self) {
        assert_eq!(
            self.stack_depth, 0,
            "native permutation expects empty VM stack"
        );
        self.bytes.push(Q_OP_NATIVE_PERMUTATION);
    }

    fn native_identity(&mut self, native_idx: usize) {
        assert_eq!(
            self.stack_depth, 0,
            "native identity expects empty VM stack"
        );
        self.bytes.push(Q_OP_NATIVE_IDENTITY);
        self.u16(native_idx);
    }

    fn finish(self, encoding: QuotientProgramEncoding) -> QuotientProgramBuild {
        let cse_temps = self.cse_temps();
        let bytes = match encoding {
            QuotientProgramEncoding::Bytes => compact_quotient_runs(&self.bytes),
            QuotientProgramEncoding::Packed32 => pack_quotient_u32_program(&self.bytes),
        };
        QuotientProgramBuild {
            bytes,
            consts: self.consts,
            max_stack: self.max_stack,
            packed32: encoding == QuotientProgramEncoding::Packed32,
            cse_temps,
        }
    }

    fn assignment(&mut self, line: &str) {
        let line = line.trim();
        let line = line.strip_prefix("let ").unwrap_or(line);
        let (dst, expr) = line
            .split_once(" := ")
            .unwrap_or_else(|| panic!("unsupported quotient assignment: {line}"));
        let expr = self.parse_expr(expr.trim());
        self.vars.insert(dst.trim().to_string(), expr);
    }

    fn parse_expr(&self, expr: &str) -> QuotientExpr {
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

    fn emit_expr(&mut self, expr: &QuotientExpr) {
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

            cse.emitted.insert(key, slot);
            self.emit_expr_cse_inner(expr, cse);
            self.bytes.push(Q_OP_STORE_TEMP);
            self.u16(slot as usize);
            return;
        }

        self.emit_expr_cse_inner(expr, cse);
    }

    fn emit_expr_cse_inner(&mut self, expr: &QuotientExpr, cse: &mut QuotientCseState) {
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

    fn emit_const(&mut self, value: U256) {
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
        self.bytes.push(op);
    }

    fn op_binary(&mut self, op: u8) {
        self.bytes.push(op);
        self.pop_stack();
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
                    idx += 3;
                }
                _ => idx += quotient_op_len(&self.bytes, idx),
            }
        }
        temps
    }
}

fn compact_quotient_runs(bytes: &[u8]) -> Vec<u8> {
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

            if run_len >= 4 {
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

fn pack_quotient_u32_program(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().next_multiple_of(4));
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
                    ptr <= 0x00ff_ffff,
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

fn push_packed_quotient_op(out: &mut Vec<u8>, op: u8, arg: u32) {
    assert!(
        arg <= 0x00ff_ffff,
        "packed quotient VM operand exceeds 24 bits"
    );
    out.extend_from_slice(&(((op as u32) << 24) | arg).to_be_bytes());
}

fn read_u16(bytes: &[u8], idx: usize) -> u16 {
    u16::from_be_bytes(
        bytes[idx..idx + 2]
            .try_into()
            .expect("u16 quotient operand"),
    )
}

fn read_u32(bytes: &[u8], idx: usize) -> u32 {
    u32::from_be_bytes(
        bytes[idx..idx + 4]
            .try_into()
            .expect("u32 quotient operand"),
    )
}

fn hybrid_quotient_inline_count(identities: &[QuotientIdentity]) -> usize {
    let requested = std::env::var(HYBRID_QUOTIENT_INLINE_IDENTITIES_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_HYBRID_QUOTIENT_INLINE_IDENTITIES);
    identities.len().min(requested)
}

fn quotient_native_gate_count(gates: &[QuotientIdentity]) -> usize {
    let requested = std::env::var(QUOTIENT_NATIVE_GATES_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_QUOTIENT_NATIVE_GATES);
    gates.len().min(requested)
}

fn quotient_program_encoding() -> QuotientProgramEncoding {
    let Ok(value) = std::env::var(QUOTIENT_ENCODING_ENV) else {
        return QuotientProgramEncoding::Bytes;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "bytes" | "byte" | "varbytes" | "compact" => QuotientProgramEncoding::Bytes,
        "3" | "option3" | "packed32" | "packed-32" | "u32" => QuotientProgramEncoding::Packed32,
        other => panic!("unsupported {QUOTIENT_ENCODING_ENV}={other}; use bytes or packed32"),
    }
}

fn quotient_inline_cse_enabled() -> bool {
    let Ok(value) = std::env::var(QUOTIENT_CSE_ENV) else {
        return false;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => false,
        "1" | "true" | "on" | "yes" | "cse" => true,
        other => panic!("unsupported {QUOTIENT_CSE_ENV}={other}; use 0/1"),
    }
}

fn quotient_vm_cse_enabled() -> bool {
    let Ok(value) = std::env::var(QUOTIENT_VM_CSE_ENV) else {
        return true;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => false,
        "1" | "true" | "on" | "yes" | "cse" => true,
        other => panic!("unsupported {QUOTIENT_VM_CSE_ENV}={other}; use 0/1"),
    }
}

fn quotient_yul_helpers_enabled() -> bool {
    let Ok(value) = std::env::var(QUOTIENT_YUL_HELPERS_ENV) else {
        return false;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => false,
        "1" | "true" | "on" | "yes" | "helpers" => true,
        other => panic!("unsupported {QUOTIENT_YUL_HELPERS_ENV}={other}; use 0/1"),
    }
}

fn quotient_structured_loops_enabled() -> bool {
    let Ok(value) = std::env::var(QUOTIENT_STRUCTURED_LOOPS_ENV) else {
        return false;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => false,
        "1" | "true" | "on" | "yes" | "loops" => true,
        other => panic!("unsupported {QUOTIENT_STRUCTURED_LOOPS_ENV}={other}; use 0/1"),
    }
}

fn quotient_structured_tail_mode() -> QuotientStructuredTailMode {
    let Ok(value) = std::env::var(QUOTIENT_STRUCTURED_TAIL_ENV) else {
        return QuotientStructuredTailMode::Trash;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => QuotientStructuredTailMode::Off,
        "1" | "true" | "on" | "yes" | "tail" | "trash" => QuotientStructuredTailMode::Trash,
        other => panic!("unsupported {QUOTIENT_STRUCTURED_TAIL_ENV}={other}; use off or trash"),
    }
}

fn quotient_native_permutation_enabled() -> bool {
    let Ok(value) = std::env::var(QUOTIENT_NATIVE_PERMUTATION_ENV) else {
        return true;
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => false,
        "1" | "true" | "on" | "yes" | "native" => true,
        other => panic!("unsupported {QUOTIENT_NATIVE_PERMUTATION_ENV}={other}; use 0/1"),
    }
}

fn count_quotient_exprs(
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

fn collect_quotient_expr_stats(
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

fn quotient_cse_candidate(count: usize, cost: usize) -> bool {
    if count <= 1 || cost <= 3 {
        return false;
    }
    // First use pays the original expression plus STORE_TEMP; each later use
    // becomes PUSH_TEMP. Keep only cases with an estimated bytecode win.
    (count - 1) * (cost - 3) > 3
}

fn quotient_inline_cse_candidate(count: usize, cost: usize) -> bool {
    if count <= 1 || cost <= 6 {
        return false;
    }
    // Straight-line CSE stores the first evaluation in memory and replaces
    // every use with an mload. Keep only expressions with enough estimated
    // duplicated arithmetic to pay for the mstore/mload bytecode.
    (count - 1) * cost > 12
}

fn quotient_cse_sort_key(key: &str, count: usize, cost: usize) -> (usize, usize, &str) {
    let score = count.saturating_sub(1).saturating_mul(cost);
    (
        usize::MAX.saturating_sub(score),
        usize::MAX.saturating_sub(cost),
        key,
    )
}

fn quotient_expr_key(expr: &QuotientExpr) -> String {
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

fn quotient_mem_load_expr(mem: QuotientMem) -> String {
    format!("mload({})", quotient_mem_ptr_expr(mem))
}

fn quotient_mem_ptr_expr(mem: QuotientMem) -> String {
    match mem {
        QuotientMem::Literal(ptr) => format!("{ptr:#x}"),
        QuotientMem::Token(token) => quotient_mem_token_name(token).to_string(),
        QuotientMem::TokenOffset(token, offset) => {
            format!("add({}, {offset:#x})", quotient_mem_token_name(token))
        }
    }
}

fn quotient_mem_token_name(token: u8) -> &'static str {
    match token {
        Q_MEM_L0 => "L_0_MPTR",
        Q_MEM_L_LAST => "L_LAST_MPTR",
        Q_MEM_L_BLIND => "L_BLIND_MPTR",
        Q_MEM_BETA => "BETA_MPTR",
        Q_MEM_GAMMA => "GAMMA_MPTR",
        Q_MEM_X => "X_MPTR",
        Q_MEM_THETA => "THETA_MPTR",
        Q_MEM_TRASH_CHALLENGE => "TRASH_CHALLENGE_MPTR",
        Q_MEM_INSTANCE_EVAL => "INSTANCE_EVAL_MPTR",
        _ => panic!("unknown quotient memory token {token:#x}"),
    }
}

fn quotient_mem_token_from_name(name: &str) -> Option<u8> {
    match name {
        "L_0_MPTR" => Some(Q_MEM_L0),
        "L_LAST_MPTR" => Some(Q_MEM_L_LAST),
        "L_BLIND_MPTR" => Some(Q_MEM_L_BLIND),
        "BETA_MPTR" => Some(Q_MEM_BETA),
        "GAMMA_MPTR" => Some(Q_MEM_GAMMA),
        "X_MPTR" => Some(Q_MEM_X),
        "THETA_MPTR" => Some(Q_MEM_THETA),
        "TRASH_CHALLENGE_MPTR" => Some(Q_MEM_TRASH_CHALLENGE),
        "INSTANCE_EVAL_MPTR" => Some(Q_MEM_INSTANCE_EVAL),
        _ => None,
    }
}

trait QuotientExpressionEnv {
    fn selector(&self, selector: Selector) -> QuotientExpr;
    fn fixed(&self, column_index: usize, rotation: i32) -> QuotientExpr;
    fn advice(&self, column_index: usize, rotation: i32) -> QuotientExpr;
    fn instance(&self, column_index: usize, rotation: i32) -> QuotientExpr;
    fn challenge(&self, index: usize) -> QuotientExpr;
}

fn quotient_expr_from_expression<E: QuotientExpressionEnv>(
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

struct DataQuotientExpressionEnv<'a> {
    meta: &'a ConstraintSystemMeta,
    data: &'a Data,
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

fn word_to_quotient_expr(word: Word) -> QuotientExpr {
    assert_eq!(
        word.loc(),
        Location::Memory,
        "quotient expressions can only load memory-backed words"
    );
    QuotientExpr::Mem(ptr_to_quotient_mem(word.ptr()))
}

fn ptr_to_quotient_mem(ptr: Ptr) -> QuotientMem {
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

fn quotient_commutative_expr_key(op: &str, lhs: &QuotientExpr, rhs: &QuotientExpr) -> String {
    let lhs = quotient_expr_key(lhs);
    let rhs = quotient_expr_key(rhs);
    if lhs <= rhs {
        format!("{op}:{lhs}:{rhs}")
    } else {
        format!("{op}:{rhs}:{lhs}")
    }
}

fn quotient_op_len(bytes: &[u8], idx: usize) -> usize {
    match bytes[idx] {
        Q_OP_PUSH_CONST | Q_OP_FOLD_SELECTOR | Q_OP_ADD_CONST | Q_OP_MUL_CONST
        | Q_OP_PUSH_MEM_U16 | Q_OP_ADD_MEM_U16 | Q_OP_MUL_MEM_U16 | Q_OP_PUSH_TEMP
        | Q_OP_STORE_TEMP | Q_OP_NATIVE_IDENTITY => 3,
        Q_OP_PUSH_MEM_LITERAL => 5,
        Q_OP_PUSH_MEM_TOKEN => 2,
        Q_OP_PUSH_MEM_TOKEN_OFFSET => 6,
        Q_OP_PUSH_CONST_U8 | Q_OP_ADD_CONST_U8 | Q_OP_MUL_CONST_U8 => 2,
        Q_OP_ADD | Q_OP_MUL | Q_OP_NEG | Q_OP_FOLD_MAIN | Q_OP_NATIVE_PERMUTATION => 1,
        Q_OP_ADD_MUL_MEM_MEM_CONST_U8 => 6,
        Q_OP_ADD_MUL_CONST_U8_MEM_U16 => 4,
        Q_OP_ADD_MUL_MEM_MEM => 5,
        op => panic!("unknown quotient op {op:#x} at byte {idx}"),
    }
}

fn quotient_leaf(expr: &QuotientExpr) -> Option<QuotientLeaf> {
    match expr {
        QuotientExpr::Const(value) => Some(QuotientLeaf::Const(*value)),
        QuotientExpr::Mem(mem) => Some(QuotientLeaf::Mem(*mem)),
        QuotientExpr::Add(_, _) | QuotientExpr::Mul(_, _) | QuotientExpr::Neg(_) => None,
    }
}

fn collect_product_leaves(expr: &QuotientExpr, leaves: &mut Vec<QuotientLeaf>) -> bool {
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

fn parse_mem(ptr: &str) -> QuotientMem {
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

fn is_literal(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("0x")
        || value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit())
}

fn parse_u256(value: &str) -> U256 {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        U256::from_str_radix(hex, 16)
            .unwrap_or_else(|err| panic!("valid hex U256 `{value}`: {err:?}"))
    } else {
        U256::from_str_radix(value, 10)
            .unwrap_or_else(|err| panic!("valid decimal U256 `{value}`: {err:?}"))
    }
}

fn u256_string(value: U256) -> String {
    if value.bit_len() < 64 {
        format!("0x{:x}", value.as_limbs()[0])
    } else {
        format!("0x{value:x}")
    }
}

fn parse_u32_literal(value: &str) -> Option<u32> {
    if !is_literal(value) {
        return None;
    }
    let parsed = parse_u256(value);
    parsed.try_into().ok()
}

fn parse_usize_literal(value: &str) -> Option<usize> {
    if !is_literal(value) {
        return None;
    }
    let parsed = parse_u256(value);
    parsed.try_into().ok()
}

fn mem_token(name: &str) -> Option<u8> {
    Some(match name {
        "L_0_MPTR" => Q_MEM_L0,
        "L_LAST_MPTR" => Q_MEM_L_LAST,
        "L_BLIND_MPTR" => Q_MEM_L_BLIND,
        "BETA_MPTR" => Q_MEM_BETA,
        "GAMMA_MPTR" => Q_MEM_GAMMA,
        "X_MPTR" => Q_MEM_X,
        "THETA_MPTR" => Q_MEM_THETA,
        "TRASH_CHALLENGE_MPTR" => Q_MEM_TRASH_CHALLENGE,
        "INSTANCE_EVAL_MPTR" => Q_MEM_INSTANCE_EVAL,
        _ => return None,
    })
}

fn yul_let_assignment(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let line = line.strip_prefix("let ")?;
    let (dst, expr) = line.split_once(" := ")?;
    Some((dst.trim().to_string(), expr.trim().to_string()))
}

fn yul_const_value(value: &str, const_vars: &HashMap<String, String>) -> Option<String> {
    let value = value.trim();
    if is_literal(value) {
        Some(u256_string(parse_u256(value)))
    } else {
        const_vars.get(value).cloned()
    }
}

fn yul_mulmod_assignment(line: &str) -> Option<(String, String, String)> {
    let (dst, expr) = yul_let_assignment(line)?;
    let args = call_args(&expr, "mulmod")?;
    if args.len() == 3 && args[2].trim() == "r" {
        Some((dst, args[0].trim().to_string(), args[1].trim().to_string()))
    } else {
        None
    }
}

fn yul_addmod_assignment(line: &str) -> Option<(String, String, String)> {
    let (dst, expr) = yul_let_assignment(line)?;
    let args = call_args(&expr, "addmod")?;
    if args.len() == 3 && args[2].trim() == "r" {
        Some((dst, args[0].trim().to_string(), args[1].trim().to_string()))
    } else {
        None
    }
}

fn yul_mload_literal_assignment(line: &str) -> Option<(String, usize)> {
    let (dst, expr) = yul_let_assignment(line)?;
    Some((dst, yul_mload_literal_expr(&expr)?))
}

fn yul_mload_literal_expr(expr: &str) -> Option<usize> {
    let args = call_args(expr.trim(), "mload")?;
    if args.len() == 1 {
        parse_usize_literal(args[0].trim())
    } else {
        None
    }
}

fn yul_sub_r_assignment(line: &str) -> Option<(String, String)> {
    let (dst, expr) = yul_let_assignment(line)?;
    let args = call_args(&expr, "sub")?;
    if args.len() == 2 && args[0].trim() == "r" {
        Some((dst, args[1].trim().to_string()))
    } else {
        None
    }
}

fn call_args(expr: &str, name: &str) -> Option<Vec<String>> {
    let prefix = format!("{name}(");
    if !expr.starts_with(&prefix) || !expr.ends_with(')') {
        return None;
    }
    Some(split_top_level(&expr[prefix.len()..expr.len() - 1]))
}

fn split_top_level(input: &str) -> Vec<String> {
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

impl<'a> SolidityGenerator<'a> {
    /// Return a new `SolidityGenerator`.
    pub fn new(
        params: &'a ParamsKZG<Bls12>,
        vk: &'a VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
        scheme: BatchOpenScheme,
        num_instances: usize,
    ) -> Self {
        assert_ne!(vk.cs().num_advice_columns(), 0);
        // midnight-proofs ZkStdLib always allocates two instance columns
        // (one committed, one non-committed), so the v0.4 `<= 1`
        // tightness no longer applies. We accept up to 2 here and let
        // `set_num_committed_instances` handle the split.
        assert!(
            vk.cs().num_instance_columns() <= 2,
            "More than two instance columns is not yet implemented"
        );
        assert!(
            !vk.cs()
                .instance_queries()
                .iter()
                .any(|(_, rotation)| *rotation != Rotation::cur()),
            "Rotated query to instance column is not yet implemented"
        );

        let num_committed_instances = 0;
        let meta = ConstraintSystemMeta::new(vk.cs(), num_committed_instances);

        Self {
            params,
            vk,
            scheme,
            num_instances,
            num_committed_instances,
            acc_encoding: None,
            meta,
        }
    }

    /// Set `AccumulatorEncoding`.
    pub fn set_acc_encoding(mut self, acc_encoding: Option<AccumulatorEncoding>) -> Self {
        self.acc_encoding = acc_encoding;
        self
    }

    /// Number of instance columns committed to in the transcript (vs read
    /// from `instances` and Lagrange-interpolated locally). Surfacing the
    /// value here so that downstream callers (drivers, debugging
    /// examples) can configure committed-instance proofs without having
    /// to plumb through a constructor argument.
    pub fn set_num_committed_instances(mut self, n: usize) -> Self {
        self.num_committed_instances = n;
        self.meta = ConstraintSystemMeta::new(self.vk.cs(), n);
        self
    }

    /// Return the exact field-evaluation counts for the proof layout consumed
    /// by the generated Solidity verifier.
    pub fn proof_evaluation_counts(&self) -> ProofEvaluationCounts {
        let proof_cptr = Ptr::calldata(0x64);
        let vk = self.generate_vk();
        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));
        let (meta, _) = self.meta_data_for_vk(&vk, vk_mptr, proof_cptr);

        let committed_instance = meta
            .instance_queries
            .iter()
            .filter(|(col, _)| *col < meta.num_committed_instances)
            .count();
        let computed_instance = meta.instance_queries.len() - committed_instance;
        let permutation_product = if meta.num_permutation_zs == 0 {
            0
        } else {
            3 * meta.num_permutation_zs - 1
        };
        let lookup_helper = meta.lookup_chunks.iter().sum();

        let counts = ProofEvaluationCounts {
            committed_instance,
            computed_instance,
            advice: meta.advice_queries.len(),
            fixed: meta.num_fixeds - meta.num_simple_selectors,
            simple_selector_fixed: meta.num_simple_selectors,
            permutation_common: meta.permutation_columns.len(),
            permutation_product,
            permutation_sets: meta.num_permutation_zs,
            lookup_multiplicity: meta.num_lookups,
            lookup_helper,
            lookup_accumulator: 2 * meta.num_lookups,
            trash: meta.num_trashcans,
            dummy: meta.num_dummy_evals,
        };

        assert_eq!(
            counts.proof_total(),
            meta.num_evals,
            "proof evaluation count accounting must match verifier proof layout"
        );
        counts
    }
}

impl<'a> SolidityGenerator<'a> {
    /// Render `Halo2Verifier.sol` with verifying key embedded into writer.
    ///
    /// The default render path emits trace/log branches when the crate
    /// is compiled with `--features solidity-trace`, and LOG1 gas
    /// checkpoints when compiled with `--features
    /// solidity-gas-checkpoints`.
    pub fn render_into(&self, verifier_writer: &mut impl fmt::Write) -> Result<(), fmt::Error> {
        self.generate_verifier(
            false,
            crate::SOLIDITY_TRACE_ENABLED,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            false,
            None,
        )
        .render(verifier_writer)
    }

    /// Render `Halo2Verifier.sol` with verifying key embedded and return it as `String`.
    pub fn render(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render a trace-enabled `Halo2Verifier.sol` with verifying key embedded into writer.
    pub fn render_trace_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            false,
            true,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            false,
            None,
        )
        .render(verifier_writer)
    }

    /// Render a trace-enabled `Halo2Verifier.sol` with verifying key embedded and return it as a
    /// `String`.
    pub fn render_trace(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_trace_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` (with VK
    /// embedded) into writer. Emits LOG1 events at section boundaries
    /// regardless of the `solidity-gas-checkpoints` feature flag.
    pub fn render_with_gas_checkpoints_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(false, crate::SOLIDITY_TRACE_ENABLED, true, false, None)
            .render(verifier_writer)
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` (with VK
    /// embedded) and return it as `String`.
    pub fn render_with_gas_checkpoints(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_with_gas_checkpoints_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` into writers.
    ///
    /// The default render path emits trace/log branches when the crate
    /// is compiled with `--features solidity-trace`, and LOG1 gas
    /// checkpoints when compiled with `--features
    /// solidity-gas-checkpoints`.
    pub fn render_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            true,
            crate::SOLIDITY_TRACE_ENABLED,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            false,
            None,
        )
        .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        Ok(())
    }

    /// Render `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` and return them as `String`.
    pub fn render_separately(&self) -> Result<(String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        self.render_separately_into(&mut verifier_output, &mut vk_output)?;
        Ok((verifier_output, vk_output))
    }

    /// Render `Halo2Verifier.sol`, `Halo2VerifyingKey.sol`, and a linked
    /// `Halo2QuotientEvaluator.sol`.
    ///
    /// External quotient evaluators are correctness-critical. Production
    /// callers must first render/compile/deploy the quotient evaluator, then
    /// call [`render_separately_with_pinned_quotient_into`] with its runtime
    /// length and codehash.
    #[deprecated(
        note = "external quotient evaluators must be pinned; use render_quotient_evaluator_into + render_separately_with_pinned_quotient_into"
    )]
    pub fn render_separately_with_quotient_into(
        &self,
        _verifier_writer: &mut impl fmt::Write,
        _vk_writer: &mut impl fmt::Write,
        _quotient_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        panic!(
            "external quotient evaluator render requires a generated runtime length/codehash; \
             render the quotient evaluator first, compile/deploy it, then call \
             render_separately_with_pinned_quotient_into"
        );
    }

    /// Render `Halo2Verifier.sol`, `Halo2VerifyingKey.sol`, and
    /// `Halo2QuotientEvaluator.sol` and return them as `String`s.
    #[deprecated(
        note = "external quotient evaluators must be pinned; use render_quotient_evaluator + render_separately_with_pinned_quotient"
    )]
    pub fn render_separately_with_quotient(&self) -> Result<(String, String, String), fmt::Error> {
        panic!(
            "external quotient evaluator render requires a generated runtime length/codehash; \
             render the quotient evaluator first, compile/deploy it, then call \
             render_separately_with_pinned_quotient"
        );
    }

    /// Render a trace-enabled `Halo2Verifier.sol`, `Halo2VerifyingKey.sol`,
    /// and linked `Halo2QuotientEvaluator.sol`.
    ///
    /// External quotient evaluators must be pinned even in trace builds.
    /// Use [`render_trace_separately_with_pinned_quotient_into`].
    #[deprecated(
        note = "external quotient evaluators must be pinned; use render_trace_separately_with_pinned_quotient_into"
    )]
    pub fn render_trace_separately_with_quotient_into(
        &self,
        _verifier_writer: &mut impl fmt::Write,
        _vk_writer: &mut impl fmt::Write,
        _quotient_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        panic!(
            "trace external quotient evaluator render requires a generated runtime length/codehash; \
             render the quotient evaluator first, compile/deploy it, then call \
             render_trace_separately_with_pinned_quotient_into"
        );
    }

    /// Render a trace-enabled split verifier/VK/quotient trio and return
    /// them as `String`s.
    #[deprecated(
        note = "external quotient evaluators must be pinned; use render_trace_separately_with_pinned_quotient"
    )]
    pub fn render_trace_separately_with_quotient(
        &self,
    ) -> Result<(String, String, String), fmt::Error> {
        panic!(
            "trace external quotient evaluator render requires a generated runtime length/codehash; \
             render the quotient evaluator first, compile/deploy it, then call \
             render_trace_separately_with_pinned_quotient"
        );
    }

    /// Render only `Halo2QuotientEvaluator.sol`. Production deployment
    /// tooling can compile/deploy this first, compute its runtime length and
    /// codehash, then render a verifier with
    /// [`render_separately_with_pinned_quotient_into`].
    pub fn render_quotient_evaluator_into(
        &self,
        quotient_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_quotient_evaluator().render(quotient_writer)
    }

    /// Render only `Halo2QuotientEvaluator.sol` and return it as a `String`.
    pub fn render_quotient_evaluator(&self) -> Result<String, fmt::Error> {
        let mut quotient_output = String::new();
        self.render_quotient_evaluator_into(&mut quotient_output)?;
        Ok(quotient_output)
    }

    /// Render `Halo2Verifier.sol`, `Halo2VerifyingKey.sol`, and
    /// `Halo2QuotientEvaluator.sol`, with the verifier hard-pinned to the
    /// supplied quotient evaluator runtime length and codehash.
    pub fn render_separately_with_pinned_quotient_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
        quotient_writer: &mut impl fmt::Write,
        expected_quotient_len: usize,
        expected_quotient_codehash: U256,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            true,
            crate::SOLIDITY_TRACE_ENABLED,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            true,
            Some((expected_quotient_len, expected_quotient_codehash)),
        )
        .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        self.generate_quotient_evaluator().render(quotient_writer)?;
        Ok(())
    }

    /// Render the separated verifier/VK/quotient sources with a hard-pinned
    /// quotient evaluator.
    pub fn render_separately_with_pinned_quotient(
        &self,
        expected_quotient_len: usize,
        expected_quotient_codehash: U256,
    ) -> Result<(String, String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        let mut quotient_output = String::new();
        self.render_separately_with_pinned_quotient_into(
            &mut verifier_output,
            &mut vk_output,
            &mut quotient_output,
            expected_quotient_len,
            expected_quotient_codehash,
        )?;
        Ok((verifier_output, vk_output, quotient_output))
    }

    /// Render a trace-enabled separated verifier/VK/quotient trio with the
    /// verifier hard-pinned to the supplied quotient evaluator runtime length
    /// and codehash.
    pub fn render_trace_separately_with_pinned_quotient_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
        quotient_writer: &mut impl fmt::Write,
        expected_quotient_len: usize,
        expected_quotient_codehash: U256,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            true,
            true,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            true,
            Some((expected_quotient_len, expected_quotient_codehash)),
        )
        .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        self.generate_quotient_evaluator().render(quotient_writer)?;
        Ok(())
    }

    /// Render a trace-enabled separated verifier/VK/quotient trio with a
    /// hard-pinned quotient evaluator.
    pub fn render_trace_separately_with_pinned_quotient(
        &self,
        expected_quotient_len: usize,
        expected_quotient_codehash: U256,
    ) -> Result<(String, String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        let mut quotient_output = String::new();
        self.render_trace_separately_with_pinned_quotient_into(
            &mut verifier_output,
            &mut vk_output,
            &mut quotient_output,
            expected_quotient_len,
            expected_quotient_codehash,
        )?;
        Ok((verifier_output, vk_output, quotient_output))
    }

    /// Render a trace-enabled `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` into writers.
    pub fn render_trace_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            true,
            true,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            false,
            None,
        )
        .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        Ok(())
    }

    /// Render a trace-enabled `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` and return them as
    /// `String`s.
    pub fn render_trace_separately(&self) -> Result<(String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        self.render_trace_separately_into(&mut verifier_output, &mut vk_output)?;
        Ok((verifier_output, vk_output))
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` and
    /// `Halo2VerifyingKey.sol` into writers. Emits LOG1 events at
    /// section boundaries regardless of the
    /// `solidity-gas-checkpoints` feature flag.
    pub fn render_with_gas_checkpoints_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(true, crate::SOLIDITY_TRACE_ENABLED, true, false, None)
            .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        Ok(())
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` and
    /// `Halo2VerifyingKey.sol` and return them as `String`s.
    pub fn render_with_gas_checkpoints_separately(&self) -> Result<(String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        self.render_with_gas_checkpoints_separately_into(&mut verifier_output, &mut vk_output)?;
        Ok((verifier_output, vk_output))
    }

    fn generate_base_vk(&self) -> Halo2VerifyingKey {
        let mut constants: Vec<(&'static str, U256)> = Vec::new();
        {
            let domain = self.vk.get_domain();
            // BLS12-381 scalar Fq is 32 bytes wide (256 bits) so the same
            // little-endian-to-u256 conversion that worked for BN254 Fr
            // also works here: the verifier reads each scalar from
            // calldata into a single 32-byte word.
            let vk_digest = fe_to_u256::<Fq>(&self.vk.transcript_repr());
            let num_instances = U256::from(self.num_instances);
            let k = U256::from(domain.k());
            let n_inv = fe_to_u256::<Fq>(&Fq::from(1u64 << domain.k()).invert().unwrap());
            let omega = fe_to_u256::<Fq>(&domain.get_omega());
            let omega_inv = fe_to_u256::<Fq>(&domain.get_omega_inv());
            let omega_inv_to_l = {
                let l = self.meta.rotation_last.unsigned_abs() as u64;
                fe_to_u256::<Fq>(&domain.get_omega_inv().pow_vartime([l]))
            };
            let has_accumulator = U256::from(self.acc_encoding.is_some() as usize);
            let acc_offset = self
                .acc_encoding
                .map(|acc_encoding| U256::from(acc_encoding.offset))
                .unwrap_or_default();
            let num_acc_limbs = self
                .acc_encoding
                .map(|acc_encoding| U256::from(acc_encoding.num_limbs))
                .unwrap_or_default();
            let num_acc_limb_bits = self
                .acc_encoding
                .map(|acc_encoding| U256::from(acc_encoding.num_limb_bits))
                .unwrap_or_default();
            // EIP-2537 padded encodings come from `g1_to_u256s` / `g2_to_u256s`
            // (4 / 8 u256 words respectively). We cannot read `params.g[0]`
            // directly (the field is crate-private in midnight-proofs), so
            // we use the canonical BLS12-381 generator.
            let g1_pt: G1Affine = G1Affine::generator();
            let g2_pt: G2Affine = self.params.g2().to_affine();
            let neg_s_g2_pt: G2Affine = (-self.params.s_g2()).to_affine();
            let g1 = g1_to_u256s(&g1_pt);
            let g2 = g2_to_u256s(&g2_pt);
            let neg_s_g2 = g2_to_u256s(&neg_s_g2_pt);

            constants.extend([
                ("vk_digest", vk_digest),
                ("num_instances", num_instances),
                ("k", k),
                ("n_inv", n_inv),
                ("omega", omega),
                ("omega_inv", omega_inv),
                ("omega_inv_to_l", omega_inv_to_l),
                ("has_accumulator", has_accumulator),
                ("acc_offset", acc_offset),
                ("num_acc_limbs", num_acc_limbs),
                ("num_acc_limb_bits", num_acc_limb_bits),
            ]);
            constants.extend([
                ("g1_x_hi", g1[0]),
                ("g1_x_lo", g1[1]),
                ("g1_y_hi", g1[2]),
                ("g1_y_lo", g1[3]),
            ]);
            constants.extend([
                ("g2_x_c0_hi", g2[0]),
                ("g2_x_c0_lo", g2[1]),
                ("g2_x_c1_hi", g2[2]),
                ("g2_x_c1_lo", g2[3]),
                ("g2_y_c0_hi", g2[4]),
                ("g2_y_c0_lo", g2[5]),
                ("g2_y_c1_hi", g2[6]),
                ("g2_y_c1_lo", g2[7]),
            ]);
            constants.extend([
                ("neg_s_g2_x_c0_hi", neg_s_g2[0]),
                ("neg_s_g2_x_c0_lo", neg_s_g2[1]),
                ("neg_s_g2_x_c1_hi", neg_s_g2[2]),
                ("neg_s_g2_x_c1_lo", neg_s_g2[3]),
                ("neg_s_g2_y_c0_hi", neg_s_g2[4]),
                ("neg_s_g2_y_c0_lo", neg_s_g2[5]),
                ("neg_s_g2_y_c1_hi", neg_s_g2[6]),
                ("neg_s_g2_y_c1_lo", neg_s_g2[7]),
            ]);
        }

        // Convert each commitment from G1Projective to G1Affine before
        // EIP-2537 packing.
        let to_affine = |g: &G1Projective| -> G1Affine { g.to_affine() };
        let fixed_comms = chain![self.vk.fixed_commitments()]
            .map(to_affine)
            .map(g1_to_u256s)
            .map(|[a, b, c, d]| (a, b, c, d))
            .collect();
        let permutation_comms = chain![self.vk.permutation().commitments()]
            .map(to_affine)
            .map(g1_to_u256s)
            .map(|[a, b, c, d]| (a, b, c, d))
            .collect();
        Halo2VerifyingKey {
            constants,
            fixed_comms,
            permutation_comms,
            quotient_const_offset_words: None,
            quotient_const_words: 0,
            quotient_program_offset_words: None,
            quotient_program_words: 0,
        }
    }

    fn generate_vk(&self) -> Halo2VerifyingKey {
        let proof_cptr = Ptr::calldata(0x64);
        let mut vk = self.generate_base_vk();
        if quotient_inline_cse_enabled() || quotient_structured_loops_enabled() {
            return vk;
        }

        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));

        let (pre_meta, pre_data) = self.meta_data_for_vk(&vk, vk_mptr, proof_cptr);
        let (pre_quotient_program_build, _) =
            self.compact_quotient_program_for(&pre_meta, &pre_data);
        let quotient_const_words = pre_quotient_program_build.consts.len();
        let quotient_program_words = Self::program_chunks(&pre_quotient_program_build.bytes).len();
        let quotient_const_offset_words = vk.constants.len();
        let quotient_program_offset_words = quotient_const_offset_words + quotient_const_words;

        vk.constants
            .extend((0..quotient_const_words).map(|_| ("quotient_const", U256::ZERO)));
        vk.constants
            .extend((0..quotient_program_words).map(|_| ("quotient_program", U256::ZERO)));

        let (meta, data) = self.meta_data_for_vk(&vk, vk_mptr, proof_cptr);
        let (quotient_program_build, _) = self.compact_quotient_program_for(&meta, &data);
        let quotient_program_chunks = Self::program_chunks(&quotient_program_build.bytes);
        assert_eq!(
            quotient_program_build.consts.len(),
            quotient_const_words,
            "quotient const table changed after VK payload reservation"
        );
        assert_eq!(
            quotient_program_chunks.len(),
            quotient_program_words,
            "quotient program length changed after VK payload reservation"
        );

        for (i, value) in quotient_program_build.consts.iter().copied().enumerate() {
            vk.constants[quotient_const_offset_words + i] = ("quotient_const", value);
        }
        for (i, value) in quotient_program_chunks.iter().copied().enumerate() {
            vk.constants[quotient_program_offset_words + i] = ("quotient_program", value);
        }

        vk.quotient_const_offset_words = Some(quotient_const_offset_words);
        vk.quotient_const_words = quotient_const_words;
        vk.quotient_program_offset_words = Some(quotient_program_offset_words);
        vk.quotient_program_words = quotient_program_words;
        vk
    }

    fn meta_data_for_vk(
        &self,
        vk: &Halo2VerifyingKey,
        vk_mptr: Ptr,
        proof_cptr: Ptr,
    ) -> (ConstraintSystemMeta, Data) {
        // ------------------------------------------------------------------
        // Phase 3 / outer-fewer-point-sets two-pass `Data` construction.
        //
        // Pass 1: build `Data` against the *raw* meta (no dummy evals).
        //   This gives us the raw query list whose commitment identity
        //   structure feeds `compute_dummy_queries`.
        //
        // Pass 2: bump meta.num_evals by the dummy count (so the
        //   memory layout - REVERSED_EVALS_MPTR buffer + downstream
        //   comms_mptr_base - grows to fit the dummies), rebuild Data,
        //   and populate the dummy eval Words.
        //
        // When the `outer-fewer-point-sets` Cargo feature is OFF, the dummy
        // count is forced to zero; pass 2 collapses to "rebuild Data
        // against unchanged meta", and the result is byte-identical
        // to the pre-Phase-3 single-pass path.
        // ------------------------------------------------------------------
        let raw_data = Data::new(&self.meta, vk, vk_mptr, proof_cptr);
        let mut meta = self.meta.clone();
        let n_dummy = if cfg!(feature = "outer-fewer-point-sets") {
            BatchOpenScheme::num_dummy_queries(&meta, &raw_data)
        } else {
            0
        };
        let main_evals = meta.num_evals;
        meta.set_num_dummy_evals(n_dummy);
        let mut data = Data::new(&meta, vk, vk_mptr, proof_cptr);
        if n_dummy > 0 {
            data.set_dummy_eval_words(main_evals, n_dummy);
        }

        meta.set_num_point_sets(BatchOpenScheme::num_point_sets(&meta, &data));
        (meta, data)
    }

    fn compact_quotient_program_for(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
    ) -> (QuotientProgramBuild, Vec<usize>) {
        let plan = self.quotient_program_plan(meta, data);
        let sorted_simple = plan.sorted_simple.clone();
        let quotient_program_build = self.build_quotient_program_items(&plan.items);
        let _quotient_max_stack = quotient_program_build.max_stack;
        (quotient_program_build, sorted_simple)
    }

    fn quotient_program_plan(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
    ) -> QuotientProgramPlan {
        let parts = self.quotient_identity_parts(meta, data);
        let inline_count = hybrid_quotient_inline_count(&parts.gates);
        let inline_identities = parts.gates[..inline_count].to_vec();
        let remaining_gates = &parts.gates[inline_count..];
        let native_gate_indices = Self::native_gate_indices(remaining_gates);
        let native_permutation =
            quotient_native_permutation_enabled() && meta.num_permutation_zs > 0;
        let structured_trash_tail = quotient_structured_tail_mode()
            == QuotientStructuredTailMode::Trash
            && meta.num_trashcans > 0;

        let mut items = Vec::with_capacity(
            remaining_gates.len()
                + parts.permutation.len()
                + parts.lookup.len()
                + parts.trash.len()
                + usize::from(native_permutation),
        );
        let mut native_identities = Vec::with_capacity(native_gate_indices.len());
        for (gate_idx, identity) in remaining_gates.iter().enumerate() {
            if native_gate_indices.contains(&gate_idx) {
                let native_idx = native_identities.len();
                native_identities.push(identity.clone());
                items.push(QuotientProgramItem::NativeIdentity(native_idx));
            } else {
                items.push(QuotientProgramItem::Identity(identity.clone()));
            }
        }

        if native_permutation {
            items.push(QuotientProgramItem::NativePermutation);
        } else {
            items.extend(
                parts
                    .permutation
                    .iter()
                    .cloned()
                    .map(QuotientProgramItem::Identity),
            );
        }
        items.extend(
            parts
                .lookup
                .iter()
                .cloned()
                .map(QuotientProgramItem::Identity),
        );
        if !structured_trash_tail {
            items.extend(
                parts
                    .trash
                    .iter()
                    .cloned()
                    .map(QuotientProgramItem::Identity),
            );
        }

        QuotientProgramPlan {
            inline_identities,
            items,
            native_identities,
            sorted_simple: parts.sorted_simple,
            has_native_permutation: native_permutation,
        }
    }

    fn native_gate_indices(gates: &[QuotientIdentity]) -> HashSet<usize> {
        let count = quotient_native_gate_count(gates);
        if count == 0 {
            return HashSet::new();
        }

        let mut costs = gates
            .iter()
            .enumerate()
            .map(|(idx, identity)| (Self::quotient_identity_program_cost(identity), idx))
            .collect::<Vec<_>>();
        costs.sort_by(|(lhs_cost, lhs_idx), (rhs_cost, rhs_idx)| {
            rhs_cost.cmp(lhs_cost).then_with(|| lhs_idx.cmp(rhs_idx))
        });
        costs.into_iter().take(count).map(|(_, idx)| idx).collect()
    }

    fn quotient_external_frame(
        vk_mptr: Ptr,
        vk_len: usize,
        meta: &ConstraintSystemMeta,
        data: &Data,
        simple_selector_count: usize,
    ) -> QuotientExternal {
        let frame_base = vk_mptr.value().as_usize();
        Self::quotient_external_frame_from_bounds(
            frame_base,
            vk_len,
            data.reversed_evals_mptr.value().as_usize(),
            meta.num_evals,
            simple_selector_count,
        )
    }

    fn quotient_external_frame_from_bounds(
        frame_base: usize,
        vk_len: usize,
        evals_base: usize,
        num_evals: usize,
        simple_selector_count: usize,
    ) -> QuotientExternal {
        let vk_end = frame_base + vk_len;
        let evals_end = evals_base + num_evals * 0x20;
        let frame_end = vk_end.max(evals_end);
        QuotientExternal {
            frame_base,
            frame_len: frame_end - frame_base,
            output_len: 0x40 + simple_selector_count * 0x20,
            magic: QUOTIENT_EXTERNAL_MAGIC,
        }
    }

    fn quotient_identity_program_cost(identity: &QuotientIdentity) -> usize {
        let mut builder = QuotientProgramBuilder::default();
        let expr = Self::quotient_identity_expr(identity);
        builder.identity_expr(&expr, identity.target, None);
        builder.bytes.len()
    }

    fn quotient_identity_parts(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
    ) -> QuotientIdentityParts {
        let evaluator = Evaluator::new(self.vk.cs(), meta, data);
        let gate_items = evaluator.gate_computations_tagged();
        let gate_exprs = self
            .vk
            .cs()
            .gates()
            .iter()
            .flat_map(|gate| gate.polynomials().iter())
            .map(|poly| Self::quotient_expr_from_plonk_expr(meta, data, poly))
            .collect::<Vec<_>>();
        assert_eq!(
            gate_items.len(),
            gate_exprs.len(),
            "gate Yul expressions and typed expressions must stay aligned"
        );
        let perm_items = evaluator.permutation_computations();
        let lookup_items = evaluator.lookup_computations();
        let trash_items = evaluator.trashcan_computations();

        let mut sorted_simple: Vec<usize> = meta.simple_selector_cols.iter().copied().collect();
        sorted_simple.sort_unstable();

        let mut gates = Vec::with_capacity(gate_items.len());
        for ((lines, var, sel_idx), expr) in gate_items.into_iter().zip(gate_exprs) {
            let target = match sel_idx {
                Some(col) => {
                    let idx = sorted_simple
                        .iter()
                        .position(|simple| *simple == col)
                        .expect("selector column present");
                    QuotientTarget::Selector(idx)
                }
                None => QuotientTarget::Main,
            };
            gates.push(QuotientIdentity {
                lines,
                var,
                target,
                expr: Some(expr),
            });
        }
        let mut permutation = Vec::with_capacity(perm_items.len());
        for (lines, var) in perm_items {
            permutation.push(QuotientIdentity {
                lines,
                var,
                target: QuotientTarget::Main,
                expr: None,
            });
        }
        let mut lookup = Vec::with_capacity(lookup_items.len());
        for (lines, var) in lookup_items {
            lookup.push(QuotientIdentity {
                lines,
                var,
                target: QuotientTarget::Main,
                expr: None,
            });
        }
        let mut trash = Vec::with_capacity(trash_items.len());
        for (lines, var) in trash_items {
            trash.push(QuotientIdentity {
                lines,
                var,
                target: QuotientTarget::Main,
                expr: None,
            });
        }

        assert_eq!(
            gates.len(),
            meta.protocol.quotient.gates,
            "gate identity count must match protocol plan"
        );
        assert_eq!(
            permutation.len(),
            meta.protocol.quotient.permutation,
            "permutation identity count must match protocol plan"
        );
        assert_eq!(
            lookup.len(),
            meta.protocol.quotient.lookup,
            "lookup identity count must match protocol plan"
        );
        assert_eq!(
            trash.len(),
            meta.protocol.quotient.trash,
            "trash identity count must match protocol plan"
        );

        QuotientIdentityParts {
            gates,
            permutation,
            lookup,
            trash,
            sorted_simple,
        }
    }

    fn quotient_identity_expr(identity: &QuotientIdentity) -> QuotientExpr {
        if let Some(expr) = &identity.expr {
            return expr.clone();
        }
        Self::quotient_identity_yul_expr(identity)
    }

    fn quotient_identity_yul_expr(identity: &QuotientIdentity) -> QuotientExpr {
        let mut parser = QuotientProgramBuilder::default();
        for line in &identity.lines {
            parser.assignment(line);
        }
        parser.parse_expr(&identity.var)
    }

    fn quotient_expr_from_plonk_expr(
        meta: &ConstraintSystemMeta,
        data: &Data,
        expression: &Expression<Fq>,
    ) -> QuotientExpr {
        quotient_expr_from_expression(&DataQuotientExpressionEnv { meta, data }, expression)
    }

    fn inline_cse_quotient_computations(
        identities: &[QuotientIdentity],
        sorted_simple: &[usize],
        cse_mptr: usize,
        helpers: bool,
    ) -> Vec<Vec<String>> {
        let sel_var = |idx: usize| format!("sel_acc_{}", sorted_simple[idx]);
        let exprs = identities
            .iter()
            .map(Self::quotient_identity_yul_expr)
            .collect::<Vec<_>>();
        let plan = QuotientInlineCsePlan::new(&exprs);
        let eval_scratch_slot = cse_mptr + plan.slots.len() * 0x20;
        let mut emitter = QuotientInlineCseEmitter::new(&plan, cse_mptr, helpers);
        let mut computations = Vec::new();

        let mut init_lines = Vec::new();
        init_lines.push("let quotient_eval_numer := 0".to_string());
        for idx in 0..sorted_simple.len() {
            init_lines.push(format!("let {} := 0", sel_var(idx)));
        }
        computations.push(init_lines);

        for (identity, expr) in identities.iter().zip(exprs.iter()) {
            let mut block = Vec::with_capacity(identity.lines.len() + 8 + sorted_simple.len());
            block.push("{".to_string());
            let value = emitter.emit_identity(expr, &mut block);
            block.push(format!("mstore({eval_scratch_slot:#x}, {value})"));
            block.push("}".to_string());
            block.push("quotient_eval_numer := mulmod(quotient_eval_numer, y, r)".to_string());
            for idx in 0..sorted_simple.len() {
                block.push(format!(
                    "{name} := mulmod({name}, y, r)",
                    name = sel_var(idx)
                ));
            }
            let target = match identity.target {
                QuotientTarget::Selector(idx) => sel_var(idx),
                QuotientTarget::Main => "quotient_eval_numer".to_string(),
            };
            block.push(format!(
                "{target} := addmod({target}, mload({eval_scratch_slot:#x}), r)"
            ));
            computations.push(block);
        }

        if !sorted_simple.is_empty() {
            let mut tail = Vec::new();
            for i in 0..sorted_simple.len() {
                tail.push(format!(
                    "mstore(add(SELECTOR_ACC_MPTR, {:#x}), {})",
                    i * 0x20,
                    sel_var(i)
                ));
            }
            computations.push(tail);
        }

        computations
    }

    fn direct_quotient_block(
        lines: &[String],
        var: &str,
        target: QuotientTarget,
        sorted_simple: &[usize],
        eval_scratch_slot: usize,
    ) -> Vec<String> {
        let mut block = Vec::with_capacity(lines.len() + 6);
        block.push("{".to_string());
        let lines = Self::specialize_limb7_chains(lines);
        for line in &lines {
            block.push(line.clone());
        }
        block.push(format!("mstore({eval_scratch_slot:#x}, {var})"));
        block.push("}".to_string());
        block.push("quotient_eval_numer := mulmod(quotient_eval_numer, y, r)".to_string());
        if !sorted_simple.is_empty() {
            block.push("q_sel_scale := mulmod(q_sel_scale, y, r)".to_string());
            block.push("q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)".to_string());
        }
        match target {
            QuotientTarget::Main => {
                block.push(format!(
                    "quotient_eval_numer := addmod(quotient_eval_numer, mload({eval_scratch_slot:#x}), r)"
                ));
            }
            QuotientTarget::Selector(idx) => {
                let offset = idx * 0x20;
                block.push(format!(
                    "mstore(add(SELECTOR_ACC_MPTR, {offset:#x}), addmod(mload(add(SELECTOR_ACC_MPTR, {offset:#x})), mulmod(mload({eval_scratch_slot:#x}), q_sel_inv_scale, r), r))"
                ));
            }
        }
        block
    }

    fn push_structured_fold_advance(
        block: &mut Vec<String>,
        count: usize,
        sorted_simple: &[usize],
        loop_var: &str,
    ) {
        if count == 1 {
            block.push("quotient_eval_numer := mulmod(quotient_eval_numer, y, r)".to_string());
            if !sorted_simple.is_empty() {
                block.push("q_sel_scale := mulmod(q_sel_scale, y, r)".to_string());
                block.push("q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)".to_string());
            }
            return;
        }

        block.push(format!(
            "for {{ let {loop_var} := 0 }} lt({loop_var}, {count}) {{ {loop_var} := add({loop_var}, 1) }} {{"
        ));
        block.push("quotient_eval_numer := mulmod(quotient_eval_numer, y, r)".to_string());
        if !sorted_simple.is_empty() {
            block.push("q_sel_scale := mulmod(q_sel_scale, y, r)".to_string());
            block.push("q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)".to_string());
        }
        block.push("}".to_string());
    }

    fn push_mstore_mload_literal_runs(
        block: &mut Vec<String>,
        dst: &str,
        entries: &[(usize, String)],
        loop_prefix: &str,
    ) {
        let mut idx = 0usize;
        while idx < entries.len() {
            let (dst_base, expr) = &entries[idx];
            let Some(src_base) = yul_mload_literal_expr(expr) else {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            };
            let Some((next_dst, next_expr)) = entries.get(idx + 1) else {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            };
            if *next_dst != *dst_base + 0x20 {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            }
            let Some(next_src) = yul_mload_literal_expr(next_expr) else {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            };
            let Some(src_stride) = next_src.checked_sub(src_base) else {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            };
            if src_stride == 0 {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            }

            let mut count = 2usize;
            while let Some((candidate_dst, candidate_expr)) = entries.get(idx + count) {
                let Some(candidate_src) = yul_mload_literal_expr(candidate_expr) else {
                    break;
                };
                if *candidate_dst != *dst_base + count * 0x20
                    || candidate_src != src_base + count * src_stride
                {
                    break;
                }
                count += 1;
            }

            if count < 3 {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            }

            block.push("{".to_string());
            block.push(format!(
                "for {{ let {loop_prefix}_i := 0 }} lt({loop_prefix}_i, {count}) {{ {loop_prefix}_i := add({loop_prefix}_i, 1) }} {{"
            ));
            block.push(format!(
                "let {loop_prefix}_dst_off := shl(5, {loop_prefix}_i)"
            ));
            if src_stride == 0x20 {
                block.push(format!(
                    "let {loop_prefix}_src_off := {loop_prefix}_dst_off"
                ));
            } else {
                block.push(format!(
                    "let {loop_prefix}_src_off := mul({loop_prefix}_i, {src_stride:#x})"
                ));
            }
            block.push(format!(
                "mstore(add(add({dst}, {dst_base:#x}), {loop_prefix}_dst_off), mload(add({src_base:#x}, {loop_prefix}_src_off)))"
            ));
            block.push("}".to_string());
            block.push("}".to_string());
            idx += count;
        }
    }

    fn yul_pair_matches(lhs: &str, rhs: &str, a: &str, b: &str) -> bool {
        (lhs == a && rhs == b) || (lhs == b && rhs == a)
    }

    fn parse_selector_linear_next_identity(
        lines: &[String],
        final_var: &str,
    ) -> Option<(usize, usize, usize)> {
        if lines.len() != 8 {
            return None;
        }

        let (one_var, one) = yul_let_assignment(&lines[0])?;
        if parse_u256(one.trim()) != U256::from(1u8) {
            return None;
        }

        let (a_var, a_addr) = yul_mload_literal_assignment(&lines[1])?;
        let (f_var, f_addr) = yul_mload_literal_assignment(&lines[2])?;
        let (sum_var, lhs, rhs) = yul_addmod_assignment(&lines[3])?;
        if !Self::yul_pair_matches(&lhs, &rhs, &a_var, &f_var) {
            return None;
        }

        let (next_var, next_addr) = yul_mload_literal_assignment(&lines[4])?;
        let (neg_var, neg_arg) = yul_sub_r_assignment(&lines[5])?;
        if neg_arg != next_var {
            return None;
        }

        let (eval_var, lhs, rhs) = yul_addmod_assignment(&lines[6])?;
        if !Self::yul_pair_matches(&lhs, &rhs, &sum_var, &neg_var) {
            return None;
        }

        let (scaled_var, lhs, rhs) = yul_mulmod_assignment(&lines[7])?;
        if scaled_var != final_var || !Self::yul_pair_matches(&lhs, &rhs, &one_var, &eval_var) {
            return None;
        }

        Some((a_addr, f_addr, next_addr))
    }

    fn selector_linear_next_loop_block(
        run: &[(Vec<String>, String)],
    ) -> Option<(usize, Vec<String>)> {
        let (a_base, f_base, next_base) =
            Self::parse_selector_linear_next_identity(&run.first()?.0, &run.first()?.1)?;
        let mut count = 1usize;
        while let Some((lines, var)) = run.get(count) {
            let Some((a_addr, f_addr, next_addr)) =
                Self::parse_selector_linear_next_identity(lines, var)
            else {
                break;
            };
            let off = count * 0x20;
            if a_addr != a_base + off || f_addr != f_base + off || next_addr != next_base + off {
                break;
            }
            count += 1;
        }

        if count < 3 {
            return None;
        }

        let mut block = Vec::with_capacity(10);
        block.push("{".to_string());
        block.push(format!(
            "for {{ let q_gate_lin_i := 0 }} lt(q_gate_lin_i, {count}) {{ q_gate_lin_i := add(q_gate_lin_i, 1) }} {{"
        ));
        block.push("let q_gate_lin_off := shl(5, q_gate_lin_i)".to_string());
        block.push(format!(
            "let q_gate_lin_a := mload(add({a_base:#x}, q_gate_lin_off))"
        ));
        block.push(format!(
            "let q_gate_lin_f := mload(add({f_base:#x}, q_gate_lin_off))"
        ));
        block.push(format!(
            "let q_gate_lin_next := mload(add({next_base:#x}, q_gate_lin_off))"
        ));
        block.push(
            "let q_gate_lin_eval := addmod(addmod(q_gate_lin_a, q_gate_lin_f, r), sub(r, q_gate_lin_next), r)"
                .to_string(),
        );
        block
            .push("q_gate_run := addmod(mulmod(q_gate_run, y, r), q_gate_lin_eval, r)".to_string());
        block.push("}".to_string());
        block.push("}".to_string());
        Some((count, block))
    }

    fn push_selector_run_identity(
        block: &mut Vec<String>,
        lines: &[String],
        var: &str,
        eval_scratch_slot: usize,
    ) {
        block.push("{".to_string());
        let lines = Self::specialize_limb7_chains(lines);
        for line in &lines {
            block.push(line.clone());
        }
        block.push(format!("mstore({eval_scratch_slot:#x}, {var})"));
        block.push("}".to_string());
        block.push(format!(
            "q_gate_run := addmod(mulmod(q_gate_run, y, r), mload({eval_scratch_slot:#x}), r)"
        ));
    }

    fn selector_run_quotient_block(
        run: &[(Vec<String>, String)],
        selector_idx: usize,
        sorted_simple: &[usize],
        eval_scratch_slot: usize,
    ) -> Vec<String> {
        let capacity = run.iter().map(|(lines, _)| lines.len() + 5).sum::<usize>() + 10;
        let mut block = Vec::with_capacity(capacity);
        let offset = selector_idx * 0x20;

        block.push("{".to_string());
        block.push("let q_gate_run := 0".to_string());
        let mut idx = 0usize;
        while idx < run.len() {
            if let Some((consumed, mut loop_block)) =
                Self::selector_linear_next_loop_block(&run[idx..])
            {
                block.append(&mut loop_block);
                idx += consumed;
                continue;
            }
            let (lines, var) = &run[idx];
            Self::push_selector_run_identity(&mut block, lines, var, eval_scratch_slot);
            idx += 1;
        }
        Self::push_structured_fold_advance(&mut block, run.len(), sorted_simple, "q_gate_run_i");
        block.push(format!(
            "mstore(add(SELECTOR_ACC_MPTR, {offset:#x}), addmod(mload(add(SELECTOR_ACC_MPTR, {offset:#x})), mulmod(q_gate_run, q_sel_inv_scale, r), r))"
        ));
        block.push("}".to_string());
        block
    }

    fn flush_structured_selector_run(
        computations: &mut Vec<Vec<String>>,
        pending_selector: &mut Option<usize>,
        pending_run: &mut Vec<(Vec<String>, String)>,
        sorted_simple: &[usize],
        eval_scratch_slot: usize,
    ) {
        let Some(selector_idx) = pending_selector.take() else {
            return;
        };
        let run = std::mem::take(pending_run);
        if run.len() == 1 {
            let (lines, var) = run.into_iter().next().expect("selector run item");
            computations.push(Self::direct_quotient_block(
                &lines,
                &var,
                QuotientTarget::Selector(selector_idx),
                sorted_simple,
                eval_scratch_slot,
            ));
        } else if !run.is_empty() {
            computations.push(Self::selector_run_quotient_block(
                &run,
                selector_idx,
                sorted_simple,
                eval_scratch_slot,
            ));
        }
    }

    fn specialize_limb7_chains(lines: &[String]) -> Vec<String> {
        let mut out = Vec::with_capacity(lines.len());
        let mut const_vars = HashMap::new();
        let mut idx = 0usize;

        while idx < lines.len() {
            if let Some((consumed, replacement, updated_consts)) =
                Self::try_limb7_chain(&lines[idx..], &const_vars, &LIMB7_YUL_COEFFS, "q_limb7")
                    .or_else(|| {
                        Self::try_limb7_chain(
                            &lines[idx..],
                            &const_vars,
                            &WIDE_LIMB7_YUL_COEFFS,
                            "q_limb7_wide",
                        )
                    })
            {
                const_vars = updated_consts;
                out.extend(replacement);
                idx += consumed;
                continue;
            }

            Self::record_yul_const_assignment(&lines[idx], &mut const_vars);
            out.push(lines[idx].clone());
            idx += 1;
        }

        out
    }

    fn try_limb7_chain(
        lines: &[String],
        const_vars: &HashMap<String, String>,
        coeffs: &[&str; 6],
        helper_name: &str,
    ) -> Option<(usize, Vec<String>, HashMap<String, String>)> {
        let mut idx = 0usize;
        let mut keep = Vec::new();
        let mut args = Vec::with_capacity(7);
        let mut previous_acc: Option<String> = None;
        let mut local_consts = const_vars.clone();

        for (step, coeff) in coeffs.iter().enumerate() {
            let mut skipped = 0usize;
            let (mul_dst, mul_arg) = loop {
                if idx >= lines.len() || skipped > 4 {
                    return None;
                }

                if let Some((dst, arg)) =
                    Self::parse_limb7_mul_assignment(&lines[idx], coeff, &local_consts)
                {
                    break (dst, arg);
                }

                if yul_let_assignment(&lines[idx]).is_some() {
                    Self::record_yul_const_assignment(&lines[idx], &mut local_consts);
                    keep.push(lines[idx].clone());
                    idx += 1;
                    skipped += 1;
                } else {
                    return None;
                }
            };

            let (add_dst, lhs, rhs) = yul_addmod_assignment(lines.get(idx + 1)?)?;
            let addend = if lhs == mul_dst {
                rhs
            } else if rhs == mul_dst {
                lhs
            } else {
                return None;
            };

            if step == 0 {
                args.push(addend);
            } else if Some(addend.as_str()) != previous_acc.as_deref() {
                return None;
            }
            args.push(mul_arg);
            previous_acc = Some(add_dst);
            idx += 2;
        }

        let final_acc = previous_acc?;
        keep.push(format!(
            "let {final_acc} := {helper_name}({})",
            args.join(", ")
        ));
        Some((idx, keep, local_consts))
    }

    fn parse_limb7_mul_assignment(
        line: &str,
        expected_coeff: &str,
        const_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        let (dst, lhs, rhs) = yul_mulmod_assignment(line)?;
        if Self::yul_coeff_matches(&lhs, expected_coeff, const_vars) {
            Some((dst, rhs))
        } else if Self::yul_coeff_matches(&rhs, expected_coeff, const_vars) {
            Some((dst, lhs))
        } else {
            None
        }
    }

    fn yul_coeff_matches(
        value: &str,
        expected_coeff: &str,
        const_vars: &HashMap<String, String>,
    ) -> bool {
        yul_const_value(value, const_vars).as_deref() == Some(expected_coeff)
    }

    fn record_yul_const_assignment(line: &str, const_vars: &mut HashMap<String, String>) {
        let Some((dst, rhs)) = yul_let_assignment(line) else {
            return;
        };
        let Some(value) = yul_const_value(&rhs, const_vars) else {
            return;
        };
        const_vars.insert(dst, value);
    }

    fn push_structured_main_fold(
        block: &mut Vec<String>,
        value: impl AsRef<str>,
        sorted_simple: &[usize],
    ) {
        Self::push_structured_fold_advance(block, 1, sorted_simple, "q_main_fold_i");
        block.push(format!(
            "quotient_eval_numer := addmod(quotient_eval_numer, {}, r)",
            value.as_ref()
        ));
    }

    fn structured_permutation_scratch_words(meta: &ConstraintSystemMeta) -> usize {
        if meta.num_permutation_zs == 0 {
            return 0;
        }

        let num_cols = meta.permutation_columns.len();
        let num_sets = meta.num_permutation_zs;
        // permutation values, permutation sigma values, z_cur, z_next,
        // z_last for every non-final set, and one spill slot for the
        // running delta base used by the native permutation callback.
        (2 * num_cols) + (2 * num_sets) + num_sets.saturating_sub(1) + 1
    }

    fn structured_permutation_loop_block(
        meta: &ConstraintSystemMeta,
        data: &Data,
        evaluator: &Evaluator<'_>,
        sorted_simple: &[usize],
        scratch_mptr: usize,
    ) -> Option<Vec<String>> {
        if meta.num_permutation_zs == 0 {
            return None;
        }

        let num_cols = meta.permutation_columns.len();
        let num_sets = meta.num_permutation_zs;
        let chunk_len = meta.permutation_chunk_len;
        let vals_mptr = scratch_mptr;
        let sigmas_mptr = vals_mptr + num_cols * 0x20;
        let z_cur_mptr = sigmas_mptr + num_cols * 0x20;
        let z_next_mptr = z_cur_mptr + num_sets * 0x20;
        let z_last_mptr = z_next_mptr + num_sets * 0x20;
        let delta_base_mptr = z_last_mptr + num_sets.saturating_sub(1) * 0x20;
        let delta_chunk = Fq::DELTA.pow_vartime([chunk_len as u64]);
        let delta_chunk = u256_string(fe_to_u256::<Fq>(&delta_chunk));

        let mut block = Vec::new();
        block.push("{".to_string());
        block.push(
            "let delta := 3793952369011177517951424454785176000433849974408744014172535497121832470999"
                .to_string(),
        );
        block.push(format!("let q_perm_vals := {vals_mptr:#x}"));
        block.push(format!("let q_perm_sigmas := {sigmas_mptr:#x}"));
        block.push(format!("let q_perm_z_cur := {z_cur_mptr:#x}"));
        block.push(format!("let q_perm_z_next := {z_next_mptr:#x}"));
        block.push(format!("let q_perm_z_last := {z_last_mptr:#x}"));
        block.push(format!("let q_perm_delta_base_ptr := {delta_base_mptr:#x}"));
        block.push(format!("let q_perm_num_cols := {num_cols}"));
        block.push(format!("let q_perm_num_sets := {num_sets}"));
        block.push(format!("let q_perm_chunk_len := {chunk_len}"));
        block.push(format!("let q_perm_delta_chunk := {delta_chunk}"));

        let mut value_entries = Vec::with_capacity(num_cols);
        let mut sigma_entries = Vec::with_capacity(num_cols);
        for (idx, column) in meta.permutation_columns.iter().enumerate() {
            let offset = idx * 0x20;
            let value = evaluator.eval_at(column, 0);
            let sigma = data
                .permutation_evals
                .get(column)
                .expect("permutation sigma eval present")
                .to_string();
            value_entries.push((offset, value));
            sigma_entries.push((offset, sigma));
        }
        Self::push_mstore_mload_literal_runs(
            &mut block,
            "q_perm_vals",
            &value_entries,
            "q_perm_val_load",
        );
        Self::push_mstore_mload_literal_runs(
            &mut block,
            "q_perm_sigmas",
            &sigma_entries,
            "q_perm_sigma_load",
        );

        let mut z_cur_entries = Vec::with_capacity(data.permutation_z_evals.len());
        let mut z_next_entries = Vec::with_capacity(data.permutation_z_evals.len());
        let mut z_last_entries = Vec::with_capacity(data.permutation_z_evals.len());
        for (idx, (z_cur, z_next, z_last)) in data.permutation_z_evals.iter().enumerate() {
            let offset = idx * 0x20;
            z_cur_entries.push((offset, z_cur.to_string()));
            z_next_entries.push((offset, z_next.to_string()));
            if let Some(z_last) = z_last {
                z_last_entries.push((offset, z_last.to_string()));
            }
        }
        Self::push_mstore_mload_literal_runs(
            &mut block,
            "q_perm_z_cur",
            &z_cur_entries,
            "q_perm_z_cur_load",
        );
        Self::push_mstore_mload_literal_runs(
            &mut block,
            "q_perm_z_next",
            &z_next_entries,
            "q_perm_z_next_load",
        );
        Self::push_mstore_mload_literal_runs(
            &mut block,
            "q_perm_z_last",
            &z_last_entries,
            "q_perm_z_last_load",
        );

        let fold_eval = |block: &mut Vec<String>| {
            block.push("quotient_eval_numer := mulmod(quotient_eval_numer, y, r)".to_string());
            if !sorted_simple.is_empty() {
                block.push("q_sel_scale := mulmod(q_sel_scale, y, r)".to_string());
                block.push("q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)".to_string());
            }
            block.push(
                "quotient_eval_numer := addmod(quotient_eval_numer, q_perm_eval, r)".to_string(),
            );
        };

        block.push("let q_perm_l0 := mload(L_0_MPTR)".to_string());
        block.push("let q_perm_llast := mload(L_LAST_MPTR)".to_string());
        block.push("let q_perm_lblind := mload(L_BLIND_MPTR)".to_string());
        block.push("let q_perm_beta := mload(BETA_MPTR)".to_string());
        block.push("let q_perm_gamma := mload(GAMMA_MPTR)".to_string());
        block.push(
            "let q_perm_active := addmod(1, sub(r, addmod(q_perm_llast, q_perm_lblind, r)), r)"
                .to_string(),
        );
        block.push("let q_perm_xbeta := mulmod(q_perm_beta, mload(X_MPTR), r)".to_string());
        block.push("let q_perm_eval := 0".to_string());

        block.push(
            "q_perm_eval := mulmod(q_perm_l0, addmod(1, sub(r, mload(q_perm_z_cur)), r), r)"
                .to_string(),
        );
        fold_eval(&mut block);

        let final_z_offset = (num_sets - 1) * 0x20;
        block.push(format!(
            "let q_perm_zn := mload(add(q_perm_z_cur, {final_z_offset:#x}))"
        ));
        block.push(
            "q_perm_eval := mulmod(q_perm_llast, addmod(mulmod(q_perm_zn, q_perm_zn, r), sub(r, q_perm_zn), r), r)"
                .to_string(),
        );
        fold_eval(&mut block);

        if num_sets > 1 {
            block.push(format!(
                "for {{ let q_perm_i := 1 }} lt(q_perm_i, {num_sets}) {{ q_perm_i := add(q_perm_i, 1) }} {{"
            ));
            block.push("let q_perm_cur := mload(add(q_perm_z_cur, shl(5, q_perm_i)))".to_string());
            block.push(
                "let q_perm_prev := mload(add(q_perm_z_last, shl(5, sub(q_perm_i, 1))))"
                    .to_string(),
            );
            block.push(
                "q_perm_eval := mulmod(q_perm_l0, addmod(q_perm_cur, sub(r, q_perm_prev), r), r)"
                    .to_string(),
            );
            fold_eval(&mut block);
            block.push("}".to_string());
        }

        block.push("mstore(q_perm_delta_base_ptr, q_perm_xbeta)".to_string());
        block.push(format!(
            "for {{ let q_perm_set := 0 }} lt(q_perm_set, {num_sets}) {{ q_perm_set := add(q_perm_set, 1) }} {{"
        ));
        block.push("let q_perm_start := mul(q_perm_set, q_perm_chunk_len)".to_string());
        block.push("let q_perm_end := add(q_perm_start, q_perm_chunk_len)".to_string());
        block.push(
            "if gt(q_perm_end, q_perm_num_cols) { q_perm_end := q_perm_num_cols }".to_string(),
        );
        block.push("let q_perm_left := mload(add(q_perm_z_next, shl(5, q_perm_set)))".to_string());
        block.push("let q_perm_right := mload(add(q_perm_z_cur, shl(5, q_perm_set)))".to_string());
        block.push("let q_perm_delta_pow := mload(q_perm_delta_base_ptr)".to_string());
        block.push("for { let q_perm_j := q_perm_start } lt(q_perm_j, q_perm_end) { q_perm_j := add(q_perm_j, 1) } {".to_string());
        block.push("let q_perm_off := shl(5, q_perm_j)".to_string());
        block.push("let q_perm_v := mload(add(q_perm_vals, q_perm_off))".to_string());
        block.push("let q_perm_s := mload(add(q_perm_sigmas, q_perm_off))".to_string());
        block.push(
            "q_perm_left := mulmod(q_perm_left, addmod(addmod(q_perm_v, mulmod(q_perm_beta, q_perm_s, r), r), q_perm_gamma, r), r)"
                .to_string(),
        );
        block.push(
            "q_perm_right := mulmod(q_perm_right, addmod(addmod(q_perm_v, q_perm_delta_pow, r), q_perm_gamma, r), r)"
                .to_string(),
        );
        block.push("q_perm_delta_pow := mulmod(q_perm_delta_pow, delta, r)".to_string());
        block.push("}".to_string());
        block.push(
            "q_perm_eval := mulmod(q_perm_active, addmod(q_perm_left, sub(r, q_perm_right), r), r)"
                .to_string(),
        );
        fold_eval(&mut block);
        block.push(
            "mstore(q_perm_delta_base_ptr, mulmod(mload(q_perm_delta_base_ptr), q_perm_delta_chunk, r))".to_string(),
        );
        block.push("}".to_string());

        block.push("}".to_string());
        Some(block)
    }

    fn structured_lookup_loop_block(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
        evaluator: &Evaluator<'_>,
        sorted_simple: &[usize],
        scratch_mptr: usize,
    ) -> Option<Vec<String>> {
        if meta.num_lookups == 0 {
            return None;
        }

        let mut max_parallel = 1usize;
        for lookup in self.vk.cs().lookups() {
            let chunked = lookup.chunk_by_degree(self.vk.cs().degree());
            for input_chunk in chunked.input_expression_chunks() {
                max_parallel = max_parallel.max(input_chunk.len());
            }
        }

        let f_plus_beta_mptr = scratch_mptr;
        let prefix_mptr = f_plus_beta_mptr + max_parallel * 0x20;
        let suffix_mptr = prefix_mptr + max_parallel * 0x20;

        let mut block = Vec::new();
        block.push("{".to_string());
        block.push(format!("let q_lookup_f := {f_plus_beta_mptr:#x}"));
        block.push(format!("let q_lookup_prefix := {prefix_mptr:#x}"));
        block.push(format!("let q_lookup_suffix := {suffix_mptr:#x}"));
        block.push("let q_lookup_l0 := mload(L_0_MPTR)".to_string());
        block.push("let q_lookup_llast := mload(L_LAST_MPTR)".to_string());
        block.push("let q_lookup_lblind := mload(L_BLIND_MPTR)".to_string());
        block.push("let q_lookup_lsum := addmod(q_lookup_l0, q_lookup_llast, r)".to_string());
        block.push(
            "let q_lookup_active := addmod(1, sub(r, addmod(q_lookup_llast, q_lookup_lblind, r)), r)"
                .to_string(),
        );
        block.push("let q_lookup_beta := mload(BETA_MPTR)".to_string());
        block.push("let q_lookup_theta := mload(THETA_MPTR)".to_string());

        for (lookup_idx, lookup) in self.vk.cs().lookups().iter().enumerate() {
            let chunked = lookup.chunk_by_degree(self.vk.cs().degree());
            let (m_eval, h_evals, z_eval, z_next_eval) = &data.lookup_evals[lookup_idx];

            block.push("{".to_string());

            // boundary = (l_0 + l_last) * Z_lookup(x)
            block.push("{".to_string());
            block.push(format!(
                "let q_lookup_eval := mulmod(q_lookup_lsum, {}, r)",
                z_eval
            ));
            Self::push_structured_main_fold(&mut block, "q_lookup_eval", sorted_simple);
            block.push("}".to_string());

            for (input_chunk, h_eval) in
                chunked.input_expression_chunks().iter().zip(h_evals.iter())
            {
                let k = input_chunk.len();
                block.push("{".to_string());

                if k == 0 {
                    block.push("let q_lookup_eval := 0".to_string());
                    Self::push_structured_main_fold(&mut block, "q_lookup_eval", sorted_simple);
                    block.push("}".to_string());
                    continue;
                }

                evaluator.reset_locals();
                if let Some(mut shared_prefix_lines) = evaluator.lookup_shared_prefix_f_plus_beta(
                    input_chunk,
                    "q_lookup_theta",
                    "q_lookup_beta",
                    "q_lookup_f",
                ) {
                    block.append(&mut shared_prefix_lines);
                } else {
                    for (input_idx, parallel_input) in input_chunk.iter().enumerate() {
                        let (mut compressed_lines, compressed_var) = evaluator
                            .compress_expressions_with_challenge_var(
                                parallel_input,
                                "q_lookup_theta",
                            );
                        block.append(&mut compressed_lines);
                        block.push(format!(
                            "mstore(add(q_lookup_f, {:#x}), addmod({compressed_var}, q_lookup_beta, r))",
                            input_idx * 0x20
                        ));
                    }
                }

                block.push("let q_lookup_product := 1".to_string());
                block.push(format!(
                    "for {{ let q_lookup_prod_i := 0 }} lt(q_lookup_prod_i, {k}) {{ q_lookup_prod_i := add(q_lookup_prod_i, 1) }} {{"
                ));
                block.push(
                    "q_lookup_product := mulmod(q_lookup_product, mload(add(q_lookup_f, shl(5, q_lookup_prod_i))), r)"
                        .to_string(),
                );
                block.push("}".to_string());

                block.push("mstore(q_lookup_prefix, 1)".to_string());
                if k > 1 {
                    block.push(format!(
                        "for {{ let q_lookup_pref_i := 1 }} lt(q_lookup_pref_i, {k}) {{ q_lookup_pref_i := add(q_lookup_pref_i, 1) }} {{"
                    ));
                    block.push("let q_lookup_pref_prev := sub(q_lookup_pref_i, 1)".to_string());
                    block.push(
                        "mstore(add(q_lookup_prefix, shl(5, q_lookup_pref_i)), mulmod(mload(add(q_lookup_prefix, shl(5, q_lookup_pref_prev))), mload(add(q_lookup_f, shl(5, q_lookup_pref_prev))), r))"
                            .to_string(),
                    );
                    block.push("}".to_string());
                }

                block.push(format!(
                    "mstore(add(q_lookup_suffix, {:#x}), 1)",
                    (k - 1) * 0x20
                ));
                if k > 1 {
                    block.push(format!(
                        "for {{ let q_lookup_suf_i := sub({k}, 1) }} gt(q_lookup_suf_i, 0) {{ q_lookup_suf_i := sub(q_lookup_suf_i, 1) }} {{"
                    ));
                    block.push("let q_lookup_suf_prev := sub(q_lookup_suf_i, 1)".to_string());
                    block.push(
                        "mstore(add(q_lookup_suffix, shl(5, q_lookup_suf_prev)), mulmod(mload(add(q_lookup_suffix, shl(5, q_lookup_suf_i))), mload(add(q_lookup_f, shl(5, q_lookup_suf_i))), r))"
                            .to_string(),
                    );
                    block.push("}".to_string());
                }

                block.push("let q_lookup_sum := 0".to_string());
                block.push(format!(
                    "for {{ let q_lookup_sum_i := 0 }} lt(q_lookup_sum_i, {k}) {{ q_lookup_sum_i := add(q_lookup_sum_i, 1) }} {{"
                ));
                block.push(
                    "q_lookup_sum := addmod(q_lookup_sum, mulmod(mload(add(q_lookup_prefix, shl(5, q_lookup_sum_i))), mload(add(q_lookup_suffix, shl(5, q_lookup_sum_i))), r), r)"
                        .to_string(),
                );
                block.push("}".to_string());
                block.push(format!(
                    "let q_lookup_eval := addmod(mulmod({}, q_lookup_product, r), sub(r, q_lookup_sum), r)",
                    h_eval
                ));
                Self::push_structured_main_fold(&mut block, "q_lookup_eval", sorted_simple);
                block.push("}".to_string());
            }

            // accumulator =
            // active * ((Z_next - Z - selector * sum(h)) * (table + beta) + m)
            block.push("{".to_string());
            let sum_h_expr = if h_evals.is_empty() {
                "0".to_string()
            } else {
                let sum_h = "q_lookup_sum_h";
                block.push(format!("let {sum_h} := {}", h_evals[0]));
                for h_eval in &h_evals[1..] {
                    block.push(format!("{sum_h} := addmod({sum_h}, {}, r)", h_eval));
                }
                sum_h.to_string()
            };

            evaluator.reset_locals();
            let (mut selector_lines, selector_var) =
                evaluator.evaluate_expression(chunked.selector_expression());
            block.append(&mut selector_lines);
            let (mut table_lines, table_var) = evaluator.compress_expressions_with_challenge_var(
                chunked.table_expressions(),
                "q_lookup_theta",
            );
            block.append(&mut table_lines);
            block.push(format!(
                "let q_lookup_s_sum_h := mulmod({selector_var}, {sum_h_expr}, r)"
            ));
            block.push(format!(
                "let q_lookup_diff := addmod({}, sub(r, addmod({}, q_lookup_s_sum_h, r)), r)",
                z_next_eval, z_eval
            ));
            block.push(format!(
                "let q_lookup_t_beta := addmod({table_var}, q_lookup_beta, r)"
            ));
            block.push(format!(
                "let q_lookup_core := addmod(mulmod(q_lookup_diff, q_lookup_t_beta, r), {}, r)",
                m_eval
            ));
            block
                .push("let q_lookup_eval := mulmod(q_lookup_active, q_lookup_core, r)".to_string());
            Self::push_structured_main_fold(&mut block, "q_lookup_eval", sorted_simple);
            block.push("}".to_string());

            block.push("}".to_string());
        }

        block.push("}".to_string());
        Some(block)
    }

    fn structured_trash_loop_block(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
        evaluator: &Evaluator<'_>,
        sorted_simple: &[usize],
    ) -> Option<Vec<String>> {
        if meta.num_trashcans == 0 {
            return None;
        }

        let mut block = Vec::new();
        block.push("{".to_string());
        block.push("let q_trash_tau := mload(TRASH_CHALLENGE_MPTR)".to_string());

        for (idx, argument) in self.vk.cs().trashcans().iter().enumerate() {
            block.push("{".to_string());
            evaluator.reset_locals();
            let (mut compressed_lines, compressed_var) = evaluator
                .compress_expressions_with_challenge_var(
                    argument.constraint_expressions(),
                    "q_trash_tau",
                );
            block.append(&mut compressed_lines);
            let (mut selector_lines, selector_var) =
                evaluator.evaluate_expression(argument.selector());
            block.append(&mut selector_lines);
            block.push(format!(
                "let q_trash_one_minus_selector := addmod(1, sub(r, {selector_var}), r)"
            ));
            block.push(format!(
                "let q_trash_scaled := mulmod(q_trash_one_minus_selector, {}, r)",
                data.trashcan_evals[idx]
            ));
            block.push(format!(
                "let q_trash_eval := addmod({compressed_var}, sub(r, q_trash_scaled), r)"
            ));
            Self::push_structured_main_fold(&mut block, "q_trash_eval", sorted_simple);
            block.push("}".to_string());
        }

        block.push("}".to_string());
        Some(block)
    }

    fn structured_loop_quotient_computations(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
        sorted_simple: &[usize],
        scratch_mptr: usize,
    ) -> Vec<Vec<String>> {
        let evaluator = Evaluator::new(self.vk.cs(), meta, data).with_pow5_helper(true);
        let eval_scratch_slot =
            scratch_mptr + Self::structured_permutation_scratch_words(meta) * 0x20;
        let gate_items = evaluator.gate_computations_tagged();

        let mut init = vec!["let quotient_eval_numer := 0".to_string()];
        if !sorted_simple.is_empty() {
            init.push(format!(
                "for {{ let q_sel_zero_off := 0 }} lt(q_sel_zero_off, {:#x}) {{ q_sel_zero_off := add(q_sel_zero_off, 0x20) }} {{",
                sorted_simple.len() * 0x20
            ));
            init.push("mstore(add(SELECTOR_ACC_MPTR, q_sel_zero_off), 0)".to_string());
            init.push("}".to_string());
        }
        if !sorted_simple.is_empty() {
            init.push("let q_sel_scale := 1".to_string());
            init.push("let q_sel_inv_scale := 1".to_string());
            init.push("let q_y_inv := 0".to_string());
            init.push("{".to_string());
            init.push(format!("let q_inv_scratch := {eval_scratch_slot:#x}"));
            init.push("if iszero(y) { revert(0, 0) }".to_string());
            init.push("mstore(q_inv_scratch, 0x20)".to_string());
            init.push("mstore(add(q_inv_scratch, 0x20), 0x20)".to_string());
            init.push("mstore(add(q_inv_scratch, 0x40), 0x20)".to_string());
            init.push("mstore(add(q_inv_scratch, 0x60), y)".to_string());
            init.push("mstore(add(q_inv_scratch, 0x80), sub(FR_MODULUS, 2))".to_string());
            init.push("mstore(add(q_inv_scratch, 0xa0), FR_MODULUS)".to_string());
            init.push(
                "if iszero(staticcall(gas(), 0x05, q_inv_scratch, 0xc0, q_inv_scratch, 0x20)) { revert(0, 0) }"
                    .to_string(),
            );
            init.push("if iszero(eq(returndatasize(), 0x20)) { revert(0, 0) }".to_string());
            init.push("q_y_inv := mload(q_inv_scratch)".to_string());
            init.push("}".to_string());
        }
        let mut computations = vec![init];

        let mut pending_selector = None;
        let mut pending_selector_run: Vec<(Vec<String>, String)> = Vec::new();
        for (lines, var, target) in gate_items {
            let target = match target {
                Some(col) => {
                    let idx = sorted_simple
                        .iter()
                        .position(|simple| *simple == col)
                        .expect("selector column present");
                    QuotientTarget::Selector(idx)
                }
                None => QuotientTarget::Main,
            };
            match target {
                QuotientTarget::Selector(idx) => {
                    if pending_selector == Some(idx) {
                        pending_selector_run.push((lines, var));
                    } else {
                        Self::flush_structured_selector_run(
                            &mut computations,
                            &mut pending_selector,
                            &mut pending_selector_run,
                            sorted_simple,
                            eval_scratch_slot,
                        );
                        pending_selector = Some(idx);
                        pending_selector_run.push((lines, var));
                    }
                }
                QuotientTarget::Main => {
                    Self::flush_structured_selector_run(
                        &mut computations,
                        &mut pending_selector,
                        &mut pending_selector_run,
                        sorted_simple,
                        eval_scratch_slot,
                    );
                    computations.push(Self::direct_quotient_block(
                        &lines,
                        &var,
                        target,
                        sorted_simple,
                        eval_scratch_slot,
                    ));
                }
            }
        }
        Self::flush_structured_selector_run(
            &mut computations,
            &mut pending_selector,
            &mut pending_selector_run,
            sorted_simple,
            eval_scratch_slot,
        );

        if let Some(block) = Self::structured_permutation_loop_block(
            meta,
            data,
            &evaluator,
            sorted_simple,
            scratch_mptr,
        ) {
            computations.push(block);
        }

        if let Some(block) = self.structured_lookup_loop_block(
            meta,
            data,
            &evaluator,
            sorted_simple,
            eval_scratch_slot,
        ) {
            computations.push(block);
        }

        if let Some(block) = self.structured_trash_loop_block(meta, data, &evaluator, sorted_simple)
        {
            computations.push(block);
        }

        if !sorted_simple.is_empty() {
            let mut tail = Vec::new();
            tail.push(format!(
                "for {{ let q_sel_tail_off := 0 }} lt(q_sel_tail_off, {:#x}) {{ q_sel_tail_off := add(q_sel_tail_off, 0x20) }} {{",
                sorted_simple.len() * 0x20
            ));
            tail.push(
                "mstore(add(SELECTOR_ACC_MPTR, q_sel_tail_off), mulmod(mload(add(SELECTOR_ACC_MPTR, q_sel_tail_off)), q_sel_scale, r))"
                    .to_string(),
            );
            tail.push("}".to_string());
            computations.push(tail);
        }

        computations
    }

    fn generate_quotient_evaluator(&self) -> Halo2QuotientEvaluator {
        let proof_cptr = Ptr::calldata(0x64);

        let vk = self.generate_vk();
        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));
        let vk_len = vk.len();
        let (meta, data) = self.meta_data_for_vk(&vk, vk_mptr, proof_cptr);
        let quotient_plan = self.quotient_program_plan(&meta, &data);
        let sorted_simple = quotient_plan.sorted_simple.clone();

        assert!(
            !(quotient_inline_cse_enabled() && quotient_structured_loops_enabled()),
            "{QUOTIENT_CSE_ENV}=1 and {QUOTIENT_STRUCTURED_LOOPS_ENV}=1 are mutually exclusive"
        );
        assert!(
            !(quotient_inline_cse_enabled() || quotient_structured_loops_enabled()),
            "external quotient evaluator is only implemented for the compact VM quotient path"
        );

        let lookup_helper_chunks_total: usize = meta.lookup_chunks.iter().sum();
        let total_advices: usize = meta.num_user_advices.iter().sum();
        let comm_g1_count = total_advices
            + meta.num_lookups
            + meta.num_permutation_zs
            + lookup_helper_chunks_total
            + meta.num_lookups
            + meta.num_trashcans
            + meta.num_quotients;
        let after_comms = data.comms_mptr_base.value().as_usize() + comm_g1_count * 0x80;
        let selector_acc_mptr = after_comms.next_multiple_of(0x20);
        let quotient_tmp_mptr =
            (selector_acc_mptr + sorted_simple.len() * 0x20).next_multiple_of(0x20);

        let quotient_program_build = self.build_quotient_program_items(&quotient_plan.items);
        let quotient_program_chunks = Self::program_chunks(&quotient_program_build.bytes);
        let quotient_const_words = vk.quotient_const_words;
        let quotient_program_words = vk.quotient_program_words;
        let quotient_const_offset_words = vk
            .quotient_const_offset_words
            .expect("VK must carry quotient constants");
        let quotient_program_offset_words = vk
            .quotient_program_offset_words
            .expect("VK must carry quotient program");
        assert_eq!(
            quotient_program_build.consts.len(),
            quotient_const_words,
            "quotient const table changed after VK payload reservation"
        );
        assert_eq!(
            quotient_program_chunks.len(),
            quotient_program_words,
            "quotient program length changed after VK payload reservation"
        );
        let quotient_stack_mptr = quotient_tmp_mptr + quotient_program_build.cse_temps * 0x20;
        let const_mptr = (vk_mptr + quotient_const_offset_words).value().as_usize();
        let program_mptr = (vk_mptr + quotient_program_offset_words).value().as_usize();
        let quotient_program = Some(QuotientProgram {
            consts: quotient_program_build.consts,
            chunks: quotient_program_chunks,
            len: quotient_program_build.bytes.len(),
            packed32: quotient_program_build.packed32,
            cse_temps: quotient_program_build.cse_temps,
            const_mptr,
            tmp_mptr: quotient_tmp_mptr,
            stack_mptr: quotient_stack_mptr,
            program_mptr,
        });

        let mut quotient_inline_computations = Vec::new();
        let quotient_eval_numer_computations = Vec::new();
        let mut quotient_post_vm_computations = Vec::new();
        let mut quotient_native_permutation_computation = Vec::new();
        let mut quotient_native_identity_computations = Vec::new();
        let quotient_native_trash_computation = Vec::new();

        let eval_scratch_slot = quotient_stack_mptr;
        let evaluator = Evaluator::new(self.vk.cs(), &meta, &data).with_pow5_helper(true);
        for identity in &quotient_plan.inline_identities {
            quotient_inline_computations.push(Self::direct_quotient_block(
                &identity.lines,
                &identity.var,
                identity.target,
                &sorted_simple,
                eval_scratch_slot,
            ));
        }
        if quotient_plan.has_native_permutation {
            if let Some(block) = Self::structured_permutation_loop_block(
                &meta,
                &data,
                &evaluator,
                &sorted_simple,
                quotient_stack_mptr,
            ) {
                quotient_native_permutation_computation = block;
            }
        }
        for identity in &quotient_plan.native_identities {
            quotient_native_identity_computations.push(Self::direct_quotient_block(
                &identity.lines,
                &identity.var,
                identity.target,
                &sorted_simple,
                eval_scratch_slot,
            ));
        }
        if quotient_structured_tail_mode() == QuotientStructuredTailMode::Trash
            && meta.num_trashcans > 0
        {
            if let Some(block) =
                self.structured_trash_loop_block(&meta, &data, &evaluator, &sorted_simple)
            {
                quotient_post_vm_computations.push(block);
            }
        }

        let quotient_pow5_helper = quotient_inline_computations
            .iter()
            .chain(quotient_post_vm_computations.iter())
            .chain(std::iter::once(&quotient_native_permutation_computation))
            .chain(quotient_native_identity_computations.iter())
            .chain(std::iter::once(&quotient_native_trash_computation))
            .flat_map(|block| block.iter())
            .any(|line| line.contains("q_pow5("));
        let quotient_limb7_helper = quotient_inline_computations
            .iter()
            .chain(quotient_post_vm_computations.iter())
            .chain(std::iter::once(&quotient_native_permutation_computation))
            .chain(quotient_native_identity_computations.iter())
            .chain(std::iter::once(&quotient_native_trash_computation))
            .flat_map(|block| block.iter())
            .any(|line| line.contains("q_limb7("));
        let quotient_wide_limb7_helper = quotient_inline_computations
            .iter()
            .chain(quotient_post_vm_computations.iter())
            .chain(std::iter::once(&quotient_native_permutation_computation))
            .chain(quotient_native_identity_computations.iter())
            .chain(std::iter::once(&quotient_native_trash_computation))
            .flat_map(|block| block.iter())
            .any(|line| line.contains("q_limb7_wide("));

        Halo2QuotientEvaluator {
            quotient_pow5_helper,
            quotient_limb7_helper,
            quotient_wide_limb7_helper,
            vk_mptr,
            challenge_mptr: data.challenge_mptr,
            theta_mptr: data.theta_mptr,
            reversed_evals_mptr: data.reversed_evals_mptr,
            selector_acc_mptr,
            quotient_external: Self::quotient_external_frame(
                vk_mptr,
                vk_len,
                &meta,
                &data,
                sorted_simple.len(),
            ),
            quotient_inline_computations,
            quotient_eval_numer_computations,
            quotient_post_vm_computations,
            quotient_native_permutation_computation,
            quotient_native_identity_computations,
            quotient_native_trash_computation,
            quotient_program,
            simple_selector_cols: sorted_simple,
        }
    }

    fn generate_verifier(
        &self,
        separate: bool,
        trace: bool,
        gas_checkpoints: bool,
        external_quotient: bool,
        expected_quotient: Option<(usize, U256)>,
    ) -> Halo2Verifier {
        assert!(
            expected_quotient.is_none() || external_quotient,
            "quotient pinning requires an external quotient evaluator"
        );
        assert!(
            !external_quotient || expected_quotient.is_some(),
            "external quotient evaluator render requires a generated runtime length/codehash; \
             render the quotient evaluator first and use the pinned quotient render API"
        );
        let proof_cptr = Ptr::calldata(0x64);

        let vk = self.generate_vk();
        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));

        let (meta, data) = self.meta_data_for_vk(&vk, vk_mptr, proof_cptr);

        let quotient_plan = self.quotient_program_plan(&meta, &data);
        let identities = self.quotient_identity_parts(&meta, &data).all_identities();
        let sorted_simple = quotient_plan.sorted_simple.clone();
        let use_inline_cse = quotient_inline_cse_enabled();
        let use_structured_loops = quotient_structured_loops_enabled();
        assert!(
            !(use_inline_cse && use_structured_loops),
            "{QUOTIENT_CSE_ENV}=1 and {QUOTIENT_STRUCTURED_LOOPS_ENV}=1 are mutually exclusive"
        );
        let quotient_yul_helpers = use_inline_cse && quotient_yul_helpers_enabled();
        let quotient_program_build = (!(use_inline_cse || use_structured_loops))
            .then(|| self.build_quotient_program_items(&quotient_plan.items));

        let lookup_helper_chunks_total: usize = meta.lookup_chunks.iter().sum();
        let total_advices: usize = meta.num_user_advices.iter().sum();
        let comm_g1_count = total_advices
            + meta.num_lookups
            + meta.num_permutation_zs
            + lookup_helper_chunks_total
            + meta.num_lookups
            + meta.num_trashcans
            + meta.num_quotients;
        let after_comms = data.comms_mptr_base.value().as_usize() + comm_g1_count * 0x80;
        let selector_acc_mptr = after_comms.next_multiple_of(0x20);
        let batch_invert_scratch_mptr = selector_acc_mptr;
        let expected_vk_codehash = separate.then(|| {
            let digest: [u8; 32] = Keccak256::digest(vk.bytes()).into();
            U256::from_be_bytes(digest)
        });
        let vk_len = vk.len();
        let quotient_tmp_mptr =
            (selector_acc_mptr + sorted_simple.len() * 0x20).next_multiple_of(0x20);
        let quotient_external = external_quotient.then(|| {
            Self::quotient_external_frame(vk_mptr, vk_len, &meta, &data, sorted_simple.len())
        });
        let (expected_quotient_len, expected_quotient_codehash) = expected_quotient
            .map(|(len, codehash)| (Some(len), Some(codehash)))
            .unwrap_or((None, None));
        let (quotient_program, quotient_stack_mptr) = if let Some(quotient_program_build) =
            quotient_program_build
        {
            let quotient_program_chunks = Self::program_chunks(&quotient_program_build.bytes);
            let quotient_const_words = vk.quotient_const_words;
            let quotient_program_words = vk.quotient_program_words;
            let quotient_const_offset_words = vk
                .quotient_const_offset_words
                .expect("VK must carry quotient constants");
            let quotient_program_offset_words = vk
                .quotient_program_offset_words
                .expect("VK must carry quotient program");
            assert_eq!(
                quotient_program_build.consts.len(),
                quotient_const_words,
                "quotient const table changed after VK payload reservation"
            );
            assert_eq!(
                quotient_program_chunks.len(),
                quotient_program_words,
                "quotient program length changed after VK payload reservation"
            );
            let quotient_stack_mptr = quotient_tmp_mptr + quotient_program_build.cse_temps * 0x20;
            let const_mptr = (vk_mptr + quotient_const_offset_words).value().as_usize();
            let program_mptr = (vk_mptr + quotient_program_offset_words).value().as_usize();
            (
                Some(QuotientProgram {
                    consts: quotient_program_build.consts,
                    chunks: quotient_program_chunks,
                    len: quotient_program_build.bytes.len(),
                    packed32: quotient_program_build.packed32,
                    cse_temps: quotient_program_build.cse_temps,
                    const_mptr,
                    tmp_mptr: quotient_tmp_mptr,
                    stack_mptr: quotient_stack_mptr,
                    program_mptr,
                }),
                quotient_stack_mptr,
            )
        } else {
            (None, quotient_tmp_mptr)
        };

        let mut quotient_inline_computations: Vec<Vec<String>> = Vec::new();
        let mut quotient_eval_numer_computations: Vec<Vec<String>> = Vec::new();
        let mut quotient_post_vm_computations: Vec<Vec<String>> = Vec::new();
        let mut quotient_native_permutation_computation: Vec<String> = Vec::new();
        let mut quotient_native_identity_computations: Vec<Vec<String>> = Vec::new();
        let quotient_native_trash_computation: Vec<String> = Vec::new();

        if external_quotient {
            // The external quotient evaluator renders and runs these blocks.
            // Keep the main verifier source free of the bulky native quotient
            // code; it only performs the staticcall and copies the output.
        } else if use_structured_loops {
            quotient_eval_numer_computations = self.structured_loop_quotient_computations(
                &meta,
                &data,
                &sorted_simple,
                quotient_tmp_mptr,
            );
        } else if use_inline_cse {
            quotient_eval_numer_computations = Self::inline_cse_quotient_computations(
                &identities,
                &sorted_simple,
                quotient_tmp_mptr,
                quotient_yul_helpers,
            );
        } else {
            let eval_scratch_slot = quotient_stack_mptr;
            let evaluator = Evaluator::new(self.vk.cs(), &meta, &data).with_pow5_helper(true);

            for identity in &quotient_plan.inline_identities {
                quotient_inline_computations.push(Self::direct_quotient_block(
                    &identity.lines,
                    &identity.var,
                    identity.target,
                    &sorted_simple,
                    eval_scratch_slot,
                ));
            }

            if quotient_plan.has_native_permutation {
                if let Some(block) = Self::structured_permutation_loop_block(
                    &meta,
                    &data,
                    &evaluator,
                    &sorted_simple,
                    quotient_stack_mptr,
                ) {
                    quotient_native_permutation_computation = block;
                }
            }

            for identity in &quotient_plan.native_identities {
                quotient_native_identity_computations.push(Self::direct_quotient_block(
                    &identity.lines,
                    &identity.var,
                    identity.target,
                    &sorted_simple,
                    eval_scratch_slot,
                ));
            }

            if quotient_structured_tail_mode() == QuotientStructuredTailMode::Trash
                && meta.num_trashcans > 0
            {
                if let Some(block) =
                    self.structured_trash_loop_block(&meta, &data, &evaluator, &sorted_simple)
                {
                    quotient_post_vm_computations.push(block);
                }
            }
        }

        let quotient_pow5_helper = !external_quotient
            && quotient_eval_numer_computations
                .iter()
                .chain(quotient_inline_computations.iter())
                .chain(quotient_post_vm_computations.iter())
                .chain(std::iter::once(&quotient_native_permutation_computation))
                .chain(quotient_native_identity_computations.iter())
                .chain(std::iter::once(&quotient_native_trash_computation))
                .flat_map(|block| block.iter())
                .any(|line| line.contains("q_pow5("));
        let quotient_limb7_helper = !external_quotient
            && quotient_eval_numer_computations
                .iter()
                .chain(quotient_inline_computations.iter())
                .chain(quotient_post_vm_computations.iter())
                .chain(std::iter::once(&quotient_native_permutation_computation))
                .chain(quotient_native_identity_computations.iter())
                .chain(std::iter::once(&quotient_native_trash_computation))
                .flat_map(|block| block.iter())
                .any(|line| line.contains("q_limb7("));
        let quotient_wide_limb7_helper = !external_quotient
            && quotient_eval_numer_computations
                .iter()
                .chain(quotient_inline_computations.iter())
                .chain(quotient_post_vm_computations.iter())
                .chain(std::iter::once(&quotient_native_permutation_computation))
                .chain(quotient_native_identity_computations.iter())
                .chain(std::iter::once(&quotient_native_trash_computation))
                .flat_map(|block| block.iter())
                .any(|line| line.contains("q_limb7_wide("));

        let pcs_computations =
            self.scheme
                .computations(&meta, &data, cfg!(feature = "truncated-challenges"));

        // Per-user-phase breakdown (advices + user challenges).
        let mut challenge_offset = 0usize;
        let user_phases: Vec<UserPhase> = meta
            .num_user_advices
            .iter()
            .zip(meta.num_user_challenges.iter())
            .map(|(&n_a, &n_c)| {
                let phase = UserPhase {
                    num_advices: n_a,
                    num_challenges: n_c,
                    challenge_offset,
                };
                challenge_offset += n_c;
                phase
            })
            .collect();
        let num_user_challenges: usize = meta.num_user_challenges.iter().sum();
        let lookup_h_plus_acc: usize = meta.lookup_chunks.iter().sum::<usize>() + meta.num_lookups;

        // Compute VK / accumulator layout helpers before moving vk into
        // the template struct.
        let fixed_comm_mptr_byte = (vk_mptr + vk.constants.len()).value().as_usize();
        let permutation_comm_mptr_byte = fixed_comm_mptr_byte + vk.fixed_comms.len() * 0x80;
        let g1_base_mptr_byte = (vk_mptr + 11).value().as_usize();

        let mut acc_fixed_bases: Vec<(String, usize, bool)> = Vec::new();
        if let Some(acc_encoding) = self.acc_encoding {
            let limbs_per_instance = (254 / acc_encoding.num_limb_bits).max(1);
            let coord_words = acc_encoding.num_limbs.div_ceil(limbs_per_instance);
            let point_and_scalar_words = 4 * coord_words + 2;
            let fixed_scalar_count = self
                .num_instances
                .checked_sub(acc_encoding.offset + point_and_scalar_words)
                .expect("accumulator public input exceeds num_instances");
            // A fully-collapsed public accumulator has no fixed-base scalar
            // tail: just (lhs point, lhs scalar=1, rhs point, rhs scalar=1).
            // Older partially-collapsed accumulators still expose the RHS
            // fixed scalars for -G, fixed commitments, and permutation
            // commitments in BTreeMap key order.
            if fixed_scalar_count != 0 {
                let num_perm_bases = vk.permutation_comms.len();
                let num_fixed_bases = fixed_scalar_count
                    .checked_sub(1 + num_perm_bases)
                    .expect("accumulator fixed scalar count is smaller than -G + permutations");

                acc_fixed_bases.push(("-G".to_string(), g1_base_mptr_byte, true));
                for i in 0..num_fixed_bases {
                    acc_fixed_bases.push((
                        format!("self_vk_fixed_com_{i}"),
                        fixed_comm_mptr_byte + i * 0x80,
                        false,
                    ));
                }
                for i in 0..num_perm_bases {
                    acc_fixed_bases.push((
                        format!("self_vk_perm_com_{i}"),
                        permutation_comm_mptr_byte + i * 0x80,
                        false,
                    ));
                }
            }
            debug_assert_eq!(
                acc_fixed_bases.len(),
                fixed_scalar_count,
                "accumulator fixed-base scalar tail must match generated bases"
            );
        }
        acc_fixed_bases.sort_by(|a, b| a.0.cmp(&b.0));
        let acc_fixed_bases: Vec<(usize, bool)> = acc_fixed_bases
            .into_iter()
            .map(|(_, mptr, negate)| (mptr, negate))
            .collect();

        let acc_msm_scratch = after_comms.max(0x7000).next_multiple_of(0x20);

        Halo2Verifier {
            scheme: self.scheme,
            trace,
            gas_checkpoints,
            quotient_yul_helpers,
            quotient_pow5_helper,
            quotient_limb7_helper,
            quotient_wide_limb7_helper,
            embedded_vk: (!separate).then_some(vk),
            expected_vk_codehash,
            vk_len,
            vk_mptr,
            num_neg_lagranges: meta.rotation_last.unsigned_abs() as usize,
            user_phases,
            num_user_challenges,
            num_lookups: meta.num_lookups,
            num_permutation_zs: meta.num_permutation_zs,
            lookup_h_plus_acc,
            num_trashcans: meta.num_trashcans,
            num_quotients: meta.num_quotients,
            num_evals: meta.num_evals,
            num_point_sets: meta.num_point_sets,
            total_advices,
            lookup_helper_chunks_total,
            lookup_chunks: meta.lookup_chunks.clone(),
            comms_mptr_base: data.comms_mptr_base,
            reversed_evals_mptr: data.reversed_evals_mptr,
            selector_acc_mptr,
            batch_invert_scratch_mptr,
            quotient_external,
            expected_quotient_len,
            expected_quotient_codehash,
            proof_cptr,
            num_instance_cptr: proof_cptr.value().as_usize() + meta.proof_len(self.scheme),
            instance_cptr: proof_cptr.value().as_usize() + meta.proof_len(self.scheme) + 0x20,
            quotient_comm_cptr: data.quotient_comm_cptr,
            proof_len: meta.proof_len(self.scheme),
            challenge_mptr: data.challenge_mptr,
            theta_mptr: data.theta_mptr,
            quotient_inline_computations,
            quotient_eval_numer_computations,
            quotient_post_vm_computations,
            quotient_native_permutation_computation,
            quotient_native_identity_computations,
            quotient_native_trash_computation,
            quotient_program: if external_quotient {
                None
            } else {
                quotient_program
            },
            pcs_computations,
            simple_selector_cols: sorted_simple.clone(),
            fixed_comm_mptr: fixed_comm_mptr_byte,
            truncated_challenges: cfg!(feature = "truncated-challenges"),
            fewer_point_sets: cfg!(feature = "outer-fewer-point-sets"),
            num_dummy_evals: meta.num_dummy_evals,
            acc_fixed_bases,
            acc_msm_scratch,
        }
    }

    fn build_quotient_program_items(&self, items: &[QuotientProgramItem]) -> QuotientProgramBuild {
        let mut builder = QuotientProgramBuilder::default();
        // Mirror snark-verifier's loader cache shape: when VM CSE is enabled,
        // choose repeated expression temps across the whole quotient program,
        // not just within one identity.
        let mut cse = quotient_vm_cse_enabled().then(|| {
            let exprs = items
                .iter()
                .filter_map(|item| match item {
                    QuotientProgramItem::Identity(identity) => {
                        Some(Self::quotient_identity_expr(identity))
                    }
                    QuotientProgramItem::NativePermutation
                    | QuotientProgramItem::NativeIdentity(_) => None,
                })
                .collect::<Vec<_>>();
            QuotientCseState::from_exprs(&exprs)
        });

        for item in items {
            match item {
                QuotientProgramItem::Identity(identity) => {
                    let expr = Self::quotient_identity_expr(identity);
                    builder.identity_expr(&expr, identity.target, cse.as_mut());
                }
                QuotientProgramItem::NativePermutation => builder.native_permutation(),
                QuotientProgramItem::NativeIdentity(native_idx) => {
                    builder.native_identity(*native_idx);
                }
            }
        }

        builder.finish(quotient_program_encoding())
    }

    fn program_chunks(bytes: &[u8]) -> Vec<U256> {
        let mut padded = bytes.to_vec();
        padded.resize(padded.len().next_multiple_of(32), 0);
        padded
            .chunks(32)
            .map(U256::from_be_slice)
            .collect::<Vec<_>>()
    }

    /// Repack a midnight-proofs proof from the on-the-wire compressed
    /// form (each G1 = 48 bytes ZCash compressed) into the EIP-2537
    /// padded form (each G1 = 4 × 32-byte BE words) and rewrites scalar
    /// proof elements from midnight-proofs' canonical LE bytes into
    /// canonical BE calldata words. This is the Solidity-facing proof
    /// shim; the native proof bytes remain unchanged.
    ///
    /// This is the off-chain repack step the verifier expects: the
    /// EVM does **not** run the modexp-based BLS12-381 decompression
    /// at every G1 site (which would cost ~80 kg / commitment); the
    /// caller pays that cost off-chain once.
    ///
    /// The walk is driven entirely by the bound `&self.vk` /
    /// `&self.meta` (so it correctly handles the non-trivial proof
    /// shapes the codegen produces: per-phase advices, lookup
    /// multiplicities + chunked helpers + accumulators, perm Z
    /// products, trashcans, quotient limbs, eval block, dummy evals
    /// from `outer-fewer-point-sets`, f_com, q_evals per point set, pi).
    ///
    /// # Panics
    /// - Panics if any G1 in the input fails to decompress (off-curve
    ///   / bad subgroup / malformed compressed encoding).
    /// - Panics if `compressed` is shorter than the schema requires.
    pub fn repack_compressed_proof(&self, compressed: &[u8]) -> Vec<u8> {
        use group::prime::PrimeCurveAffine;
        use group::GroupEncoding;

        // ----------------------------------------------------------
        // Re-run the same num_dummy_evals / num_point_sets simulation
        // `generate_verifier` runs, so the repack walks the **exact**
        // proof layout the rendered Solidity body reads.
        // ----------------------------------------------------------
        let proof_cptr = Ptr::calldata(0x64);
        let vk = self.generate_vk();
        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));

        let raw_data = Data::new(&self.meta, &vk, vk_mptr, proof_cptr);
        let mut meta = self.meta.clone();
        let n_dummy = if cfg!(feature = "outer-fewer-point-sets") {
            BatchOpenScheme::num_dummy_queries(&meta, &raw_data)
        } else {
            0
        };
        let main_evals = meta.num_evals;
        meta.set_num_dummy_evals(n_dummy);
        let mut data = Data::new(&meta, &vk, vk_mptr, proof_cptr);
        if n_dummy > 0 {
            data.set_dummy_eval_words(main_evals, n_dummy);
        }
        let n_point_sets = BatchOpenScheme::num_point_sets(&meta, &data);

        // ----------------------------------------------------------
        // Build the prefix-G1 group counts in transcript order.
        // (Mirrors the ordering used by the codegen and tested in
        // `tests/poseidon_fixture.rs`.)
        // ----------------------------------------------------------
        let cs = self.vk.cs();
        let perm_chunks = cs.permutation().columns.chunks(cs.degree() - 2).count();
        let mut g1_groups: Vec<usize> = Vec::new();

        // User phases: each phase contributes its advice columns.
        let advice_phase = cs.advice_column_phase();
        let max_phase = *advice_phase.iter().max().unwrap_or(&0);
        for phase in 0..=max_phase {
            let n = advice_phase.iter().filter(|p| **p == phase).count();
            if n != 0 {
                g1_groups.push(n);
            }
        }
        if !cs.lookups().is_empty() {
            g1_groups.push(cs.lookups().len());
        }
        if perm_chunks != 0 {
            g1_groups.push(perm_chunks);
        }
        for l in cs.lookups().iter() {
            let nb_chunks = l.chunk_by_degree(cs.degree()).num_chunks();
            g1_groups.push(nb_chunks);
            g1_groups.push(1);
        }
        if !cs.trashcans().is_empty() {
            g1_groups.push(cs.trashcans().len());
        }
        let num_quotients = cs.degree() - 1;
        g1_groups.push(num_quotients);
        let prefix_g1_count: usize = g1_groups.iter().sum();

        let total_evals = meta.num_evals; // already includes dummy evals
        let expected_compressed_len =
            prefix_g1_count * 48 + total_evals * 32 + 48 + n_point_sets * 32 + 48;
        assert_eq!(
            compressed.len(),
            expected_compressed_len,
            "compressed proof length mismatch: expected {expected_compressed_len} bytes (prefix_g1={prefix_g1_count}, num_evals={total_evals}, num_point_sets={n_point_sets}, +f_com+pi), got {}",
            compressed.len()
        );

        let mut out: Vec<u8> = Vec::with_capacity(
            prefix_g1_count * 128 + total_evals * 32 + 128 + n_point_sets * 32 + 128,
        );
        let mut cursor = 0usize;
        let push_g1 = |cursor: &mut usize, out: &mut Vec<u8>| {
            let mut comp = <G1Affine as GroupEncoding>::Repr::default();
            comp.as_mut()
                .copy_from_slice(&compressed[*cursor..*cursor + 48]);
            let cur = *cursor;
            *cursor += 48;
            let pt: G1Affine = Option::from(<G1Affine as GroupEncoding>::from_bytes(&comp))
                .unwrap_or_else(|| {
                    panic!(
                        "decompress failed at compressed[{cur}..{}]: bytes = 0x{}",
                        cur + 48,
                        hex::encode(comp.as_ref())
                    )
                });
            if bool::from(pt.is_identity()) {
                out.extend_from_slice(&[0u8; 128]);
                return;
            }
            let x_be = pt.x().to_bytes_be();
            let y_be = pt.y().to_bytes_be();
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&x_be[0..16]);
            out.extend_from_slice(&x_be[16..48]);
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&y_be[0..16]);
            out.extend_from_slice(&y_be[16..48]);
        };
        let push_scalar_be = |cursor: &mut usize, out: &mut Vec<u8>| {
            out.extend_from_slice(&scalar_le_to_be_word(&compressed[*cursor..*cursor + 32]));
            *cursor += 32;
        };
        for &n in &g1_groups {
            for _ in 0..n {
                push_g1(&mut cursor, &mut out);
            }
        }
        // evals (Fr 32-byte LE in native proof) -> BE calldata words
        // (incl. dummy slots).
        for _ in 0..total_evals {
            push_scalar_be(&mut cursor, &mut out);
        }
        // f_com
        push_g1(&mut cursor, &mut out);
        // q_evals (Fr 32-byte LE in native proof) -> BE calldata words.
        for _ in 0..n_point_sets {
            push_scalar_be(&mut cursor, &mut out);
        }
        // pi
        push_g1(&mut cursor, &mut out);
        assert_eq!(
            cursor,
            compressed.len(),
            "compressed proof not fully consumed"
        );
        out
    }

    #[cfg(test)]
    pub(crate) fn repacked_proof_scalar_layout_for_test(&self) -> RepackedProofScalarLayout {
        let proof_cptr = Ptr::calldata(0x64);
        let vk = self.generate_vk();
        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));

        let raw_data = Data::new(&self.meta, &vk, vk_mptr, proof_cptr);
        let mut meta = self.meta.clone();
        let n_dummy = if cfg!(feature = "outer-fewer-point-sets") {
            BatchOpenScheme::num_dummy_queries(&meta, &raw_data)
        } else {
            0
        };
        let main_evals = meta.num_evals;
        meta.set_num_dummy_evals(n_dummy);
        let mut data = Data::new(&meta, &vk, vk_mptr, proof_cptr);
        if n_dummy > 0 {
            data.set_dummy_eval_words(main_evals, n_dummy);
        }
        let num_point_sets = BatchOpenScheme::num_point_sets(&meta, &data);

        let cs = self.vk.cs();
        let perm_chunks = cs.permutation().columns.chunks(cs.degree() - 2).count();
        let mut g1_groups: Vec<usize> = Vec::new();
        let advice_phase = cs.advice_column_phase();
        let max_phase = *advice_phase.iter().max().unwrap_or(&0);
        for phase in 0..=max_phase {
            let n = advice_phase.iter().filter(|p| **p == phase).count();
            if n != 0 {
                g1_groups.push(n);
            }
        }
        if !cs.lookups().is_empty() {
            g1_groups.push(cs.lookups().len());
        }
        if perm_chunks != 0 {
            g1_groups.push(perm_chunks);
        }
        for lookup in cs.lookups().iter() {
            let nb_chunks = lookup.chunk_by_degree(cs.degree()).num_chunks();
            g1_groups.push(nb_chunks);
            g1_groups.push(1);
        }
        if !cs.trashcans().is_empty() {
            g1_groups.push(cs.trashcans().len());
        }
        g1_groups.push(cs.degree() - 1);

        let prefix_g1_count: usize = g1_groups.iter().sum();
        let eval_offset = prefix_g1_count * 0x80;
        let q_eval_offset = eval_offset + meta.num_evals * 0x20 + 0x80;
        RepackedProofScalarLayout {
            eval_offset,
            num_evals: meta.num_evals,
            q_eval_offset,
            num_point_sets,
        }
    }

    fn static_working_memory_size(&self, vk: &Halo2VerifyingKey, proof_cptr: Ptr) -> usize {
        let pcs_computation = {
            let mock_vk_mptr = Ptr::memory(0x100000);
            let mock = Data::new(&self.meta, vk, mock_vk_mptr, proof_cptr);
            self.scheme.static_working_memory_size(&self.meta, &mock)
        };

        let transcript_words = Self::transcript_buffer_words_bound(&self.meta, self.num_instances);

        itertools::max([
            // Transcript buffer (streaming Keccak256). The buffer must
            // fit *below* `VK_MPTR` because every `mload(VK_MPTR + ...)`
            // assumes the VK contract bytes copied via `extcodecopy`
            // remain intact, and the buffer would otherwise overwrite
            // them as it grows past the start of the VK area.
            transcript_words,
            // PCS computation scratch
            pcs_computation,
            // Pairing: 2 G1 points (4 words each) + 2 G2 points (8 words each)
            // = 24 words, plus 1-word output buffer.
            25,
            // Modexp scratch for decompression (240 bytes input + 48
            // bytes output = 9 words; we round up to 16 to leave room
            // for separate scratch areas).
            16,
        ])
        .unwrap()
            * 0x20
    }

    fn transcript_buffer_words_bound(meta: &ConstraintSystemMeta, num_instances: usize) -> usize {
        // The Step 6 transcript model is a streaming Keccak256 buffer at
        // memory `[0..buf_len)`. The buffer monotonically grows between
        // two challenge squeezes and is reset to 32 bytes after each
        // squeeze, so the *peak* buf_len equals the longest absorb run
        // between two consecutive squeezes. For midnight-proofs verifiers
        // the dominating run is whichever of the following is largest:
        //   (a) initial absorbs (vk_digest + committed_pi + num_instances
        //       + all instance scalars + all phase-1 advices) before the
        //       first user-phase challenge squeeze (`theta`), or
        //   (b) the evaluation block (all `num_evals` scalars) absorbed
        //       after the `y` squeeze and before the next squeeze.
        //
        // We compute a per-run conservative upper bound for each and
        // take the max, then add the 32-byte post-squeeze seed cushion.
        //
        // Per-absorb costs in the patched (uncompressed-G1) emitter:
        //   - word                         = 32 bytes  (`common_word`)
        //   - uncompressed G1              = 128 bytes (`common_uncompressed_g1`)
        //   - squeeze output               = 32 bytes  (post-squeeze seed)
        // The earlier (compressed-G1) emitter used 49 bytes per G1; the
        // 49 used here is wrong now that the verifier hashes the 128-byte
        // EIP-2537 padded form, so we use 128. Mismatching the bound
        // causes the keccak buffer to overrun `VK_MPTR` mid-verify and
        // silently corrupt `K_MPTR`, `OMEGA_MPTR`, etc., producing a
        // multi-billion-gas spin in the Lagrange block.
        // (a) initial run: vk_digest (32) + committed_pi (128)
        //     + num_instances scalar (32) + num_instances * 32
        //     + phase-1 advices * 128 + 32 cushion.
        let phase_1_advices = meta.num_user_advices.first().copied().unwrap_or(0);
        let initial_run = 32                  // vk_digest
            + 128                             // committed_pi
            + 32                              // num_instances scalar
            + num_instances * 32              // committed instances
            + phase_1_advices * 128           // phase-1 advices
            + 32; // post-squeeze seed cushion

        // (b) eval-block run: quotient limbs + num_evals scalars
        //     + num_point_sets scalars + 32 cushion.
        let eval_run =
            meta.num_quotients * 128 + meta.num_evals * 32 + meta.num_point_sets * 32 + 32;

        // Catch-all: any other phase. We bound it by every G1 + every
        // scalar absorbed across the whole transcript; this is a strict
        // overestimate but cheap and finite.
        let total_g1: usize = meta.num_user_advices.iter().sum::<usize>()
            + meta.num_lookups
            + meta.num_permutation_zs
            + meta.lookup_chunks.iter().sum::<usize>()
            + meta.num_lookups
            + meta.num_trashcans
            + meta.num_quotients
            + 2; // f_com + pi
        let total_scalar = meta.num_evals + meta.num_point_sets + 32;
        let total_run = 32 + total_g1 * 128 + total_scalar * 32 + 32;

        initial_run.max(eval_run).max(total_run).div_ceil(0x20)
    }
}

/// Encode a midnight-proofs proof + instances into Halo2Verifier calldata.
///
/// In the midnight-proofs schema each G1 commitment in the proof byte
/// stream is the **48-byte compressed** BLS12-381 form. The Solidity
/// verifier expects G1s already expanded to EIP-2537 padded uncompressed
/// form and scalar proof elements already rewritten to canonical BE words by
/// `repack_compressed_proof`. This helper just wraps `encode_calldata` so
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
    fn transcript_memory_bound_handles_wide_bls_advice_phase() {
        let mut cs = ConstraintSystem::default();
        for _ in 0..64 {
            cs.advice_column();
        }
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
        let verifier_template = include_str!("../templates/Halo2Verifier.sol");
        let pcs_codegen = include_str!("codegen/pcs/gwc19.rs");

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
    fn external_quotient_template_has_no_unpinned_fallback() {
        let verifier_template = include_str!("../templates/Halo2Verifier.sol");

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
        let verifier_template = include_str!("../templates/Halo2Verifier.sol");

        assert!(
            verifier_template.contains("let acc_expected_words :="),
            "accumulator verifier must compute the generated public-input schema width"
        );
        assert!(
            verifier_template.contains("eq(mload(NUM_INSTANCES_MPTR), acc_expected_words)"),
            "accumulator verifier must reject extra or missing accumulator tail words"
        );
    }

    #[test]
    fn accumulator_limb_packing_is_checked_before_decoding() {
        let verifier_template = include_str!("../templates/Halo2Verifier.sol");

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
                include_str!("../templates/Halo2Verifier.sol"),
            ),
            (
                "Halo2VerifyingKey.sol",
                include_str!("../templates/Halo2VerifyingKey.sol"),
            ),
            (
                "Halo2QuotientEvaluator.sol",
                include_str!("../templates/Halo2QuotientEvaluator.sol"),
            ),
        ] {
            assert!(
                source.contains("pragma solidity ^0.8.24;"),
                "{name} must require Solidity 0.8.24+ for Cancun Yul opcodes"
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
