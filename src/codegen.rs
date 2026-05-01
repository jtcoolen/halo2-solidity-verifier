use crate::codegen::{
    evaluator::Evaluator,
    template::{Halo2Verifier, Halo2VerifyingKey, QuotientProgram, UserPhase},
    util::{fe_to_u256, g1_to_u256s, g2_to_u256s, ConstraintSystemMeta, Data, Ptr},
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
    plonk::VerifyingKey,
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
}

// Optional experiment: spend part of the verifier bytecode headroom recovered
// by moving the quotient payload into the VK. The first N identities are
// emitted as straight-line Yul, while the suffix remains interpreted by the
// compact VM. Keep the default at zero; benchmark with
// HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=N.
const DEFAULT_HYBRID_QUOTIENT_INLINE_IDENTITIES: usize = 0;
const HYBRID_QUOTIENT_INLINE_IDENTITIES_ENV: &str =
    "HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES";
const QUOTIENT_ENCODING_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_ENCODING";
const QUOTIENT_CSE_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_CSE";
const QUOTIENT_VM_CSE_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_VM_CSE";
const QUOTIENT_YUL_HELPERS_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_YUL_HELPERS";
const QUOTIENT_STRUCTURED_LOOPS_ENV: &str = "HALO2_SOLIDITY_QUOTIENT_STRUCTURED_LOOPS";

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

const Q_MEM_L0: u8 = 0x01;
const Q_MEM_L_LAST: u8 = 0x02;
const Q_MEM_L_BLIND: u8 = 0x03;
const Q_MEM_BETA: u8 = 0x04;
const Q_MEM_GAMMA: u8 = 0x05;
const Q_MEM_X: u8 = 0x06;
const Q_MEM_THETA: u8 = 0x07;
const Q_MEM_TRASH_CHALLENGE: u8 = 0x08;
const Q_MEM_INSTANCE_EVAL: u8 = 0x09;

#[derive(Clone, Debug)]
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

#[derive(Clone, Copy, Debug)]
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
    fn identity(
        &mut self,
        lines: &[String],
        final_var: &str,
        target: QuotientTarget,
        cse: Option<&mut QuotientCseState>,
    ) {
        self.vars.clear();
        self.stack_depth = 0;

        for line in lines {
            self.assignment(line);
        }
        self.expr(final_var, cse);
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

        assert_eq!(self.stack_depth, 0, "quotient VM stack leak");
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

    fn expr(&mut self, expr: &str, cse: Option<&mut QuotientCseState>) {
        let expr = self.parse_expr(expr);
        if let Some(cse) = cse {
            self.emit_expr_cse(&expr, cse);
        } else {
            self.emit_expr(&expr);
        }
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
            | Q_OP_STORE_TEMP => {
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
            Q_OP_ADD | Q_OP_MUL | Q_OP_NEG | Q_OP_FOLD_MAIN => {
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
        return false;
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
        | Q_OP_STORE_TEMP => 3,
        Q_OP_PUSH_MEM_LITERAL => 5,
        Q_OP_PUSH_MEM_TOKEN => 2,
        Q_OP_PUSH_MEM_TOKEN_OFFSET => 6,
        Q_OP_PUSH_CONST_U8 | Q_OP_ADD_CONST_U8 | Q_OP_MUL_CONST_U8 => 2,
        Q_OP_ADD | Q_OP_MUL | Q_OP_NEG | Q_OP_FOLD_MAIN => 1,
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
    value.starts_with("0x")
        || value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit())
}

fn parse_u256(value: &str) -> U256 {
    if let Some(hex) = value.strip_prefix("0x") {
        U256::from_str_radix(hex, 16).expect("valid hex U256")
    } else {
        U256::from_str_radix(value, 10).expect("valid decimal U256")
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
        self.generate_verifier(false, true, crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED)
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
        self.generate_verifier(false, crate::SOLIDITY_TRACE_ENABLED, true)
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

    /// Render a trace-enabled `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` into writers.
    pub fn render_trace_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(true, true, crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED)
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
        self.generate_verifier(true, crate::SOLIDITY_TRACE_ENABLED, true)
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
        let (identities, sorted_simple) = self.quotient_identities(meta, data);
        let inline_count = hybrid_quotient_inline_count(&identities);
        let quotient_program_build = self.build_quotient_program(&identities[inline_count..]);
        let _quotient_max_stack = quotient_program_build.max_stack;
        (quotient_program_build, sorted_simple)
    }

    fn quotient_identities(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
    ) -> (Vec<QuotientIdentity>, Vec<usize>) {
        let evaluator = Evaluator::new(self.vk.cs(), meta, data);
        let gate_items = evaluator.gate_computations_tagged();
        let perm_items = evaluator.permutation_computations();
        let lookup_items = evaluator.lookup_computations();
        let trash_items = evaluator.trashcan_computations();

        let mut sorted_simple: Vec<usize> = meta.simple_selector_cols.iter().copied().collect();
        sorted_simple.sort_unstable();

        let mut identities = Vec::with_capacity(
            gate_items.len() + perm_items.len() + lookup_items.len() + trash_items.len(),
        );
        for (lines, var, sel_idx) in gate_items {
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
            identities.push(QuotientIdentity { lines, var, target });
        }
        for (lines, var) in perm_items {
            identities.push(QuotientIdentity {
                lines,
                var,
                target: QuotientTarget::Main,
            });
        }
        for (lines, var) in lookup_items {
            identities.push(QuotientIdentity {
                lines,
                var,
                target: QuotientTarget::Main,
            });
        }
        for (lines, var) in trash_items {
            identities.push(QuotientIdentity {
                lines,
                var,
                target: QuotientTarget::Main,
            });
        }

        (identities, sorted_simple)
    }

    fn quotient_identity_expr(identity: &QuotientIdentity) -> QuotientExpr {
        let mut parser = QuotientProgramBuilder::default();
        for line in &identity.lines {
            parser.assignment(line);
        }
        parser.parse_expr(&identity.var)
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
            .map(Self::quotient_identity_expr)
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
        for line in lines {
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

    fn structured_permutation_scratch_words(meta: &ConstraintSystemMeta) -> usize {
        if meta.num_permutation_zs == 0 {
            return 0;
        }

        let num_cols = meta.permutation_columns.len();
        let num_sets = meta.num_permutation_zs;
        // permutation values, permutation sigma values, z_cur, z_next,
        // z_last for every non-final set.
        (2 * num_cols) + (2 * num_sets) + num_sets.saturating_sub(1)
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
        let delta_chunk = Fq::DELTA.pow_vartime([chunk_len as u64]);
        let delta_chunk = u256_string(fe_to_u256::<Fq>(&delta_chunk));

        let mut block = Vec::new();
        block.push("{".to_string());
        block.push(format!("let q_perm_vals := {vals_mptr:#x}"));
        block.push(format!("let q_perm_sigmas := {sigmas_mptr:#x}"));
        block.push(format!("let q_perm_z_cur := {z_cur_mptr:#x}"));
        block.push(format!("let q_perm_z_next := {z_next_mptr:#x}"));
        block.push(format!("let q_perm_z_last := {z_last_mptr:#x}"));
        block.push(format!("let q_perm_num_cols := {num_cols}"));
        block.push(format!("let q_perm_num_sets := {num_sets}"));
        block.push(format!("let q_perm_chunk_len := {chunk_len}"));
        block.push(format!("let q_perm_delta_chunk := {delta_chunk}"));

        for (idx, column) in meta.permutation_columns.iter().enumerate() {
            let offset = idx * 0x20;
            let value = evaluator.eval_at(column, 0);
            let sigma = data
                .permutation_evals
                .get(column)
                .expect("permutation sigma eval present")
                .to_string();
            block.push(format!("mstore(add(q_perm_vals, {offset:#x}), {value})"));
            block.push(format!("mstore(add(q_perm_sigmas, {offset:#x}), {sigma})"));
        }

        for (idx, (z_cur, z_next, z_last)) in data.permutation_z_evals.iter().enumerate() {
            let offset = idx * 0x20;
            block.push(format!("mstore(add(q_perm_z_cur, {offset:#x}), {})", z_cur));
            block.push(format!(
                "mstore(add(q_perm_z_next, {offset:#x}), {})",
                z_next
            ));
            if let Some(z_last) = z_last {
                block.push(format!(
                    "mstore(add(q_perm_z_last, {offset:#x}), {})",
                    z_last
                ));
            }
        }

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

        block.push("let q_perm_delta_base := q_perm_xbeta".to_string());
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
        block.push("let q_perm_delta_pow := q_perm_delta_base".to_string());
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
            "q_perm_delta_base := mulmod(q_perm_delta_base, q_perm_delta_chunk, r)".to_string(),
        );
        block.push("}".to_string());

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
        let evaluator = Evaluator::new(self.vk.cs(), meta, data);
        let eval_scratch_slot =
            scratch_mptr + Self::structured_permutation_scratch_words(meta) * 0x20;
        let gate_items = evaluator.gate_computations_tagged();
        let lookup_items = evaluator.lookup_computations();
        let trash_items = evaluator.trashcan_computations();

        let mut init = vec!["let quotient_eval_numer := 0".to_string()];
        for idx in 0..sorted_simple.len() {
            init.push(format!(
                "mstore(add(SELECTOR_ACC_MPTR, {:#x}), 0)",
                idx * 0x20
            ));
        }
        if !sorted_simple.is_empty() {
            init.push("let q_sel_scale := 1".to_string());
            init.push("let q_sel_inv_scale := 1".to_string());
            init.push("let q_y_inv := 0".to_string());
            init.push("{".to_string());
            init.push(format!("let q_inv_scratch := {eval_scratch_slot:#x}"));
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
            init.push("q_y_inv := mload(q_inv_scratch)".to_string());
            init.push("}".to_string());
        }
        let mut computations = vec![init];

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
            computations.push(Self::direct_quotient_block(
                &lines,
                &var,
                target,
                sorted_simple,
                eval_scratch_slot,
            ));
        }

        if let Some(block) = Self::structured_permutation_loop_block(
            meta,
            data,
            &evaluator,
            sorted_simple,
            scratch_mptr,
        ) {
            computations.push(block);
        }

        for (lines, var) in lookup_items {
            computations.push(Self::direct_quotient_block(
                &lines,
                &var,
                QuotientTarget::Main,
                sorted_simple,
                eval_scratch_slot,
            ));
        }

        for (lines, var) in trash_items {
            computations.push(Self::direct_quotient_block(
                &lines,
                &var,
                QuotientTarget::Main,
                sorted_simple,
                eval_scratch_slot,
            ));
        }

        if !sorted_simple.is_empty() {
            let mut tail = Vec::new();
            for i in 0..sorted_simple.len() {
                tail.push(format!(
                    "mstore(add(SELECTOR_ACC_MPTR, {:#x}), mulmod(mload(add(SELECTOR_ACC_MPTR, {:#x})), q_sel_scale, r))",
                    i * 0x20,
                    i * 0x20
                ));
            }
            computations.push(tail);
        }

        computations
    }

    fn generate_verifier(
        &self,
        separate: bool,
        trace: bool,
        gas_checkpoints: bool,
    ) -> Halo2Verifier {
        let proof_cptr = Ptr::calldata(0x64);

        let vk = self.generate_vk();
        let vk_mptr = Ptr::memory(self.static_working_memory_size(&vk, proof_cptr));

        let (meta, data) = self.meta_data_for_vk(&vk, vk_mptr, proof_cptr);

        let (identities, sorted_simple) = self.quotient_identities(&meta, &data);
        let use_inline_cse = quotient_inline_cse_enabled();
        let use_structured_loops = quotient_structured_loops_enabled();
        assert!(
            !(use_inline_cse && use_structured_loops),
            "{QUOTIENT_CSE_ENV}=1 and {QUOTIENT_STRUCTURED_LOOPS_ENV}=1 are mutually exclusive"
        );
        let quotient_yul_helpers = use_inline_cse && quotient_yul_helpers_enabled();
        let inline_count = if use_inline_cse || use_structured_loops {
            0
        } else {
            hybrid_quotient_inline_count(&identities)
        };
        let (inline_identities, vm_identities) = identities.split_at(inline_count);
        let sel_var = |idx: usize| format!("sel_acc_{}", sorted_simple[idx]);
        let quotient_program_build = (!(use_inline_cse || use_structured_loops))
            .then(|| self.build_quotient_program(vm_identities));

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

        if use_structured_loops {
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
            // Step 0: declare and zero-init all accumulators.
            {
                let mut init_lines = Vec::new();
                init_lines.push("let quotient_eval_numer := 0".to_string());
                for idx in 0..sorted_simple.len() {
                    init_lines.push(format!("let {} := 0", sel_var(idx)));
                }
                quotient_eval_numer_computations.push(init_lines);
            }

            // Helper that emits a self-contained Horner-fold step for one
            // identity. The eval is computed inside its own `{}` scope
            // (so per-block `v0..vN` locals don't collide with siblings)
            // and exported via a small per-step shim. We compute the
            // eval inside the block, store its value at scratch, and then
            // perform the Horner update at the outer scope. Using
            // mstore/mload here is wasteful but lets us keep the existing
            // `evaluate` contract untouched.
            // Scratch slot for piping each identity's eval out of its
            // inner `{}` block back to the outer Horner accumulator. Must
            // not overlap the generated verifier's VK, challenge, proof
            // commitment, simple-selector, or scalar-inversion regions.
            let eval_scratch_slot = quotient_stack_mptr;
            let make_block = |identity: &QuotientIdentity| -> Vec<String> {
                let mut block = Vec::with_capacity(identity.lines.len() + 6);
                // Inner block: compute the eval and stash it in a scratch slot.
                block.push("{".to_string());
                for l in &identity.lines {
                    block.push(l.clone());
                }
                block.push(format!("mstore({eval_scratch_slot:#x}, {})", identity.var));
                block.push("}".to_string());
                // Outer Horner update (re-loads from the scratch slot).
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
                block
            };

            let make_inline_block = |identity: &QuotientIdentity| -> Vec<String> {
                let mut block = Vec::with_capacity(identity.lines.len() + 8 + sorted_simple.len());
                block.push("{".to_string());
                for l in &identity.lines {
                    block.push(l.clone());
                }
                block.push(format!("mstore({eval_scratch_slot:#x}, {})", identity.var));
                block.push("}".to_string());
                block.push("quotient_eval_numer := mulmod(quotient_eval_numer, y, r)".to_string());
                if !sorted_simple.is_empty() {
                    block.push("q_sel_scale := mulmod(q_sel_scale, y, r)".to_string());
                    block
                        .push("q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)".to_string());
                }
                match identity.target {
                    QuotientTarget::Main => {
                        block.push(format!(
                        "quotient_eval_numer := addmod(quotient_eval_numer, mload({eval_scratch_slot:#x}), r)"
                    ));
                    }
                    QuotientTarget::Selector(idx) => {
                        block.push(format!(
                        "mstore(add(SELECTOR_ACC_MPTR, {:#x}), addmod(mload(add(SELECTOR_ACC_MPTR, {:#x})), mulmod(mload({eval_scratch_slot:#x}), q_sel_inv_scale, r), r))",
                        idx * 0x20,
                        idx * 0x20
                    ));
                    }
                }
                block
            };

            for identity in inline_identities {
                quotient_inline_computations.push(make_inline_block(identity));
            }
            for identity in &identities {
                quotient_eval_numer_computations.push(make_block(identity));
            }

            // Tail block: store each simple-selector accumulator at a
            // dedicated scratch slot so the linearization-MSM emitter can
            // pick them up. The base is placed after the decompressed proof
            // commitments; later PCS scratch tables may reuse it after the
            // linearization MSM has consumed these values.
            if !sorted_simple.is_empty() {
                let mut tail = Vec::new();
                for i in 0..sorted_simple.len() {
                    tail.push(format!(
                        "mstore(add(SELECTOR_ACC_MPTR, {:#x}), {})",
                        i * 0x20,
                        sel_var(i)
                    ));
                }
                quotient_eval_numer_computations.push(tail);
            }
        }

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
            proof_cptr,
            num_instance_cptr: proof_cptr.value().as_usize() + meta.proof_len(self.scheme),
            instance_cptr: proof_cptr.value().as_usize() + meta.proof_len(self.scheme) + 0x20,
            quotient_comm_cptr: data.quotient_comm_cptr,
            proof_len: meta.proof_len(self.scheme),
            challenge_mptr: data.challenge_mptr,
            theta_mptr: data.theta_mptr,
            quotient_inline_computations,
            quotient_eval_numer_computations,
            quotient_program,
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

    fn build_quotient_program(&self, identities: &[QuotientIdentity]) -> QuotientProgramBuild {
        let mut builder = QuotientProgramBuilder::default();
        // Mirror snark-verifier's loader cache shape: when VM CSE is enabled,
        // choose repeated expression temps across the whole quotient program,
        // not just within one identity.
        let mut cse = quotient_vm_cse_enabled().then(|| {
            let exprs = identities
                .iter()
                .map(Self::quotient_identity_expr)
                .collect::<Vec<_>>();
            QuotientCseState::from_exprs(&exprs)
        });

        for identity in identities {
            builder.identity(
                &identity.lines,
                &identity.var,
                identity.target,
                cse.as_mut(),
            );
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
    /// padded form (each G1 = 4 × 32-byte BE words) the rendered
    /// Solidity verifier reads from calldata.
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
        for &n in &g1_groups {
            for _ in 0..n {
                push_g1(&mut cursor, &mut out);
            }
        }
        // evals (Fr 32-byte LE) - pass through (incl. dummy slots).
        out.extend_from_slice(&compressed[cursor..cursor + total_evals * 32]);
        cursor += total_evals * 32;
        // f_com
        push_g1(&mut cursor, &mut out);
        // q_evals
        out.extend_from_slice(&compressed[cursor..cursor + n_point_sets * 32]);
        cursor += n_point_sets * 32;
        // pi
        push_g1(&mut cursor, &mut out);
        assert_eq!(
            cursor,
            compressed.len(),
            "compressed proof not fully consumed"
        );
        out
    }

    fn static_working_memory_size(&self, vk: &Halo2VerifyingKey, proof_cptr: Ptr) -> usize {
        let pcs_computation = {
            let mock_vk_mptr = Ptr::memory(0x100000);
            let mock = Data::new(&self.meta, vk, mock_vk_mptr, proof_cptr);
            self.scheme.static_working_memory_size(&self.meta, &mock)
        };

        // The Step 6 transcript model is a streaming Keccak256 buffer at
        // memory `[0..buf_len)`. The buffer monotonically grows between
        // two challenge squeezes and is reset to 64 bytes after each
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
        // take the max, then add the 64-byte post-squeeze seed cushion.
        //
        // Per-absorb costs in the patched (uncompressed-G1) emitter:
        //   - PREFIX_COMMON || word        = 33 bytes  (`common_word`)
        //   - PREFIX_COMMON || 128 bytes   = 129 bytes (`common_uncompressed_g1`)
        //   - PREFIX_CHALLENGE || forks    = 64 bytes  (post-squeeze seed)
        // The earlier (compressed-G1) emitter used 49 bytes per G1; the
        // 49 used here is wrong now that the verifier hashes the 128-byte
        // EIP-2537 padded form, so we use 129. Mismatching the bound
        // causes the keccak buffer to overrun `VK_MPTR` mid-verify and
        // silently corrupt `K_MPTR`, `OMEGA_MPTR`, etc., producing a
        // multi-billion-gas spin in the Lagrange block.
        let transcript_words: usize = {
            // (a) initial run: vk_digest (33) + committed_pi (129)
            //     + num_instances scalar (33) + num_instances * 33
            //     + phase_1_advices * 129 + 64 cushion.
            let phase_1_advices = self.meta.num_user_advices.first().copied().unwrap_or(0);
            let initial_run = 33                      // vk_digest
                + 129                                 // committed_pi
                + 33                                  // num_instances scalar
                + self.num_instances * 33             // committed instances
                + phase_1_advices * 129               // phase-1 advices
                + 64; // post-squeeze seed cushion

            // (b) eval-block run: quotient_limbs (Keccak common_uncompressed
            //     of each quotient G1) + num_evals scalars + num_point_sets
            //     scalars + 64 cushion.
            let eval_run = self.meta.num_quotients * 129
                + self.meta.num_evals * 33
                + self.meta.num_point_sets * 33
                + 64;

            // Catch-all: any other phase. We bound it by every G1 + every
            // scalar absorbed across the whole transcript; this is a
            // strict overestimate but cheap and finite.
            let total_g1: usize = self.meta.num_user_advices.iter().sum::<usize>()
                + self.meta.num_lookups
                + self.meta.num_permutation_zs
                + self.meta.lookup_chunks.iter().sum::<usize>()
                + self.meta.num_lookups
                + self.meta.num_trashcans
                + self.meta.num_quotients
                + 2; // f_com + pi
            let total_scalar = self.meta.num_evals + self.meta.num_point_sets + 32;
            let total_run = 64 + total_g1 * 129 + total_scalar * 33 + 64;

            let peak = initial_run.max(eval_run).max(total_run);
            peak.div_ceil(0x20)
        };

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
}

/// Encode a midnight-proofs proof + instances into Halo2Verifier calldata.
///
/// In the midnight-proofs schema each G1 commitment in the proof byte
/// stream is the **48-byte compressed** BLS12-381 form. The Solidity
/// verifier decompresses internally and feeds EIP-2537 the padded
/// uncompressed form, so the calldata stays a flat byte concatenation
/// of `(compressed-G1 | scalars | compressed-G1 | scalars | ...)` with
/// the exact layout `parse_trace` consumes. This helper just wraps
/// `encode_calldata` so callers don't have to import `evm`.
pub fn encode_calldata_bls_padded(
    _generator: &SolidityGenerator<'_>,
    proof: &[u8],
    instances: &[Fq],
) -> Vec<u8> {
    crate::evm::encode_calldata(proof, instances)
}
