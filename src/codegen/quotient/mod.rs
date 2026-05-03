use super::*;

// Compact quotient-identity bytecode interpreted by the generated Yul verifier.
// The identities are still derived from the same evaluator output; this only
// changes how the arithmetic is represented in deployed bytecode.
#[derive(Clone, Copy, Debug)]
pub(super) enum QuotientTarget {
    Main,
    Selector(usize),
}

#[derive(Debug)]
pub(super) struct QuotientProgramBuild {
    pub(super) bytes: Vec<u8>,
    pub(super) consts: Vec<U256>,
    pub(super) max_stack: usize,
    pub(super) packed32: bool,
    pub(super) cse_temps: usize,
}

#[derive(Clone, Debug)]
pub(super) struct QuotientIdentity {
    pub(super) lines: Vec<String>,
    pub(super) var: String,
    pub(super) target: QuotientTarget,
    pub(super) expr: Option<QuotientExpr>,
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

#[derive(Clone, Debug)]
pub(super) enum QuotientProgramItem {
    Identity(QuotientIdentity),
    NativePermutation,
    NativeIdentity(usize),
}

#[derive(Clone, Debug)]
pub(super) struct QuotientProgramPlan {
    pub(super) inline_identities: Vec<QuotientIdentity>,
    pub(super) items: Vec<QuotientProgramItem>,
    pub(super) native_identities: Vec<QuotientIdentity>,
    pub(super) sorted_simple: Vec<usize>,
    pub(super) has_native_permutation: bool,
}

pub(super) const QUOTIENT_EXTERNAL_MAGIC: u64 = 0x5155_4556_414c_0001;
pub(super) const LIMB7_YUL_COEFFS: [&str; 6] = [
    "0x100000000000000",
    "0x10000000000000000000000000000",
    "0x400000000",
    "0x40000000000000000000000",
    "0x1000",
    "0x100000000000000000",
];
pub(super) const WIDE_LIMB7_YUL_COEFFS: [&str; 6] = [
    "0x100000000000000",
    "0x10000000000000000000000000000",
    "0x1000000000000000000000000000000000000000000",
    "0x100000000000000000000000000000000000000000000000000000000",
    "0x6bc66e553973f396854f5626172ba135587d41e37a68209402355093fdcaaf6c",
    "0x63f31e3f446953960c9d6964474300df43ab29179970f642a28e39d6c883c74b",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuotientProgramEncoding {
    Bytes,
    Packed32,
}

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
    pub(super) slots: HashMap<String, u16>,
    pub(super) emitted: HashMap<String, u16>,
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
        format!("{:#x}", self.cse_mptr + slot * 0x20)
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
        // numerator or into the simple-selector bucket.
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

    pub(super) fn native_permutation(&mut self) {
        assert_eq!(
            self.stack_depth, 0,
            "native permutation expects empty VM stack"
        );
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

    pub(super) fn assignment(&mut self, line: &str) {
        let line = line.trim();
        let line = line.strip_prefix("let ").unwrap_or(line);
        let (dst, expr) = line
            .split_once(" := ")
            .unwrap_or_else(|| panic!("unsupported quotient assignment: {line}"));
        let expr = self.parse_expr(expr.trim());
        self.vars.insert(dst.trim().to_string(), expr);
    }

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

            cse.emitted.insert(key, slot);
            self.emit_expr_cse_inner(expr, cse);
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
                    idx += 3;
                }
                _ => idx += quotient_op_len(&self.bytes, idx),
            }
        }
        temps
    }
}

pub(super) fn compact_quotient_runs(bytes: &[u8]) -> Vec<u8> {
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

pub(super) fn pack_quotient_u32_program(bytes: &[u8]) -> Vec<u8> {
    if quotient_program_uses_limb_ops(bytes) {
        panic!("{QUOTIENT_LIMB_VM_OPS_ENV}=1 is only supported with {QUOTIENT_ENCODING_ENV}=bytes");
    }

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

pub(super) fn quotient_program_uses_limb_ops(bytes: &[u8]) -> bool {
    let mut idx = 0usize;
    while idx < bytes.len() {
        if matches!(
            bytes[idx],
            Q_OP_LIN7 | Q_OP_BILIN7_ROW | Q_OP_BILIN7_PAIRWISE
        ) {
            return true;
        }
        idx += quotient_op_len(bytes, idx);
    }
    false
}

pub(super) fn push_packed_quotient_op(out: &mut Vec<u8>, op: u8, arg: u32) {
    assert!(
        arg <= 0x00ff_ffff,
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
    // Straight-line CSE stores the first evaluation in memory and replaces
    // every use with an mload. Keep only expressions with enough estimated
    // duplicated arithmetic to pay for the mstore/mload bytecode.
    (count - 1) * cost > 12
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

pub(super) fn quotient_mem_token_from_name(name: &str) -> Option<u8> {
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
        Q_OP_LIN7 => 1 + 7 * 3,
        Q_OP_BILIN7_ROW => 1 + 2 + 7 * 3,
        Q_OP_BILIN7_PAIRWISE => 1 + 2 + 2 + 13,
        op => panic!("unknown quotient op {op:#x} at byte {idx}"),
    }
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
    if grouped.len() != 7 {
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
    if pairs.len() != 7 {
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
        if ok && grouped.len() == 7 {
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
    if pairs.len() != 49 {
        return None;
    }

    let bases = limb7_base_candidates(&ptrs);
    for lhs_base in &bases {
        for rhs_base in &bases {
            let mut coeffs = vec![Fq::ZERO; 49];
            let mut seen = [false; 49];
            let mut ok = true;

            for (coeff, lhs, rhs) in &pairs {
                let direct = limb7_index(*lhs_base, *lhs).zip(limb7_index(*rhs_base, *rhs));
                let swapped = limb7_index(*lhs_base, *rhs).zip(limb7_index(*rhs_base, *lhs));
                let Some((i, j)) = direct.or(swapped) else {
                    ok = false;
                    break;
                };
                let idx = i * 7 + j;
                coeffs[idx] += *coeff;
                seen[idx] = true;
            }

            if !ok || seen.iter().any(|seen| !seen) {
                continue;
            }

            let mut by_sum = vec![None; 13];
            for i in 0..7 {
                for j in 0..7 {
                    let coeff = coeffs[i * 7 + j];
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
            (0..7).all(|idx| {
                base.checked_add((idx * 0x20) as u16)
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
    if diff % 0x20 != 0 {
        return None;
    }
    let idx = (diff / 0x20) as usize;
    (idx < 7).then_some(idx)
}

pub(super) fn quotient_fq_from_u256(value: U256) -> Option<Fq> {
    let bytes = value.to_le_bytes::<32>();
    let repr = <Fq as PrimeField>::Repr::from(bytes);
    Option::<Fq>::from(Fq::from_repr(repr))
}

pub(super) fn quotient_fq_to_u256(value: Fq) -> U256 {
    fe_to_u256::<Fq>(&value)
}

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

pub(super) fn mem_token(name: &str) -> Option<u8> {
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

pub(super) fn yul_let_assignment(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let line = line.strip_prefix("let ")?;
    let (dst, expr) = line.split_once(" := ")?;
    Some((dst.trim().to_string(), expr.trim().to_string()))
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
    let prefix = format!("{name}(");
    if !expr.starts_with(&prefix) || !expr.ends_with(')') {
        return None;
    }
    Some(split_top_level(&expr[prefix.len()..expr.len() - 1]))
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
