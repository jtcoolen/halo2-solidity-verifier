#![allow(clippy::useless_format)]

//! Quotient-numerator emitter.
//!
//! This module walks the gates / permutation / lookup / trash arguments
//! stored in a `midnight_proofs::plonk::ConstraintSystem` and emits the
//! Yul lines that compute their per-row contributions to
//! `quotient_eval_numer` at the evaluation challenge `x`.
//!
//! ## Step 4 status (2026-04-26)
//!
//! All four emitters are now ported:
//!
//!   * [`Evaluator::gate_computations`]      — per-gate `polynomials()`
//!   * [`Evaluator::permutation_computations`] — boundary + product equality
//!   * [`Evaluator::lookup_computations`]    — boundary + helper + accumulator
//!   * [`Evaluator::trashcan_computations`]  — `compressed - (1-q)*trash`
//!
//! Each returns a `Vec<(Vec<String>, String)>` where the inner pair is
//! `(yul_lines, final_var)`; the caller (in `codegen.rs`) chains them
//! into `quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r),
//! var, r)` (the y-power-fold accumulator).
//!
//! All emitters reference well-known Yul memory pointers that the
//! verifier prologue (Step 6) will populate before invoking the
//! quotient-numerator block. Names follow the original
//! halo2-solidity-verifier convention except for `TRASH_CHALLENGE_MPTR`,
//! which is new in midnight-proofs.

use std::{cell::RefCell, cmp::Ordering, collections::HashMap};

use ff::{Field, PrimeField};
use midnight_curves::Fq;
use midnight_proofs::plonk::{Any, Column, ConstraintSystem, Expression};
use ruint::aliases::U256;

use crate::codegen::util::{fe_to_u256, ConstraintSystemMeta, Data, Word};

#[derive(Debug)]
pub(crate) struct Evaluator<'a> {
    cs: &'a ConstraintSystem<Fq>,
    meta: &'a ConstraintSystemMeta,
    data: &'a Data,
    var_counter: RefCell<usize>,
    var_cache: RefCell<HashMap<String, String>>,
}

impl<'a> Evaluator<'a> {
    pub(crate) fn new(
        cs: &'a ConstraintSystem<Fq>,
        meta: &'a ConstraintSystemMeta,
        data: &'a Data,
    ) -> Self {
        Self {
            cs,
            meta,
            data,
            var_counter: Default::default(),
            var_cache: Default::default(),
        }
    }

    // ----------------------------------------------------------------
    // Gate emitter: one constraint per gate-polynomial.
    // ----------------------------------------------------------------

    pub fn gate_computations(&self) -> Vec<(Vec<String>, String)> {
        self.cs
            .gates()
            .iter()
            .flat_map(|gate| {
                gate.polynomials()
                    .iter()
                    .map(|poly| self.evaluate_and_reset(poly))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Like [`gate_computations`], but additionally tags each gate
    /// polynomial with its simple-selector fixed-column index (if any).
    /// Mirrors `partially_evaluate_identities` in
    /// `midfall/proofs/src/plonk/mod.rs`: for each gate, the simple
    /// selector index is `gate.queried_selectors().filter(|s|
    /// s.is_simple()).next().map(|s| s.index())`. After
    /// `directly_convert_selectors_to_fixed`, a simple selector's
    /// `index()` equals the fixed column index of its replacement
    /// (selector indices were shifted by `nr_fixed_columns`).
    pub fn gate_computations_tagged(&self) -> Vec<(Vec<String>, String, Option<usize>)> {
        self.cs
            .gates()
            .iter()
            .flat_map(|gate| {
                let simple_idx = gate
                    .queried_selectors()
                    .iter()
                    .find(|s| s.is_simple())
                    .map(|s| s.index());
                gate.polynomials()
                    .iter()
                    .map(|poly| {
                        let (lines, var) = self.evaluate_and_reset(poly);
                        (lines, var, simple_idx)
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    // ----------------------------------------------------------------
    // Permutation emitter.
    //
    // Mirrors `midfall/proofs/src/plonk/permutation.rs::expressions`:
    //
    //   1. l_0 * (1 - z_0)                              [first set]
    //   2. l_last * (z_n^2 - z_n)                       [last set]
    //   3. l_0 * (z_i - z_{i-1}_last)                   [for i >= 1]
    //   4. (1 - (l_last + l_blind)) * (left_i - right_i) [for each set]
    //      where
    //        left_i  = z_i_next * ∏_{c in chunk_i} (eval(c) + β·s(c) + γ)
    //        right_i = z_i      * ∏_{c in chunk_i} (eval(c) + δ_pow + γ)
    //        δ_pow   starts at β·x·δ^(i*chunk_len) and is *= δ each step
    //
    // δ is the field's `PrimeField::DELTA` constant (a generator of
    // a small-order multiplicative subgroup that separates the chunk
    // permutation cosets).
    // ----------------------------------------------------------------

    pub fn permutation_computations(&self) -> Vec<(Vec<String>, String)> {
        if self.meta.num_permutation_zs == 0 {
            return Vec::new();
        }

        let chunk_len = self.meta.permutation_chunk_len;
        let columns = &self.meta.permutation_columns;
        let z_evals = &self.data.permutation_z_evals;

        let mut out: Vec<(Vec<String>, String)> = Vec::new();

        // 1. First-set boundary: l_0 * (1 - z_0_cur)
        {
            self.reset();
            let mut lines = Vec::new();
            let z0 = z_evals.first().expect("perm sets non-empty").0.to_string();
            let l0 = self.fresh_var();
            lines.push(format!("let {l0} := mload(L_0_MPTR)"));
            let one_minus_z0 = self.fresh_var();
            lines.push(format!("let {one_minus_z0} := addmod(1, sub(r, {z0}), r)"));
            let bnd_first = self.fresh_var();
            lines.push(format!(
                "let {bnd_first} := mulmod({l0}, {one_minus_z0}, r)"
            ));
            out.push((lines, bnd_first));
        }

        // 2. Last-set boundary: l_last * (z_n^2 - z_n)
        {
            self.reset();
            let mut lines = Vec::new();
            let zn = z_evals.last().expect("perm sets non-empty").0.to_string();
            let llast = self.fresh_var();
            lines.push(format!("let {llast} := mload(L_LAST_MPTR)"));
            let zn_sq = self.fresh_var();
            lines.push(format!("let {zn_sq} := mulmod({zn}, {zn}, r)"));
            let zn_sq_minus_zn = self.fresh_var();
            lines.push(format!(
                "let {zn_sq_minus_zn} := addmod({zn_sq}, sub(r, {zn}), r)"
            ));
            let bnd_last = self.fresh_var();
            lines.push(format!(
                "let {bnd_last} := mulmod({llast}, {zn_sq_minus_zn}, r)"
            ));
            out.push((lines, bnd_last));
        }

        // 3. Set-to-set continuity: l_0 * (z_i_cur - z_{i-1}_last)
        for i in 1..self.meta.num_permutation_zs {
            self.reset();
            let mut lines = Vec::new();
            let zi = z_evals[i].0.to_string();
            let z_prev_last = z_evals[i - 1]
                .2
                .as_ref()
                .expect("non-last set has last eval")
                .to_string();
            let l0 = self.fresh_var();
            lines.push(format!("let {l0} := mload(L_0_MPTR)"));
            let diff = self.fresh_var();
            lines.push(format!(
                "let {diff} := addmod({zi}, sub(r, {z_prev_last}), r)"
            ));
            let cont = self.fresh_var();
            lines.push(format!("let {cont} := mulmod({l0}, {diff}, r)"));
            out.push((lines, cont));
        }

        // 4. Per-set product equality.
        let delta = fe_to_u256::<Fq>(&Fq::DELTA);
        for (set_idx, ((z_cur, z_next, _), chunk_cols)) in
            z_evals.iter().zip(columns.chunks(chunk_len)).enumerate()
        {
            self.reset();
            let mut lines = Vec::new();

            // active_rows = 1 - (l_last + l_blind)
            let l_last = self.fresh_var();
            lines.push(format!("let {l_last} := mload(L_LAST_MPTR)"));
            let l_blind = self.fresh_var();
            lines.push(format!("let {l_blind} := mload(L_BLIND_MPTR)"));
            let l_last_plus_blind = self.fresh_var();
            lines.push(format!(
                "let {l_last_plus_blind} := addmod({l_last}, {l_blind}, r)"
            ));
            let active = self.fresh_var();
            lines.push(format!(
                "let {active} := addmod(1, sub(r, {l_last_plus_blind}), r)"
            ));

            let beta = self.fresh_var();
            lines.push(format!("let {beta} := mload(BETA_MPTR)"));
            let gamma = self.fresh_var();
            lines.push(format!("let {gamma} := mload(GAMMA_MPTR)"));

            // left = z_next * ∏ (eval(c) + β * s_eval(c) + γ)
            let left = self.fresh_var();
            lines.push(format!("let {left} := {}", z_next.to_string()));
            for col in chunk_cols {
                let col_eval = self.eval_at(col, 0);
                let s_eval = self
                    .data
                    .permutation_evals
                    .get(col)
                    .expect("permutation eval present")
                    .to_string();
                let beta_s = self.fresh_var();
                lines.push(format!("let {beta_s} := mulmod({beta}, {s_eval}, r)"));
                let term = self.fresh_var();
                lines.push(format!(
                    "let {term} := addmod(addmod({col_eval}, {beta_s}, r), {gamma}, r)"
                ));
                lines.push(format!("{left} := mulmod({left}, {term}, r)"));
            }

            // right = z_cur * ∏ (eval(c) + δ_pow + γ)
            //   δ_pow_0 = β * x * δ^(set_idx * chunk_len)
            //   δ_pow_{j+1} = δ_pow_j * δ
            let initial_delta_power = Fq::DELTA.pow_vartime([(set_idx * chunk_len) as u64]);
            let initial_delta_u256 = fe_to_u256::<Fq>(&initial_delta_power);
            let delta_pow = self.fresh_var();
            lines.push(format!(
                "let {delta_pow} := mulmod(mulmod({beta}, mload(X_MPTR), r), {}, r)",
                u256_string(initial_delta_u256)
            ));
            let right = self.fresh_var();
            lines.push(format!("let {right} := {}", z_cur.to_string()));
            for col in chunk_cols {
                let col_eval = self.eval_at(col, 0);
                let term = self.fresh_var();
                lines.push(format!(
                    "let {term} := addmod(addmod({col_eval}, {delta_pow}, r), {gamma}, r)"
                ));
                lines.push(format!("{right} := mulmod({right}, {term}, r)"));
                lines.push(format!(
                    "{delta_pow} := mulmod({delta_pow}, {}, r)",
                    u256_string(delta)
                ));
            }

            let diff = self.fresh_var();
            lines.push(format!("let {diff} := addmod({left}, sub(r, {right}), r)"));
            let constraint = self.fresh_var();
            lines.push(format!("let {constraint} := mulmod({active}, {diff}, r)"));
            out.push((lines, constraint));
        }

        out
    }

    // ----------------------------------------------------------------
    // LogUp emitter.
    //
    // Mirrors `midfall/proofs/src/plonk/logup.rs::Evaluated::expressions`:
    //
    //   For each lookup:
    //     boundary = (l_0 + l_last) * z_eval
    //     for each chunk c:
    //       compressed_inputs[j] = θ-fold-compress(input_chunk_c[j])
    //       f_plus_β[j]          = compressed_inputs[j] + β
    //       P                    = ∏_j f_plus_β[j]
    //       partial[j]           = P / f_plus_β[j]   (computed via prefix*suffix)
    //       sum                  = Σ_j partial[j]
    //       helper_constraint    = h_eval[c] * P - sum
    //     accumulator_constraint =
    //       (z_next - z - selector·Σh_eval) * (compressed_table + β) + m_eval
    //       all multiplied by active_rows = 1 - (l_last + l_blind)
    // ----------------------------------------------------------------

    pub fn lookup_computations(&self) -> Vec<(Vec<String>, String)> {
        if self.meta.num_lookups == 0 {
            return Vec::new();
        }

        let cs_degree = self.cs.degree();
        let mut out: Vec<(Vec<String>, String)> = Vec::new();

        for (lookup_idx, lookup) in self.cs.lookups().iter().enumerate() {
            let chunked = lookup.chunk_by_degree(cs_degree);
            let (m_eval, h_evals, z_eval, z_next_eval) = &self.data.lookup_evals[lookup_idx];

            // Boundary: (l_0 + l_last) * z_eval
            {
                self.reset();
                let mut lines = Vec::new();
                let l_0 = self.fresh_var();
                lines.push(format!("let {l_0} := mload(L_0_MPTR)"));
                let l_last = self.fresh_var();
                lines.push(format!("let {l_last} := mload(L_LAST_MPTR)"));
                let l_sum = self.fresh_var();
                lines.push(format!("let {l_sum} := addmod({l_0}, {l_last}, r)"));
                let bnd = self.fresh_var();
                lines.push(format!(
                    "let {bnd} := mulmod({l_sum}, {}, r)",
                    z_eval.to_string()
                ));
                out.push((lines, bnd));
            }

            // Pre-evaluate selector once (used by accumulator
            // constraint). We stash its var name across iterations.
            let selector_expr = chunked.selector_expression();

            // Per-chunk helper constraints.
            let mut sum_helpers_var: Option<String> = None;

            // Re-emit selector inside each block (the var cache is reset
            // per-constraint). To avoid emitting it twice, we evaluate it
            // *once* here and inline its value into the eventual
            // accumulator constraint.
            //
            // Memo: each constraint resets self.var_cache, so vars do not
            // leak between (Vec<String>, String) entries.

            for (chunk_idx, (input_chunk, h_eval)) in chunked
                .input_expression_chunks()
                .iter()
                .zip(h_evals.iter())
                .enumerate()
            {
                self.reset();
                let mut lines = Vec::new();

                let beta = self.fresh_var();
                lines.push(format!("let {beta} := mload(BETA_MPTR)"));

                // Compute compressed_input + β for each parallel-lookup
                // entry in this chunk.
                let mut f_plus_beta_vars: Vec<String> = Vec::new();
                for parallel_input in input_chunk.iter() {
                    let compressed = self.compress_expressions_with_theta(parallel_input);
                    let (mut compressed_lines, compressed_var) = compressed;
                    lines.append(&mut compressed_lines);
                    let fb = self.fresh_var();
                    lines.push(format!("let {fb} := addmod({compressed_var}, {beta}, r)"));
                    f_plus_beta_vars.push(fb);
                }

                let k = f_plus_beta_vars.len();
                if k == 0 {
                    // Empty chunk shouldn't happen but emit a no-op.
                    let zero = self.fresh_var();
                    lines.push(format!("let {zero} := 0"));
                    out.push((lines, zero));
                    continue;
                }

                // P = ∏_j f_plus_β[j]
                let p = self.fresh_var();
                lines.push(format!("let {p} := {}", f_plus_beta_vars[0]));
                for fb in &f_plus_beta_vars[1..] {
                    lines.push(format!("{p} := mulmod({p}, {fb}, r)"));
                }

                // Build partial products via prefix * suffix.
                //   prefix[j] = ∏_{i<j} f_plus_β[i],  prefix[0] = 1
                //   suffix[j] = ∏_{i>j} f_plus_β[i],  suffix[k-1] = 1
                //   partial[j] = prefix[j] * suffix[j]
                let mut prefix_vars: Vec<String> = Vec::with_capacity(k);
                {
                    let p0 = self.fresh_var();
                    lines.push(format!("let {p0} := 1"));
                    prefix_vars.push(p0);
                    for j in 1..k {
                        let pj = self.fresh_var();
                        lines.push(format!(
                            "let {pj} := mulmod({}, {}, r)",
                            prefix_vars[j - 1],
                            f_plus_beta_vars[j - 1]
                        ));
                        prefix_vars.push(pj);
                    }
                }
                let mut suffix_vars: Vec<String> = vec![String::new(); k];
                {
                    let sk = self.fresh_var();
                    lines.push(format!("let {sk} := 1"));
                    suffix_vars[k - 1] = sk;
                    for j in (0..k - 1).rev() {
                        let sj = self.fresh_var();
                        lines.push(format!(
                            "let {sj} := mulmod({}, {}, r)",
                            suffix_vars[j + 1],
                            f_plus_beta_vars[j + 1]
                        ));
                        suffix_vars[j] = sj;
                    }
                }

                // sum = Σ_j prefix[j] * suffix[j]
                let sum_var = self.fresh_var();
                lines.push(format!(
                    "let {sum_var} := mulmod({}, {}, r)",
                    prefix_vars[0], suffix_vars[0]
                ));
                for j in 1..k {
                    let term = self.fresh_var();
                    lines.push(format!(
                        "let {term} := mulmod({}, {}, r)",
                        prefix_vars[j], suffix_vars[j]
                    ));
                    lines.push(format!("{sum_var} := addmod({sum_var}, {term}, r)"));
                }

                // helper_constraint = h_eval * P - sum
                let h_p = self.fresh_var();
                lines.push(format!(
                    "let {h_p} := mulmod({}, {p}, r)",
                    h_eval.to_string()
                ));
                let helper_c = self.fresh_var();
                lines.push(format!(
                    "let {helper_c} := addmod({h_p}, sub(r, {sum_var}), r)"
                ));
                out.push((lines, helper_c));

                // Sum of helper evals (used by accumulator constraint).
                // Build incrementally outside this loop. We track the
                // running symbolic name; since the accumulator constraint
                // resets `self`, we just remember the *Word* values and
                // re-emit later.
                let _ = chunk_idx;
                let _ = h_eval;
                let _ = sum_helpers_var.take(); // explicit reset
            }

            // Accumulator constraint:
            //   active * ((z_next - z - s · Σh) · (t + β) + m)
            {
                self.reset();
                let mut lines = Vec::new();

                let l_last = self.fresh_var();
                lines.push(format!("let {l_last} := mload(L_LAST_MPTR)"));
                let l_blind = self.fresh_var();
                lines.push(format!("let {l_blind} := mload(L_BLIND_MPTR)"));
                let active = self.fresh_var();
                lines.push(format!(
                    "let {active} := addmod(1, sub(r, addmod({l_last}, {l_blind}, r)), r)"
                ));

                let beta = self.fresh_var();
                lines.push(format!("let {beta} := mload(BETA_MPTR)"));

                // Σ_h h_eval[c]
                let sum_h = self.fresh_var();
                lines.push(format!("let {sum_h} := {}", h_evals[0].to_string()));
                for h in &h_evals[1..] {
                    lines.push(format!("{sum_h} := addmod({sum_h}, {}, r)", h.to_string()));
                }

                // selector eval (full Expression; not necessarily a
                // single column query).
                let (mut sel_lines, sel_var) = self.evaluate(selector_expr);
                lines.append(&mut sel_lines);

                // s · Σh
                let s_sum_h = self.fresh_var();
                lines.push(format!("let {s_sum_h} := mulmod({sel_var}, {sum_h}, r)"));

                // diff = z_next - z - s·Σh
                let diff = self.fresh_var();
                lines.push(format!(
                    "let {diff} := addmod({}, sub(r, addmod({}, {s_sum_h}, r)), r)",
                    z_next_eval.to_string(),
                    z_eval.to_string()
                ));

                // compressed_table = θ-fold-compress(table_expressions)
                let (mut t_lines, t_var) =
                    self.compress_expressions_with_theta(chunked.table_expressions());
                lines.append(&mut t_lines);
                let t_plus_beta = self.fresh_var();
                lines.push(format!("let {t_plus_beta} := addmod({t_var}, {beta}, r)"));

                // (diff) · (t + β) + m_eval
                let core = self.fresh_var();
                lines.push(format!(
                    "let {core} := addmod(mulmod({diff}, {t_plus_beta}, r), {}, r)",
                    m_eval.to_string()
                ));

                let acc_c = self.fresh_var();
                lines.push(format!("let {acc_c} := mulmod({active}, {core}, r)"));

                out.push((lines, acc_c));
            }
        }

        out
    }

    // ----------------------------------------------------------------
    // Trash emitter.
    //
    // Mirrors `midfall/proofs/src/plonk/trash.rs::Evaluated::expressions`:
    //
    //   For each trashcan:
    //     compressed = θ_trash-fold(constraint_expressions)
    //     selector   = eval(argument.selector)
    //     constraint = compressed - (1 - selector) * trash_eval
    //
    // Note: midnight-proofs uses the *trash_challenge* (a separate
    // squeeze) as the compression τ, NOT θ. We expose it as
    // TRASH_CHALLENGE_MPTR; the Yul template (Step 6) is responsible for
    // squeezing and storing it before the quotient eval block.
    // ----------------------------------------------------------------

    pub fn trashcan_computations(&self) -> Vec<(Vec<String>, String)> {
        if self.meta.num_trashcans == 0 {
            return Vec::new();
        }

        let mut out: Vec<(Vec<String>, String)> = Vec::new();

        for (idx, argument) in self.cs.trashcans().iter().enumerate() {
            self.reset();
            let mut lines = Vec::new();

            let trash_challenge = self.fresh_var();
            lines.push(format!(
                "let {trash_challenge} := mload(TRASH_CHALLENGE_MPTR)"
            ));

            // compressed = fold((acc, e) -> acc * τ + e) over
            // argument.constraint_expressions(). Note this is the same
            // recipe as the logup θ-compression, but with the trash
            // challenge as the variable.
            let mut compressed_var: Option<String> = None;
            for expr in argument.constraint_expressions() {
                let (mut e_lines, e_var) = self.evaluate(expr);
                lines.append(&mut e_lines);
                let next = self.fresh_var();
                let prev = compressed_var.unwrap_or_else(|| "0".to_string());
                lines.push(format!(
                    "let {next} := addmod(mulmod({prev}, {trash_challenge}, r), {e_var}, r)"
                ));
                compressed_var = Some(next);
            }
            let compressed = compressed_var.unwrap_or_else(|| {
                let zero = self.fresh_var();
                lines.push(format!("let {zero} := 0"));
                zero
            });

            // selector eval
            let (mut sel_lines, sel_var) = self.evaluate(argument.selector());
            lines.append(&mut sel_lines);

            // (1 - q) * trash_eval
            let one_minus_q = self.fresh_var();
            lines.push(format!(
                "let {one_minus_q} := addmod(1, sub(r, {sel_var}), r)"
            ));
            let trash_eval = self.data.trashcan_evals[idx].to_string();
            let scaled = self.fresh_var();
            lines.push(format!(
                "let {scaled} := mulmod({one_minus_q}, {trash_eval}, r)"
            ));

            // constraint = compressed - (1 - q) * trash_eval
            let c = self.fresh_var();
            lines.push(format!(
                "let {c} := addmod({compressed}, sub(r, {scaled}), r)"
            ));
            out.push((lines, c));
        }

        out
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    /// θ-compress a slice of expressions:
    ///   compressed = fold((acc, e) -> acc * θ + e) over expressions
    ///
    /// Returns the Yul lines + the final variable name. Uses a fresh
    /// `theta` mload at the start; relies on the caller's reset cycle
    /// to deduplicate within a constraint.
    fn compress_expressions_with_theta(
        &self,
        expressions: &[Expression<Fq>],
    ) -> (Vec<String>, String) {
        let mut lines = Vec::new();
        let theta = self.fresh_var();
        lines.push(format!("let {theta} := mload(THETA_MPTR)"));

        let mut acc_var: Option<String> = None;
        for expr in expressions {
            let (mut e_lines, e_var) = self.evaluate(expr);
            lines.append(&mut e_lines);
            let next = self.fresh_var();
            let prev = acc_var.unwrap_or_else(|| "0".to_string());
            lines.push(format!(
                "let {next} := addmod(mulmod({prev}, {theta}, r), {e_var}, r)"
            ));
            acc_var = Some(next);
        }
        let final_var = acc_var.unwrap_or_else(|| {
            let zero = self.fresh_var();
            lines.push(format!("let {zero} := 0"));
            zero
        });
        (lines, final_var)
    }

    /// Resolve a `Column<Any>` evaluation at a rotation. Used by the
    /// permutation emitter (which works in `Column<Any>` form rather
    /// than `Expression<F>`).
    pub(crate) fn eval_at(&self, column: &Column<Any>, rotation: i32) -> String {
        let col_idx = column.index();
        match column.column_type() {
            Any::Advice(_) => self
                .data
                .advice_evals
                .get(&(col_idx, rotation))
                .expect("advice eval present in permutation chunk")
                .to_string(),
            Any::Fixed => {
                if self.meta.simple_selector_cols.contains(&col_idx) {
                    "0x1".to_string()
                } else {
                    self.data
                        .fixed_evals
                        .get(&(col_idx, rotation))
                        .expect("fixed eval present in permutation chunk")
                        .to_string()
                }
            }
            Any::Instance => self.instance_eval_at(col_idx, rotation),
        }
    }

    fn fresh_var(&self) -> String {
        self.next_var()
    }

    fn reset(&self) {
        *self.var_counter.borrow_mut() = Default::default();
        *self.var_cache.borrow_mut() = Default::default();
    }

    fn evaluate_and_reset(&self, expression: &Expression<Fq>) -> (Vec<String>, String) {
        self.reset();
        self.evaluate(expression)
    }

    fn evaluate(&self, expression: &Expression<Fq>) -> (Vec<String>, String) {
        if let Some(result) = self.evaluate_sum_with_coeff_and_const(expression) {
            return result;
        }

        self.evaluate_basic(expression)
    }

    fn evaluate_sum_with_coeff_and_const(
        &self,
        expression: &Expression<Fq>,
    ) -> Option<(Vec<String>, String)> {
        let mut terms = Vec::new();
        let mut constant = Fq::ZERO;
        self.collect_sum_terms(expression, Fq::ONE, &mut constant, &mut terms);

        terms.retain(|(coeff, _)| !bool::from(coeff.is_zero_vartime()));
        let has_constant = !bool::from(constant.is_zero_vartime());
        let should_fuse = has_constant
            || terms.len() > 1
            || terms.first().is_some_and(|(coeff, _)| *coeff != Fq::ONE);
        if !should_fuse {
            return None;
        }

        let mut lines = Vec::new();
        let mut acc = if has_constant {
            let (const_lines, const_var) =
                self.init_var(u256_string(fe_to_u256::<Fq>(&constant)), None);
            lines.extend(const_lines);
            Some(const_var)
        } else {
            None
        };

        for (coeff, term) in terms {
            let (mut term_lines, term_var) = self.evaluate_scaled_term(term, coeff);
            lines.append(&mut term_lines);
            acc = Some(match acc {
                Some(acc_var) => {
                    let (add_lines, add_var) =
                        self.init_var(format!("addmod({acc_var}, {term_var}, r)"), None);
                    lines.extend(add_lines);
                    add_var
                }
                None => term_var,
            });
        }

        Some(match acc {
            Some(var) => (lines, var),
            None => self.init_var("0x0", None),
        })
    }

    fn collect_sum_terms<'b>(
        &self,
        expression: &'b Expression<Fq>,
        coeff: Fq,
        constant: &mut Fq,
        terms: &mut Vec<(Fq, &'b Expression<Fq>)>,
    ) {
        match expression {
            Expression::Constant(value) => {
                *constant += coeff * value;
            }
            Expression::Negated(inner) => {
                self.collect_sum_terms(inner, -coeff, constant, terms);
            }
            Expression::Sum(lhs, rhs) => {
                self.collect_sum_terms(lhs, coeff, constant, terms);
                self.collect_sum_terms(rhs, coeff, constant, terms);
            }
            Expression::Scaled(inner, scale) => {
                self.collect_sum_terms(inner, coeff * scale, constant, terms);
            }
            _ => terms.push((coeff, expression)),
        }
    }

    fn evaluate_scaled_term(
        &self,
        expression: &Expression<Fq>,
        coeff: Fq,
    ) -> (Vec<String>, String) {
        let coeff_is_one = coeff == Fq::ONE;

        if let Expression::Product(lhs, rhs) = expression {
            let (mut lines, lhs_var) = self.evaluate_basic(lhs);
            let (mut rhs_lines, rhs_var) = self.evaluate_basic(rhs);
            lines.append(&mut rhs_lines);
            let expr = if coeff_is_one {
                format!("mulmod({lhs_var}, {rhs_var}, r)")
            } else {
                let (coeff_lines, coeff_var) =
                    self.init_var(u256_string(fe_to_u256::<Fq>(&coeff)), None);
                lines.extend(coeff_lines);
                format!("mulmod(mulmod({lhs_var}, {rhs_var}, r), {coeff_var}, r)")
            };
            let (out_lines, out_var) = self.init_var(expr, None);
            lines.extend(out_lines);
            return (lines, out_var);
        }

        let (mut lines, var) = self.evaluate_basic(expression);
        if coeff_is_one {
            return (lines, var);
        }

        let (coeff_lines, coeff_var) = self.init_var(u256_string(fe_to_u256::<Fq>(&coeff)), None);
        lines.extend(coeff_lines);
        let (scale_lines, out_var) = self.init_var(format!("mulmod({var}, {coeff_var}, r)"), None);
        lines.extend(scale_lines);
        (lines, out_var)
    }

    fn evaluate_basic(&self, expression: &Expression<Fq>) -> (Vec<String>, String) {
        // midnight-proofs `Expression<F>` carries the full frontend
        // variants: Constant / Selector / Fixed / Advice / Instance /
        // Challenge / Negated / Sum / Product / Scaled. We do not expect
        // to see `Selector` here because virtual selectors are removed
        // during `directly_convert_selectors_to_fixed`.
        expression.evaluate(
            &|scalar| self.init_var(u256_string(fe_to_u256::<Fq>(&scalar)), None),
            &|_| panic!("virtual selectors must be removed before codegen"),
            &|query| {
                let column_index = query.column_index();
                let rotation = query.rotation().0;
                if self.meta.simple_selector_cols.contains(&column_index) {
                    // Simple selectors have no eval slot; the verifier
                    // semantics insert F::ONE.
                    self.init_var("0x1".to_string(), None)
                } else {
                    let eval: Word = *self
                        .data
                        .fixed_evals
                        .get(&(column_index, rotation))
                        .expect("fixed eval present");
                    let var_name = column_eval_var("f", column_index, rotation);
                    self.init_var(eval.to_string(), Some(var_name))
                }
            },
            &|query| {
                let column_index = query.column_index();
                let rotation = query.rotation().0;
                let eval: Word = *self
                    .data
                    .advice_evals
                    .get(&(column_index, rotation))
                    .expect("advice eval present");
                let var_name = column_eval_var("a", column_index, rotation);
                self.init_var(eval.to_string(), Some(var_name))
            },
            &|query| {
                let column_index = query.column_index();
                let rotation = query.rotation().0;
                let eval = self.instance_eval_at(column_index, rotation);
                self.init_var(eval, Some(column_eval_var("i", column_index, rotation)))
            },
            &|challenge| {
                self.init_var(
                    self.data.challenges[challenge.index()],
                    Some(format!("c_{}", challenge.index())),
                )
            },
            &|(mut acc, var)| {
                let (lines, var) = self.init_var(format!("sub(r, {var})"), None);
                acc.extend(lines);
                (acc, var)
            },
            &|(mut lhs_acc, lhs_var), (rhs_acc, rhs_var)| {
                let (lines, var) = self.init_var(format!("addmod({lhs_var}, {rhs_var}, r)"), None);
                lhs_acc.extend(rhs_acc);
                lhs_acc.extend(lines);
                (lhs_acc, var)
            },
            &|(mut lhs_acc, lhs_var), (rhs_acc, rhs_var)| {
                let (lines, var) = self.init_var(format!("mulmod({lhs_var}, {rhs_var}, r)"), None);
                lhs_acc.extend(rhs_acc);
                lhs_acc.extend(lines);
                (lhs_acc, var)
            },
            &|(mut acc, var), scalar| {
                let scalar_var = self.init_var(u256_string(fe_to_u256::<Fq>(&scalar)), None);
                acc.extend(scalar_var.0);
                let (lines, out) =
                    self.init_var(format!("mulmod({var}, {}, r)", scalar_var.1), None);
                acc.extend(lines);
                (acc, out)
            },
        )
    }

    fn instance_eval_at(&self, column_index: usize, rotation: i32) -> String {
        if column_index < self.meta.num_committed_instances {
            self.data
                .committed_instance_evals
                .get(&(column_index, rotation))
                .expect("committed instance eval present")
                .to_string()
        } else {
            // The current public API supports one non-committed instance
            // column, whose Lagrange-combined evaluation is computed by
            // the template prologue and stored at INSTANCE_EVAL_MPTR.
            self.data.instance_eval.to_string()
        }
    }

    fn init_var(&self, value: impl ToString, var: Option<String>) -> (Vec<String>, String) {
        let value = value.to_string();
        if self.var_cache.borrow().contains_key(&value) {
            (vec![], self.var_cache.borrow()[&value].clone())
        } else {
            let var = var.unwrap_or_else(|| self.next_var());
            self.var_cache
                .borrow_mut()
                .insert(value.clone(), var.clone());
            (vec![format!("let {var} := {value}")], var)
        }
    }

    fn next_var(&self) -> String {
        let count = *self.var_counter.borrow();
        *self.var_counter.borrow_mut() += 1;
        format!("var{count}")
    }
}

fn u256_string(value: U256) -> String {
    if value.bit_len() < 64 {
        format!("0x{:x}", value.as_limbs()[0])
    } else {
        format!("0x{value:x}")
    }
}

fn column_eval_var(prefix: &'static str, column_index: usize, rotation: i32) -> String {
    match rotation.cmp(&0) {
        Ordering::Less => format!("{prefix}_{column_index}_prev_{}", rotation.abs()),
        Ordering::Equal => format!("{prefix}_{column_index}"),
        Ordering::Greater => format!("{prefix}_{column_index}_next_{rotation}"),
    }
}
