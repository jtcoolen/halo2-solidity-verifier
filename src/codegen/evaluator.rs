#![allow(clippy::useless_format)]

//! Quotient-numerator emitter.
//!
//! This module walks the gates / permutation / lookup / trash-can
//! arguments stored in a `midnight_proofs::plonk::ConstraintSystem` and
//! emits the Yul lines that compute their per-row contributions to
//! `quotient_eval_numer` at the evaluation challenge `x`.
//!
//! The previous halo2-proofs v0.4 backend exposed a flat
//! `ExpressionBack<F>` (Constant / Var / Negated / Sum / Product) that
//! made expression walking trivial. midnight-proofs preserves the
//! frontend `Expression<F>` directly:
//!
//! ```ignore
//! enum Expression<F> {
//!     Constant(F),
//!     Selector(Selector),                 // removed during keygen
//!     Fixed(FixedQuery),                  // index, column_index, rotation
//!     Advice(AdviceQuery),                // index, column_index, rotation, phase
//!     Instance(InstanceQuery),            // index, column_index, rotation
//!     Challenge(Challenge),               // index, phase
//!     Negated(Box<Expression<F>>),
//!     Sum(Box<Expression<F>>, Box<Expression<F>>),
//!     Product(Box<Expression<F>>, Box<Expression<F>>),
//!     Scaled(Box<Expression<F>>, F),
//! }
//! ```
//!
//! plus a `.evaluate(...)` visitor with 10 callbacks.
//!
//! ## Migration status (Steps 1-3, 2026-04-26)
//!
//! For Steps 1-3 we only rebind the types and stub out
//! `permutation_computations` / `lookup_computations` / `trashcan_computations`
//! to empty slices so the codegen tree compiles. The actual Yul emitters
//! for permutation, logup, and trash will be re-implemented in Step 4
//! against the midnight-proofs schema (in particular: logup needs the
//! per-chunk `f_j` / helper / accumulator structure, and trash needs
//! the (1 - q)*trash_eval shape from `proofs/src/plonk/trash.rs`).
//!
//! `gate_computations` is fully ported because the gate shape (one
//! `Expression<F>` per polynomial in each gate) carries over directly
//! from halo2.

use std::{cell::RefCell, cmp::Ordering, collections::HashMap};

use midnight_curves::Fq;
use midnight_proofs::plonk::{Any, ConstraintSystem, Expression};
use ruint::aliases::U256;

use crate::codegen::util::{fe_to_u256, ConstraintSystemMeta, Data};

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

    /// Permutation argument expressions emitter.
    ///
    /// **TODO (Step 4)**: port the midnight-proofs permutation expression
    /// emitter from `proofs/src/plonk/permutation.rs::expressions`. The
    /// per-set boundary / wrap-around terms differ from halo2 (sets +
    /// per-chunk delta-pow walking + l_last z^2-z), so the previous
    /// emitter cannot be reused as-is.
    pub fn permutation_computations(&self) -> Vec<(Vec<String>, String)> {
        let _ = (&self.meta, &self.data); // silence unused warnings
        Vec::new()
    }

    /// LogUp lookup argument emitter.
    ///
    /// **TODO (Step 4)**: implement the helper / accumulator constraints
    /// from `proofs/src/plonk/logup.rs::Evaluated::expressions`.
    pub fn lookup_computations(&self) -> Vec<(Vec<String>, String)> {
        Vec::new()
    }

    /// Trash argument emitter.
    ///
    /// **TODO (Step 4)**: implement the trash boundary check from
    /// `proofs/src/plonk/trash.rs::Evaluated::expressions`.
    pub fn trashcan_computations(&self) -> Vec<(Vec<String>, String)> {
        Vec::new()
    }

    fn eval(&self, column_type: Any, column_index: usize, rotation: i32) -> String {
        match column_type {
            Any::Advice(_) => self.data.advice_evals[&(column_index, rotation)].to_string(),
            Any::Fixed => self.data.fixed_evals[&(column_index, rotation)].to_string(),
            Any::Instance => self.data.instance_eval.to_string(),
        }
    }

    fn reset(&self) {
        *self.var_counter.borrow_mut() = Default::default();
        *self.var_cache.borrow_mut() = Default::default();
    }

    fn evaluate_and_reset(&self, expression: &Expression<Fq>) -> (Vec<String>, String) {
        let result = self.evaluate(expression);
        self.reset();
        result
    }

    fn evaluate(&self, expression: &Expression<Fq>) -> (Vec<String>, String) {
        // midnight-proofs `Expression<F>` carries the full frontend
        // variants: Constant / Selector / Fixed / Advice / Instance /
        // Challenge / Negated / Sum / Product / Scaled. We do not expect
        // to see `Selector` here because virtual selectors are removed
        // during `directly_convert_selectors_to_fixed`. We collapse
        // `Scaled` into a Product against a constant.
        expression.evaluate(
            &|scalar| self.init_var(u256_string(fe_to_u256::<Fq>(&scalar)), None),
            // Selector is removed during compile; if we hit it the VK is
            // malformed. We panic loud rather than silently emit garbage.
            &|_| panic!("virtual selectors must be removed before codegen"),
            &|query| {
                let column_index = query.column_index();
                let rotation = query.rotation().0;
                let eval = self.eval(Any::Fixed, column_index, rotation);
                let var_name = column_eval_var("f", column_index, rotation);
                self.init_var(eval, Some(var_name))
            },
            &|query| {
                let column_index = query.column_index();
                let rotation = query.rotation().0;
                let eval = self.eval(Any::advice(), column_index, rotation);
                let var_name = column_eval_var("a", column_index, rotation);
                self.init_var(eval, Some(var_name))
            },
            &|_query| {
                // Instance queries always rotate to the current row in
                // the verifier's view. The codegen pre-computes
                // `instance_eval` once.
                let eval = self.eval(Any::Instance, 0, 0);
                self.init_var(eval, Some("i_eval".to_string()))
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
                let (lines, var) =
                    self.init_var(format!("addmod({lhs_var}, {rhs_var}, r)"), None);
                lhs_acc.extend(rhs_acc);
                lhs_acc.extend(lines);
                (lhs_acc, var)
            },
            &|(mut lhs_acc, lhs_var), (rhs_acc, rhs_var)| {
                let (lines, var) =
                    self.init_var(format!("mulmod({lhs_var}, {rhs_var}, r)"), None);
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

    fn init_var(&self, value: impl ToString, var: Option<String>) -> (Vec<String>, String) {
        let value = value.to_string();
        if self.var_cache.borrow().contains_key(&value) {
            (vec![], self.var_cache.borrow()[&value].clone())
        } else {
            let var = var.unwrap_or_else(|| self.next_var());
            self.var_cache.borrow_mut().insert(value.clone(), var.clone());
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
