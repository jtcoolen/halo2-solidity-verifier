//! Multi-prepare KZG emitter (Step 5 of MIGRATION.md).
//!
//! This module mirrors `midfall/proofs/src/poly/kzg/mod.rs::multi_prepare`
//! line-by-line in Yul. The high-level structure is:
//!
//!   1. Build the verifier query list (`queries`).
//!   2. Run a code-gen-time `construct_intermediate_sets` simulation that
//!      assigns each commitment to a point set (sorted by ascending
//!      cardinality with original-order tiebreak).
//!   3. Emit Yul that:
//!        a. Pre-computes rotation points `x * omega^rot` for every
//!           distinct rotation appearing in any query.
//!        b. Pre-computes `x1` powers up to `max_set_size - 1`.
//!        c. Computes `q_com[s]` and `q_eval_set[s]` per set.
//!        d. Computes `f_eval` via Horner over reverse(point_sets) using
//!           Lagrange interpolation at `x3`.
//!        e. Builds the final commitment via `msm_inner_product` with
//!           `x4` powers, plus `f_com` at the highest power.
//!        f. Emits the pairing inputs `(pi, final_com - v*G + x3*pi)`.
//!
//! Notes:
//!
//!   * The current emission targets the simplified case
//!     `num_simple_selectors() == 0`. In that regime the linearization
//!     commitment is just the combined quotient commitment with eval
//!     `quotient_eval_numer / (x^n - 1)`, both already produced by the
//!     evaluator/prologue. Step 6/7 will extend the emitter to handle
//!     the linearized commitment as a `Linear` MSM.
//!
//!   * For point-set inversion we emit one `modexp` precompile call per
//!     set (`x3 - p_j`), then locally compose. This is gas-suboptimal
//!     but correct and easy to validate; a Montgomery batch invert can
//!     replace it once the rest of the verifier is byte-stable.

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::codegen::util::{ConstraintSystemMeta, Data, EcPoint, Word};

// ---------------------------------------------------------------------------
// Verifier query list.
// ---------------------------------------------------------------------------

/// A single verifier query: a commitment opened at `omega^rotation * x`
/// to claim `eval`. The current Step 5 emitter assumes commitments are
/// `OnePiece` (single G1 point). The linearized commitment introduced
/// by `compute_linearization_commitment` will be added in Step 6/7 as
/// a `Linear` variant.
#[derive(Clone, Debug)]
pub(crate) struct Query {
    pub rotation: i32,
    pub comm: EcPoint,
    pub eval: Word,
}

impl Query {
    fn new(comm: EcPoint, rotation: i32, eval: Word) -> Self {
        Self {
            rotation,
            comm,
            eval,
        }
    }
}

/// Build the verifier query list for the codegen verifier.
///
/// Mirrors the iterator chain in
/// `midfall/proofs/src/plonk/verifier.rs::verify_algebraic_constraints`,
/// excluding committed-instance queries (the codegen path supports only
/// `nb_committed_instances == 0` for now).
pub(crate) fn queries(meta: &ConstraintSystemMeta, data: &Data) -> Vec<Query> {
    let mut out: Vec<Query> = Vec::new();

    // Per-proof queries (we only support num_proofs = 1 in the codegen).
    // Order matches `verify_algebraic_constraints` in
    // `midfall/proofs/src/plonk/verifier.rs`.

    // 1. Advice commitments at advice_query rotations.
    for q in &meta.advice_queries {
        let comm = data.advice_comms[q.0];
        let eval = *data
            .advice_evals
            .get(q)
            .expect("advice eval present for every advice query");
        out.push(Query::new(comm, q.1, eval));
    }

    // 1b. Committed-instance queries (col_idx < num_committed_instances).
    //    All committed-instance commitments point at the G1 identity in
    //    memory.
    for q in &meta.instance_queries {
        if q.0 >= meta.num_committed_instances {
            continue;
        }
        let comm = data.committed_instance_comms[q.0];
        let eval = *data
            .committed_instance_evals
            .get(q)
            .expect("committed instance eval present for every committed instance query");
        out.push(Query::new(comm, q.1, eval));
    }

    // 2. Permutation product set queries: (cur, next) at each set, plus
    //    (last) for all but the final set.
    for (set_idx, (z_cur, z_next, z_last)) in data.permutation_z_evals.iter().enumerate() {
        let comm = data.permutation_z_comms[set_idx];
        out.push(Query::new(comm, 0, *z_cur));
        out.push(Query::new(comm, 1, *z_next));
        if let Some(last) = z_last {
            out.push(Query::new(comm, meta.rotation_last, *last));
        }
    }

    // 3. Lookup queries: m, h_i, z at rotation 0; z at rotation 1.
    for (lookup_idx, (m_eval, h_evals, z_eval, z_next_eval)) in
        data.lookup_evals.iter().enumerate()
    {
        let m_comm = data.lookup_m_comms[lookup_idx];
        let z_comm = data.lookup_z_comms[lookup_idx];
        out.push(Query::new(m_comm, 0, *m_eval));
        for (h_eval, h_comm) in h_evals.iter().zip(data.lookup_helper_comms[lookup_idx].iter()) {
            out.push(Query::new(*h_comm, 0, *h_eval));
        }
        out.push(Query::new(z_comm, 0, *z_eval));
        out.push(Query::new(z_comm, 1, *z_next_eval));
    }

    // 4. Trashcan queries: trash_commitment at rotation 0.
    for (idx, t_eval) in data.trashcan_evals.iter().enumerate() {
        out.push(Query::new(data.trashcan_comms[idx], 0, *t_eval));
    }

    // 5. Fixed (non-simple-selector) queries.
    for q in &meta.fixed_queries {
        if meta.simple_selector_cols.contains(&q.0) {
            continue;
        }
        let comm = data.fixed_comms[q.0];
        let eval = *data.fixed_evals.get(q).expect("fixed eval present");
        out.push(Query::new(comm, q.1, eval));
    }

    // 6. Permutation common (vk perm) queries at rotation 0.
    for col in &meta.permutation_columns {
        let comm = data.permutation_comms[col];
        let eval = data.permutation_evals[col];
        out.push(Query::new(comm, 0, eval));
    }

    // 7. Linearization query at rotation 0. With num_simple_selectors == 0
    //    this collapses to (computed_quotient_comm, computed_quotient_eval).
    //    The evaluator emits `quotient_eval` already as
    //    `quotient_eval_numer / (x^n - 1)`, which matches the
    //    linearization eval target.
    out.push(Query::new(
        data.computed_quotient_comm,
        0,
        data.computed_quotient_eval,
    ));

    out
}

// ---------------------------------------------------------------------------
// IntermediateSets simulation (codegen-time port of
// `midfall/proofs/src/poly/kzg/utils.rs::construct_intermediate_sets`).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub(crate) struct CommitmentEntry {
    /// Index into the sorted `point_sets` vector.
    pub set_index: usize,
    /// G1 commitment (deduplicated).
    pub comm: EcPoint,
    /// Evals aligned with `point_sets[set_index]`.
    pub evals: Vec<Word>,
}

#[derive(Clone, Debug)]
pub(crate) struct IntermediateSets {
    pub commitments: Vec<CommitmentEntry>,
    pub point_sets: Vec<Vec<i32>>,
}

/// Run the intermediate-set construction over the codegen-time queries.
///
/// `EcPoint` comparisons use derived `PartialEq`, which compares the
/// underlying memory pointer; that is exactly the identity semantics we
/// want (same memory location = same commitment).
fn construct_intermediate_sets_impl(queries: &[Query]) -> IntermediateSets {
    // Step 1: build commitment_map (one entry per unique commitment) and
    // a point_index map (one entry per unique rotation).
    let mut commitment_map: Vec<(EcPoint, Vec<usize>, Vec<Word>)> = Vec::new();
    let mut point_index_of: Vec<i32> = Vec::new();

    for query in queries {
        let point_idx = match point_index_of.iter().position(|p| *p == query.rotation) {
            Some(i) => i,
            None => {
                point_index_of.push(query.rotation);
                point_index_of.len() - 1
            }
        };

        if let Some(slot) = commitment_map.iter_mut().find(|(c, _, _)| *c == query.comm) {
            assert!(
                !slot.1.contains(&point_idx),
                "duplicate (commitment, rotation) query"
            );
            slot.1.push(point_idx);
            slot.2.push(query.eval);
        } else {
            commitment_map.push((query.comm, vec![point_idx], vec![query.eval]));
        }
    }

    // Step 2: bucket commitments by their point-index set (BTreeSet so
    // the bucket key is order-insensitive and deterministically ordered).
    let mut point_idx_sets: BTreeMap<Vec<usize>, usize> = BTreeMap::new();
    for (_, point_indices, _) in &commitment_map {
        let mut sorted = point_indices.clone();
        sorted.sort_unstable();
        sorted.dedup();
        let n = point_idx_sets.len();
        point_idx_sets.entry(sorted).or_insert(n);
    }

    // Step 3: for each commitment, look up its set_index and align evals
    // with the *sorted* point_indices order.
    let mut commitments: Vec<CommitmentEntry> = Vec::with_capacity(commitment_map.len());
    for (comm, point_indices, evals) in commitment_map {
        let mut sorted_indices = point_indices.clone();
        sorted_indices.sort_unstable();
        sorted_indices.dedup();

        let set_index = *point_idx_sets.get(&sorted_indices).unwrap();

        // Build evals[k] = eval whose point_index lands at sorted_indices[k].
        let mut aligned_evals = vec![None; sorted_indices.len()];
        for (pi, ev) in point_indices.iter().zip(evals.iter()) {
            let pos = sorted_indices.iter().position(|p| p == pi).unwrap();
            aligned_evals[pos] = Some(*ev);
        }
        commitments.push(CommitmentEntry {
            set_index,
            comm,
            evals: aligned_evals.into_iter().map(Option::unwrap).collect(),
        });
    }

    // Step 4: turn point_idx sets into actual rotation lists, in the
    // ordering BTreeMap iterates (which is by Vec<usize> lex order). We
    // rely on this ordering for tiebreak when sorting by cardinality.
    let mut point_sets: Vec<Vec<i32>> = vec![Vec::new(); point_idx_sets.len()];
    for (idx_set, &set_idx) in point_idx_sets.iter() {
        let rotations: Vec<i32> = idx_set.iter().map(|i| point_index_of[*i]).collect();
        point_sets[set_idx] = rotations;
    }

    IntermediateSets {
        commitments,
        point_sets,
    }
}

/// Sort the IntermediateSets by ascending cardinality (tiebreaker by
/// original set index). Returns a new IntermediateSets with `set_index`
/// values rewritten to point to the sorted positions.
fn sort_sets(input: IntermediateSets) -> IntermediateSets {
    let mut order: Vec<usize> = (0..input.point_sets.len()).collect();
    order.sort_by_key(|&i| (input.point_sets[i].len(), i));

    // remap[old_idx] = new_idx
    let mut remap = vec![0usize; input.point_sets.len()];
    for (new_idx, &old_idx) in order.iter().enumerate() {
        remap[old_idx] = new_idx;
    }

    let point_sets = order.iter().map(|&i| input.point_sets[i].clone()).collect();
    let commitments = input
        .commitments
        .into_iter()
        .map(|mut c| {
            c.set_index = remap[c.set_index];
            c
        })
        .collect();

    IntermediateSets {
        commitments,
        point_sets,
    }
}

pub(crate) fn intermediate_sets(meta: &ConstraintSystemMeta, data: &Data) -> IntermediateSets {
    sort_sets(construct_intermediate_sets_impl(&queries(meta, data)))
}

pub(super) fn num_point_sets(meta: &ConstraintSystemMeta, data: &Data) -> usize {
    intermediate_sets(meta, data).point_sets.len()
}

// ---------------------------------------------------------------------------
// Yul emission.
// ---------------------------------------------------------------------------

pub(super) fn static_working_memory_size(_meta: &ConstraintSystemMeta, _data: &Data) -> usize {
    // Reserve generous scratch for the pairing call and intermediate
    // q_com / final_com slots. The pairing precompile needs 2 G1 (8
    // words) + 2 G2 (16 words) + 1 output word = 25 words. We round up
    // to 32 to leave room for the in-Yul accumulator slots used during
    // MSM construction.
    32
}

/// Emit the multi-prepare Yul body. The output is the same vec-of-vec-of-strings
/// shape the rest of the codegen uses; each inner Vec<String> is a discrete
/// Yul code block (rendered between `{` and `}` in the template).
pub(super) fn computations(meta: &ConstraintSystemMeta, data: &Data) -> Vec<Vec<String>> {
    let sets = intermediate_sets(meta, data);
    let n_sets = sets.point_sets.len();
    if n_sets == 0 {
        return Vec::new();
    }

    // The number of x1 powers is bounded by the largest commitments-per-set
    // count (one power per commitment within a set).
    let nb_x1_powers: usize = (0..n_sets)
        .map(|s| sets.commitments.iter().filter(|c| c.set_index == s).count())
        .max()
        .unwrap_or(0);

    // Distinct rotations encountered, sorted; emit code that stores
    // `x * omega^rot` at a known scratch slot per rotation.
    let mut distinct_rotations: Vec<i32> = sets
        .point_sets
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
    distinct_rotations.sort_unstable();
    distinct_rotations.dedup();

    let mut blocks: Vec<Vec<String>> = Vec::new();

    // ------------------------------------------------------------------
    // Block 1: pre-compute rotation points (x * omega^rot).
    //
    // We stash each `x*omega^rot` at scratch offset
    //   ROT_POINTS_MPTR + 32 * idx_of(rot)
    // where `idx_of(rot)` is the index of `rot` in `distinct_rotations`.
    //
    // The Yul template (Step 6) will define ROT_POINTS_MPTR. For now we
    // just emit symbolic references; the macro layout is finalised
    // alongside Step 6.
    // ------------------------------------------------------------------
    {
        let mut lines: Vec<String> = Vec::new();
        lines.push(format!("// {} distinct rotation(s)", distinct_rotations.len()));
        lines.push("let x := mload(X_MPTR)".to_string());
        lines.push("let omega := mload(OMEGA_MPTR)".to_string());
        lines.push("let omega_inv := mload(OMEGA_INV_MPTR)".to_string());

        // Walk forward from rotation 0 through max positive rotation,
        // multiplying by omega; then walk back to min negative rotation,
        // multiplying by omega_inv.
        let max_rot = *distinct_rotations.iter().max().unwrap_or(&0);
        let min_rot = *distinct_rotations.iter().min().unwrap_or(&0);

        let store_rot = |rot: i32| -> Option<String> {
            distinct_rotations
                .iter()
                .position(|r| *r == rot)
                .map(|idx| {
                    format!(
                        "mstore(add(ROT_POINTS_MPTR, {:#x}), x_pow_of_omega)",
                        idx * 0x20
                    )
                })
        };

        // Rotation 0 = x.
        lines.push("let x_pow_of_omega := x".to_string());
        if let Some(s) = store_rot(0) {
            lines.push(s);
        }

        // Forward walk for positive rotations.
        for rot in 1..=max_rot {
            lines.push("x_pow_of_omega := mulmod(x_pow_of_omega, omega, r)".to_string());
            if let Some(s) = store_rot(rot) {
                lines.push(s);
            }
        }

        // Backward walk for negative rotations.
        if min_rot < 0 {
            lines.push("x_pow_of_omega := x".to_string());
            for rot in (min_rot..0).rev() {
                lines.push("x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)".to_string());
                if let Some(s) = store_rot(rot) {
                    lines.push(s);
                }
            }
        }

        blocks.push(lines);
    }

    // ------------------------------------------------------------------
    // Block 2: pre-compute x1 powers (x1^0 .. x1^(nb_x1_powers - 1)).
    //
    // Stashed at X1_POWERS_MPTR + 32 * idx (idx = 0..nb_x1_powers - 1).
    // ------------------------------------------------------------------
    if nb_x1_powers > 0 {
        let mut lines: Vec<String> = Vec::new();
        lines.push(format!("// pre-compute {nb_x1_powers} x1 power(s)"));
        lines.push("let x1 := mload(X1_MPTR)".to_string());
        lines.push("mstore(X1_POWERS_MPTR, 1)".to_string());
        if nb_x1_powers > 1 {
            lines.push("let acc := 1".to_string());
            for i in 1..nb_x1_powers {
                lines.push("acc := mulmod(acc, x1, r)".to_string());
                lines.push(format!(
                    "mstore(add(X1_POWERS_MPTR, {:#x}), acc)",
                    i * 0x20
                ));
            }
        }
        blocks.push(lines);
    }

    // ------------------------------------------------------------------
    // Block 3: per-set q_com / q_eval_set computation.
    //
    // For each set s:
    //   q_com[s]      = sum_{i, c in commitments of s} x1[i] * c.point
    //   q_eval_set[s] = sum_{i, c in commitments of s} x1[i] * c.eval[?]
    //
    // The commitment ordering inside a set follows the order in which
    // commitments appear in `sets.commitments` (which is the order in
    // which queries were enumerated; this matches the midnight-proofs
    // for_each iteration order).
    //
    // Storage:
    //   Q_COM_MPTR  + 0x80 * s : q_com[s] (4 words, EIP-2537 padded)
    //   Q_EVAL_SET_MPTR + 0x20 * s : q_eval_set[s] (1 Fq word)
    // ------------------------------------------------------------------
    {
        // Per-set commitment list.
        let mut by_set: Vec<Vec<&CommitmentEntry>> = vec![Vec::new(); n_sets];
        for c in &sets.commitments {
            by_set[c.set_index].push(c);
        }

        for (set_idx, commitments_in_set) in by_set.iter().enumerate() {
            let mut lines: Vec<String> = Vec::new();
            let q_com_base = format!("add(Q_COM_MPTR, {:#x})", set_idx * 0x80);
            let q_eval_base = format!("add(Q_EVAL_SET_MPTR, {:#x})", set_idx * 0x20);

            lines.push(format!(
                "// q_com[{set_idx}] / q_eval_set[{set_idx}]: {} commitment(s)",
                commitments_in_set.len()
            ));

            // Initialise q_com[s] = first commitment in the set.
            // Initialise q_eval_set[s] = first commitment's eval at the
            // first rotation (which is x1^0 = 1, so no scaling needed).
            let first = &commitments_in_set[0];
            let first_pt = &first.comm;
            // Copy first commitment to (0x00..0x80) scratch.
            for (off, w) in first_pt.words().iter().enumerate() {
                lines.push(format!("mstore({:#x}, {})", off * 0x20, w));
            }
            // q_eval_set[s] = sum_k x1^0 * c0.evals[k] over rotations k.
            // We compute the eval contribution as the "inner product"
            // with rotations[k] inside the set, but actually the
            // midnight-proofs structure has one eval per (commitment,
            // rotation) pair in the same set. The scaling by x1^pos
            // applies to the *commitment* index (across commitments in
            // the same set), NOT across rotations. Each commitment in
            // the set contributes a sum over rotations of evals,
            // unscaled by anything within the set; the scaling by
            // x1^pos ties commitments together.
            //
            // Wait -- re-checking midnight-proofs:
            //   q_polys[set_idx] contains one poly per commitment
            //   q_polys[set_idx] = sum_i x1^i * poly_i  (across commits)
            //   q_eval_sets[set_idx] = sum_i x1^i * evals_i_at_set_points
            // where evals_i_at_set_points is a vector of |set| field
            // elements (the i-th commitment's evals across the set's
            // rotations).
            //
            // So q_eval_set[s] is itself a *vector* of |set| evaluations
            // (not a single scalar). The verifier later proves the
            // multi-open by reducing this vector via lagrange
            // interpolation at x3.
            //
            // We therefore store q_eval_set[s] as |set| consecutive
            // words. Layout:
            //   Q_EVAL_SET_MPTR + 0x20 * (set_offset + k)
            // where set_offset is the cumulative |sets[<s]| sum.

            // Push initial first-commitment evals into the set slot.
            // For each rotation k in the set, the slot value is
            // first.evals[k] (since x1^0 = 1).
            let set_eval_offset_words: usize = sets.point_sets[..set_idx]
                .iter()
                .map(|s| s.len())
                .sum::<usize>();
            for (k, ev) in first.evals.iter().enumerate() {
                lines.push(format!(
                    "mstore(add(Q_EVAL_SET_MPTR, {:#x}), {})",
                    (set_eval_offset_words + k) * 0x20,
                    ev
                ));
            }

            // For each subsequent commitment in the set, scale by
            // x1^i and accumulate.
            for (i, c) in commitments_in_set.iter().enumerate().skip(1) {
                let x1_pow = format!("mload(add(X1_POWERS_MPTR, {:#x}))", i * 0x20);

                // q_com[s] += x1_pow * c.comm
                // Load c.comm into 0x80..0x100 scratch.
                for (off, w) in c.comm.words().iter().enumerate() {
                    lines.push(format!("mstore({:#x}, {})", 0x80 + off * 0x20, w));
                }
                // ec_mul_tmp scales the operand at 0x80..0x100 by
                // mload(0x100) = x1_pow scalar.
                lines.push(format!("mstore(0x100, {x1_pow})"));
                lines.push("success := and(success, staticcall(gas(), 0x0c, 0x80, 0xa0, 0x80, 0x80))".to_string());
                // ec_add_acc reads acc at 0x00 and operand at 0x80.
                lines.push("success := and(success, staticcall(gas(), 0x0b, 0x00, 0x100, 0x00, 0x80))".to_string());

                // q_eval_set[s][k] += x1_pow * c.evals[k]
                for (k, ev) in c.evals.iter().enumerate() {
                    let slot = format!(
                        "add(Q_EVAL_SET_MPTR, {:#x})",
                        (set_eval_offset_words + k) * 0x20
                    );
                    lines.push(format!(
                        "mstore({slot}, addmod(mload({slot}), mulmod({ev}, {x1_pow}, r), r))"
                    ));
                }
            }

            // Persist q_com[s] from 0x00..0x80 scratch into Q_COM_MPTR slot.
            for off in 0..4 {
                lines.push(format!(
                    "mstore({}, mload({:#x}))",
                    add_offset(&q_com_base, off * 0x20),
                    off * 0x20
                ));
            }

            blocks.push(lines);
            let _ = q_eval_base; // not needed at this layer, kept for symmetry.
        }
    }

    // ------------------------------------------------------------------
    // Block 4: f_eval via Horner over reverse(point_sets) using Lagrange
    // interpolation at x3.
    //
    //   acc <- 0
    //   for s in (n_sets - 1).. down to 0:
    //       points  := point_sets[s]
    //       evals   := q_eval_set[s][0..|points|]
    //       proofE  := mload(Q_EVAL_CPTR + s * 0x20)   (= q_evals[s])
    //       r_eval  := lagrange_interpolate(points, evals).eval(x3)
    //       den     := prod_{p in points} (x3 - p)
    //       eval    := (proofE - r_eval) * den.invert()
    //       acc     := acc * x2 + eval
    //   f_eval := acc
    //
    // Stored at F_EVAL_MPTR.
    // ------------------------------------------------------------------
    {
        let mut lines: Vec<String> = Vec::new();
        lines.push(format!("// f_eval via Horner over {n_sets} reversed set(s)"));
        lines.push("let x2 := mload(X2_MPTR)".to_string());
        lines.push("let x3 := mload(X3_MPTR)".to_string());
        lines.push("let f_eval := 0".to_string());
        // Resolve the calldata pointer to the q_evals block once.
        lines.push("let Q_EVAL_CPTR := mload(Q_EVAL_CPTR_MPTR)".to_string());

        for set_idx in (0..n_sets).rev() {
            let points = &sets.point_sets[set_idx];
            let m = points.len();
            // proof_eval is the s-th q_eval scalar in calldata.
            let proof_eval = format!(
                "calldataload(add(Q_EVAL_CPTR, {:#x}))",
                set_idx * 0x20
            );
            // Reference to q_eval_set[set_idx][k]:
            let set_eval_offset_words: usize =
                sets.point_sets[..set_idx].iter().map(|s| s.len()).sum::<usize>();

            lines.push(format!("// --- set {set_idx} (cardinality {m}) ---"));
            lines.push("{".to_string()); // local block

            // Compute den_j = prod_{k != j} (points[j] - points[k]) and
            // dx_j = (x3 - points[j]) for each j.
            // Then r_eval = sum_j evals[j] * den * inv(dx_j) * inv(den_j),
            // where den = prod_j dx_j.
            //
            // Special-case |set| == 1: r_eval = evals[0], den = dx[0].
            if m == 1 {
                let pt = format!(
                    "mload(add(ROT_POINTS_MPTR, {:#x}))",
                    rot_offset(&distinct_rotations, points[0])
                );
                let ev = format!(
                    "mload(add(Q_EVAL_SET_MPTR, {:#x}))",
                    set_eval_offset_words * 0x20
                );
                lines.push(format!(
                    "let dx0 := addmod(x3, sub(r, {pt}), r)"
                ));
                lines.push("let dx0_inv := scalar_inv(dx0)".to_string());
                lines.push(format!(
                    "let eval := mulmod(addmod({proof_eval}, sub(r, {ev}), r), dx0_inv, r)"
                ));
                lines.push("f_eval := addmod(mulmod(f_eval, x2, r), eval, r)".to_string());
                lines.push("}".to_string());
                continue;
            }

            // General case: m >= 2.
            // Accumulate dx[] and den_j[] inline; compute their product,
            // then call scalar_inv, then expand.
            //
            // Because we can't easily batch-invert, we call scalar_inv
            // for each individually. For m up to ~5 this is fine.
            //
            // The reference computes lagrange interpolation directly via
            // full polynomial construction; here we collapse the
            // evaluation at x3 directly using the identity above.
            for j in 0..m {
                let pt = format!(
                    "mload(add(ROT_POINTS_MPTR, {:#x}))",
                    rot_offset(&distinct_rotations, points[j])
                );
                lines.push(format!(
                    "let dx_{j} := addmod(x3, sub(r, {pt}), r)"
                ));
            }
            // den = prod_j dx_j
            lines.push("let den := dx_0".to_string());
            for j in 1..m {
                lines.push(format!("den := mulmod(den, dx_{j}, r)"));
            }
            lines.push("let den_inv := scalar_inv(den)".to_string());

            // For each j: lagrange_basis_inv_j = inv(prod_{k!=j} (p_j - p_k))
            for j in 0..m {
                let pj = format!(
                    "mload(add(ROT_POINTS_MPTR, {:#x}))",
                    rot_offset(&distinct_rotations, points[j])
                );
                lines.push(format!("let lbasis_{j} := 1"));
                for k in 0..m {
                    if k == j {
                        continue;
                    }
                    let pk = format!(
                        "mload(add(ROT_POINTS_MPTR, {:#x}))",
                        rot_offset(&distinct_rotations, points[k])
                    );
                    lines.push(format!(
                        "lbasis_{j} := mulmod(lbasis_{j}, addmod({pj}, sub(r, {pk}), r), r)"
                    ));
                }
                lines.push(format!("let lbasis_inv_{j} := scalar_inv(lbasis_{j})"));
            }

            // r_eval = sum_j evals[j] * den * inv(dx_j) * lbasis_inv_j
            //        = den * sum_j evals[j] * inv(dx_j) * lbasis_inv_j
            //
            // We can simplify: (proof_eval - r_eval) * inv(den)
            //   = proof_eval * inv(den) - sum_j evals[j] * inv(dx_j) * lbasis_inv_j
            lines.push(format!(
                "let eval := mulmod({proof_eval}, den_inv, r)"
            ));
            for j in 0..m {
                let ev_j = format!(
                    "mload(add(Q_EVAL_SET_MPTR, {:#x}))",
                    (set_eval_offset_words + j) * 0x20
                );
                lines.push(format!("let dx_inv_{j} := scalar_inv(dx_{j})"));
                lines.push(format!(
                    "let term_{j} := mulmod(mulmod({ev_j}, dx_inv_{j}, r), lbasis_inv_{j}, r)"
                ));
                lines.push(format!("eval := addmod(eval, sub(r, term_{j}), r)"));
            }
            lines.push("f_eval := addmod(mulmod(f_eval, x2, r), eval, r)".to_string());
            lines.push("}".to_string());
        }

        lines.push("mstore(F_EVAL_MPTR, f_eval)".to_string());
        blocks.push(lines);
    }

    // ------------------------------------------------------------------
    // Block 5: final commitment via msm_inner_product with x4 powers,
    // plus f_com at the highest power.
    //
    //   x4_powers = [1, x4, x4^2, ..., x4^n_sets]  (n_sets + 1 entries)
    //   final_com = sum_s x4_powers[s] * q_com[s] + x4_powers[n_sets] * f_com
    //   v         = sum_s x4_powers[s] * q_evals_at_x3[s] + x4_powers[n_sets] * f_eval
    //
    // Accumulator at 0x00..0x80; operand at 0x80..0x100.
    // ------------------------------------------------------------------
    {
        let mut lines: Vec<String> = Vec::new();
        lines.push("// build final_com and v (KZG single-opening proof)".to_string());
        lines.push("let x4 := mload(X4_MPTR)".to_string());
        // Resolve the calldata pointer to the q_evals block once.
        lines.push("let Q_EVAL_CPTR := mload(Q_EVAL_CPTR_MPTR)".to_string());

        // Seed acc with q_com[0] (x4^0 = 1).
        for off in 0..4 {
            lines.push(format!(
                "mstore({:#x}, mload(add(Q_COM_MPTR, {:#x})))",
                off * 0x20,
                off * 0x20
            ));
        }
        // v = q_evals[0] (calldata)
        lines.push("let v := calldataload(Q_EVAL_CPTR)".to_string());
        lines.push("let x4_pow := 1".to_string());

        for s in 1..n_sets {
            lines.push("x4_pow := mulmod(x4_pow, x4, r)".to_string());
            // Load q_com[s] into operand slot.
            for off in 0..4 {
                lines.push(format!(
                    "mstore({:#x}, mload(add(Q_COM_MPTR, {:#x})))",
                    0x80 + off * 0x20,
                    s * 0x80 + off * 0x20
                ));
            }
            // Scale operand by x4_pow.
            lines.push("mstore(0x100, x4_pow)".to_string());
            lines.push(
                "success := and(success, staticcall(gas(), 0x0c, 0x80, 0xa0, 0x80, 0x80))"
                    .to_string(),
            );
            // Add into accumulator.
            lines.push(
                "success := and(success, staticcall(gas(), 0x0b, 0x00, 0x100, 0x00, 0x80))"
                    .to_string(),
            );
            // v += x4_pow * q_evals[s]
            lines.push(format!(
                "v := addmod(v, mulmod(calldataload(add(Q_EVAL_CPTR, {:#x})), x4_pow, r), r)",
                s * 0x20
            ));
        }

        // Final f_com term: x4^n_sets.
        lines.push("x4_pow := mulmod(x4_pow, x4, r)".to_string());
        for off in 0..4 {
            lines.push(format!(
                "mstore({:#x}, mload(add(F_COM_MPTR, {:#x})))",
                0x80 + off * 0x20,
                off * 0x20
            ));
        }
        lines.push("mstore(0x100, x4_pow)".to_string());
        lines.push(
            "success := and(success, staticcall(gas(), 0x0c, 0x80, 0xa0, 0x80, 0x80))"
                .to_string(),
        );
        lines.push(
            "success := and(success, staticcall(gas(), 0x0b, 0x00, 0x100, 0x00, 0x80))"
                .to_string(),
        );
        lines.push("v := addmod(v, mulmod(mload(F_EVAL_MPTR), x4_pow, r), r)".to_string());

        // Persist final_com to FINAL_COM_MPTR.
        for off in 0..4 {
            lines.push(format!(
                "mstore(add(FINAL_COM_MPTR, {:#x}), mload({:#x}))",
                off * 0x20,
                off * 0x20
            ));
        }
        lines.push("mstore(V_MPTR, v)".to_string());

        blocks.push(lines);
    }

    // ------------------------------------------------------------------
    // Block 6: pairing inputs.
    //
    //   PAIRING_LHS = pi
    //   PAIRING_RHS = final_com - v*G + x3*pi
    //
    // We compute RHS in three steps:
    //   tmp1 := -v * G     (G is G1 generator at G1_BASE_MPTR)
    //   tmp2 := x3 * pi
    //   PAIRING_RHS := final_com + tmp1 + tmp2
    // ------------------------------------------------------------------
    {
        let mut lines: Vec<String> = Vec::new();
        lines.push("// pairing inputs (LHS = pi; RHS = final_com - v*G + x3*pi)".to_string());

        // PAIRING_LHS = pi (paired against G2_BASE).
        for off in 0..4 {
            lines.push(format!(
                "mstore(add(PAIRING_LHS_MPTR, {:#x}), mload(add(PI_MPTR, {:#x})))",
                off * 0x20,
                off * 0x20
            ));
        }

        // tmp = (-v) * G  =>  load G into 0x00, scale by (r - v).
        for off in 0..4 {
            lines.push(format!(
                "mstore({:#x}, mload(add(G1_BASE_MPTR, {:#x})))",
                off * 0x20,
                off * 0x20
            ));
        }
        lines.push("mstore(0x80, sub(r, mload(V_MPTR)))".to_string());
        lines.push(
            "success := and(success, staticcall(gas(), 0x0c, 0x00, 0xa0, 0x00, 0x80))"
                .to_string(),
        );

        // tmp += final_com.
        for off in 0..4 {
            lines.push(format!(
                "mstore({:#x}, mload(add(FINAL_COM_MPTR, {:#x})))",
                0x80 + off * 0x20,
                off * 0x20
            ));
        }
        lines.push(
            "success := and(success, staticcall(gas(), 0x0b, 0x00, 0x100, 0x00, 0x80))"
                .to_string(),
        );

        // tmp += x3 * pi.
        for off in 0..4 {
            lines.push(format!(
                "mstore({:#x}, mload(add(PI_MPTR, {:#x})))",
                0x80 + off * 0x20,
                off * 0x20
            ));
        }
        lines.push("mstore(0x100, mload(X3_MPTR))".to_string());
        lines.push(
            "success := and(success, staticcall(gas(), 0x0c, 0x80, 0xa0, 0x80, 0x80))"
                .to_string(),
        );
        lines.push(
            "success := and(success, staticcall(gas(), 0x0b, 0x00, 0x100, 0x00, 0x80))"
                .to_string(),
        );

        // Persist as PAIRING_RHS = final_com - v*G + x3*pi.
        for off in 0..4 {
            lines.push(format!(
                "mstore(add(PAIRING_RHS_MPTR, {:#x}), mload({:#x}))",
                off * 0x20,
                off * 0x20
            ));
        }

        blocks.push(lines);
    }

    blocks
}

// ---------------------------------------------------------------------------
// Tiny formatting helpers.
// ---------------------------------------------------------------------------

fn add_offset(base: &str, offset: usize) -> String {
    if offset == 0 {
        base.to_string()
    } else {
        format!("add({base}, {offset:#x})")
    }
}

fn rot_offset(rotations: &[i32], rot: i32) -> usize {
    rotations
        .iter()
        .position(|r| *r == rot)
        .expect("rotation present in distinct_rotations")
        * 0x20
}

// ---------------------------------------------------------------------------
// Diagnostics tests against a hand-built minimal `IntermediateSets`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::util::{EcPoint, Ptr};

    fn pt(off: usize) -> EcPoint {
        EcPoint::new(Ptr::memory(off))
    }
    fn ev(off: usize) -> Word {
        Word::from(Ptr::memory(off))
    }

    #[test]
    fn intermediate_sets_partitions_by_rotation_set() {
        // Build a synthetic query list:
        //   c0 at rot 0
        //   c1 at rot 0, rot 1
        //   c2 at rot 0, rot 1
        //   c3 at rot 0, rot 1, rot -1
        //
        // Expected:
        //   set0 = {0}     -> c0
        //   set1 = {0, 1}  -> c1, c2
        //   set2 = {-1, 0, 1} -> c3
        let queries = vec![
            Query::new(pt(0x100), 0, ev(0x200)),
            Query::new(pt(0x110), 0, ev(0x210)),
            Query::new(pt(0x110), 1, ev(0x230)),
            Query::new(pt(0x120), 0, ev(0x240)),
            Query::new(pt(0x120), 1, ev(0x260)),
            Query::new(pt(0x130), 0, ev(0x270)),
            Query::new(pt(0x130), 1, ev(0x290)),
            Query::new(pt(0x130), -1, ev(0x2b0)),
        ];

        let raw = construct_intermediate_sets_impl(&queries);
        // After dedup, point_sets must include {0}, {0, 1}, {-1, 0, 1}.
        let mut found_sizes: Vec<usize> = raw.point_sets.iter().map(|s| s.len()).collect();
        found_sizes.sort();
        assert_eq!(found_sizes, vec![1, 2, 3]);

        // Now sort and verify ordering.
        let sorted = sort_sets(raw);
        assert_eq!(
            sorted.point_sets.iter().map(|s| s.len()).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn intermediate_sets_dedups_commitments() {
        // Two queries with the same commitment at two different
        // rotations must coalesce into one CommitmentEntry with two
        // evals.
        let queries = vec![
            Query::new(pt(0x100), 0, ev(0x200)),
            Query::new(pt(0x100), 1, ev(0x220)),
        ];
        let result = sort_sets(construct_intermediate_sets_impl(&queries));
        assert_eq!(result.commitments.len(), 1);
        assert_eq!(result.commitments[0].evals.len(), 2);
        assert_eq!(result.point_sets.len(), 1);
        assert_eq!(result.point_sets[0].len(), 2);
    }
}


