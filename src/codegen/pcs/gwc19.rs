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
// Dummy-query computation (codegen-time port of
// `midfall/proofs/src/poly/kzg/utils.rs::compute_dummy_queries`, gated
// behind the `fewer-point-sets` feature on the Rust side).
// ---------------------------------------------------------------------------

/// A dummy query: append `(query_index, point)` to the raw query list,
/// reusing `raw_queries[query_index].comm` as the commitment and
/// allocating a new eval Word for the dummy proof scalar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DummyQuery {
    /// Index into the *raw* query list (the output of `queries`)
    /// whose commitment this dummy reuses.
    pub query_index: usize,
    /// Rotation point at which the dummy query opens.
    pub rotation: i32,
}

/// Run the dummy-query computation over the raw query list.
///
/// Mirrors `compute_dummy_queries` 1:1: groups queries by commitment
/// (using the [`EcPoint`] identity, which is the underlying memory
/// pointer), unions all non-singleton point sets, and emits the
/// missing `(first_index, point)` pairs that, once added, make every
/// non-singleton point set identical.
///
/// The output order is deterministic (insertion order of groups *
/// insertion order of points), matching the prover's transcript layout.
pub(crate) fn compute_dummy_queries(queries: &[Query]) -> Vec<DummyQuery> {
    // Group by commitment, tracking each group's first occurrence
    // index in `queries` and the rotations already covered.
    let mut groups: Vec<(usize, Vec<i32>)> = Vec::new();
    for (i, q) in queries.iter().enumerate() {
        match groups.iter_mut().find(|(idx, _)| queries[*idx].comm == q.comm) {
            Some((_, points)) if !points.contains(&q.rotation) => {
                points.push(q.rotation);
            }
            Some(_) => {
                panic!(
                    "duplicate (commitment, rotation) query at index {i}: \
                     compute_dummy_queries cannot run on a non-deduplicated \
                     query list"
                );
            }
            None => groups.push((i, vec![q.rotation])),
        }
    }

    // Union of all non-singleton point sets, in insertion order.
    let mut union: Vec<i32> = Vec::new();
    for (_, points) in &groups {
        if points.len() <= 1 {
            continue;
        }
        for &p in points {
            if !union.contains(&p) {
                union.push(p);
            }
        }
    }

    // Emit missing (first_index, point) pairs in deterministic order.
    let mut out: Vec<DummyQuery> = Vec::new();
    for (idx, existing) in &groups {
        for &p in &union {
            if !existing.contains(&p) {
                out.push(DummyQuery {
                    query_index: *idx,
                    rotation: p,
                });
            }
        }
    }
    out
}

/// Augment `raw_queries` with dummy queries; the i-th dummy uses
/// `dummy_eval_words[i]` as its eval Word. Caller must ensure
/// `dummy_eval_words.len() == compute_dummy_queries(raw_queries).len()`.
pub(crate) fn augment_queries_with_dummies(
    raw_queries: &[Query],
    dummy_eval_words: &[Word],
) -> Vec<Query> {
    let dummies = compute_dummy_queries(raw_queries);
    assert_eq!(
        dummies.len(),
        dummy_eval_words.len(),
        "augment_queries_with_dummies: expected {} dummy eval Words, got {}",
        dummies.len(),
        dummy_eval_words.len()
    );
    let mut out = raw_queries.to_vec();
    for (d, eval) in dummies.iter().zip(dummy_eval_words.iter()) {
        let comm = raw_queries[d.query_index].comm;
        out.push(Query::new(comm, d.rotation, *eval));
    }
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
    let raw = queries(meta, data);
    let queries = if data.dummy_eval_words.is_empty() {
        raw
    } else {
        // fewer-point-sets path: append dummy queries built against the
        // pre-allocated dummy eval Words (Data::set_dummy_evals).
        augment_queries_with_dummies(&raw, &data.dummy_eval_words)
    };
    sort_sets(construct_intermediate_sets_impl(&queries))
}

pub(super) fn num_point_sets(meta: &ConstraintSystemMeta, data: &Data) -> usize {
    intermediate_sets(meta, data).point_sets.len()
}

/// Returns the number of dummy queries (and thus the number of extra
/// Fr scalars in the proof's eval block) emitted by the
/// fewer-point-sets path for this circuit's query topology. Call this
/// over the *raw* (unaugmented) queries to size the dummy buffer
/// before constructing the augmented `Data`.
pub(super) fn num_dummy_queries(meta: &ConstraintSystemMeta, data: &Data) -> usize {
    compute_dummy_queries(&queries(meta, data)).len()
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
pub(super) fn computations(
    meta: &ConstraintSystemMeta,
    data: &Data,
    truncated_challenges: bool,
) -> Vec<Vec<String>> {
    /// 128-bit mask for `truncate(scalar)` in midnight-proofs:
    /// `truncate` keeps the lower `ceil(NUM_BITS/8)/2 = 16` bytes
    /// of the LE Fr representation, which is the lower 128 bits.
    const TRUNC_MASK_128: &str = "0xffffffffffffffffffffffffffffffff";
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
            // Roll the power-of-x1 sequence into a Yul `for` loop.
            // The unrolled emission (32 sequential mulmod+mstore
            // pairs for the Poseidon fixture) was costing ~26 kg
            // — far above the ~700 gas the arithmetic itself
            // requires. solc-via-ir struggles to register-allocate
            // 32 unrolled mulmods sharing one accumulator, and the
            // unrolled mstore-add chain inflates each line to
            // ~50-60 gas of dispatch overhead. The rolled loop
            // restores the basic-block heuristic and lets the
            // optimizer schedule the inner body once.
            //
            // Per iteration (rolled):
            //   lt + add(i+1) + add(p)   ≈ 9 gas (loop control)
            //   mulmod + mstore           ≈ 11 gas (body)
            //   ----
            //   ~20 gas/iter, × 32 = ~640 gas + 50 setup = ~700 gas
            //
            // truncated-challenges: midnight-proofs computes
            //   power[i] = truncate(x1^i)
            // where the internal x1^i accumulator stays at full
            // precision (powers(x1).map(truncate) in Rust). We mirror
            // that here by storing `and(acc, mask)` while keeping
            // `acc` itself in full precision. The +3 gas/iter cost is
            // negligible vs the ~640 gas of the loop body.
            let last = nb_x1_powers - 1;
            lines.push("let acc := 1".to_string());
            lines.push("let p := X1_POWERS_MPTR".to_string());
            lines.push(format!(
                "for {{ let i := 0 }} lt(i, {last:#x}) {{ i := add(i, 1) }} {{"
            ));
            lines.push("    p := add(p, 0x20)".to_string());
            lines.push("    acc := mulmod(acc, x1, r)".to_string());
            if truncated_challenges {
                lines.push(format!("    mstore(p, and(acc, {TRUNC_MASK_128}))"));
            } else {
                lines.push("    mstore(p, acc)".to_string());
            }
            lines.push("}".to_string());
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

        // ------------------------------------------------------------------
        // Memory layout for Block 3 (Phase 2 / Opt I+J — rolled q_eval/q_com).
        //
        // For "wide" sets (m >= ROLL_THRESHOLD), the previously-unrolled
        // `m * n_rot` straight-line addmod block + `m` mcopy/mstore staging
        // pair block is collapsed into a single Yul `for` loop. The loop
        // body indexes two pre-staged scratch tables that hold the source
        // addresses (point base + per-rotation eval addr) of each commit.
        //
        // Per-set scratch layout:
        //   POINT_SRC_TABLE_MPTR     m * 0x20 bytes  (one address per commit)
        //   EVAL_SRC_TABLE_MPTR      m * n_rot * 0x20 bytes (eval addrs)
        //   MSM_SCRATCH              m * 0xa0 bytes  (point+scalar pairs)
        //
        // The tables are placed ABOVE the previous MSM_SCRATCH=0x6100, sized
        // for the worst-case m across all sets so that the same constants
        // can be reused per-set without collision. The +~3 KB memory
        // expansion costs ~3 kg, dwarfed by the >100 kg saving on wide
        // sets (cf. OPTIMISATION.md cp19/H2 −48 kg from rolling the
        // 32-step x1-powers loop alone).
        //
        // Sets with m < ROLL_THRESHOLD keep the unrolled emission (faster
        // for tiny m where loop overhead dominates).
        // ------------------------------------------------------------------
        const ROLL_THRESHOLD: usize = 4;
        let max_m = by_set.iter().map(|c| c.len()).max().unwrap_or(0);
        let max_n_rot = by_set
            .iter()
            .filter(|c| !c.is_empty())
            .map(|c| c[0].evals.len())
            .max()
            .unwrap_or(0);
        // Phase-2.1 staging tables must live ABOVE every commitment slot
        // — `comms_mptr_base` starts the advice-comm region, then
        // lookup_m, perm_z, lookup_helpers, lookup_z, trashcan,
        // quotient-limb (all 4-word EIP-2537 padded points). The codegen
        // uses the same arithmetic as the template's
        // `QUOTIENT_LIMB_COMMS_MPTR_BASE` constant, plus 4 words for each
        // quotient limb. Hardcoded `0x6100` (the previous Poseidon-only
        // MSM_SCRATCH) silently overlapped ADVICE_COMMS_MPTR_BASE for the
        // IVC fixture (110 instances, ~250 advice columns) and fed the
        // staticcall garbage point coords, costing ~5B gas on the
        // BLS12_G1MSM precompile path.
        let comms_top_words = data.comms_mptr_base.value().as_usize() / 0x20
            + 4 * (
                meta.num_user_advices.iter().sum::<usize>()
                    + meta.num_lookups
                    + meta.num_permutation_zs
                    + meta.lookup_chunks.iter().sum::<usize>()
                    + meta.num_lookups
                    + meta.num_trashcans
                    + meta.num_quotients
            );
        // Round up to 0x20 alignment (it already is since words are 32-byte aligned).
        let needs_rolled_path = max_m >= ROLL_THRESHOLD;
        let point_src_table_mptr: usize = comms_top_words * 0x20;
        let eval_src_table_mptr: usize = if needs_rolled_path {
            point_src_table_mptr + max_m * 0x20
        } else {
            point_src_table_mptr
        };
        let msm_scratch: usize = if needs_rolled_path {
            eval_src_table_mptr + max_m * max_n_rot * 0x20
        } else {
            point_src_table_mptr
        };

        for (set_idx, commitments_in_set) in by_set.iter().enumerate() {
            let mut lines: Vec<String> = Vec::new();
            let q_com_base = format!("add(Q_COM_MPTR, {:#x})", set_idx * 0x80);
            let q_eval_base = format!("add(Q_EVAL_SET_MPTR, {:#x})", set_idx * 0x20);
            let m = commitments_in_set.len();

            // q_eval_set[s] is itself a *vector* of |set| evaluations
            // (not a single scalar): one per rotation in the set's
            // point list. midnight-proofs computes
            //   q_polys[s]    = sum_i x1^i * poly_i             (across commits in s)
            //   q_eval_set[s] = sum_i x1^i * evals_i_at_set_points
            // The verifier later folds this vector via Lagrange
            // interpolation at x3 (block 4).
            //
            // Storage:
            //   Q_EVAL_SET_MPTR + 0x20 * (set_offset + k)
            // where set_offset is the cumulative |sets[<s]| sum.
            let first = &commitments_in_set[0];
            let n_rot = first.evals.len();
            let set_eval_offset_words: usize = sets.point_sets[..set_idx]
                .iter()
                .map(|s| s.len())
                .sum::<usize>();

            if m >= ROLL_THRESHOLD {
                // -------- Rolled path (Opt I + Opt J merged) ----------
                lines.push(format!(
                    "// q_com[{set_idx}] / q_eval_set[{set_idx}]: {m} commitment(s) (batched MSM, rolled, m>={ROLL_THRESHOLD})"
                ));

                // 1. Pre-stage source-point addresses at POINT_SRC_TABLE_MPTR.
                //    Each entry is the base address of c[i].comm (4-word point).
                lines.push("// stage commit-point source addresses".to_string());
                for (i, c) in commitments_in_set.iter().enumerate() {
                    lines.push(format!(
                        "mstore({:#x}, {})",
                        point_src_table_mptr + i * 0x20,
                        c.comm.ptr()
                    ));
                }

                // 2. Pre-stage source-eval addresses at EVAL_SRC_TABLE_MPTR.
                //    Layout: row-major i over commits, k over rotations.
                //    Stride between commit rows = n_rot * 0x20.
                lines.push("// stage per-(commit, rotation) eval source addresses".to_string());
                for (i, c) in commitments_in_set.iter().enumerate() {
                    debug_assert_eq!(c.evals.len(), n_rot);
                    for (k, ev) in c.evals.iter().enumerate() {
                        // Each ev is a Word; for memory-anchored evals
                        // (which is the case after H3) `ev.ptr()` renders
                        // to the bare address. For calldata-anchored
                        // evals we'd have to fall back to the unrolled
                        // path; the default test fixtures all go through
                        // REVERSED_EVALS_MPTR so this branch is hot.
                        debug_assert!(
                            matches!(ev.loc(), crate::codegen::util::Location::Memory),
                            "rolled q_eval emission requires memory-anchored evals"
                        );
                        lines.push(format!(
                            "mstore({:#x}, {})",
                            eval_src_table_mptr + (i * n_rot + k) * 0x20,
                            ev.ptr()
                        ));
                    }
                }

                // 3. Seed q_eval_set_k stack locals from c[0].evals[k]
                //    (x1^0 = 1, so no scaling needed).
                for (k, ev) in first.evals.iter().enumerate() {
                    lines.push(format!("let q_eval_set_{k} := {ev}"));
                }

                // 4. Stage commit 0 at MSM_SCRATCH (point + scalar=1).
                lines.push(format!(
                    "mcopy({:#x}, {}, 0x80)",
                    msm_scratch,
                    first.comm.ptr()
                ));
                lines.push(format!("mstore({:#x}, 1)", msm_scratch + 0x80));

                // 5. Single Yul `for` loop: stage commits 1..m-1 +
                //    accumulate evals using a single x1 power load per
                //    iteration (vs n_rot loads in the unrolled form).
                //
                //    Loop variables:
                //      pow_p : ptr into X1_POWERS_MPTR (i*0x20)
                //      eval_p: ptr into EVAL_SRC_TABLE_MPTR (i*n_rot*0x20)
                //      pt_p  : ptr into POINT_SRC_TABLE_MPTR (i*0x20)
                //      dst   : ptr into MSM_SCRATCH (i*0xa0)
                //
                //    Per iter: 1 mload(pow), n_rot * (mload + mulmod +
                //    addmod) for the evals, 1 mcopy + 1 mstore for the
                //    staging, 4 ptr-bump adds. Compared to the unrolled
                //    block this halves the total mload count and gives
                //    solc-via-ir a single basic block to schedule.
                let n_rot_stride = n_rot * 0x20;
                lines.push(format!(
                    "let pow_p := add(X1_POWERS_MPTR, 0x20)"
                ));
                lines.push(format!(
                    "let eval_p := add({:#x}, {:#x})",
                    eval_src_table_mptr, n_rot_stride
                ));
                lines.push(format!(
                    "let pt_p := add({:#x}, 0x20)",
                    point_src_table_mptr
                ));
                lines.push(format!("let dst := add({:#x}, 0xa0)", msm_scratch));
                lines.push(format!(
                    "for {{ let i := 1 }} lt(i, {:#x}) {{ i := add(i, 1) }} {{",
                    m
                ));
                lines.push("    let pow := mload(pow_p)".to_string());
                for k in 0..n_rot {
                    if k == 0 {
                        lines.push(
                            "    q_eval_set_0 := addmod(q_eval_set_0, mulmod(mload(mload(eval_p)), pow, r), r)"
                                .to_string(),
                        );
                    } else {
                        lines.push(format!(
                            "    q_eval_set_{k} := addmod(q_eval_set_{k}, mulmod(mload(mload(add(eval_p, {:#x}))), pow, r), r)",
                            k * 0x20
                        ));
                    }
                }
                lines.push("    mcopy(dst, mload(pt_p), 0x80)".to_string());
                lines.push("    mstore(add(dst, 0x80), pow)".to_string());
                lines.push("    pow_p := add(pow_p, 0x20)".to_string());
                lines.push(format!(
                    "    eval_p := add(eval_p, {:#x})",
                    n_rot_stride
                ));
                lines.push("    pt_p := add(pt_p, 0x20)".to_string());
                lines.push("    dst := add(dst, 0xa0)".to_string());
                lines.push("}".to_string());

                // 6. MSM call + writeback.
                lines.push(format!(
                    "success := and(success, staticcall(gas(), 0x0c, {:#x}, {:#x}, {:#x}, 0x80))",
                    msm_scratch,
                    m * 0xa0,
                    msm_scratch
                ));
                lines.push(format!(
                    "mcopy({}, {:#x}, 0x80)",
                    q_com_base, msm_scratch
                ));

                // 7. Persist q_eval_set[s][k].
                for k in 0..n_rot {
                    lines.push(format!(
                        "mstore(add(Q_EVAL_SET_MPTR, {:#x}), q_eval_set_{k})",
                        (set_eval_offset_words + k) * 0x20
                    ));
                }
            } else {
                // -------- Unrolled path (preserved for m < ROLL_THRESHOLD) --
                lines.push(format!(
                    "// q_com[{set_idx}] / q_eval_set[{set_idx}]: {m} commitment(s) (batched MSM, optimisation #1)"
                ));

                // Phase 1: Fr-only eval accumulation in stack locals.
                for (k, ev) in first.evals.iter().enumerate() {
                    lines.push(format!("let q_eval_set_{k} := {ev}"));
                }
                for (i, c) in commitments_in_set.iter().enumerate().skip(1) {
                    let x1_pow = format!("mload(add(X1_POWERS_MPTR, {:#x}))", i * 0x20);
                    for (k, ev) in c.evals.iter().enumerate() {
                        lines.push(format!(
                            "q_eval_set_{k} := addmod(q_eval_set_{k}, mulmod({ev}, {x1_pow}, r), r)"
                        ));
                    }
                }

                // Phase 2: G1 commitment fold via one m-pair MSM (or mcopy
                // for m=1).
                if m == 1 {
                    lines.push(format!(
                        "mcopy({}, {}, 0x80)",
                        q_com_base,
                        first.comm.ptr()
                    ));
                } else {
                    for (i, c) in commitments_in_set.iter().enumerate() {
                        let pair_base = msm_scratch + i * 0xa0;
                        lines.push(format!(
                            "mcopy({:#x}, {}, 0x80)",
                            pair_base,
                            c.comm.ptr()
                        ));
                        if i == 0 {
                            lines.push(format!("mstore({:#x}, 1)", pair_base + 0x80));
                        } else {
                            lines.push(format!(
                                "mstore({:#x}, mload(add(X1_POWERS_MPTR, {:#x})))",
                                pair_base + 0x80,
                                i * 0x20
                            ));
                        }
                    }
                    lines.push(format!(
                        "success := and(success, staticcall(gas(), 0x0c, {:#x}, {:#x}, {:#x}, 0x80))",
                        msm_scratch,
                        m * 0xa0,
                        msm_scratch
                    ));
                    lines.push(format!(
                        "mcopy({}, {:#x}, 0x80)",
                        q_com_base, msm_scratch
                    ));
                }

                // Persist q_eval_set[s][k].
                for k in 0..first.evals.len() {
                    lines.push(format!(
                        "mstore(add(Q_EVAL_SET_MPTR, {:#x}), q_eval_set_{k})",
                        (set_eval_offset_words + k) * 0x20
                    ));
                }
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
        // Hoist all distinct rotation points to stack locals; each
        // gets read up to ~m^2 times across the set's dx_j and
        // lbasis_j chains, so a single mload at the top of the block
        // saves several mloads per reference.
        for (i, _rot) in distinct_rotations.iter().enumerate() {
            lines.push(format!(
                "let rot_pt_{i} := mload(add(ROT_POINTS_MPTR, {:#x}))",
                i * 0x20
            ));
        }

        // Helper closure: rotation-point reference for codegen.
        let rot_pt_ref = |rot: i32| -> String {
            let idx = distinct_rotations
                .iter()
                .position(|r| *r == rot)
                .expect("rotation present in distinct_rotations");
            format!("rot_pt_{idx}")
        };

        for set_idx in (0..n_sets).rev() {
            let points = &sets.point_sets[set_idx];
            let m = points.len();
            // proof_eval is the s-th q_eval scalar in calldata.
            let proof_eval = format!(
                "byte_reverse_32(calldataload(add(Q_EVAL_CPTR, {:#x})))",
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
                let pt = rot_pt_ref(points[0]);
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
            //
            // We need to invert {dx_j} for j=0..m and {lbasis_j} for
            // j=0..m, where:
            //
            //   dx_j      = x3 - p_j
            //   lbasis_j  = prod_{k != j} (p_j - p_k)
            //
            // Naively that's 2m + 1 separate `scalar_inv` (modexp) calls
            // (the original code also inverted `den = prod_j dx_j`).
            // But `den_inv` is just `prod_j dx_j_inv`, so we don't need
            // to invert it separately. And the remaining 2m values can
            // be Montgomery-batched into a SINGLE modexp:
            //
            //   p_0     = a_0
            //   p_i     = p_{i-1} * a_i           for i = 1..n-1   (n-1 muls)
            //   q       = scalar_inv(p_{n-1})                       (1 modexp)
            //   a_inv_i = q * p_{i-1} ; q *= a_i  for i = n-1..1  (2(n-1) muls)
            //   a_inv_0 = q
            //
            // Total: 1 modexp + (3n − 3) muls vs the original n modexp.
            // For m=3, n=6: saves 5 modexp ≈ 7.5 kg. For m=2, n=4:
            // saves 3 modexp ≈ 4.5 kg.
            //
            // Soundness: requires every input to be non-zero. dx_j is
            // non-zero by Fiat-Shamir (x3 is uniform random; the
            // probability that x3 = p_j for a structured rotation point
            // is ~2^-256). lbasis_j is non-zero because the points in a
            // set are distinct by construction (`construct_intermediate_sets`
            // de-duplicates rotations within each set). Defensive note:
            // a malicious prover cannot influence either, so we don't
            // need an explicit zero check.
            //
            // The reference computes lagrange interpolation directly via
            // full polynomial construction; here we collapse the
            // evaluation at x3 directly using the identity above.
            for j in 0..m {
                let pt = rot_pt_ref(points[j]);
                lines.push(format!(
                    "let dx_{j} := addmod(x3, sub(r, {pt}), r)"
                ));
            }
            // For each j: lagrange_basis_inv_j = inv(prod_{k!=j} (p_j - p_k))
            for j in 0..m {
                let pj = rot_pt_ref(points[j]);
                lines.push(format!("let lbasis_{j} := 1"));
                for k in 0..m {
                    if k == j {
                        continue;
                    }
                    let pk = rot_pt_ref(points[k]);
                    lines.push(format!(
                        "lbasis_{j} := mulmod(lbasis_{j}, addmod({pj}, sub(r, {pk}), r), r)"
                    ));
                }
            }

            // Build the Montgomery batch input list: dx_0, ..., dx_{m-1},
            // then lbasis_0, ..., lbasis_{m-1}.
            let mut batch_inputs: Vec<String> = Vec::with_capacity(2 * m);
            for j in 0..m {
                batch_inputs.push(format!("dx_{j}"));
            }
            for j in 0..m {
                batch_inputs.push(format!("lbasis_{j}"));
            }
            let n = batch_inputs.len();

            // Forward pass: build prefix products bp_0, bp_1, ..., bp_{n-1}.
            //   bp_0     = batch_inputs[0]
            //   bp_i     = bp_{i-1} * batch_inputs[i]
            // Last one (bp_{n-1}) is the total product.
            lines.push(format!("let bp_0 := {}", batch_inputs[0]));
            for i in 1..n {
                lines.push(format!(
                    "let bp_{i} := mulmod(bp_{}, {}, r)",
                    i - 1,
                    batch_inputs[i]
                ));
            }

            // One modexp for the whole set.
            lines.push(format!("let bq := scalar_inv(bp_{})", n - 1));

            // Backward pass: extract individual inverses. Walk from
            // i=n-1 down to i=1, then handle i=0 last.
            //
            //   inv_i  = bq * bp_{i-1}
            //   bq    *= batch_inputs[i]
            //
            // We name each inverse using its original variable: the
            // first m inputs are dx_j → dx_inv_j, the next m are
            // lbasis_j → lbasis_inv_j.
            let inv_name = |idx: usize| -> String {
                if idx < m {
                    format!("dx_inv_{idx}")
                } else {
                    format!("lbasis_inv_{}", idx - m)
                }
            };
            for i in (1..n).rev() {
                lines.push(format!(
                    "let {} := mulmod(bq, bp_{}, r)",
                    inv_name(i),
                    i - 1
                ));
                lines.push(format!(
                    "bq := mulmod(bq, {}, r)",
                    batch_inputs[i]
                ));
            }
            lines.push(format!("let {} := bq", inv_name(0)));

            // den_inv = prod_j dx_inv_j (free, no extra modexp).
            lines.push("let den_inv := dx_inv_0".to_string());
            for j in 1..m {
                lines.push(format!("den_inv := mulmod(den_inv, dx_inv_{j}, r)"));
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
    //
    // Note: tried batching this into one (n_sets+1)-pair MSM, but for
    // n_sets <= 3 (typical) the 4-pair MSM (~33k) is more expensive
    // than the equivalent 3 × G1MSM-1 + 3 × G1ADD chain (~37.5k base,
    // but the existing structure folds q_com[0] in for free as the
    // accumulator seed, leaving 2 × G1MSM-1 + 2 × G1ADD + 1 final
    // (f_com) MSM-1 + 1 final ADD = ~25k); the staging mstore overhead
    // (24 stores × 9 = ~216 gas) erases the small precompile saving.
    // The win for batched MSM only kicks in once n_sets >= 5 or so.
    // ------------------------------------------------------------------
    {
        let mut lines: Vec<String> = Vec::new();
        lines.push("// build final_com and v (KZG single-opening proof)".to_string());
        lines.push("let x4 := mload(X4_MPTR)".to_string());
        // Resolve the calldata pointer to the q_evals block once.
        lines.push("let Q_EVAL_CPTR := mload(Q_EVAL_CPTR_MPTR)".to_string());

        // Seed acc with q_com[0] (x4^0 = 1).
        // 4-word point copy via Cancun MCOPY: ~15 gas vs ~60 for the
        // mstore/mload chain. Same for every other 4-word copy below.
        lines.push("mcopy(0x0, Q_COM_MPTR, 0x80)".to_string());
        // v = q_evals[0] (calldata, midnight-proofs Fr::to_repr() is LE -> byte-reverse)
        lines.push("let v := byte_reverse_32(calldataload(Q_EVAL_CPTR))".to_string());
        // truncated-challenges: midnight-proofs uses
        //   truncated_powers(x4)[i] = truncate(x4^i)
        // i.e. the internal accumulator stays full precision while
        // each emitted power is truncated to 128 bits. We mirror that
        // by maintaining `x4_pow_full` (the full-precision Fr running
        // product, advanced by `mulmod(_, x4, r)`) separately from
        // `x4_pow` (the truncated value used as the MSM scalar / Fr
        // coefficient in `v`).
        //
        // When the feature is OFF the two collapse into one variable
        // and the emitted code is byte-identical to the pre-Phase-3
        // path.
        if truncated_challenges {
            lines.push("let x4_pow_full := 1".to_string());
            lines.push("let x4_pow := 1".to_string());
        } else {
            lines.push("let x4_pow := 1".to_string());
        }

        // Helper closure: emit the lines that advance `x4_pow` to the
        // next power. Renders to one mulmod when the feature is off,
        // or to one mulmod + one and(_, mask) when it is on.
        let advance_x4_pow = |lines: &mut Vec<String>| {
            if truncated_challenges {
                lines.push("x4_pow_full := mulmod(x4_pow_full, x4, r)".to_string());
                lines.push(format!(
                    "x4_pow := and(x4_pow_full, {TRUNC_MASK_128})"
                ));
            } else {
                lines.push("x4_pow := mulmod(x4_pow, x4, r)".to_string());
            }
        };

        for s in 1..n_sets {
            advance_x4_pow(&mut lines);
            // Load q_com[s] into operand slot.
            lines.push(format!(
                "mcopy(0x80, add(Q_COM_MPTR, {:#x}), 0x80)",
                s * 0x80
            ));
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
                "v := addmod(v, mulmod(byte_reverse_32(calldataload(add(Q_EVAL_CPTR, {:#x}))), x4_pow, r), r)",
                s * 0x20
            ));
        }

        // Final f_com term: x4^n_sets.
        advance_x4_pow(&mut lines);
        lines.push("mcopy(0x80, F_COM_MPTR, 0x80)".to_string());
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
        lines.push("mcopy(FINAL_COM_MPTR, 0x0, 0x80)".to_string());
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
    //
    // Note: We tried batching this into a 3-pair MSM but per EIP-2537
    // gas tables, 3-pair G1MSM (~27.5k gas) is *more* expensive than
    // 2 × G1MSM-1 + 2 × G1ADD (= 25k gas) in this size regime; the
    // multi-pair discount only starts to dominate at >= 4 pairs.
    // ------------------------------------------------------------------
    {
        let mut lines: Vec<String> = Vec::new();
        lines.push("// pairing inputs (LHS = pi; RHS = final_com - v*G + x3*pi)".to_string());

        // PAIRING_LHS = pi (paired against G2_BASE).
        lines.push("mcopy(PAIRING_LHS_MPTR, PI_MPTR, 0x80)".to_string());

        // tmp = (-v) * G  =>  load G into 0x00, scale by (r - v).
        lines.push("mcopy(0x0, G1_BASE_MPTR, 0x80)".to_string());
        lines.push("mstore(0x80, sub(r, mload(V_MPTR)))".to_string());
        lines.push(
            "success := and(success, staticcall(gas(), 0x0c, 0x00, 0xa0, 0x00, 0x80))"
                .to_string(),
        );

        // tmp += final_com.
        lines.push("mcopy(0x80, FINAL_COM_MPTR, 0x80)".to_string());
        lines.push(
            "success := and(success, staticcall(gas(), 0x0b, 0x00, 0x100, 0x00, 0x80))"
                .to_string(),
        );

        // tmp += x3 * pi.
        lines.push("mcopy(0x80, PI_MPTR, 0x80)".to_string());
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
        lines.push("mcopy(PAIRING_RHS_MPTR, 0x0, 0x80)".to_string());

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

#[allow(dead_code)]
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

    // ----------------------------------------------------------------
    // Phase 3: dummy-query computation (fewer-point-sets path).
    // ----------------------------------------------------------------

    #[test]
    fn compute_dummy_queries_emits_no_dummies_when_all_singletons() {
        // Every commitment has exactly one rotation - no point sets to
        // unify. Output must be empty.
        let queries = vec![
            Query::new(pt(0x100), 0, ev(0x200)),
            Query::new(pt(0x110), 0, ev(0x220)),
            Query::new(pt(0x120), 5, ev(0x240)),
        ];
        assert_eq!(compute_dummy_queries(&queries), Vec::new());
    }

    #[test]
    fn compute_dummy_queries_emits_no_dummies_for_aligned_pairs() {
        // Two non-singleton commitments share the same rotation set.
        // No dummies are needed.
        let queries = vec![
            Query::new(pt(0x100), 0, ev(0x200)),
            Query::new(pt(0x100), 1, ev(0x210)),
            Query::new(pt(0x110), 0, ev(0x220)),
            Query::new(pt(0x110), 1, ev(0x230)),
        ];
        assert_eq!(compute_dummy_queries(&queries), Vec::new());
    }

    #[test]
    fn compute_dummy_queries_unifies_two_distinct_pairs() {
        // c1 at {0, 1}, c2 at {0, 2}. Union = {0, 1, 2}; c1 needs a
        // dummy at 2; c2 needs a dummy at 1.
        let queries = vec![
            Query::new(pt(0x100), 0, ev(0x200)),
            Query::new(pt(0x100), 1, ev(0x210)),
            Query::new(pt(0x110), 0, ev(0x220)),
            Query::new(pt(0x110), 2, ev(0x230)),
        ];
        let dummies = compute_dummy_queries(&queries);
        // c1's first occurrence is index 0; c2's first occurrence is 2.
        // Insertion order of union: rot 0, rot 1, rot 2 (from c1 first,
        // then c2 contributes 2). For c1 (existing {0, 1}), missing 2.
        // For c2 (existing {0, 2}), missing 1.
        assert_eq!(
            dummies,
            vec![
                DummyQuery {
                    query_index: 0,
                    rotation: 2,
                },
                DummyQuery {
                    query_index: 2,
                    rotation: 1,
                },
            ]
        );
    }

    #[test]
    fn compute_dummy_queries_skips_singletons() {
        // c0 at {0} (singleton, untouched), c1 at {0, 1}, c2 at {0, 2}.
        // Union of non-singletons = {0, 1, 2}. c0 is a singleton so it
        // is NOT padded. c1 needs dummy at 2; c2 needs dummy at 1.
        let queries = vec![
            Query::new(pt(0x0f0), 0, ev(0x100)), // c0 (singleton)
            Query::new(pt(0x100), 0, ev(0x200)), // c1
            Query::new(pt(0x100), 1, ev(0x210)),
            Query::new(pt(0x110), 0, ev(0x220)), // c2
            Query::new(pt(0x110), 2, ev(0x230)),
        ];
        let dummies = compute_dummy_queries(&queries);
        assert_eq!(
            dummies,
            vec![
                DummyQuery {
                    query_index: 1, // c1's first occurrence
                    rotation: 2,
                },
                DummyQuery {
                    query_index: 3, // c2's first occurrence
                    rotation: 1,
                },
            ]
        );
    }

    #[test]
    fn augmented_queries_collapse_to_single_set() {
        // After adding dummies, the augmented query list must yield
        // exactly ONE non-singleton point set covering {0, 1, 2}.
        let raw = vec![
            Query::new(pt(0x100), 0, ev(0x200)),
            Query::new(pt(0x100), 1, ev(0x210)),
            Query::new(pt(0x110), 0, ev(0x220)),
            Query::new(pt(0x110), 2, ev(0x230)),
        ];
        let dummy_words = vec![ev(0x300), ev(0x320)];
        let augmented = augment_queries_with_dummies(&raw, &dummy_words);
        assert_eq!(augmented.len(), 6);
        let sets = sort_sets(construct_intermediate_sets_impl(&augmented));
        assert_eq!(sets.point_sets.len(), 1, "all merged into one set");
        assert_eq!(sets.point_sets[0].len(), 3);
    }
}
