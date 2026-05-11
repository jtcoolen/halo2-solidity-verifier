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
//!      - Pre-computes rotation points `x * omega^rot` for every distinct
//!        rotation appearing in any query.
//!      - Pre-computes `x1` powers up to `max_set_size - 1`.
//!      - Computes `q_com[s]` and `q_eval_set[s]` per set.
//!      - Computes `f_eval` via Horner over reverse(point_sets) using
//!        Lagrange interpolation at `x3`.
//!      - Builds the final commitment via `msm_inner_product` with `x4`
//!        powers, plus `f_com` at the highest power.
//!      - Scales `z*pi - vG` as the final pairing-side correction and emits
//!        the pairing inputs `(pi, final_com - v*G + x3*pi)`.
//!
//! Notes:
//!
//!   * The query list includes the linearized commitment built from the
//!     quotient commitment(s) and any simple-selector commitments. Its
//!     expected opening scalar is not `h(x)`; the verifier reconstructs
//!     the batched identity numerator `nu_y(x)` and stores `-nu_y(x)`.
//!     The commitment side already carries the `(1 - x^n)` quotient
//!     factor.
//!
//!   * For point-set inversion we emit one `modexp` precompile call per
//!     set (`x3 - p_j`), then locally compose. This is gas-suboptimal
//!     but correct and easy to validate; a Montgomery batch invert can
//!     replace it once the rest of the verifier is byte-stable.
//!
//! Upstream comments ported here are preserved in
//! `docs/MIDFALL_PROOFS_COMMENT_CORPUS.md` and adapted at the matching
//! emission points below. The most important ones are the Halo 2
//! multi-opening description, dummy-query/fewer-point-sets behavior, the
//! deterministic ascending-cardinality point-set sort, and the final KZG
//! pairing input `(pi, C - vG + z*pi)`.

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::codegen::{
    layout::{self, trace},
    memory::{
        FinalMsmShape, PcsMemoryRequirements, VerifierMemoryLayout, G1ADD_INPUT_BYTES, G1_BYTES,
        G1_MSM_PAIR_BYTES, PCS_STATIC_WORKING_WORDS, WORD_BYTES,
    },
    protocol::{PcsQuerySource, PermutationZEval},
    util::{ConstraintSystemMeta, Data, EcPoint, Location, Ptr, Word},
};

// ---------------------------------------------------------------------------
// Verifier query list.
// ---------------------------------------------------------------------------

/// A single verifier query: a commitment opened at `omega^rotation * x`
/// to claim `eval`. The current emitter assumes commitments are `OnePiece`
/// (single G1 point) except for the linearization query, whose synthetic
/// commitment is expanded into quotient-limb and simple-selector MSM terms
/// when the Yul is emitted.
#[derive(Clone, Debug)]
pub(crate) struct Query {
    /// Rotation exponent for the opening point `omega^rotation * x`.
    pub rotation: i32,
    /// Commitment being opened.
    pub comm: EcPoint,
    /// Claimed evaluation scalar.
    pub eval: Word,
}

impl Query {
    /// Construct one query from a commitment, rotation, and eval word.
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
/// `midfall/proofs/src/plonk/verifier.rs::verify_algebraic_constraints`.
/// The upstream verifier collects all queries for the final multi-open proof;
/// simple multiplicative selector queries are skipped because the custom
/// linearization query carries their commitments and selector accumulators.
pub(crate) fn queries(meta: &ConstraintSystemMeta, data: &Data) -> Vec<Query> {
    meta.protocol
        .pcs_queries
        .iter()
        .copied()
        .map(|source| query_from_plan(source, meta, data))
        .collect()
}

/// Resolve a typed protocol query source to concrete commitment/eval handles.
fn query_from_plan(source: PcsQuerySource, meta: &ConstraintSystemMeta, data: &Data) -> Query {
    match source {
        PcsQuerySource::Advice(q) => Query::new(
            data.advice_comms[q.column],
            q.rotation,
            *data
                .advice_evals
                .get(&q.tuple())
                .expect("advice eval present for every advice query"),
        ),
        PcsQuerySource::CommittedInstance(q) => Query::new(
            data.committed_instance_comms[q.column],
            q.rotation,
            *data
                .committed_instance_evals
                .get(&q.tuple())
                .expect("committed instance eval present for every committed instance query"),
        ),
        PcsQuerySource::PermutationZ { set, kind } => {
            let (z_cur, z_next, z_last) = data.permutation_z_evals[set];
            let (rotation, eval) = match kind {
                PermutationZEval::Cur => (0, z_cur),
                PermutationZEval::Next => (1, z_next),
                PermutationZEval::Last => (
                    meta.rotation_last,
                    z_last.expect("permutation last eval present for planned query"),
                ),
            };
            Query::new(data.permutation_z_comms[set], rotation, eval)
        }
        PcsQuerySource::LookupMultiplicity { lookup } => {
            let (m_eval, _, _, _) = &data.lookup_evals[lookup];
            Query::new(data.lookup_m_comms[lookup], 0, *m_eval)
        }
        PcsQuerySource::LookupHelper { lookup, chunk } => {
            let (_, h_evals, _, _) = &data.lookup_evals[lookup];
            Query::new(data.lookup_helper_comms[lookup][chunk], 0, h_evals[chunk])
        }
        PcsQuerySource::LookupAccumulator { lookup, rotation } => {
            let (_, _, z_eval, z_next_eval) = &data.lookup_evals[lookup];
            let eval = match rotation {
                0 => *z_eval,
                1 => *z_next_eval,
                _ => panic!("unsupported lookup accumulator rotation {rotation}"),
            };
            Query::new(data.lookup_z_comms[lookup], rotation, eval)
        }
        PcsQuerySource::Trash { index } => {
            Query::new(data.trashcan_comms[index], 0, data.trashcan_evals[index])
        }
        PcsQuerySource::Fixed(q) => Query::new(
            data.fixed_comms[q.column],
            q.rotation,
            *data
                .fixed_evals
                .get(&q.tuple())
                .expect("fixed eval present"),
        ),
        PcsQuerySource::PermutationCommon { column } => Query::new(
            data.permutation_comms[&column],
            0,
            data.permutation_evals[&column],
        ),
        PcsQuerySource::Linearization => {
            Query::new(data.computed_quotient_comm, 0, data.computed_quotient_eval)
        }
    }
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
/// Upstream comment: add dummy queries to reduce the number of distinct
/// point sets that the KZG verifier must batch.
///
/// The output order is deterministic (insertion order of groups *
/// insertion order of points), matching the prover's transcript layout.
pub(crate) fn compute_dummy_queries(queries: &[Query]) -> Vec<DummyQuery> {
    // Group by commitment, tracking each group's first occurrence
    // index in `queries` and the rotations already covered.
    let mut groups: Vec<(usize, Vec<i32>)> = Vec::new();
    for (i, q) in queries.iter().enumerate() {
        match groups
            .iter_mut()
            .find(|(idx, _)| queries[*idx].comm == q.comm)
        {
            Some((_, points)) if !points.contains(&q.rotation) => {
                points.push(q.rotation);
            }
            // Same `(commitment, rotation)` already recorded. Eval consistency
            // is enforced upstream in `construct_intermediate_sets_impl`, so
            // here we silently skip the redundant rotation rather than panic;
            // this matters when several queries (e.g. multiple committed-
            // instance columns) legally share `G1_IDENTITY_MPTR` at rotation 0.
            Some(_) => continue,
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

/// Codegen-time result of the KZG intermediate-set construction.
#[derive(Clone, Debug)]
pub(crate) struct IntermediateSets {
    /// Unique commitments with eval vectors aligned to their point set.
    pub commitments: Vec<CommitmentEntry>,
    /// Distinct rotation sets, sorted by verifier order.
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
            // Two queries can share `(commitment, rotation)` legally when the
            // protocol points multiple columns at the same slot (e.g. every
            // committed-instance column shares `G1_IDENTITY_MPTR` in the
            // zk_stdlib `verify` path). Collapse them into the existing entry
            // when their evals also agree; otherwise the proof claims the
            // same polynomial opens to two different values, which is a
            // protocol bug and must be rejected.
            if let Some(existing_pos) = slot.1.iter().position(|pi| *pi == point_idx) {
                assert_eq!(
                    slot.2[existing_pos], query.eval,
                    "duplicate (commitment, rotation) query with conflicting evals"
                );
                continue;
            }
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

    // Step 4: turn point_idx sets into actual rotation lists. The slot
    // assigned to each set is its *insertion* order, captured at
    // `or_insert(n)` above. The BTreeMap iteration here is by `Vec<usize>`
    // lex order purely so we visit every entry once; the index that lands
    // in `point_sets[..]` is `set_idx` (insertion order), which is also
    // the tiebreak key used by `sort_sets`. Anyone replacing this map
    // with a `HashMap` must preserve that insertion-order capture, not
    // the iteration order itself.
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

/// Sort point sets by ascending cardinality (tiebreaker by original set
/// index). The Rust KZG verifier relies on this deterministic order so the
/// first point set contains the fixed commitments opened at x, and the
/// in-circuit verifier can collapse the same MSMs. Returns a new
/// IntermediateSets with `set_index` values rewritten to point to the sorted
/// positions.
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

/// Build sorted intermediate sets, applying dummy queries when configured.
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

/// Return the number of distinct KZG point sets after dummy-query planning.
pub(super) fn num_point_sets(meta: &ConstraintSystemMeta, data: &Data) -> usize {
    intermediate_sets(meta, data).point_sets.len()
}

/// Group commitment entries by their sorted point-set index.
fn commitments_by_set(sets: &IntermediateSets, n_sets: usize) -> Vec<Vec<&CommitmentEntry>> {
    let mut by_set: Vec<Vec<&CommitmentEntry>> = vec![Vec::new(); n_sets];
    for c in &sets.commitments {
        by_set[c.set_index].push(c);
    }
    by_set
}

/// Number of MSM terms represented by the synthetic linearization commitment.
fn linearization_term_count(meta: &ConstraintSystemMeta) -> usize {
    // `linearization/verifier.rs::compute_linearization_commitment` builds an
    // MSM for
    //   S_0*id_0(x) + y*S_1*id_1(x) + ... -
    //   (h_0 + x^(n-1)h_1 + ...)*(x^n - 1)
    // In the outer single-H layout this quotient slice has exactly one term,
    // so the scalar is just `(1 - x^n)`.
    // Fully evaluated identities are not included on the commitment side;
    // they are accumulated, negated, and used as the expected eval scalar.
    meta.num_quotients + meta.simple_selector_cols.len()
}

/// Number of non-identity q_com MSM terms needed for one point set.
fn q_com_terms_for_set(
    meta: &ConstraintSystemMeta,
    data: &Data,
    commitments_in_set: &[&CommitmentEntry],
) -> usize {
    let g1_identity = EcPoint::new(Ptr::memory("G1_IDENTITY_MPTR"));
    let linearization_comm = data.computed_quotient_comm;
    let linearization_term_count = linearization_term_count(meta);

    commitments_in_set
        .iter()
        .map(|entry| {
            if entry.comm == g1_identity {
                0
            } else if entry.comm == linearization_comm {
                linearization_term_count
            } else {
                1
            }
        })
        .sum()
}

/// Maximum trace-only q_com MSM size across all point sets.
fn q_com_trace_terms(
    meta: &ConstraintSystemMeta,
    data: &Data,
    by_set: &[Vec<&CommitmentEntry>],
) -> usize {
    by_set
        .iter()
        .map(|commitments| q_com_terms_for_set(meta, data, commitments))
        .max()
        .unwrap_or(0)
}

/// Shape of the fused final PCS MSM after expanding linearization terms.
fn final_msm_shape(
    meta: &ConstraintSystemMeta,
    data: &Data,
    by_set: &[Vec<&CommitmentEntry>],
) -> FinalMsmShape {
    let g1_identity = EcPoint::new(Ptr::memory("G1_IDENTITY_MPTR"));
    let linearization_comm = data.computed_quotient_comm;
    let linearization_term_count = linearization_term_count(meta);
    let terms = by_set
        .iter()
        .flat_map(|commitments| commitments.iter())
        .filter(|entry| entry.comm != g1_identity)
        .map(|entry| {
            if entry.comm == linearization_comm {
                linearization_term_count
            } else {
                1
            }
        })
        .sum::<usize>()
        + 1; // f_com

    FinalMsmShape::from_terms(terms)
}

pub(super) const Q_EVAL_ROLL_THRESHOLD: usize = 4;

/// Emission strategy for a point set's q_eval fold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QEvalStrategy {
    /// Use a loop over memory-backed eval source addresses.
    Rolled,
    /// Emit straight-line arithmetic.
    Unrolled,
}

/// Pick the q_eval emission strategy for commitments in one point set.
fn q_eval_strategy(commitments: &[&CommitmentEntry]) -> QEvalStrategy {
    let Some(first) = commitments.first() else {
        return QEvalStrategy::Unrolled;
    };
    if commitments.len() < Q_EVAL_ROLL_THRESHOLD {
        return QEvalStrategy::Unrolled;
    }

    let n_rot = first.evals.len();
    let can_roll = commitments.iter().all(|commitment| {
        commitment.evals.len() == n_rot
            && commitment
                .evals
                .iter()
                .all(|eval| matches!(eval.loc(), Location::Memory))
    });

    if can_roll {
        QEvalStrategy::Rolled
    } else {
        QEvalStrategy::Unrolled
    }
}

/// Compute all PCS scratch-window and MSM size requirements.
pub(super) fn memory_requirements(
    meta: &ConstraintSystemMeta,
    data: &Data,
) -> PcsMemoryRequirements {
    let sets = intermediate_sets(meta, data);
    let n_sets = sets.point_sets.len();
    if n_sets == 0 {
        return PcsMemoryRequirements::default();
    }

    let by_set = commitments_by_set(&sets, n_sets);
    let commitments_per_set = by_set.iter().map(Vec::len);

    let mut distinct_rotations: Vec<i32> = sets
        .point_sets
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
    distinct_rotations.sort_unstable();
    distinct_rotations.dedup();

    let q_eval_source_table_words = by_set
        .iter()
        .zip(sets.point_sets.iter())
        .filter(|(commitments, _)| q_eval_strategy(commitments) == QEvalStrategy::Rolled)
        .map(|(commitments, rotations)| commitments.len() * rotations.len())
        .max()
        .unwrap_or(0);
    let q_com_trace_terms = q_com_trace_terms(meta, data, &by_set);

    PcsMemoryRequirements {
        rot_points_words: distinct_rotations.len(),
        x1_powers_words: commitments_per_set.max().unwrap_or(0),
        // Current q_com materialization is fused into the final MSM scratch
        // instead of Q_COM_MPTR. Keep the field explicit so a future
        // Q_COM_MPTR user must also participate in layout validation.
        q_com_words: 0,
        q_eval_set_words: sets.point_sets.iter().map(Vec::len).sum(),
        q_eval_source_table_words,
        q_com_trace_msm: FinalMsmShape::from_terms(q_com_trace_terms),
        final_msm: final_msm_shape(meta, data, &by_set),
    }
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

pub(super) fn static_working_memory_size() -> usize {
    // Reserve generous scratch for the pairing call and intermediate
    // q_com / final_com slots. The pairing precompile needs 2 G1 (8
    // words) + 2 G2 (16 words) + 1 output word = 25 words. We round up
    // to 32 to leave room for the in-Yul accumulator slots used during
    // MSM construction.
    PCS_STATIC_WORKING_WORDS
}

/// Emit the multi-prepare Yul body. The output is the same vec-of-vec-of-strings
/// shape the rest of the codegen uses; each inner `Vec<String>` is a discrete
/// Yul code block (rendered between `{` and `}` in the template).
#[allow(clippy::vec_init_then_push)]
pub(super) fn computations(
    meta: &ConstraintSystemMeta,
    data: &Data,
    memory: &VerifierMemoryLayout,
    truncated_challenges: bool,
    trace: bool,
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

    // The emitted blocks below adapt the Rust `multi_prepare` flow:
    // construct/sort point sets, fold q_eval vectors, interpolate at x3,
    // build the final commitment with x4 powers, then prepare the final KZG
    // pairing inputs `(pi, final_com - vG + x3*pi)`.
    // Per-set commitment list. Reused by the q_eval fold block and the
    // fused final commitment MSM.
    let by_set = commitments_by_set(&sets, n_sets);

    // The number of x1 powers is bounded by the largest commitments-per-set
    // count (one power per commitment within a set).
    let nb_x1_powers: usize = by_set.iter().map(Vec::len).max().unwrap_or(0);

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
        lines.push(format!(
            "// {} distinct rotation(s)",
            distinct_rotations.len()
        ));
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
                        idx * WORD_BYTES
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

        if trace {
            // Trace-only serialization of each point set's rotation values.
            // We borrow `Q_EVAL_SET_MPTR` as scratch for the `log1` payload
            // because Block 3 unconditionally rewrites those words with the
            // real `q_eval_set[s][k]` folds before any later block reads
            // them. Any future reader of `Q_EVAL_SET_MPTR` between this
            // block and Block 3 must move the trace scratch elsewhere.
            for (set_idx, points) in sets.point_sets.iter().enumerate() {
                lines.push(format!(
                    "// trace serialized PCS point set {set_idx} ({} point(s))",
                    points.len()
                ));
                for (point_idx, rot) in points.iter().enumerate() {
                    let rot_idx = distinct_rotations
                        .iter()
                        .position(|r| r == rot)
                        .expect("point-set rotation present in distinct rotations");
                    lines.push(format!(
                        "mstore(add(Q_EVAL_SET_MPTR, {:#x}), mload(add(ROT_POINTS_MPTR, {:#x})))",
                        point_idx * WORD_BYTES,
                        rot_idx * WORD_BYTES
                    ));
                }
                lines.push(format!(
                    "log1(Q_EVAL_SET_MPTR, {:#x}, {})",
                    points.len() * WORD_BYTES,
                    trace::PCS_SERIALIZED_POINT_SET_BASE + set_idx as u64
                ));
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
            // truncated-challenges: midnight-proofs
            // proofs/src/poly/kzg/mod.rs computes
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
            lines.push(format!("    p := add(p, {WORD_BYTES:#x})"));
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
    // Block 3: per-set q_eval_set computation.
    //
    // For each set s:
    //   q_eval_set[s] = sum_{i, c in commitments of s} x1[i] * c.eval[?]
    //
    // The commitment ordering inside a set follows the order in which
    // commitments appear in `sets.commitments` (which is the order in
    // which queries were enumerated; this matches the midnight-proofs
    // for_each iteration order).
    //
    // Storage:
    //   Q_EVAL_SET_MPTR + 0x20 * s : q_eval_set[s] (1 Fq word)
    // ------------------------------------------------------------------
    {
        // ------------------------------------------------------------------
        // Memory layout for Block 3 (rolled q_eval).
        //
        // For "wide" memory-backed sets (m >= Q_EVAL_ROLL_THRESHOLD), the `m * n_rot`
        // straight-line addmod block is collapsed into a single Yul `for`
        // loop. The loop body indexes a pre-staged scratch table holding
        // per-rotation eval addresses for each commitment.
        //
        // Per-set scratch layout:
        //   EVAL_SRC_TABLE_MPTR      m * n_rot * 0x20 bytes (eval addrs)
        //
        // The table is placed above every commitment slot. Block 5 reuses
        // the same scratch region for the fused final MSM after the q_eval
        // folds have been persisted to Q_EVAL_SET_MPTR.
        //
        // Sets with m < Q_EVAL_ROLL_THRESHOLD, ragged rotation rows, or
        // calldata-backed evals keep the unrolled emission. That preserves
        // correctness if a future proof layout stops spilling evals to memory.
        // ------------------------------------------------------------------
        let eval_src_table_mptr: usize = memory.pcs_q_eval_source_table_mptr;

        for (set_idx, commitments_in_set) in by_set.iter().enumerate() {
            let mut lines: Vec<String> = Vec::new();
            let q_eval_base = format!("add(Q_EVAL_SET_MPTR, {:#x})", set_idx * WORD_BYTES);
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

            if q_eval_strategy(commitments_in_set) == QEvalStrategy::Rolled {
                // -------- Rolled path (Opt I + Opt J merged) ----------
                lines.push(format!(
                    "// q_eval_set[{set_idx}]: {m} commitment(s) (rolled, m>={Q_EVAL_ROLL_THRESHOLD})"
                ));

                // 1. Pre-stage source-eval addresses at EVAL_SRC_TABLE_MPTR.
                //    Layout: row-major i over commits, k over rotations.
                //    Stride between commit rows = n_rot * 0x20.
                lines.push("// stage per-(commit, rotation) eval source addresses".to_string());
                for (i, c) in commitments_in_set.iter().enumerate() {
                    debug_assert_eq!(c.evals.len(), n_rot);
                    for (k, ev) in c.evals.iter().enumerate() {
                        debug_assert!(matches!(ev.loc(), Location::Memory));
                        lines.push(format!(
                            "mstore({:#x}, {})",
                            eval_src_table_mptr + (i * n_rot + k) * WORD_BYTES,
                            ev.ptr()
                        ));
                    }
                }

                // 2. Seed q_eval_set_k stack locals from c[0].evals[k]
                //    (x1^0 = 1, so no scaling needed).
                for (k, ev) in first.evals.iter().enumerate() {
                    lines.push(format!("let q_eval_set_{k} := {ev}"));
                }

                // 3. Single Yul `for` loop: accumulate evals using a single x1 power load per
                //    iteration (vs n_rot loads in the unrolled form).
                //
                //    Loop variables:
                //      pow_p : ptr into X1_POWERS_MPTR (i*0x20)
                //      eval_p: ptr into EVAL_SRC_TABLE_MPTR (i*n_rot*0x20)
                //
                //    Per iter: 1 mload(pow), n_rot * (mload + mulmod +
                //    addmod) for the evals, and 2 ptr-bump adds. Compared
                //    to the unrolled block this halves the total mload
                //    count and gives solc-via-ir a single basic block to
                //    schedule.
                let n_rot_stride = n_rot * WORD_BYTES;
                lines.push(format!("let pow_p := add(X1_POWERS_MPTR, {WORD_BYTES:#x})"));
                lines.push(format!(
                    "let eval_p := add({:#x}, {:#x})",
                    eval_src_table_mptr, n_rot_stride
                ));
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
                            k * WORD_BYTES
                        ));
                    }
                }
                lines.push(format!("    pow_p := add(pow_p, {WORD_BYTES:#x})"));
                lines.push(format!("    eval_p := add(eval_p, {:#x})", n_rot_stride));
                lines.push("}".to_string());

                // 4. Persist q_eval_set[s][k].
                for k in 0..n_rot {
                    lines.push(format!(
                        "mstore(add(Q_EVAL_SET_MPTR, {:#x}), q_eval_set_{k})",
                        (set_eval_offset_words + k) * WORD_BYTES
                    ));
                }
            } else {
                // -------- Unrolled path (preserved for non-rolled sets) --
                lines.push(format!("// q_eval_set[{set_idx}]: {m} commitment(s)"));

                // Fr-only eval accumulation in stack locals.
                for (k, ev) in first.evals.iter().enumerate() {
                    lines.push(format!("let q_eval_set_{k} := {ev}"));
                }
                for (i, c) in commitments_in_set.iter().enumerate().skip(1) {
                    let x1_pow = format!("mload(add(X1_POWERS_MPTR, {:#x}))", i * WORD_BYTES);
                    for (k, ev) in c.evals.iter().enumerate() {
                        lines.push(format!(
                            "q_eval_set_{k} := addmod(q_eval_set_{k}, mulmod({ev}, {x1_pow}, r), r)"
                        ));
                    }
                }

                // Persist q_eval_set[s][k].
                for k in 0..first.evals.len() {
                    lines.push(format!(
                        "mstore(add(Q_EVAL_SET_MPTR, {:#x}), q_eval_set_{k})",
                        (set_eval_offset_words + k) * WORD_BYTES
                    ));
                }
            }

            blocks.push(lines);
            let _ = q_eval_base; // not needed at this layer, kept for symmetry.
        }
    }

    if trace {
        // Trace-only block: per-set q_com materialization that re-runs the
        // same MSM Block 5 emits, so the trace stream can log each
        // intermediate q_com point. In production (`trace == false`) this
        // block is fully skipped because the staged data is never read by
        // the verifier itself; Block 5 stages its own copy into
        // `pcs_final_msm_scratch_mptr`.
        let mut lines: Vec<String> = Vec::new();
        let g1_identity = EcPoint::new(Ptr::memory("G1_IDENTITY_MPTR"));
        let linearization_comm = data.computed_quotient_comm;
        let simple_selector_cols: Vec<usize> = meta.simple_selector_cols.iter().copied().collect();
        let linearization_term_count = linearization_term_count(meta);
        let trace_scratch = memory.pcs_q_com_trace_scratch_mptr;
        lines.push("// materialize per-set q_com inputs for trace logging".to_string());
        for (set_idx, commitments_in_set) in by_set.iter().enumerate() {
            let non_identity_terms = commitments_in_set
                .iter()
                .map(|entry| {
                    if entry.comm == g1_identity {
                        0
                    } else if entry.comm == linearization_comm {
                        linearization_term_count
                    } else {
                        1
                    }
                })
                .sum::<usize>();
            if non_identity_terms == 0 {
                lines.push(format!(
                    "mcopy({trace_scratch:#x}, G1_IDENTITY_MPTR, {G1_BYTES:#x})"
                ));
                lines.push(format!(
                    "trace_point({}, {trace_scratch:#x})",
                    40000 + set_idx
                ));
                continue;
            }

            let mut pair_idx = 0usize;
            for (commitment_idx, c) in commitments_in_set.iter().enumerate() {
                if c.comm == g1_identity {
                    continue;
                }
                let scalar = if commitment_idx == 0 {
                    "1".to_string()
                } else {
                    format!(
                        "mload(add(X1_POWERS_MPTR, {:#x}))",
                        commitment_idx * WORD_BYTES
                    )
                };
                if c.comm == linearization_comm {
                    let lin_query_var =
                        format!("q_com_lin_query_scalar_{set_idx}_{commitment_idx}");
                    let lin_cur_var = format!("q_com_lin_cur_scalar_{set_idx}_{commitment_idx}");
                    lines.push(format!("let {lin_query_var} := {scalar}"));
                    lines.push(format!(
                        "let {lin_cur_var} := mulmod({lin_query_var}, mload(add(QUOTIENT_MPTR, {WORD_BYTES:#x})), r)"
                    ));

                    for q_idx in 0..meta.num_quotients {
                        let pair_base = trace_scratch + pair_idx * G1_MSM_PAIR_BYTES;
                        lines.push(format!(
                            "mcopy({pair_base:#x}, add(QUOTIENT_LIMB_COMMS_MPTR_BASE, {:#x}), {G1_BYTES:#x})",
                            q_idx * G1_BYTES
                        ));
                        lines.push(format!(
                            "mstore({:#x}, {lin_cur_var})",
                            pair_base + G1_BYTES
                        ));
                        pair_idx += 1;
                        if q_idx + 1 != meta.num_quotients {
                            lines.push(format!(
                                "{lin_cur_var} := mulmod({lin_cur_var}, mload(QUOTIENT_MPTR), r)"
                            ));
                        }
                    }

                    for (sel_idx, col) in simple_selector_cols.iter().copied().enumerate() {
                        let pair_base = trace_scratch + pair_idx * G1_MSM_PAIR_BYTES;
                        let selector_scalar =
                            format!("mload(add(SELECTOR_ACC_MPTR, {:#x}))", sel_idx * WORD_BYTES);
                        lines.push(format!(
                            "mcopy({pair_base:#x}, {}, {G1_BYTES:#x})",
                            data.fixed_comms[col].ptr()
                        ));
                        lines.push(format!(
                            "mstore({:#x}, mulmod({lin_query_var}, {}, r))",
                            pair_base + G1_BYTES,
                            selector_scalar
                        ));
                        pair_idx += 1;
                    }
                } else {
                    let pair_base = trace_scratch + pair_idx * G1_MSM_PAIR_BYTES;
                    lines.push(format!(
                        "mcopy({pair_base:#x}, {}, {G1_BYTES:#x})",
                        c.comm.ptr()
                    ));
                    lines.push(format!("mstore({:#x}, {scalar})", pair_base + G1_BYTES));
                    pair_idx += 1;
                }
            }
            assert_eq!(
                pair_idx, non_identity_terms,
                "q_com trace MSM input term count changed during emission"
            );
            let msm_len = non_identity_terms * G1_MSM_PAIR_BYTES;
            let msm_gas_cap = layout::precompile::g1msm_gas_cap(msm_len);
            lines.push(format!(
                "let q_com_trace_ok_{set_idx} := staticcall({msm_gas_cap}, 0x0c, {trace_scratch:#x}, {msm_len:#x}, {trace_scratch:#x}, {G1_BYTES:#x})"
            ));
            lines.push(format!(
                "q_com_trace_ok_{set_idx} := and(q_com_trace_ok_{set_idx}, eq(returndatasize(), {G1_BYTES:#x}))"
            ));
            lines.push(format!(
                "if iszero(q_com_trace_ok_{set_idx}) {{ mstore(TRACE_U256_MPTR, {}) revert(TRACE_U256_MPTR, {WORD_BYTES:#x}) }}",
                40000 + set_idx
            ));
            lines.push(format!(
                "trace_point({}, {trace_scratch:#x})",
                40000 + set_idx
            ));
        }
        blocks.push(lines);
    }

    // ------------------------------------------------------------------
    // Block 4: f_eval via Horner over reverse(point_sets) using Lagrange
    // interpolation at x3.
    // Sample a challenge x_3 so the verifier can check that f(X)
    // is correctly committed by evaluating it at a fresh point. The expected
    // eval uses the prover-supplied q_eval scalar, the reconstructed
    // interpolation r_eval, and prod_i (x_3 - point_i).
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
        lines.push(format!(
            "// f_eval via Horner over {n_sets} reversed set(s)"
        ));
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
                i * WORD_BYTES
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
            // proof_eval is the s-th q_eval scalar in calldata. The
            // Solidity proof shim rewrites q_evals to canonical BE words, so
            // calldataload gives the field element directly.
            let proof_eval = format!(
                "calldataload(add(Q_EVAL_CPTR, {:#x}))",
                set_idx * WORD_BYTES
            );
            // Reference to q_eval_set[set_idx][k]:
            let set_eval_offset_words: usize = sets.point_sets[..set_idx]
                .iter()
                .map(|s| s.len())
                .sum::<usize>();

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
                    set_eval_offset_words * WORD_BYTES
                );
                lines.push(format!("let dx0 := addmod(x3, sub(r, {pt}), r)"));
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
            for (j, point) in points.iter().enumerate().take(m) {
                let pt = rot_pt_ref(*point);
                lines.push(format!("let dx_{j} := addmod(x3, sub(r, {pt}), r)"));
            }
            // For each j: lagrange_basis_inv_j = inv(prod_{k!=j} (p_j - p_k))
            for (j, point_j) in points.iter().enumerate().take(m) {
                let pj = rot_pt_ref(*point_j);
                lines.push(format!("let lbasis_{j} := 1"));
                for (k, point_k) in points.iter().enumerate().take(m) {
                    if k == j {
                        continue;
                    }
                    let pk = rot_pt_ref(*point_k);
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
            for (i, batch_input) in batch_inputs.iter().enumerate().take(n).skip(1) {
                lines.push(format!(
                    "let bp_{i} := mulmod(bp_{}, {}, r)",
                    i - 1,
                    batch_input
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
                lines.push(format!("bq := mulmod(bq, {}, r)", batch_inputs[i]));
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
            lines.push(format!("let eval := mulmod({proof_eval}, den_inv, r)"));
            for j in 0..m {
                let ev_j = format!(
                    "mload(add(Q_EVAL_SET_MPTR, {:#x}))",
                    (set_eval_offset_words + j) * WORD_BYTES
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
    // Block 5: fused final commitment MSM with x4 powers.
    //
    // Instead of materialising every q_com[s] and then combining those
    // points with x4 powers, use linearity:
    //
    //   q_com[s]   = sum_i x1^i * C[s][i]
    //   final_com  = sum_s x4^s * q_com[s] + x4^n_sets * f_com
    //              = sum_{s,i} (x4^s * x1^i) * C[s][i]
    //                + x4^n_sets * f_com
    //
    // The q_eval_set scalar folds from Block 3 are still needed by Block 4,
    // but q_com points are not needed anywhere else. This also lets us skip
    // G1 identity commitments in the MSM input while preserving their eval
    // contribution in q_eval_set.
    // ------------------------------------------------------------------
    {
        let mut lines: Vec<String> = Vec::new();
        let g1_identity = EcPoint::new(Ptr::memory("G1_IDENTITY_MPTR"));
        let linearization_comm = data.computed_quotient_comm;
        let simple_selector_cols: Vec<usize> = meta.simple_selector_cols.iter().copied().collect();
        let final_msm_shape = final_msm_shape(meta, data, &by_set);
        let final_msm_terms = final_msm_shape.terms;
        let final_msm_len = final_msm_shape.input_bytes;
        let final_msm_scratch = memory.pcs_final_msm_scratch_mptr;

        lines.push("// build final_com and v (KZG single-opening proof, fused MSM)".to_string());
        lines.push(format!(
            "// final MSM input length from circuit/VK shape: {final_msm_terms} term(s)"
        ));
        lines.push("let x4 := mload(X4_MPTR)".to_string());
        lines.push("let lin_x_split := mload(QUOTIENT_MPTR)".to_string());
        lines.push(format!(
            "let lin_one_minus_x_n := mload(add(QUOTIENT_MPTR, {WORD_BYTES:#x}))"
        ));
        // Resolve the calldata pointer to the q_evals block once.
        lines.push("let Q_EVAL_CPTR := mload(Q_EVAL_CPTR_MPTR)".to_string());

        // truncated-challenges: midnight-proofs
        // proofs/src/poly/kzg/mod.rs uses
        //   truncated_powers(x4)[i] = truncate(x4^i)
        // i.e. the internal accumulator stays full precision while
        // each emitted power is truncated to 128 bits.
        if truncated_challenges {
            lines.push("let x4_pow_full := 1".to_string());
        } else {
            lines.push("let x4_pow_0 := 1".to_string());
        }
        for s in 1..=n_sets {
            if truncated_challenges {
                lines.push("x4_pow_full := mulmod(x4_pow_full, x4, r)".to_string());
                lines.push(format!(
                    "let x4_pow_{s} := and(x4_pow_full, {TRUNC_MASK_128})"
                ));
            } else {
                lines.push(format!("let x4_pow_{s} := mulmod(x4_pow_{}, x4, r)", s - 1));
            }
        }

        // v = sum_s x4^s * q_evals[s] + x4^n_sets * f_eval.
        lines.push("let v := calldataload(Q_EVAL_CPTR)".to_string());
        for s in 1..n_sets {
            lines.push(format!(
                "v := addmod(v, mulmod(calldataload(add(Q_EVAL_CPTR, {:#x})), x4_pow_{s}, r), r)",
                s * WORD_BYTES
            ));
        }
        lines.push(format!(
            "v := addmod(v, mulmod(mload(F_EVAL_MPTR), x4_pow_{n_sets}, r), r)"
        ));

        // final_com = sum_{s,i} (x4^s * x1^i) * C[s][i]
        //             + x4^n_sets * f_com.
        let mut pair_idx = 0usize;
        let scalar_expr = |set_idx: usize, commitment_idx: usize| -> String {
            let x1_pow = if commitment_idx == 0 {
                "1".to_string()
            } else {
                format!(
                    "mload(add(X1_POWERS_MPTR, {:#x}))",
                    commitment_idx * WORD_BYTES
                )
            };

            match (set_idx, commitment_idx) {
                (0, _) => x1_pow,
                (_, 0) => format!("x4_pow_{set_idx}"),
                _ => format!("mulmod({x1_pow}, x4_pow_{set_idx}, r)"),
            }
        };

        for (set_idx, commitments_in_set) in by_set.iter().enumerate() {
            for (commitment_idx, c) in commitments_in_set.iter().enumerate() {
                if c.comm == g1_identity {
                    continue;
                }

                let scalar = scalar_expr(set_idx, commitment_idx);
                if c.comm == linearization_comm {
                    let lin_query_var = format!("lin_query_scalar_{pair_idx}");
                    let lin_cur_var = format!("lin_cur_scalar_{pair_idx}");
                    lines.push(format!("let {lin_query_var} := {scalar}"));
                    lines.push(format!(
                        "let {lin_cur_var} := mulmod({lin_query_var}, lin_one_minus_x_n, r)"
                    ));

                    for q_idx in 0..meta.num_quotients {
                        let pair_base = final_msm_scratch + pair_idx * G1_MSM_PAIR_BYTES;
                        lines.push(format!(
                            "mcopy({pair_base:#x}, add(QUOTIENT_LIMB_COMMS_MPTR_BASE, {:#x}), {G1_BYTES:#x})",
                            q_idx * G1_BYTES
                        ));
                        lines.push(format!(
                            "mstore({:#x}, {lin_cur_var})",
                            pair_base + G1_BYTES,
                        ));
                        pair_idx += 1;
                        if q_idx + 1 != meta.num_quotients {
                            lines.push(format!(
                                "{lin_cur_var} := mulmod({lin_cur_var}, lin_x_split, r)"
                            ));
                        }
                    }

                    for (sel_idx, col) in simple_selector_cols.iter().copied().enumerate() {
                        let pair_base = final_msm_scratch + pair_idx * G1_MSM_PAIR_BYTES;
                        let selector_scalar =
                            format!("mload(add(SELECTOR_ACC_MPTR, {:#x}))", sel_idx * WORD_BYTES);
                        lines.push(format!(
                            "mcopy({pair_base:#x}, {}, {G1_BYTES:#x})",
                            data.fixed_comms[col].ptr()
                        ));
                        lines.push(format!(
                            "mstore({:#x}, mulmod({lin_query_var}, {}, r))",
                            pair_base + G1_BYTES,
                            selector_scalar
                        ));
                        pair_idx += 1;
                    }
                } else {
                    let pair_base = final_msm_scratch + pair_idx * G1_MSM_PAIR_BYTES;
                    lines.push(format!(
                        "mcopy({pair_base:#x}, {}, {G1_BYTES:#x})",
                        c.comm.ptr()
                    ));
                    lines.push(format!("mstore({:#x}, {scalar})", pair_base + G1_BYTES));
                    pair_idx += 1;
                }
            }
        }

        let pair_base = final_msm_scratch + pair_idx * G1_MSM_PAIR_BYTES;
        lines.push(format!("mcopy({pair_base:#x}, F_COM_MPTR, {G1_BYTES:#x})"));
        lines.push(format!(
            "mstore({:#x}, x4_pow_{n_sets})",
            pair_base + G1_BYTES
        ));
        pair_idx += 1;
        assert_eq!(
            pair_idx, final_msm_terms,
            "final MSM input term count changed during emission"
        );

        let final_msm_gas_cap = layout::precompile::g1msm_gas_cap(final_msm_len);
        lines.push("if success {".to_string());
        lines.push(format!(
            "    success := staticcall({final_msm_gas_cap}, 0x0c, {final_msm_scratch:#x}, {:#x}, FINAL_COM_MPTR, {G1_BYTES:#x})",
            final_msm_len
        ));
        lines.push(format!(
            "    success := and(success, eq(returndatasize(), {G1_BYTES:#x}))"
        ));
        lines.push("}".to_string());
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
        lines.push("// Scale z*pi - vG before the final pairing check".to_string());
        lines.push("// pairing inputs (LHS = pi; RHS = final_com - v*G + x3*pi)".to_string());

        // PAIRING_LHS = pi (paired against G2_BASE).
        lines.push(format!("mcopy(PAIRING_LHS_MPTR, PI_MPTR, {G1_BYTES:#x})"));

        // tmp = (-v) * G  =>  load G into planned scratch, scale by (r - v).
        let scratch = memory.pcs_pairing_scratch_mptr;
        let scratch_g1_b = scratch + G1_BYTES;
        let scratch_g1add_scalar = scratch + G1ADD_INPUT_BYTES;
        lines.push(format!("mcopy({scratch:#x}, G1_BASE_MPTR, {G1_BYTES:#x})"));
        lines.push(format!(
            "mstore({scratch_g1_b:#x}, addmod(0, sub(r, mload(V_MPTR)), r))"
        ));
        lines.push("if success {".to_string());
        lines.push(format!(
            "    success := staticcall({}, 0x0c, {scratch:#x}, {G1_MSM_PAIR_BYTES:#x}, {scratch:#x}, {G1_BYTES:#x})",
            layout::precompile::g1msm_gas_cap(G1_MSM_PAIR_BYTES)
        ));
        lines.push(format!(
            "    success := and(success, eq(returndatasize(), {G1_BYTES:#x}))"
        ));
        lines.push("}".to_string());

        // tmp += final_com.
        lines.push(format!(
            "mcopy({scratch_g1_b:#x}, FINAL_COM_MPTR, {G1_BYTES:#x})"
        ));
        lines.push("if success {".to_string());
        lines.push(format!(
            "    success := staticcall({}, 0x0b, {scratch:#x}, {G1ADD_INPUT_BYTES:#x}, {scratch:#x}, {G1_BYTES:#x})",
            layout::precompile::G1ADD_GAS_CAP
        ));
        lines.push(format!(
            "    success := and(success, eq(returndatasize(), {G1_BYTES:#x}))"
        ));
        lines.push("}".to_string());

        // tmp += x3 * pi.
        lines.push(format!("mcopy({scratch_g1_b:#x}, PI_MPTR, {G1_BYTES:#x})"));
        lines.push(format!("mstore({scratch_g1add_scalar:#x}, mload(X3_MPTR))"));
        lines.push("if success {".to_string());
        lines.push(format!(
            "    success := staticcall({}, 0x0c, {scratch_g1_b:#x}, {G1_MSM_PAIR_BYTES:#x}, {scratch_g1_b:#x}, {G1_BYTES:#x})",
            layout::precompile::g1msm_gas_cap(G1_MSM_PAIR_BYTES)
        ));
        lines.push(format!(
            "    success := and(success, eq(returndatasize(), {G1_BYTES:#x}))"
        ));
        lines.push("}".to_string());
        lines.push("if success {".to_string());
        lines.push(format!(
            "    success := staticcall({}, 0x0b, {scratch:#x}, {G1ADD_INPUT_BYTES:#x}, {scratch:#x}, {G1_BYTES:#x})",
            layout::precompile::G1ADD_GAS_CAP
        ));
        lines.push(format!(
            "    success := and(success, eq(returndatasize(), {G1_BYTES:#x}))"
        ));
        lines.push("}".to_string());

        // Persist as PAIRING_RHS = final_com - v*G + x3*pi.
        lines.push(format!(
            "mcopy(PAIRING_RHS_MPTR, {scratch:#x}, {G1_BYTES:#x})"
        ));

        blocks.push(lines);
    }

    blocks
}

// ---------------------------------------------------------------------------
// Tiny formatting helpers.
// ---------------------------------------------------------------------------

/// Render `base` or `add(base, offset)` for generated Yul pointers.
fn add_offset(base: &str, offset: usize) -> String {
    if offset == 0 {
        base.to_string()
    } else {
        format!("add({base}, {offset:#x})")
    }
}

#[allow(dead_code)]
/// Return the byte offset of a rotation inside a sorted rotation list.
fn rot_offset(rotations: &[i32], rot: i32) -> usize {
    rotations
        .iter()
        .position(|r| *r == rot)
        .expect("rotation present in distinct_rotations")
        * WORD_BYTES
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
    fn calldata_ev(off: usize) -> Word {
        Word::from(Ptr::calldata(off))
    }

    #[test]
    fn q_eval_roll_strategy_is_single_source_for_planning_and_emission() {
        assert_eq!(Q_EVAL_ROLL_THRESHOLD, 4);

        let rolled = vec![
            CommitmentEntry {
                set_index: 0,
                comm: pt(0x100),
                evals: vec![ev(0x200), ev(0x220)],
            },
            CommitmentEntry {
                set_index: 0,
                comm: pt(0x180),
                evals: vec![ev(0x240), ev(0x260)],
            },
            CommitmentEntry {
                set_index: 0,
                comm: pt(0x200),
                evals: vec![ev(0x280), ev(0x2a0)],
            },
            CommitmentEntry {
                set_index: 0,
                comm: pt(0x280),
                evals: vec![ev(0x2c0), ev(0x2e0)],
            },
        ];
        let refs = rolled.iter().collect::<Vec<_>>();
        assert_eq!(q_eval_strategy(&refs), QEvalStrategy::Rolled);

        let mut calldata_backed = rolled.clone();
        calldata_backed[3].evals[1] = calldata_ev(0x40);
        let refs = calldata_backed.iter().collect::<Vec<_>>();
        assert_eq!(q_eval_strategy(&refs), QEvalStrategy::Unrolled);

        let mut ragged = rolled;
        ragged[3].evals.pop();
        let refs = ragged.iter().collect::<Vec<_>>();
        assert_eq!(q_eval_strategy(&refs), QEvalStrategy::Unrolled);
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

        // Now sort and verify ordering and content.
        let sorted = sort_sets(raw);
        assert_eq!(
            sorted
                .point_sets
                .iter()
                .map(|s| s.len())
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        // Sets sorted by ascending cardinality must hold the expected
        // rotation values, regardless of the within-set order. Compare
        // by sorted content to avoid coupling the test to the internal
        // `point_index_of` ordering.
        let mut s0 = sorted.point_sets[0].clone();
        s0.sort_unstable();
        assert_eq!(s0, vec![0]);
        let mut s1 = sorted.point_sets[1].clone();
        s1.sort_unstable();
        assert_eq!(s1, vec![0, 1]);
        let mut s2 = sorted.point_sets[2].clone();
        s2.sort_unstable();
        assert_eq!(s2, vec![-1, 0, 1]);

        // Eval alignment: each commitment's `evals[k]` must correspond to
        // the rotation at `sorted.point_sets[c.set_index][k]`.
        let mut found_c0 = false;
        let mut found_c3 = false;
        for c in &sorted.commitments {
            let pts = &sorted.point_sets[c.set_index];
            assert_eq!(c.evals.len(), pts.len(), "evals/points length mismatch");
            if c.comm == pt(0x100) {
                found_c0 = true;
                assert_eq!(c.evals, vec![ev(0x200)]);
            }
            if c.comm == pt(0x130) {
                found_c3 = true;
                // c3's evals are aligned with the set's sorted point list;
                // use the protocol-level pairs (rotation -> eval) for a
                // location-independent check.
                let pairs: Vec<(i32, Word)> =
                    pts.iter().copied().zip(c.evals.iter().copied()).collect();
                assert!(pairs.contains(&(0, ev(0x270))));
                assert!(pairs.contains(&(1, ev(0x290))));
                assert!(pairs.contains(&(-1, ev(0x2b0))));
            }
        }
        assert!(
            found_c0 && found_c3,
            "expected c0 and c3 entries in commitments"
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
    fn compute_dummy_queries_matches_midnight_singleton_padding() {
        // This mirrors the current midnight-proofs helper exactly:
        // singleton groups do not contribute points to the union, but
        // once the union is known they are still padded to it.
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
                    query_index: 0, // c0's singleton gets padded after unioning c1/c2
                    rotation: 1,
                },
                DummyQuery {
                    query_index: 0,
                    rotation: 2,
                },
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
