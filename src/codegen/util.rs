// Step 1-3 migration: most of the Yul-emission helpers in this module are
// only consumed by the codegen tree once Steps 4-9 are completed. We
// keep them here (rather than gating them with `cfg(test)`) so the
// post-migration emitter has them available without a re-import dance.
#![allow(dead_code)]

use crate::codegen::{
    template::Halo2VerifyingKey,
    BatchOpenScheme::{self, Gwc19},
};
use ff::PrimeField;
use itertools::{chain, izip, Itertools};
use midnight_curves::{Coordinates, CurveAffine, Fq, G1Affine, G2Affine};
use midnight_proofs::plonk::{Any, Column, ConstraintSystem};
use ruint::{aliases::U256, UintTryFrom};
use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt::{self, Display, Formatter},
    ops::{Add, Sub},
};

// ----------------------------------------------------------------------------
// Migration note (Steps 1-3, 2026-04-26): the old `ConstraintSystemMeta` was
// driven by halo2-proofs v0.4 backend types (`ConstraintSystemBack`,
// `ColumnMid`, halo2 grand-product lookup). We now walk the
// `midnight_proofs::plonk::ConstraintSystem<Fq>` directly, which exposes:
//
//   * `cs.lookups()` -> `Vec<logup::BatchedArgument<F>>` (with `chunk_by_degree`,
//     `num_chunks`)
//   * `cs.trashcans()` -> `Vec<trash::Argument<F>>`
//   * `cs.permutation()` -> `&permutation::Argument` with `get_columns()`
//   * `cs.num_simple_selectors()`, `cs.has_simple_selector_col(idx)`
//
// The proof byte layout this metadata describes corresponds to
// `midnight_proofs::plonk::verifier::parse_trace`:
//   per phase: read advices, squeeze challenges, ...
//   theta
//   per proof: read multiplicities (one G1 per lookup)
//   beta, gamma
//   per proof: read permutation product commitments
//   per proof: per lookup, read num_chunks helpers + 1 accumulator
//   trash_challenge
//   per proof: read trashcan commitments
//   y
//   read quotient limbs
//   x
//   read evaluations (committed_instance? + advice + fixed-non-simple +
//                     perm_common + perm_set + lookup + trash)
//   PCS (multi_prepare):
//     x1, x2; read f_com; x3; read q_evals (one per point set);
//     x4; read pi
//
// Steps 4-9 of MIGRATION.md track the remaining work to materialise this
// schema into a complete Yul emitter. For Steps 1-3 we only need the
// scalar metadata fields below to be derivable from the new CS so that
// `cargo check --lib` is green.
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct ConstraintSystemMeta {
    pub(crate) num_fixeds: usize,
    pub(crate) permutation_columns: Vec<Column<Any>>,
    pub(crate) permutation_chunk_len: usize,
    pub(crate) num_lookups: usize,
    pub(crate) lookup_chunks: Vec<usize>,
    pub(crate) num_trashcans: usize,
    pub(crate) num_permutation_zs: usize,
    pub(crate) num_quotients: usize,
    pub(crate) advice_queries: Vec<(usize, i32)>,
    pub(crate) fixed_queries: Vec<(usize, i32)>,
    pub(crate) num_simple_selectors: usize,
    pub(crate) num_committed_instances: usize,
    pub(crate) num_rotations: usize,
    pub(crate) num_evals: usize,
    pub(crate) num_user_advices: Vec<usize>,
    pub(crate) num_user_challenges: Vec<usize>,
    pub(crate) advice_indices: Vec<usize>,
    pub(crate) challenge_indices: Vec<usize>,
    pub(crate) rotation_last: i32,
}

impl ConstraintSystemMeta {
    /// Derive metadata from a midnight-proofs `ConstraintSystem`.
    ///
    /// `nb_committed_instances` is the number of instance columns that the
    /// verifier *reads* from the proof transcript (vs. computes locally
    /// via Lagrange interpolation). For the poseidon example this is 0;
    /// for IVC-style fixtures with committed inputs it would be > 0.
    pub(crate) fn new(cs: &ConstraintSystem<Fq>, nb_committed_instances: usize) -> Self {
        let cs_degree = cs.degree();
        let num_fixeds = cs.num_fixed_columns();
        let permutation_columns = cs.permutation().get_columns();
        let permutation_chunk_len = cs_degree - 2;

        let num_permutation_zs = if permutation_columns.is_empty() {
            0
        } else {
            permutation_columns.len().div_ceil(permutation_chunk_len)
        };

        // For each batched lookup, midnight-proofs commits to one
        // multiplicity polynomial, `num_chunks` helper polynomials
        // (degree-bounded chunking of the parallel-lookups), and one
        // accumulator polynomial. See `midnight_proofs::plonk::logup`.
        let lookup_chunks: Vec<usize> = cs
            .lookups()
            .iter()
            .map(|l| l.chunk_by_degree(cs_degree).num_chunks())
            .collect();
        let num_lookups = cs.lookups().len();

        let num_trashcans = cs.trashcans().len();

        // The quotient polynomial has degree `(d - 1) * (n - 1)` for a
        // CS of degree `d`. Without the `single-h-commitment` feature we
        // commit one limb per `(d - 1)`.
        let num_quotients = cs_degree.saturating_sub(1);

        let advice_queries = cs
            .advice_queries()
            .iter()
            .map(|(column, rotation)| (column.index(), rotation.0))
            .collect_vec();
        let fixed_queries = cs
            .fixed_queries()
            .iter()
            .map(|(column, rotation)| (column.index(), rotation.0))
            .collect_vec();

        let num_simple_selectors = cs.num_simple_selectors();

        // Total number of evaluations the verifier reads from the proof
        // transcript. See `midnight_proofs::plonk::verifier::verify_algebraic_constraints`.
        //
        //   committed_instance reads:
        //     #{ (col, _) in instance_queries : col.index() < nb_committed_instances }
        //   advice reads:        advice_queries.len()
        //   fixed-non-simple:    num_fixed_columns - num_simple_selectors
        //   perm common:         permutation_columns.len()
        //   perm sets:           per set, (cur, next) + (last for all but the final set)
        //                        => 3 * num_permutation_zs - 1 if > 0, else 0
        //   lookup evals:        per lookup, m + helpers + acc + acc_next
        //                        => sum(num_chunks) + 3 * num_lookups
        //   trash evals:         num_trashcans
        let num_committed_instance_reads = cs
            .instance_queries()
            .iter()
            .filter(|(col, _)| col.index() < nb_committed_instances)
            .count();
        let perm_set_evals = if num_permutation_zs == 0 {
            0
        } else {
            3 * num_permutation_zs - 1
        };
        let lookup_helper_total: usize = lookup_chunks.iter().sum();
        let lookup_evals_total = lookup_helper_total + 3 * num_lookups;
        let num_evals = num_committed_instance_reads
            + advice_queries.len()
            + (num_fixeds - num_simple_selectors)
            + permutation_columns.len()
            + perm_set_evals
            + lookup_evals_total
            + num_trashcans;

        let num_phase = *cs.advice_column_phase().iter().max().unwrap_or(&0) as usize + 1;
        let remapping = |phase: Vec<u8>| {
            let nums = phase.iter().fold(vec![0usize; num_phase], |mut nums, p| {
                nums[*p as usize] += 1;
                nums
            });
            let offsets = nums.iter().take(num_phase - 1).fold(vec![0usize], |mut offsets, n| {
                offsets.push(offsets.last().unwrap() + n);
                offsets
            });
            let index = phase
                .iter()
                .scan(offsets, |state, p| {
                    let i = state[*p as usize];
                    state[*p as usize] += 1;
                    Some(i)
                })
                .collect::<Vec<_>>();
            (nums, index)
        };
        let (num_user_advices, advice_indices) = remapping(cs.advice_column_phase());
        let (num_user_challenges, challenge_indices) = remapping(cs.challenge_phase());

        let rotation_last = -(cs.blinding_factors() as i32 + 1);
        let num_rotations = chain![
            advice_queries.iter().map(|q| q.1),
            fixed_queries.iter().map(|q| q.1),
            (num_permutation_zs > 0).then_some([0, 1]).into_iter().flatten(),
            (num_permutation_zs > 1).then_some(rotation_last),
            (num_lookups > 0).then_some([0, 1]).into_iter().flatten(),
            (num_trashcans > 0).then_some(0),
        ]
        .unique()
        .count();

        Self {
            num_fixeds,
            permutation_columns,
            permutation_chunk_len,
            num_lookups,
            lookup_chunks,
            num_trashcans,
            num_permutation_zs,
            num_quotients,
            advice_queries,
            fixed_queries,
            num_simple_selectors,
            num_committed_instances: nb_committed_instances,
            num_evals,
            num_rotations,
            num_user_advices,
            num_user_challenges,
            advice_indices,
            challenge_indices,
            rotation_last,
        }
    }

    /// Returns the number of advice / advice-like commitments emitted in
    /// each phase of the proof byte stream. This matches the
    /// `for current_phase in vk.cs.phases() { ... }` loop in
    /// `midnight_proofs::plonk::verifier::parse_trace`, *plus* dedicated
    /// "phases" for:
    ///   - lookup multiplicities (one per lookup, after theta)
    ///   - permutation product commitments (after beta/gamma)
    ///   - lookup helpers + accumulators (after permutation products)
    ///   - trashcan commitments (after trash_challenge)
    ///   - quotient limbs (after y)
    ///
    /// We surface the per-phase counts so the Yul template can emit the
    /// matching `read_g1_compressed` loops.
    pub(crate) fn num_advices(&self) -> Vec<usize> {
        let mut out = self.num_user_advices.clone();
        // theta is squeezed *between* the user phases and the lookup
        // multiplicity phase, so the multiplicity phase is its own block.
        if self.num_lookups != 0 {
            out.push(self.num_lookups); // multiplicities
        }
        // permutation product commitments
        if self.num_permutation_zs != 0 {
            out.push(self.num_permutation_zs);
        }
        // lookup helpers + accumulators
        let lookup_h_plus_acc: usize =
            self.lookup_chunks.iter().sum::<usize>() + self.num_lookups;
        if lookup_h_plus_acc != 0 {
            out.push(lookup_h_plus_acc);
        }
        // trashcans
        if self.num_trashcans != 0 {
            out.push(self.num_trashcans);
        }
        // quotient limbs
        out.push(self.num_quotients);
        out
    }

    pub(crate) fn num_challenges(&self) -> Vec<usize> {
        // midnight-proofs squeezes the challenges in this order:
        //   user-phase challenges (any number per user phase)
        //   theta
        //   beta, gamma
        //   trash_challenge
        //   y
        //   x
        //
        // To keep the Yul template structure (alternating "read advices /
        // squeeze challenges"), we splice these into the per-phase
        // schedule. The exact splicing scheme is finalised in Step 6
        // (Yul rewrite); this metadata only records the *counts* and
        // their squeeze ordering.
        let mut counts = self.num_user_challenges.clone();

        if self.num_lookups != 0 {
            // Last user phase: append theta (squeezed before reading
            // multiplicities).
            *counts.last_mut().unwrap() += 1; // theta
            counts.push(2); // beta, gamma after multiplicities
            // After permutation_products + lookup_helpers, before trashcans.
            if self.num_trashcans != 0 {
                counts.push(1); // trash_challenge
            }
            counts.push(1); // y
            counts.push(1); // x
        } else {
            // No lookups: theta+beta+gamma collapse to a single squeeze
            // block (they are still squeezed individually but with no
            // intervening reads).
            *counts.last_mut().unwrap() += 3; // theta, beta, gamma
            if self.num_trashcans != 0 {
                counts.push(1); // trash_challenge
            }
            counts.push(1); // y
            counts.push(1); // x
        }

        counts
    }

    pub(crate) fn num_permutations(&self) -> usize {
        self.permutation_columns.len()
    }

    pub(crate) fn proof_len(&self, scheme: BatchOpenScheme) -> usize {
        // Each G1 commitment in the proof is 48 bytes (compressed
        // BLS12-381). Each Fq evaluation is 32 bytes. For now we still
        // declare the verifier proof layout in terms of EIP-2537
        // *uncompressed* points (4 words = 128 bytes per G1) because
        // the Solidity verifier converts compressed -> uncompressed
        // internally before doing curve arithmetic; calldata however
        // carries the *compressed* form to keep proofs small.
        //
        // This length is the calldata size (compressed). The Yul
        // verifier will read 48 bytes per point and decompress in-EVM.
        let g1_count: usize = self.num_advices().iter().sum::<usize>()
            + self.batch_open_g1_count(scheme);
        g1_count * 0x30 + self.num_evals * 0x20 + self.batch_open_extra_evals(scheme) * 0x20
    }

    pub(crate) fn batch_open_proof_len(&self, scheme: BatchOpenScheme) -> usize {
        match scheme {
            // Trailing G1 points are: f_com (1) + pi (1) = 2.
            // Plus the per-set q_evals (handled separately as scalars).
            Gwc19 => self.batch_open_g1_count(scheme) * 0x30,
        }
    }

    /// G1 commitments emitted *after* the evaluation block in the proof
    /// stream by `KZGCommitmentScheme::multi_open` (midnight-proofs):
    ///   `f_com` (the proof of the polynomial-commitment-degree
    ///   reduction) and `pi` (the final KZG opening). 2 G1 in total.
    pub(crate) fn batch_open_g1_count(&self, scheme: BatchOpenScheme) -> usize {
        match scheme {
            Gwc19 => 2,
        }
    }

    /// Extra Fq scalars in the multi-open block: one `q_eval` per
    /// distinct point set (read at `x_3`).
    pub(crate) fn batch_open_extra_evals(&self, _scheme: BatchOpenScheme) -> usize {
        // We don't know the exact number of point sets at codegen time
        // without reproducing `construct_intermediate_sets`. The Yul
        // verifier reads them in a loop bounded by "everything between
        // the last fixed eval and the trailing pi G1" -- mirrors the
        // approach in `midfall/proofs/solidity-verifier/src/trace_replay.rs`.
        0
    }
}

// ----------------------------------------------------------------------------
// Memory-layout helpers (Data, Ptr, EcPoint, Word, ...). Keep mostly as-is
// from the halo2 era; the BLS12-381 layout (4 words per G1) does not
// change. Only the type that keys `permutation_comms` flips from
// `ColumnMid` to `Column<Any>`.
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct Data {
    pub(crate) challenge_mptr: Ptr,
    pub(crate) theta_mptr: Ptr,

    pub(crate) quotient_comm_cptr: Ptr,
    pub(crate) w_cptr: Ptr,

    pub(crate) fixed_comms: Vec<EcPoint>,
    pub(crate) permutation_comms: HashMap<Column<Any>, EcPoint>,
    pub(crate) advice_comms: Vec<EcPoint>,
    pub(crate) permutation_z_comms: Vec<EcPoint>,
    pub(crate) lookup_m_comms: Vec<EcPoint>,
    pub(crate) lookup_helper_comms: Vec<Vec<EcPoint>>,
    pub(crate) lookup_z_comms: Vec<EcPoint>,
    pub(crate) trashcan_comms: Vec<EcPoint>,

    pub(crate) challenges: Vec<Word>,

    pub(crate) instance_eval: Word,
    pub(crate) advice_evals: HashMap<(usize, i32), Word>,
    pub(crate) fixed_evals: HashMap<(usize, i32), Word>,
    pub(crate) permutation_evals: HashMap<Column<Any>, Word>,
    pub(crate) permutation_z_evals: Vec<(Word, Word, Word)>,
    /// Per lookup: `(m, [helpers], z, z_next)` evaluations.
    pub(crate) lookup_evals: Vec<(Word, Vec<Word>, Word, Word)>,
    pub(crate) trashcan_evals: Vec<Word>,

    pub(crate) computed_quotient_comm: EcPoint,
    pub(crate) computed_quotient_eval: Word,
}

impl Data {
    pub(crate) fn new(
        meta: &ConstraintSystemMeta,
        vk: &Halo2VerifyingKey,
        vk_mptr: Ptr,
        proof_cptr: Ptr,
    ) -> Self {
        // BLS12-381 G1 commitments occupy 4 words (EIP-2537 padded), so the
        // stride between consecutive points is 4 instead of the BN254-era 2.
        let fixed_comm_mptr = vk_mptr + vk.constants.len();
        let permutation_comm_mptr = fixed_comm_mptr + 4 * vk.fixed_comms.len();
        let challenge_mptr = permutation_comm_mptr + 4 * vk.permutation_comms.len();
        let theta_mptr = challenge_mptr + meta.challenge_indices.len();

        // ------------------------------------------------------------
        // The calldata layout below is *placeholder* and only used to
        // make the codegen tree compile during Steps 1-3. The real
        // midnight-proofs layout is finalised in Step 6 of
        // MIGRATION.md. In particular, lookup helpers/accumulators,
        // trashcans, and the new PCS commitments are not yet placed
        // into this map.
        // ------------------------------------------------------------
        let advice_comm_start = proof_cptr;
        let lookup_m_comm_start = advice_comm_start + 4 * meta.advice_indices.len();
        let permutation_z_comm_start = lookup_m_comm_start + 4 * meta.num_lookups;
        let lookup_helper_total: usize = meta.lookup_chunks.iter().sum();
        let lookup_helper_comm_start =
            permutation_z_comm_start + 4 * meta.num_permutation_zs;
        let lookup_z_comm_start = lookup_helper_comm_start + 4 * lookup_helper_total;
        let trashcan_comm_start = lookup_z_comm_start + 4 * meta.num_lookups;
        let quotient_comm_start = trashcan_comm_start + 4 * meta.num_trashcans;

        let eval_cptr = quotient_comm_start + 4 * meta.num_quotients;
        let w_cptr = eval_cptr + meta.num_evals;

        let fixed_comms = EcPoint::range(fixed_comm_mptr).take(meta.num_fixeds).collect();
        let permutation_comms = izip!(
            meta.permutation_columns.iter().cloned(),
            EcPoint::range(permutation_comm_mptr)
        )
        .collect();
        let advice_comms = meta
            .advice_indices
            .iter()
            .map(|idx| advice_comm_start + 4 * idx)
            .map_into()
            .collect();
        let lookup_m_comms = EcPoint::range(lookup_m_comm_start)
            .take(meta.num_lookups)
            .collect();
        let permutation_z_comms = EcPoint::range(permutation_z_comm_start)
            .take(meta.num_permutation_zs)
            .collect();

        // Group helpers per lookup by lookup_chunks[i].
        let mut lookup_helper_comms: Vec<Vec<EcPoint>> = Vec::with_capacity(meta.num_lookups);
        let mut helper_cursor = lookup_helper_comm_start;
        for &chunks in &meta.lookup_chunks {
            let row: Vec<EcPoint> = EcPoint::range(helper_cursor).take(chunks).collect();
            helper_cursor = helper_cursor + 4 * chunks;
            lookup_helper_comms.push(row);
        }
        let lookup_z_comms = EcPoint::range(lookup_z_comm_start)
            .take(meta.num_lookups)
            .collect();
        let trashcan_comms = EcPoint::range(trashcan_comm_start)
            .take(meta.num_trashcans)
            .collect();
        let computed_quotient_comm = EcPoint::new(Ptr::memory("QUOTIENT_MPTR"));

        let challenges = meta
            .challenge_indices
            .iter()
            .map(|idx| challenge_mptr + *idx)
            .map_into()
            .collect_vec();
        let instance_eval = Ptr::memory("INSTANCE_EVAL_MPTR").into();

        // For Steps 1-3 we just place evals contiguously at eval_cptr,
        // skipping the committed-instance reads (we don't yet support
        // committed instances on the codegen side). The exact mapping
        // is finalised in Step 6.
        let mut eval_walk = eval_cptr + meta.num_committed_instances;
        let advice_evals = izip!(
            meta.advice_queries.iter().cloned(),
            Word::range(eval_walk)
        )
        .take(meta.advice_queries.len())
        .collect::<HashMap<_, _>>();
        eval_walk = eval_walk + meta.advice_queries.len();

        // fixed-non-simple evals
        let mut fixed_evals: HashMap<(usize, i32), Word> = HashMap::new();
        let mut fixed_walk = eval_walk;
        for query in &meta.fixed_queries {
            // We only emit a slot for non-simple-selector columns; for
            // simple selectors the evaluator must use Fq::ONE in place.
            // (See `midnight_proofs::plonk::verifier::verify_algebraic_constraints`
            // which inserts F::ONE into fixed_evals at simple-selector
            // indices after reading the rest from the transcript.)
            // For Steps 1-3 we don't enforce this filter; later steps
            // will adjust.
            fixed_evals.insert(*query, fixed_walk.into());
            fixed_walk = fixed_walk + 1;
        }
        eval_walk = fixed_walk;

        let permutation_evals = izip!(
            meta.permutation_columns.iter().cloned(),
            Word::range(eval_walk)
        )
        .collect::<HashMap<_, _>>();
        eval_walk = eval_walk + meta.permutation_columns.len();

        let perm_set_count = if meta.num_permutation_zs == 0 {
            0
        } else {
            3 * meta.num_permutation_zs - 1
        };
        let permutation_z_evals = Word::range(eval_walk)
            .take(perm_set_count)
            .collect::<Vec<_>>()
            .chunks(3)
            .map(|chunk| match chunk {
                [a, b, c] => (*a, *b, *c),
                [a, b] => (*a, *b, *a), // last set has no last_eval
                _ => unreachable!(),
            })
            .collect_vec();
        eval_walk = eval_walk + perm_set_count;

        // lookup evals: per lookup, m + helpers + acc + acc_next
        let mut lookup_evals: Vec<(Word, Vec<Word>, Word, Word)> =
            Vec::with_capacity(meta.num_lookups);
        for &chunks in &meta.lookup_chunks {
            let m = eval_walk.into();
            eval_walk = eval_walk + 1;
            let helpers: Vec<Word> = Word::range(eval_walk).take(chunks).collect();
            eval_walk = eval_walk + chunks;
            let z = eval_walk.into();
            eval_walk = eval_walk + 1;
            let z_next = eval_walk.into();
            eval_walk = eval_walk + 1;
            lookup_evals.push((m, helpers, z, z_next));
        }

        let trashcan_evals: Vec<Word> = Word::range(eval_walk).take(meta.num_trashcans).collect();

        let computed_quotient_eval = Ptr::memory("QUOTIENT_EVAL_MPTR").into();

        Self {
            challenge_mptr,
            theta_mptr,
            quotient_comm_cptr: quotient_comm_start,
            w_cptr,
            fixed_comms,
            permutation_comms,
            advice_comms,
            permutation_z_comms,
            lookup_m_comms,
            lookup_helper_comms,
            lookup_z_comms,
            trashcan_comms,
            computed_quotient_comm,
            challenges,
            instance_eval,
            advice_evals,
            fixed_evals,
            permutation_evals,
            permutation_z_evals,
            lookup_evals,
            trashcan_evals,
            computed_quotient_eval,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Location {
    Calldata,
    Memory,
}

impl Location {
    fn opcode(&self) -> &'static str {
        match self {
            Location::Calldata => "calldataload",
            Location::Memory => "mload",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    /// Byte offset stored as signed so that the BLS code-gen can compute
    /// `ptr - N` even when `N` exceeds the original offset (the result
    /// only ever appears as `ptr_end` in `lt(ptr_end, ptr)` style loops
    /// where any value strictly less than the smallest visited address is
    /// acceptable).
    Integer(isize),
    /// A symbolic Yul identifier `name`, with an optional byte-offset that
    /// will be rendered as `add(name, 0xNN)` (or just `name` when zero).
    Identifier(&'static str, isize),
}

impl Value {
    pub(crate) fn is_integer(&self) -> bool {
        matches!(self, Value::Integer(_))
    }

    pub(crate) fn as_usize(&self) -> usize {
        match self {
            Value::Integer(int) => *int as usize,
            Value::Identifier(..) => unreachable!(),
        }
    }
}

impl Default for Value {
    fn default() -> Self {
        Self::Integer(0)
    }
}

impl From<&'static str> for Value {
    fn from(ident: &'static str) -> Self {
        Value::Identifier(ident, 0)
    }
}

impl From<usize> for Value {
    fn from(int: usize) -> Self {
        Value::Integer(int as isize)
    }
}

fn fmt_hex(off: isize) -> String {
    let hex = format!("{:x}", off as usize);
    if hex.len() % 2 == 1 {
        format!("0x0{hex}")
    } else {
        format!("0x{hex}")
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Value::Integer(int) if *int >= 0 => write!(f, "{}", fmt_hex(*int)),
            Value::Integer(int) => write!(f, "sub(0, {})", fmt_hex(-*int)),
            Value::Identifier(ident, 0) => write!(f, "{ident}"),
            Value::Identifier(ident, off) if *off > 0 => {
                write!(f, "add({ident}, {})", fmt_hex(*off))
            }
            Value::Identifier(ident, off) => {
                write!(f, "sub({ident}, {})", fmt_hex(-*off))
            }
        }
    }
}

impl Add<usize> for Value {
    type Output = Value;
    fn add(self, rhs: usize) -> Self::Output {
        match self {
            Value::Integer(int) => Value::Integer(int + (rhs as isize) * 0x20),
            Value::Identifier(name, off) => {
                Value::Identifier(name, off + (rhs as isize) * 0x20)
            }
        }
    }
}

impl Sub<usize> for Value {
    type Output = Value;
    fn sub(self, rhs: usize) -> Self::Output {
        match self {
            Value::Integer(int) => Value::Integer(int - (rhs as isize) * 0x20),
            Value::Identifier(name, off) => {
                Value::Identifier(name, off - (rhs as isize) * 0x20)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ptr {
    loc: Location,
    value: Value,
}

impl Ptr {
    pub(crate) fn new(loc: Location, value: impl Into<Value>) -> Self {
        Self {
            loc,
            value: value.into(),
        }
    }

    pub(crate) fn memory(value: impl Into<Value>) -> Self {
        Self::new(Location::Memory, value.into())
    }

    pub(crate) fn calldata(value: impl Into<Value>) -> Self {
        Self::new(Location::Calldata, value.into())
    }

    pub(crate) fn loc(&self) -> Location {
        self.loc
    }

    pub(crate) fn value(&self) -> Value {
        self.value
    }
}

impl Display for Ptr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl Add<usize> for Ptr {
    type Output = Ptr;
    fn add(mut self, rhs: usize) -> Self::Output {
        self.value = self.value + rhs;
        self
    }
}

impl Sub<usize> for Ptr {
    type Output = Ptr;
    fn sub(mut self, rhs: usize) -> Self::Output {
        self.value = self.value - rhs;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Word(Ptr);

impl Word {
    pub(crate) fn range(word: impl Into<Word>) -> impl Iterator<Item = Word> {
        let ptr = word.into().ptr();
        (0..).map(move |idx| ptr + idx).map_into()
    }

    pub(crate) fn ptr(&self) -> Ptr {
        self.0
    }

    pub(crate) fn loc(&self) -> Location {
        self.0.loc()
    }
}

impl Display for Word {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.0.loc.opcode(), self.0.value)
    }
}

impl From<Ptr> for Word {
    fn from(ptr: Ptr) -> Self {
        Self(ptr)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EcPoint {
    base: Ptr,
}

impl EcPoint {
    pub(crate) fn new(base: impl Into<Ptr>) -> Self {
        Self { base: base.into() }
    }

    pub(crate) fn range(base: impl Into<EcPoint>) -> impl Iterator<Item = EcPoint> {
        let base = base.into().base;
        (0..).map(move |idx| EcPoint::new(base + 4 * idx))
    }

    pub(crate) fn loc(&self) -> Location {
        self.base.loc()
    }

    pub(crate) fn ptr(&self) -> Ptr {
        self.base
    }

    pub(crate) fn x_hi(&self) -> Word {
        Word::from(self.base)
    }
    pub(crate) fn x_lo(&self) -> Word {
        Word::from(self.base + 1)
    }
    pub(crate) fn y_hi(&self) -> Word {
        Word::from(self.base + 2)
    }
    pub(crate) fn y_lo(&self) -> Word {
        Word::from(self.base + 3)
    }

    pub(crate) fn words(&self) -> [Word; 4] {
        [self.x_hi(), self.x_lo(), self.y_hi(), self.y_lo()]
    }
}

impl From<Ptr> for EcPoint {
    fn from(ptr: Ptr) -> Self {
        Self::new(ptr)
    }
}

pub(crate) fn copy_g1_point(dst_base: Ptr, src: &EcPoint) -> [String; 4] {
    let [x_hi, x_lo, y_hi, y_lo] = src.words();
    [
        format!("mstore({}, {x_hi})", dst_base),
        format!("mstore({}, {x_lo})", dst_base + 1),
        format!("mstore({}, {y_hi})", dst_base + 2),
        format!("mstore({}, {y_lo})", dst_base + 3),
    ]
}

pub(crate) fn indent<const N: usize>(
    lines: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| format!("{}{}", " ".repeat(N * 4), line.into()))
        .collect()
}

pub(crate) fn code_block<const N: usize, const PACKED: bool>(
    lines: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    let lines = lines.into_iter().map_into().collect_vec();
    let bracket_indent = " ".repeat((N - 1) * 4);
    match lines.len() {
        0 => vec![format!("{bracket_indent}{{}}")],
        1 if PACKED => vec![format!("{bracket_indent}{{ {} }}", lines[0])],
        _ => chain![
            [format!("{bracket_indent}{{")],
            indent::<N>(lines),
            [format!("{bracket_indent}}}")],
        ]
        .collect(),
    }
}

pub(crate) fn for_loop(
    initialization: impl IntoIterator<Item = impl Into<String>>,
    condition: impl Into<String>,
    advancement: impl IntoIterator<Item = impl Into<String>>,
    body: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    chain![
        ["for".to_string()],
        code_block::<2, true>(initialization),
        indent::<1>([condition.into()]),
        code_block::<2, true>(advancement),
        code_block::<1, false>(body),
    ]
    .collect()
}

pub(crate) fn group_backward_adjacent_words<'a>(
    words: impl IntoIterator<Item = &'a Word>,
) -> Vec<(Location, Vec<&'a Word>)> {
    words.into_iter().fold(Vec::new(), |mut word_groups, word| {
        if let Some(last_group) = word_groups.last_mut() {
            let last_word = **last_group.1.last().unwrap();
            if last_group.0 == word.loc()
                && last_word.ptr().value().is_integer()
                && last_word.ptr() - 1 == word.ptr()
            {
                last_group.1.push(word)
            } else {
                word_groups.push((word.loc(), vec![word]))
            }
            word_groups
        } else {
            vec![(word.loc(), vec![word])]
        }
    })
}

pub(crate) fn group_backward_adjacent_ec_points<'a>(
    ec_point: impl IntoIterator<Item = &'a EcPoint>,
) -> Vec<(Location, Vec<&'a EcPoint>)> {
    ec_point.into_iter().fold(Vec::new(), |mut ec_point_groups, ec_point| {
        if let Some(last_group) = ec_point_groups.last_mut() {
            let last_ec_point = **last_group.1.last().unwrap();
            if last_group.0 == ec_point.loc()
                && last_ec_point.ptr().value().is_integer()
                && last_ec_point.ptr() - 4 == ec_point.ptr()
            {
                last_group.1.push(ec_point)
            } else {
                ec_point_groups.push((ec_point.loc(), vec![ec_point]))
            }
            ec_point_groups
        } else {
            vec![(ec_point.loc(), vec![ec_point])]
        }
    })
}

// ----------------------------------------------------------------------------
// BLS12-381 EIP-2537 encoding helpers (post-migration: types come from
// `midnight_curves` instead of `halo2curves::bls12381`). The shape of the
// encoded U256 array is unchanged.
// ----------------------------------------------------------------------------

fn fp48_be_to_hi_lo(be: &[u8]) -> (U256, U256) {
    debug_assert_eq!(be.len(), 48);
    let mut hi_bytes = [0u8; 32];
    hi_bytes[16..].copy_from_slice(&be[..16]);
    let mut lo_bytes = [0u8; 32];
    lo_bytes.copy_from_slice(&be[16..]);
    (U256::from_be_bytes(hi_bytes), U256::from_be_bytes(lo_bytes))
}

/// Encode a midnight-curves G1 point in EIP-2537 padded form (4 u256 words).
///
/// `Fp::to_repr()` returns *little-endian* 48 bytes (FpRepr). We reverse to
/// big-endian and split (hi=top 16 bytes padded into u256, lo=bottom 32
/// bytes).
pub(crate) fn g1_to_u256s(ec_point: impl Borrow<G1Affine>) -> [U256; 4] {
    let coords: Coordinates<G1Affine> =
        Option::from(ec_point.borrow().coordinates()).expect("g1 identity not supported in VK");
    let mut x_be = [0u8; 48];
    x_be.copy_from_slice(coords.x().to_repr().as_ref());
    x_be.reverse();
    let mut y_be = [0u8; 48];
    y_be.copy_from_slice(coords.y().to_repr().as_ref());
    y_be.reverse();
    let (x_hi, x_lo) = fp48_be_to_hi_lo(&x_be);
    let (y_hi, y_lo) = fp48_be_to_hi_lo(&y_be);
    [x_hi, x_lo, y_hi, y_lo]
}

/// Encode a midnight-curves G2 point in EIP-2537 padded form (8 u256 words).
///
/// G2 coordinates are `Fp2` with c0/c1 components, each a 48-byte
/// little-endian Fp. EIP-2537 expects (c0, c1) for both x and y, packed
/// in big-endian per coord. The midnight-curves convention matches:
/// each `Fp` coordinate read via `to_repr()` returns LE bytes.
pub(crate) fn g2_to_u256s(ec_point: impl Borrow<G2Affine>) -> [U256; 8] {
    let coords: Coordinates<G2Affine> =
        Option::from(ec_point.borrow().coordinates()).expect("g2 identity not supported in VK");

    let pack_fp = |fp: midnight_curves::Fp| -> [u8; 48] {
        let mut be = [0u8; 48];
        be.copy_from_slice(fp.to_repr().as_ref());
        be.reverse();
        be
    };

    let x = coords.x();
    let y = coords.y();

    let x0 = pack_fp(x.c0());
    let x1 = pack_fp(x.c1());
    let y0 = pack_fp(y.c0());
    let y1 = pack_fp(y.c1());

    let (x0_hi, x0_lo) = fp48_be_to_hi_lo(&x0);
    let (x1_hi, x1_lo) = fp48_be_to_hi_lo(&x1);
    let (y0_hi, y0_lo) = fp48_be_to_hi_lo(&y0);
    let (y1_hi, y1_lo) = fp48_be_to_hi_lo(&y1);
    [x0_hi, x0_lo, x1_hi, x1_lo, y0_hi, y0_lo, y1_hi, y1_lo]
}

pub(crate) fn fe_to_u256<F>(fe: impl Borrow<F>) -> U256
where
    F: PrimeField,
    F::Repr: AsRef<[u8]>,
{
    let repr = fe.borrow().to_repr();
    let bytes = repr.as_ref();
    debug_assert_eq!(bytes.len(), 32, "fe_to_u256 expects 32-byte repr");
    let mut le = [0u8; 32];
    le.copy_from_slice(bytes);
    U256::from_le_bytes(le)
}

pub(crate) fn to_u256_be_bytes<T>(value: T) -> [u8; 32]
where
    U256: UintTryFrom<T>,
{
    U256::from(value).to_be_bytes()
}
