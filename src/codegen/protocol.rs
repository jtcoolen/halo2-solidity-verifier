//! Typed verifier protocol plan.
//!
//! This module is deliberately small and local. It ports the useful shape of
//! `snark-verifier`'s protocol/query planning into this generator without
//! adopting its loader or unrolled EVM output. The Askama/Yul emitters still
//! decide how to render the verifier, but they consume one validated source of
//! truth for proof reads, quotient topology, common polynomial needs, and PCS
//! query order.

#![allow(dead_code)]

use std::collections::BTreeSet;

use itertools::Itertools;
use midnight_curves::Fq;
use midnight_proofs::plonk::{Any, Column, ConstraintSystem, Expression};

use crate::codegen::layout::trace;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct QueryKey {
    /// Column index within its column kind.
    pub(crate) column: usize,
    /// Halo2 rotation relative to the current row.
    pub(crate) rotation: i32,
}

impl QueryKey {
    /// Construct a query key from a column index and rotation.
    pub(crate) fn new(column: usize, rotation: i32) -> Self {
        Self { column, rotation }
    }

    /// Return the historical tuple representation used by `ConstraintSystemMeta`.
    pub(crate) fn tuple(self) -> (usize, i32) {
        (self.column, self.rotation)
    }
}

/// Kinds of G1 commitments read from proof calldata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitmentRead {
    // The commitment stream only needs kinds for sizing and transcript order.
    // Column/query identity lives in the eval and PCS plans below.
    Advice,
    LookupMultiplicity,
    PermutationProduct,
    LookupHelper,
    LookupAccumulator,
    Trash,
    Quotient,
}

impl CommitmentRead {
    /// Return whether this read is one of the quotient limb commitments.
    pub(crate) fn is_quotient(self) -> bool {
        matches!(self, Self::Quotient)
    }
}

/// Which evaluation of a permutation product commitment is being read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PermutationZEval {
    /// Evaluation at `x`.
    Cur,
    /// Evaluation at `omega * x`.
    Next,
    /// Evaluation at the last usable rotation.
    Last,
}

/// Scalar evaluations read from the proof's main eval block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvalRead {
    /// PCS-opened committed instance column.
    CommittedInstance(QueryKey),
    /// Advice polynomial query.
    Advice(QueryKey),
    /// Non-simple fixed polynomial query.
    Fixed(QueryKey),
    /// Common permutation sigma polynomial query.
    PermutationCommon { column: Column<Any> },
    /// Permutation product query.
    PermutationZ { set: usize, kind: PermutationZEval },
    /// LogUp multiplicity polynomial query.
    LookupMultiplicity { lookup: usize },
    /// LogUp helper polynomial query.
    LookupHelper { lookup: usize, chunk: usize },
    /// LogUp accumulator polynomial query.
    LookupAccumulator { lookup: usize, rotation: i32 },
    /// Trashcan accumulator query.
    Trash { index: usize },
}

/// Source of one KZG multi-open query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PcsQuerySource {
    Advice(QueryKey),
    CommittedInstance(QueryKey),
    PermutationZ { set: usize, kind: PermutationZEval },
    LookupMultiplicity { lookup: usize },
    LookupHelper { lookup: usize, chunk: usize },
    LookupAccumulator { lookup: usize, rotation: i32 },
    Trash { index: usize },
    Fixed(QueryKey),
    PermutationCommon { column: Column<Any> },
    Linearization,
}

impl PcsQuerySource {
    /// Return the rotation point used by this query.
    ///
    /// `rotation_last` is circuit-dependent and is needed only for the
    /// permutation product's last-row opening.
    pub(crate) fn rotation(self, rotation_last: i32) -> i32 {
        match self {
            Self::Advice(q) | Self::CommittedInstance(q) | Self::Fixed(q) => q.rotation,
            Self::PermutationZ { kind, .. } => match kind {
                PermutationZEval::Cur => 0,
                PermutationZEval::Next => 1,
                PermutationZEval::Last => rotation_last,
            },
            Self::LookupMultiplicity { .. }
            | Self::LookupHelper { .. }
            | Self::Trash { .. }
            | Self::PermutationCommon { .. }
            | Self::Linearization => 0,
            Self::LookupAccumulator { rotation, .. } => rotation,
        }
    }
}

/// Common polynomial values generated locally by the verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CommonPoly {
    /// Rotation point `omega^rotation * x`.
    Rotation(i32),
    /// First-row Lagrange basis evaluation.
    L0,
    /// Last-row Lagrange basis evaluation.
    LLast,
    /// Blinding-row Lagrange basis evaluation.
    LBlind,
}

/// Ordered proof-read plan for commitments and scalar evaluations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProofReadPlan {
    /// G1 commitment reads in transcript order.
    pub(crate) commitments: Vec<CommitmentRead>,
    /// Scalar evaluation reads in proof order.
    pub(crate) evals: Vec<EvalRead>,
}

/// Counts of quotient identities by source family.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct QuotientIdentityPlan {
    /// Gate polynomial identities.
    pub(crate) gates: usize,
    /// Permutation identities.
    pub(crate) permutation: usize,
    /// Lookup identities.
    pub(crate) lookup: usize,
    /// Trashcan identities.
    pub(crate) trash: usize,
}

impl QuotientIdentityPlan {
    /// Total identity count in the global `y` fold.
    pub(crate) fn total(&self) -> usize {
        self.gates + self.permutation + self.lookup + self.trash
    }
}

pub(crate) const TRACE_QUOTIENT_IDENTITY_BASE: u64 = trace::QUOTIENT_IDENTITY_BASE;
pub(crate) const TRACE_PCS_QUERY_BASE: u64 = trace::PCS_QUERY_BASE;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UsedQueries {
    /// Fixed queries referenced by an expression.
    pub(crate) fixed: BTreeSet<QueryKey>,
    /// Advice queries referenced by an expression.
    pub(crate) advice: BTreeSet<QueryKey>,
    /// Instance queries referenced by an expression.
    pub(crate) instance: BTreeSet<QueryKey>,
    /// Challenge indices referenced by an expression.
    pub(crate) challenges: BTreeSet<usize>,
}

impl UsedQueries {
    /// Merge two expression-use summaries.
    fn merge(mut self, other: Self) -> Self {
        self.fixed.extend(other.fixed);
        self.advice.extend(other.advice);
        self.instance.extend(other.instance);
        self.challenges.extend(other.challenges);
        self
    }
}

/// Collect the polynomial/challenge queries an expression references.
///
/// This is the local analogue of snark-verifier's expression visitors: the
/// generator can validate and lower expressions without string matching the
/// emitted Yul.
pub(crate) fn used_query(expression: &Expression<Fq>) -> UsedQueries {
    expression.evaluate(
        &|_| UsedQueries::default(),
        &|_| UsedQueries::default(),
        &|query| {
            let mut used = UsedQueries::default();
            used.fixed
                .insert(QueryKey::new(query.column_index(), query.rotation().0));
            used
        },
        &|query| {
            let mut used = UsedQueries::default();
            used.advice
                .insert(QueryKey::new(query.column_index(), query.rotation().0));
            used
        },
        &|query| {
            let mut used = UsedQueries::default();
            used.instance
                .insert(QueryKey::new(query.column_index(), query.rotation().0));
            used
        },
        &|challenge| {
            let mut used = UsedQueries::default();
            used.challenges.insert(challenge.index());
            used
        },
        &|inner| inner,
        &|lhs, rhs| lhs.merge(rhs),
        &|lhs, rhs| lhs.merge(rhs),
        &|inner, _| inner,
    )
}

/// Return which locally-computed Lagrange polynomials are needed.
pub(crate) fn used_lagrange(
    uses_permutation: bool,
    uses_lookup: bool,
    uses_trash: bool,
) -> BTreeSet<CommonPoly> {
    let mut out = BTreeSet::new();
    if uses_permutation || uses_lookup {
        out.insert(CommonPoly::L0);
        out.insert(CommonPoly::LLast);
        out.insert(CommonPoly::LBlind);
    }
    if uses_trash {
        out.insert(CommonPoly::Rotation(0));
    }
    out
}

/// Complete protocol-shape plan consumed by proof layout, memory layout, and emitters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProtocolPlan {
    /// Number of fixed columns in the constraint system.
    pub(crate) num_fixeds: usize,
    /// Columns participating in the permutation argument.
    pub(crate) permutation_columns: Vec<Column<Any>>,
    /// Maximum columns per permutation product chunk.
    pub(crate) permutation_chunk_len: usize,
    /// Helper chunks per lookup argument.
    pub(crate) lookup_chunks: Vec<usize>,
    /// Number of lookup arguments.
    pub(crate) num_lookups: usize,
    /// Number of trashcan arguments.
    pub(crate) num_trashcans: usize,
    /// Number of permutation product commitments.
    pub(crate) num_permutation_zs: usize,
    /// Number of quotient limb commitments.
    pub(crate) num_quotients: usize,
    /// Advice queries in upstream verifier order.
    pub(crate) advice_queries: Vec<QueryKey>,
    /// Fixed queries in upstream verifier order.
    pub(crate) fixed_queries: Vec<QueryKey>,
    /// Instance queries in upstream verifier order.
    pub(crate) instance_queries: Vec<QueryKey>,
    /// Number of simple selector columns.
    pub(crate) num_simple_selectors: usize,
    /// Fixed-column indices that are simple selectors.
    pub(crate) simple_selector_cols: BTreeSet<usize>,
    /// Number of instance columns opened through PCS.
    pub(crate) num_committed_instances: usize,
    /// Number of distinct rotation points needed by PCS/common polys.
    pub(crate) num_rotations: usize,
    /// Advice commitment counts by user phase.
    pub(crate) num_user_advices: Vec<usize>,
    /// Challenge counts by user phase.
    pub(crate) num_user_challenges: Vec<usize>,
    /// Advice-column remapping from CS order into phase-order commitment order.
    pub(crate) advice_indices: Vec<usize>,
    /// Challenge-index remapping from CS order into phase-order memory slots.
    pub(crate) challenge_indices: Vec<usize>,
    /// Last negative row rotation used by blinding/last-row checks.
    pub(crate) rotation_last: i32,
    /// Commitment/evaluation proof-read schedule.
    pub(crate) proof: ProofReadPlan,
    /// PCS query schedule, ending with the synthetic linearization query.
    pub(crate) pcs_queries: Vec<PcsQuerySource>,
    /// Trace topic ids for quotient identities.
    pub(crate) quotient_trace_ids: Vec<u64>,
    /// Trace topic ids for PCS queries.
    pub(crate) pcs_query_trace_ids: Vec<u64>,
    /// Common polynomial values the generated verifier must materialize.
    pub(crate) common_polys: BTreeSet<CommonPoly>,
    /// Quotient identity counts by family.
    pub(crate) quotient: QuotientIdentityPlan,
}

impl ProtocolPlan {
    /// Build the generated verifier's proof-read and PCS-query plan from the
    /// Midfall constraint system.
    ///
    /// This is the codegen-time counterpart of the iterator-heavy verifier
    /// flow in `midfall/proofs/src/plonk/verifier.rs`: hash/read advice
    /// commitments by phase, read lookup/permutation/trash commitments, read
    /// quotient limb commitments, sample `x`, then read or compute the evals
    /// passed to `partially_evaluate_identities` and KZG `multi_prepare`.
    /// The plan preserves that order so the Solidity transcript and proof
    /// cursors stay byte-compatible with the Rust verifier.
    pub(crate) fn from_constraint_system(
        cs: &ConstraintSystem<Fq>,
        nb_committed_instances: usize,
    ) -> Self {
        let cs_degree = cs.degree();
        let num_fixeds = cs.num_fixed_columns();
        let permutation_columns = cs.permutation().get_columns();
        let permutation_chunk_len = cs_degree - 2;
        let num_permutation_zs = if permutation_columns.is_empty() {
            0
        } else {
            permutation_columns.len().div_ceil(permutation_chunk_len)
        };

        let lookup_chunks: Vec<usize> = cs
            .lookups()
            .iter()
            .map(|lookup| lookup.chunk_by_degree(cs_degree).num_chunks())
            .collect();
        let num_lookups = lookup_chunks.len();
        let num_trashcans = cs.trashcans().len();
        let num_quotients = if crate::OUTER_SINGLE_H_COMMITMENT_ENABLED {
            1
        } else {
            cs_degree.saturating_sub(1)
        };

        let advice_queries = cs
            .advice_queries()
            .iter()
            .map(|(column, rotation)| QueryKey::new(column.index(), rotation.0))
            .collect_vec();
        let fixed_queries = cs
            .fixed_queries()
            .iter()
            .map(|(column, rotation)| QueryKey::new(column.index(), rotation.0))
            .collect_vec();
        let instance_queries = cs
            .instance_queries()
            .iter()
            .map(|(column, rotation)| QueryKey::new(column.index(), rotation.0))
            .collect_vec();

        let num_simple_selectors = cs.num_simple_selectors();
        let simple_selector_cols: BTreeSet<usize> = (0..num_fixeds)
            .filter(|&idx| cs.has_simple_selector_col(idx))
            .collect();

        let max_advice_phase = cs.advice_column_phase().iter().copied().max().unwrap_or(0);
        let max_challenge_phase = cs.challenge_phase().iter().copied().max().unwrap_or(0);
        let num_phase = max_advice_phase.max(max_challenge_phase) as usize + 1;
        let remapping = |phase: Vec<u8>| {
            // Midnight stores advice/challenge columns in declaration order but
            // verifies them phase by phase. `nums` gives per-phase counts and
            // `index` maps original column indices into that phase-packed order.
            let nums = phase.iter().fold(vec![0usize; num_phase], |mut nums, p| {
                nums[*p as usize] += 1;
                nums
            });
            let offsets = nums
                .iter()
                .take(num_phase - 1)
                .fold(vec![0usize], |mut offsets, n| {
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
        let mut proof = ProofReadPlan::default();

        // Hash the prover's advice commitments into the transcript by phase,
        // squeezing the phase challenge before the next phase's commitments
        // are read (`parse_trace`).
        proof
            .commitments
            .extend((0..advice_indices.len()).map(|_| CommitmentRead::Advice));
        // Lookup commitments follow the Rust verifier order: one LogUp
        // multiplicity commitment per lookup, then each chunk helper and
        // accumulator commitment after permutation products are bound.
        proof
            .commitments
            .extend((0..num_lookups).map(|_| CommitmentRead::LookupMultiplicity));
        // The verifier samples beta/gamma before hashing each permutation
        // product commitment; this plan keeps only the proof cursor order,
        // while the Solidity template owns the transcript squeezes.
        proof
            .commitments
            .extend((0..num_permutation_zs).map(|_| CommitmentRead::PermutationProduct));
        for &chunks in &lookup_chunks {
            proof
                .commitments
                .extend((0..chunks).map(|_| CommitmentRead::LookupHelper));
            proof.commitments.push(CommitmentRead::LookupAccumulator);
        }
        proof
            .commitments
            .extend((0..num_trashcans).map(|_| CommitmentRead::Trash));
        // Read commitment(s) to the quotient polynomial h(X)=nu(X)/(X^n-1).
        // The outer single-H feature mirrors midnight-proofs' one-commitment
        // transcript shape; otherwise h is split into degree-bound limbs.
        proof
            .commitments
            .extend((0..num_quotients).map(|_| CommitmentRead::Quotient));

        // Committed-instance columns are opened by PCS and read as proof
        // evals. Non-committed instance columns are Lagrange-interpolated
        // locally from public inputs and therefore do not appear here.
        proof.evals.extend(
            instance_queries
                .iter()
                .copied()
                .filter(|q| q.column < nb_committed_instances)
                .map(EvalRead::CommittedInstance),
        );
        proof
            .evals
            .extend(advice_queries.iter().copied().map(EvalRead::Advice));
        // Read (num_fixed_columns - num_simple_selectors) fixed evaluations.
        // Simple selector columns are intentionally absent from the proof
        // scalar stream and are filled by the quotient/linearization path.
        proof.evals.extend(
            fixed_queries
                .iter()
                .copied()
                .filter(|q| !simple_selector_cols.contains(&q.column))
                .map(EvalRead::Fixed),
        );
        // The permutation argument opens its product commitments at x and
        // omega*x, plus omega^last*x for every set except the final one.
        proof.evals.extend(
            permutation_columns
                .iter()
                .copied()
                .map(|column| EvalRead::PermutationCommon { column }),
        );
        for set in 0..num_permutation_zs {
            proof.evals.push(EvalRead::PermutationZ {
                set,
                kind: PermutationZEval::Cur,
            });
            proof.evals.push(EvalRead::PermutationZ {
                set,
                kind: PermutationZEval::Next,
            });
            if set + 1 != num_permutation_zs {
                proof.evals.push(EvalRead::PermutationZ {
                    set,
                    kind: PermutationZEval::Last,
                });
            }
        }
        for (lookup, &chunks) in lookup_chunks.iter().enumerate() {
            proof.evals.push(EvalRead::LookupMultiplicity { lookup });
            proof
                .evals
                .extend((0..chunks).map(move |chunk| EvalRead::LookupHelper { lookup, chunk }));
            proof.evals.push(EvalRead::LookupAccumulator {
                lookup,
                rotation: 0,
            });
            proof.evals.push(EvalRead::LookupAccumulator {
                lookup,
                rotation: 1,
            });
        }
        proof
            .evals
            .extend((0..num_trashcans).map(|index| EvalRead::Trash { index }));

        // Collect the queries checked in the KZG multi-open.
        // Queries corresponding to simple, multiplicative selectors need not be checked directly;
        // `compute_linearization_commitment` reintroduces
        // those selector commitments through the custom linearization query.
        let mut pcs_queries: Vec<PcsQuerySource> = Vec::new();
        pcs_queries.extend(advice_queries.iter().copied().map(PcsQuerySource::Advice));
        pcs_queries.extend(
            instance_queries
                .iter()
                .copied()
                .filter(|q| q.column < nb_committed_instances)
                .map(PcsQuerySource::CommittedInstance),
        );
        for set in 0..num_permutation_zs {
            pcs_queries.push(PcsQuerySource::PermutationZ {
                set,
                kind: PermutationZEval::Cur,
            });
            pcs_queries.push(PcsQuerySource::PermutationZ {
                set,
                kind: PermutationZEval::Next,
            });
            if set + 1 != num_permutation_zs {
                pcs_queries.push(PcsQuerySource::PermutationZ {
                    set,
                    kind: PermutationZEval::Last,
                });
            }
        }
        for (lookup, &chunks) in lookup_chunks.iter().enumerate() {
            pcs_queries.push(PcsQuerySource::LookupMultiplicity { lookup });
            pcs_queries.extend(
                (0..chunks).map(move |chunk| PcsQuerySource::LookupHelper { lookup, chunk }),
            );
            pcs_queries.push(PcsQuerySource::LookupAccumulator {
                lookup,
                rotation: 0,
            });
            pcs_queries.push(PcsQuerySource::LookupAccumulator {
                lookup,
                rotation: 1,
            });
        }
        pcs_queries.extend((0..num_trashcans).map(|index| PcsQuerySource::Trash { index }));
        pcs_queries.extend(
            fixed_queries
                .iter()
                .copied()
                .filter(|q| !simple_selector_cols.contains(&q.column))
                .map(PcsQuerySource::Fixed),
        );
        pcs_queries.extend(
            permutation_columns
                .iter()
                .copied()
                .map(|column| PcsQuerySource::PermutationCommon { column }),
        );
        pcs_queries.push(PcsQuerySource::Linearization);

        let mut common_polys = used_lagrange(
            num_permutation_zs != 0,
            num_lookups != 0,
            num_trashcans != 0,
        );
        // `verify_algebraic_constraints` samples x after all proof
        // commitments, then every planned PCS query opens at
        // omega^rotation*x (including x itself at rotation zero).
        common_polys.extend(
            pcs_queries
                .iter()
                .copied()
                .map(|query| CommonPoly::Rotation(query.rotation(rotation_last))),
        );

        let num_rotations = common_polys
            .iter()
            .filter_map(|poly| match poly {
                CommonPoly::Rotation(rotation) => Some(*rotation),
                _ => None,
            })
            .chain(
                instance_queries
                    .iter()
                    .filter(|q| q.column < nb_committed_instances)
                    .map(|q| q.rotation),
            )
            .unique()
            .count();

        let permutation_identity_count = if num_permutation_zs == 0 {
            0
        } else {
            2 + (num_permutation_zs.saturating_sub(1)) + num_permutation_zs
        };
        let lookup_identity_count = lookup_chunks.iter().map(|chunks| chunks + 2).sum();
        let quotient = QuotientIdentityPlan {
            gates: cs.gates().iter().map(|gate| gate.polynomials().len()).sum(),
            permutation: permutation_identity_count,
            lookup: lookup_identity_count,
            trash: num_trashcans,
        };
        let quotient_trace_ids = (0..quotient.total())
            .map(|idx| TRACE_QUOTIENT_IDENTITY_BASE + idx as u64)
            .collect::<Vec<_>>();
        let pcs_query_trace_ids = (0..pcs_queries.len())
            .map(|idx| TRACE_PCS_QUERY_BASE + idx as u64)
            .collect::<Vec<_>>();

        let plan = Self {
            num_fixeds,
            permutation_columns,
            permutation_chunk_len,
            lookup_chunks,
            num_lookups,
            num_trashcans,
            num_permutation_zs,
            num_quotients,
            advice_queries,
            fixed_queries,
            instance_queries,
            num_simple_selectors,
            simple_selector_cols,
            num_committed_instances: nb_committed_instances,
            num_rotations,
            num_user_advices,
            num_user_challenges,
            advice_indices,
            challenge_indices,
            rotation_last,
            proof,
            pcs_queries,
            quotient_trace_ids,
            pcs_query_trace_ids,
            common_polys,
            quotient,
        };
        plan.validate()
            .unwrap_or_else(|err| panic!("invalid protocol plan: {err}"));
        plan
    }

    /// Number of scalar evaluations in the proof's main eval block.
    pub(crate) fn num_main_evals(&self) -> usize {
        self.proof.evals.len()
    }

    /// Number of proof commitment reads, including quotient limbs.
    pub(crate) fn num_commitments(&self) -> usize {
        self.proof.commitments.len()
    }

    /// Number of proof commitment reads before quotient limbs.
    pub(crate) fn num_non_quotient_commitments(&self) -> usize {
        self.proof
            .commitments
            .iter()
            .filter(|commitment| !commitment.is_quotient())
            .count()
    }

    /// Commitment group sizes in the exact proof/transcript order used by
    /// the generated verifier and the off-chain proof repacker.
    pub(crate) fn commitment_read_groups(&self) -> Vec<usize> {
        let mut groups = Vec::new();
        groups.extend(self.num_user_advices.iter().copied().filter(|&n| n != 0));
        if self.num_lookups != 0 {
            groups.push(self.num_lookups);
        }
        if self.num_permutation_zs != 0 {
            groups.push(self.num_permutation_zs);
        }
        for &chunks in &self.lookup_chunks {
            groups.push(chunks);
            groups.push(1);
        }
        if self.num_trashcans != 0 {
            groups.push(self.num_trashcans);
        }
        groups.push(self.num_quotients);
        debug_assert_eq!(
            groups.iter().sum::<usize>(),
            self.proof.commitments.len(),
            "protocol commitment groups must cover the proof commitment plan"
        );
        groups
    }

    /// Map a source-local lookup identity index to `(lookup_index,
    /// identity_index_within_lookup)`.
    ///
    /// LogUp emits `boundary`, one helper identity per chunk, and an
    /// accumulator identity for each lookup, so the stride is
    /// `lookup_chunks[i] + 2`, not a constant.
    pub(crate) fn lookup_identity_source(&self, identity_index: usize) -> Option<(usize, usize)> {
        let mut base = 0usize;
        for (lookup, &chunks) in self.lookup_chunks.iter().enumerate() {
            let count = chunks + 2;
            if identity_index < base + count {
                return Some((lookup, identity_index - base));
            }
            base += count;
        }
        None
    }

    /// Check cross-field invariants of the protocol plan.
    ///
    /// This catches stale assumptions when upstream `midnight-proofs` changes
    /// proof-read order, selector handling, or PCS query coverage.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.num_simple_selectors != self.simple_selector_cols.len() {
            return Err(format!(
                "simple selector count mismatch: count={} cols={}",
                self.num_simple_selectors,
                self.simple_selector_cols.len()
            ));
        }

        let quotient_count = self
            .proof
            .commitments
            .iter()
            .filter(|commitment| commitment.is_quotient())
            .count();
        if quotient_count != self.num_quotients {
            return Err(format!(
                "quotient commitment count mismatch: plan={quotient_count} meta={}",
                self.num_quotients
            ));
        }

        let grouped_commitments = self.commitment_read_groups().iter().sum::<usize>();
        if grouped_commitments != self.proof.commitments.len() {
            return Err(format!(
                "commitment group schedule mismatch: groups={grouped_commitments} commitments={}",
                self.proof.commitments.len()
            ));
        }

        let non_quotient_count = self.num_non_quotient_commitments();
        let expected_non_quotient = self.advice_indices.len()
            + self.num_lookups
            + self.num_permutation_zs
            + self.lookup_chunks.iter().sum::<usize>()
            + self.num_lookups
            + self.num_trashcans;
        if non_quotient_count != expected_non_quotient {
            return Err(format!(
                "non-quotient commitment count mismatch: plan={non_quotient_count} expected={expected_non_quotient}"
            ));
        }

        if self
            .proof
            .evals
            .iter()
            .any(|eval| matches!(eval, EvalRead::Fixed(q) if self.simple_selector_cols.contains(&q.column)))
        {
            return Err("simple selector fixed column appears in proof eval reads".to_string());
        }

        let expected_perm_z_evals = if self.num_permutation_zs == 0 {
            0
        } else {
            3 * self.num_permutation_zs - 1
        };
        let actual_perm_z_evals = self
            .proof
            .evals
            .iter()
            .filter(|eval| matches!(eval, EvalRead::PermutationZ { .. }))
            .count();
        if actual_perm_z_evals != expected_perm_z_evals {
            return Err(format!(
                "permutation z eval count mismatch: plan={actual_perm_z_evals} expected={expected_perm_z_evals}"
            ));
        }

        let expected_lookup_evals = self.lookup_chunks.iter().sum::<usize>() + 3 * self.num_lookups;
        let actual_lookup_evals = self
            .proof
            .evals
            .iter()
            .filter(|eval| {
                matches!(
                    eval,
                    EvalRead::LookupMultiplicity { .. }
                        | EvalRead::LookupHelper { .. }
                        | EvalRead::LookupAccumulator { .. }
                )
            })
            .count();
        if actual_lookup_evals != expected_lookup_evals {
            return Err(format!(
                "lookup eval count mismatch: plan={actual_lookup_evals} expected={expected_lookup_evals}"
            ));
        }

        if !matches!(self.pcs_queries.last(), Some(PcsQuerySource::Linearization)) {
            return Err("PCS query schedule must end with linearization query".to_string());
        }

        // Every proof G1 commitment absorbed into Fiat-Shamir must either be
        // opened by PCS or consumed by a generated EIP-2537 MSM/pairing path.
        // Advice commitments are the only category whose read set can be
        // wider than the opened query set for a malformed/unsupported circuit.
        // Reject those plans at codegen time rather than paying a precompile
        // validation call for every absorbed proof point.
        let opened_advice_cols = self
            .advice_queries
            .iter()
            .map(|query| query.column)
            .collect::<BTreeSet<_>>();
        for column in 0..self.advice_indices.len() {
            if !opened_advice_cols.contains(&column) {
                return Err(format!(
                    "advice commitment column {column} is absorbed but never opened by PCS"
                ));
            }
        }

        let pcs_lookup_multiplicities = self
            .pcs_queries
            .iter()
            .filter(|query| matches!(query, PcsQuerySource::LookupMultiplicity { .. }))
            .count();
        if pcs_lookup_multiplicities != self.num_lookups {
            return Err(format!(
                "lookup multiplicity PCS coverage mismatch: pcs={pcs_lookup_multiplicities} expected={}",
                self.num_lookups
            ));
        }

        let pcs_lookup_helpers = self
            .pcs_queries
            .iter()
            .filter(|query| matches!(query, PcsQuerySource::LookupHelper { .. }))
            .count();
        let expected_lookup_helpers = self.lookup_chunks.iter().sum::<usize>();
        if pcs_lookup_helpers != expected_lookup_helpers {
            return Err(format!(
                "lookup helper PCS coverage mismatch: pcs={pcs_lookup_helpers} expected={expected_lookup_helpers}"
            ));
        }

        let pcs_lookup_accumulators = self
            .pcs_queries
            .iter()
            .filter_map(|query| match query {
                PcsQuerySource::LookupAccumulator { lookup, .. } => Some(*lookup),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if pcs_lookup_accumulators.len() != self.num_lookups {
            return Err(format!(
                "lookup accumulator PCS coverage mismatch: pcs={} expected={}",
                pcs_lookup_accumulators.len(),
                self.num_lookups
            ));
        }

        let pcs_permutation_sets = self
            .pcs_queries
            .iter()
            .filter_map(|query| match query {
                PcsQuerySource::PermutationZ { set, .. } => Some(*set),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if pcs_permutation_sets.len() != self.num_permutation_zs {
            return Err(format!(
                "permutation product PCS coverage mismatch: pcs={} expected={}",
                pcs_permutation_sets.len(),
                self.num_permutation_zs
            ));
        }

        let pcs_trash = self
            .pcs_queries
            .iter()
            .filter(|query| matches!(query, PcsQuerySource::Trash { .. }))
            .count();
        if pcs_trash != self.num_trashcans {
            return Err(format!(
                "trashcan PCS coverage mismatch: pcs={pcs_trash} expected={}",
                self.num_trashcans
            ));
        }

        if self.quotient_trace_ids.len() != self.quotient.total() {
            return Err(format!(
                "quotient trace id count mismatch: ids={} identities={}",
                self.quotient_trace_ids.len(),
                self.quotient.total()
            ));
        }
        let lookup_identity_count = self
            .lookup_chunks
            .iter()
            .map(|chunks| chunks + 2)
            .sum::<usize>();
        if self.quotient.lookup != lookup_identity_count {
            return Err(format!(
                "lookup quotient identity count mismatch: plan={} expected={lookup_identity_count}",
                self.quotient.lookup
            ));
        }
        if self.pcs_query_trace_ids.len() != self.pcs_queries.len() {
            return Err(format!(
                "PCS trace id count mismatch: ids={} queries={}",
                self.pcs_query_trace_ids.len(),
                self.pcs_queries.len()
            ));
        }
        if self
            .quotient_trace_ids
            .iter()
            .any(|id| self.pcs_query_trace_ids.contains(id))
        {
            return Err("quotient and PCS trace id spaces overlap".to_string());
        }

        let pcs_without_linearization = self.pcs_queries.len().saturating_sub(1);
        let proof_query_evals = self.proof.evals.len();
        if pcs_without_linearization != proof_query_evals {
            return Err(format!(
                "PCS/proof eval query mismatch before linearization: pcs={pcs_without_linearization} evals={proof_query_evals}"
            ));
        }

        let committed_instance_reads = self.proof.evals.iter().filter_map(|eval| match eval {
            EvalRead::CommittedInstance(q) => Some(q),
            _ => None,
        });
        for q in committed_instance_reads {
            if q.column >= self.num_committed_instances {
                return Err(format!(
                    "non-committed instance column {} is read from proof",
                    q.column
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_proofs::{
        plonk::{Constraints, FirstPhase, SecondPhase},
        poly::Rotation,
    };
    use proptest::prelude::*;

    fn simple_cs() -> ConstraintSystem<Fq> {
        let mut cs = ConstraintSystem::default();
        let a0 = cs.advice_column();
        let a1 = cs.advice_column();
        let fixed = cs.fixed_column();
        let instance = cs.instance_column();
        cs.create_gate("mul with fixed and instance", |meta| {
            let a0 = meta.query_advice(a0, Rotation::cur());
            let a1_next = meta.query_advice(a1, Rotation::next());
            let fixed_prev = meta.query_fixed(fixed, Rotation::prev());
            let instance_cur = meta.query_instance(instance, Rotation::cur());
            Constraints::without_selector(vec![("basic", a0 * a1_next + fixed_prev + instance_cur)])
        });
        cs
    }

    #[test]
    fn expression_visitor_collects_queries() {
        let mut cs = ConstraintSystem::default();
        let advice = cs.advice_column();
        let fixed = cs.fixed_column();
        let instance = cs.instance_column();
        let challenge = cs.challenge_usable_after(FirstPhase);
        cs.create_gate("visitor", |meta| {
            let advice = meta.query_advice(advice, Rotation::next());
            let fixed = meta.query_fixed(fixed, Rotation::prev());
            let instance = meta.query_instance(instance, Rotation::cur());
            let challenge = meta.query_challenge(challenge);
            Constraints::without_selector(vec![("visitor", advice + fixed * instance + challenge)])
        });
        let expr = cs.gates()[0].polynomials()[0].clone();
        let used = used_query(&expr);
        assert!(used.advice.contains(&QueryKey::new(advice.index(), 1)));
        assert!(used.fixed.contains(&QueryKey::new(fixed.index(), -1)));
        assert!(used.instance.contains(&QueryKey::new(instance.index(), 0)));
        assert!(used.challenges.contains(&challenge.index()));
    }

    #[test]
    fn plan_preserves_eval_and_pcs_order_for_basic_cs() {
        let cs = simple_cs();
        let plan = ProtocolPlan::from_constraint_system(&cs, 1);

        assert_eq!(
            plan.advice_queries.iter().map(|q| q.tuple()).collect_vec(),
            vec![(0, 0), (1, 1)]
        );
        assert_eq!(
            plan.fixed_queries.iter().map(|q| q.tuple()).collect_vec(),
            vec![(0, -1)]
        );
        assert_eq!(
            plan.instance_queries
                .iter()
                .map(|q| q.tuple())
                .collect_vec(),
            vec![(0, 0)]
        );
        assert_eq!(
            &plan.proof.evals[..],
            &[
                EvalRead::CommittedInstance(QueryKey::new(0, 0)),
                EvalRead::Advice(QueryKey::new(0, 0)),
                EvalRead::Advice(QueryKey::new(1, 1)),
                EvalRead::Fixed(QueryKey::new(0, -1)),
            ]
        );
        assert_eq!(
            &plan.pcs_queries[..],
            &[
                PcsQuerySource::Advice(QueryKey::new(0, 0)),
                PcsQuerySource::Advice(QueryKey::new(1, 1)),
                PcsQuerySource::CommittedInstance(QueryKey::new(0, 0)),
                PcsQuerySource::Fixed(QueryKey::new(0, -1)),
                PcsQuerySource::Linearization,
            ]
        );
        assert_eq!(plan.num_main_evals(), 4);
        assert_eq!(plan.commitment_read_groups(), vec![2, plan.num_quotients]);
        assert_eq!(plan.quotient_trace_ids, vec![TRACE_QUOTIENT_IDENTITY_BASE]);
        assert_eq!(
            plan.pcs_query_trace_ids,
            (0..plan.pcs_queries.len())
                .map(|idx| TRACE_PCS_QUERY_BASE + idx as u64)
                .collect::<Vec<_>>()
        );
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn plan_skips_non_committed_instance_eval_reads() {
        let cs = simple_cs();
        let plan = ProtocolPlan::from_constraint_system(&cs, 0);
        assert!(!plan
            .proof
            .evals
            .iter()
            .any(|eval| matches!(eval, EvalRead::CommittedInstance(_))));
        assert!(!plan
            .pcs_queries
            .iter()
            .any(|query| matches!(query, PcsQuerySource::CommittedInstance(_))));
    }

    #[test]
    fn plan_tracks_permutation_chunking() {
        let mut cs = ConstraintSystem::default();
        let a0 = cs.advice_column();
        let a1 = cs.advice_column();
        let a2 = cs.advice_column();
        let fixed = cs.fixed_column();
        let instance = cs.instance_column();
        cs.enable_equality(a0);
        cs.enable_equality(fixed);
        cs.enable_equality(instance);
        cs.create_gate("degree three", |meta| {
            let a0 = meta.query_advice(a0, Rotation::cur());
            let a1 = meta.query_advice(a1, Rotation::cur());
            let a2 = meta.query_advice(a2, Rotation::cur());
            Constraints::without_selector(vec![("degree three", a0 * a1 * a2)])
        });

        let plan = ProtocolPlan::from_constraint_system(&cs, 0);
        assert_eq!(plan.permutation_columns.len(), 3);
        assert!(plan.num_permutation_zs >= 1);
        assert_eq!(
            plan.proof
                .evals
                .iter()
                .filter(|eval| matches!(eval, EvalRead::PermutationZ { .. }))
                .count(),
            3 * plan.num_permutation_zs - 1
        );
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn lookup_identity_source_handles_variable_chunk_counts() {
        let lookup_chunks = vec![1usize, 4, 2];
        let lookup_count = lookup_chunks.iter().map(|chunks| chunks + 2).sum();
        let plan = ProtocolPlan {
            lookup_chunks,
            quotient: QuotientIdentityPlan {
                lookup: lookup_count,
                ..QuotientIdentityPlan::default()
            },
            ..ProtocolPlan::default()
        };

        assert_eq!(plan.lookup_identity_source(0), Some((0, 0)));
        assert_eq!(plan.lookup_identity_source(2), Some((0, 2)));
        assert_eq!(plan.lookup_identity_source(3), Some((1, 0)));
        assert_eq!(plan.lookup_identity_source(8), Some((1, 5)));
        assert_eq!(plan.lookup_identity_source(9), Some((2, 0)));
        assert_eq!(plan.lookup_identity_source(12), Some((2, 3)));
        assert_eq!(plan.lookup_identity_source(13), None);
    }

    #[test]
    fn plan_allows_challenge_phase_beyond_advice_phases() {
        let mut cs = ConstraintSystem::default();
        let advice_first = cs.advice_column();
        let advice_second = cs.advice_column_in(SecondPhase);
        let challenge = cs.challenge_usable_after(SecondPhase);
        cs.create_gate("late challenge", |meta| {
            let advice_first = meta.query_advice(advice_first, Rotation::cur());
            let advice_second = meta.query_advice(advice_second, Rotation::cur());
            let challenge = meta.query_challenge(challenge);
            Constraints::without_selector(vec![(
                "late challenge",
                advice_first + advice_second + challenge,
            )])
        });

        let plan = ProtocolPlan::from_constraint_system(&cs, 0);
        assert_eq!(plan.num_user_advices[0], 1);
        assert_eq!(plan.num_user_advices[1], 1);
        assert_eq!(plan.num_user_challenges.iter().sum::<usize>(), 1);
        assert_eq!(plan.challenge_indices.len(), 1);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn quotient_commitment_count_matches_outer_single_h_feature() {
        let mut cs = ConstraintSystem::default();
        let a0 = cs.advice_column();
        let a1 = cs.advice_column();
        let a2 = cs.advice_column();
        cs.create_gate("degree three", |meta| {
            let a0 = meta.query_advice(a0, Rotation::cur());
            let a1 = meta.query_advice(a1, Rotation::cur());
            let a2 = meta.query_advice(a2, Rotation::cur());
            Constraints::without_selector(vec![("degree three", a0 * a1 * a2)])
        });

        let plan = ProtocolPlan::from_constraint_system(&cs, 0);
        let expected = if crate::OUTER_SINGLE_H_COMMITMENT_ENABLED {
            1
        } else {
            cs.degree() - 1
        };
        assert_eq!(plan.num_quotients, expected);
        assert_eq!(
            plan.proof
                .commitments
                .iter()
                .filter(|read| read.is_quotient())
                .count(),
            expected
        );
    }

    #[test]
    fn validation_rejects_simple_selector_eval_reads() {
        let mut plan = ProtocolPlan::from_constraint_system(&simple_cs(), 0);
        plan.simple_selector_cols.insert(0);
        plan.proof.evals.push(EvalRead::Fixed(QueryKey::new(0, 0)));
        let err = plan.validate().unwrap_err();
        assert!(err.contains("simple selector"));
    }

    #[test]
    fn validation_rejects_absorbed_unopened_advice_commitments() {
        let mut plan = ProtocolPlan::from_constraint_system(&simple_cs(), 0);
        plan.advice_queries.retain(|query| query.column != 1);
        plan.proof
            .evals
            .retain(|eval| !matches!(eval, EvalRead::Advice(query) if query.column == 1));
        plan.pcs_queries
            .retain(|query| !matches!(query, PcsQuerySource::Advice(query) if query.column == 1));

        let err = plan.validate().unwrap_err();
        assert!(
            err.contains("absorbed but never opened by PCS"),
            "unexpected validation error: {err}"
        );
    }

    proptest! {
        #[test]
        fn protocol_plan_invariants_hold_for_small_constraint_systems(
            n_advice in 1usize..6,
            n_fixed in 0usize..4,
            n_instance in 0usize..3,
            n_perm in 0usize..6,
            n_committed_instance in 0usize..3,
        ) {
            let mut cs = ConstraintSystem::default();
            let advice = (0..n_advice).map(|_| cs.advice_column()).collect::<Vec<_>>();
            let fixed = (0..n_fixed).map(|_| cs.fixed_column()).collect::<Vec<_>>();
            let instance = (0..n_instance).map(|_| cs.instance_column()).collect::<Vec<_>>();

            for column in advice.iter().take(n_perm.min(n_advice)) {
                cs.enable_equality(*column);
            }

            cs.create_gate("pbt protocol plan", |meta| {
                let mut expr = meta.query_advice(advice[0], Rotation::cur())
                    * meta.query_advice(advice[0], Rotation::next())
                    * meta.query_advice(advice[0], Rotation::prev());

                for (idx, column) in advice.iter().enumerate() {
                    let rotation = match idx % 3 {
                        0 => Rotation::cur(),
                        1 => Rotation::next(),
                        _ => Rotation::prev(),
                    };
                    expr = expr + meta.query_advice(*column, rotation);
                }
                for (idx, column) in fixed.iter().enumerate() {
                    let rotation = if idx % 2 == 0 { Rotation::cur() } else { Rotation::prev() };
                    expr = expr + meta.query_fixed(*column, rotation);
                }
                for (idx, column) in instance.iter().enumerate() {
                    let rotation = if idx % 2 == 0 { Rotation::cur() } else { Rotation::next() };
                    expr = expr + meta.query_instance(*column, rotation);
                }

                Constraints::without_selector(vec![("pbt", expr)])
            });

            let committed = n_committed_instance.min(n_instance);
            let plan = ProtocolPlan::from_constraint_system(&cs, committed);
            prop_assert!(plan.validate().is_ok());
            prop_assert_eq!(plan.pcs_queries.len(), plan.proof.evals.len() + 1);
            prop_assert_eq!(
                plan.commitment_read_groups().iter().sum::<usize>(),
                plan.proof.commitments.len()
            );
            prop_assert_eq!(plan.quotient_trace_ids.len(), plan.quotient.total());
            prop_assert_eq!(plan.pcs_query_trace_ids.len(), plan.pcs_queries.len());
            let simple_selector_eval = plan
                .proof
                .evals
                .iter()
                .all(|eval| !matches!(eval, EvalRead::Fixed(q) if plan.simple_selector_cols.contains(&q.column)));
            prop_assert!(simple_selector_eval);

            let committed_instance_reads_in_bounds = plan
                .proof
                .evals
                .iter()
                .filter_map(|eval| match eval {
                    EvalRead::CommittedInstance(q) => Some(q.column),
                    _ => None,
                })
                .all(|column| column < committed);
            prop_assert!(committed_instance_reads_in_bounds);
        }
    }
}
