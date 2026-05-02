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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct QueryKey {
    pub(crate) column: usize,
    pub(crate) rotation: i32,
}

impl QueryKey {
    pub(crate) fn new(column: usize, rotation: i32) -> Self {
        Self { column, rotation }
    }

    pub(crate) fn tuple(self) -> (usize, i32) {
        (self.column, self.rotation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitmentRead {
    Advice { column: usize },
    LookupMultiplicity { lookup: usize },
    PermutationProduct { set: usize },
    LookupHelper { lookup: usize, chunk: usize },
    LookupAccumulator { lookup: usize },
    Trash { index: usize },
    Quotient { limb: usize },
}

impl CommitmentRead {
    pub(crate) fn is_quotient(self) -> bool {
        matches!(self, Self::Quotient { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PermutationZEval {
    Cur,
    Next,
    Last,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvalRead {
    CommittedInstance(QueryKey),
    Advice(QueryKey),
    Fixed(QueryKey),
    PermutationCommon { column: Column<Any> },
    PermutationZ { set: usize, kind: PermutationZEval },
    LookupMultiplicity { lookup: usize },
    LookupHelper { lookup: usize, chunk: usize },
    LookupAccumulator { lookup: usize, rotation: i32 },
    Trash { index: usize },
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CommonPoly {
    Rotation(i32),
    L0,
    LLast,
    LBlind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProofReadPlan {
    pub(crate) commitments: Vec<CommitmentRead>,
    pub(crate) evals: Vec<EvalRead>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct QuotientIdentityPlan {
    pub(crate) gates: usize,
    pub(crate) permutation: usize,
    pub(crate) lookup: usize,
    pub(crate) trash: usize,
}

impl QuotientIdentityPlan {
    pub(crate) fn total(&self) -> usize {
        self.gates + self.permutation + self.lookup + self.trash
    }
}

pub(crate) const TRACE_QUOTIENT_IDENTITY_BASE: u64 = 1_000;
pub(crate) const TRACE_PCS_QUERY_BASE: u64 = 2_000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UsedQueries {
    pub(crate) fixed: BTreeSet<QueryKey>,
    pub(crate) advice: BTreeSet<QueryKey>,
    pub(crate) instance: BTreeSet<QueryKey>,
    pub(crate) challenges: BTreeSet<usize>,
}

impl UsedQueries {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProtocolPlan {
    pub(crate) num_fixeds: usize,
    pub(crate) permutation_columns: Vec<Column<Any>>,
    pub(crate) permutation_chunk_len: usize,
    pub(crate) lookup_chunks: Vec<usize>,
    pub(crate) num_lookups: usize,
    pub(crate) num_trashcans: usize,
    pub(crate) num_permutation_zs: usize,
    pub(crate) num_quotients: usize,
    pub(crate) advice_queries: Vec<QueryKey>,
    pub(crate) fixed_queries: Vec<QueryKey>,
    pub(crate) instance_queries: Vec<QueryKey>,
    pub(crate) num_simple_selectors: usize,
    pub(crate) simple_selector_cols: BTreeSet<usize>,
    pub(crate) num_committed_instances: usize,
    pub(crate) num_rotations: usize,
    pub(crate) num_user_advices: Vec<usize>,
    pub(crate) num_user_challenges: Vec<usize>,
    pub(crate) advice_indices: Vec<usize>,
    pub(crate) challenge_indices: Vec<usize>,
    pub(crate) rotation_last: i32,
    pub(crate) proof: ProofReadPlan,
    pub(crate) pcs_queries: Vec<PcsQuerySource>,
    pub(crate) quotient_trace_ids: Vec<u64>,
    pub(crate) pcs_query_trace_ids: Vec<u64>,
    pub(crate) common_polys: BTreeSet<CommonPoly>,
    pub(crate) quotient: QuotientIdentityPlan,
}

impl ProtocolPlan {
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
        let num_quotients = cs_degree.saturating_sub(1);

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

        let num_phase = *cs.advice_column_phase().iter().max().unwrap_or(&0) as usize + 1;
        let remapping = |phase: Vec<u8>| {
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

        proof.commitments.extend(
            advice_indices
                .iter()
                .copied()
                .map(|column| CommitmentRead::Advice { column }),
        );
        proof
            .commitments
            .extend((0..num_lookups).map(|lookup| CommitmentRead::LookupMultiplicity { lookup }));
        proof
            .commitments
            .extend((0..num_permutation_zs).map(|set| CommitmentRead::PermutationProduct { set }));
        for (lookup, &chunks) in lookup_chunks.iter().enumerate() {
            proof.commitments.extend(
                (0..chunks).map(move |chunk| CommitmentRead::LookupHelper { lookup, chunk }),
            );
            proof
                .commitments
                .push(CommitmentRead::LookupAccumulator { lookup });
        }
        proof
            .commitments
            .extend((0..num_trashcans).map(|index| CommitmentRead::Trash { index }));
        proof
            .commitments
            .extend((0..num_quotients).map(|limb| CommitmentRead::Quotient { limb }));

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
        proof.evals.extend(
            fixed_queries
                .iter()
                .copied()
                .filter(|q| !simple_selector_cols.contains(&q.column))
                .map(EvalRead::Fixed),
        );
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
        let lookup_identity_count = num_lookups * 3;
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

    pub(crate) fn num_main_evals(&self) -> usize {
        self.proof.evals.len()
    }

    pub(crate) fn num_commitments(&self) -> usize {
        self.proof.commitments.len()
    }

    pub(crate) fn num_non_quotient_commitments(&self) -> usize {
        self.proof
            .commitments
            .iter()
            .filter(|commitment| !commitment.is_quotient())
            .count()
    }

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
        plonk::{Constraints, FirstPhase},
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
