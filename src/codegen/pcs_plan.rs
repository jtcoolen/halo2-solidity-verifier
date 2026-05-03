//! Typed wrapper around the existing PCS query/intermediate-set planner.
//!
//! This is intentionally a planning facade, not a new emitter. The current Yul
//! generation remains in `pcs.rs`, while callers can validate term counts and
//! memory requirements against one typed summary.

use crate::codegen::{
    memory::{FinalMsmShape, PcsMemoryRequirements},
    pcs::{self, IntermediateSets, QEvalStrategy, Query},
    util::{ConstraintSystemMeta, Data},
};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct PcsPlan {
    pub(crate) raw_query_count: usize,
    pub(crate) query_count: usize,
    pub(crate) dummy_query_count: usize,
    pub(crate) point_set_count: usize,
    pub(crate) point_sets: Vec<PcsPointSetPlan>,
    pub(crate) distinct_rotations: Vec<i32>,
    pub(crate) commitment_count: usize,
    pub(crate) q_com_trace_msm: FinalMsmShape,
    pub(crate) final_msm: FinalMsmShape,
    pub(crate) memory: PcsMemoryRequirements,
    sets: IntermediateSets,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PcsQEvalStrategy {
    Rolled,
    Unrolled,
}

impl PcsQEvalStrategy {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Rolled => "rolled",
            Self::Unrolled => "unrolled",
        }
    }
}

impl From<QEvalStrategy> for PcsQEvalStrategy {
    fn from(strategy: QEvalStrategy) -> Self {
        match strategy {
            QEvalStrategy::Rolled => Self::Rolled,
            QEvalStrategy::Unrolled => Self::Unrolled,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PcsPointSetPlan {
    pub(crate) index: usize,
    pub(crate) rotations: Vec<i32>,
    pub(crate) commitment_count: usize,
    pub(crate) q_eval_strategy: PcsQEvalStrategy,
    pub(crate) q_eval_words: usize,
    pub(crate) q_eval_source_table_words: usize,
}

impl PcsPlan {
    pub(crate) fn new(meta: &ConstraintSystemMeta, data: &Data) -> Self {
        let queries = pcs::queries(meta, data);
        let sets = pcs::intermediate_sets(meta, data);
        Self::from_parts(meta, data, &queries, &sets)
    }

    fn from_parts(
        meta: &ConstraintSystemMeta,
        data: &Data,
        queries: &[Query],
        sets: &IntermediateSets,
    ) -> Self {
        let memory = pcs::memory_requirements_from_intermediate_sets(meta, data, sets);
        let dummy_query_count = data.dummy_eval_words.len();
        let by_set = pcs::commitments_by_set(sets, sets.point_sets.len());
        let point_sets = sets
            .point_sets
            .iter()
            .zip(by_set.iter())
            .enumerate()
            .map(|(index, (rotations, commitments))| {
                let q_eval_strategy = PcsQEvalStrategy::from(pcs::q_eval_strategy(commitments));
                let q_eval_source_table_words = match q_eval_strategy {
                    PcsQEvalStrategy::Rolled => commitments.len() * rotations.len(),
                    PcsQEvalStrategy::Unrolled => 0,
                };
                PcsPointSetPlan {
                    index,
                    rotations: rotations.clone(),
                    commitment_count: commitments.len(),
                    q_eval_strategy,
                    q_eval_words: rotations.len(),
                    q_eval_source_table_words,
                }
            })
            .collect::<Vec<_>>();
        let mut distinct_rotations = sets
            .point_sets
            .iter()
            .flat_map(|rotations| rotations.iter().copied())
            .collect::<Vec<_>>();
        distinct_rotations.sort_unstable();
        distinct_rotations.dedup();

        Self {
            raw_query_count: queries.len(),
            query_count: queries.len() + dummy_query_count,
            dummy_query_count,
            point_set_count: sets.point_sets.len(),
            point_sets,
            distinct_rotations,
            commitment_count: sets.commitments.len(),
            q_com_trace_msm: memory.q_com_trace_msm,
            final_msm: memory.final_msm,
            memory,
            sets: sets.clone(),
        }
    }

    pub(crate) fn intermediate_sets(&self) -> &IntermediateSets {
        &self.sets
    }

    pub(crate) fn validate_against_memory(
        &self,
        memory: &PcsMemoryRequirements,
    ) -> Result<(), String> {
        if self.memory != *memory {
            return Err(format!(
                "PCS memory requirements mismatch: plan={:?} memory={memory:?}",
                self.memory
            ));
        }
        if self.final_msm.terms == 0 && self.query_count != 0 {
            return Err("PCS final MSM has no terms for a non-empty query plan".to_string());
        }
        if self.raw_query_count + self.dummy_query_count != self.query_count {
            return Err(format!(
                "PCS query count mismatch: raw={} dummy={} total={}",
                self.raw_query_count, self.dummy_query_count, self.query_count
            ));
        }
        if self.point_set_count != self.point_sets.len() {
            return Err(format!(
                "PCS point-set count mismatch: count={} sets={}",
                self.point_set_count,
                self.point_sets.len()
            ));
        }
        let commitment_count = self
            .point_sets
            .iter()
            .map(|set| set.commitment_count)
            .sum::<usize>();
        if commitment_count != self.commitment_count {
            return Err(format!(
                "PCS commitment count mismatch: grouped={commitment_count} total={}",
                self.commitment_count
            ));
        }
        let q_eval_words = self
            .point_sets
            .iter()
            .map(|set| set.q_eval_words)
            .sum::<usize>();
        if q_eval_words != memory.q_eval_set_words {
            return Err(format!(
                "PCS q_eval word count mismatch: plan={q_eval_words} memory={}",
                memory.q_eval_set_words
            ));
        }
        let x1_powers_words = self
            .point_sets
            .iter()
            .map(|set| set.commitment_count)
            .max()
            .unwrap_or(0);
        if x1_powers_words != memory.x1_powers_words {
            return Err(format!(
                "PCS x1 powers mismatch: plan={x1_powers_words} memory={}",
                memory.x1_powers_words
            ));
        }
        if self.distinct_rotations.len() != memory.rot_points_words {
            return Err(format!(
                "PCS rotation point mismatch: plan={} memory={}",
                self.distinct_rotations.len(),
                memory.rot_points_words
            ));
        }
        let q_eval_source_table_words = self
            .point_sets
            .iter()
            .map(|set| set.q_eval_source_table_words)
            .max()
            .unwrap_or(0);
        if q_eval_source_table_words != memory.q_eval_source_table_words {
            return Err(format!(
                "PCS q_eval source table mismatch: plan={q_eval_source_table_words} memory={}",
                memory.q_eval_source_table_words
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcs_plan_validates_against_its_memory_summary() {
        let memory_requirements = PcsMemoryRequirements {
            rot_points_words: 3,
            x1_powers_words: 2,
            q_eval_set_words: 5,
            q_eval_source_table_words: 6,
            final_msm: FinalMsmShape::from_terms(4),
            ..PcsMemoryRequirements::default()
        };
        let plan = PcsPlan {
            raw_query_count: 4,
            query_count: 4,
            dummy_query_count: 0,
            point_set_count: 2,
            point_sets: vec![
                PcsPointSetPlan {
                    index: 0,
                    rotations: vec![0, 1],
                    commitment_count: 1,
                    q_eval_strategy: PcsQEvalStrategy::Unrolled,
                    q_eval_words: 2,
                    q_eval_source_table_words: 0,
                },
                PcsPointSetPlan {
                    index: 1,
                    rotations: vec![-1, 0, 1],
                    commitment_count: 2,
                    q_eval_strategy: PcsQEvalStrategy::Rolled,
                    q_eval_words: 3,
                    q_eval_source_table_words: 6,
                },
            ],
            distinct_rotations: vec![-1, 0, 1],
            commitment_count: 3,
            q_com_trace_msm: memory_requirements.q_com_trace_msm,
            final_msm: memory_requirements.final_msm,
            memory: memory_requirements,
            sets: IntermediateSets {
                commitments: Vec::new(),
                point_sets: vec![vec![0, 1], vec![-1, 0, 1]],
            },
        };

        assert_eq!(plan.final_msm, memory_requirements.final_msm);
        assert_eq!(plan.q_com_trace_msm, memory_requirements.q_com_trace_msm);
        assert!(plan.validate_against_memory(&memory_requirements).is_ok());
    }
}
