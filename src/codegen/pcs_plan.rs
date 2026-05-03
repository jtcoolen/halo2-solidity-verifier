//! Typed wrapper around the existing PCS query/intermediate-set planner.
//!
//! This is intentionally a planning facade, not a new emitter. The current Yul
//! generation remains in `pcs.rs`, while callers can validate term counts and
//! memory requirements against one typed summary.

use crate::codegen::{
    memory::{FinalMsmShape, PcsMemoryRequirements},
    pcs::{self, IntermediateSets, Query},
    util::{ConstraintSystemMeta, Data},
};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct PcsPlan {
    pub(crate) query_count: usize,
    pub(crate) point_set_count: usize,
    pub(crate) commitment_count: usize,
    pub(crate) q_com_trace_msm: FinalMsmShape,
    pub(crate) final_msm: FinalMsmShape,
    pub(crate) memory: PcsMemoryRequirements,
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
        let memory = pcs::memory_requirements(meta, data);
        Self {
            query_count: queries.len(),
            point_set_count: sets.point_sets.len(),
            commitment_count: sets.commitments.len(),
            q_com_trace_msm: memory.q_com_trace_msm,
            final_msm: memory.final_msm,
            memory,
        }
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcs_plan_validates_against_its_memory_summary() {
        let memory_requirements = PcsMemoryRequirements {
            rot_points_words: 2,
            x1_powers_words: 3,
            q_eval_set_words: 5,
            final_msm: FinalMsmShape::from_terms(4),
            ..PcsMemoryRequirements::default()
        };
        let plan = PcsPlan {
            query_count: 4,
            point_set_count: 2,
            commitment_count: 3,
            q_com_trace_msm: memory_requirements.q_com_trace_msm,
            final_msm: memory_requirements.final_msm,
            memory: memory_requirements,
        };

        assert_eq!(plan.final_msm, memory_requirements.final_msm);
        assert_eq!(plan.q_com_trace_msm, memory_requirements.q_com_trace_msm);
        assert!(plan.validate_against_memory(&memory_requirements).is_ok());
    }
}
