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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PcsRenderPlan {
    pub(crate) blocks: Vec<PcsRenderBlock>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PcsRenderBlock {
    pub(crate) kind: PcsRenderBlockKind,
    pub(crate) lines: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PcsRenderBlockKind {
    RotationPoints,
    X1Powers,
    QEvalSet {
        set: usize,
        strategy: PcsQEvalStrategy,
    },
    QComTrace,
    FEval,
    FinalMsm,
    PairingInputs,
}

impl PcsRenderBlockKind {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::RotationPoints => "rotation_points",
            Self::X1Powers => "x1_powers",
            Self::QEvalSet { .. } => "q_eval_set",
            Self::QComTrace => "q_com_trace",
            Self::FEval => "f_eval",
            Self::FinalMsm => "final_msm",
            Self::PairingInputs => "pairing_inputs",
        }
    }
}

impl PcsRenderPlan {
    pub(crate) fn from_blocks(
        pcs: &PcsPlan,
        blocks: Vec<Vec<String>>,
        trace: bool,
    ) -> Result<Self, String> {
        let kinds = Self::expected_block_kinds(pcs, trace);
        if blocks.len() != kinds.len() {
            return Err(format!(
                "PCS render block count mismatch: got {} block(s), expected {} ({:?})",
                blocks.len(),
                kinds.len(),
                kinds
            ));
        }

        let blocks = kinds
            .into_iter()
            .zip(blocks)
            .map(|(kind, lines)| {
                Self::validate_block(&kind, &lines)?;
                Ok(PcsRenderBlock { kind, lines })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(Self { blocks })
    }

    pub(crate) fn expected_block_kinds(pcs: &PcsPlan, trace: bool) -> Vec<PcsRenderBlockKind> {
        if pcs.point_set_count == 0 {
            return Vec::new();
        }

        let mut kinds = Vec::with_capacity(4 + pcs.point_sets.len() + usize::from(trace));
        kinds.push(PcsRenderBlockKind::RotationPoints);
        if pcs.memory.x1_powers_words > 0 {
            kinds.push(PcsRenderBlockKind::X1Powers);
        }
        kinds.extend(
            pcs.point_sets
                .iter()
                .map(|set| PcsRenderBlockKind::QEvalSet {
                    set: set.index,
                    strategy: set.q_eval_strategy,
                }),
        );
        if trace {
            kinds.push(PcsRenderBlockKind::QComTrace);
        }
        kinds.push(PcsRenderBlockKind::FEval);
        kinds.push(PcsRenderBlockKind::FinalMsm);
        kinds.push(PcsRenderBlockKind::PairingInputs);
        kinds
    }

    #[cfg(test)]
    pub(crate) fn block_kinds(&self) -> Vec<&'static str> {
        self.blocks
            .iter()
            .map(|block| block.kind.as_str())
            .collect()
    }

    fn validate_block(kind: &PcsRenderBlockKind, lines: &[String]) -> Result<(), String> {
        let block_name = kind.as_str();
        let require = |needle: &str| {
            if lines.iter().any(|line| line.contains(needle)) {
                Ok(())
            } else {
                Err(format!(
                    "PCS {block_name} block is missing expected marker `{needle}`"
                ))
            }
        };

        match kind {
            PcsRenderBlockKind::RotationPoints => require("ROT_POINTS_MPTR"),
            PcsRenderBlockKind::X1Powers => require("X1_POWERS_MPTR"),
            PcsRenderBlockKind::QEvalSet { set, strategy } => {
                require(&format!("q_eval_set[{set}]"))?;
                require("Q_EVAL_SET_MPTR")?;
                let has_rolled_loop = lines.iter().any(|line| line.contains("eval_p"));
                match strategy {
                    PcsQEvalStrategy::Rolled if !has_rolled_loop => Err(format!(
                        "PCS q_eval_set block {set} is planned as rolled but has no eval_p loop"
                    )),
                    PcsQEvalStrategy::Unrolled if has_rolled_loop => Err(format!(
                        "PCS q_eval_set block {set} is planned as unrolled but contains eval_p loop state"
                    )),
                    _ => Ok(()),
                }
            }
            PcsRenderBlockKind::QComTrace => require("trace_point(40000"),
            PcsRenderBlockKind::FEval => {
                require("F_EVAL_MPTR")?;
                require("Q_EVAL_CPTR_MPTR")?;
                require("Q_EVAL_SET_MPTR")
            }
            PcsRenderBlockKind::FinalMsm => {
                require("FINAL_COM_MPTR")?;
                require("V_MPTR")?;
                require("F_COM_MPTR")
            }
            PcsRenderBlockKind::PairingInputs => {
                require("PAIRING_LHS_MPTR")?;
                require("PAIRING_RHS_MPTR")?;
                require("PI_MPTR")
            }
        }
    }
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

        let blocks = vec![
            vec!["mstore(add(ROT_POINTS_MPTR, 0x0), x)".to_string()],
            vec!["mstore(X1_POWERS_MPTR, 1)".to_string()],
            vec![
                "// q_eval_set[0]: 1 commitment(s)".to_string(),
                "mstore(add(Q_EVAL_SET_MPTR, 0x0), q_eval_set_0)".to_string(),
            ],
            vec![
                "// q_eval_set[1]: 4 commitment(s) (rolled, m>=4)".to_string(),
                "let eval_p := add(0x1000, 0x20)".to_string(),
                "mstore(add(Q_EVAL_SET_MPTR, 0x20), q_eval_set_0)".to_string(),
            ],
            vec![
                "let Q_EVAL_CPTR := mload(Q_EVAL_CPTR_MPTR)".to_string(),
                "let ev := mload(Q_EVAL_SET_MPTR)".to_string(),
                "mstore(F_EVAL_MPTR, ev)".to_string(),
            ],
            vec![
                "mcopy(FINAL_COM_MPTR, 0x1000, 0x80)".to_string(),
                "mcopy(0x1000, F_COM_MPTR, 0x80)".to_string(),
                "mstore(V_MPTR, v)".to_string(),
            ],
            vec![
                "mcopy(PAIRING_LHS_MPTR, PI_MPTR, 0x80)".to_string(),
                "mcopy(PAIRING_RHS_MPTR, PI_MPTR, 0x80)".to_string(),
            ],
        ];
        let render =
            PcsRenderPlan::from_blocks(&plan, blocks.clone(), false).expect("PCS render plan");
        assert_eq!(
            render.block_kinds(),
            vec![
                "rotation_points",
                "x1_powers",
                "q_eval_set",
                "q_eval_set",
                "f_eval",
                "final_msm",
                "pairing_inputs"
            ]
        );
        assert!(PcsRenderPlan::from_blocks(&plan, vec![vec![]], true).is_err());

        let mut missing_marker = blocks.clone();
        missing_marker[2] = vec!["// q_eval_set[0]: 1 commitment(s)".to_string()];
        assert!(PcsRenderPlan::from_blocks(&plan, missing_marker, false).is_err());

        let mut wrong_strategy = blocks;
        wrong_strategy[2].push("let eval_p := add(0x1000, 0x20)".to_string());
        assert!(PcsRenderPlan::from_blocks(&plan, wrong_strategy, false).is_err());
    }
}
