//! Typed transcript schedule for generated Solidity verifiers.
//!
//! The Askama template still renders the current hand-shaped loops, but this
//! module records the semantic Fiat-Shamir event order in one place and checks
//! that it agrees with the calldata layout produced from `ProtocolPlan`.

use crate::codegen::{
    proof_layout::{ProofCalldataLayout, ProofSection},
    protocol::ProtocolPlan,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TranscriptPlan {
    pub(crate) events: Vec<TranscriptEvent>,
}

impl TranscriptPlan {
    pub(crate) fn from_protocol(
        protocol: &ProtocolPlan,
        proof: &ProofCalldataLayout,
        num_instances: usize,
    ) -> Self {
        let mut events = Vec::new();
        events.push(TranscriptEvent::AbsorbVkDigest);
        // The patched Midfall Keccak transcript absorbs the committed-instance
        // identity point once whenever the committed-instances feature is
        // compiled in, even when this verifier has zero committed columns.
        events.push(TranscriptEvent::AbsorbCommittedInstanceIdentity { count: 1 });
        events.push(TranscriptEvent::AbsorbInstanceCount);
        events.push(TranscriptEvent::AbsorbInstances {
            count: num_instances,
        });

        for (phase, section) in proof.advice_phases.iter().enumerate() {
            if section.item_count != 0 {
                events.push(TranscriptEvent::AbsorbProofCommitments {
                    section: TranscriptProofSection::AdvicePhase(phase),
                    count: section.item_count,
                });
            }
            for challenge in 0..protocol
                .num_user_challenges
                .get(phase)
                .copied()
                .unwrap_or(0)
            {
                events.push(TranscriptEvent::Squeeze {
                    challenge: TranscriptChallenge::User {
                        phase,
                        index: challenge,
                    },
                    count: 1,
                });
            }
        }

        events.push(TranscriptEvent::Squeeze {
            challenge: TranscriptChallenge::Theta,
            count: 1,
        });
        push_g1_section(
            &mut events,
            TranscriptProofSection::LookupMultiplicity,
            proof.lookup_multiplicities,
        );
        events.push(TranscriptEvent::Squeeze {
            challenge: TranscriptChallenge::Beta,
            count: 1,
        });
        events.push(TranscriptEvent::Squeeze {
            challenge: TranscriptChallenge::Gamma,
            count: 1,
        });
        push_g1_section(
            &mut events,
            TranscriptProofSection::PermutationProduct,
            proof.permutation_products,
        );
        for lookup in &proof.lookups {
            push_g1_section(
                &mut events,
                TranscriptProofSection::LookupHelper {
                    lookup: lookup.lookup,
                },
                lookup.helpers,
            );
            push_g1_section(
                &mut events,
                TranscriptProofSection::LookupAccumulator {
                    lookup: lookup.lookup,
                },
                lookup.accumulator,
            );
        }
        events.push(TranscriptEvent::Squeeze {
            challenge: TranscriptChallenge::TrashChallenge,
            count: 1,
        });
        push_g1_section(&mut events, TranscriptProofSection::Trash, proof.trash);
        events.push(TranscriptEvent::Squeeze {
            challenge: TranscriptChallenge::Y,
            count: 1,
        });
        push_g1_section(
            &mut events,
            TranscriptProofSection::QuotientLimb,
            proof.quotient_limbs,
        );
        events.push(TranscriptEvent::Squeeze {
            challenge: TranscriptChallenge::X,
            count: 1,
        });
        if proof.evals.item_count != 0 {
            events.push(TranscriptEvent::AbsorbProofEvaluations {
                count: proof.evals.item_count,
            });
        }
        events.push(TranscriptEvent::Squeeze {
            challenge: TranscriptChallenge::X1,
            count: 1,
        });
        events.push(TranscriptEvent::Squeeze {
            challenge: TranscriptChallenge::X2,
            count: 1,
        });
        events.push(TranscriptEvent::AbsorbBatchOpenCommitment {
            kind: BatchOpenCommitmentKind::FCom,
        });
        events.push(TranscriptEvent::Squeeze {
            challenge: TranscriptChallenge::X3,
            count: 1,
        });
        if proof.q_evals.item_count != 0 {
            events.push(TranscriptEvent::AbsorbBatchOpenEvaluations {
                count: proof.q_evals.item_count,
            });
        }
        events.push(TranscriptEvent::Squeeze {
            challenge: TranscriptChallenge::X4,
            count: 1,
        });
        events.push(TranscriptEvent::AbsorbBatchOpenCommitment {
            kind: BatchOpenCommitmentKind::Pi,
        });

        Self { events }
    }

    pub(crate) fn validate_against_layout(
        &self,
        protocol: &ProtocolPlan,
        proof: &ProofCalldataLayout,
    ) -> Result<(), String> {
        if proof.advice_phases.len() != protocol.num_user_advices.len() {
            return Err(format!(
                "transcript/proof phase mismatch: proof={} protocol={}",
                proof.advice_phases.len(),
                protocol.num_user_advices.len()
            ));
        }
        let event_commitments = self.proof_commitment_count();
        if event_commitments != proof.commitment_g1_count() {
            return Err(format!(
                "transcript proof commitment count mismatch: events={event_commitments} layout={}",
                proof.commitment_g1_count()
            ));
        }
        if self.batch_open_commitment_count() != 2 {
            return Err("transcript must absorb f_com and pi batch-open commitments".to_string());
        }
        if self.proof_eval_count() != proof.evals.item_count {
            return Err(format!(
                "transcript main eval count mismatch: events={} layout={}",
                self.proof_eval_count(),
                proof.evals.item_count
            ));
        }
        if self.batch_open_eval_count() != proof.q_evals.item_count {
            return Err(format!(
                "transcript q_eval count mismatch: events={} layout={}",
                self.batch_open_eval_count(),
                proof.q_evals.item_count
            ));
        }
        if proof.commitment_read_groups() != protocol.commitment_read_groups() {
            return Err(format!(
                "transcript proof groups mismatch: proof={:?} protocol={:?}",
                proof.commitment_read_groups(),
                protocol.commitment_read_groups()
            ));
        }
        Ok(())
    }

    pub(crate) fn proof_commitment_count(&self) -> usize {
        self.events
            .iter()
            .map(|event| match event {
                TranscriptEvent::AbsorbProofCommitments { count, .. } => *count,
                _ => 0,
            })
            .sum()
    }

    pub(crate) fn proof_eval_count(&self) -> usize {
        self.events
            .iter()
            .map(|event| match event {
                TranscriptEvent::AbsorbProofEvaluations { count } => *count,
                _ => 0,
            })
            .sum()
    }

    pub(crate) fn batch_open_eval_count(&self) -> usize {
        self.events
            .iter()
            .map(|event| match event {
                TranscriptEvent::AbsorbBatchOpenEvaluations { count } => *count,
                _ => 0,
            })
            .sum()
    }

    pub(crate) fn batch_open_commitment_count(&self) -> usize {
        self.events
            .iter()
            .filter(|event| matches!(event, TranscriptEvent::AbsorbBatchOpenCommitment { .. }))
            .count()
    }
}

fn push_g1_section(
    events: &mut Vec<TranscriptEvent>,
    section: TranscriptProofSection,
    proof_section: ProofSection,
) {
    if proof_section.item_count != 0 {
        events.push(TranscriptEvent::AbsorbProofCommitments {
            section,
            count: proof_section.item_count,
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TranscriptEvent {
    AbsorbVkDigest,
    AbsorbCommittedInstanceIdentity {
        count: usize,
    },
    AbsorbInstanceCount,
    AbsorbInstances {
        count: usize,
    },
    AbsorbProofCommitments {
        section: TranscriptProofSection,
        count: usize,
    },
    Squeeze {
        challenge: TranscriptChallenge,
        count: usize,
    },
    AbsorbProofEvaluations {
        count: usize,
    },
    AbsorbBatchOpenCommitment {
        kind: BatchOpenCommitmentKind,
    },
    AbsorbBatchOpenEvaluations {
        count: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TranscriptProofSection {
    AdvicePhase(usize),
    LookupMultiplicity,
    PermutationProduct,
    LookupHelper { lookup: usize },
    LookupAccumulator { lookup: usize },
    Trash,
    QuotientLimb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TranscriptChallenge {
    User { phase: usize, index: usize },
    Theta,
    Beta,
    Gamma,
    TrashChallenge,
    Y,
    X,
    X1,
    X2,
    X3,
    X4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BatchOpenCommitmentKind {
    FCom,
    Pi,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::{
        layout,
        protocol::{CommitmentRead, ProofReadPlan},
    };

    fn protocol_shape(
        user_advices: Vec<usize>,
        user_challenges: Vec<usize>,
        lookup_chunks: Vec<usize>,
        permutation_zs: usize,
        trashcans: usize,
        quotients: usize,
    ) -> ProtocolPlan {
        let num_lookups = lookup_chunks.len();
        let mut proof = ProofReadPlan::default();
        for column in 0..user_advices.iter().sum::<usize>() {
            proof.commitments.push(CommitmentRead::Advice { column });
        }
        proof
            .commitments
            .extend((0..num_lookups).map(|lookup| CommitmentRead::LookupMultiplicity { lookup }));
        proof
            .commitments
            .extend((0..permutation_zs).map(|set| CommitmentRead::PermutationProduct { set }));
        for (lookup, chunks) in lookup_chunks.iter().copied().enumerate() {
            proof.commitments.extend(
                (0..chunks).map(move |chunk| CommitmentRead::LookupHelper { lookup, chunk }),
            );
            proof
                .commitments
                .push(CommitmentRead::LookupAccumulator { lookup });
        }
        proof
            .commitments
            .extend((0..trashcans).map(|index| CommitmentRead::Trash { index }));
        proof
            .commitments
            .extend((0..quotients).map(|limb| CommitmentRead::Quotient { limb }));

        ProtocolPlan {
            num_user_advices: user_advices,
            num_user_challenges: user_challenges,
            lookup_chunks,
            num_lookups,
            num_permutation_zs: permutation_zs,
            num_trashcans: trashcans,
            num_quotients: quotients,
            advice_indices: (0..proof
                .commitments
                .iter()
                .filter(|read| matches!(read, CommitmentRead::Advice { .. }))
                .count())
                .collect(),
            proof,
            ..ProtocolPlan::default()
        }
    }

    #[test]
    fn transcript_plan_matches_current_verifier_order() {
        let protocol = protocol_shape(vec![2, 1], vec![1, 0], vec![2], 1, 1, 3);
        let proof = ProofCalldataLayout::from_protocol(
            &protocol,
            layout::abi::VERIFY_PROOF_PROOF_CPTR,
            7,
            2,
        );
        let plan = TranscriptPlan::from_protocol(&protocol, &proof, 5);

        assert_eq!(plan.events[0], TranscriptEvent::AbsorbVkDigest);
        assert_eq!(
            plan.events[1],
            TranscriptEvent::AbsorbCommittedInstanceIdentity { count: 1 }
        );
        assert!(plan.events.windows(3).any(|events| matches!(
            events,
            [
                TranscriptEvent::Squeeze {
                    challenge: TranscriptChallenge::Theta,
                    ..
                },
                TranscriptEvent::AbsorbProofCommitments {
                    section: TranscriptProofSection::LookupMultiplicity,
                    count: 1
                },
                TranscriptEvent::Squeeze {
                    challenge: TranscriptChallenge::Beta,
                    ..
                },
            ]
        )));
        assert_eq!(plan.proof_commitment_count(), proof.commitment_g1_count());
        assert_eq!(plan.proof_eval_count(), 7);
        assert_eq!(plan.batch_open_eval_count(), 2);
        assert!(plan.validate_against_layout(&protocol, &proof).is_ok());
    }
}
