//! Codegen-time proof calldata and transcript-buffer layout.
//!
//! The generated Solidity verifier still walks calldata with simple Yul
//! loops, but the section boundaries are planned here instead of being
//! recomputed ad hoc by templates, the repacker, and `Data`.

use crate::codegen::{
    layout::{self, G1_BYTES, WORD_BYTES},
    protocol::{CommitmentRead, ProtocolPlan},
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProofSection {
    /// Start byte offset in verifier calldata.
    pub(crate) start: usize,
    /// Number of homogeneous items in this section.
    pub(crate) item_count: usize,
    /// Byte length of one item.
    pub(crate) item_bytes: usize,
    /// Total byte length of the section.
    pub(crate) byte_len: usize,
}

impl ProofSection {
    /// Construct a homogeneous section and derive its byte length.
    fn new(start: usize, item_count: usize, item_bytes: usize) -> Self {
        Self {
            start,
            item_count,
            item_bytes,
            byte_len: item_count * item_bytes,
        }
    }

    /// End byte offset, exclusive.
    pub(crate) fn end(self) -> usize {
        self.start + self.byte_len
    }
}

/// Calldata layout for one lookup argument's commitment reads.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProofLookupCommitmentsLayout {
    /// Lookup argument index.
    pub(crate) lookup: usize,
    /// Chunk helper commitments for this lookup.
    pub(crate) helpers: ProofSection,
    /// LogUp accumulator commitment for this lookup.
    pub(crate) accumulator: ProofSection,
}

/// Complete calldata section map for the generated verifier proof argument.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProofCalldataLayout {
    /// Byte offset of the first proof payload byte.
    pub(crate) proof_cptr: usize,
    /// Advice commitments grouped by user phase.
    pub(crate) advice_phases: Vec<ProofSection>,
    /// Lookup multiplicity commitments.
    pub(crate) lookup_multiplicities: ProofSection,
    /// Permutation product commitments.
    pub(crate) permutation_products: ProofSection,
    /// Per-lookup helper and accumulator commitments.
    pub(crate) lookups: Vec<ProofLookupCommitmentsLayout>,
    /// Trashcan commitments.
    pub(crate) trash: ProofSection,
    /// Quotient limb commitments.
    pub(crate) quotient_limbs: ProofSection,
    /// Main scalar evaluation block.
    pub(crate) evals: ProofSection,
    /// KZG `f_com` commitment.
    pub(crate) f_com: ProofSection,
    /// KZG point-set evaluation scalars.
    pub(crate) q_evals: ProofSection,
    /// KZG proof commitment `pi`.
    pub(crate) pi: ProofSection,
    /// Start of quotient commitment section.
    pub(crate) quotient_comm_cptr: usize,
    /// Start of the main evaluation scalar section.
    pub(crate) eval_cptr: usize,
    /// Start of the trailing KZG multi-open G1 block (`f_com`).
    pub(crate) w_cptr: usize,
    /// Start of quotient point-set evaluation scalars.
    pub(crate) q_eval_cptr: usize,
    /// End byte offset of the proof payload.
    pub(crate) proof_end: usize,
    /// Total proof payload byte length.
    pub(crate) proof_len: usize,
}

impl ProofCalldataLayout {
    fn take_commitment_section(
        protocol: &ProtocolPlan,
        read_idx: &mut usize,
        cursor: &mut usize,
        expected: CommitmentRead,
        count: usize,
        label: &str,
    ) -> ProofSection {
        let section = ProofSection::new(*cursor, count, G1_BYTES);
        for local in 0..count {
            let actual = protocol.proof.commitments.get(*read_idx).copied();
            assert_eq!(
                actual,
                Some(expected),
                "proof commitment plan drift at {label}[{local}]: got {actual:?}, expected {expected:?}"
            );
            *read_idx += 1;
        }
        *cursor = section.end();
        section
    }

    /// Build the calldata layout by replaying the protocol proof-read order.
    ///
    /// `num_evals` and `num_point_sets` include feature-dependent dummy evals
    /// and PCS point-set planning results, so this function stays independent
    /// of those later codegen passes.
    pub(crate) fn from_protocol(
        protocol: &ProtocolPlan,
        proof_cptr: usize,
        num_evals: usize,
        num_point_sets: usize,
    ) -> Self {
        let mut cursor = proof_cptr;
        let mut read_idx = 0usize;
        let word_section = |cursor: &mut usize, item_count: usize| {
            let section = ProofSection::new(*cursor, item_count, WORD_BYTES);
            *cursor = section.end();
            section
        };

        let advice_phases = protocol
            .num_user_advices
            .iter()
            .copied()
            .map(|count| {
                Self::take_commitment_section(
                    protocol,
                    &mut read_idx,
                    &mut cursor,
                    CommitmentRead::Advice,
                    count,
                    "advice phase",
                )
            })
            .collect::<Vec<_>>();
        let lookup_multiplicities = Self::take_commitment_section(
            protocol,
            &mut read_idx,
            &mut cursor,
            CommitmentRead::LookupMultiplicity,
            protocol.num_lookups,
            "lookup multiplicity",
        );
        let permutation_products = Self::take_commitment_section(
            protocol,
            &mut read_idx,
            &mut cursor,
            CommitmentRead::PermutationProduct,
            protocol.num_permutation_zs,
            "permutation product",
        );
        let lookups = protocol
            .lookup_chunks
            .iter()
            .copied()
            .enumerate()
            .map(|(lookup, chunks)| ProofLookupCommitmentsLayout {
                lookup,
                helpers: Self::take_commitment_section(
                    protocol,
                    &mut read_idx,
                    &mut cursor,
                    CommitmentRead::LookupHelper,
                    chunks,
                    "lookup helper",
                ),
                accumulator: Self::take_commitment_section(
                    protocol,
                    &mut read_idx,
                    &mut cursor,
                    CommitmentRead::LookupAccumulator,
                    1,
                    "lookup accumulator",
                ),
            })
            .collect::<Vec<_>>();
        let trash = Self::take_commitment_section(
            protocol,
            &mut read_idx,
            &mut cursor,
            CommitmentRead::Trash,
            protocol.num_trashcans,
            "trash",
        );

        let quotient_comm_cptr = cursor;
        let quotient_limbs = Self::take_commitment_section(
            protocol,
            &mut read_idx,
            &mut cursor,
            CommitmentRead::Quotient,
            protocol.num_quotients,
            "quotient limb",
        );
        assert_eq!(
            read_idx,
            protocol.proof.commitments.len(),
            "proof commitment layout did not consume the full protocol plan"
        );
        let eval_cptr = cursor;
        let evals = word_section(&mut cursor, num_evals);
        let w_cptr = cursor;
        let f_com = ProofSection::new(cursor, 1, G1_BYTES);
        cursor = f_com.end();
        let q_eval_cptr = cursor;
        let q_evals = word_section(&mut cursor, num_point_sets);
        let pi = ProofSection::new(cursor, 1, G1_BYTES);
        cursor = pi.end();
        let proof_end = cursor;

        Self {
            proof_cptr,
            advice_phases,
            lookup_multiplicities,
            permutation_products,
            lookups,
            trash,
            quotient_limbs,
            evals,
            f_com,
            q_evals,
            pi,
            quotient_comm_cptr,
            eval_cptr,
            w_cptr,
            q_eval_cptr,
            proof_end,
            proof_len: proof_end - proof_cptr,
        }
    }

    /// Number of proof G1 commitments before quotient limbs.
    pub(crate) fn non_quotient_g1_count(&self) -> usize {
        self.advice_phases
            .iter()
            .map(|section| section.item_count)
            .sum::<usize>()
            + self.lookup_multiplicities.item_count
            + self.permutation_products.item_count
            + self
                .lookups
                .iter()
                .map(|lookup| lookup.helpers.item_count + lookup.accumulator.item_count)
                .sum::<usize>()
            + self.trash.item_count
    }

    /// Number of proof G1 commitments that participate in transcript reads.
    pub(crate) fn commitment_g1_count(&self) -> usize {
        self.non_quotient_g1_count() + self.quotient_limbs.item_count
    }

    /// Total number of G1 points in the Solidity-facing proof payload.
    pub(crate) fn total_g1_count(&self) -> usize {
        self.commitment_g1_count() + self.f_com.item_count + self.pi.item_count
    }

    /// Commitment group sizes in the exact read/repack order.
    pub(crate) fn commitment_read_groups(&self) -> Vec<usize> {
        let mut groups = Vec::new();
        groups.extend(
            self.advice_phases
                .iter()
                .map(|section| section.item_count)
                .filter(|&count| count != 0),
        );
        if self.lookup_multiplicities.item_count != 0 {
            groups.push(self.lookup_multiplicities.item_count);
        }
        if self.permutation_products.item_count != 0 {
            groups.push(self.permutation_products.item_count);
        }
        for lookup in &self.lookups {
            groups.push(lookup.helpers.item_count);
            groups.push(lookup.accumulator.item_count);
        }
        if self.trash.item_count != 0 {
            groups.push(self.trash.item_count);
        }
        groups.push(self.quotient_limbs.item_count);
        groups
    }
}

/// Conservative bound for the streaming transcript buffer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TranscriptBufferLayout {
    /// Max bytes before the first challenge squeeze.
    pub(crate) initial_run_bytes: usize,
    /// Max bytes for the evaluation scalar absorb run.
    pub(crate) eval_run_bytes: usize,
    /// Max bytes for the full commitment/scalar absorb run.
    pub(crate) total_run_bytes: usize,
    /// Required EVM words above `TRANSCRIPT_BUFFER_START`.
    pub(crate) words: usize,
}

impl TranscriptBufferLayout {
    /// Derive transcript-buffer bounds from proof calldata shape and instances.
    pub(crate) fn from_proof_layout(proof: &ProofCalldataLayout, num_instances: usize) -> Self {
        let word_absorb = layout::transcript::WORD_ABSORB_BYTES;
        let g1_absorb = layout::transcript::G1_ABSORB_BYTES;
        let squeeze_cushion = layout::transcript::POST_SQUEEZE_CUSHION_WORDS * WORD_BYTES;

        let phase_1_advices = proof
            .advice_phases
            .first()
            .map(|section| section.item_count)
            .unwrap_or(0);
        let initial_run_bytes = word_absorb
            + g1_absorb
            + word_absorb
            + num_instances * word_absorb
            + phase_1_advices * g1_absorb
            + squeeze_cushion;

        let eval_run_bytes = proof.quotient_limbs.byte_len
            + proof.evals.byte_len
            + proof.q_evals.byte_len
            + squeeze_cushion;

        let total_scalar_bytes = proof.evals.byte_len
            + proof.q_evals.byte_len
            + layout::transcript::POST_SQUEEZE_CUSHION_WORDS * word_absorb;
        let total_run_bytes =
            word_absorb + proof.total_g1_count() * g1_absorb + total_scalar_bytes + squeeze_cushion;

        let max_bytes = initial_run_bytes.max(eval_run_bytes).max(total_run_bytes);
        Self {
            initial_run_bytes,
            eval_run_bytes,
            total_run_bytes,
            words: max_bytes.div_ceil(WORD_BYTES),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::protocol::{CommitmentRead, ProofReadPlan, ProtocolPlan};

    fn protocol_shape(
        user_advices: Vec<usize>,
        lookup_chunks: Vec<usize>,
        permutation_zs: usize,
        trashcans: usize,
        quotients: usize,
    ) -> ProtocolPlan {
        let num_lookups = lookup_chunks.len();
        let mut proof = ProofReadPlan::default();
        proof
            .commitments
            .extend((0..user_advices.iter().sum::<usize>()).map(|_| CommitmentRead::Advice));
        proof
            .commitments
            .extend((0..num_lookups).map(|_| CommitmentRead::LookupMultiplicity));
        proof
            .commitments
            .extend((0..permutation_zs).map(|_| CommitmentRead::PermutationProduct));
        for chunks in lookup_chunks.iter().copied() {
            proof
                .commitments
                .extend((0..chunks).map(|_| CommitmentRead::LookupHelper));
            proof.commitments.push(CommitmentRead::LookupAccumulator);
        }
        proof
            .commitments
            .extend((0..trashcans).map(|_| CommitmentRead::Trash));
        proof
            .commitments
            .extend((0..quotients).map(|_| CommitmentRead::Quotient));

        ProtocolPlan {
            num_user_advices: user_advices,
            advice_indices: (0..proof
                .commitments
                .iter()
                .filter(|read| matches!(read, CommitmentRead::Advice))
                .count())
                .collect(),
            lookup_chunks,
            num_lookups,
            num_permutation_zs: permutation_zs,
            num_trashcans: trashcans,
            num_quotients: quotients,
            proof,
            ..ProtocolPlan::default()
        }
    }

    #[test]
    fn proof_layout_matches_legacy_offsets() {
        let protocol = protocol_shape(vec![2, 1], vec![2, 0], 1, 1, 3);
        let proof_cptr = layout::abi::VERIFY_PROOF_PROOF_CPTR;
        let layout = ProofCalldataLayout::from_protocol(&protocol, proof_cptr, 5, 2);

        let non_quotient_g1s = 3 + 2 + 1 + 4 + 1;
        assert_eq!(layout.non_quotient_g1_count(), non_quotient_g1s);
        assert_eq!(
            layout.quotient_comm_cptr,
            proof_cptr + non_quotient_g1s * G1_BYTES
        );
        assert_eq!(layout.eval_cptr, layout.quotient_comm_cptr + 3 * G1_BYTES);
        assert_eq!(layout.w_cptr, layout.eval_cptr + 5 * WORD_BYTES);
        assert_eq!(layout.q_eval_cptr, layout.w_cptr + G1_BYTES);
        assert_eq!(
            layout.proof_len,
            (non_quotient_g1s + 3 + 2) * G1_BYTES + (5 + 2) * WORD_BYTES
        );
    }

    #[test]
    fn proof_layout_preserves_lookup_helper_accumulator_grouping() {
        let protocol = protocol_shape(vec![1], vec![2, 1], 0, 0, 2);
        let layout = ProofCalldataLayout::from_protocol(&protocol, 0, 0, 0);

        assert_eq!(layout.lookups.len(), 2);
        assert_eq!(layout.lookups[0].helpers.item_count, 2);
        assert_eq!(layout.lookups[0].accumulator.item_count, 1);
        assert_eq!(layout.lookups[0].helpers.start, 3 * G1_BYTES);
        assert_eq!(layout.lookups[0].accumulator.start, 5 * G1_BYTES);
        assert_eq!(layout.lookups[1].helpers.item_count, 1);
        assert_eq!(layout.lookups[1].helpers.start, 6 * G1_BYTES);
        assert_eq!(layout.lookups[1].accumulator.start, 7 * G1_BYTES);
    }

    #[test]
    #[should_panic(expected = "proof commitment plan drift")]
    fn proof_layout_rejects_commitment_order_drift() {
        let mut protocol = protocol_shape(vec![1], vec![1], 1, 0, 1);
        let lhs = protocol
            .proof
            .commitments
            .iter()
            .position(|read| matches!(read, CommitmentRead::LookupMultiplicity))
            .expect("lookup multiplicity");
        let rhs = protocol
            .proof
            .commitments
            .iter()
            .position(|read| matches!(read, CommitmentRead::PermutationProduct))
            .expect("permutation product");
        protocol.proof.commitments.swap(lhs, rhs);

        let _ = ProofCalldataLayout::from_protocol(&protocol, 0, 0, 0);
    }

    #[test]
    fn proof_layout_handles_zero_lookup_and_trash() {
        let protocol = protocol_shape(vec![0, 4], vec![], 0, 0, 1);
        let layout = ProofCalldataLayout::from_protocol(&protocol, 0x64, 7, 0);

        assert_eq!(layout.lookup_multiplicities.byte_len, 0);
        assert_eq!(layout.permutation_products.byte_len, 0);
        assert_eq!(layout.trash.byte_len, 0);
        assert_eq!(layout.quotient_comm_cptr, 0x64 + 4 * G1_BYTES);
        assert_eq!(layout.commitment_read_groups(), vec![4, 1]);
    }

    #[test]
    fn transcript_layout_matches_current_conservative_bound() {
        let protocol = protocol_shape(vec![64], vec![], 0, 0, 2);
        let proof = ProofCalldataLayout::from_protocol(&protocol, 0, 10, 3);
        let transcript = TranscriptBufferLayout::from_proof_layout(&proof, 0);

        let first_phase_run = 32 + 128 + 32 + 64 * 128 + 32 * 32;
        assert!(transcript.words * WORD_BYTES >= first_phase_run);
        assert_eq!(
            transcript.eval_run_bytes,
            2 * G1_BYTES + (10 + 3) * WORD_BYTES + 32 * WORD_BYTES
        );
    }
}
