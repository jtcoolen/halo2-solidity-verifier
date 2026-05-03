//! Debug manifest for generated verifier plans.
//!
//! The manifest is intentionally an internal, dependency-free JSON renderer.
//! It gives tests and reviewers one stable object that summarizes the proof
//! layout, memory anchors, quotient VM payload, feature flags, and dependency
//! pins used by a render.

use ruint::aliases::U256;

use crate::codegen::{
    memory::{PcsMemoryRequirements, VerifierMemoryLayout},
    proof_layout::{ProofCalldataLayout, ProofSection},
    quotient::QuotientProgramBuild,
    transcript_plan::TranscriptPlan,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodegenManifest {
    pub(crate) proof_len: usize,
    pub(crate) proof_sections: Vec<ManifestSection>,
    pub(crate) vk_len: usize,
    pub(crate) memory: ManifestMemory,
    pub(crate) quotient: ManifestQuotient,
    pub(crate) transcript_events: usize,
    pub(crate) pcs: ManifestPcs,
    pub(crate) features: ManifestFeatures,
    pub(crate) dependency_hashes: ManifestDependencyHashes,
}

impl CodegenManifest {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        proof: &ProofCalldataLayout,
        vk_len: usize,
        memory: &VerifierMemoryLayout,
        quotient: Option<&QuotientProgramBuild>,
        transcript: &TranscriptPlan,
        pcs: PcsMemoryRequirements,
        features: ManifestFeatures,
        dependency_hashes: ManifestDependencyHashes,
    ) -> Self {
        Self {
            proof_len: proof.proof_len,
            proof_sections: proof_sections(proof),
            vk_len,
            memory: ManifestMemory::from_layout(memory),
            quotient: ManifestQuotient::from_build(quotient),
            transcript_events: transcript.events.len(),
            pcs: ManifestPcs::from_requirements(pcs),
            features,
            dependency_hashes,
        }
    }

    pub(crate) fn to_json_pretty(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        push_num_field(&mut out, 1, "proof_len", self.proof_len, true);
        push_num_field(&mut out, 1, "vk_len", self.vk_len, true);
        out.push_str("  \"proof_sections\": [\n");
        for (idx, section) in self.proof_sections.iter().enumerate() {
            out.push_str("    ");
            out.push_str(&section.to_json());
            if idx + 1 != self.proof_sections.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ],\n");
        out.push_str("  \"memory\": ");
        out.push_str(&self.memory.to_json());
        out.push_str(",\n");
        out.push_str("  \"quotient\": ");
        out.push_str(&self.quotient.to_json());
        out.push_str(",\n");
        push_num_field(
            &mut out,
            1,
            "transcript_events",
            self.transcript_events,
            true,
        );
        out.push_str("  \"pcs\": ");
        out.push_str(&self.pcs.to_json());
        out.push_str(",\n");
        out.push_str("  \"features\": ");
        out.push_str(&self.features.to_json());
        out.push_str(",\n");
        out.push_str("  \"dependency_hashes\": ");
        out.push_str(&self.dependency_hashes.to_json());
        out.push('\n');
        out.push('}');
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManifestSection {
    pub(crate) name: String,
    pub(crate) start: usize,
    pub(crate) byte_len: usize,
    pub(crate) item_count: usize,
    pub(crate) item_bytes: usize,
}

impl ManifestSection {
    fn new(name: impl Into<String>, section: ProofSection) -> Self {
        Self {
            name: name.into(),
            start: section.start,
            byte_len: section.byte_len,
            item_count: section.item_count,
            item_bytes: section.item_bytes,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"name\":\"{}\",\"start\":{},\"byte_len\":{},\"item_count\":{},\"item_bytes\":{}}}",
            json_escape(&self.name),
            self.start,
            self.byte_len,
            self.item_count,
            self.item_bytes
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManifestMemory {
    pub(crate) vk_mptr: usize,
    pub(crate) challenge_mptr: usize,
    pub(crate) theta_mptr: usize,
    pub(crate) reversed_evals_mptr: usize,
    pub(crate) comms_mptr_base: usize,
    pub(crate) selector_acc_mptr: usize,
    pub(crate) quotient_tmp_mptr: usize,
    pub(crate) quotient_stack_mptr: usize,
}

impl ManifestMemory {
    fn from_layout(memory: &VerifierMemoryLayout) -> Self {
        Self {
            vk_mptr: memory.vk_mptr.value().as_usize(),
            challenge_mptr: memory.challenge_mptr.value().as_usize(),
            theta_mptr: memory.theta_mptr.value().as_usize(),
            reversed_evals_mptr: memory.reversed_evals_mptr.value().as_usize(),
            comms_mptr_base: memory.comms_mptr_base.value().as_usize(),
            selector_acc_mptr: memory.selector_acc_mptr,
            quotient_tmp_mptr: memory.quotient_tmp_mptr,
            quotient_stack_mptr: memory.quotient_stack_mptr,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"vk_mptr\":{},\"challenge_mptr\":{},\"theta_mptr\":{},\"reversed_evals_mptr\":{},\"comms_mptr_base\":{},\"selector_acc_mptr\":{},\"quotient_tmp_mptr\":{},\"quotient_stack_mptr\":{}}}",
            self.vk_mptr,
            self.challenge_mptr,
            self.theta_mptr,
            self.reversed_evals_mptr,
            self.comms_mptr_base,
            self.selector_acc_mptr,
            self.quotient_tmp_mptr,
            self.quotient_stack_mptr
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManifestQuotient {
    pub(crate) external: bool,
    pub(crate) program_bytes: usize,
    pub(crate) const_words: usize,
    pub(crate) packed32: bool,
    pub(crate) cse_temps: usize,
    pub(crate) max_stack: usize,
}

impl ManifestQuotient {
    fn from_build(build: Option<&QuotientProgramBuild>) -> Self {
        match build {
            Some(build) => Self {
                external: false,
                program_bytes: build.bytes.len(),
                const_words: build.consts.len(),
                packed32: build.packed32,
                cse_temps: build.cse_temps,
                max_stack: build.max_stack,
            },
            None => Self {
                external: true,
                program_bytes: 0,
                const_words: 0,
                packed32: false,
                cse_temps: 0,
                max_stack: 0,
            },
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"external\":{},\"program_bytes\":{},\"const_words\":{},\"packed32\":{},\"cse_temps\":{},\"max_stack\":{}}}",
            self.external,
            self.program_bytes,
            self.const_words,
            self.packed32,
            self.cse_temps,
            self.max_stack
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManifestPcs {
    pub(crate) rot_points_words: usize,
    pub(crate) x1_powers_words: usize,
    pub(crate) q_eval_set_words: usize,
    pub(crate) q_eval_source_table_words: usize,
    pub(crate) final_msm_terms: usize,
}

impl ManifestPcs {
    fn from_requirements(pcs: PcsMemoryRequirements) -> Self {
        Self {
            rot_points_words: pcs.rot_points_words,
            x1_powers_words: pcs.x1_powers_words,
            q_eval_set_words: pcs.q_eval_set_words,
            q_eval_source_table_words: pcs.q_eval_source_table_words,
            final_msm_terms: pcs.final_msm.terms,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"rot_points_words\":{},\"x1_powers_words\":{},\"q_eval_set_words\":{},\"q_eval_source_table_words\":{},\"final_msm_terms\":{}}}",
            self.rot_points_words,
            self.x1_powers_words,
            self.q_eval_set_words,
            self.q_eval_source_table_words,
            self.final_msm_terms
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManifestFeatures {
    pub(crate) truncated_challenges: bool,
    pub(crate) outer_fewer_point_sets: bool,
    pub(crate) solidity_trace: bool,
    pub(crate) solidity_gas_checkpoints: bool,
}

impl ManifestFeatures {
    pub(crate) fn current() -> Self {
        Self {
            truncated_challenges: cfg!(feature = "truncated-challenges"),
            outer_fewer_point_sets: cfg!(feature = "outer-fewer-point-sets"),
            solidity_trace: crate::SOLIDITY_TRACE_ENABLED,
            solidity_gas_checkpoints: crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"truncated_challenges\":{},\"outer_fewer_point_sets\":{},\"solidity_trace\":{},\"solidity_gas_checkpoints\":{}}}",
            self.truncated_challenges,
            self.outer_fewer_point_sets,
            self.solidity_trace,
            self.solidity_gas_checkpoints
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ManifestDependencyHashes {
    pub(crate) expected_vk_codehash: Option<U256>,
    pub(crate) expected_quotient_codehash: Option<U256>,
}

impl ManifestDependencyHashes {
    pub(crate) fn new(
        expected_vk_codehash: Option<U256>,
        expected_quotient_codehash: Option<U256>,
    ) -> Self {
        Self {
            expected_vk_codehash,
            expected_quotient_codehash,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"expected_vk_codehash\":{},\"expected_quotient_codehash\":{}}}",
            json_u256(self.expected_vk_codehash),
            json_u256(self.expected_quotient_codehash)
        )
    }
}

fn proof_sections(proof: &ProofCalldataLayout) -> Vec<ManifestSection> {
    let mut sections = Vec::new();
    for (phase, section) in proof.advice_phases.iter().copied().enumerate() {
        sections.push(ManifestSection::new(
            format!("advice_phase_{phase}"),
            section,
        ));
    }
    sections.push(ManifestSection::new(
        "lookup_multiplicities",
        proof.lookup_multiplicities,
    ));
    sections.push(ManifestSection::new(
        "permutation_products",
        proof.permutation_products,
    ));
    for lookup in &proof.lookups {
        sections.push(ManifestSection::new(
            format!("lookup_{}_helpers", lookup.lookup),
            lookup.helpers,
        ));
        sections.push(ManifestSection::new(
            format!("lookup_{}_accumulator", lookup.lookup),
            lookup.accumulator,
        ));
    }
    sections.push(ManifestSection::new("trash", proof.trash));
    sections.push(ManifestSection::new("quotient_limbs", proof.quotient_limbs));
    sections.push(ManifestSection::new("evals", proof.evals));
    sections.push(ManifestSection::new("f_com", proof.f_com));
    sections.push(ManifestSection::new("q_evals", proof.q_evals));
    sections.push(ManifestSection::new("pi", proof.pi));
    sections
}

fn push_num_field(out: &mut String, indent: usize, name: &str, value: usize, comma: bool) {
    out.push_str(&"  ".repeat(indent));
    out.push('"');
    out.push_str(name);
    out.push_str("\": ");
    out.push_str(&value.to_string());
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn json_u256(value: Option<U256>) -> String {
    value
        .map(|value| format!("\"0x{:064x}\"", value))
        .unwrap_or_else(|| "null".to_string())
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::protocol::{CommitmentRead, ProofReadPlan, ProtocolPlan};

    #[test]
    fn manifest_json_contains_core_sections() {
        let proof = ProofCalldataLayout::from_protocol(
            &crate::codegen::protocol::ProtocolPlan::default(),
            crate::codegen::layout::abi::VERIFY_PROOF_PROOF_CPTR,
            0,
            0,
        );
        let manifest = CodegenManifest {
            proof_len: proof.proof_len,
            proof_sections: proof_sections(&proof),
            vk_len: 0,
            memory: ManifestMemory {
                vk_mptr: 0,
                challenge_mptr: 0,
                theta_mptr: 0,
                reversed_evals_mptr: 0,
                comms_mptr_base: 0,
                selector_acc_mptr: 0,
                quotient_tmp_mptr: 0,
                quotient_stack_mptr: 0,
            },
            quotient: ManifestQuotient::from_build(None),
            transcript_events: 0,
            pcs: ManifestPcs::from_requirements(PcsMemoryRequirements::default()),
            features: ManifestFeatures::current(),
            dependency_hashes: ManifestDependencyHashes::default(),
        };

        let json = manifest.to_json_pretty();
        assert!(json.contains("\"proof_len\""));
        assert!(json.contains("\"quotient_limbs\""));
        assert!(json.contains("\"dependency_hashes\""));
    }

    #[test]
    fn poseidon_like_manifest_snapshot_shape_is_stable() {
        let protocol = manifest_protocol_shape(vec![3], vec![], 1, 0, 3);
        let proof = ProofCalldataLayout::from_protocol(
            &protocol,
            crate::codegen::layout::abi::VERIFY_PROOF_PROOF_CPTR,
            6,
            2,
        );
        let manifest = test_manifest(&proof, 0x800, 0x180, 0x40, 12);
        let names = manifest
            .proof_sections
            .iter()
            .map(|section| section.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "advice_phase_0",
                "lookup_multiplicities",
                "permutation_products",
                "trash",
                "quotient_limbs",
                "evals",
                "f_com",
                "q_evals",
                "pi",
            ]
        );
        assert_eq!(manifest.proof_len, 1408);
        let json = manifest.to_json_pretty();
        assert!(json.contains("\"vk_len\": 2048"));
        assert!(json.contains(
            "\"name\":\"advice_phase_0\",\"start\":100,\"byte_len\":384,\"item_count\":3,\"item_bytes\":128"
        ));
        assert!(json.contains("\"program_bytes\":384"));
        assert!(json.contains("\"const_words\":64"));
        assert!(json.contains("\"transcript_events\": 12"));
    }

    #[test]
    fn ivc_like_manifest_snapshot_shape_is_stable() {
        let protocol = manifest_protocol_shape(vec![2, 1], vec![2, 1], 2, 1, 4);
        let proof = ProofCalldataLayout::from_protocol(
            &protocol,
            crate::codegen::layout::abi::VERIFY_PROOF_PROOF_CPTR,
            17,
            5,
        );
        let manifest = test_manifest(&proof, 0x2c00, 0x640, 0x120, 31);
        let names = manifest
            .proof_sections
            .iter()
            .map(|section| section.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "advice_phase_0",
                "advice_phase_1",
                "lookup_multiplicities",
                "permutation_products",
                "lookup_0_helpers",
                "lookup_0_accumulator",
                "lookup_1_helpers",
                "lookup_1_accumulator",
                "trash",
                "quotient_limbs",
                "evals",
                "f_com",
                "q_evals",
                "pi",
            ]
        );
        assert_eq!(manifest.proof_len, 3136);
        let json = manifest.to_json_pretty();
        assert!(json.contains("\"vk_len\": 11264"));
        assert!(json.contains(
            "\"name\":\"lookup_0_helpers\",\"start\":996,\"byte_len\":256,\"item_count\":2,\"item_bytes\":128"
        ));
        assert!(json.contains(
            "\"name\":\"q_evals\",\"start\":2948,\"byte_len\":160,\"item_count\":5,\"item_bytes\":32"
        ));
        assert!(json.contains("\"program_bytes\":1600"));
        assert!(json.contains("\"const_words\":288"));
        assert!(json.contains("\"transcript_events\": 31"));
    }

    fn manifest_protocol_shape(
        user_advices: Vec<usize>,
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
            lookup_chunks,
            num_lookups,
            num_permutation_zs: permutation_zs,
            num_trashcans: trashcans,
            num_quotients: quotients,
            proof,
            ..ProtocolPlan::default()
        }
    }

    fn test_manifest(
        proof: &ProofCalldataLayout,
        vk_len: usize,
        program_bytes: usize,
        const_words: usize,
        transcript_events: usize,
    ) -> CodegenManifest {
        CodegenManifest {
            proof_len: proof.proof_len,
            proof_sections: proof_sections(proof),
            vk_len,
            memory: ManifestMemory {
                vk_mptr: 0x4000,
                challenge_mptr: 0x5000,
                theta_mptr: 0x6000,
                reversed_evals_mptr: 0x7000,
                comms_mptr_base: 0x8000,
                selector_acc_mptr: 0x9000,
                quotient_tmp_mptr: 0xa000,
                quotient_stack_mptr: 0xb000,
            },
            quotient: ManifestQuotient {
                external: false,
                program_bytes,
                const_words,
                packed32: false,
                cse_temps: 0,
                max_stack: 8,
            },
            transcript_events,
            pcs: ManifestPcs {
                rot_points_words: 3,
                x1_powers_words: 4,
                q_eval_set_words: proof.q_evals.item_count,
                q_eval_source_table_words: 0,
                final_msm_terms: 9,
            },
            features: ManifestFeatures::current(),
            dependency_hashes: ManifestDependencyHashes::default(),
        }
    }
}
