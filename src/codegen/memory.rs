//! Generated-verifier memory planner.
//!
//! The Solidity verifier intentionally uses absolute Yul memory addresses
//! instead of Solidity's free-memory pointer. That keeps generated code small,
//! makes precompile frames cheap to address, and lets the external quotient
//! evaluator rehydrate exactly the same verifier memory image. The tradeoff is
//! that memory safety has to be checked at codegen time.
//!
//! `VerifierMemoryLayout` is that codegen-time manifest. It preserves the
//! historical addresses in the generated verifier, gives each range a name and
//! lifetime, and rejects accidental overlap when two live ranges can coexist.
//! Intentional scratch reuse is modeled by assigning the same byte range to
//! disjoint `MemoryPhase`s.
//!
//! This is not a packing allocator yet. The first version is deliberately
//! conservative: it names the old layout, validates it, and centralizes all
//! sizing decisions. See `docs/MEMORY_LAYOUT.md` for the offset table and the
//! rules for changing it.

use crate::codegen::{
    layout::{theta_window, ThetaSlot},
    template::Halo2VerifyingKey,
    util::{ConstraintSystemMeta, Ptr},
};
use std::collections::BTreeMap;

pub(crate) use crate::codegen::layout::{
    ACC_MSM_MIN_SCRATCH_BYTES, G1ADD_INPUT_BYTES, G1_BYTES, G1_MSM_PAIR_BYTES, G1_WORDS,
    LOW_MEMORY_SCRATCH_START, MODEXP_DECOMPRESSION_WORKING_WORDS, MODEXP_FRAME_BYTES,
    MODEXP_SCRATCH_BYTES, PAIRING_PAIR_BYTES, PAIRING_STATIC_WORKING_WORDS, PAIRING_TWO_PAIR_BYTES,
    PCS_PAIRING_SCRATCH_START, PCS_STATIC_WORKING_WORDS, QUOTIENT_RETURN_BUFFER_START,
    SOLIDITY_FREE_MEMORY_POINTER_SLOT, SOLIDITY_RESERVED_MEMORY_BYTES,
    SOLIDITY_SCRATCH_SPACE_BYTES, SOLIDITY_ZERO_SLOT, TRANSCRIPT_BUFFER_START,
    VERIFIER_RETURN_BUFFER_START, VK_CONSTRUCTOR_PAYLOAD_START, WORD_BYTES,
};
/// Accumulator pairing-batch hash frame.
///
/// The template starts this frame at `0x100`, writes a one-word domain tag,
/// then four G1 points: KZG rhs/lhs and accumulator rhs/lhs. The last copy ends
/// at `0x320`, so the registered range is `[0x100, 0x320)`.
const ACCUMULATOR_PAIRING_BATCH_BYTES: usize =
    PAIRING_TWO_PAIR_BYTES - G1ADD_INPUT_BYTES + WORD_BYTES;

// Fixed word offsets from `THETA_MPTR`.
//
// These constants are compatibility anchors for the current generated
// verifier. The range `[THETA_MPTR, THETA_MPTR + 52 words)` holds scalar
// challenges, proof G1 slots, accumulator G1 slots, and pairing-input G1
// slots. PCS fixed windows start at word 52. Some gaps are intentionally left
// unused because older generated templates had those offsets; they are not
// available for scratch unless registered below with a disjoint lifetime.
//
//   words       region
//   0..10       theta, beta, gamma, trash_challenge, y, x, x1, x2, x3, x4
//   10..14      f_com G1
//   14..18      pi G1
//   18..22      accumulator lhs G1
//   22..26      accumulator rhs G1
//   26..33      Lagrange and linearization scalar slots
//   33..37      quotient linearization scratch, rendered as a trace G1
//   37          historical padding
//   38..40      f_eval, v
//   40..44      final_com G1
//   44..48      pairing lhs G1
//   48..52      pairing rhs G1
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThetaWindowLayout {
    pub(crate) rot_points_word: usize,
    pub(crate) x1_powers_word: usize,
    pub(crate) q_com_word: usize,
    pub(crate) q_eval_set_word: usize,
    pub(crate) q_eval_cptr_word: usize,
    pub(crate) g1_identity_word: usize,
    pub(crate) reversed_evals_word: usize,
    pub(crate) rot_points_cap_words: usize,
    pub(crate) x1_powers_cap_words: usize,
    pub(crate) q_com_cap_words: usize,
    pub(crate) q_eval_set_cap_words: usize,
}

impl ThetaWindowLayout {
    /// Return the historical theta-rooted window layout.
    ///
    /// Debug assertions tie the derived offsets back to `layout::theta_window`
    /// so future edits cannot drift silently.
    pub(crate) fn compatibility() -> Self {
        let rot_points_word = ThetaSlot::PairingRhs.word() + G1_WORDS;
        let x1_powers_word = rot_points_word + theta_window::ROT_POINTS_CAP_WORDS;
        let q_com_word = x1_powers_word + theta_window::X1_POWERS_CAP_WORDS;
        let q_eval_set_word = q_com_word;
        let q_eval_cptr_word = q_eval_set_word + theta_window::Q_EVAL_SET_CAP_WORDS;
        let g1_identity_word = q_eval_cptr_word + 1 + theta_window::Q_EVAL_CPTR_PADDING_WORDS;
        let reversed_evals_word =
            g1_identity_word + G1_WORDS + theta_window::G1_IDENTITY_PADDING_WORDS;

        debug_assert_eq!(rot_points_word, theta_window::ROT_POINTS_WORD);
        debug_assert_eq!(x1_powers_word, theta_window::X1_POWERS_WORD);
        debug_assert_eq!(q_com_word, theta_window::Q_COM_WORD);
        debug_assert_eq!(q_eval_set_word, theta_window::Q_EVAL_SET_WORD);
        debug_assert_eq!(q_eval_cptr_word, theta_window::Q_EVAL_CPTR_WORD);
        debug_assert_eq!(g1_identity_word, theta_window::G1_IDENTITY_WORD);
        debug_assert_eq!(reversed_evals_word, theta_window::REVERSED_EVALS_WORD);

        Self {
            rot_points_word,
            x1_powers_word,
            q_com_word,
            q_eval_set_word,
            q_eval_cptr_word,
            g1_identity_word,
            reversed_evals_word,
            rot_points_cap_words: theta_window::ROT_POINTS_CAP_WORDS,
            x1_powers_cap_words: theta_window::X1_POWERS_CAP_WORDS,
            q_com_cap_words: theta_window::Q_COM_CAP_WORDS,
            q_eval_set_cap_words: theta_window::Q_EVAL_SET_CAP_WORDS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum MemoryPhase {
    /// Generated verifying-key constructor return payload.
    VkConstructorPayload,
    /// Constructor-only precompile smoke tests.
    ConstructorSmoke,
    /// Streaming Fiat-Shamir buffer before generated VK memory is live.
    Transcript,
    /// Conservative legacy low-memory decompression working set.
    LegacyDecompressionScratch,
    /// Single scalar inversion scratch used by the modexp wrapper.
    ScalarInv,
    /// Batch inversion for Lagrange denominator terms.
    LagrangeBatchInvert,
    /// Compact quotient VM temps and stack.
    QuotientVm,
    /// Historical fixed PCS windows rooted at `ROT_POINTS_MPTR`.
    PcsFixed,
    /// Source-address table used by the rolled q_eval fold.
    PcsQEvalSourceTable,
    /// Optional trace-only q_com MSM materialization.
    PcsQComTrace,
    /// Fused final PCS MSM input buffer.
    PcsFinalMsm,
    /// Low-memory PCS pairing input helpers.
    PcsPairing,
    /// Public-accumulator MSM input buffer.
    AccumulatorMsm,
    /// Public-accumulator pairing-batch hash and two G1 add/MSM frames.
    AccumulatorPairingBatch,
    /// Final two-pair KZG pairing frame.
    FinalPairing,
    /// Main verifier return word.
    VerifierReturn,
    /// Standalone quotient evaluator output frame.
    QuotientReturn,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MemoryLifetime {
    /// Region can be read after it is written and must never overlap another
    /// live region.
    Permanent,
    /// Region is live only during the named phase. Regions in different phases
    /// may reuse the same byte range.
    Phase(MemoryPhase),
}

impl MemoryLifetime {
    /// Return whether two lifetimes can be live at the same time.
    fn intersects(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Permanent, _) | (_, Self::Permanent) => true,
            (Self::Phase(lhs), Self::Phase(rhs)) => lhs == rhs,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MemoryRegion {
    /// Stable human-readable region name used in validation errors.
    pub(crate) name: &'static str,
    /// Start byte offset in EVM memory.
    pub(crate) start: usize,
    /// Length in bytes. Zero-length regions are allowed for optional paths.
    pub(crate) len: usize,
    /// Permanent or phase-bounded lifetime.
    pub(crate) lifetime: MemoryLifetime,
}

impl MemoryRegion {
    /// Create a named region at an absolute byte range with a lifetime.
    pub(crate) fn new(
        name: &'static str,
        start: usize,
        len: usize,
        lifetime: MemoryLifetime,
    ) -> Self {
        Self {
            name,
            start,
            len,
            lifetime,
        }
    }

    /// End byte offset, exclusive.
    fn end(&self) -> usize {
        self.start + self.len
    }

    /// Return whether two non-empty byte ranges overlap.
    fn overlaps(&self, other: &Self) -> bool {
        self.len != 0 && other.len != 0 && self.start < other.end() && other.start < self.end()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MemoryMap {
    regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    /// Register a region for later validation.
    pub(crate) fn push(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Find a region by name for tests.
    #[cfg(test)]
    pub(crate) fn region(&self, name: &str) -> Option<&MemoryRegion> {
        self.regions.iter().find(|region| region.name == name)
    }

    /// Validate alignment, Solidity reserved-memory rules, and live overlap.
    pub(crate) fn validate(&self) -> Result<(), String> {
        // All generated Yul uses word-granular `mload`, `mstore`, and
        // precompile input lengths. Byte-granular ranges would be a bug, not a
        // clever packing opportunity.
        for region in &self.regions {
            if region.len != 0 && region.start < SOLIDITY_RESERVED_MEMORY_BYTES {
                let reserved_name = if region.start < SOLIDITY_SCRATCH_SPACE_BYTES {
                    "scratch space"
                } else if region.start < SOLIDITY_ZERO_SLOT {
                    debug_assert_eq!(
                        SOLIDITY_FREE_MEMORY_POINTER_SLOT,
                        SOLIDITY_SCRATCH_SPACE_BYTES
                    );
                    "free-memory pointer"
                } else {
                    "zero slot"
                };
                return Err(format!(
                    "memory region {} starts at {:#x}, inside Solidity-reserved {reserved_name} memory [0x00..{:#x})",
                    region.name, region.start, SOLIDITY_RESERVED_MEMORY_BYTES
                ));
            }
            if region.start % WORD_BYTES != 0 {
                return Err(format!(
                    "memory region {} starts at unaligned byte offset {:#x}",
                    region.name, region.start
                ));
            }
            if region.len % WORD_BYTES != 0 {
                return Err(format!(
                    "memory region {} has unaligned length {:#x}",
                    region.name, region.len
                ));
            }
        }

        // Permanent regions intersect every phase. Scratch regions intersect
        // only when the generator says they are live in the same phase.
        for (idx, lhs) in self.regions.iter().enumerate() {
            for rhs in self.regions.iter().skip(idx + 1) {
                if lhs.overlaps(rhs) && lhs.lifetime.intersects(&rhs.lifetime) {
                    return Err(format!(
                        "memory region {} [{:#x}..{:#x}) overlaps {} [{:#x}..{:#x})",
                        lhs.name,
                        lhs.start,
                        lhs.end(),
                        rhs.name,
                        rhs.start,
                        rhs.end()
                    ));
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MemoryArena {
    map: MemoryMap,
}

impl MemoryArena {
    /// Register a region at an explicit historical or precompile-required
    /// byte address.
    pub(crate) fn alloc_fixed(
        &mut self,
        name: &'static str,
        start: usize,
        len: usize,
        lifetime: MemoryLifetime,
    ) -> usize {
        self.map.push(MemoryRegion::new(name, start, len, lifetime));
        start
    }

    /// Register a region immediately after an existing anchor range, rounded
    /// up to the next EVM word. This is the compatibility-mode equivalent of
    /// "place this after that", without trying to repack earlier anchors.
    pub(crate) fn alloc_after(
        &mut self,
        name: &'static str,
        anchor_start: usize,
        anchor_len: usize,
        len: usize,
        lifetime: MemoryLifetime,
    ) -> usize {
        let start = (anchor_start + anchor_len).next_multiple_of(WORD_BYTES);
        self.alloc_fixed(name, start, len, lifetime)
    }

    /// Register fixed-address scratch that is live only during one phase.
    pub(crate) fn alloc_phase_scratch(
        &mut self,
        name: &'static str,
        start: usize,
        len: usize,
        phase: MemoryPhase,
    ) -> usize {
        self.alloc_fixed(name, start, len, MemoryLifetime::Phase(phase))
    }

    /// Create a phase-aware scratch allocator rooted at `base`.
    ///
    /// Each phase has its own cursor, so allocations in different phases reuse
    /// `base`, while multiple allocations in the same phase advance
    /// sequentially. That exactly models the current verifier's intentional
    /// scratch aliasing without changing byte addresses.
    pub(crate) fn scratch_allocator(&mut self, base: usize) -> ScratchAllocator<'_> {
        ScratchAllocator {
            arena: self,
            base,
            cursors: BTreeMap::new(),
        }
    }

    /// Consume the arena and return its registered map.
    pub(crate) fn into_map(self) -> MemoryMap {
        self.map
    }
}

/// Phase-aware scratch allocator that reuses a base across disjoint phases.
pub(crate) struct ScratchAllocator<'arena> {
    arena: &'arena mut MemoryArena,
    base: usize,
    cursors: BTreeMap<MemoryPhase, usize>,
}

impl ScratchAllocator<'_> {
    /// Allocate phase-scoped scratch from this allocator's base.
    pub(crate) fn alloc_phase_scratch(
        &mut self,
        name: &'static str,
        len: usize,
        phase: MemoryPhase,
    ) -> usize {
        let cursor = self.cursors.entry(phase).or_insert(self.base);
        let start = *cursor;
        *cursor = (start + len).next_multiple_of(WORD_BYTES);
        self.arena.alloc_phase_scratch(name, start, len, phase)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FinalMsmShape {
    /// Number of `(G1, scalar)` pairs emitted for this MSM.
    pub(crate) terms: usize,
    /// Total G1MSM input length in bytes.
    pub(crate) input_bytes: usize,
}

impl FinalMsmShape {
    /// Build a shape from a number of `(G1, scalar)` pairs.
    pub(crate) fn from_terms(terms: usize) -> Self {
        Self {
            terms,
            input_bytes: terms * G1_MSM_PAIR_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PcsMemoryRequirements {
    /// Distinct rotation points stored at `ROT_POINTS_MPTR`.
    pub(crate) rot_points_words: usize,
    /// Powers of `x1` stored at `X1_POWERS_MPTR`.
    pub(crate) x1_powers_words: usize,
    /// Legacy q_com window. Currently zero because production emission fuses
    /// q_com terms directly into final MSM scratch.
    pub(crate) q_com_words: usize,
    /// Folded q_eval scalars stored at `Q_EVAL_SET_MPTR`.
    pub(crate) q_eval_set_words: usize,
    /// Rolled q_eval source-address table size.
    pub(crate) q_eval_source_table_words: usize,
    /// Optional trace MSM used to materialize q_com per point set.
    pub(crate) q_com_trace_msm: FinalMsmShape,
    /// Production fused final PCS MSM.
    pub(crate) final_msm: FinalMsmShape,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifierMemoryLayout {
    pub(crate) map: MemoryMap,
    pub(crate) theta_windows: ThetaWindowLayout,
    /// Fixed low-memory scratch for constructor EIP-2537 smoke checks.
    pub(crate) constructor_smoke_scratch_mptr: usize,
    /// Base of the streaming transcript buffer.
    pub(crate) transcript_mptr: usize,
    /// Conservative low-memory working set retained for legacy proof
    /// decompression bounds.
    pub(crate) legacy_decompression_scratch_mptr: usize,
    /// Low-memory scratch used by the PCS pairing-preparation helper.
    pub(crate) pcs_pairing_scratch_mptr: usize,
    /// Low-memory output word used by the main verifier.
    pub(crate) verifier_return_mptr: usize,
    /// Low-memory output frame used by the standalone quotient evaluator.
    pub(crate) quotient_return_mptr: usize,
    /// Start of the copied or embedded verifying-key payload.
    pub(crate) vk_mptr: Ptr,
    /// Scratch frame used by the scalar-inversion modexp wrapper.
    pub(crate) scalar_inv_scratch_mptr: usize,
    /// Start of the variable-length user-challenge block after the VK payload.
    pub(crate) challenge_mptr: Ptr,
    /// Anchor for every historical fixed verifier slot below.
    pub(crate) theta_mptr: Ptr,
    pub(crate) beta_mptr: Ptr,
    pub(crate) gamma_mptr: Ptr,
    pub(crate) trash_challenge_mptr: Ptr,
    pub(crate) y_mptr: Ptr,
    pub(crate) x_mptr: Ptr,
    pub(crate) x1_mptr: Ptr,
    pub(crate) x2_mptr: Ptr,
    pub(crate) x3_mptr: Ptr,
    pub(crate) x4_mptr: Ptr,
    pub(crate) f_com_mptr: Ptr,
    pub(crate) pi_mptr: Ptr,
    pub(crate) acc_lhs_mptr: Ptr,
    pub(crate) acc_rhs_mptr: Ptr,
    pub(crate) x_n_mptr: Ptr,
    pub(crate) x_n_minus_1_inv_mptr: Ptr,
    pub(crate) l_last_mptr: Ptr,
    pub(crate) l_blind_mptr: Ptr,
    pub(crate) l_0_mptr: Ptr,
    pub(crate) instance_eval_mptr: Ptr,
    pub(crate) quotient_eval_mptr: Ptr,
    pub(crate) quotient_mptr: Ptr,
    pub(crate) f_eval_mptr: Ptr,
    pub(crate) v_mptr: Ptr,
    pub(crate) final_com_mptr: Ptr,
    pub(crate) pairing_lhs_mptr: Ptr,
    pub(crate) pairing_rhs_mptr: Ptr,
    pub(crate) rot_points_mptr: Ptr,
    pub(crate) x1_powers_mptr: Ptr,
    pub(crate) q_com_mptr: Ptr,
    pub(crate) q_eval_set_mptr: Ptr,
    pub(crate) q_eval_cptr_mptr: Ptr,
    pub(crate) g1_identity_mptr: Ptr,
    pub(crate) reversed_evals_mptr: Ptr,
    pub(crate) comms_mptr_base: Ptr,
    pub(crate) advice_comms_mptr_base: Ptr,
    pub(crate) lookup_m_comms_mptr_base: Ptr,
    pub(crate) perm_z_comms_mptr_base: Ptr,
    pub(crate) lookup_helper_comms_mptr_base: Ptr,
    pub(crate) lookup_z_comms_mptr_base: Ptr,
    pub(crate) trashcan_comms_mptr_base: Ptr,
    pub(crate) quotient_limb_comms_mptr_base: Ptr,
    /// First byte after all decompressed proof commitments. Selector
    /// accumulators are live here during final linearization/final MSM.
    pub(crate) selector_acc_mptr: usize,
    /// Reuses selector-accumulator bytes during the earlier Lagrange batch
    /// inversion phase.
    pub(crate) batch_invert_scratch_mptr: usize,
    /// First quotient VM temporary. Also the canonical PCS scratch base once
    /// selector accumulators are accounted for.
    pub(crate) quotient_tmp_mptr: usize,
    pub(crate) quotient_stack_mptr: usize,
    pub(crate) pcs_q_eval_source_table_mptr: usize,
    pub(crate) pcs_q_com_trace_scratch_mptr: usize,
    pub(crate) pcs_final_msm_scratch_mptr: usize,
    /// Public accumulator MSM buffer, historically floored at 0x7000.
    pub(crate) acc_msm_scratch: usize,
    /// Low-memory transcript hash frame used to batch the accumulator pairing
    /// equation with the KZG pairing equation.
    pub(crate) accumulator_pairing_batch_mptr: usize,
    /// Final KZG two-pairing precompile input frame.
    pub(crate) final_pairing_scratch_mptr: usize,
    /// One-word buffer used only to materialize LOG data for trace builds.
    /// It is planned after every permanent and scratch region because
    /// `trace_u256` may be called between long-lived reads from the VK,
    /// decoded evals, and decompressed commitments.
    pub(crate) trace_u256_mptr: usize,
    pub(crate) pcs: PcsMemoryRequirements,
}

/// Memory map for the generated verifying-key constructor.
///
/// The VK contract is a separate deployment/runtime context from the verifier,
/// so its constructor payload cannot be mixed into `VerifierMemoryLayout` without
/// creating fake overlaps with verifier-runtime permanent regions. This small
/// layout still keeps the fixed `0x80` payload pointer registered and validated
/// by the same `MemoryMap` rules.
#[derive(Clone, Debug)]
pub(crate) struct VkConstructorMemoryLayout {
    pub(crate) map: MemoryMap,
    /// Constructor return-runtime buffer.
    pub(crate) payload_mptr: usize,
}

impl VkConstructorMemoryLayout {
    /// Register the fixed constructor runtime buffer for a VK runtime length.
    pub(crate) fn new(runtime_len: usize) -> Self {
        let mut arena = MemoryArena::default();
        let reserved_len = runtime_len.next_multiple_of(WORD_BYTES);
        let payload_mptr = arena.alloc_phase_scratch(
            "vk_constructor_payload",
            VK_CONSTRUCTOR_PAYLOAD_START,
            reserved_len,
            MemoryPhase::VkConstructorPayload,
        );
        Self {
            map: arena.into_map(),
            payload_mptr,
        }
    }

    /// Validate the constructor payload pointer and memory map.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.payload_mptr != VK_CONSTRUCTOR_PAYLOAD_START {
            return Err(format!(
                "VK constructor payload pointer drifted: got {:#x}, expected {VK_CONSTRUCTOR_PAYLOAD_START:#x}",
                self.payload_mptr
            ));
        }
        self.map.validate()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct VerifierMemoryLayoutConfig {
    /// Maximum live transcript-buffer words before a squeeze/reset.
    pub(crate) transcript_words: usize,
    /// Public instance count, needed to size the Lagrange batch-inversion
    /// input range.
    pub(crate) num_instances: usize,
    /// Compact quotient VM common-subexpression temp count.
    pub(crate) quotient_cse_temps: usize,
    /// Maximum compact quotient VM stack/scratch words. Native quotient
    /// callbacks may share the VM stack base, so callers must include those
    /// callback-specific scratch requirements in this count.
    pub(crate) quotient_stack_words: usize,
    /// Number of `(G1, scalar)` pairs in the public-accumulator MSM.
    pub(crate) acc_msm_terms: usize,
    /// PCS fixed-window and scratch requirements computed from the circuit and
    /// VK query shape.
    pub(crate) pcs: PcsMemoryRequirements,
}

impl VerifierMemoryLayout {
    /// Plan the generated verifier's complete memory map.
    ///
    /// The function preserves historical permanent addresses first, then
    /// registers scratch regions with explicit phases so intentional aliasing
    /// is validated instead of accidental.
    pub(crate) fn new(
        meta: &ConstraintSystemMeta,
        vk: &Halo2VerifyingKey,
        vk_mptr: Ptr,
        config: VerifierMemoryLayoutConfig,
    ) -> Self {
        let commitments_len = commitment_g1_count(meta) * G1_BYTES;
        let selector_len = meta.num_simple_selectors * WORD_BYTES;
        let quotient_tmp_len = config.quotient_cse_temps * WORD_BYTES;
        let quotient_stack_len = config.quotient_stack_words * WORD_BYTES;
        let q_eval_source_len = config.pcs.q_eval_source_table_words * WORD_BYTES;
        let q_com_trace_len = config.pcs.q_com_trace_msm.input_bytes;
        let final_msm_len = config.pcs.final_msm.input_bytes;
        let acc_msm_len = config.acc_msm_terms * G1_MSM_PAIR_BYTES;
        let batch_invert_len = batch_invert_scratch_bytes(meta, config.num_instances);
        let quotient_return_len = (2 + meta.num_simple_selectors) * WORD_BYTES;

        let mut arena = MemoryArena::default();
        let theta_windows = ThetaWindowLayout::compatibility();

        // Low-memory helpers are phase-scoped because the transcript buffer is
        // no longer live once algebra/precompile work begins.
        let constructor_smoke_scratch_mptr = arena.alloc_phase_scratch(
            "constructor_smoke_scratch",
            LOW_MEMORY_SCRATCH_START,
            PAIRING_PAIR_BYTES,
            MemoryPhase::ConstructorSmoke,
        );
        let transcript_mptr = arena.alloc_phase_scratch(
            "transcript_buffer",
            TRANSCRIPT_BUFFER_START,
            config.transcript_words * WORD_BYTES,
            MemoryPhase::Transcript,
        );
        let legacy_decompression_scratch_mptr = arena.alloc_phase_scratch(
            "legacy_decompression_scratch",
            LOW_MEMORY_SCRATCH_START,
            MODEXP_DECOMPRESSION_WORKING_WORDS * WORD_BYTES,
            MemoryPhase::LegacyDecompressionScratch,
        );
        let pcs_pairing_scratch_mptr = arena.alloc_phase_scratch(
            "pcs_pairing_static_working",
            PCS_PAIRING_SCRATCH_START,
            PCS_STATIC_WORKING_WORDS * WORD_BYTES,
            MemoryPhase::PcsPairing,
        );
        let verifier_return_mptr = arena.alloc_phase_scratch(
            "verifier_return",
            VERIFIER_RETURN_BUFFER_START,
            WORD_BYTES,
            MemoryPhase::VerifierReturn,
        );
        let quotient_return_mptr = arena.alloc_phase_scratch(
            "quotient_return",
            QUOTIENT_RETURN_BUFFER_START,
            quotient_return_len,
            MemoryPhase::QuotientReturn,
        );
        let final_pairing_scratch_mptr = arena.alloc_phase_scratch(
            "final_pairing_scratch",
            crate::codegen::layout::FINAL_PAIRING_SCRATCH_START,
            PAIRING_STATIC_WORKING_WORDS * WORD_BYTES,
            MemoryPhase::FinalPairing,
        );

        // VK bytes are copied first, then user-phase challenge slots, then
        // the fixed theta-relative region. The caller is responsible for
        // choosing a stable `vk_mptr` after proof-shape planning; this keeps
        // the transcript buffer below the VK payload.
        let vk_start = arena.alloc_fixed(
            "vk_payload",
            vk_mptr.value().as_usize(),
            vk.len(),
            MemoryLifetime::Permanent,
        );
        let scalar_inv_scratch_mptr = arena.alloc_phase_scratch(
            "scalar_inv_scratch",
            vk_start.saturating_sub(MODEXP_SCRATCH_BYTES),
            MODEXP_FRAME_BYTES,
            MemoryPhase::ScalarInv,
        );
        let challenge_start = arena.alloc_after(
            "challenge_slots",
            vk_start,
            vk.len(),
            meta.challenge_indices.len() * WORD_BYTES,
            MemoryLifetime::Permanent,
        );
        let theta_start = arena.alloc_after(
            "theta_scalar_and_g1_slots",
            challenge_start,
            meta.challenge_indices.len() * WORD_BYTES,
            theta_windows.rot_points_word * WORD_BYTES,
            MemoryLifetime::Permanent,
        );
        let challenge_mptr = Ptr::memory(challenge_start);
        let at_theta = |words: usize| theta_start + words * WORD_BYTES;
        let ptr_at_theta = |slot: ThetaSlot| Ptr::memory(at_theta(slot.word()));
        let theta_mptr = ptr_at_theta(ThetaSlot::Theta);

        let total_advices: usize = meta.num_user_advices.iter().sum();
        let lookup_helper_chunks_total: usize = meta.lookup_chunks.iter().sum();
        // Commitment memory mirrors the proof read schedule but is stored by
        // category. PCS and quotient code take typed bases for each category so
        // these offsets are the single source of truth for all later mloads.
        let non_quotient_g1s = total_advices
            + meta.num_lookups
            + meta.num_permutation_zs
            + lookup_helper_chunks_total
            + meta.num_lookups
            + meta.num_trashcans;
        let committed_g1s = non_quotient_g1s + meta.num_quotients;
        let rot_points_mptr = Ptr::memory(arena.alloc_fixed(
            "rot_points",
            at_theta(theta_windows.rot_points_word),
            config.pcs.rot_points_words * WORD_BYTES,
            MemoryLifetime::Phase(MemoryPhase::PcsFixed),
        ));
        let x1_powers_mptr = Ptr::memory(arena.alloc_fixed(
            "x1_powers",
            at_theta(theta_windows.x1_powers_word),
            config.pcs.x1_powers_words * WORD_BYTES,
            MemoryLifetime::Phase(MemoryPhase::PcsFixed),
        ));
        let q_com_mptr = Ptr::memory(arena.alloc_fixed(
            "q_com_fixed_window",
            at_theta(theta_windows.q_com_word),
            config.pcs.q_com_words * WORD_BYTES,
            MemoryLifetime::Phase(MemoryPhase::PcsFixed),
        ));
        let q_eval_set_mptr = Ptr::memory(arena.alloc_fixed(
            "q_eval_set",
            at_theta(theta_windows.q_eval_set_word),
            config.pcs.q_eval_set_words * WORD_BYTES,
            MemoryLifetime::Phase(MemoryPhase::PcsFixed),
        ));
        let q_eval_cptr_mptr = Ptr::memory(arena.alloc_fixed(
            "q_eval_cptr_slot",
            at_theta(theta_windows.q_eval_cptr_word),
            WORD_BYTES,
            MemoryLifetime::Permanent,
        ));
        let g1_identity_mptr = Ptr::memory(arena.alloc_fixed(
            "g1_identity",
            at_theta(theta_windows.g1_identity_word),
            G1_BYTES,
            MemoryLifetime::Permanent,
        ));
        let reversed_evals_mptr = Ptr::memory(arena.alloc_fixed(
            "decoded_evals",
            at_theta(theta_windows.reversed_evals_word),
            meta.num_evals * WORD_BYTES,
            MemoryLifetime::Permanent,
        ));
        let comms_mptr_base = Ptr::memory(arena.alloc_after(
            "decompressed_commitments",
            reversed_evals_mptr.value().as_usize(),
            meta.num_evals * WORD_BYTES,
            commitments_len,
            MemoryLifetime::Permanent,
        ));
        let advice_comms_mptr_base = comms_mptr_base;
        let lookup_m_comms_mptr_base = advice_comms_mptr_base + G1_WORDS * total_advices;
        let perm_z_comms_mptr_base = lookup_m_comms_mptr_base + G1_WORDS * meta.num_lookups;
        let lookup_helper_comms_mptr_base =
            perm_z_comms_mptr_base + G1_WORDS * meta.num_permutation_zs;
        let lookup_z_comms_mptr_base =
            lookup_helper_comms_mptr_base + G1_WORDS * lookup_helper_chunks_total;
        let trashcan_comms_mptr_base = lookup_z_comms_mptr_base + G1_WORDS * meta.num_lookups;
        let quotient_limb_comms_mptr_base =
            trashcan_comms_mptr_base + G1_WORDS * meta.num_trashcans;

        // Decompressed proof commitments are stored contiguously by category.
        // Everything after this point is either selector state or scratch.
        let after_comms = comms_mptr_base.value().as_usize() + committed_g1s * G1_BYTES;
        let selector_acc_mptr = arena.alloc_after(
            "selector_accumulators",
            comms_mptr_base.value().as_usize(),
            commitments_len,
            selector_len,
            MemoryLifetime::Phase(MemoryPhase::PcsFinalMsm),
        );
        let batch_invert_scratch_mptr = {
            let mut scratch = arena.scratch_allocator(selector_acc_mptr);
            scratch.alloc_phase_scratch(
                "batch_invert_scratch",
                batch_invert_len,
                MemoryPhase::LagrangeBatchInvert,
            )
        };
        let quotient_tmp_base = (selector_acc_mptr + selector_len).next_multiple_of(WORD_BYTES);
        let (quotient_tmp_mptr, quotient_stack_mptr) = {
            let mut scratch = arena.scratch_allocator(quotient_tmp_base);
            let quotient_tmp_mptr = scratch.alloc_phase_scratch(
                "quotient_temps",
                quotient_tmp_len,
                MemoryPhase::QuotientVm,
            );
            let quotient_stack_mptr = scratch.alloc_phase_scratch(
                "quotient_stack",
                quotient_stack_len.max(MODEXP_FRAME_BYTES),
                MemoryPhase::QuotientVm,
            );
            (quotient_tmp_mptr, quotient_stack_mptr)
        };
        let pcs_scratch_mptr = quotient_tmp_mptr;
        let (
            pcs_q_eval_source_table_mptr,
            pcs_q_com_trace_scratch_mptr,
            pcs_final_msm_scratch_mptr,
        ) = {
            let mut scratch = arena.scratch_allocator(pcs_scratch_mptr);
            let q_eval = scratch.alloc_phase_scratch(
                "pcs_q_eval_source_table",
                q_eval_source_len,
                MemoryPhase::PcsQEvalSourceTable,
            );
            let q_com = scratch.alloc_phase_scratch(
                "pcs_q_com_trace_msm",
                q_com_trace_len,
                MemoryPhase::PcsQComTrace,
            );
            let final_msm = scratch.alloc_phase_scratch(
                "pcs_final_msm",
                final_msm_len,
                MemoryPhase::PcsFinalMsm,
            );
            (q_eval, q_com, final_msm)
        };
        let acc_msm_scratch_base = after_comms
            .max(ACC_MSM_MIN_SCRATCH_BYTES)
            .next_multiple_of(WORD_BYTES);
        let acc_msm_scratch = {
            let mut scratch = arena.scratch_allocator(acc_msm_scratch_base);
            scratch.alloc_phase_scratch("accumulator_msm", acc_msm_len, MemoryPhase::AccumulatorMsm)
        };
        let accumulator_pairing_batch_mptr = arena.alloc_phase_scratch(
            "accumulator_pairing_batch",
            crate::codegen::layout::accumulator::PAIRING_BATCH_PTR,
            ACCUMULATOR_PAIRING_BATCH_BYTES,
            MemoryPhase::AccumulatorPairingBatch,
        );
        // Trace logging can occur between otherwise long-lived reads, so its
        // one-word scratch is placed after every registered region rather than
        // borrowing any phase-specific base.
        let trace_u256_mptr = [
            constructor_smoke_scratch_mptr + PAIRING_PAIR_BYTES,
            transcript_mptr + config.transcript_words * WORD_BYTES,
            legacy_decompression_scratch_mptr + MODEXP_DECOMPRESSION_WORKING_WORDS * WORD_BYTES,
            pcs_pairing_scratch_mptr + PCS_STATIC_WORKING_WORDS * WORD_BYTES,
            verifier_return_mptr + WORD_BYTES,
            quotient_return_mptr + quotient_return_len,
            final_pairing_scratch_mptr + PAIRING_STATIC_WORKING_WORDS * WORD_BYTES,
            scalar_inv_scratch_mptr + MODEXP_FRAME_BYTES,
            vk_start + vk.len(),
            challenge_start + meta.challenge_indices.len() * WORD_BYTES,
            theta_start + theta_windows.rot_points_word * WORD_BYTES,
            g1_identity_mptr.value().as_usize() + G1_BYTES,
            reversed_evals_mptr.value().as_usize() + meta.num_evals * WORD_BYTES,
            comms_mptr_base.value().as_usize() + commitments_len,
            selector_acc_mptr + selector_len,
            batch_invert_scratch_mptr + batch_invert_len,
            quotient_stack_mptr + quotient_stack_len.max(MODEXP_FRAME_BYTES),
            pcs_q_eval_source_table_mptr + q_eval_source_len,
            pcs_q_com_trace_scratch_mptr + q_com_trace_len,
            pcs_final_msm_scratch_mptr + final_msm_len,
            acc_msm_scratch + acc_msm_len,
            accumulator_pairing_batch_mptr + ACCUMULATOR_PAIRING_BATCH_BYTES,
        ]
        .into_iter()
        .max()
        .expect("trace scratch bounds are non-empty")
        .next_multiple_of(WORD_BYTES);
        arena.alloc_fixed(
            "trace_u256_log_word",
            trace_u256_mptr,
            WORD_BYTES,
            MemoryLifetime::Permanent,
        );

        Self {
            map: arena.into_map(),
            theta_windows,
            constructor_smoke_scratch_mptr,
            transcript_mptr,
            legacy_decompression_scratch_mptr,
            pcs_pairing_scratch_mptr,
            verifier_return_mptr,
            quotient_return_mptr,
            vk_mptr,
            scalar_inv_scratch_mptr,
            challenge_mptr,
            theta_mptr,
            beta_mptr: ptr_at_theta(ThetaSlot::Beta),
            gamma_mptr: ptr_at_theta(ThetaSlot::Gamma),
            trash_challenge_mptr: ptr_at_theta(ThetaSlot::TrashChallenge),
            y_mptr: ptr_at_theta(ThetaSlot::Y),
            x_mptr: ptr_at_theta(ThetaSlot::X),
            x1_mptr: ptr_at_theta(ThetaSlot::X1),
            x2_mptr: ptr_at_theta(ThetaSlot::X2),
            x3_mptr: ptr_at_theta(ThetaSlot::X3),
            x4_mptr: ptr_at_theta(ThetaSlot::X4),
            f_com_mptr: ptr_at_theta(ThetaSlot::FCom),
            pi_mptr: ptr_at_theta(ThetaSlot::Pi),
            acc_lhs_mptr: ptr_at_theta(ThetaSlot::AccLhs),
            acc_rhs_mptr: ptr_at_theta(ThetaSlot::AccRhs),
            x_n_mptr: ptr_at_theta(ThetaSlot::XN),
            x_n_minus_1_inv_mptr: ptr_at_theta(ThetaSlot::XNMinus1Inv),
            l_last_mptr: ptr_at_theta(ThetaSlot::LLast),
            l_blind_mptr: ptr_at_theta(ThetaSlot::LBlind),
            l_0_mptr: ptr_at_theta(ThetaSlot::L0),
            instance_eval_mptr: ptr_at_theta(ThetaSlot::InstanceEval),
            quotient_eval_mptr: ptr_at_theta(ThetaSlot::QuotientEval),
            quotient_mptr: ptr_at_theta(ThetaSlot::Quotient),
            f_eval_mptr: ptr_at_theta(ThetaSlot::FEval),
            v_mptr: ptr_at_theta(ThetaSlot::V),
            final_com_mptr: ptr_at_theta(ThetaSlot::FinalCom),
            pairing_lhs_mptr: ptr_at_theta(ThetaSlot::PairingLhs),
            pairing_rhs_mptr: ptr_at_theta(ThetaSlot::PairingRhs),
            rot_points_mptr,
            x1_powers_mptr,
            q_com_mptr,
            q_eval_set_mptr,
            q_eval_cptr_mptr,
            g1_identity_mptr,
            reversed_evals_mptr,
            comms_mptr_base,
            advice_comms_mptr_base,
            lookup_m_comms_mptr_base,
            perm_z_comms_mptr_base,
            lookup_helper_comms_mptr_base,
            lookup_z_comms_mptr_base,
            trashcan_comms_mptr_base,
            quotient_limb_comms_mptr_base,
            selector_acc_mptr,
            batch_invert_scratch_mptr,
            quotient_tmp_mptr,
            quotient_stack_mptr,
            pcs_q_eval_source_table_mptr,
            pcs_q_com_trace_scratch_mptr,
            pcs_final_msm_scratch_mptr,
            acc_msm_scratch,
            accumulator_pairing_batch_mptr,
            final_pairing_scratch_mptr,
            trace_u256_mptr,
            pcs: config.pcs,
        }
    }

    /// Validate fixed-window capacities and registered memory lifetimes.
    pub(crate) fn validate(&self) -> Result<(), String> {
        let fixed_low_memory = [
            (
                "constructor_smoke_scratch_mptr",
                self.constructor_smoke_scratch_mptr,
                LOW_MEMORY_SCRATCH_START,
            ),
            (
                "transcript_mptr",
                self.transcript_mptr,
                TRANSCRIPT_BUFFER_START,
            ),
            (
                "legacy_decompression_scratch_mptr",
                self.legacy_decompression_scratch_mptr,
                LOW_MEMORY_SCRATCH_START,
            ),
            (
                "pcs_pairing_scratch_mptr",
                self.pcs_pairing_scratch_mptr,
                PCS_PAIRING_SCRATCH_START,
            ),
            (
                "verifier_return_mptr",
                self.verifier_return_mptr,
                VERIFIER_RETURN_BUFFER_START,
            ),
            (
                "quotient_return_mptr",
                self.quotient_return_mptr,
                QUOTIENT_RETURN_BUFFER_START,
            ),
            (
                "accumulator_pairing_batch_mptr",
                self.accumulator_pairing_batch_mptr,
                crate::codegen::layout::accumulator::PAIRING_BATCH_PTR,
            ),
            (
                "final_pairing_scratch_mptr",
                self.final_pairing_scratch_mptr,
                crate::codegen::layout::FINAL_PAIRING_SCRATCH_START,
            ),
        ];
        for (name, actual, expected) in fixed_low_memory {
            if actual != expected {
                return Err(format!(
                    "fixed memory pointer {name} drifted: got {actual:#x}, expected {expected:#x}"
                ));
            }
        }

        let expected_scalar_inv = self
            .vk_mptr
            .value()
            .as_usize()
            .saturating_sub(MODEXP_SCRATCH_BYTES);
        if self.scalar_inv_scratch_mptr != expected_scalar_inv {
            return Err(format!(
                "scalar inversion scratch drifted: got {:#x}, expected {expected_scalar_inv:#x}",
                self.scalar_inv_scratch_mptr
            ));
        }

        let windows = self.theta_windows;
        if self.pcs.rot_points_words > windows.rot_points_cap_words {
            return Err(format!(
                "PCS scratch layout mismatch: ROT_POINTS_MPTR needs {} word(s), capacity is {}",
                self.pcs.rot_points_words, windows.rot_points_cap_words
            ));
        }
        if self.pcs.x1_powers_words > windows.x1_powers_cap_words {
            return Err(format!(
                "PCS scratch layout mismatch: X1_POWERS_MPTR needs {} word(s), capacity is {}",
                self.pcs.x1_powers_words, windows.x1_powers_cap_words
            ));
        }
        if self.pcs.q_com_words > windows.q_com_cap_words {
            return Err(format!(
                "PCS scratch layout mismatch: Q_COM_MPTR needs {} word(s), capacity is {}",
                self.pcs.q_com_words, windows.q_com_cap_words
            ));
        }
        if self.pcs.q_eval_set_words > windows.q_eval_set_cap_words {
            return Err(format!(
                "PCS scratch layout mismatch: Q_EVAL_SET_MPTR needs {} word(s), capacity is {}",
                self.pcs.q_eval_set_words, windows.q_eval_set_cap_words
            ));
        }

        self.map.validate()?;

        Ok(())
    }
}

/// Number of proof commitment G1 points materialized in verifier memory.
pub(crate) fn commitment_g1_count(meta: &ConstraintSystemMeta) -> usize {
    meta.num_user_advices.iter().sum::<usize>()
        + meta.num_lookups
        + meta.num_permutation_zs
        + meta.lookup_chunks.iter().sum::<usize>()
        + meta.num_lookups
        + meta.num_trashcans
        + meta.num_quotients
}

/// Scratch size required by the batched scalar-inversion helper.
fn batch_invert_scratch_bytes(meta: &ConstraintSystemMeta, num_instances: usize) -> usize {
    // The template calls:
    //   batch_invert(X_N_MPTR, mptr_end + WORD_BYTES, scratch, r)
    //
    // The input range covers:
    //   - num_instances public Lagrange denominators, or one fallback word
    //     when there are no public instances;
    //   - `abs(rotation_last)` negative-row denominators;
    //   - x_n - 1.
    //
    // For N inputs, the batched inversion stores N-2 prefix products and then
    // overlays one modexp frame at the current prefix pointer. Singletons use
    // only the frame.
    let input_words = if num_instances == 0 {
        meta.rotation_last.unsigned_abs() as usize + 2
    } else {
        num_instances + meta.rotation_last.unsigned_abs() as usize + 1
    };

    MODEXP_FRAME_BYTES + input_words.saturating_sub(2) * WORD_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::template::G1Words;
    use ruint::aliases::U256;

    fn region(name: &'static str, start: usize, len: usize, phase: MemoryPhase) -> MemoryRegion {
        MemoryRegion::new(name, start, len, MemoryLifetime::Phase(phase))
    }

    #[test]
    fn overlapping_permanent_regions_fail() {
        let mut map = MemoryMap::default();
        map.push(MemoryRegion::new(
            "a",
            0x100,
            WORD_BYTES * 2,
            MemoryLifetime::Permanent,
        ));
        map.push(MemoryRegion::new(
            "b",
            0x120,
            WORD_BYTES,
            MemoryLifetime::Permanent,
        ));

        let err = map.validate().unwrap_err();
        assert!(err.contains("overlaps"));
    }

    #[test]
    fn same_bytes_are_allowed_for_disjoint_phases() {
        let mut map = MemoryMap::default();
        map.push(region("a", 0x100, WORD_BYTES, MemoryPhase::QuotientVm));
        map.push(region("b", 0x100, WORD_BYTES, MemoryPhase::PcsFinalMsm));

        map.validate().expect("disjoint scratch lifetimes");
    }

    #[test]
    fn unaligned_regions_fail() {
        let mut map = MemoryMap::default();
        map.push(region("a", 0x101, WORD_BYTES, MemoryPhase::QuotientVm));
        assert!(map.validate().unwrap_err().contains("unaligned"));

        let mut map = MemoryMap::default();
        map.push(region("a", 0x100, WORD_BYTES - 1, MemoryPhase::QuotientVm));
        assert!(map.validate().unwrap_err().contains("unaligned"));
    }

    #[test]
    fn reserved_solidity_memory_regions_fail() {
        let mut map = MemoryMap::default();
        map.push(region(
            "free_memory_pointer",
            crate::codegen::layout::SOLIDITY_FREE_MEMORY_POINTER_SLOT,
            WORD_BYTES,
            MemoryPhase::Transcript,
        ));
        let err = map.validate().unwrap_err();
        assert!(
            err.contains("Solidity-reserved") && err.contains("free-memory pointer"),
            "unexpected validation error: {err}"
        );

        let mut map = MemoryMap::default();
        map.push(region(
            "zero_slot",
            crate::codegen::layout::SOLIDITY_ZERO_SLOT,
            WORD_BYTES,
            MemoryPhase::Transcript,
        ));
        assert!(map.validate().unwrap_err().contains("Solidity-reserved"));
    }

    #[test]
    fn arena_alloc_after_aligns_after_anchor() {
        let mut arena = MemoryArena::default();
        let after = arena.alloc_after(
            "after",
            0x101,
            WORD_BYTES,
            WORD_BYTES,
            MemoryLifetime::Permanent,
        );
        let map = arena.into_map();

        assert_eq!(after, 0x140);
        assert_eq!(map.region("after").unwrap().start, 0x140);
        map.validate().expect("allocated region is word-aligned");
    }

    #[test]
    fn scratch_allocator_reuses_base_across_phases_and_advances_within_phase() {
        let mut arena = MemoryArena::default();
        {
            let mut scratch = arena.scratch_allocator(0x400);
            let first = scratch.alloc_phase_scratch("first", WORD_BYTES, MemoryPhase::QuotientVm);
            let second = scratch.alloc_phase_scratch("second", WORD_BYTES, MemoryPhase::QuotientVm);
            let reused =
                scratch.alloc_phase_scratch("reused", WORD_BYTES, MemoryPhase::PcsFinalMsm);

            assert_eq!(first, 0x400);
            assert_eq!(second, 0x420);
            assert_eq!(reused, 0x400);
        }

        arena
            .into_map()
            .validate()
            .expect("scratch phases may reuse the same base");
    }

    #[test]
    fn vk_constructor_payload_is_planner_registered() {
        let layout = VkConstructorMemoryLayout::new(0x660);
        let region = layout
            .map
            .region("vk_constructor_payload")
            .expect("VK constructor payload registered");

        assert_eq!(layout.payload_mptr, VK_CONSTRUCTOR_PAYLOAD_START);
        assert_eq!(region.start, VK_CONSTRUCTOR_PAYLOAD_START);
        assert_eq!(region.len, 0x660);
        layout.validate().expect("VK constructor layout is valid");
    }

    #[test]
    fn vk_constructor_runtime_region_rounds_up_unaligned_length() {
        let layout = VkConstructorMemoryLayout::new(0x661);
        let region = layout
            .map
            .region("vk_constructor_payload")
            .expect("VK constructor payload registered");

        assert_eq!(layout.payload_mptr, VK_CONSTRUCTOR_PAYLOAD_START);
        assert_eq!(region.start, VK_CONSTRUCTOR_PAYLOAD_START);
        assert_eq!(region.len, 0x680);
        layout
            .validate()
            .expect("unaligned runtime length reserves aligned memory");
    }

    fn synthetic_vk() -> Halo2VerifyingKey {
        let fixed: Vec<G1Words> = vec![(U256::ZERO, U256::ZERO, U256::ZERO, U256::ZERO)];
        let constructor_memory = VkConstructorMemoryLayout::new(
            crate::codegen::layout::VK_HEADER_WORDS * WORD_BYTES + fixed.len() * G1_BYTES,
        );
        Halo2VerifyingKey {
            constructor_payload_mptr: constructor_memory.payload_mptr,
            constants: (0..crate::codegen::layout::VK_HEADER_WORDS)
                .map(|_| ("c", U256::ZERO))
                .collect(),
            fixed_comms: fixed,
            permutation_comms: vec![],
            quotient_const_offset_words: None,
            quotient_const_words: 0,
            quotient_program_offset_words: None,
            quotient_program_words: 0,
        }
    }

    #[test]
    fn synthetic_layout_preserves_current_offsets() {
        let meta = ConstraintSystemMeta {
            num_user_advices: vec![2],
            num_lookups: 1,
            num_permutation_zs: 1,
            lookup_chunks: vec![2],
            num_trashcans: 1,
            num_quotients: 3,
            num_evals: 5,
            ..ConstraintSystemMeta::default()
        };
        let vk = synthetic_vk();
        let layout = VerifierMemoryLayout::new(
            &meta,
            &vk,
            Ptr::memory(0x1000),
            VerifierMemoryLayoutConfig::default(),
        );
        let theta = layout.theta_mptr.value().as_usize();
        let windows = layout.theta_windows;

        assert_eq!(
            layout.rot_points_mptr.value().as_usize(),
            theta + windows.rot_points_word * WORD_BYTES
        );
        assert_eq!(
            layout.x1_powers_mptr.value().as_usize(),
            theta + windows.x1_powers_word * WORD_BYTES
        );
        assert_eq!(
            layout.q_eval_set_mptr.value().as_usize(),
            theta + windows.q_eval_set_word * WORD_BYTES
        );
        assert_eq!(
            layout.q_eval_cptr_mptr.value().as_usize(),
            theta + windows.q_eval_cptr_word * WORD_BYTES
        );
        assert_eq!(
            layout.g1_identity_mptr.value().as_usize(),
            theta + windows.g1_identity_word * WORD_BYTES
        );
        assert_eq!(
            layout.reversed_evals_mptr.value().as_usize(),
            theta + windows.reversed_evals_word * WORD_BYTES
        );
        assert_eq!(
            layout.comms_mptr_base.value().as_usize(),
            theta + (windows.reversed_evals_word + meta.num_evals) * WORD_BYTES
        );
        assert_eq!(windows.rot_points_word, theta_window::ROT_POINTS_WORD);
        assert_eq!(windows.x1_powers_word, theta_window::X1_POWERS_WORD);
        assert_eq!(windows.q_eval_set_word, theta_window::Q_EVAL_SET_WORD);
        assert_eq!(windows.q_eval_cptr_word, theta_window::Q_EVAL_CPTR_WORD);
        assert_eq!(windows.g1_identity_word, theta_window::G1_IDENTITY_WORD);
        assert_eq!(
            windows.reversed_evals_word,
            theta_window::REVERSED_EVALS_WORD
        );
    }

    #[test]
    fn fixed_low_memory_regions_are_planner_registered() {
        let meta = ConstraintSystemMeta {
            num_simple_selectors: 3,
            ..ConstraintSystemMeta::default()
        };
        let vk = synthetic_vk();
        let layout = VerifierMemoryLayout::new(
            &meta,
            &vk,
            Ptr::memory(0x1000),
            VerifierMemoryLayoutConfig::default(),
        );

        let cases = [
            (
                "constructor_smoke_scratch",
                layout.constructor_smoke_scratch_mptr,
                LOW_MEMORY_SCRATCH_START,
                PAIRING_PAIR_BYTES,
            ),
            (
                "transcript_buffer",
                layout.transcript_mptr,
                TRANSCRIPT_BUFFER_START,
                0,
            ),
            (
                "legacy_decompression_scratch",
                layout.legacy_decompression_scratch_mptr,
                LOW_MEMORY_SCRATCH_START,
                MODEXP_DECOMPRESSION_WORKING_WORDS * WORD_BYTES,
            ),
            (
                "pcs_pairing_static_working",
                layout.pcs_pairing_scratch_mptr,
                PCS_PAIRING_SCRATCH_START,
                PCS_STATIC_WORKING_WORDS * WORD_BYTES,
            ),
            (
                "verifier_return",
                layout.verifier_return_mptr,
                VERIFIER_RETURN_BUFFER_START,
                WORD_BYTES,
            ),
            (
                "quotient_return",
                layout.quotient_return_mptr,
                QUOTIENT_RETURN_BUFFER_START,
                (2 + meta.num_simple_selectors) * WORD_BYTES,
            ),
            (
                "accumulator_pairing_batch",
                layout.accumulator_pairing_batch_mptr,
                crate::codegen::layout::accumulator::PAIRING_BATCH_PTR,
                ACCUMULATOR_PAIRING_BATCH_BYTES,
            ),
            (
                "final_pairing_scratch",
                layout.final_pairing_scratch_mptr,
                crate::codegen::layout::FINAL_PAIRING_SCRATCH_START,
                PAIRING_STATIC_WORKING_WORDS * WORD_BYTES,
            ),
        ];

        for (name, field, start, len) in cases {
            let region = layout.map.region(name).expect("fixed region registered");
            assert_eq!(field, start, "{name} field drifted");
            assert_eq!(region.start, start, "{name} start drifted");
            assert_eq!(region.len, len, "{name} len drifted");
        }

        let scalar_inv = layout
            .map
            .region("scalar_inv_scratch")
            .expect("scalar inversion scratch registered");
        assert_eq!(
            layout.scalar_inv_scratch_mptr,
            0x1000 - MODEXP_SCRATCH_BYTES
        );
        assert_eq!(scalar_inv.start, layout.scalar_inv_scratch_mptr);
        assert_eq!(scalar_inv.len, MODEXP_FRAME_BYTES);
        layout.validate().expect("fixed regions are phase-scoped");
    }

    #[test]
    fn pcs_fixed_window_overflows_fail_with_clear_messages() {
        let meta = ConstraintSystemMeta::default();
        let vk = synthetic_vk();
        let windows = ThetaWindowLayout::compatibility();
        let mut config = VerifierMemoryLayoutConfig::default();
        config.pcs.rot_points_words = windows.rot_points_cap_words + 1;
        let layout = VerifierMemoryLayout::new(&meta, &vk, Ptr::memory(0x1000), config);
        assert!(layout.validate().unwrap_err().contains("ROT_POINTS_MPTR"));

        let mut config = VerifierMemoryLayoutConfig::default();
        config.pcs.x1_powers_words = windows.x1_powers_cap_words + 1;
        let layout = VerifierMemoryLayout::new(&meta, &vk, Ptr::memory(0x1000), config);
        assert!(layout.validate().unwrap_err().contains("X1_POWERS_MPTR"));

        let mut config = VerifierMemoryLayoutConfig::default();
        config.pcs.q_eval_set_words = windows.q_eval_set_cap_words + 1;
        let layout = VerifierMemoryLayout::new(&meta, &vk, Ptr::memory(0x1000), config);
        assert!(layout.validate().unwrap_err().contains("Q_EVAL_SET_MPTR"));
    }

    #[test]
    fn accumulator_msm_region_is_sized_from_shape() {
        let meta = ConstraintSystemMeta::default();
        let vk = synthetic_vk();
        let config = VerifierMemoryLayoutConfig {
            acc_msm_terms: 4,
            ..VerifierMemoryLayoutConfig::default()
        };
        let layout = VerifierMemoryLayout::new(&meta, &vk, Ptr::memory(0x1000), config);
        let region = layout
            .map
            .region("accumulator_msm")
            .expect("accumulator MSM region registered");

        assert_eq!(region.len, 4 * G1_MSM_PAIR_BYTES);
    }

    #[test]
    fn trace_log_word_is_registered_after_scratch_regions() {
        let meta = ConstraintSystemMeta {
            num_user_advices: vec![8],
            num_quotients: 4,
            num_evals: 16,
            ..ConstraintSystemMeta::default()
        };
        let vk = synthetic_vk();
        let config = VerifierMemoryLayoutConfig {
            acc_msm_terms: 3,
            pcs: PcsMemoryRequirements {
                q_com_trace_msm: FinalMsmShape::from_terms(9),
                final_msm: FinalMsmShape::from_terms(10),
                ..PcsMemoryRequirements::default()
            },
            ..VerifierMemoryLayoutConfig::default()
        };
        let layout = VerifierMemoryLayout::new(&meta, &vk, Ptr::memory(0x1000), config);
        let region = layout
            .map
            .region("trace_u256_log_word")
            .expect("trace_u256 region registered");

        assert_eq!(region.start, layout.trace_u256_mptr);
        assert_eq!(region.len, WORD_BYTES);
        assert!(
            layout.trace_u256_mptr >= layout.pcs_final_msm_scratch_mptr + 10 * G1_MSM_PAIR_BYTES
        );
        layout.validate().expect("trace log word must not overlap");
    }

    #[test]
    fn batch_invert_scratch_region_tracks_instance_shape() {
        let meta = ConstraintSystemMeta {
            rotation_last: -3,
            ..ConstraintSystemMeta::default()
        };
        let vk = synthetic_vk();
        let config = VerifierMemoryLayoutConfig {
            num_instances: 5,
            ..VerifierMemoryLayoutConfig::default()
        };
        let layout = VerifierMemoryLayout::new(&meta, &vk, Ptr::memory(0x1000), config);
        let region = layout
            .map
            .region("batch_invert_scratch")
            .expect("batch invert scratch region registered");

        assert_eq!(
            region.len,
            MODEXP_FRAME_BYTES + (5 + 3 + 1 - 2) * WORD_BYTES
        );
    }
}
