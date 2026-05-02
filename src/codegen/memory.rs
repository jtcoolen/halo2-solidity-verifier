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
    template::Halo2VerifyingKey,
    util::{ConstraintSystemMeta, Ptr},
};

/// EVM word size. BLS12-381 Fr values are rendered as one canonical
/// big-endian EVM word in calldata/memory.
pub(crate) const WORD_BYTES: usize = 0x20;
/// Number of EVM words in one Fr scalar.
pub(crate) const FR_WORDS: usize = 1;
/// EIP-2537 padded G1 encoding: x_hi, x_lo, y_hi, y_lo.
pub(crate) const G1_WORDS: usize = 4;
/// EIP-2537 padded G2 encoding: four Fp2 coordinates, two words each.
pub(crate) const G2_WORDS: usize = 8;
pub(crate) const FR_BYTES: usize = FR_WORDS * WORD_BYTES;
pub(crate) const G1_BYTES: usize = G1_WORDS * WORD_BYTES;
pub(crate) const G2_BYTES: usize = G2_WORDS * WORD_BYTES;
/// EIP-2537 G1MSM input tuple: one padded G1 plus one scalar.
pub(crate) const G1_MSM_PAIR_BYTES: usize = G1_BYTES + FR_BYTES;
/// EIP-2537 G1ADD input tuple: two padded G1 points.
pub(crate) const G1ADD_INPUT_BYTES: usize = 2 * G1_BYTES;
/// EVM modexp frame for 32-byte base, exponent, and modulus.
///
/// Layout: three 32-byte length words followed by base, exponent, modulus.
pub(crate) const MODEXP_FRAME_BYTES: usize = 0xc0;
/// Historical low-memory reservation used by scalar inversion helpers near
/// `VK_MPTR`. It is larger than the frame because older code treated the
/// surrounding 0x100-byte window as scratch; keep the same distance from
/// `VK_MPTR` when checking overlaps.
pub(crate) const MODEXP_SCRATCH_BYTES: usize = 0x100;
/// EIP-2537 pairing precompile input for one `(G1, G2)` pair.
pub(crate) const PAIRING_PAIR_BYTES: usize = G1_BYTES + G2_BYTES;
/// Two-pair KZG pairing input: `(rhs, G2)` and `(lhs, -sG2)`.
pub(crate) const PAIRING_TWO_PAIR_BYTES: usize = 2 * PAIRING_PAIR_BYTES;
/// Historical floor for the accumulator MSM input buffer.
///
/// The accumulator path used a fixed `0x7000` scratch base before the planner.
/// Preserve that address whenever the decompressed commitment payload ends
/// below it, so generated verifier byte addresses stay stable. Larger circuits
/// move the scratch up to `after_comms`.
pub(crate) const ACC_MSM_MIN_SCRATCH_BYTES: usize = 0x7000;
/// Static low-memory working set required by the PCS pairing helpers.
pub(crate) const PCS_STATIC_WORKING_WORDS: usize = 32;
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
const ROT_POINTS_OFFSET_WORDS: usize = 52;
const X1_POWERS_OFFSET_WORDS: usize = 80;
const Q_COM_OFFSET_WORDS: usize = 145;
const Q_EVAL_SET_OFFSET_WORDS: usize = 145;
const Q_EVAL_CPTR_OFFSET_WORDS: usize = 201;
const G1_IDENTITY_OFFSET_WORDS: usize = 209;
const REVERSED_EVALS_OFFSET_WORDS: usize = 220;

// Capacities of the historical PCS fixed windows above. Validation fails when
// a circuit would exceed one of these windows rather than silently overwriting
// the next planned slot.
const ROT_POINTS_CAP_WORDS: usize = X1_POWERS_OFFSET_WORDS - ROT_POINTS_OFFSET_WORDS;
const X1_POWERS_CAP_WORDS: usize = Q_EVAL_SET_OFFSET_WORDS - X1_POWERS_OFFSET_WORDS;
const Q_COM_CAP_WORDS: usize = Q_EVAL_SET_OFFSET_WORDS - Q_COM_OFFSET_WORDS;
const Q_EVAL_SET_CAP_WORDS: usize = Q_EVAL_CPTR_OFFSET_WORDS - Q_EVAL_SET_OFFSET_WORDS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemoryPhase {
    /// Constructor-only precompile smoke tests.
    ConstructorSmoke,
    /// Streaming Fiat-Shamir buffer before generated VK memory is live.
    Transcript,
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

    fn end(&self) -> usize {
        self.start + self.len
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.len != 0 && other.len != 0 && self.start < other.end() && other.start < self.end()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MemoryMap {
    regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    pub(crate) fn push(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    #[cfg(test)]
    pub(crate) fn region(&self, name: &str) -> Option<&MemoryRegion> {
        self.regions.iter().find(|region| region.name == name)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        // All generated Yul uses word-granular `mload`, `mstore`, and
        // precompile input lengths. Byte-granular ranges would be a bug, not a
        // clever packing opportunity.
        for region in &self.regions {
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FinalMsmShape {
    /// Number of `(G1, scalar)` pairs emitted for this MSM.
    pub(crate) terms: usize,
    /// Total G1MSM input length in bytes.
    pub(crate) input_bytes: usize,
}

impl FinalMsmShape {
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
    /// Start of the copied or embedded verifying-key payload.
    pub(crate) vk_mptr: Ptr,
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
    /// Canonical transient PCS scratch base. Subregions below intentionally
    /// alias this byte range and are distinguished by lifetime phase.
    pub(crate) pcs_scratch_mptr: usize,
    pub(crate) pcs_q_eval_source_table_mptr: usize,
    pub(crate) pcs_q_com_trace_scratch_mptr: usize,
    pub(crate) pcs_final_msm_scratch_mptr: usize,
    /// Public accumulator MSM buffer, historically floored at 0x7000.
    pub(crate) acc_msm_scratch: usize,
    pub(crate) pcs: PcsMemoryRequirements,
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
    /// Maximum compact quotient VM stack words.
    pub(crate) quotient_stack_words: usize,
    /// Number of `(G1, scalar)` pairs in the public-accumulator MSM.
    pub(crate) acc_msm_terms: usize,
    /// PCS fixed-window and scratch requirements computed from the circuit and
    /// VK query shape.
    pub(crate) pcs: PcsMemoryRequirements,
}

impl VerifierMemoryLayout {
    pub(crate) fn new(
        meta: &ConstraintSystemMeta,
        vk: &Halo2VerifyingKey,
        vk_mptr: Ptr,
        config: VerifierMemoryLayoutConfig,
    ) -> Self {
        // VK bytes are copied first, then user-phase challenge slots, then
        // the fixed theta-relative region. The caller is responsible for
        // choosing a stable `vk_mptr` after proof-shape planning; this keeps
        // the transcript buffer below the VK payload.
        let challenge_mptr = vk_mptr + vk.len() / WORD_BYTES;
        let theta_mptr = challenge_mptr + meta.challenge_indices.len();
        let theta_words = theta_mptr.value().as_usize() / WORD_BYTES;
        let at_theta = |words: usize| Ptr::memory((theta_words + words) * WORD_BYTES);

        let total_advices: usize = meta.num_user_advices.iter().sum();
        let lookup_helper_chunks_total: usize = meta.lookup_chunks.iter().sum();
        let non_quotient_g1s = total_advices
            + meta.num_lookups
            + meta.num_permutation_zs
            + lookup_helper_chunks_total
            + meta.num_lookups
            + meta.num_trashcans;
        let committed_g1s = non_quotient_g1s + meta.num_quotients;
        let reversed_evals_mptr = at_theta(REVERSED_EVALS_OFFSET_WORDS);
        let comms_mptr_base = at_theta(REVERSED_EVALS_OFFSET_WORDS + meta.num_evals);
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
        let selector_acc_mptr = after_comms.next_multiple_of(WORD_BYTES);
        let batch_invert_scratch_mptr = selector_acc_mptr;
        let quotient_tmp_mptr = (selector_acc_mptr + meta.num_simple_selectors * WORD_BYTES)
            .next_multiple_of(WORD_BYTES);
        let quotient_stack_mptr = quotient_tmp_mptr + config.quotient_cse_temps * WORD_BYTES;
        // The PCS emitter is allowed to reuse quotient temp/stack bytes in
        // later phases; validation distinguishes those uses by phase.
        let pcs_scratch_mptr = quotient_tmp_mptr;
        let acc_msm_scratch = after_comms
            .max(ACC_MSM_MIN_SCRATCH_BYTES)
            .next_multiple_of(WORD_BYTES);

        let mut layout = Self {
            map: MemoryMap::default(),
            vk_mptr,
            challenge_mptr,
            theta_mptr,
            beta_mptr: at_theta(1),
            gamma_mptr: at_theta(2),
            trash_challenge_mptr: at_theta(3),
            y_mptr: at_theta(4),
            x_mptr: at_theta(5),
            x1_mptr: at_theta(6),
            x2_mptr: at_theta(7),
            x3_mptr: at_theta(8),
            x4_mptr: at_theta(9),
            f_com_mptr: at_theta(10),
            pi_mptr: at_theta(14),
            acc_lhs_mptr: at_theta(18),
            acc_rhs_mptr: at_theta(22),
            x_n_mptr: at_theta(26),
            x_n_minus_1_inv_mptr: at_theta(27),
            l_last_mptr: at_theta(28),
            l_blind_mptr: at_theta(29),
            l_0_mptr: at_theta(30),
            instance_eval_mptr: at_theta(31),
            quotient_eval_mptr: at_theta(32),
            quotient_mptr: at_theta(33),
            f_eval_mptr: at_theta(38),
            v_mptr: at_theta(39),
            final_com_mptr: at_theta(40),
            pairing_lhs_mptr: at_theta(44),
            pairing_rhs_mptr: at_theta(48),
            rot_points_mptr: at_theta(ROT_POINTS_OFFSET_WORDS),
            x1_powers_mptr: at_theta(X1_POWERS_OFFSET_WORDS),
            q_com_mptr: at_theta(Q_COM_OFFSET_WORDS),
            q_eval_set_mptr: at_theta(Q_EVAL_SET_OFFSET_WORDS),
            q_eval_cptr_mptr: at_theta(Q_EVAL_CPTR_OFFSET_WORDS),
            g1_identity_mptr: at_theta(G1_IDENTITY_OFFSET_WORDS),
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
            pcs_scratch_mptr,
            pcs_q_eval_source_table_mptr: pcs_scratch_mptr,
            pcs_q_com_trace_scratch_mptr: pcs_scratch_mptr,
            pcs_final_msm_scratch_mptr: pcs_scratch_mptr,
            acc_msm_scratch,
            pcs: config.pcs,
        };
        layout.populate_map(meta, vk, config);
        layout
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.pcs.rot_points_words > ROT_POINTS_CAP_WORDS {
            return Err(format!(
                "PCS scratch layout mismatch: ROT_POINTS_MPTR needs {} word(s), capacity is {ROT_POINTS_CAP_WORDS}",
                self.pcs.rot_points_words
            ));
        }
        if self.pcs.x1_powers_words > X1_POWERS_CAP_WORDS {
            return Err(format!(
                "PCS scratch layout mismatch: X1_POWERS_MPTR needs {} word(s), capacity is {X1_POWERS_CAP_WORDS}",
                self.pcs.x1_powers_words
            ));
        }
        if self.pcs.q_com_words > Q_COM_CAP_WORDS {
            return Err(format!(
                "PCS scratch layout mismatch: Q_COM_MPTR needs {} word(s), capacity is {Q_COM_CAP_WORDS}",
                self.pcs.q_com_words
            ));
        }
        if self.pcs.q_eval_set_words > Q_EVAL_SET_CAP_WORDS {
            return Err(format!(
                "PCS scratch layout mismatch: Q_EVAL_SET_MPTR needs {} word(s), capacity is {Q_EVAL_SET_CAP_WORDS}",
                self.pcs.q_eval_set_words
            ));
        }

        self.map.validate()?;

        Ok(())
    }

    fn populate_map(
        &mut self,
        meta: &ConstraintSystemMeta,
        vk: &Halo2VerifyingKey,
        config: VerifierMemoryLayoutConfig,
    ) {
        let vk_start = self.vk_mptr.value().as_usize();
        let challenge_start = self.challenge_mptr.value().as_usize();
        let theta_start = self.theta_mptr.value().as_usize();
        let commitments_len = commitment_g1_count(meta) * G1_BYTES;
        let selector_len = meta.num_simple_selectors * WORD_BYTES;
        let quotient_tmp_len = config.quotient_cse_temps * WORD_BYTES;
        let quotient_stack_len = config.quotient_stack_words * WORD_BYTES;
        let q_eval_source_len = self.pcs.q_eval_source_table_words * WORD_BYTES;
        let q_com_trace_len = self.pcs.q_com_trace_msm.input_bytes;
        let final_msm_len = self.pcs.final_msm.input_bytes;
        let acc_msm_len = config.acc_msm_terms * G1_MSM_PAIR_BYTES;
        let batch_invert_len = batch_invert_scratch_bytes(meta, config.num_instances);

        // Low-memory helpers are phase-scoped because the transcript buffer is
        // no longer live once algebra/precompile work begins.
        self.map.push(MemoryRegion::new(
            "constructor_smoke_scratch",
            G1_BYTES,
            PAIRING_PAIR_BYTES,
            MemoryLifetime::Phase(MemoryPhase::ConstructorSmoke),
        ));
        self.map.push(MemoryRegion::new(
            "transcript_buffer",
            0,
            config.transcript_words * WORD_BYTES,
            MemoryLifetime::Phase(MemoryPhase::Transcript),
        ));
        self.map.push(MemoryRegion::new(
            "scalar_inv_scratch",
            vk_start.saturating_sub(MODEXP_SCRATCH_BYTES),
            MODEXP_FRAME_BYTES,
            MemoryLifetime::Phase(MemoryPhase::ScalarInv),
        ));
        self.map.push(MemoryRegion::new(
            "pcs_pairing_tmp",
            0,
            G1_BYTES + G1_MSM_PAIR_BYTES,
            MemoryLifetime::Phase(MemoryPhase::PcsPairing),
        ));
        self.map.push(MemoryRegion::new(
            "final_pairing_scratch",
            PAIRING_TWO_PAIR_BYTES,
            PAIRING_TWO_PAIR_BYTES,
            MemoryLifetime::Phase(MemoryPhase::FinalPairing),
        ));
        self.map.push(MemoryRegion::new(
            "vk_payload",
            vk_start,
            vk.len(),
            MemoryLifetime::Permanent,
        ));
        self.map.push(MemoryRegion::new(
            "challenge_slots",
            challenge_start,
            meta.challenge_indices.len() * WORD_BYTES,
            MemoryLifetime::Permanent,
        ));
        self.map.push(MemoryRegion::new(
            "theta_scalar_and_g1_slots",
            theta_start,
            ROT_POINTS_OFFSET_WORDS * WORD_BYTES,
            MemoryLifetime::Permanent,
        ));
        self.map.push(MemoryRegion::new(
            "rot_points",
            self.rot_points_mptr.value().as_usize(),
            self.pcs.rot_points_words * WORD_BYTES,
            MemoryLifetime::Phase(MemoryPhase::PcsFixed),
        ));
        self.map.push(MemoryRegion::new(
            "x1_powers",
            self.x1_powers_mptr.value().as_usize(),
            self.pcs.x1_powers_words * WORD_BYTES,
            MemoryLifetime::Phase(MemoryPhase::PcsFixed),
        ));
        self.map.push(MemoryRegion::new(
            "q_com_fixed_window",
            self.q_com_mptr.value().as_usize(),
            self.pcs.q_com_words * WORD_BYTES,
            MemoryLifetime::Phase(MemoryPhase::PcsFixed),
        ));
        self.map.push(MemoryRegion::new(
            "q_eval_set",
            self.q_eval_set_mptr.value().as_usize(),
            self.pcs.q_eval_set_words * WORD_BYTES,
            MemoryLifetime::Phase(MemoryPhase::PcsFixed),
        ));
        self.map.push(MemoryRegion::new(
            "q_eval_cptr_slot",
            self.q_eval_cptr_mptr.value().as_usize(),
            WORD_BYTES,
            MemoryLifetime::Permanent,
        ));
        self.map.push(MemoryRegion::new(
            "g1_identity",
            self.g1_identity_mptr.value().as_usize(),
            G1_BYTES,
            MemoryLifetime::Permanent,
        ));
        self.map.push(MemoryRegion::new(
            "decoded_evals",
            self.reversed_evals_mptr.value().as_usize(),
            meta.num_evals * WORD_BYTES,
            MemoryLifetime::Permanent,
        ));
        self.map.push(MemoryRegion::new(
            "decompressed_commitments",
            self.comms_mptr_base.value().as_usize(),
            commitments_len,
            MemoryLifetime::Permanent,
        ));
        self.map.push(MemoryRegion::new(
            "batch_invert_scratch",
            self.batch_invert_scratch_mptr,
            batch_invert_len,
            MemoryLifetime::Phase(MemoryPhase::LagrangeBatchInvert),
        ));
        self.map.push(MemoryRegion::new(
            "selector_accumulators",
            self.selector_acc_mptr,
            selector_len,
            MemoryLifetime::Phase(MemoryPhase::PcsFinalMsm),
        ));
        self.map.push(MemoryRegion::new(
            "quotient_temps",
            self.quotient_tmp_mptr,
            quotient_tmp_len,
            MemoryLifetime::Phase(MemoryPhase::QuotientVm),
        ));
        self.map.push(MemoryRegion::new(
            "quotient_stack",
            self.quotient_stack_mptr,
            quotient_stack_len.max(MODEXP_FRAME_BYTES),
            MemoryLifetime::Phase(MemoryPhase::QuotientVm),
        ));
        self.map.push(MemoryRegion::new(
            "pcs_q_eval_source_table",
            self.pcs_q_eval_source_table_mptr,
            q_eval_source_len,
            MemoryLifetime::Phase(MemoryPhase::PcsQEvalSourceTable),
        ));
        self.map.push(MemoryRegion::new(
            "pcs_q_com_trace_msm",
            self.pcs_q_com_trace_scratch_mptr,
            q_com_trace_len,
            MemoryLifetime::Phase(MemoryPhase::PcsQComTrace),
        ));
        self.map.push(MemoryRegion::new(
            "pcs_final_msm",
            self.pcs_final_msm_scratch_mptr,
            final_msm_len,
            MemoryLifetime::Phase(MemoryPhase::PcsFinalMsm),
        ));
        self.map.push(MemoryRegion::new(
            "accumulator_msm",
            self.acc_msm_scratch,
            acc_msm_len,
            MemoryLifetime::Phase(MemoryPhase::AccumulatorMsm),
        ));
        self.map.push(MemoryRegion::new(
            "accumulator_pairing_batch",
            G1ADD_INPUT_BYTES,
            ACCUMULATOR_PAIRING_BATCH_BYTES,
            MemoryLifetime::Phase(MemoryPhase::AccumulatorPairingBatch),
        ));
    }
}

pub(crate) fn commitment_g1_count(meta: &ConstraintSystemMeta) -> usize {
    meta.num_user_advices.iter().sum::<usize>()
        + meta.num_lookups
        + meta.num_permutation_zs
        + meta.lookup_chunks.iter().sum::<usize>()
        + meta.num_lookups
        + meta.num_trashcans
        + meta.num_quotients
}

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

    fn synthetic_vk() -> Halo2VerifyingKey {
        let fixed: Vec<G1Words> = vec![(U256::ZERO, U256::ZERO, U256::ZERO, U256::ZERO)];
        Halo2VerifyingKey {
            constants: (0..31).map(|_| ("c", U256::ZERO)).collect(),
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

        assert_eq!(
            layout.rot_points_mptr.value().as_usize(),
            theta + 52 * WORD_BYTES
        );
        assert_eq!(
            layout.x1_powers_mptr.value().as_usize(),
            theta + 80 * WORD_BYTES
        );
        assert_eq!(
            layout.q_eval_set_mptr.value().as_usize(),
            theta + 145 * WORD_BYTES
        );
        assert_eq!(
            layout.q_eval_cptr_mptr.value().as_usize(),
            theta + 201 * WORD_BYTES
        );
        assert_eq!(
            layout.g1_identity_mptr.value().as_usize(),
            theta + 209 * WORD_BYTES
        );
        assert_eq!(
            layout.reversed_evals_mptr.value().as_usize(),
            theta + 220 * WORD_BYTES
        );
        assert_eq!(
            layout.comms_mptr_base.value().as_usize(),
            theta + (220 + meta.num_evals) * WORD_BYTES
        );
    }

    #[test]
    fn pcs_fixed_window_overflows_fail_with_clear_messages() {
        let meta = ConstraintSystemMeta::default();
        let vk = synthetic_vk();
        let mut config = VerifierMemoryLayoutConfig::default();
        config.pcs.rot_points_words = ROT_POINTS_CAP_WORDS + 1;
        let layout = VerifierMemoryLayout::new(&meta, &vk, Ptr::memory(0x1000), config);
        assert!(layout.validate().unwrap_err().contains("ROT_POINTS_MPTR"));

        let mut config = VerifierMemoryLayoutConfig::default();
        config.pcs.x1_powers_words = X1_POWERS_CAP_WORDS + 1;
        let layout = VerifierMemoryLayout::new(&meta, &vk, Ptr::memory(0x1000), config);
        assert!(layout.validate().unwrap_err().contains("X1_POWERS_MPTR"));

        let mut config = VerifierMemoryLayoutConfig::default();
        config.pcs.q_eval_set_words = Q_EVAL_SET_CAP_WORDS + 1;
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
