//! Shared metadata, pointer, formatting, and BLS encoding helpers for codegen.
//!
//! This module is intentionally close to the generated Yul model. `Ptr`,
//! `Word`, and `EcPoint` render directly as calldata/memory loads, while
//! `ConstraintSystemMeta` and `Data` bind the typed protocol plan to concrete
//! verifier memory addresses.
//!
//! Some Yul-emission helpers in this module are shared by production codegen
//! and tests. Keep them available without `cfg(test)` gates so the emitter can
//! reuse a single metadata model.
#![allow(dead_code)]

use crate::codegen::{
    layout::{BLS_FP_BYTES, EIP2537_FP_PAD_BYTES},
    memory::{VerifierMemoryLayout, G1_WORDS, WORD_BYTES},
    proof_layout::ProofCalldataLayout,
    protocol::{EvalRead, PermutationZEval, ProtocolPlan},
    template::Halo2VerifyingKey,
};
use ff::PrimeField;
use itertools::{chain, izip, Itertools};
use midnight_curves::{Coordinates, CurveAffine, Fq, G1Affine, G2Affine};
use midnight_proofs::plonk::{Any, Column, ConstraintSystem};
use ruint::{aliases::U256, UintTryFrom};
use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashMap},
    fmt::{self, Display, Formatter},
    ops::{Add, Sub},
};

type LookupEvalSlots = (Option<Word>, Vec<Option<Word>>, Option<Word>, Option<Word>);

// ----------------------------------------------------------------------------
// `ConstraintSystemMeta` walks `midnight_proofs::plonk::ConstraintSystem<Fq>`
// directly, which exposes:
//
//   * `cs.lookups()` -> `Vec<logup::BatchedArgument<F>>` (with `chunk_by_degree`,
//     `num_chunks`)
//   * `cs.trashcans()` -> `Vec<trash::Argument<F>>`
//   * `cs.permutation()` -> `&permutation::Argument` with `get_columns()`
//   * `cs.num_simple_selectors()`, `cs.has_simple_selector_col(idx)`
//
// The proof byte layout this metadata describes corresponds to
// `midnight_proofs::plonk::verifier::parse_trace`:
//   per phase: read advices, squeeze challenges, ...
//   theta
//   per proof: read multiplicities (one G1 per lookup)
//   beta, gamma
//   per proof: read permutation product commitments
//   per proof: per lookup, read num_chunks helpers + 1 accumulator
//   trash_challenge
//   per proof: read trashcan commitments
//   y
//   read quotient limbs
//   x
//   read evaluations (committed_instance? + advice + fixed-non-simple +
//                     perm_common + perm_set + lookup + trash)
//   PCS (multi_prepare):
//     x1, x2; read f_com; x3; read q_evals (one per point set);
//     x4; read pi
//
// Steps 4-9 of MIGRATION.md track the remaining work to materialise this
// schema into a complete Yul emitter. For Steps 1-3 we only need the
// scalar metadata fields below to be derivable from the new CS so that
// `cargo check --lib` is green.
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub(crate) struct ConstraintSystemMeta {
    /// Typed source plan for proof reads and PCS queries.
    pub(crate) protocol: ProtocolPlan,
    /// Number of fixed columns.
    pub(crate) num_fixeds: usize,
    /// Columns participating in the permutation argument.
    pub(crate) permutation_columns: Vec<Column<Any>>,
    /// Maximum columns per permutation product chunk.
    pub(crate) permutation_chunk_len: usize,
    /// Number of lookup arguments.
    pub(crate) num_lookups: usize,
    /// Helper chunks per lookup.
    pub(crate) lookup_chunks: Vec<usize>,
    /// Number of trashcan arguments.
    pub(crate) num_trashcans: usize,
    /// Number of permutation product commitments.
    pub(crate) num_permutation_zs: usize,
    /// Number of quotient limb commitments.
    pub(crate) num_quotients: usize,
    /// Advice query tuples `(column, rotation)`.
    pub(crate) advice_queries: Vec<(usize, i32)>,
    /// Fixed query tuples `(column, rotation)`.
    pub(crate) fixed_queries: Vec<(usize, i32)>,
    /// Instance query tuples `(column, rotation)`.
    pub(crate) instance_queries: Vec<(usize, i32)>,
    pub(crate) num_simple_selectors: usize,
    /// Set of fixed-column indices that are *simple selectors* (i.e.
    /// multiplicative selectors that the prover sets to 0 or 1 only).
    /// These columns have no eval slot in the proof transcript: the
    /// verifier substitutes `F::ONE` at their fixed_query index after
    /// reading the rest. Step 6 (Yul rewrite) keeps the same convention;
    /// the codegen evaluator emits `0x1` directly for these queries.
    pub(crate) simple_selector_cols: BTreeSet<usize>,
    pub(crate) num_committed_instances: usize,
    pub(crate) num_rotations: usize,
    /// Number of Fr scalars in the main eval block of the proof
    /// (committed-instance + advice + fixed + perm + lookup + trash
    /// evals). When `fewer-point-sets` is on, the codegen bumps this
    /// to include the dummy-query evals via `set_num_dummy_evals` so
    /// that the memory layout (REVERSED_EVALS_MPTR buffer +
    /// comms_mptr_base) and the transcript-loop count both grow by
    /// the dummy count.
    pub(crate) num_evals: usize,
    /// Number of dummy `(commitment, point)` queries the
    /// `fewer-point-sets` path appends to the raw query list. Each
    /// dummy is read as one extra Fr at the end of the main eval
    /// block. Populated lazily by `SolidityGenerator::generate_verifier`
    /// after running the PCS dummy-query planner.
    pub(crate) num_dummy_evals: usize,
    /// Number of distinct point sets returned by the codegen-side
    /// `construct_intermediate_sets` simulation. Populated lazily by
    /// `SolidityGenerator::generate_verifier` once it has constructed the
    /// `Data` and run `pcs::queries`.
    pub(crate) num_point_sets: usize,
    /// Advice commitment counts by user phase.
    pub(crate) num_user_advices: Vec<usize>,
    /// Challenge counts by user phase.
    pub(crate) num_user_challenges: Vec<usize>,
    /// Advice remapping into phase-packed verifier order.
    pub(crate) advice_indices: Vec<usize>,
    /// Challenge remapping into phase-packed memory order.
    pub(crate) challenge_indices: Vec<usize>,
    /// Last negative rotation used for row-boundary constraints.
    pub(crate) rotation_last: i32,
}

impl ConstraintSystemMeta {
    /// Derive metadata from a midnight-proofs `ConstraintSystem`.
    ///
    /// `nb_committed_instances` is the number of instance columns that the
    /// verifier *reads* from the proof transcript (vs. computes locally
    /// via Lagrange interpolation). For the poseidon example this is 0;
    /// for IVC-style fixtures with committed inputs it would be > 0.
    pub(crate) fn new(cs: &ConstraintSystem<Fq>, nb_committed_instances: usize) -> Self {
        let protocol = ProtocolPlan::from_constraint_system(cs, nb_committed_instances);

        Self {
            protocol: protocol.clone(),
            num_fixeds: protocol.num_fixeds,
            permutation_columns: protocol.permutation_columns.clone(),
            permutation_chunk_len: protocol.permutation_chunk_len,
            num_lookups: protocol.num_lookups,
            lookup_chunks: protocol.lookup_chunks.clone(),
            num_trashcans: protocol.num_trashcans,
            num_permutation_zs: protocol.num_permutation_zs,
            num_quotients: protocol.num_quotients,
            advice_queries: protocol.advice_queries.iter().map(|q| q.tuple()).collect(),
            fixed_queries: protocol.fixed_queries.iter().map(|q| q.tuple()).collect(),
            instance_queries: protocol
                .instance_queries
                .iter()
                .map(|q| q.tuple())
                .collect(),
            num_simple_selectors: protocol.num_simple_selectors,
            simple_selector_cols: protocol.simple_selector_cols.clone(),
            num_committed_instances: protocol.num_committed_instances,
            num_evals: protocol.num_main_evals(),
            num_dummy_evals: 0,
            num_rotations: protocol.num_rotations,
            num_point_sets: 0,
            num_user_advices: protocol.num_user_advices.clone(),
            num_user_challenges: protocol.num_user_challenges.clone(),
            advice_indices: protocol.advice_indices.clone(),
            challenge_indices: protocol.challenge_indices.clone(),
            rotation_last: protocol.rotation_last,
        }
    }

    /// Check legacy scalar fields against the typed protocol plan.
    pub(crate) fn validate_against_protocol(&self) -> Result<(), String> {
        self.protocol.validate()?;
        let planned_g1s = self.protocol.num_commitments();
        let scheduled_g1s = self.num_user_advices.iter().sum::<usize>()
            + self.num_lookups
            + self.num_permutation_zs
            + self.lookup_chunks.iter().sum::<usize>()
            + self.num_lookups
            + self.num_trashcans
            + self.num_quotients;
        if planned_g1s != scheduled_g1s {
            return Err(format!(
                "proof G1 read schedule mismatch: protocol={planned_g1s} metadata={scheduled_g1s}"
            ));
        }
        if self.protocol.num_main_evals() != self.num_main_evals() {
            return Err(format!(
                "proof eval read schedule mismatch: protocol={} metadata={}",
                self.protocol.num_main_evals(),
                self.num_main_evals()
            ));
        }
        Ok(())
    }

    /// Number of columns participating in permutation checks.
    pub(crate) fn num_permutations(&self) -> usize {
        self.permutation_columns.len()
    }

    /// Solidity-facing proof payload length for this metadata snapshot.
    pub(crate) fn proof_len(&self) -> usize {
        self.validate_against_protocol()
            .expect("constraint-system metadata must match protocol plan before proof sizing");
        ProofCalldataLayout::from_protocol(&self.protocol, 0, self.num_evals, self.num_point_sets)
            .proof_len
    }

    /// Setter used by `SolidityGenerator` after running the codegen-side
    /// `construct_intermediate_sets` simulation in `pcs::queries`.
    pub(crate) fn set_num_point_sets(&mut self, n: usize) {
        self.num_point_sets = n;
    }

    /// Setter used by `SolidityGenerator` after running
    /// the PCS dummy-query planner over the raw query list.
    /// Bumps `num_evals` by `n` so that the memory layout of `Data`
    /// (REVERSED_EVALS_MPTR buffer + downstream `comms_mptr_base`) and
    /// the transcript-loop iteration count in the rendered template
    /// both grow to include the dummy slots.
    pub(crate) fn set_num_dummy_evals(&mut self, n: usize) {
        self.num_dummy_evals = n;
        self.num_evals += n;
    }

    /// Number of "main" eval Words (the slots used by the gate
    /// evaluator, permutation Z, lookup, etc.); excludes the dummy
    /// slots appended for fewer-point-sets.
    pub(crate) fn num_main_evals(&self) -> usize {
        self.num_evals - self.num_dummy_evals
    }
}

// ----------------------------------------------------------------------------
// Memory-layout helpers (Data, Ptr, EcPoint, Word, ...). The BLS12-381 layout
// uses four words per G1 and `Column<Any>` keys for permutation commitments.
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct Data {
    /// Memory pointer to user challenge slots.
    pub(crate) challenge_mptr: Ptr,
    /// Memory pointer to the fixed theta-rooted state window.
    pub(crate) theta_mptr: Ptr,

    /// Calldata pointer to quotient limb commitments.
    pub(crate) quotient_comm_cptr: Ptr,
    /// Calldata pointer to KZG `f_com`.
    pub(crate) w_cptr: Ptr,

    /// Fixed commitments in VK memory.
    pub(crate) fixed_comms: Vec<EcPoint>,
    /// Permutation commitments keyed by `Column<Any>`.
    pub(crate) permutation_comms: HashMap<Column<Any>, EcPoint>,
    /// Advice commitments in phase-packed memory order.
    pub(crate) advice_comms: Vec<EcPoint>,
    /// Per committed-instance column: the EcPoint of the committed
    /// instance commitment. Currently always points to `G1_IDENTITY_MPTR`
    /// because the zk_stdlib `verify` path passes
    /// `committed_pi = G1Affine::identity()`.
    pub(crate) committed_instance_comms: Vec<EcPoint>,
    pub(crate) permutation_z_comms: Vec<EcPoint>,
    pub(crate) lookup_m_comms: Vec<EcPoint>,
    pub(crate) lookup_helper_comms: Vec<Vec<EcPoint>>,
    pub(crate) lookup_z_comms: Vec<EcPoint>,
    pub(crate) trashcan_comms: Vec<EcPoint>,

    /// User challenge words.
    pub(crate) challenges: Vec<Word>,

    /// Locally-computed non-committed instance evaluation.
    pub(crate) instance_eval: Word,
    /// Per-(committed-instance-column, rotation): the calldata word for
    /// that committed instance evaluation. Empty when
    /// `num_committed_instances == 0`.
    pub(crate) committed_instance_evals: HashMap<(usize, i32), Word>,
    pub(crate) advice_evals: HashMap<(usize, i32), Word>,
    pub(crate) fixed_evals: HashMap<(usize, i32), Word>,
    pub(crate) permutation_evals: HashMap<Column<Any>, Word>,
    /// Per permutation set: `(z_cur, z_next, z_last)`. `z_last` is
    /// `None` for the last set (it has no `last_eval` in the proof; see
    /// `midnight_proofs::plonk::permutation::verifier::Committed::evaluate`).
    pub(crate) permutation_z_evals: Vec<(Word, Word, Option<Word>)>,
    /// Per lookup: `(m, [helpers], z, z_next)` evaluations.
    pub(crate) lookup_evals: Vec<(Word, Vec<Word>, Word, Word)>,
    pub(crate) trashcan_evals: Vec<Word>,

    pub(crate) computed_quotient_comm: EcPoint,
    /// Historical name mirroring `QUOTIENT_EVAL_MPTR`. This is the
    /// expected opening scalar for the linearized commitment (`-nu_y(x)`),
    /// not an alleged quotient-polynomial evaluation `h(x)`.
    pub(crate) computed_quotient_eval: Word,

    /// Word offset (in the verifier's static memory map) of the start of
    /// the per-category EIP-2537-padded commitment region. See the
    /// `KNOWN BUG` block in `Data::new` for the layout convention.
    pub(crate) comms_mptr_base: Ptr,
    /// Calldata pointer to the first EIP-2537-padded quotient G1 in the proof
    /// stream. Used by the quotient-fold loop in the template.
    pub(crate) quotient_limb_cptr: Ptr,
    /// Memory base of the decoded-evals buffer (Optimisation H3). The
    /// transcript-side `evaluations` loop spills the decoded scalar value to
    /// `REVERSED_EVALS_MPTR + i * 0x20` so that every later eval reference can
    /// `mload` instead of rereading calldata.
    pub(crate) reversed_evals_mptr: Ptr,
    /// Eval Words for the dummy queries appended by the
    /// fewer-point-sets path. Empty when the feature is disabled. The
    /// dummy buffer is laid out immediately after the main reversed-
    /// evals buffer; `dummy_eval_words[i]` points at
    /// `REVERSED_EVALS_MPTR + (num_evals + i) * 0x20`. The transcript
    /// loop reads `num_dummy_evals` extra Fr scalars after the main
    /// eval block and spills them into this buffer the same way the
    /// main loop does.
    pub(crate) dummy_eval_words: Vec<Word>,
}

impl Data {
    /// Bind protocol metadata to concrete proof calldata and verifier memory.
    ///
    /// The resulting value is the lookup table every emitter uses: it maps
    /// proof commitments, evaluations, challenges, and computed helper values
    /// to typed `Word`/`EcPoint` handles that render as Yul loads.
    pub(crate) fn new(
        meta: &ConstraintSystemMeta,
        vk: &Halo2VerifyingKey,
        proof_cptr: Ptr,
        memory: &VerifierMemoryLayout,
    ) -> Self {
        // BLS12-381 G1 commitments occupy 4 words (EIP-2537 padded), so the
        // stride between consecutive points is 4 instead of the BN254-era 2.
        let fixed_comm_mptr = memory.vk_mptr + vk.constants.len();
        let permutation_comm_mptr = fixed_comm_mptr + G1_WORDS * vk.fixed_comms.len();
        let challenge_mptr = memory.challenge_mptr;
        let theta_mptr = memory.theta_mptr;

        // ------------------------------------------------------------
        // Step 8 layout (2026-04-26):
        //
        // The Solidity proof stream carries BLS12-381 G1 commitments as
        // EIP-2537 padded 128-byte points. The PCS / quotient-fold emitters
        // consume points as 4 contiguous words via `EcPoint::words()`, so
        // the template validates and copies each padded G1 into its fixed
        // memory MPTR during proof reading.
        //
        // The seven per-category memory bases below match the constants
        // emitted in `templates/Halo2Verifier.sol`. Each base anchors a
        // contiguous run of 4-word slots (one per G1).
        // ------------------------------------------------------------
        // -- calldata cursor (uncompressed, G1_BYTES stride per G1) --
        // Section starts come from `ProofCalldataLayout`, shared with the
        // verifier template and off-chain proof repacker.
        let proof_cptr_bytes = match proof_cptr.value() {
            Value::Integer(b) => b as usize,
            _ => unreachable!("proof_cptr must be a literal byte offset"),
        };
        let proof_layout = ProofCalldataLayout::from_protocol(
            &meta.protocol,
            proof_cptr_bytes,
            meta.num_evals,
            meta.num_point_sets,
        );
        let quotient_comm_start = Ptr::calldata(proof_layout.quotient_comm_cptr);
        let w_cptr = Ptr::calldata(proof_layout.w_cptr);

        // -- memory bases for EIP-2537-padded commitments (4 words each) --
        // The template emits a named Solidity constant for each base so
        // the hand-written proof-reading loops can use friendly
        // identifiers like `ADVICE_COMMS_MPTR_BASE`. The PCS code
        // generated below operates on absolute integer offsets so it
        // matches the constant values exactly.
        // ------------------------------------------------------------
        // Optimisation H3: pre-decode polynomial evaluations.
        //
        // Each polynomial evaluation in the proof is referenced multiple
        // times across the gate evaluator (cp12) and the PCS q_eval Horner
        // accumulators (cp14). The Solidity proof shim rewrites scalar proof
        // bytes into canonical BE calldata words, so the transcript-side
        // evaluations loop can range-check and spill the decoded value once.
        //
        // We add a single `mstore` per iter to spill the decoded value into a
        // contiguous memory buffer at REVERSED_EVALS_MPTR. Every later eval
        // reference then becomes `mload(N)` instead of a calldata read.
        //
        // To make this transparent to the codegen, we construct
        // `eval_cptr` as a *Memory* Ptr pointing at REVERSED_EVALS_MPTR
        // instead of a Calldata Ptr. All eval Words built via
        // `Word::range(eval_cptr)` (committed_instance_evals,
        // advice_evals, fixed_evals, permutation_evals,
        // permutation_z_evals, lookup_evals, trashcan_evals) inherit
        // the Memory location, so `Word::Display` renders them as
        // `mload(...)` automatically.
        //
        // The calldata-side reading code (transcript loop) keeps a
        // separate `eval_cd` byte offset for the per-iter
        // `calldataload(proof_cptr)`.
        //
        let reversed_evals_mptr = memory.reversed_evals_mptr;
        let eval_cptr = reversed_evals_mptr;
        let comms_mptr_base = memory.comms_mptr_base;
        let lookup_m_comm_mem_base = memory.lookup_m_comms_mptr_base;
        let perm_z_comm_mem_base = memory.perm_z_comms_mptr_base;
        let lookup_helper_comm_mem_base = memory.lookup_helper_comms_mptr_base;
        let lookup_z_comm_mem_base = memory.lookup_z_comms_mptr_base;
        let trashcan_comm_mem_base = memory.trashcan_comms_mptr_base;

        let fixed_comms = EcPoint::range(fixed_comm_mptr)
            .take(meta.num_fixeds)
            .collect();
        // Committed instance commitments: all point at the same memory
        // slot (G1_IDENTITY_MPTR) since the zk_stdlib `verify` path
        // passes `committed_pi = G1::identity()`. The memory at that
        // slot is never written and EVM memory is zero-initialised, so
        // the four `mload` reads produce the identity encoding.
        let committed_instance_comms: Vec<EcPoint> = (0..meta.num_committed_instances)
            .map(|_| EcPoint::new(Ptr::memory("G1_IDENTITY_MPTR")))
            .collect();
        let permutation_comms = izip!(
            meta.permutation_columns.iter().cloned(),
            EcPoint::range(permutation_comm_mptr)
        )
        .collect();
        let advice_comms = meta
            .advice_indices
            .iter()
            .map(|idx| comms_mptr_base + G1_WORDS * idx)
            .map_into()
            .collect();
        let lookup_m_comms = EcPoint::range(lookup_m_comm_mem_base)
            .take(meta.num_lookups)
            .collect();
        let permutation_z_comms = EcPoint::range(perm_z_comm_mem_base)
            .take(meta.num_permutation_zs)
            .collect();

        // Group helpers per lookup by lookup_chunks[i].
        let mut lookup_helper_comms: Vec<Vec<EcPoint>> = Vec::with_capacity(meta.num_lookups);
        let mut helper_cursor = lookup_helper_comm_mem_base;
        for &chunks in &meta.lookup_chunks {
            let row: Vec<EcPoint> = EcPoint::range(helper_cursor).take(chunks).collect();
            helper_cursor = helper_cursor + G1_WORDS * chunks;
            lookup_helper_comms.push(row);
        }
        let lookup_z_comms = EcPoint::range(lookup_z_comm_mem_base)
            .take(meta.num_lookups)
            .collect();
        let trashcan_comms = EcPoint::range(trashcan_comm_mem_base)
            .take(meta.num_trashcans)
            .collect();
        let computed_quotient_comm = EcPoint::new(Ptr::memory("QUOTIENT_MPTR"));

        let challenges = meta
            .challenge_indices
            .iter()
            .map(|idx| challenge_mptr + *idx)
            .map_into()
            .collect_vec();
        let instance_eval = Ptr::memory("INSTANCE_EVAL_MPTR").into();

        // Main proof evaluations are assigned by the typed protocol plan.
        // This replaces the old category-by-category cursor walk with a
        // single checked schedule shared with the PCS query construction.
        let mut committed_instance_evals: HashMap<(usize, i32), Word> = HashMap::new();
        let mut advice_evals: HashMap<(usize, i32), Word> = HashMap::new();
        let mut fixed_evals: HashMap<(usize, i32), Word> = HashMap::new();
        let mut permutation_evals: HashMap<Column<Any>, Word> = HashMap::new();
        let mut permutation_z_slots: Vec<(Option<Word>, Option<Word>, Option<Word>)> =
            vec![(None, None, None); meta.num_permutation_zs];
        let mut lookup_slots: Vec<LookupEvalSlots> = meta
            .lookup_chunks
            .iter()
            .map(|&chunks| (None, vec![None; chunks], None, None))
            .collect();
        let mut trashcan_slots: Vec<Option<Word>> = vec![None; meta.num_trashcans];

        assert_eq!(
            meta.protocol.proof.evals.len(),
            meta.num_main_evals(),
            "protocol proof eval plan must match main eval count"
        );
        for (read, word) in meta
            .protocol
            .proof
            .evals
            .iter()
            .copied()
            .zip(Word::range(eval_cptr))
        {
            match read {
                EvalRead::CommittedInstance(q) => {
                    committed_instance_evals.insert(q.tuple(), word);
                }
                EvalRead::Advice(q) => {
                    advice_evals.insert(q.tuple(), word);
                }
                EvalRead::Fixed(q) => {
                    fixed_evals.insert(q.tuple(), word);
                }
                EvalRead::PermutationCommon { column } => {
                    permutation_evals.insert(column, word);
                }
                EvalRead::PermutationZ { set, kind } => {
                    let slot = permutation_z_slots
                        .get_mut(set)
                        .expect("permutation z eval set in bounds");
                    match kind {
                        PermutationZEval::Cur => slot.0 = Some(word),
                        PermutationZEval::Next => slot.1 = Some(word),
                        PermutationZEval::Last => slot.2 = Some(word),
                    }
                }
                EvalRead::LookupMultiplicity { lookup } => {
                    lookup_slots
                        .get_mut(lookup)
                        .expect("lookup multiplicity in bounds")
                        .0 = Some(word);
                }
                EvalRead::LookupHelper { lookup, chunk } => {
                    lookup_slots
                        .get_mut(lookup)
                        .and_then(|(_, helpers, _, _)| helpers.get_mut(chunk))
                        .expect("lookup helper eval in bounds")
                        .replace(word);
                }
                EvalRead::LookupAccumulator { lookup, rotation } => {
                    let slot = lookup_slots
                        .get_mut(lookup)
                        .expect("lookup accumulator in bounds");
                    match rotation {
                        0 => slot.2 = Some(word),
                        1 => slot.3 = Some(word),
                        _ => panic!("unsupported lookup accumulator rotation {rotation}"),
                    }
                }
                EvalRead::Trash { index } => {
                    trashcan_slots
                        .get_mut(index)
                        .expect("trash eval in bounds")
                        .replace(word);
                }
            }
        }

        let permutation_z_evals: Vec<(Word, Word, Option<Word>)> = permutation_z_slots
            .into_iter()
            .enumerate()
            .map(|(set_idx, (cur, next, last))| {
                let cur = cur.unwrap_or_else(|| panic!("missing permutation z[{set_idx}] cur"));
                let next = next.unwrap_or_else(|| panic!("missing permutation z[{set_idx}] next"));
                (cur, next, last)
            })
            .collect();
        let lookup_evals: Vec<(Word, Vec<Word>, Word, Word)> = lookup_slots
            .into_iter()
            .enumerate()
            .map(|(lookup_idx, (m, helpers, z, z_next))| {
                let m = m.unwrap_or_else(|| panic!("missing lookup[{lookup_idx}] multiplicity"));
                let helpers = helpers
                    .into_iter()
                    .enumerate()
                    .map(|(chunk, helper)| {
                        helper.unwrap_or_else(|| {
                            panic!("missing lookup[{lookup_idx}] helper[{chunk}]")
                        })
                    })
                    .collect();
                let z = z.unwrap_or_else(|| panic!("missing lookup[{lookup_idx}] accumulator"));
                let z_next = z_next
                    .unwrap_or_else(|| panic!("missing lookup[{lookup_idx}] next accumulator"));
                (m, helpers, z, z_next)
            })
            .collect();
        let trashcan_evals: Vec<Word> = trashcan_slots
            .into_iter()
            .enumerate()
            .map(|(index, word)| word.unwrap_or_else(|| panic!("missing trash eval[{index}]")))
            .collect();

        let computed_quotient_eval = Ptr::memory("QUOTIENT_EVAL_MPTR").into();

        Self {
            challenge_mptr,
            theta_mptr,
            quotient_comm_cptr: quotient_comm_start,
            w_cptr,
            fixed_comms,
            permutation_comms,
            advice_comms,
            committed_instance_comms,
            permutation_z_comms,
            lookup_m_comms,
            lookup_helper_comms,
            lookup_z_comms,
            trashcan_comms,
            computed_quotient_comm,
            challenges,
            instance_eval,
            committed_instance_evals,
            advice_evals,
            fixed_evals,
            permutation_evals,
            permutation_z_evals,
            lookup_evals,
            trashcan_evals,
            computed_quotient_eval,
            comms_mptr_base,
            quotient_limb_cptr: Ptr::calldata(proof_layout.quotient_comm_cptr),
            reversed_evals_mptr,
            // Default: no dummy queries (fewer-point-sets disabled).
            // The caller can populate this via `set_dummy_eval_words`
            // after running the PCS dummy-query planner to
            // size the buffer.
            dummy_eval_words: Vec::new(),
        }
    }

    /// Allocate `n` dummy eval Words at
    /// `REVERSED_EVALS_MPTR + (num_main_evals + i) * 0x20` for i in 0..n,
    /// for the `fewer-point-sets` path.
    ///
    /// Wiring: `SolidityGenerator::generate_verifier` builds `Data`
    /// twice. The first build (with `num_dummy_evals = 0`) lets us
    /// run the PCS dummy-query planner over the raw query
    /// list. The second build is against a `ConstraintSystemMeta`
    /// whose `num_evals` already includes the dummies (see
    /// [`ConstraintSystemMeta::set_num_dummy_evals`]); this method
    /// then populates `dummy_eval_words` with Word handles pointing
    /// at the dummy slots in the same `REVERSED_EVALS_MPTR` buffer.
    pub(crate) fn set_dummy_eval_words(&mut self, num_main_evals: usize, n: usize) {
        self.dummy_eval_words = (0..n)
            .map(|i| Word::from(self.reversed_evals_mptr + num_main_evals + i))
            .collect();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Location {
    /// A value loaded from calldata.
    Calldata,
    /// A value loaded from EVM memory.
    Memory,
}

impl Location {
    /// Yul load opcode for this location.
    fn opcode(&self) -> &'static str {
        match self {
            Location::Calldata => "calldataload",
            Location::Memory => "mload",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    /// Byte offset stored as signed so that the BLS code-gen can compute
    /// `ptr - N` even when `N` exceeds the original offset (the result
    /// only ever appears as `ptr_end` in `lt(ptr_end, ptr)` style loops
    /// where any value strictly less than the smallest visited address is
    /// acceptable).
    Integer(isize),
    /// A symbolic Yul identifier `name`, with an optional byte-offset that
    /// will be rendered as `add(name, 0xNN)` (or just `name` when zero).
    Identifier(&'static str, isize),
}

impl Value {
    /// Return true when this value is a concrete byte offset.
    pub(crate) fn is_integer(&self) -> bool {
        matches!(self, Value::Integer(_))
    }

    /// Return the concrete offset, panicking for symbolic identifiers.
    pub(crate) fn as_usize(&self) -> usize {
        match self {
            Value::Integer(int) => *int as usize,
            Value::Identifier(..) => unreachable!(),
        }
    }
}

impl Default for Value {
    /// Default to the zero byte offset.
    fn default() -> Self {
        Self::Integer(0)
    }
}

impl From<&'static str> for Value {
    /// Convert a Yul identifier into a symbolic pointer value.
    fn from(ident: &'static str) -> Self {
        Value::Identifier(ident, 0)
    }
}

impl From<usize> for Value {
    /// Convert a concrete byte offset into a pointer value.
    fn from(int: usize) -> Self {
        Value::Integer(int as isize)
    }
}

/// Format an integer byte offset as a stable even-width Yul hex literal.
fn fmt_hex(off: isize) -> String {
    let hex = format!("{:x}", off as usize);
    if hex.len() % 2 == 1 {
        format!("0x0{hex}")
    } else {
        format!("0x{hex}")
    }
}

impl Display for Value {
    /// Render the value as a Yul pointer expression.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Value::Integer(int) if *int >= 0 => write!(f, "{}", fmt_hex(*int)),
            Value::Integer(int) => write!(f, "sub(0, {})", fmt_hex(-*int)),
            Value::Identifier(ident, 0) => write!(f, "{ident}"),
            Value::Identifier(ident, off) if *off > 0 => {
                write!(f, "add({ident}, {})", fmt_hex(*off))
            }
            Value::Identifier(ident, off) => {
                write!(f, "sub({ident}, {})", fmt_hex(-*off))
            }
        }
    }
}

impl Add<usize> for Value {
    type Output = Value;
    /// Advance by `rhs` EVM words.
    fn add(self, rhs: usize) -> Self::Output {
        match self {
            Value::Integer(int) => Value::Integer(int + (rhs as isize) * WORD_BYTES as isize),
            Value::Identifier(name, off) => {
                Value::Identifier(name, off + (rhs as isize) * WORD_BYTES as isize)
            }
        }
    }
}

impl Sub<usize> for Value {
    type Output = Value;
    /// Move backward by `rhs` EVM words.
    fn sub(self, rhs: usize) -> Self::Output {
        match self {
            Value::Integer(int) => Value::Integer(int - (rhs as isize) * WORD_BYTES as isize),
            Value::Identifier(name, off) => {
                Value::Identifier(name, off - (rhs as isize) * WORD_BYTES as isize)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ptr {
    loc: Location,
    value: Value,
}

impl Ptr {
    /// Construct a pointer at a location with a concrete or symbolic value.
    pub(crate) fn new(loc: Location, value: impl Into<Value>) -> Self {
        Self {
            loc,
            value: value.into(),
        }
    }

    /// Construct a memory pointer.
    pub(crate) fn memory(value: impl Into<Value>) -> Self {
        Self::new(Location::Memory, value.into())
    }

    /// Construct a calldata pointer.
    pub(crate) fn calldata(value: impl Into<Value>) -> Self {
        Self::new(Location::Calldata, value.into())
    }

    /// Return whether this pointer targets calldata or memory.
    pub(crate) fn loc(&self) -> Location {
        self.loc
    }

    /// Return the underlying byte-offset expression.
    pub(crate) fn value(&self) -> Value {
        self.value
    }
}

impl Display for Ptr {
    /// Render the pointer's byte-offset expression.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl Add<usize> for Ptr {
    type Output = Ptr;
    /// Advance by `rhs` EVM words while preserving location.
    fn add(mut self, rhs: usize) -> Self::Output {
        self.value = self.value + rhs;
        self
    }
}

impl Sub<usize> for Ptr {
    type Output = Ptr;
    /// Move backward by `rhs` EVM words while preserving location.
    fn sub(mut self, rhs: usize) -> Self::Output {
        self.value = self.value - rhs;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Word(Ptr);

impl Word {
    /// Infinite iterator of consecutive word handles starting at `word`.
    pub(crate) fn range(word: impl Into<Word>) -> impl Iterator<Item = Word> {
        let ptr = word.into().ptr();
        (0..).map(move |idx| ptr + idx).map_into()
    }

    /// Return the pointer backing this word.
    pub(crate) fn ptr(&self) -> Ptr {
        self.0
    }

    /// Return whether the word is loaded from calldata or memory.
    pub(crate) fn loc(&self) -> Location {
        self.0.loc()
    }
}

impl Display for Word {
    /// Render as the appropriate Yul load expression.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // For Calldata-located Words (proof evals/q_evals), the Solidity
        // proof shim stores scalars as canonical BE words, so calldataload
        // gives the field-element value directly.
        match self.0.loc {
            Location::Calldata => write!(f, "calldataload({})", self.0.value),
            Location::Memory => write!(f, "mload({})", self.0.value),
        }
    }
}

impl From<Ptr> for Word {
    /// Treat a pointer as the start of one word.
    fn from(ptr: Ptr) -> Self {
        Self(ptr)
    }
}

/// EIP-2537-padded G1 point handle in calldata or memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EcPoint {
    base: Ptr,
}

impl EcPoint {
    /// Construct a point handle at its first word.
    pub(crate) fn new(base: impl Into<Ptr>) -> Self {
        Self { base: base.into() }
    }

    /// Infinite iterator of consecutive padded G1 points.
    pub(crate) fn range(base: impl Into<EcPoint>) -> impl Iterator<Item = EcPoint> {
        let base = base.into().base;
        (0..).map(move |idx| EcPoint::new(base + 4 * idx))
    }

    /// Return whether the point is loaded from calldata or memory.
    pub(crate) fn loc(&self) -> Location {
        self.base.loc()
    }

    /// Return the pointer to the first word.
    pub(crate) fn ptr(&self) -> Ptr {
        self.base
    }

    /// High word of the x coordinate.
    pub(crate) fn x_hi(&self) -> Word {
        Word::from(self.base)
    }
    /// Low word of the x coordinate.
    pub(crate) fn x_lo(&self) -> Word {
        Word::from(self.base + 1)
    }
    /// High word of the y coordinate.
    pub(crate) fn y_hi(&self) -> Word {
        Word::from(self.base + 2)
    }
    /// Low word of the y coordinate.
    pub(crate) fn y_lo(&self) -> Word {
        Word::from(self.base + 3)
    }

    /// All four EIP-2537 words in order.
    pub(crate) fn words(&self) -> [Word; 4] {
        [self.x_hi(), self.x_lo(), self.y_hi(), self.y_lo()]
    }
}

impl From<Ptr> for EcPoint {
    /// Treat a pointer as the first word of a padded G1 point.
    fn from(ptr: Ptr) -> Self {
        Self::new(ptr)
    }
}

/// Emit four `mstore` statements that copy one padded G1 point.
pub(crate) fn copy_g1_point(dst_base: Ptr, src: &EcPoint) -> [String; 4] {
    let [x_hi, x_lo, y_hi, y_lo] = src.words();
    [
        format!("mstore({}, {x_hi})", dst_base),
        format!("mstore({}, {x_lo})", dst_base + 1),
        format!("mstore({}, {y_hi})", dst_base + 2),
        format!("mstore({}, {y_lo})", dst_base + 3),
    ]
}

/// Indent generated Yul lines by `N` four-space levels.
pub(crate) fn indent<const N: usize>(
    lines: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| format!("{}{}", " ".repeat(N * 4), line.into()))
        .collect()
}

/// Render a Yul block around generated lines.
///
/// `PACKED` renders single-line blocks as `{ stmt }`, which keeps compact
/// `for` clauses readable.
pub(crate) fn code_block<const N: usize, const PACKED: bool>(
    lines: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    let lines = lines.into_iter().map_into().collect_vec();
    let bracket_indent = " ".repeat((N - 1) * 4);
    match lines.len() {
        0 => vec![format!("{bracket_indent}{{}}")],
        1 if PACKED => vec![format!("{bracket_indent}{{ {} }}", lines[0])],
        _ => chain![
            [format!("{bracket_indent}{{")],
            indent::<N>(lines),
            [format!("{bracket_indent}}}")],
        ]
        .collect(),
    }
}

/// Build a formatted Yul `for` loop from initialization, condition, step, and body.
pub(crate) fn for_loop(
    initialization: impl IntoIterator<Item = impl Into<String>>,
    condition: impl Into<String>,
    advancement: impl IntoIterator<Item = impl Into<String>>,
    body: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    chain![
        ["for".to_string()],
        code_block::<2, true>(initialization),
        indent::<1>([condition.into()]),
        code_block::<2, true>(advancement),
        code_block::<1, false>(body),
    ]
    .collect()
}

/// Group adjacent words that walk backward by one word in the same location.
pub(crate) fn group_backward_adjacent_words<'a>(
    words: impl IntoIterator<Item = &'a Word>,
) -> Vec<(Location, Vec<&'a Word>)> {
    words.into_iter().fold(Vec::new(), |mut word_groups, word| {
        if let Some(last_group) = word_groups.last_mut() {
            let last_word = **last_group.1.last().unwrap();
            if last_group.0 == word.loc()
                && last_word.ptr().value().is_integer()
                && last_word.ptr() - 1 == word.ptr()
            {
                last_group.1.push(word)
            } else {
                word_groups.push((word.loc(), vec![word]))
            }
            word_groups
        } else {
            vec![(word.loc(), vec![word])]
        }
    })
}

/// Group adjacent G1 points that walk backward by one point in the same location.
pub(crate) fn group_backward_adjacent_ec_points<'a>(
    ec_point: impl IntoIterator<Item = &'a EcPoint>,
) -> Vec<(Location, Vec<&'a EcPoint>)> {
    ec_point
        .into_iter()
        .fold(Vec::new(), |mut ec_point_groups, ec_point| {
            if let Some(last_group) = ec_point_groups.last_mut() {
                let last_ec_point = **last_group.1.last().unwrap();
                if last_group.0 == ec_point.loc()
                    && last_ec_point.ptr().value().is_integer()
                    && last_ec_point.ptr() - 4 == ec_point.ptr()
                {
                    last_group.1.push(ec_point)
                } else {
                    ec_point_groups.push((ec_point.loc(), vec![ec_point]))
                }
                ec_point_groups
            } else {
                vec![(ec_point.loc(), vec![ec_point])]
            }
        })
}

// ----------------------------------------------------------------------------
// BLS12-381 EIP-2537 encoding helpers. The shape of the encoded U256 array
// matches the padded precompile calldata expected by the generated verifier.
// ----------------------------------------------------------------------------

/// Split a 48-byte big-endian Fp coordinate into EIP-2537 hi/lo words.
fn fp48_be_to_hi_lo(be: &[u8]) -> (U256, U256) {
    debug_assert_eq!(be.len(), BLS_FP_BYTES);
    let mut hi_bytes = [0u8; 32];
    hi_bytes[EIP2537_FP_PAD_BYTES..].copy_from_slice(&be[..EIP2537_FP_PAD_BYTES]);
    let mut lo_bytes = [0u8; 32];
    lo_bytes.copy_from_slice(&be[EIP2537_FP_PAD_BYTES..]);
    (U256::from_be_bytes(hi_bytes), U256::from_be_bytes(lo_bytes))
}

/// Encode a midnight-curves G1 point in EIP-2537 padded form (4 u256 words).
///
/// `Fp::to_repr()` returns *little-endian* 48 bytes (FpRepr). We reverse to
/// big-endian and split (hi=top 16 bytes padded into u256, lo=bottom 32
/// bytes).
pub(crate) fn g1_to_u256s(ec_point: impl Borrow<G1Affine>) -> [U256; 4] {
    let Some(coords) = Option::<Coordinates<G1Affine>>::from(ec_point.borrow().coordinates())
    else {
        return [U256::ZERO; 4];
    };
    let mut x_be = [0u8; BLS_FP_BYTES];
    x_be.copy_from_slice(coords.x().to_repr().as_ref());
    x_be.reverse();
    let mut y_be = [0u8; BLS_FP_BYTES];
    y_be.copy_from_slice(coords.y().to_repr().as_ref());
    y_be.reverse();
    let (x_hi, x_lo) = fp48_be_to_hi_lo(&x_be);
    let (y_hi, y_lo) = fp48_be_to_hi_lo(&y_be);
    [x_hi, x_lo, y_hi, y_lo]
}

/// Encode a midnight-curves G2 point in EIP-2537 padded form (8 u256 words).
///
/// G2 coordinates are `Fp2` with c0/c1 components, each a 48-byte
/// little-endian Fp. EIP-2537 expects (c0, c1) for both x and y, packed
/// in big-endian per coord. The midnight-curves convention matches:
/// each `Fp` coordinate read via `to_repr()` returns LE bytes.
pub(crate) fn g2_to_u256s(ec_point: impl Borrow<G2Affine>) -> [U256; 8] {
    let Some(coords) = Option::<Coordinates<G2Affine>>::from(ec_point.borrow().coordinates())
    else {
        return [U256::ZERO; 8];
    };

    let pack_fp = |fp: midnight_curves::Fp| -> [u8; BLS_FP_BYTES] {
        let mut be = [0u8; BLS_FP_BYTES];
        be.copy_from_slice(fp.to_repr().as_ref());
        be.reverse();
        be
    };

    let x = coords.x();
    let y = coords.y();

    let x0 = pack_fp(x.c0());
    let x1 = pack_fp(x.c1());
    let y0 = pack_fp(y.c0());
    let y1 = pack_fp(y.c1());

    let (x0_hi, x0_lo) = fp48_be_to_hi_lo(&x0);
    let (x1_hi, x1_lo) = fp48_be_to_hi_lo(&x1);
    let (y0_hi, y0_lo) = fp48_be_to_hi_lo(&y0);
    let (y1_hi, y1_lo) = fp48_be_to_hi_lo(&y1);
    [x0_hi, x0_lo, x1_hi, x1_lo, y0_hi, y0_lo, y1_hi, y1_lo]
}

/// Convert a 32-byte little-endian prime-field representation into `U256`.
pub(crate) fn fe_to_u256<F>(fe: impl Borrow<F>) -> U256
where
    F: PrimeField,
    F::Repr: AsRef<[u8]>,
{
    let repr = fe.borrow().to_repr();
    let bytes = repr.as_ref();
    debug_assert_eq!(bytes.len(), 32, "fe_to_u256 expects 32-byte repr");
    let mut le = [0u8; 32];
    le.copy_from_slice(bytes);
    U256::from_le_bytes(le)
}

/// Convert an integer-like value into one 32-byte big-endian EVM word.
pub(crate) fn to_u256_be_bytes<T>(value: T) -> [u8; 32]
where
    U256: UintTryFrom<T>,
{
    U256::from(value).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::{Curve, Group};
    use midnight_curves::{G1Projective, G2Projective};

    #[test]
    fn eip2537_encoders_accept_identity_points() {
        let g1 = G1Projective::identity().to_affine();
        let g2 = G2Projective::identity().to_affine();

        assert_eq!(g1_to_u256s(g1), [U256::ZERO; 4]);
        assert_eq!(g2_to_u256s(g2), [U256::ZERO; 8]);
    }
}
