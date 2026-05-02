#![allow(dead_code)]

//! KZG multi-prepare PCS emitter.
//!
//! Step 5 of MIGRATION.md (2026-04-26). The previous halo2-era GWC19
//! emitter (one trailing `W` commitment per rotation set, `nu`/`mu`
//! reduction) has been replaced with the midnight-proofs
//! `KZGCommitmentScheme::multi_prepare` flow:
//!
//! ```text
//!   x1, x2  <- transcript squeeze (after evals)
//!   for each set s:
//!       q_com[s]      = sum_{q in s} x1^pos(q) * (msm of q's commitment)
//!       q_eval_set[s] = sum_{q in s} x1^pos(q) * eval(q)
//!   sort sets by ascending |set|, tiebreak by original index
//!   read f_com (1 G1)
//!   x3 <- transcript squeeze
//!   read q_evals[s]  (1 Fq per set)
//!   compute f_eval via Horner over reverse(point_sets):
//!       acc <- 0
//!       for (points, evals, proof_eval) in zip(point_sets, q_eval_sets, q_evals).rev():
//!           r_eval = lagrange_interpolate(points, evals).eval(x3)
//!           den    = prod_{p in points} (x3 - p)
//!           acc    = acc * x2 + (proof_eval - r_eval) * den.invert()
//!   x4 <- transcript squeeze
//!   final_com = msm_inner_product(q_coms ++ [f_com], powers(x4))
//!   v         = inner_product(q_evals_at_x3 ++ [f_eval], powers(x4))
//!   read pi (1 G1)
//!   PAIRING_LHS = pi
//!   PAIRING_RHS = final_com - v*G1 + x3*pi
//! ```
//!
//! See `midfall/proofs/src/poly/kzg/mod.rs::multi_prepare` for the
//! reference implementation.
//!
//! The Yul emitted here references the following symbolic identifiers:
//!
//! | Identifier        | Meaning                                                   |
//! |-------------------|-----------------------------------------------------------|
//! | `X1_MPTR`         | x1 challenge (Fq)                                         |
//! | `X2_MPTR`         | x2 challenge (Fq)                                         |
//! | `X3_MPTR`         | x3 challenge (Fq)                                         |
//! | `X4_MPTR`         | x4 challenge (Fq)                                         |
//! | `F_COM_MPTR`      | f_com point (4 EVM words, EIP-2537 padded)                |
//! | `PI_MPTR`         | pi point (4 EVM words, EIP-2537 padded)                   |
//! | `Q_EVAL_CPTR`     | calldata pointer to the first q_eval scalar (Fq)          |
//! | `G1_BASE_MPTR`    | (existing) BLS12-381 G1 generator (4 EVM words)           |
//! | `PAIRING_LHS_MPTR`/`PAIRING_RHS_MPTR` | (existing) pairing input slots        |
//!
//! The Step 6 template rewrite is responsible for:
//!   * squeezing x1..x4 into the corresponding MPTRs
//!   * validating and copying f_com / pi from EIP-2537-padded calldata
//!     into `F_COM_MPTR` / `PI_MPTR`
//!   * exposing the q_eval calldata block via `Q_EVAL_CPTR`
//!
//! For Step 5 we only emit the algebraic body; the template that
//! consumes it will be rewritten in Step 6.

use crate::codegen::util::{ConstraintSystemMeta, Data};

mod gwc19;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PcsScratchRequirements {
    pub(crate) rot_points_words: usize,
    pub(crate) x1_powers_words: usize,
    pub(crate) q_com_words: usize,
    pub(crate) q_eval_set_words: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchOpenScheme {
    /// Midnight-proofs multi-prepare KZG flow. The variant name is kept
    /// from the halo2 era for migration continuity; there is only one
    /// scheme.
    Gwc19,
}

impl BatchOpenScheme {
    pub(crate) fn static_working_memory_size(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
    ) -> usize {
        match self {
            Self::Gwc19 => gwc19::static_working_memory_size(meta, data),
        }
    }

    pub(crate) fn computations(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
        truncated_challenges: bool,
        trace: bool,
    ) -> Vec<Vec<String>> {
        match self {
            Self::Gwc19 => gwc19::computations(meta, data, truncated_challenges, trace),
        }
    }

    pub(crate) fn scratch_requirements(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
    ) -> PcsScratchRequirements {
        match self {
            Self::Gwc19 => gwc19::scratch_requirements(meta, data),
        }
    }

    /// G1 commitments emitted *after* the evaluation block. Multi-prepare
    /// emits exactly two: `f_com` and `pi`.
    pub(crate) fn num_trailing_g1_points(&self, _meta: &ConstraintSystemMeta) -> usize {
        match self {
            Self::Gwc19 => 2,
        }
    }

    /// Number of distinct point sets the verifier reads `q_evals` for.
    /// This is the size of the IntermediateSets vector returned by
    /// `gwc19::queries`. The metadata is computed by `SolidityGenerator`
    /// after building `Data` and stored back into `ConstraintSystemMeta`
    /// via `set_num_point_sets`, so it is available downstream when the
    /// template is rendered.
    pub(crate) fn num_point_sets(meta: &ConstraintSystemMeta, data: &Data) -> usize {
        gwc19::num_point_sets(meta, data)
    }

    /// Number of dummy `(commitment, point)` queries the
    /// fewer-point-sets path appends to the raw query list. Each dummy
    /// pulls one extra Fr scalar from the proof transcript before the
    /// x1/x2 squeeze. Pass the *raw* (un-augmented) `Data` to size the
    /// dummy buffer; the result is then plumbed back into a fresh
    /// `Data` via `Data::set_dummy_eval_words`.
    pub(crate) fn num_dummy_queries(meta: &ConstraintSystemMeta, data: &Data) -> usize {
        gwc19::num_dummy_queries(meta, data)
    }
}
