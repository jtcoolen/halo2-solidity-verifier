#![allow(dead_code)]

use crate::codegen::util::{ConstraintSystemMeta, Data};

mod gwc19;

/// PCS schemes supported by the codegen.
///
/// **Migration status (Steps 1-3, 2026-04-26)**: only GWC19 is exposed
/// as a placeholder. The midnight-proofs PCS is `KZGCommitmentScheme`'s
/// `multi_prepare`/`multi_open` flow (x1, x2, f_com, x3, q_evals, x4,
/// pi); see `MIGRATION.md` Step 5 for the planned rewrite of this
/// module. Until then, the GWC19 emitter delegates everything to a
/// zero-output stub so the codegen tree compiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchOpenScheme {
    /// Placeholder for the midnight-proofs multi-prepare KZG flow.
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
    ) -> Vec<Vec<String>> {
        match self {
            Self::Gwc19 => gwc19::computations(meta, data),
        }
    }

    /// Number of G1 commitments that appear *after* the evaluation block
    /// in the proof byte-stream. For midnight-proofs multi-prepare this
    /// is 2: `f_com` and `pi`.
    pub(crate) fn num_trailing_g1_points(&self, _meta: &ConstraintSystemMeta) -> usize {
        match self {
            Self::Gwc19 => 2,
        }
    }
}
