//! Stub PCS emitter.
//!
//! **Migration status (Steps 1-3, 2026-04-26)**: this module is empty
//! while the real midnight-proofs `multi_prepare` Yul translation is
//! prepared in MIGRATION.md Step 5. The previous halo2-era GWC19 emitter
//! has been removed because its rotation-set / trailing-W shape does not
//! map to midnight-proofs (which emits `f_com` / `pi` and `q_evals`
//! per point set, with separate `x1, x2, x3, x4` challenges).
//!
//! Returning empty vecs here keeps `cargo check --lib` green; the
//! generated Solidity will be incomplete until Step 5 lands.

#![allow(dead_code)]

use crate::codegen::util::{ConstraintSystemMeta, Data};

pub(super) fn static_working_memory_size(_meta: &ConstraintSystemMeta, _data: &Data) -> usize {
    // Reserve enough scratch for the eventual pairing call (2 G1 + 2 G2
    // = 24 words) so callers have room while we finish Step 5.
    25
}

pub(super) fn computations(_meta: &ConstraintSystemMeta, _data: &Data) -> Vec<Vec<String>> {
    Vec::new()
}
