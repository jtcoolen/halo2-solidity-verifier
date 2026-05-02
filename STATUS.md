# Solidity Verifier Soundness Status

I read through the Rust verifier (`midfall/proofs/src/plonk/verifier.rs` plus
`linearization/verifier.rs`, `permutation/verifier.rs`, `logup/verifier.rs`,
`trash/verifier.rs`, `partially_evaluate_identities`, and
`KZGCommitmentScheme::multi_prepare` / `DualMSM::check`), then walked the
Solidity templates (`templates/Halo2Verifier.sol`) and the codegen
(`src/codegen.rs`, `codegen/util.rs`, `codegen/evaluator.rs`,
`codegen/pcs/gwc19.rs`).

Short answer: **the Solidity verifier mirrors the high-level shape of the
Rust one and re-derives the same algebraic identity / linearization / KZG
pairing relation, but it is not a complete, generic 1-to-1 port. It is
currently a migration target hard-wired to a narrow circuit shape, with
several soundness-relevant simplifications, and the end-to-end integration
test (`tests/poseidon_fixture.rs`) is still `#[ignore]`d / failing per
`MIGRATION.md`. The code therefore should not be considered audited-sound
today.**

## What is encoded (matches Rust)

| Rust check | Solidity counterpart |
|---|---|
| `vk.hash_into(transcript)` | `common_word(buf_len, mload(VK_DIGEST_MPTR))` |
| Keccak transcript data append + one-digest squeeze/reseed + BE digest modulo-r sampling | `transcript_init`, `common_word`, `common_uncompressed_g1`, `squeeze_to` |
| Per user-phase advices then per-phase challenge squeeze; then `theta`, lookup multiplicities, `beta`, `gamma`, perm-Z, lookup helpers + accumulators, `trash_challenge`, trashcans, `y`, quotient limbs, `x`, evals, `x1, x2`, `f_com`, `x3`, `q_evals`, `x4`, `pi` | Same schedule in the Yul body |
| Canonical scalar bound on every Fq read | `success := and(success, lt(eval, r))` for every instance / eval / q_eval |
| `partially_evaluate_identities` (gates → permutation → logup → trash) | `Evaluator::{gate_computations_tagged, permutation_computations, lookup_computations, trashcan_computations}` Horner-folded with `y` |
| `compute_linearization_commitment`: quotient limbs scaled by `(1-x^n)·x^(k(n-1))` + simple-selector fixed comms with `Σ y^k·eval_k`, eval target `-Σ eval_k` | Quotient-fold block + simple-selector loop, `quotient_eval := sub(r, quotient_eval_numer)` |
| `construct_intermediate_sets` (BTreeSet of point indices, sort by `(len, i)`) | `pcs/gwc19.rs::construct_intermediate_sets_impl` + `sort_sets` |
| `multi_prepare`: `q_com[s]=Σx1^i·c_i`, `q_eval_set[s]=Σx1^i·evals_i`, `f_eval` via Lagrange at `x3`, `final_com = Σ x4^s·q_com[s] + x4^N·f_com`, `v` analogous, `DualMSM(left=π, right=final_com − v·G + x3·π)` | Six emitted Yul blocks producing exactly that decomposition |
| Pairing `e(π, [s]_2) = e(final_com − v·G + x3·π, [1]_2)` | `ec_pairing(success, PAIRING_RHS_MPTR, PAIRING_LHS_MPTR)` against `G2_BASE` and `NEG_S_G2_BASE` |
| Trailing-bytes rejection (Rust transcript errors on extra reads) | `eq(calldatasize(), add(INSTANCE_CPTR, mul(0x20, num_instances)))` and `eq(proof_len, calldataload(PROOF_LEN_CPTR))` |
| Adversarial VK rejection | Constructor pin: `AUTHORIZED_VK.code.length == EXPECTED_VK_LENGTH && codehash == EXPECTED_VK_CODEHASH` |

## Soundness-relevant gaps / divergences

1. **Hard-coded `committed_pi = G1::identity()` absorption (always exactly
   one).** The Rust loop is `for committed_instances in iter() { for
   commitment in iter() { transcript.common(commitment) }}` — i.e.
   `num_proofs × num_committed_instances` absorptions. The Yul
   unconditionally absorbs **one** 48-byte compressed-identity blob before
   the instance count, regardless of `num_committed_instances`. It only
   matches Rust when `num_proofs = 1` and `num_committed_instances ∈ {0, 1}`
   *and* (for the `0` case) the prover-side actually emitted that
   absorption. Any other shape diverges the Fiat-Shamir transcripts →
   silent acceptance of unrelated proofs is possible.

2. **Single non-committed instance column assumption.** Rust loops over
   each instance column and absorbs its length followed by its values.
   Solidity absorbs `num_instances` once, then a flat run of values. Holds
   only for one column (codegen `assert!(vk.cs().num_instance_columns() <=
   2)` plus `Rotation::cur` only).

3. **`num_proofs = 1` only.** The codegen builds `data` for a single
   proof; multi-proof verification (which the Rust verifier supports
   natively) is not encoded.

4. **G1 point validation deferred to EIP-2537.** Rust
   `transcript.read::<G1>()` decodes from compressed bytes and rejects
   off-curve / off-subgroup points before they enter the transcript. The
   Solidity verifier reads pre-decompressed `(x_hi, x_lo, y_hi, y_lo)`
   straight from calldata, masks off the EIP-2537 padding, computes the
   compressed form on the fly *purely from those four words*, and absorbs
   that. On-curve / subgroup checks happen only when the points hit
   `0x0b`/`0x0c`/`0x0f`. Soundness still holds because the precompile
   reverts on bad points, but the transcript can absorb gibberish bytes
   for invalid (x, y) inputs before that reject — the failure is
   detected, not prevented at transcript time.

5. **G2 trust.** `G2_BASE`, `NEG_S_G2_BASE` are read from VK with no
   field/curve/subgroup check. Soundness rests entirely on the
   deployment-time codehash pin (`AUDIT.md` §2 / F-9).

6. **Non-redundant VK constants.** `n_inv`, `omega_inv_to_l` are read
   from VK and not re-derived from `k`/`omega` on chain (audit I-11).
   Same risk model: pin-dependent.

7. **Carry-over open issues from `AUDIT.md`** (the file under `AUDIT.md`):
   - F-1: `static_working_memory_size` was originally BN254-stride; the
     post-Step-6 layout repositions the keccak buffer at `[0x00..buf_len)`
     *below* `vk_mptr`, but the comment still warns "if a future codegen
     change moves any MPTR past 0x6000, bump this constant in lock-step"
     — i.e. the keccak / scratch / VK separation is hand-maintained, not
     statically asserted.
   - F-2: empty-phase Fiat-Shamir mismatch (no Yul-side handling of
     `buf_len == 32` post-squeeze).
   - F-3 (latent): in Solidity the four `mstore` writes for compressed-G1
     happen *before* validity flags are checked.
   - F-4: limb decomposition uses native `add`/`shl` (the `if
     mload(HAS_ACCUMULATOR_MPTR)` block), no `addmod` on the limbs.
   - F-9: VK-driven `HAS_ACCUMULATOR_MPTR` is not cross-checked against
     codegen `acc_encoding`.

8. **Migration is incomplete.** `MIGRATION.md` Step 8 explicitly notes:
   "verifier reverts mid-execution with empty payload at gas ~123 k
   against the real proof", and `tests/poseidon_fixture.rs` is
   `#[ignore]`. The only currently green tests (`cargo test --lib`) are
   7 unit tests pinning the transcript, intermediate-sets bucketing, and
   VK-layout shape — none of them is an end-to-end soundness test
   against a real `(proof, vk, instance)` triple. Step 9 (PBT +
   soundness flips) is unwritten.

## Bottom line

For the very narrow regime the codegen targets — single proof, ≤ 1
committed instance column, exactly 1 non-committed instance column, all
instance queries at `Rotation::cur()`, no rotated instance queries,
BLS12-381 + EIP-2537, codehash-pinned VK — the algebraic structure of
every check the Rust verifier performs is reproduced in the Yul output:

- transcript / Fiat-Shamir is byte-equivalent (per the unit tests),
- gate / permutation / logup / trash identities are folded into
  `quotient_eval_numer` with the same `y`-power weighting,
- the linearization-commitment MSM uses the same scalars as
  `compute_linearization_commitment`,
- the multi-prepare PCS reconstructs `final_com − v·G + x3·π` and checks
  it against `π` via the BLS12-381 pairing precompile.

But there are real, documented gaps (committed-instance hardcode,
single-column instance schema, deferred point validation, multiple
audit-flagged items still open) and **no end-to-end fixture currently
passes** — `tests/poseidon_fixture.rs` is ignored and the in-flight
debug session in `MIGRATION.md` reports a still-failing revert. Until
that test is green and adversarial PBTs exist, treat the verifier as
"structurally aligned with the Rust spec, not yet operationally
verified".
