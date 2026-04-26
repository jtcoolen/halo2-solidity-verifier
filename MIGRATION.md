# `halo2-solidity-verifier-exp` -> midnight-proofs migration

Started: 2026-04-26.

## Goal

Replace the vendored halo2 v0.4 dependency with a path dep on
`midnight-proofs` (the midfall fork) so the codegen-based Solidity
verifier in this crate verifies proofs produced by midnight-proofs +
midnight-curves on BLS12-381 / EIP-2537.

The first verification target is the **poseidon** circuit fixture under
`midfall/proofs/solidity-verifier/fixtures/poseidon/` (`proof.bin`,
`vk.bin`, `instance.be`).

## Why three crates change at once

midnight-proofs differs from halo2 v0.4 in three ways that all affect
the Solidity verifier surface:

1. **LogUp lookup argument** (`midnight_proofs::plonk::logup`) replaces
   halo2's grand-product lookup. The proof carries one
   *multiplicity* commitment + N *helper* commitments + one
   *accumulator* commitment per lookup, plus eval at `x` and `omega*x`.
2. **Trash argument** (`midnight_proofs::plonk::trash`) is new. The
   proof carries one trashcan commitment per `cs.trashcans()` entry and
   one eval at `x`.
3. **KZG multi-prepare PCS**
   (`midnight_proofs::poly::kzg::KZGCommitmentScheme::multi_open`)
   replaces both halo2's GWC19 and SHPLONK emitters. The proof block
   ends with `(x1, x2, f_com, x3, q_evals_per_set, x4, pi)` instead of
   one `W` per rotation set.
4. **Keccak256 transcript** uses a domain separator + a 64-byte squeeze
   (two-fork pattern) + `Fq::from_uniform_bytes` for challenge sampling.
   This differs from halo2's "concat with 0x01 marker, single 32-byte
   digest, mod-r reduce" recipe.

## Plan

```
Step 1. Cargo.toml: dep swap (halo2_proofs/halo2_middleware/halo2_backend
        + halo2curves) -> midnight-proofs path dep + midnight-curves +
        ff + group.
Step 2. src/transcript.rs: full rewrite as Keccak256Transcript matching
        midnight_proofs::CircuitTranscript<Keccak256> byte-for-byte.
        Includes round-trip test against the upstream Rust impl.
Step 3. src/codegen/util.rs::ConstraintSystemMeta + Data: rebind to
        midnight_proofs::plonk::ConstraintSystem<Fq>; record logup
        chunk counts, trashcan count, num_simple_selectors,
        num_committed_instances. g1_to_u256s/g2_to_u256s migrated to
        midnight-curves types via AsRef<[u8]> on FpRepr.

------------------ Steps 1-3 land here. cargo check --lib + cargo
                  test --lib transcript pass. ------------------

Step 4. src/codegen/evaluator.rs: implement permutation_computations,
        lookup_computations, and trashcan_computations against the
        midnight-proofs argument expressions
        (proofs/src/plonk/{permutation,logup,trash}.rs::expressions).
        The gate emitter is already ported.
Step 5. src/codegen/pcs.rs + pcs/gwc19.rs: replace the rotation-set
        emitter with the multi_prepare flow:
          * read x1, x2 from squeeze
          * read f_com (1 G1)
          * read x3 from squeeze
          * read q_evals (1 Fq per point set; point sets come from
            construct_intermediate_sets after deduplication)
          * read x4 from squeeze
          * read pi (1 G1)
          * compute the verifier MSM into PAIRING_LHS / PAIRING_RHS
        Two G1s + #point-sets Fqs replace the previous trailing-W loop.
Step 6. templates/Halo2Verifier.sol: rewrite the Yul body to read the
        new proof byte stream (compressed 48-byte G1 -> in-EVM
        decompression -> EIP-2537 padded form), squeeze challenges via
        the 64-byte two-fork keccak, and execute the PCS check from
        Step 5. Embed the lookup helpers/accumulators + trashcans
        between user-phase advices and the quotient limbs.
Step 7. templates/Halo2VerifyingKey.sol: regenerate the const layout to
        match the new ConstraintSystemMeta (per-lookup chunk counts,
        per-trashcan tables, num_simple_selectors). Constants block is
        no longer fixed-size, so the embedded-VK / separate-VK paths
        must agree on a length-prefix.
Step 8. examples/: port `compare_trace`, `trace`, `separately`,
        `probe_revert`, `check_delta` to the new SolidityGenerator API.
        Add a `verify_poseidon` example that loads
        midfall/proofs/solidity-verifier/fixtures/poseidon/{proof.bin,
        vk.bin, instance.be} and executes
        encode_calldata + Evm::call against the rendered Halo2Verifier.
Step 9. tests/: PBT + soundness tests against the rendered verifier.
        Mirror the existing approach in
        midfall/proofs/solidity-verifier/tests/.
```

## What landed in Steps 1-6

### Steps 1-3

* `Cargo.toml` — swapped dep tree; `cargo check --lib` resolves
  midnight-proofs and midnight-curves.
* `src/transcript.rs` — new `Keccak256Transcript<S>` matches
  `CircuitTranscript<Keccak256>` byte-for-byte. Three round-trip tests
  pass:
    * `empty_squeeze_matches_midnight_proofs`
    * `common_scalar_then_squeeze_matches`
    * `common_g1_then_squeeze_matches`
* `src/codegen/util.rs::ConstraintSystemMeta` — walks
  `midnight_proofs::plonk::ConstraintSystem<Fq>`. New fields:
  `lookup_chunks: Vec<usize>` (one per lookup), `num_lookups`,
  `num_trashcans`, `num_simple_selectors`, `num_committed_instances`.
  `num_advices()` and `num_challenges()` emit per-phase counts that
  match the midnight-proofs proof byte stream.
* `src/codegen/util.rs::Data` — gains `lookup_m_comms`,
  `lookup_helper_comms: Vec<Vec<EcPoint>>`, `lookup_z_comms`,
  `trashcan_comms`, `lookup_evals: Vec<(m, [helpers], z, z_next)>`,
  `trashcan_evals`. Permutation map is keyed by `Column<Any>`.
* `src/codegen/util.rs::g1_to_u256s` / `g2_to_u256s` — now consume
  midnight-curves `G1Affine` / `G2Affine`. The `FpRepr([u8; 48])` tuple
  field is private upstream, so we read via `AsRef<[u8]>` and
  `copy_from_slice`.
* `src/codegen/evaluator.rs::Evaluator` — `gate_computations()` is fully
  ported. `permutation_computations()`, `lookup_computations()`, and
  `trashcan_computations()` are stubbed empty pending Step 4.
  Expression walking uses the 10-callback `Expression::evaluate`
  visitor; queries use `column_index()` / `rotation()` accessors
  (private fields upstream). Selectors panic — they should already be
  removed during `directly_convert_selectors_to_fixed`.
* `src/codegen.rs::SolidityGenerator` — takes
  `&ParamsKZG<Bls12>` and
  `&VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>`. The `params.g[0]`
  field is crate-private upstream, so we use
  `G1Affine::generator()` for the SRS G1 generator. `g2()` / `s_g2()`
  return projective; we `.to_affine()` before EIP-2537 packing.
  `set_num_committed_instances(n)` exposes the `nb_committed_instances`
  knob (defaults to 0 for poseidon).
* `src/codegen/pcs.rs` and `src/codegen/pcs/gwc19.rs` — stubbed empty.
  Their previous halo2-era emitters did not map to multi-prepare.
* `src/codegen/template.rs::Halo2Verifier` — gains `num_lookups`,
  `num_trashcans` fields so Step 6 templates can reference them.
* `src/lib.rs` — the test-only `__test_only_g1_to_u256s` now takes
  `&midnight_curves::G1Affine`. Removed the `#![deny(missing_docs)]`
  attribute since the full migration leaves several internal items
  un-doc'd until Step 8.
* `src/evm.rs` — `encode_calldata` now uses `ff::PrimeField` directly.

### Step 4 (2026-04-26)

* `src/codegen/evaluator.rs::Evaluator::permutation_computations()` — emits the
  midnight-proofs permutation argument: l_0 boundary, l_last boundary, set-to-set
  continuity, and per-set `(z_next * Π(eval + β·s + γ)) - (z_cur * Π(eval + δ_pow + γ))`.
* `src/codegen/evaluator.rs::Evaluator::lookup_computations()` — full LogUp emitter:
  `(l_0 + l_last) * Z` boundary, per-chunk
  `h*Π(f + β) - Σ_j Π_{i≠j}(f_i + β)` helpers (computed via prefix·suffix), and the
  accumulator `(z_next - z - sel·Σh)(t + β) + m` constraint.
* `src/codegen/evaluator.rs::Evaluator::trashcan_computations()` — emits
  `compressed - (1 - q)*trash` where `compressed` folds the trashcan's
  constraint expressions with `trash_challenge`.
* `src/codegen/util.rs::ConstraintSystemMeta` — gains `permutation_chunk_len`
  and `simple_selector_cols: BTreeSet<usize>` (used by the permutation emitter
  and the fixed-eval lookup).

### Step 5 (2026-04-26)

* `src/codegen/pcs.rs` — module-level rewrite. Single `BatchOpenScheme::Gwc19`
  variant kept for migration continuity; semantics now refer to the
  midnight-proofs `KZGCommitmentScheme::multi_prepare` flow.
* `src/codegen/pcs/gwc19.rs::queries()` — builds the verifier query list
  mirroring `verify_algebraic_constraints`: advice queries, permutation product
  cur/next/last, lookup m/h/z/z_next, trashcan, fixed (non-simple), perm common,
  linearization (= computed quotient).
* `src/codegen/pcs/gwc19.rs::construct_intermediate_sets_impl()` — codegen-time
  port of the Rust algorithm. Buckets queries by `(commitment_id, point_set)`
  and assigns `set_index`. `sort_sets()` then orders sets by ascending
  cardinality (tiebreaker: original index).
* `src/codegen/pcs/gwc19.rs::computations()` — emits Yul for the multi-prepare
  body in six blocks:
    1. Pre-compute `x * ω^rot` for every distinct rotation
    2. Pre-compute `x1` powers
    3. Per-set: `q_com[s] = Σ x1^i · c_i` and `q_eval_set[s] = Σ x1^i · evals_i`
    4. `f_eval` via Horner over reverse(point_sets) + Lagrange interpolation
    5. `final_com = msm_inner_product(q_coms ++ [f_com], powers(x4))`,
       `v = inner_product(q_evals ++ [f_eval], powers(x4))`
    6. `PAIRING_LHS = π`; `PAIRING_RHS = final_com - v·G + x3·π`
* `src/codegen/util.rs::ConstraintSystemMeta::num_point_sets` + setter — populated
  by `SolidityGenerator::generate_verifier` after building `Data` so that
  `proof_len()` and `batch_open_extra_evals()` report the correct calldata size.
* `src/codegen.rs::generate_verifier()` — clones `meta` locally, populates
  `num_point_sets` via the IntermediateSets simulation, and threads the
  populated meta through evaluator + PCS emission + template fields.

The emitted Yul references symbolic identifiers (`X1_MPTR`, `X2_MPTR`,
`X3_MPTR`, `X4_MPTR`, `F_COM_MPTR`, `PI_MPTR`, `Q_EVAL_CPTR`, `Q_COM_MPTR`,
`Q_EVAL_SET_MPTR`, `ROT_POINTS_MPTR`, `X1_POWERS_MPTR`, `F_EVAL_MPTR`,
`V_MPTR`, `FINAL_COM_MPTR`, `scalar_inv`) that Step 6 will define in the
template.

Two tests pin the IntermediateSets builder (`intermediate_sets_*`); transcript
tests still pass.

### Step 6 (2026-04-26)

* `templates/Halo2Verifier.sol` — full Yul rewrite. The verifier now
  consumes the midnight-proofs proof byte stream end-to-end:
    1. `transcript_init()` seeds a streaming Keccak256 buffer at memory
       `[0x00..buf_len)` with the 31-byte `"Domain separator for transcript"`.
    2. `common_word(buf_len, w)` and `common_compressed_g1(buf_len, cptr)`
       append `[PREFIX_COMMON=0x01, ...payload]` to the buffer.
    3. `squeeze_to(buf_len, mptr)` implements the two-fork squeeze:
       append `[PREFIX_CHALLENGE=0x02]`, then keccak with
       `[..., 0x00]` and `[..., 0x01]` separately to produce a 64-byte
       output, reseed the buffer, and sample an Fq via
       `from_uniform_bytes(64)` = `a0 + a1 * 2^256 (mod r)` with the
       Montgomery constant `2^256 mod r` baked in (`FR_R_2POW256_MOD`).
    4. `decompress_g1(success, src, dst)` parses the zcash 48-byte
       compressed encoding (top 3 flag bits + 381-bit x), runs
       `modexp(x, 3, p)` then `modexp(y_sq, (p+1)/4, p)` to recover y,
       and selects the correct sign by comparing `y` vs `p-y` limb-wise.
       Identity points (infinity flag set) are written as four zero words.
    5. `scalar_inv(x)` computes `x^(r-2) mod r` via modexp.
    6. `byte_reverse_32(x)` swaps the byte order of a 32-byte word
       (used to convert calldata BE u256s to LE bytes for transcript
       hashing, since midnight-proofs hashes `Fq::to_repr()` LE bytes).
* New MPTR layout in `templates/Halo2Verifier.sol`:
    * `THETA, BETA, GAMMA, TRASH_CHALLENGE, Y, X` at `theta_mptr+0..+5`
    * `X1, X2, X3, X4` at `theta_mptr+6..+9`
    * `F_COM` (4 words) at `theta_mptr+10`, `PI` (4 words) at `+14`
    * Lagrange / quotient / instance scratch shifted accordingly
    * `F_EVAL`, `V`, `FINAL_COM` (4 words) added for the PCS pairing
      reconstruction
    * `ROT_POINTS`, `X1_POWERS`, `Q_COM`, `Q_EVAL_SET`, `Q_EVAL_CPTR_MPTR`
      reserved for the Step 5 emitter
* New proof-read schedule in the Yul body (mirrors
  `midnight_proofs::plonk::verifier::parse_trace` +
  `verify_algebraic_constraints`):
    * domain sep -> common(VK_DIGEST) -> common(num_instances) ->
      common(each instance, byte-reversed) ->
    * for each user phase: read `num_advices` compressed G1 +
      squeeze `num_challenges` Fq (cumulative offset tracked via
      `UserPhase::challenge_offset`) ->
    * theta -> read multiplicities -> beta, gamma -> read perm Z ->
      read lookup helpers + accumulators -> trash_challenge ->
      read trashcans -> y -> read quotient limbs -> x ->
      read evals -> x1, x2 -> read f_com (decompressed at F_COM_MPTR) ->
      x3 -> read q_evals (Q_EVAL_CPTR saved for the PCS emitter) ->
      x4 -> read pi (decompressed at PI_MPTR)
* The existing Lagrange / quotient / final-pairing blocks are
  preserved unchanged (pure Fr arithmetic).
* `src/codegen/template.rs` — adds `UserPhase { num_advices,
  num_challenges, challenge_offset }` plus six new fields on
  `Halo2Verifier` (`user_phases`, `num_user_challenges`,
  `num_lookups`, `num_permutation_zs`, `lookup_h_plus_acc`,
  `num_trashcans`, `num_quotients`, `num_evals`, `num_point_sets`)
  consumed by the new template.
* `src/codegen.rs::generate_verifier()` — populates the new fields
  and threads the local `meta` clone (with `num_point_sets` baked in)
  through the evaluator, PCS emitter, and template.
* `src/codegen.rs::static_working_memory_size()` — replaces the old
  per-phase Keccak input estimate with a streaming-buffer estimate
  based on total absorbed G1 + scalar bytes; the result is only a
  lower bound on `vk_mptr`, the actual transcript scratch lives at
  `[0x00..0x2200)` and the modexp scratch at `[0x2200..0x2400)`.

The rendered Yul produces the entire end-to-end verifier flow but is
**not yet exercised** against a real proof — that requires the
Step 8 example driver. Existing unit tests (`cargo test --lib`)
continue to pass: 3 transcript tests + 2 IntermediateSets tests.

## Pending work (Steps 7-9)

| Step | Files | Notes |
|------|-------|-------|
| 7 | `templates/Halo2VerifyingKey.sol` | regenerate the constants block + per-lookup tables + num_simple_selectors prelude so the embedded-VK and separate-VK paths match the Step 6 layout. |
| 8 | `examples/`, drivers | `verify_poseidon` example consuming the fixture; verify the rendered Yul compiles under solc and the precompile addresses (0x05/0x0b/0x0c/0x0f) execute on Prague-spec revm. |
| 9 | `tests/` | PBTs + soundness flips. Mirror the existing approach in `midfall/proofs/solidity-verifier/tests/`. |

## How to validate the current state

```sh
$ cargo check --lib
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.08s

$ cargo test --lib
running 3 tests
test transcript::tests::empty_squeeze_matches_midnight_proofs ... ok
test transcript::tests::common_scalar_then_squeeze_matches ... ok
test transcript::tests::common_g1_then_squeeze_matches ... ok
test result: ok. 3 passed; 0 failed; ...
```

`examples/`, `src/test.rs`, and the rendered Yul are *not yet* fully
exercised end-to-end and will fail to verify until Steps 7-9 are
completed (in particular, Step 7 finalises the Halo2VerifyingKey
template and Step 8 wires up an example driver that compiles the
rendered Yul under solc and executes it against the poseidon
fixture).
