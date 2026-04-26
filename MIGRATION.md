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

## What landed in Steps 1-3

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

## Pending work (Steps 4-9)

| Step | Files | Notes |
|------|-------|-------|
| 4 | `src/codegen/evaluator.rs` | port permutation/logup/trash expression emitters from `midfall/proofs/src/plonk/{permutation,logup,trash}.rs::expressions`. Each emitter must respect the squeeze ordering of `theta`, `beta`, `gamma`, `trash_challenge`. |
| 5 | `src/codegen/pcs.rs`, `pcs/gwc19.rs` | replace the rotation-set emitter with `multi_prepare` (x1/x2/f_com/x3/q_evals/x4/pi). `q_evals` count = number of point sets returned by `construct_intermediate_sets`. |
| 6 | `templates/Halo2Verifier.sol` | rewrite the Yul body. Compressed-G1 -> EVM decompression helper has to match `<G1Projective as GroupEncoding>::from_bytes` (sign bit at top of x; subgroup check). |
| 7 | `templates/Halo2VerifyingKey.sol` | new constants block; per-lookup tables; num_simple_selectors prelude. |
| 8 | `examples/`, drivers | add `verify_poseidon` example consuming the fixture. |
| 9 | `tests/` | PBTs + soundness flips. Mirror existing tests under `midfall/proofs/solidity-verifier/tests/`. |

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

`examples/`, `src/test.rs`, and the rendered Yul are *not yet* fixed
and will fail to build until Steps 4-9 are completed. The `evm`
feature is buildable but the rendered Solidity will be incomplete (no
permutation / lookup / trashcan / PCS Yul code is emitted).
