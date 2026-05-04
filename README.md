# Halo2 Solidity Verifier

> ⚠️ This repo has NOT been audited and is NOT intended for a production environment yet.

Solidity verifier generator for `midnight-proofs` / Midfall verifier proofs with
the KZG polynomial commitment scheme on BLS12-381. Generated verifiers use
Solidity `^0.8.24` source pragmas, and reproducible test/bench bytecode is
compiled with pinned `solc 0.8.30+commit.73712a01`.

For audited solidity verifier generator and proof aggregation toolkits, please refer to [`snark-verifier`](http://github.com/axiom-crypto/snark-verifier).

## Usage

### Generate verifier and verifying key separately as 2 Solidity contracts

```rust
let generator = SolidityGenerator::new(&params, &vk, num_instances, 1);
let (verifier_solidity, vk_solidity) = generator.render_separately().unwrap();
```

### Generate verifier and verifying key in a single solidity contract

```rust
let generator = SolidityGenerator::new(&params, &vk, num_instances, 1);
let verifier_solidity = generator.render().unwrap();
```

### Encode proof into calldata to invoke `verifyProof`

```rust
let calldata = encode_calldata(&proof, &instances);
```

Note that function selector is already included.

## Test

### Current status

As of this revision, `cargo test --workspace --all-features --all-targets -- --list`
reports 106 library tests and 4 integration tests.

The implemented suite is narrower than the full assurance roadmap in
[`TESTING_STRATEGY.md`](./TESTING_STRATEGY.md). Today it covers transcript
compatibility, protocol planning, memory layout, VK payload encoding, proof
layout/canonicality checks, Solidity render invariants, Prague EIP-2537 smoke
coverage, Poseidon verifier property/adversarial tests, a Poseidon end-to-end
fixture, the Keccak IVC Poseidon-chain Solidity bench, and two ignored diagnostic
decompression probes.

| Area | Current status | Default behavior |
| ---- | -------------- | ---------------- |
| Library/codegen tests under `src/` | Implemented and part of the normal Cargo suite. | Run by `cargo test`. |
| Solidity/EVM tests in `src/test.rs` | Implemented behind the `evm` feature. Heavy Poseidon cases self-skip unless `HALO2_SOLIDITY_RUN_EVM_TESTS=1`, `solc`, and SRS assets are available. | Listed by Cargo; skipped cleanly without the gate. |
| `tests/poseidon_fixture.rs` | Implemented end-to-end Poseidon proof -> Solidity render -> `solc` -> Prague `revm` verification. | Self-skips unless `HALO2_SOLIDITY_RUN_EVM_TESTS=1`. |
| `tests/ivc_keccak_solidity.rs` | Implemented slow Keccak IVC final-proof Solidity bench over Poseidon hash-chain leaves. | Self-skips unless `HALO2_SOLIDITY_RUN_IVC_BENCH=1`. |
| `tests/fcom_decompress.rs` | Implemented diagnostic probes only. | Marked `#[ignore]`. |

### Requirements

The workspace is pinned to the toolchain in
[`rust-toolchain.toml`](./rust-toolchain.toml). Midfall dependencies are pinned
to immutable revision `53dc872f495104046d96bdac0a690f903dc0c537`, without
repository-local `.cargo/config.toml` path overrides. Solidity-touching tests
require `solc 0.8.30+commit.73712a01` on `PATH` or via the `SOLC` environment
variable.

The heavy proof/EVM tests also need Filecoin/Midnight SRS assets. Set
`SRS_DIR` when they are not available at the default adjacent Midfall checkout
path:

```bash
SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets
```

### Common commands

List the currently implemented tests without running them:

```bash
cargo test --workspace --all-features --all-targets -- --list
```

Run the normal workspace suite. Without opt-in environment gates, heavy EVM and
IVC tests are still compiled/listed but skip at runtime:

```bash
cargo test --workspace --all-features --all-targets -- --nocapture
```

> [!NOTE]
> CI and reproducible benches compile Solidity with
> `solc 0.8.30+commit.73712a01`.

The pinned Midfall revision, solc version, canonical IVC bench command, and
published verifier/VK/quotient runtime hashes are recorded in
[`docs/REPRODUCIBLE_BUILDS.md`](./docs/REPRODUCIBLE_BUILDS.md).
The map between the Askama templates, generated Solidity/Yul, Midfall Rust
verifier, and optimization choices is documented in
[`docs/ASKAMA_TEMPLATE_RUST_MAPPING.md`](./docs/ASKAMA_TEMPLATE_RUST_MAPPING.md).

Run one test by name:

```bash
cargo test --workspace --all-features codegen::memory::tests::overlapping_permanent_regions_fail -- --nocapture
```

The maintained example is `examples/ivc_replay.rs`; obsolete legacy diagnostic
examples have been removed so default example discovery stays green.

Run the `src/test.rs` Solidity/EVM verifier tests with the opt-in gate:

```bash
HALO2_SOLIDITY_RUN_EVM_TESTS=1 \
SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
cargo test --release --all-features --lib test:: -- --nocapture
```

Run a single Solidity/EVM test:

```bash
HALO2_SOLIDITY_RUN_EVM_TESTS=1 \
SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
cargo test --release --all-features pbt_solidity_rejects_malleated_proofs -- --nocapture
```

Run the Poseidon integration fixture:

```bash
HALO2_SOLIDITY_RUN_EVM_TESTS=1 \
SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
cargo test --release --features evm,truncated-challenges --test poseidon_fixture -- --nocapture
```

Run the ignored diagnostic decompression probes:

```bash
cargo test --test fcom_decompress -- --ignored --nocapture
```

### IVC detailed bench

Run the Keccak IVC Solidity verifier bench over Poseidon hash-chain leaves with per-section gas checkpoints:

```bash
SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
scripts/run_ivc_bench.sh
```

This prints the detailed checkpoint table, deployed runtime sizes, total
transaction gas, and real checkpointed section work. The default path uses the
outer single-H quotient commitment layout for the Solidity-facing decider
proof, so `SRS_DIR` must contain `midnight-srs-2p19`, `midnight-srs-2p20`,
and `midnight-srs-2p22`. If `--skip-srs-download` is passed and `2p22` is
missing, the script fails before compiling; run without `--skip-srs-download`
once, or fetch it with:

```bash
curl -fL --retry 3 --retry-delay 2 \
  -o .srs/midnight-srs-2p22 \
  https://srs.midnight.network/midnight-srs-2p22
```

Single-H is outer-only in this repo: the recursive leaf proofs verified inside
the decider circuit stay on Midfall's multi-limb quotient layout, while the
final Solidity-facing decider proof uses one quotient commitment. The bench
therefore performs a two-phase run: first it generates a multi-limb leaf bundle
without `outer-single-h-commitment`, then it proves and verifies the final
decider proof with `outer-single-h-commitment`.

The gas effect is intentionally modest. For the current IVC decider shape,
single-H removes three quotient commitment terms from the fused PCS final MSM:
`78 -> 75` terms. In the current profiled command this saves `17,912` gas in
PCS block 5 and `24,571` total transaction gas versus
`--no-outer-single-h-commitment`. The batched identity numerator
reconstruction is unchanged. The larger structural effect is proof layout size:
three fewer G1 commitments means `144` fewer compressed proof bytes and `384`
fewer EIP-2537-padded proof bytes.

To keep the recursive verifier on fewer point sets but benchmark the outer
decider proof without dummy PCS evals:

```bash
scripts/run_ivc_bench.sh --no-outer-fewer-point-sets
```

To run the legacy multi-limb outer proof shape:

```bash
scripts/run_ivc_bench.sh --no-outer-single-h-commitment
```

Native Rust/Solidity trace equivalence is enabled by the `--trace` bench path:
`scripts/run_ivc_bench.sh --trace`. Custom Midfall overrides must expose the
`midnight-proofs/solidity-verifier-trace` feature for that leg.
For the external IVC quotient evaluator, this compares the proof scalar reads
including `q_evals` and the reconstructed quotient numerator, while internal
quotient identity trace ids `30_000..40_000` are only available in monolithic
trace tests because the split evaluator runs under `STATICCALL`.

Compile-check the IVC bench without running the full proof:

```bash
scripts/run_ivc_bench.sh --check-only
```

Run every implemented test, including ignored diagnostics and opt-in EVM/IVC
paths:

```bash
HALO2_SOLIDITY_RUN_EVM_TESTS=1 \
HALO2_SOLIDITY_RUN_IVC_BENCH=1 \
SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
cargo test --release --workspace --all-features --all-targets -- --include-ignored --nocapture
```

### Implemented test inventory

This inventory is the output shape of
`cargo test --workspace --all-features --all-targets -- --list`.

#### Library and codegen tests

- `codegen::artifact::tests::packed_program_codec_rejects_length_past_capacity`
- `codegen::artifact::tests::packed_program_codec_rejects_non_zero_padding`
- `codegen::artifact::tests::packed_program_codec_round_trips_with_explicit_byte_len`
- `codegen::artifact::tests::vk_payload_layout_rejects_duplicate_sections`
- `codegen::artifact::tests::vk_payload_layout_reserves_monotonic_sections`
- `codegen::generator::tests::instance_column_shape_validation_is_exact`
- `codegen::memory::tests::accumulator_msm_region_is_sized_from_shape`
- `codegen::memory::tests::arena_alloc_after_aligns_after_anchor`
- `codegen::memory::tests::batch_invert_scratch_region_tracks_instance_shape`
- `codegen::memory::tests::overlapping_permanent_regions_fail`
- `codegen::memory::tests::pcs_fixed_window_overflows_fail_with_clear_messages`
- `codegen::memory::tests::same_bytes_are_allowed_for_disjoint_phases`
- `codegen::memory::tests::scratch_allocator_reuses_base_across_phases_and_advances_within_phase`
- `codegen::memory::tests::synthetic_layout_preserves_current_offsets`
- `codegen::memory::tests::trace_log_word_is_registered_after_scratch_regions`
- `codegen::memory::tests::unaligned_regions_fail`
- `codegen::pcs::tests::augmented_queries_collapse_to_single_set`
- `codegen::pcs::tests::compute_dummy_queries_emits_no_dummies_for_aligned_pairs`
- `codegen::pcs::tests::compute_dummy_queries_emits_no_dummies_when_all_singletons`
- `codegen::pcs::tests::compute_dummy_queries_matches_midnight_singleton_padding`
- `codegen::pcs::tests::compute_dummy_queries_unifies_two_distinct_pairs`
- `codegen::pcs::tests::intermediate_sets_dedups_commitments`
- `codegen::pcs::tests::intermediate_sets_partitions_by_rotation_set`
- `codegen::protocol::tests::expression_visitor_collects_queries`
- `codegen::protocol::tests::plan_preserves_eval_and_pcs_order_for_basic_cs`
- `codegen::protocol::tests::plan_skips_non_committed_instance_eval_reads`
- `codegen::protocol::tests::plan_tracks_permutation_chunking`
- `codegen::protocol::tests::protocol_plan_invariants_hold_for_small_constraint_systems`
- `codegen::protocol::tests::validation_rejects_absorbed_unopened_advice_commitments`
- `codegen::protocol::tests::validation_rejects_simple_selector_eval_reads`
- `codegen::template::tests::verifier_layout_validation_checks_calldata_and_memory_cursors`
- `codegen::template::tests::verifier_layout_validation_rejects_cursor_drift`
- `codegen::template::tests::verifier_layout_validation_rejects_pcs_scratch_overflow`
- `codegen::template::tests::verifier_layout_validation_rejects_vk_challenge_overlap`
- `codegen::template::tests::verifying_key_payload_layout_matches_rendered_byte_order`
- `codegen::template::tests::verifying_key_payload_layout_rejects_stale_quotient_offsets`
- `codegen::template::tests::vk_layout_byte_consistency`
- `codegen::template::tests::vk_renders_and_returns_correct_length`
- `codegen::tests::accumulator_limb_packing_is_checked_before_decoding`
- `codegen::tests::accumulator_schema_is_checked_against_instance_count`
- `codegen::tests::accumulator_vk_header_is_checked_against_codegen_metadata`
- `codegen::tests::batch_invert_handles_empty_and_singleton_ranges`
- `codegen::tests::compact_quotient_default_matches_gas_capped_setting`
- `codegen::tests::differential_trace_hooks_cover_expected_categories`
- `codegen::tests::eip2537_calls_use_bounded_gas_helpers`
- `codegen::tests::expression_lowering_matches_quotient_vm_eval`
- `codegen::tests::external_quotient_frame_covers_vk_and_eval_memory`
- `codegen::tests::external_quotient_template_has_no_unpinned_fallback`
- `codegen::tests::failed_success_paths_do_not_enter_ec_precompiles`
- `codegen::tests::field_negations_used_by_traces_are_canonical`
- `codegen::tests::final_msm_pair_count_is_a_codegen_assertion`
- `codegen::tests::gas_checkpoints_are_debug_only_template_paths`
- `codegen::tests::generated_comments_describe_padded_g1_calldata`
- `codegen::tests::generated_heavy_assemblies_keep_memory_safe_for_via_ir`
- `codegen::tests::generated_solidity_pragmas_require_mcopy_capable_compiler`
- `codegen::tests::generator_restriction_errors_are_typed`
- `codegen::tests::limb7_linear_chain_is_recognized_as_native_helper_call`
- `codegen::tests::native_arithmetic_linear_next_run_stays_structured`
- `codegen::tests::permutation_delta_literal_is_computed_from_field_constant`
- `codegen::tests::point_validation_boundary_is_documented_and_plan_checked`
- `codegen::tests::production_verifier_documents_revert_or_true_policy`
- `codegen::tests::production_verifier_entrypoint_is_external_view`
- `codegen::tests::quotient_forward_y_batch_matches_rust_reverse_fold`
- `codegen::tests::quotient_selector_inverse_fold_matches_final_scale`
- `codegen::tests::quotient_vm_bilin7_pairwise_matches_direct_expr_eval`
- `codegen::tests::quotient_vm_bilin7_row_matches_direct_expr_eval`
- `codegen::tests::quotient_vm_lin7_matches_direct_expr_eval`
- `codegen::tests::scalar_le_to_be_word_reverses_exactly_one_word`
- `codegen::tests::templates_use_planned_memory_slots_for_theta_and_commitment_layout`
- `codegen::tests::trace_u256_uses_planned_memory_slot`
- `codegen::tests::transcript_memory_bound_handles_wide_bls_advice_phase`
- `codegen::tests::trash_challenge_is_squeezed_even_without_trash_arguments`
- `codegen::tests::truncated_challenge_comments_cover_x1_x4_power_masks`
- `codegen::tests::unmatched_limb_shape_falls_back_to_existing_vm_ops`
- `codegen::tests::verifier_checks_canonical_dynamic_abi_heads`
- `codegen::tests::verifier_constructor_smoke_tests_eip2537_precompiles`
- `codegen::tests::verifier_template_omits_dead_constants_and_ec_helpers`
- `codegen::tests::verify_proof_natspec_requires_application_binding`
- `codegen::util::tests::eip2537_encoders_accept_identity_points`
- `transcript::tests::common_g1_then_squeeze_matches`
- `transcript::tests::common_scalar_then_squeeze_matches`
- `transcript::tests::empty_squeeze_matches_midnight_proofs`
- `transcript::tests::read_g1_matches_write_g1_transcript_state`

#### Solidity/EVM verifier tests

- `test::compile_solidity_is_deterministic_for_same_source`
- `test::every_proof_g1_rejects_noncanonical_coordinates`
- `test::every_proof_g1_rejects_off_curve_coordinates`
- `test::every_proof_scalar_rejects_fr_modulus`
- `test::function_signature`
- `test::malformed_embedded_calldata_variants_are_rejected`
- `test::mutated_separate_vk_contract_is_rejected`
- `test::native_midfall_verifier_trace_matches_solidity_trace`
- `test::pbt_separate_vk_digest_prefix_affects_verification`
- `test::pbt_solidity_rejects_malleated_proofs`
- `test::pbt_solidity_rejects_wrong_instances`
- `test::pbt_solidity_rejects_wrong_verifying_keys`
- `test::pbt_solidity_verifies_standard_plonk_embedded_vk_proofs`
- `test::pinned_quotient_verifier_rejects_wrong_vk_and_quotient_contracts`
- `test::poseidon_verifier_variants_compile_with_pinned_solc`
- `test::prague_evm_runs_eip2537_identity_smoke_tests`
- `test::production_renders_do_not_emit_gas_checkpoints`
- `test::separate_verifier_adversarial_calldata_variants_are_rejected`
- `test::standard_plonk_render_is_deterministic_for_same_seed`
- `test::supported_shape_circuit_fuzz_e2e`
- `test::trace_verifiers_revert_on_final_pairing_failure`
- `test::verifier_constructor_rejects_missing_or_mismatched_eip2537_precompiles`
- `test::vk_payload_section_mutations_are_rejected`

#### Integration tests

- `tests/fcom_decompress.rs`: `fcom_decompress` (`#[ignore]`)
- `tests/fcom_decompress.rs`: `quotient_limb_decompress` (`#[ignore]`)
- `tests/ivc_keccak_solidity.rs`: `ivc_final_keccak_solidity_e2e`
- `tests/poseidon_fixture.rs`: `poseidon_renders_compiles_and_verifies`

## Limitations & Caveats

- It currently supports the Midfall verifier shape used by this repo: exactly
  one committed identity instance column and one non-committed public-input
  column, no rotated instance queries, and KZG on BLS12-381.
- Verifying-key generation must be reproducible for the circuit shape being
  rendered. If selector assignments can differ between proving and verifier
  generation, disable selector compression or use the Midfall keygen path that
  preserves the same selector layout.

## Compatibility

The [`Keccak256Transcript`](./src/transcript.rs#L19) follows the Midfall
Keccak transcript shape used by the generated Solidity verifier.

## Design Rationale

The current solidity verifier generator within `snark-verifier` faces a couple of issues:

- The generator receives only unoptimized, low-level operations, such as add or mul. As a result, it currently unrolls all assembly codes, making it susceptible to exceeding the contract size limit, even with a moderately sized circuit.
- The existing solution involves complex abstractions and APIs for consumers.

This repository is a ground-up rebuild, addressing these concerns while maintaining a focus on code size and readability. Remarkably, the gas cost is comparable, if not slightly lower, than the one generated by `snark-verifier`.

See [`docs/PR17_BORROWED_IDEAS.md`](./docs/PR17_BORROWED_IDEAS.md) for the
small artifact-layout and packed-program ideas borrowed from
`privacy-ethereum/halo2-solidity-verifier` PR #17, and why this repo keeps a
static pinned verifier instead of adopting a fully reusable runtime artifact.

See [`docs/MEMORY_LAYOUT.md`](./docs/MEMORY_LAYOUT.md) for the generated
verifier memory planner, including the fixed theta-relative offsets,
precompile-frame constants, scratch lifetimes, and update rules.

See [`docs/HALO2_MIDNIGHT_VERIFIER_SPEC.md`](./docs/HALO2_MIDNIGHT_VERIFIER_SPEC.md)
for a consolidated specification and architecture guide covering the ABI,
proof layout, transcript, quotient reconstruction, KZG PCS check, VK payload,
and split verifier contracts.

## Acknowledgement

The template is heavily inspired by Aztec's [`BaseUltraVerifier.sol`](https://github.com/AztecProtocol/barretenberg/blob/4c456a2b196282160fd69bead6a1cea85289af37/sol/src/ultra/BaseUltraVerifier.sol).
