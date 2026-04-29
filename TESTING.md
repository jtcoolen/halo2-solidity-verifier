# Testing

This document collects the commands needed to exercise the examples and the
property-based test (PBT) suite shipped with this crate.

The workspace is pinned to the toolchain in [`rust-toolchain.toml`](./rust-toolchain.toml)
(currently Rust 1.90.0). Solidity-touching tests and examples additionally
require `solc` on `PATH`; any 0.8.x release works.

Midnight crates resolve from the published midfall GitHub branch configured in
`Cargo.toml`:

```text
https://github.com/EYBlockchain/midfall.git#keccak
```

The ignored proving benches need local SRS files. `scripts/run_ivc_bench.sh`
downloads the IVC bench assets into `.srs/` by default, or you can point
`SRS_DIR` at an existing Filecoin/Midnight SRS directory.

```bash
rustc --version    # should report 1.90.0
solc --version     # should report 0.8.x
```

---

## Examples

All three examples live under `examples/` and require the `evm` feature so that
the embedded `revm` runner is available. Run them in `--release` to avoid a
debug-only `revm` interpreter panic on newer Rust toolchains.

### `separately` — render verifier and VK as two contracts

Builds verifier + VK contracts for a `StandardPlonk` circuit across `k = 10..17`,
deploys both via `revm`, and prints gas costs.

```bash
cargo run --release --all-features --example separately
```

Outputs:

- `generated/Halo2Verifier.sol`
- `generated/Halo2VerifyingKey-{10..16}.sol`

### `trace` — render trace-enabled verifier and dump intermediate state

Builds the trace-mode verifier (which emits `LOG1` events for challenges,
evaluations and pairing inputs), runs it once, and pretty-prints the captured
trace entries.

```bash
cargo run --release --all-features --example trace
```

### `compare_trace` — cross-check Solidity vs Rust verifier state

Runs the trace-mode verifier and the in-tree Rust reference verifier on the
same `(params, vk, proof, instances)`, then asserts every comparable trace
entry (`vk_digest`, `theta`, `beta`, `gamma`, `y`, `x`, `zeta`, `nu`, `mu`,
`x_n`, `l_last`, `l_blind`, `l_0`, `instance_eval`, ...) matches.

```bash
cargo run --release --all-features --example compare_trace
```

---

## Tests

### Default suite (render + EVM smoke tests)

These compile and run the verifier end-to-end on `HugeCircuit` and
`MainGateWithRange` for both `Bdfg21` and `Gwc19`. They are not `#[ignore]`d
and run as part of the default test invocation:

```bash
cargo test --workspace --all-features --all-targets -- --nocapture
```

Covers:

- `render_bdfg21_huge`, `render_bdfg21_maingate`
- `render_gwc19_huge`, `render_gwc19_maingate`
- `render_separately_bdfg21_huge`, `render_separately_bdfg21_maingate`
- `render_separately_gwc19_huge`, `render_separately_gwc19_maingate`

### Property-based tests (PBT)

The PBT cases are marked `#[ignore]` because they are EVM-heavy and only make
sense in `--release`. Run the whole PBT batch with:

```bash
cargo test --release --all-features pbt_ -- --ignored --nocapture
```

Individual cases:

```bash
# Positive case: real proofs are accepted by the embedded verifier.
cargo test --release --all-features \
    pbt_solidity_verifies_standard_plonk_embedded_vk_proofs \
    -- --ignored --nocapture

# Negative: corrupted public inputs must be rejected (embedded + separate).
cargo test --release --all-features \
    pbt_solidity_rejects_wrong_instances \
    -- --ignored --nocapture

# Negative: any single-bit flip in the proof bytes must be rejected.
cargo test --release --all-features \
    pbt_solidity_rejects_malleated_proofs \
    -- --ignored --nocapture

# Negative: a separate verifier must reject a VK contract it was not pinned to.
cargo test --release --all-features \
    pbt_solidity_rejects_wrong_verifying_keys \
    -- --ignored --nocapture

# Negative: even a one-nibble change inside vk_digest must break verification.
cargo test --release --all-features \
    pbt_separate_vk_digest_prefix_affects_verification \
    -- --ignored --nocapture
```

### Other Solidity/EVM-heavy tests

These are also `#[ignore]`d but are not property tests. Run them all with:

```bash
cargo test --release --all-features \
    -- --ignored --nocapture \
    malformed_embedded_calldata_variants_are_rejected \
    mutated_separate_vk_contract_is_rejected \
    standard_plonk_render_is_deterministic_for_same_seed \
    compile_solidity_is_deterministic_for_same_source
```

What each one covers:

- `malformed_embedded_calldata_variants_are_rejected` — empty proof, truncated
  proof, extra trailing bytes, wrong selector, wrong instance-array length.
- `mutated_separate_vk_contract_is_rejected` — flips a single nibble in the
  first 64-byte hex literal of the VK source and asserts rejection.
- `standard_plonk_render_is_deterministic_for_same_seed` — same `(k, seed)`
  must produce identical Solidity sources for both embedded and separate.
- `compile_solidity_is_deterministic_for_same_source` — same Solidity source
  must compile to identical bytecode (smoke test for `solc` reproducibility).

### IVC Keccak Solidity bench

This slow ignored test proves three inner SHA-256 statements, emits the final
IVC proof under a Keccak transcript, renders the Solidity verifier/VK, deploys
them in Prague-spec `revm`, verifies on-chain, reports contract sizes, and
prints section-level gas checkpoints.

Compile-only check:

```bash
scripts/run_ivc_bench.sh --check-only
```

Full bench:

```bash
scripts/run_ivc_bench.sh
```

Use an existing SRS directory and also run the native Midfall final-proof twin:

```bash
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
  scripts/run_ivc_bench.sh --native-midfall
```

Generated contracts, calldata, proof bytes, and size reports are written to:

```text
target/ivc-keccak-solidity-dump/
```

### Run absolutely everything

```bash
cargo test --release --workspace --all-features --all-targets \
    -- --include-ignored --nocapture
```

Be aware: this can take several minutes because the PBT cases run multiple
proof-generation + EVM rounds per case.
