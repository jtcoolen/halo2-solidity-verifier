# Testing

This document collects the commands needed to exercise the examples and the
property-based test (PBT) suite shipped with this crate.

The workspace is pinned to the toolchain in [`rust-toolchain.toml`](./rust-toolchain.toml)
(currently Rust 1.90.0). Solidity-touching tests and examples additionally
require `solc >=0.8.24` on `PATH`.

Midnight crates resolve from the published midfall GitHub branch configured in
`Cargo.toml`:

```text
https://github.com/EYBlockchain/midfall.git#keccak
```

To test against a local Midfall checkout, copy
[`.cargo/config.toml.example`](./.cargo/config.toml.example) to
`.cargo/config.toml` and update the paths. The real `.cargo/config.toml` is
ignored so machine-local overrides do not leak into commits.

The ignored proving benches need local SRS files. `scripts/run_ivc_bench.sh`
downloads the IVC bench assets into `.srs/` by default, or you can point
`SRS_DIR` at an existing Filecoin/Midnight SRS directory. The IVC Solidity
tree bench needs Midnight `midnight-srs-2p19` for the leaf IVC proofs and
`midnight-srs-2p20` for the final decider proof.

```bash
rustc --version    # should report 1.90.0
solc --version     # should report 0.8.24 or newer
```

---

## Examples

`Cargo.toml` sets `autoexamples = false`, so stale pre-Midnight diagnostic
programs under `examples/` are not built by default. The maintained registered
example is the IVC replay harness:

```bash
cargo run --release \
  --features evm,truncated-challenges,fewer-point-sets \
  --example ivc_replay
```

It loads contracts and calldata previously written by the ignored IVC bench at
`target/ivc-keccak-solidity-dump/`, recompiles them with `solc`, deploys them
in Prague-spec `revm`, and calls `verifyProof`.

---

## Tests

### Default suite (render + EVM smoke tests)

These compile and run the verifier end-to-end with the default multi-prepare
KZG PCS emitter. They are not `#[ignore]`d and run as part of the default test
invocation:

```bash
cargo test --workspace --all-features --all-targets -- --nocapture
```

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

This slow ignored test proves two independent one-step IVC SHA-256 aggregation
leaves, proves a final Keccak-transcript tree decider that verifies both leaf
proofs and fully collapses the carried IVC proof accumulator, renders the
Solidity verifier/VK for that decider proof, deploys them in Prague-spec
`revm`, verifies on-chain, reports contract sizes, and prints section-level gas
checkpoints.

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
SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
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
