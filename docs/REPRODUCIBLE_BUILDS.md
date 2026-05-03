# Reproducible Builds

This repository pins the generated Solidity verifier build inputs that affect
bytecode:

- Rust toolchain: `rust-toolchain.toml`
- Midfall dependency revision:
  `53dc872f495104046d96bdac0a690f903dc0c537`
- Solidity compiler: `solc 0.8.30+commit.73712a01`
- Solidity compile flags: `--bin --optimize --via-ir --evm-version cancun --no-cbor-metadata`

Repository-local `.cargo/config.toml` path overrides are intentionally not used.
All Midfall crates are resolved from the pinned git revision in `Cargo.toml`.

## Canonical IVC Runtime Hashes

Generated with the production verifier path:

```bash
HALO2_SOLIDITY_RUN_IVC_BENCH=1 \
SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
cargo test --release \
  --features evm,truncated-challenges,in-circuit-fewer-point-sets,outer-fewer-point-sets \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --nocapture
```

The command uses:

- features:
  `evm,truncated-challenges,in-circuit-fewer-point-sets,outer-fewer-point-sets`
- `SRS_DIR` pointing at local Midfall SRS assets
- `solc optimize runs: 1`
- CBOR metadata omitted
- external pinned quotient evaluator
- no Solidity trace logs and no gas-checkpoint logs

Published deployed-runtime hashes:

| Artifact | Runtime bytes | Runtime `keccak256` |
| --- | ---: | --- |
| `Halo2Verifier` | 10,517 | `0x516104f5fdc12e7ad10fb5ccbf34734e5a20feffa7eef245835639284fc0cab1` |
| `Halo2VerifyingKey` | 15,104 | `0xb5162f13fd1b5dc0c3b37f7c07601b8c063ba8717eb7d4f5a4e555beb4fdbc13` |
| `Halo2QuotientEvaluator` | 18,329 | `0x5a2c2158ea4547c364a620851d5fdd70d7ee509c5dd3f0e1dc754df05820eeb9` |

Total deployed runtime bytes: `43,950`.

The latest release-mode run accepted the final IVC Keccak proof on-chain in
`1,804,024` gas. The runtime hashes above are the stable reproducibility
anchor; total transaction gas can drift slightly with proof/calldata bytes.

## Trace-Equivalence IVC Runtime Hashes

Native Rust/Solidity trace equivalence intentionally renders a trace verifier:

```bash
HALO2_SOLIDITY_RUN_IVC_BENCH=1 \
SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
cargo test --release \
  --features evm,rust-verifier-trace,truncated-challenges,in-circuit-fewer-point-sets,outer-fewer-point-sets \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --nocapture
```

That path matched `340` native Rust/Solidity trace points and accepted the
same proof in `2,833,846` gas. This is not the production gas number; it
includes the trace verifier's emitted logs and larger verifier runtime.
