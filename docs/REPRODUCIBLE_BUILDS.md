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

Generated with:

```bash
scripts/run_ivc_bench.sh --skip-srs-download
```

The command uses:

- features:
  `evm,truncated-challenges,in-circuit-fewer-point-sets,outer-fewer-point-sets,solidity-gas-checkpoints`
- `SRS_DIR=./.srs` via the bench script default
- `solc optimize runs: 1`
- CBOR metadata omitted

Published deployed-runtime hashes:

| Artifact | Runtime bytes | Runtime `keccak256` |
| --- | ---: | --- |
| `Halo2Verifier` | 13,885 | `0xbbc033200a10a22a30dd7c2ae55f382bd23e8ee53d0c4175153ced5115eb698a` |
| `Halo2VerifyingKey` | 15,136 | `0x3e935334ddb91f56e302e88a8331e5e639b936e6d2ab1a570cc11f353fb427ce` |
| `Halo2QuotientEvaluator` | 18,329 | `0x414011cf401e996940275baaba5b30fb4bb1fd92d4b440a2f5a17c6d0fc10c59` |

Total deployed runtime bytes: `47,350`.

The same run accepted the final IVC Keccak proof on-chain in `1,793,791` gas.
