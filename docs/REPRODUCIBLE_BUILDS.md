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

## Canonical IVC Bench Command

The current default IVC Solidity bench uses the outer single-H decider proof
layout:

```bash
scripts/run_ivc_bench.sh --skip-srs-download
```

That command assumes `.srs/` already contains:

- `midnight-srs-2p19` for the leaf IVC proofs;
- `midnight-srs-2p20` for the decider base SRS;
- `midnight-srs-2p22` for the outer single-H decider's extended monomial SRS.

Without `--skip-srs-download`, the script downloads missing Midnight SRS assets
it needs. With `--skip-srs-download`, it fails before compiling if any required
asset is missing.

The default run has two Cargo phases:

1. compile and run the multi-limb leaf-bundle generator without
   `outer-single-h-commitment`;
2. compile and run the final Solidity decider bench with
   `outer-single-h-commitment`.

The final decider invocation uses:

- features:
  `evm,truncated-challenges,in-circuit-fewer-point-sets,outer-single-h-commitment,solidity-gas-checkpoints`
- `SRS_DIR=./.srs` via the bench script default
- `solc optimize runs: 1`
- CBOR metadata omitted

Use the legacy multi-limb outer proof shape with:

```bash
scripts/run_ivc_bench.sh --skip-srs-download --no-outer-single-h-commitment
```

## Recorded Default Outer Single-H Runtime Hashes

The concrete hashes below were generated with:

```bash
HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=4 \
HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=trash \
HALO2_SOLIDITY_QUOTIENT_NATIVE_LOOKUP=1 \
scripts/run_ivc_bench.sh \
  --no-outer-fewer-point-sets \
  --skip-srs-download
```

That command uses:

- features:
  `evm,truncated-challenges,in-circuit-fewer-point-sets,outer-single-h-commitment,solidity-gas-checkpoints`
- `SRS_DIR=./.srs` via the bench script default
- `solc optimize runs: 1`
- CBOR metadata omitted

Published deployed-runtime hashes:

| Artifact | Runtime bytes | Runtime `keccak256` |
| --- | ---: | --- |
| `Halo2Verifier` | 11,962 | `0x8772fd9c1c75fbc2bbf6699778e3a19004b05c386536d1026b157a1b254802a5` |
| `Halo2VerifyingKey` | 14,016 | `0xd081cc83b30d045cb208f3045bd3d8ed6eb3ba582f44bc8358128319fc535363` |
| `Halo2QuotientEvaluator` | 23,221 | `0x4f4ea4e626f795dece8a739204772e0a25f91a6ea8ff0524656d079a84167b6f` |

Total deployed runtime bytes: `49,199`.

The same run accepted the final IVC Keccak proof on-chain in `1,374,697` gas.
The proof repacked from `4,912` compressed bytes to `7,392` padded bytes, with
`7,972` bytes of calldata.

## Recorded Legacy Multi-Limb Runtime Hashes

The concrete hashes below are the latest recorded fallback profile in this
repository, not the default outer single-H profile. They were generated with:

```bash
HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=4 \
HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=trash \
HALO2_SOLIDITY_QUOTIENT_NATIVE_LOOKUP=1 \
scripts/run_ivc_bench.sh \
  --no-outer-fewer-point-sets \
  --skip-srs-download \
  --no-outer-single-h-commitment
```

That command uses:

- features:
  `evm,truncated-challenges,in-circuit-fewer-point-sets,solidity-gas-checkpoints`
- `SRS_DIR=./.srs` via the bench script default
- `solc optimize runs: 1`
- CBOR metadata omitted

Published deployed-runtime hashes:

| Artifact | Runtime bytes | Runtime `keccak256` |
| --- | ---: | --- |
| `Halo2Verifier` | 12,061 | `0xf0d2433a3142294afb4d9a9434d623b8f00bbea212380777b5aee197e79b1454` |
| `Halo2VerifyingKey` | 14,016 | `0x0f858e789c9d52f7e11beb96dd39fa30712c42f629c3505be9cceef3225119a0` |
| `Halo2QuotientEvaluator` | 23,221 | `0x1f8acc8aa363e10d031e9e56dd4180a70c714330fa466d3423f9ce1d4e1f00b2` |

Total deployed runtime bytes: `49,298`.

The same run accepted the final IVC Keccak proof on-chain in `1,399,268` gas.
The proof repacked from `5,056` compressed bytes to `7,776` padded bytes, with
`8,356` bytes of calldata.

Compared with this legacy profile, outer single-H removes three quotient G1
commitments: proof size drops by `144` compressed bytes and `384` padded bytes,
PCS block 5 drops from `533,202` to `515,290` gas, and total transaction gas
drops by `24,571`.
