# Codegen Correctness And Security Assurance Dossier

Assessed on 2026-05-11 for this repository's Midfall/Midnight Halo2 Solidity
verifier generator.

## 1. Claim And Protocol Envelope

The defensible claim is intentionally narrow:

```text
For the supported Midfall profile and pinned generated artifacts, the generated
Solidity verifier is a faithful lowering of the Rust verifier in
../midfall/proofs/src, and no known exploitable security issue remains after
the audit, trace, mutation, and reproducibility gates in this dossier pass.
```

This is not a claim that the generator is a generic Halo2 verifier. The
supported profile is:

- BLS12-381 KZG over `midnight_curves::Bls12` and scalar field `Fq`.
- Midfall Keccak transcript with committed instances enabled.
- One proof, one identity-committed instance column, and one direct public
  instance column.
- No rotated non-committed instance queries.
- Matching Rust/Solidity feature flags for truncated challenges, fewer point
  sets, and outer single-H quotient commitments.
- EIP-2537 BLS12-381 precompiles available with Prague-compatible semantics.
- VK bytecode and optional quotient evaluator bytecode pinned by runtime length
  and codehash.

The proof about any production deployment must be made over a fixed artifact
manifest:

| Input | Required record |
| --- | --- |
| Midfall revision | `53dc872f495104046d96bdac0a690f903dc0c537` |
| Rust toolchain | `rust-toolchain.toml` |
| Cargo features | Exact feature list used to generate the verifier |
| Solidity compiler | `solc 0.8.30+commit.73712a01` |
| Solc flags | `--bin --optimize --via-ir --evm-version cancun --no-cbor-metadata` |
| Generated sources | Hashes of verifier, VK, and optional quotient evaluator sources |
| Runtime bytecode | Runtime length and `keccak256` for each deployed artifact |
| VK binding | VK digest plus external VK runtime length/codehash when split |
| Quotient binding | Evaluator runtime length/codehash when split |
| Proof ABI | `verifyProof(bytes proof, uint256[] instances)` |
| SRS assumption | Midnight SRS asset names, sizes, and expected source |

Application-level statement binding is out of scope for raw `verifyProof`.
Wrappers must separately bind chain/domain, caller, state roots, action hashes,
nullifiers, replay windows, and any application-specific liveness rules.

## 2. Rust To Solidity Semantic Map

The generated verifier is justified by semantic checkpoints rather than by a
line-for-line translation.

| Checkpoint | Rust source of truth | Solidity/codegen owner | Evidence expected |
| --- | --- | --- | --- |
| Parser and proof reads | `plonk/verifier.rs::{parse_trace,verify_algebraic_constraints}` | `src/codegen/protocol.rs`, `src/codegen/proof_layout.rs`, `templates/Halo2Verifier.sol` | Exact proof length, ABI head checks, per-section offsets, canonical scalar and G1 checks |
| Transcript challenges | `transcript/mod.rs`, `transcript/implementors.rs` | `src/transcript.rs`, `templates/Halo2Verifier.sol` | Rust/Solidity trace equality for VK, instances, commitments, and all challenges |
| Quotient identities | `plonk/mod.rs::partially_evaluate_identities` | `src/codegen/evaluator.rs`, `src/codegen/quotient/mod.rs`, `templates/QuotientNumeratorBlock.yul` | Identity order manifest, quotient trace ids, VM validator, selector-fold trace coverage |
| Linearization | `plonk/linearization/verifier.rs::compute_linearization_commitment` | `src/codegen/generator.rs`, `src/codegen/pcs.rs` | Same `-nu_y(x)` scalar, selector buckets, quotient limb scalars, and commitment expansion |
| KZG multi-open | `poly/kzg/mod.rs::multi_prepare` | `src/codegen/pcs.rs` | Same dummy queries, point-set sort, `x1..x4`, `f_com`, `q_evals`, `pi`, final MSM |
| Final pairing | `poly/kzg/msm.rs::DualMSM::check` | `templates/Halo2Verifier.sol`, `src/codegen/pcs.rs` | Pairing precompile success, return size, and semantic result word checked |
| Optional accumulator | Wrapper logic outside `plonk/verifier.rs` | `AccumulatorEncoding`, VK header, `templates/Halo2Verifier.sol` | Public-input schema validation and batched accumulator/KZG pairing equation |

The bridge between Solidity calldata and Rust verifier objects is:

- Solidity scalar words are canonical `Fr` elements and are rejected when
  `>= Fr::MODULUS`.
- Solidity G1 commitments are EIP-2537 padded uncompressed points; the off-chain
  repacker derives them from native compressed Midfall proof bytes.
- Solidity public inputs are big-endian field words that correspond to the
  Rust `instances` slice after the committed/non-committed split.
- The Solidity verifier absorbs the same mathematical transcript objects as
  Rust, even where the physical proof encoding differs.

## 3. Security Argument And Threat Model

The no-false-accepts property is the primary security goal:

```text
If the generated Solidity verifier returns true, then the pinned Midfall Rust
verifier would accept the same mathematical proof for the same VK and public
inputs, under the same feature profile.
```

Required controls:

- Unsupported shapes fail in `SolidityGenerator::try_new` before rendering.
- VK and quotient dependencies are pinned by bytecode length and codehash.
- The proof parser rejects malformed ABI heads, wrong proof length, trailing
  bytes, non-canonical scalars, and non-canonical/off-curve G1 coordinates.
- The transcript absorbs VK digest, committed identity instance, public input
  length, public input scalars, and every prover message before the next
  challenge.
- The quotient VM safety pass rejects unknown opcodes, truncated operands,
  invalid memory tokens, stack underflow/leaks, unsupported packed32 forms, and
  logical operand-width corruption.
- The memory planner models permanent and phase-scoped ranges, including the
  external quotient return buffer, and rejects live overlap.
- Production render paths remain `external view` and do not emit trace or gas
  logs. Trace and gas-checkpoint paths are debug surfaces only.
- EIP-2537 wrappers check call success, exact return size, and semantic pairing
  output.
- Accumulator inputs are validated before batching; malformed identity,
  zero-scalar, and one-scalar paths still route points through EIP-2537
  validation.

Explicit exclusions:

- Generic committed-instance commitments other than the identity-commitment
  zk_stdlib profile.
- Generic multi-proof verification and arbitrary instance-column layouts.
- Application wrapper soundness, replay protection, and state-machine liveness.
- Chains or L2s without the expected EIP-2537 semantics.

## 4. Audit And Test Evidence

`AUDIT_FINDINGS.md` is the open-issues ledger. A release cannot claim this
dossier until every finding is either fixed with code/test evidence or explicitly
excluded from production scope.

Required gates:

```bash
cargo test --workspace --all-features --all-targets
```

```bash
HALO2_SOLIDITY_RUN_EVM_TESTS=1 \
cargo test --release --features evm,truncated-challenges,rust-verifier-trace -- --nocapture
```

```bash
HALO2_SOLIDITY_RUN_IVC_BENCH=1 \
cargo test --release --features evm,truncated-challenges,fewer-point-sets,rust-verifier-trace \
  --test ivc_keccak_solidity -- --nocapture
```

Negative evidence must include:

- Every proof scalar offset: `Fr`, `Fr + 1`, high-bit, and random
  non-canonical words reject.
- Every proof G1 offset: nonzero top padding, coordinate `p`, off-curve point,
  and malformed infinity policy reject.
- Every public input slot mutates to rejection unless it is intentionally unused
  by a documented wrapper.
- Every VK and quotient section mutation rejects by constructor pinning or
  proof failure.
- ABI variants with wrong selector, shifted dynamic heads, wrong array length,
  trailing bytes, and truncated proof reject.
- Precompile failure, short return data, false pairing return, and stale memory
  paths reject.
- Accumulator limb, coordinate, scalar, and point-pair mutations reject for
  accumulator-enabled profiles.

Release evidence should attach:

- Test command logs and feature lists.
- Rust/Solidity trace comparison summary.
- Generated artifact hashes and runtime sizes.
- Pinned solc identity and compile flags.
- Any intentionally excluded debug-only or wrapper-only risk.
