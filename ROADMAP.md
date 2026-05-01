# Production Readiness Roadmap

This repository is not production-ready yet.

The current tests are useful and have caught real regressions, but this is
cryptographic verifier code. The production bar is higher than happy-path proof
acceptance plus random proof mutation. The verifier should not be used for
meaningful value while known High and Medium issues remain open in
[`AUDIT.md`](./AUDIT.md).

## Current Strengths

- End-to-end IVC proof acceptance through `scripts/run_ivc_bench.sh`.
- Section-level gas and size instrumentation.
- Property tests for wrong instances, proof mutation, wrong VKs, and malformed
  calldata.
- Deterministic rendering and compilation checks.
- Rust/Solidity trace-comparison tooling.
- Bench artifacts dumped for replay under `target/ivc-keccak-solidity-dump/`.

These are a strong base, but they are not enough for production cryptographic
assurance.

## Production Blockers

Fix known verifier-soundness and deployment issues before any production use:

1. Pin the quotient evaluator by generated codehash and runtime length.
2. Check `returndatasize()` after every precompile call.
3. Add precompile self-tests or deployment guards for EIP-2537 behavior.
4. Fix the Rust `read_g1` transcript asymmetry.
5. Reject malformed and non-canonical G1 inputs consistently.
6. Reject zero inversion denominators.
7. Add an end-of-proof cursor check after parsing `pi`.

Every fix above needs a regression test that fails on the old behavior.

## Required Test Expansion

### Differential Testing

For every generated verifier variant, compare Solidity behavior against the
Rust verifier:

- transcript challenges,
- quotient numerator values,
- selector accumulators,
- PCS `q_eval` folds,
- `f_eval`,
- final MSM / `final_com`,
- pairing inputs,
- final accept/reject result.

Cover at least:

- compact quotient VM,
- native quotient callbacks,
- external quotient contract,
- fused PCS final MSM,
- accumulator pairing batching,
- `fewer-point-sets` on and off,
- truncated challenges,
- simple selectors,
- lookups,
- permutations,
- trash gates.

The quotient evaluator especially needs straight-line vs VM vs external-contract
differential tests.

### Adversarial Negative Tests

Add targeted malformed-proof tests, not only random mutation:

- malformed G1 padding,
- off-curve and subgroup-invalid points,
- unused or zero-weight commitments,
- wrong quotient evaluator contract,
- wrong or absent precompile behavior in a test harness,
- boundary field values: `0`, `1`, `r - 1`, `r`, and non-canonical encodings,
- denominator-zero cases where toy circuits can force them.

### Codegen Invariant Tests

Add tests that prove generated layouts and bindings are internally consistent:

- memory regions do not overlap,
- proof cursor consumes exactly the expected bytes,
- `proof_len`, `num_evals`, `num_point_sets`, and dummy eval counts match the
  native proof parser,
- generated verifier, VK, and quotient evaluator are mutually bound,
- trace and gas-checkpoint builds cannot be accidentally used as production
  artifacts.

## CI Gate

Before production, CI should run at least:

```bash
cargo test --workspace --all-features --all-targets

cargo test --release --workspace --all-features --all-targets \
  -- --include-ignored

scripts/run_ivc_bench.sh --check-only

scripts/run_ivc_bench.sh
```

For release candidates, CI should also run the native Midfall comparison:

```bash
scripts/run_ivc_bench.sh --native-midfall
```

## Deployment Hardening

Production deployment must be reproducible and pinned:

- fixed Rust toolchain,
- fixed `solc` version,
- locked dependencies,
- explicit feature set,
- reproducible verifier/VK/quotient runtime bytecode,
- published runtime bytecode hashes,
- automated address wiring,
- chain compatibility check for EIP-2537 addresses and semantics,
- no manual deployment path that can bypass quotient/VK codehash checks.

Deployment artifacts should include:

- verifier runtime hash,
- VK runtime hash,
- quotient evaluator runtime hash,
- compiler version,
- feature flags,
- source commit,
- expected contract sizes,
- expected bench result.

## External Review

After fixing the known issues and expanding tests:

1. Run an internal security review focused on soundness, transcript equivalence,
   calldata canonicality, memory layout, and deployment binding.
2. Freeze a release candidate.
3. Commission an independent external audit.
4. Fix all High and Medium findings.
5. Run a public testnet period with pinned bytecode and monitored proofs.

## Minimum Production Bar

Treat the verifier as production-ready only when all of the following are true:

- no known High or Medium verifier-soundness findings remain open,
- every fixed audit issue has a regression test,
- Rust/Solidity differential tests cover the active feature matrix,
- adversarial malformed-proof tests pass,
- deployment is reproducible and hash-pinned,
- target-chain precompile compatibility is verified,
- an independent external audit has been completed,
- the exact production bytecode has survived a testnet soak period.

Until then, this code should be considered experimental cryptographic
infrastructure.
