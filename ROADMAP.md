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

## Halo2/KZG Solidity Audit Checklist

This checklist is for implementing or auditing a Halo2/KZG verifier in Solidity
using BLS12-381 precompiles. The source reports behind it are mostly BN254
PLONK/Groth16/Halo2 verifier audits, but the same bug classes apply here. Some
are sharper for BLS because coordinates are 381-bit, subgroup/cofactor handling
matters more, and Solidity/Yul must marshal non-`uint256` field elements
carefully.

### 1. Pin The Exact Protocol And Trust Model

Define the verifier as a precise protocol, not just "Halo2 verifier":

- Exact Halo2 variant: KZG vs IPA; SHPLONK/multi-opening scheme;
  aggregation/accumulator scheme; single proof vs batch proof.
- Exact transcript: challenge order, hash function, domain separators,
  encodings, challenge-to-field method.
- Exact proving key/verifying key relationship: domain size `k`, number of
  instance columns, rotations, commitments, fixed/advice/lookup configuration.
- Exact SRS/CRS assumption: whether a trusted setup is required, which
  ceremony, which powers are included, and whether the verifier is bound to
  that SRS.

This is not optional. The Linea audit framed verifier correctness as
consistency with the PLONK paper and prover implementation, proof
soundness/completeness, and absence of unintended edge cases. It also found
"No Proper Trusted Setup" as critical because an unsafe CRS can allow forged
proofs.

### 2. Bind The Verifier To The Right VK, SRS, Circuit, And Chain Context

Things to bind or hardcode:

- `vk_digest` / circuit digest / verifying-key hash.
- SRS elements used by the verifier, especially `[x]_2` or equivalent BLS G2
  SRS element.
- Domain parameters: `n`, `omega`, `omega_inv`, `n_inv`, rotations, cosets.
- Number and order of public inputs and instance columns.
- Protocol version, curve ID, transcript version, and proof layout version.
- Chain ID and verifier contract address when the proof authorizes an on-chain
  state transition, withdrawal, bridge action, or nullifier update.

The Espresso audit found that the transcript omitted common preprocessed input
and SRS elements, introducing an unexpected degree of freedom; it recommended
including `[x]_2` in the verifying key. Scroll's Halo2 audit similarly flagged
Fiat-Shamir transcripts that did not include elliptic-curve parameters and
recommended including all public parameters in the transcript.

### 3. Treat Calldata And Proof Layout As Consensus-Critical

For a generated Solidity verifier, calldata parsing is part of the proof
system. Check:

- Exact proof length; reject missing and extra bytes.
- Exact public input count.
- No dynamic array overlap or assumptions about ABI layout.
- No unused appended bytes ignored by the verifier.
- Fixed offsets for every commitment/evaluation.
- Separate parsers for compressed vs uncompressed points.
- Explicit endian convention.
- For BLS: handle 48-byte Fq elements and 96-byte Fq2 elements carefully; do
  not truncate them into `uint256`.

The Linea audit found a missing proof length check that could cause proof and
public-input memory overlap or allow ignored extra data. Espresso also found
public input handling problems: dynamic arrays were accepted while only the
first eight public inputs were validated and used.

### 4. Enforce Canonical Field Encodings Everywhere

Do not reduce prover-supplied values unless the protocol explicitly specifies
reduction before hashing and verification. Prefer rejection.

Check all:

- Public inputs `< Fr`.
- Scalar evaluations `< Fr`.
- MSM scalars `< Fr`.
- Challenge outputs `< Fr`.
- Fq coordinates `< q`.
- Fq2 coordinates: both limbs `< q`.
- Compressed point encodings are canonical and unique.
- No `x + q`, `s + r`, or multiple encodings of the same element accepted.

Linea found missing range checks for public inputs and scalar proof elements.
Risc0's Groth16 audit warned that reducing public inputs modulo the group order
creates multiple representations; it recommended asserting that inputs are
already reduced. Espresso found non-canonical G1 deserialization and broader
ambiguity about canonical scalar/field arguments.

### 5. Validate All Curve Points Explicitly, Not Only Via Precompiles

For BLS12-381, this is especially important:

- Check G1/G2 points are canonically encoded.
- Check on-curve.
- Check subgroup membership.
- Decide whether point at infinity is allowed. Usually reject proof
  commitments/opening proofs unless the protocol explicitly permits infinity.
- Ensure negation is only applied to reduced, on-curve points.
- Ensure compressed point sign bits are canonical and match the off-chain
  implementation.
- Ensure G2 Fq2 coefficient ordering matches the precompile spec and prover
  library.

Linea recommended explicit field/curve checks for proof elements even when
precompiles also check, because relying on precompile failure gives poor errors
and can create unintended behavior. Axiom's Halo2 audit found multiple edge
case failures around elliptic-curve operations, including point-at-infinity
handling and missing on-curve checks for loaded witness points.

### 6. Wrap BLS Precompiles With Hardened Tiny Wrappers

Every precompile wrapper should enforce:

- Exact input length.
- Exact output length.
- Fresh output memory or cleared memory before call.
- `staticcall` success checked.
- `returndatasize()` checked.
- Pairing result value checked, not just call success.
- No arbitrary `sub(gas(), 2000)` unless justified; pass available gas or a
  carefully bounded amount.
- No stale memory reuse if the call fails.
- Precompile behavior documented per target chain/L2.

Linea's PLONK audit had two critical precompile-related issues: it failed to
check the pairing result stored in memory, so invalid proofs could pass, and
several `staticcall`s ignored failure, allowing stale memory to be used for
challenges, exponentiation, point addition, or scalar multiplication. Espresso
also flagged inconsistent staticcall offsets and unnecessary gas subtraction in
curve wrapper code.

### 7. Get Finite-Field Arithmetic Edge Cases Right

Critical arithmetic checks:

- Never define `inv(0) = 0`; revert or branch explicitly.
- Batch inversion must precheck all denominators nonzero, or correctly handle
  zero denominators in a protocol-specific way.
- Lagrange evaluation must handle `zeta` being a root of unity.
- Use `addmod`/`mulmod` for Fr arithmetic; avoid plain `add` unless there is a
  proof that overflow and modulus mismatch cannot occur.
- For BLS Fq arithmetic, do not use `uint256` arithmetic; use precompiles or
  multi-limb logic.
- Check domain size and root-of-unity constants.
- Check `n_inv * n = 1 mod Fr`, `omega^n = 1`, correct two-adicity, coset
  uniqueness, and rotation constants.

Linea and Espresso both found the same high-impact Lagrange-at-root-of-unity
issue: the efficient formula returns zero when `zeta` is in the domain, but the
correct Lagrange value may be one. Both also flagged zero inversion as invalid.

### 8. Reproduce The Transcript Exactly

For Halo2, transcript mismatches are a common source of silent unsoundness or
incompatibility.

Consider:

- Absorb VK/SRS/circuit digest before proof messages.
- Absorb all public inputs, including lengths and indices.
- Absorb every prover message before deriving the next challenge.
- Include curve ID and encoding mode.
- Domain-separate challenge rounds.
- Use unambiguous fixed-width encodings.
- Avoid `abi.encodePacked` ambiguity for variable-length data.
- Do not prepend/rehash in a way that deviates from the reference transcript
  unless formally justified.
- Ensure hash precompile calls cannot fail silently.

Espresso found challenge generation deviating from the protocol spec and
recommended directly hashing the transcript with round indices for multiple
challenges. Linea showed how failed hash precompile calls could make challenges
predictable if return status is ignored.

### 9. Match Halo2/KZG Opening Logic Exactly

Audit the PCS layer separately:

- KZG pairing equation sign and ordering.
- Whether `A`/opening accumulator is negated or not.
- SHPLONK accumulator construction.
- Multi-opening batching challenges.
- Non-empty accumulator/vector checks.
- Commitment/evaluation pairing: every evaluation must correspond to the
  correct commitment and point.
- Rotations: `zeta`, `zeta * omega`, last-row rotations, wraparound handling.
- Lookup arguments and permutation arguments.
- Quotient polynomial chunk count and degree.
- Whether linearization polynomial evaluations are included in proof or
  recomputed.
- Compatibility with the exact prover version.

Linea found deviations from the intended PLONK approach, including mismatches
in custom gate commitments/evaluations and sign conventions, and recommended
thorough review of those sections. Axiom/Scroll found that native PCS deciders
accepting empty vectors could bypass verification, recommending non-empty
assertions and negative tests.

### 10. Avoid Hardcoded One-Custom-Gate Or One-Commitment Assumptions

Generated verifier templates often accidentally bake in the first supported
circuit.

Check support for:

- Zero, one, or many custom gate commitments.
- Zero, one, or many lookup arguments.
- Variable numbers of advice/fixed/instance columns.
- Multiple proof systems or aggregation depths.
- Empty arrays where invalid.
- Number of public inputs exactly matching the circuit.
- Proof layout generated from metadata, not hand-maintained constants.

Linea found that its verifier supported only one BSB22 commitment and would
fail for zero or multiple commitments; the same report emphasized missing edge
case tests for no/multiple commitments.

### 11. Make Memory And Yul Rules Explicit

For a Solidity/Yul verifier:

- Respect the free memory pointer.
- Do not clobber `0x40` or Solidity scratch conventions unexpectedly.
- Start verifier-owned memory at a known safe offset, usually `0x80`.
- Keep a memory map for state, transcript, scratch, precompile inputs, and
  precompile outputs.
- Do not write computed values into `state_success` or other high-value flags
  accidentally.
- Fail fast instead of carrying `state_success` through expensive later
  operations.
- Remove debug writes and unused state fields.
- Use fixed compiler version and pinned solc binary.
- Regenerate ABI/bin in CI from source; do not commit stale artifacts.

Axiom's Halo2 upgrade audit found that an EVM verifier ignored Solidity's free
memory pointer and recommended starting allocation at `0x80` and asserting
`mload(0x40) == 0x80`. Linea's formal verification appendix specifically
checked memory-state modification, state reset, and scratch-memory correctness,
which are good invariants to replicate.

### 12. Error Behavior: Separate Malformed Input From Invalid Proof

A production verifier should define:

- Malformed calldata -> revert with custom error.
- Non-canonical field element -> revert.
- Invalid curve/subgroup point -> revert.
- Precompile failure -> revert.
- Wrong proof length -> revert.
- Mathematically well-formed but false proof -> either return `false` or
  revert, but be consistent with the consuming protocol.
- Internal invariant violation -> revert.

For general-purpose verifier APIs, prefer:

```solidity
function verify(bytes calldata proof, bytes32[] calldata publicInputs)
    external
    view
    returns (bool);
```

where malformed inputs revert and a well-formed invalid proof returns `false`.
For protocol entrypoints like `proveAndExecute(...)`, revert on both malformed
and invalid proof. Worldcoin's verifier audit recommended custom errors, and
the fix added distinct errors such as `PublicInputNotInField` and
`ProofInvalid`.

### 13. Test Like A Malicious Prover, Not Just An Honest Prover

Minimum negative test suite:

- Valid reference proof from the canonical Halo2 prover.
- Every proof byte flipped one at a time.
- Every scalar replaced by `x + r`, `r`, `r - 1`, `0`, `1`.
- Every Fq coordinate replaced by `x + q`, `q`, `q - 1`, non-canonical
  48-byte values.
- G1/G2 infinity in every commitment slot.
- Off-curve points.
- Wrong-subgroup BLS points.
- Wrong proof length: short, long, extra trailing bytes.
- Wrong public input count.
- Public input not in Fr.
- Wrong endianness.
- Wrong VK digest.
- Wrong SRS element.
- Wrong domain size.
- `zeta` forced to domain point in test harness.
- Zero denominators in batch inversion.
- Precompile failure using mocks or a fork target that can simulate failure.
- Pairing precompile returns zero.
- Empty accumulator/MSM/vector.
- Multiple custom commitments and zero custom commitments.
- Differential tests against the Rust verifier.

Linea explicitly called out missing edge-case tests for off-curve proof
elements, infinity, all-zero proof elements, wrong scalars, scalar wraparound,
invalid public inputs, and zero/multiple commitments. Scroll recommends
adversarial testing focused on malicious prover behavior, because ordinary
geth/reference tracing mostly exercises completeness rather than soundness.

### 14. Use Lightweight Formal Methods For The Small Critical Helpers

High-value targets for formal specs:

- `load_fr`, `load_fq`, `load_g1`, `load_g2`.
- `is_canonical_fr`, `is_canonical_fq`.
- `batch_invert`.
- `invert_nonzero`.
- `evaluate_lagrange`.
- `evaluate_pi_poly`.
- `hash_to_field` / transcript challenge derivation.
- Precompile wrappers: success, returndata size, result semantics.
- Memory allocator / scratch memory separation.
- `state_success` monotonicity: once false, never true again.
- Calldata layout precheck.
- VK codehash/deployment precheck.
- Pairing equation wrapper.

The Linea audit used Dafny/Z3 to prove selected verifier properties such as
termination, arithmetic overflow/underflow behavior, immutable inputs,
memory-state modification, state reset, scratch-memory safety, and batch
inversion correctness.

### 15. BLS-Specific Implementation Notes

Because this verifier uses BLS precompiles, add these BLS-only checks to the
BN254-derived lessons:

- BLS Fq is 381 bits: Solidity `uint256` cannot hold a coordinate. Use
  byte-sliced canonical comparisons.
- BLS Fr fits in 255 bits: scalar field arithmetic can use `addmod`/`mulmod`
  with Fr modulus, but only after strict canonical Fr loading.
- G1 and G2 have cofactors: subgroup validation must be explicit or guaranteed
  by the precompile spec.
- G2 encoding is easy to swap: lock down Fq2 coefficient ordering and test
  against vectors from the exact off-chain library.
- Pairing precompile semantics must be known: does it reject invalid encodings,
  return false, or fail the call?
- MSM precompile semantics must be known: empty MSM, infinity bases, zero
  scalars, non-canonical scalars, subgroup checks.
- If proof points are compressed, implement decompression/sign handling once,
  test it heavily, and expose a view/helper only if it cannot create
  alternative encodings. Worldcoin's audit specifically reviewed compressed
  proof support and recommended making complex compression helpers accessible
  rather than leaving them only in tests.

### 16. Code Generator Invariants

Because Halo2 Solidity verifiers are usually generated, move as many checks as
possible into the generator:

- Generate a machine-readable proof layout manifest.
- Generate Solidity offsets from that manifest, not hand-written constants.
- Generate tests from the same manifest.
- Generate static assertions for proof length, public input count, and VK
  constants.
- Generate a reference JSON test vector: proof, public inputs, transcript
  intermediate challenges, expected pairing inputs.
- Generate negative tests for every field/point input.
- Generate a memory map and assert no overlap.
- Generate NatSpec and custom errors.
- Pin solc version in generated output.
- Produce a reproducible build artifact and compare bytecode hash in CI.

The Worldcoin audit notes that the verifier was produced by a Go data-driven
code generator, and its recommendations focused on template-level improvements
such as custom errors, compression helper availability, and NatSpec; those are
exactly the kinds of properties that should be baked into the generator once
rather than manually patched in each verifier.

### Condensed Do-Not-Ship-Without List

Do not ship until the verifier has:

- strict proof length checks;
- canonical Fr/Fq loading;
- explicit G1/G2 on-curve/subgroup/infinity policy;
- all precompile success and return values checked;
- pairing result checked;
- zero inversion rejected;
- Lagrange root-of-unity case handled;
- VK/SRS/public inputs bound into transcript;
- Solidity memory pointer respected;
- invalid proof/invalid encoding tests;
- differential tests against the reference Halo2 verifier.
