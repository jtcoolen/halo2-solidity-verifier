# Testing

This document collects the commands needed to exercise the examples and the
property-based test (PBT) suite shipped with this crate.

The workspace is pinned to the toolchain in [`rust-toolchain.toml`](./rust-toolchain.toml)
(currently Rust 1.90.0). Solidity-touching tests and examples additionally
require pinned `solc 0.8.30+commit.73712a01` on `PATH` or via `SOLC`.

Midnight crates resolve from the immutable Midfall revision configured in
`Cargo.toml`:

```text
https://github.com/EYBlockchain/midfall.git#53dc872f495104046d96bdac0a690f903dc0c537
```

Repository-local `.cargo/config.toml` path overrides are intentionally not
used. They make generated verifier bytecode depend on a local checkout instead
of the pinned dependency graph.

The ignored proving benches need local SRS files. `scripts/run_ivc_bench.sh`
downloads the IVC bench assets into `.srs/` by default, or you can point
`SRS_DIR` at an existing SRS directory. The IVC Solidity tree bench needs
Midnight `midnight-srs-2p19` for the leaf IVC proofs and
`midnight-srs-2p20` for the final decider proof; the optional native Midfall
comparison path also needs a Filecoin SRS.

```bash
rustc --version    # should report 1.90.0
solc --version     # should report 0.8.30+commit.73712a01
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

The PBT cases are EVM-heavy and only make sense in `--release`. They self-skip
unless `HALO2_SOLIDITY_RUN_EVM_TESTS=1`, the pinned solc is available, and the
SRS assets are present. Run the whole PBT batch with:

```bash
HALO2_SOLIDITY_RUN_EVM_TESTS=1 \
SRS_DIR=/path/to/srs \
cargo test --release --all-features pbt_ -- --nocapture
```

Individual cases:

```bash
# Positive case: real proofs are accepted by the embedded verifier.
cargo test --release --all-features \
    pbt_solidity_verifies_standard_plonk_embedded_vk_proofs \
    -- --nocapture

# Negative: corrupted public inputs must be rejected (embedded + separate).
cargo test --release --all-features \
    pbt_solidity_rejects_wrong_instances \
    -- --nocapture

# Negative: any single-bit flip in the proof bytes must be rejected.
cargo test --release --all-features \
    pbt_solidity_rejects_malleated_proofs \
    -- --nocapture

# Negative: a separate verifier must reject a VK contract it was not pinned to.
cargo test --release --all-features \
    pbt_solidity_rejects_wrong_verifying_keys \
    -- --nocapture

# Negative: even a one-nibble change inside vk_digest must break verification.
cargo test --release --all-features \
    pbt_separate_vk_digest_prefix_affects_verification \
    -- --nocapture
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

This slow ignored test proves two independent one-step IVC Poseidon hash-chain
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

Run the same bench with fewer point sets kept for the recursive verifier, but
disabled for the outer Solidity-facing decider proof:

```bash
scripts/run_ivc_bench.sh --no-outer-fewer-point-sets
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

---

## Audit-Driven Halo2/KZG Solidity Test Checklist

This checklist is source-grounded in verifier audit findings across PLONK,
Groth16, Halo2, and verifier code generators. It is tailored to this repository:
Halo2/KZG Solidity verifier generation over BLS12-381/EIP-2537 precompiles.
The broader production-readiness framing is also recorded in
[`ROADMAP.md`](./ROADMAP.md).

### 1. Protocol And Trust Model

Tests and fixtures must pin the exact protocol being checked:

- Halo2 variant: KZG vs IPA, SHPLONK/multi-opening scheme, aggregation or
  accumulator scheme, single proof vs batch proof.
- Transcript: challenge order, hash function, domain separators, encodings,
  and challenge-to-field method.
- Proving-key/verifying-key relationship: domain size `k`, instance columns,
  rotations, commitments, fixed/advice/lookup configuration.
- SRS/CRS assumption: ceremony, powers included, and whether the verifier is
  bound to that SRS.

Linea-style trusted-setup failures should be treated as critical: a forged or
unbound CRS can make proofs meaningless.

### 2. VK, SRS, Circuit, And Chain Binding

Negative tests should mutate or swap:

- `vk_digest` / circuit digest / verifying-key hash.
- `[x]_2` or equivalent BLS G2 SRS element.
- Domain parameters: `n`, `omega`, `omega_inv`, `n_inv`, rotations, cosets.
- Public input count and ordering.
- Protocol version, curve ID, transcript version, proof layout version.
- Chain ID / verifier address for state-transition wrappers.

Espresso and Scroll findings around missing SRS/curve/public-parameter
transcript binding should be covered by transcript and VK mutation tests.

### 3. Calldata And Proof Layout

Malformed calldata tests must cover:

- Exact proof length; missing bytes and extra trailing bytes.
- Exact public input count.
- Dynamic ABI offset overlap and malformed dynamic heads.
- Unused appended bytes ignored by the verifier.
- Every fixed commitment/evaluation offset.
- Compressed vs uncompressed point parser separation.
- Explicit endian convention.
- BLS 48-byte Fq and 96-byte Fq2 handling, with no truncation into `uint256`.

Proof layout is consensus-critical: the Solidity parser is part of the proof
system.

### 4. Canonical Field Encodings

Reject prover-supplied non-canonical values instead of reducing them unless the
reference protocol explicitly specifies reduction first.

Boundary cases:

- Public inputs `< Fr`.
- Scalar evaluations `< Fr`.
- MSM scalars `< Fr`.
- Challenges `< Fr`.
- Fq coordinates `< q`.
- Fq2 limbs `< q`.
- Compressed point encodings are canonical and unique.
- Reject `x + q`, `s + r`, `q`, `r`, and alternative encodings.

Linea, Risc0, and Espresso findings all point to canonicalization tests as a
core negative-test family.

### 5. Curve Points

For every proof/VK/accumulator point slot, test:

- canonical encoding;
- on-curve validation;
- subgroup membership or documented precompile guarantee;
- infinity policy;
- negation only after reduction and on-curve validation;
- compressed sign-bit canonicality;
- G2 Fq2 coefficient ordering against the exact off-chain library.

BLS12-381 makes subgroup/cofactor and coordinate-width mistakes especially
expensive.

### 6. BLS Precompile Wrappers

Mock/fork tests should force precompile failure modes:

- exact input length;
- exact output length;
- fresh or cleared output memory;
- checked `staticcall` success;
- checked `returndatasize()`;
- checked pairing result value;
- no unjustified `sub(gas(), 2000)`;
- no stale memory reuse after failure;
- target-chain/L2 behavior documented.

Linea found invalid proofs passing when the pairing result was not checked, and
stale-memory bugs when `staticcall` failure was ignored.

### 7. Finite-Field Arithmetic Edge Cases

Add small/toy circuits or direct helper tests for:

- `inv(0)` rejection;
- batch inversion with empty, singleton, and zero-containing ranges;
- Lagrange evaluation when `zeta` is a root of unity;
- `addmod`/`mulmod` usage for Fr arithmetic;
- no `uint256` arithmetic for BLS Fq;
- `n_inv * n = 1 mod Fr`;
- `omega^n = 1`;
- correct two-adicity, cosets, and rotation constants.

Linea and Espresso both found high-impact root-of-unity/Lagrange bugs and
zero-inversion issues.

### 8. Transcript Equivalence

Differential trace tests should confirm:

- VK/SRS/circuit digest absorbed before proof messages;
- all public inputs, lengths, and indices absorbed;
- every prover message absorbed before the next challenge;
- curve ID and encoding mode bound where required;
- challenge rounds domain-separated;
- fixed-width encodings are unambiguous;
- no `abi.encodePacked` ambiguity for variable-length data;
- no unreviewed prepend/rehash deviation from the reference transcript;
- failed hash/precompile calls cannot become predictable challenges.

Use the Rust verifier transcript as the oracle.

### 9. Halo2/KZG Opening Logic

PCS tests must isolate:

- KZG pairing equation sign and ordering;
- whether `A`/opening accumulator is negated;
- SHPLONK accumulator construction;
- multi-opening batching challenges;
- non-empty accumulator/vector checks;
- each evaluation paired with the correct commitment and point;
- rotations: `zeta`, `zeta * omega`, last-row rotations, wraparound;
- lookup and permutation arguments;
- quotient chunk count and degree;
- whether linearization evaluations are proof-provided or recomputed;
- compatibility with the exact prover revision.

Native PCS deciders accepting empty vectors should have explicit negative
tests.

### 10. Circuit Shape Coverage

Generated templates must not bake in the first supported circuit shape. Cover:

- zero, one, and many custom gate commitments;
- zero, one, and many lookup arguments;
- variable advice/fixed/instance column counts;
- multiple proof systems or aggregation depths;
- invalid empty arrays;
- exact public input count;
- proof layout generated from metadata rather than hand-maintained constants.

Linea's "one commitment" failure class belongs here.

### 11. Memory And Yul Rules

Regression tests should assert:

- Solidity free memory pointer conventions are respected;
- no generated writes clobber `0x40` or reserved scratch unexpectedly;
- verifier-owned memory starts at `0x80` or a reviewed safe offset;
- generated memory map covers transcript, state, scratch, precompile inputs,
  and precompile outputs;
- computed values cannot overwrite `state_success` or other high-value flags;
- failure paths stop early enough and cannot later turn success true;
- debug writes and unused state fields are absent;
- solc version is fixed and checked;
- generated artifacts are reproducible from source.

Axiom's Halo2 audit and Linea's formal appendix both make memory layout a
first-class verifier invariant.

### 12. Error Behavior

Define and test the API policy:

- malformed calldata -> revert;
- non-canonical field element -> revert;
- invalid curve/subgroup point -> revert;
- precompile failure -> revert;
- wrong proof length -> revert;
- mathematically well-formed false proof -> return `false` or revert, but be
  consistent;
- internal invariant violation -> revert.

General-purpose verifier APIs may return `false` for well-formed invalid
proofs, while protocol entrypoints should usually revert.

### 13. Malicious-Prover Negative Suite

Minimum adversarial cases:

- valid reference proof from the canonical prover;
- every proof byte flipped one at a time;
- every scalar replaced by `x + r`, `r`, `r - 1`, `0`, `1`;
- every Fq coordinate replaced by `x + q`, `q`, `q - 1`, non-canonical
  48-byte values;
- G1/G2 infinity in every commitment slot;
- off-curve points;
- wrong-subgroup BLS points;
- short, long, and trailing-byte proof lengths;
- wrong public input count;
- public input not in Fr;
- wrong endianness;
- wrong VK digest;
- wrong SRS element;
- wrong domain size;
- `zeta` forced to a domain point;
- zero denominators in batch inversion;
- mocked precompile failure;
- pairing precompile returns zero;
- empty accumulator/MSM/vector;
- multiple and zero custom commitments;
- differential tests against the Rust verifier.

Scroll recommends malicious-prover testing because reference traces mostly
exercise completeness, not soundness.

### 14. Lightweight Formal Targets

High-value helpers for formal specs or bounded symbolic tests:

- `load_fr`, `load_fq`, `load_g1`, `load_g2`;
- `is_canonical_fr`, `is_canonical_fq`;
- `batch_invert`;
- `invert_nonzero`;
- `evaluate_lagrange`;
- `evaluate_pi_poly`;
- `hash_to_field` / transcript challenge derivation;
- precompile wrappers;
- memory allocator and scratch separation;
- `state_success` monotonicity;
- calldata layout precheck;
- VK codehash/deployment precheck;
- pairing equation wrapper.

Linea used Dafny/Z3 to prove small verifier properties; replicate that style
for compact helpers before trying to prove the whole verifier.

### 15. BLS-Specific Tests

BLS-only concerns:

- Fq is 381 bits, so coordinates cannot fit in Solidity `uint256`;
- Fr fits in 255 bits and can use `addmod`/`mulmod` only after canonical load;
- G1/G2 cofactors require subgroup validation or a documented precompile
  guarantee;
- G2 Fq2 coefficient ordering must be locked down with vectors;
- pairing precompile invalid-input semantics must be known;
- MSM precompile behavior for empty MSM, infinity bases, zero scalars,
  non-canonical scalars, and subgroup checks must be known;
- compressed proof-point decompression/sign handling should be implemented
  once and tested heavily.

Worldcoin's compressed-proof audit notes belong in this family.

### 16. Code Generator Invariants

Generator-level tests should produce and consume:

- machine-readable proof layout manifest;
- Solidity offsets generated from that manifest;
- tests generated from the same manifest;
- static assertions for proof length, public input count, and VK constants;
- reference JSON vector: proof, public inputs, transcript challenges, expected
  pairing inputs;
- negative tests for every field/point input;
- memory map with non-overlap assertions;
- NatSpec and custom errors;
- pinned solc/version metadata in generated output;
- reproducible build artifact and bytecode-hash comparison in CI.

Worldcoin's generator audit recommendations reinforce the rule: bake template
properties into the generator once, instead of manually patching each verifier.

### Condensed Do-Not-Ship-Without Tests

Do not ship without tests for:

- strict proof length checks;
- canonical Fr/Fq loading;
- explicit G1/G2 on-curve/subgroup/infinity policy;
- every precompile success and return value;
- pairing result value;
- zero inversion rejection;
- Lagrange root-of-unity case;
- VK/SRS/public inputs bound into transcript;
- Solidity memory pointer conventions;
- invalid proof and invalid encoding rejection;
- differential equivalence against the reference Halo2 verifier.
