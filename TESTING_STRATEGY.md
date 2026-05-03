# Testing Strategy

This document records the verifier-bug taxonomy from the source prompt and
turns it into a practical test suite for this repository's Halo2 Solidity
verifier generator.

The core target is generated on-chain verifier code for Midnight/Halo2 KZG on
BLS12-381, including embedded verifier-key mode, separate verifier-key mode,
pinned external quotient evaluators, EIP-2537 precompile integration, calldata
parsing, public-input handling, transcript equivalence, accumulator handling,
and wrapper/application binding.

## Source Prompt Taxonomy

The prompt asked for a test suite based on a practical taxonomy of
SNARK/STARK verifier contract bugs. The consolidated taxonomy below preserves
the prompt's main audit concerns and maps them to testable invariants.

### 1. Statement-Binding Bugs

These bugs let the proof verify a statement different from the one the contract
thinks it is verifying.

- Public input not fully bound: every protocol-critical value must be included
  in public inputs or the verifier transcript.
- Wrong public-input ordering: compare generated verifier ABI, Solidity
  packing, and circuit witness/public-input layout.
- Missing public input length check: enforce the exact length in the base
  verifier, not only in wrappers.
- Non-canonical public inputs: reject values greater than or equal to the field
  modulus before hashing, events, storage, or verification.
- Unused public inputs: require every non-zero public input entry to be
  referenced by active proof logic.
- Statement not bound to action: wrappers must bind chain, contract, caller,
  recipient, nullifier, amount, root, image ID, journal digest, calldata hash,
  and other application-specific context.

### 2. Setup, Verifying-Key, Circuit-Identity, and Parameter Trust Bugs

The proof may be valid for a different circuit, verifier key, version, or
parameter set than intended.

- Toxic-waste or CRS misuse: deployed verifiers must not rely on toy or
  unverifiable setup parameters.
- Verifying-key mismatch: bind domain size, public-input count, custom gate
  set, commitment layout, circuit digest, and verifier-key code.
- Wrong VK selected: registry keys must identify the full circuit shape and
  version, not only partial parameters.
- Missing VK/dependency binding: pin VK contract codehash, quotient evaluator
  codehash, preprocessed roots, SRS elements, curve, and circuit digest.
- VK upgrade risk: verifier upgrades should be timelocked, immutable for
  emergency exits, or paired with user exit windows.
- Missing deployment-code validation: hash or validate deployed bytecode and
  generated constants.
- Recursive verifier wrong inner VK: inner VK must be constant or transcript
  bound and impossible to swap.
- Wrong security parameters: FRI query count, blowup factor, grinding,
  commitment security bits, and extension-field assumptions must be on-chain
  or otherwise pinned.

### 3. ABI, Calldata, Encoding, and Memory-Layout Bugs

The wrapper and verifier parse different proof or instance data, or low-level
code corrupts memory.

- Non-canonical ABI accepted: assert exact dynamic offsets, lengths, and
  trailing data, or use Solidity ABI decoding directly.
- Proof selector not checked: validate selector and expected verifier entry
  point.
- Proof length/layout bugs: reject truncation, extra bytes, calldata overlap,
  stale bytes, off-by-one unmarshalling, and hardcoded proof-size drift.
- Endianness and serialization drift: test off-chain/on-chain byte order,
  point compression conventions, and field canonicalization.
- Free memory pointer clobber: assembly must respect Solidity memory layout,
  use planned scratch, and avoid reserved memory corruption.
- Return length mismatch: precompile/verifier returns must match documented
  ABI exactly.
- Out-of-bounds memory reads: failed reads must not turn into zeroes or stale
  data.
- Magic offsets/constants: generated layouts should be derived from typed
  metadata and checked by tests.

### 4. Field-Element Canonicalization and Range Bugs

These bugs arise when EVM `uint256`, native integers, limbs, and finite-field
elements are confused.

- Missing `< q` or `< r` checks: public inputs, proof scalars, and point
  coordinates must be canonical before use.
- Non-canonical public inputs: reject `x + r` or `x + q` encodings instead of
  reducing them silently.
- Packing and width bugs: packed small-field values must have strict width and
  unused-bit checks.
- Modulus wraparound: attested or computed data must not wrap modulo field.
- Non-native limb range unsoundness: prove limb range and native congruence.
- Truncation: reject 512-bit to 256-bit overflow or panic paths.
- Debug-only validation: security checks must be runtime assertions or circuit
  constraints, not `debug_assert!`.
- Zero inverse/division edge cases: reject denominator zero unless the protocol
  explicitly defines that behavior.

### 5. Curve, Pairing, Subgroup, and Point-Encoding Bugs

These are common in Groth16, KZG, IPA, Halo2, BLS, and pairing precompiles.

- Missing curve/subgroup checks: proof commitments, VK commitments, G1/G2
  points, and accumulators must be valid subgroup elements.
- Identity point accepted: reject identity public keys, accumulators, and proof
  commitments unless explicitly supported.
- Point-at-infinity mishandled: define one representation and handle it in
  every EC operation.
- Invalid point deserialization: reject coordinates not in field or not on
  curve before pairing, MSM, or scalar multiplication.
- Non-canonical point coordinates: reject `x >= p`, `y >= p`, or multiple
  encodings of one point.
- Unsound point negation: validate `y < q` and on-curve before computing
  `q - y`.
- Scalar range omission: reject proof scalars outside the scalar field where
  required.
- Pairing equation implementation bugs: test sign, negation, term order, and
  constants against trusted vectors.
- Precompile failure conflated with invalid proof: distinguish malformed
  inputs, verifier-key dependency failures, and semantic proof failure where
  the API supports it.

### 6. Fiat-Shamir Transcript Bugs

Non-interactive verification must bind every part of the statement and every
prover message before deriving challenges.

- Missing transcript fields: VK, public inputs, commitments, domains,
  protocol IDs, curve parameters, SRS elements, circuit IDs, and public params
  must be absorbed.
- Missing prover/public data: public memory, LogUp sums, commitment roots, and
  proof metadata must be challenge-bound.
- Wrong domain separation/order: use explicit domain tags and round labels per
  proof type, chain, circuit, and verifier.
- Public inputs not included in transcript: challenge generation must include
  public inputs when the protocol requires it.
- Challenge bias: avoid biased modulo reduction unless documented by the
  proof system; use the native verifier as the oracle.
- Hash domain collisions: prefix lengths, node types, proof/data domains, and
  variable-length structures.
- Failed hash/precompile calls not checked: failed SHA/modexp/staticcall
  paths must not leave stale memory that becomes a challenge.

### 7. Polynomial-Commitment, Accumulation, Pairing, IPA, KZG, and FRI Bugs

This layer is often the final check. A single missing boolean can invalidate
the verifier.

- Pairing result ignored: check both precompile call success and semantic
  result.
- Empty accumulator accepted: reject empty proof, accumulator, PCS, KZG, IPA,
  or FRI vectors unless explicitly valid.
- Commitment not checked: validate proof commitments against configured or
  attested commitments.
- Missing commitment opening check: every required opening must be checked at
  the correct point and against the correct commitment.
- All-but-pairing proof not finalized: final pairing/decision must always run.
- Aggregation spec incomplete: outer proof must imply all inner proofs, bind
  inner VK constants, and bind accumulator state.
- Wrong commitment opening domain: differential test against the native
  verifier.
- Merkle/FRI decommitment skip: prover-controlled lengths must not skip
  iterations or checks.
- Preprocessed trace/root unchecked: STARK preprocessed roots and trace roots
  must be pinned.

### 8. Polynomial Identity and Domain Edge-Case Bugs

Verifier math is often correct except at boundary cases.

- Root-of-unity special cases: Lagrange evaluation must be correct when
  challenge points lie in the evaluation domain.
- Vanishing polynomial edge cases: avoid division by zero at domain points.
- Batch inversion with zeros: handle empty, singleton, and zero-containing
  ranges.
- Wrong polynomial version: do not mix old/new PLONK linearization formulas,
  signs, constants, quotient shard degrees, or domain sizes.
- Domain-size miscalculation: check `n`, `m`, `k`, public-input counts, and
  number of constraints.

### 9. Underconstrained Circuit and Recursive-Verifier Bugs

Even with a correct Solidity verifier, an underconstrained circuit can make
false statements verify.

- Missing equality constraint: negative tests with malicious witnesses.
- Missing boolean/range constraint: selectors, indices, flags, signs, bytes,
  tags, and condition flags must be constrained to valid domains.
- Non-unique witness: prove uniqueness or specify tie-breaking.
- Lookup misuse: membership is not multiplicity or permutation.
- Zero division/inverse unconstrained: require denominator nonzero or define
  zero behavior.
- Unused verifier output: recursive verifier circuits must constrain the
  verification result to true and expose/bind the exact public input consumed
  by the outer verifier.
- Underconstrained VM/opcode semantics: malicious prover behavior should be
  tested against reference semantics.
- Error/success path overlap: success and error gadgets must be disjoint.
- Release-build-only underconstraints: no security-critical `debug_assert!`
  paths.

### 10. STARK-Specific Verifier Bugs

For STARK contracts, equivalent bugs usually live in FRI, Merkle, AIR, and
transcript logic.

- AIR public input mismatch: bind trace length, program hash, memory roots,
  public memory, and output roots.
- FRI parameter mismatch: enforce blowup factor, folding schedule, query
  count, domain size, and proof-of-work on-chain.
- Query sampling bias: derive query indices from the complete transcript.
- Merkle path malleability: domain-separate leaves/nodes and bind level,
  index, and path length.
- Field extension encoding bugs: test limb order and encoding against
  canonical vectors.
- OOD/DEEP composition mistakes: bind out-of-domain challenges and check the
  exact composition polynomial formula.
- Proof-of-work grinding mistakes: verify exact transcript prefix and target.

### 11. Protocol Integration, App Binding, Replay, and Liveness Bugs

The proof may be true while the surrounding protocol still fails.

- Proof valid but state transition unusable: test rollover, max IDs, max
  roots, and long-running counters.
- Forced-exit verifier can be disabled: model censorship and forced withdrawal
  paths.
- Nullifiers not reserved: delayed proofs can be invalidated by spending the
  same nullifier.
- Snapshot timing races: version roots and bind proofs to snapshot versions.
- Unspendable outputs: commitment and encrypted note metadata must match.
- Replay/malleability misuse: do not use Groth16 or other malleable proof
  bytes as unique IDs unless the design accounts for malleability.
- Emergency stop too narrow: kill-switches should cover generalized proof of
  exploitation, not only one hardcoded invalid statement.
- Cross-layer finality and root freshness: bind chain roots and fraud-window
  assumptions.
- Upgradable verifier/router risk: pin dependency codehashes and verifier
  router targets.

### 12. Fail-Open, Fail-Closed, DoS, and Low-Level EVM Bugs

Low-level integration bugs can break otherwise correct cryptography.

- Panic on malformed proof: malformed input should fail fast and clearly.
- Fail-open assembly return: helpers must not use `return(0, 0)` in a way that
  exits verification successfully.
- Malformed proof causes expensive path first: validate lengths, offsets,
  bounds, and field elements before hashing or precompiles.
- Valid proofs rejected: positive vectors and interoperability tests should
  catch over-strict canonicality and wrong return formats.
- Error conflation: custom errors or documented revert policy should
  distinguish dependency failures from invalid proofs where useful.
- `staticcall` status ignored: ECADD, ECMUL, pairing, SHA, and modexp failures
  must not leave stale memory.
- Return buffer stale data: failed precompile return data must not be reused.
- Gas subtraction griefing: avoid `gas() - constant` patterns that fail near
  the end of execution.
- ABI/bin/template drift: committed artifacts must be regenerated from current
  templates and compiler settings.

### 13. Testing and Specification Gaps

The prompt emphasized that missing negative tests and missing specifications
are strong predictors of verifier bugs.

- Only positive proof tests miss ignored pairing results, malleability, missing
  length/range checks, invalid points, and invalid public inputs.
- No malformed calldata tests misses truncation, overlap, bad offsets, and
  trailing data.
- No adversarial prover tests misses underconstrained witnesses and skipped
  Merkle paths.
- No differential tests misses native/EVM divergence.
- No known-answer vectors misses hash, Keccak, pairing, FRI, EC, and
  serialization mistakes.
- Spec-code drift: comments and docs should be treated as formal layout/API
  specifications.
- Generator bugs: audit templates and generators, not only generated
  instances.

## Highest-Risk Prompt Checklist

For each generated verifier, the prompt's highest-risk invariants become:

1. The verifier proves the intended circuit: VK, circuit version, shape, public
   input length, and proof-system parameters are all bound.
2. The contract computes and consumes exactly the same public inputs as the
   circuit expects.
3. Every public input is canonical, field-bounded, ordered, and consumed.
4. ABI/calldata decoding is canonical; no alternate encoding can make wrapper
   and verifier parse different data.
5. All EC points, commitments, and accumulator elements are on-curve,
   in-subgroup, non-identity when required, and correctly encoded.
6. The transcript includes all commitments, public inputs, VK/domain data, and
   protocol separators.
7. Precompile calls check both call success and expected return size/result.
8. Assembly respects Solidity memory layout and never fails open.
9. Upgrade/admin controls cannot silently replace, weaken, or disable the
   verifier.
10. Negative tests exist for malformed proofs, wrong public inputs, wrong VK,
    wrong proof length, non-canonical field elements, empty accumulators, and
    replay/liveness edge cases.

## Repo-Specific Testing Goal

Build a verifier conformance and adversarial regression suite, mostly in
Rust/revm, because this repository already has that harness in `src/test.rs`,
with slow IVC coverage in `tests/ivc_keccak_solidity.rs`.

Every generated verifier should pass three oracles:

1. Native Midfall/Halo2 verification accepts the valid proof.
2. Solidity/revm accepts exactly the same proof, public inputs, VK, quotient
   evaluator, and feature profile.
3. Every targeted mutation either reverts or fails, never returns true.

## Proposed Test Suite

| Layer | Tests |
| --- | --- |
| Positive vectors | Valid Poseidon fixture, shape-fuzz circuits, and IVC final Keccak proof must verify in embedded VK, separate VK, and pinned quotient modes. |
| Public input binding | Mutate every public input slot, not only slot 0. Swap instance order, truncate/extend instances, set each input to `Fr`, `Fr + 1`, `2Fr - 1`, and for IVC mutate every accumulator limb word. |
| ABI/calldata canonicality | Wrong selector, empty proof, truncated proof, trailing bytes, overlapping dynamic heads, shifted but otherwise ABI-valid heads, wrong length words, stale padding between proof and instances. |
| VK/circuit identity | Mutate each VK section: digest, params, fixed commitments, permutation commitments, quotient constants, quotient program. Verify constructor rejects wrong VK codehash, wrong quotient codehash, wrong runtime length, swapped VK/quotient addresses. |
| Proof scalar canonicality | For every scalar offset in the repacked proof, test `Fr`, `Fr + 1`, high-bit values, and random noncanonical words. These should reject before or during verification. |
| G1/EIP-2537 encoding | For every proof G1: nonzero top padding, coordinate `p`, coordinate `p + 1`, off-curve point, infinity where not explicitly allowed, and on-curve wrong-subgroup point if a fixture can be generated. |
| Transcript equivalence | Trace Rust and Solidity for all challenge stages: VK digest, committed instance, public instances, advice commitments, theta/beta/gamma/y/x/x1/x2/x3/x4, quotient eval, PCS inputs, final pairing inputs. Keep the native/Solidity trace comparison as a required EVM gate. |
| Empty/edge circuit shapes | Shape fuzz circuits with no advice in a phase, no lookups, one lookup, additive selectors, complex selectors, next rotations, second phase advice, permutation on/off, and wide advice counts that stress memory layout. |
| PCS/KZG/quotient | Mutate every quotient commitment, proof eval, opening proof, batching scalar source, quotient evaluator output, and external quotient return length. Assert the final pairing result is semantically checked, not just precompile call success. |
| Accumulator-specific | Check accumulator schema consumes exactly the expected public input words. Test unused high limb bits, malformed identity encoding, x/y limb swaps, scalar mutation, zero/identity accumulator cases, and any future fixed-base tail. |
| Precompile/fail behavior | Constructor smoke tests for EIP-2537 are good; add tests for short return data, false pairing result, reverted precompile call, and stale return memory using generated-template mutations or a helper harness. |
| Memory/layout | Fast generator tests should assert no overlap between VK, challenge, transcript, quotient, PCS, accumulator, and scratch regions. Keep these as compile-time/layout tests in `src/codegen/mod.rs` and `src/codegen/template.rs`. |
| Production artifact checks | `verifyProof` production renders stay `external view`, no `LOG1`, no gas checkpoints, Solidity pragma `^0.8.24`, Cancun/Prague target, runtime size below EIP-170 with margin. |
| Wrapper/application binding | Add small mock wrapper contracts that bind expected state root, program ID, chain/domain, caller/action hash, nullifier/nonce. Same proof with wrong wrapper context must reject. |

## Priority Backlog

### P0

- Mutate every public input slot.
- Expand ABI canonicality tests to all verifier variants: embedded VK,
  separate VK, pinned quotient, trace, and gas-checkpoint render paths where
  applicable.
- Add category-aware proof mutations for every scalar, G1, eval, commitment,
  and opening offset.
- Require native/Solidity trace equivalence in the EVM gate whenever the
  `rust-verifier-trace` feature is available.

### P1

- Add accumulator malformation tests outside the slow IVC bench, especially
  unused high limb bits and identity encoding variants.
- Add precompile-return semantic tests: short return, false pairing return,
  reverted call, stale memory, and bounded-gas failure.
- Add quotient-evaluator adversarial tests for wrong output length, wrong
  codehash, wrong runtime length, mutated quotient program, and mutated
  quotient constants.
- Add field-boundary tests for `Fr`, `Fr + 1`, `2Fr - 1`, `p`, `p + 1`, and
  high-bit values where the encoding makes sense.

### P2

- Add wrapper-level tests for application binding and replay/nullifier
  behavior, since raw `verifyProof(bytes,uint256[])` intentionally proves only
  "this proof verifies for these public instances under this VK."
- Add generated layout invariant tests for every rendered constant group and
  memory region.
- Add wrong-subgroup G1/G2 fixtures if a reliable generator can produce them.
- Add long-running/liveness tests for counters, root windows, and snapshot
  versions in downstream integration wrappers.

## Run Tiers

### Fast CI

```bash
cargo test --workspace --all-features --all-targets
```

### EVM Negative Suite

```bash
HALO2_SOLIDITY_RUN_EVM_TESTS=1 \
cargo test --release --features evm,truncated-challenges,rust-verifier-trace -- --nocapture
```

### Property-Based EVM Suite

```bash
cargo test --release --all-features pbt_ -- --ignored --nocapture
```

### Slow IVC/Accumulator Suite

```bash
HALO2_SOLIDITY_RUN_IVC_BENCH=1 \
cargo test --release --features evm,truncated-challenges,fewer-point-sets,rust-verifier-trace \
  --test ivc_keccak_solidity -- --nocapture
```

### Full Local Stress Run

```bash
cargo test --release --workspace --all-features --all-targets \
  -- --include-ignored --nocapture
```

## Implementation Mapping

Existing coverage already includes a healthy baseline:

- Positive Poseidon fixture verification.
- Public-input mutation for basic cases.
- Proof bit-flip rejection.
- Separate VK pinning and VK payload mutation.
- Pinned quotient dependency checks.
- Malformed calldata rejection.
- EIP-2537 constructor smoke tests.
- Production render checks for `external view` and no gas logs.
- Native/Solidity trace equivalence.
- Scalar canonicality tests for proof scalars.
- Noncanonical and off-curve G1 rejection.
- Slow IVC accumulator packing rejection in the bench path.

The highest-value additions are:

- Broader per-slot public-input mutations.
- Lighter accumulator canonicality fixtures that do not require the full IVC
  bench.
- Precompile failure and return-size harnesses.
- Category-aware proof-layout mutation helpers.
- Wrapper tests that bind application-specific state.

## Definition of Done

A verifier profile is considered covered when:

1. At least one valid native proof verifies in every supported generated
   Solidity mode for that profile.
2. Native and Solidity trace outputs match for the transcript, quotient, PCS,
   and final pairing checkpoints exposed by the profile.
3. Every declared proof scalar, G1 point, public-input word, VK section,
   quotient section, and accumulator word has at least one negative mutation
   test.
4. ABI canonicality tests reject alternate but Solidity-decodable calldata
   forms that the hand-rolled parser is not intended to accept.
5. EIP-2537 integration tests cover call failure, short return, semantic false
   return, and valid precompile behavior.
6. Production artifacts compile with the pinned compiler/EVM target and stay
   within size limits.
7. Raw verifier NatSpec documents that application contracts must bind
   protocol semantics, and wrapper tests prove those bindings reject replay or
   wrong-context proofs.

