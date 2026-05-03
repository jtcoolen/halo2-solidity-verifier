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

## Layered Verifier-Assurance Addendum

The repo-specific strategy above should be implemented as a layered assurance
suite:

- Cheap deterministic tests on every PR.
- Fuzz and property tests nightly.
- Mutation testing weekly and before release.
- Small formal models for the highest-risk parser, transcript, state, and
  precompile boundaries.

The core invariant for every verifier integration is:

```text
For any accepted proof, the contract's interpretation of the statement must
equal the circuit/protocol's interpretation of the statement, and all
protocol-critical state transitions must remain live under long-running usage.
```

This catches recurring audit failures: public-input mismatches,
non-canonical inputs, wrong VK selection, subgroup mistakes, verifier upgrade
risks, rollovers, and underconstrained circuit helpers. PrivacyBoost's
tree-number issue is the canonical liveness example: the circuit constrained
tree numbers as small sparse-array indices while the contract treated them as
15-bit global identifiers, eventually halting deposits, transfers,
withdrawals, and forced withdrawals after enough rollovers.

### Deterministic Negative Tests: Invalid Things Must Fail

Create a reusable negative suite, for example `VerifierNegative.rs` for this
repo and `VerifierNegative.t.sol` for downstream Solidity wrappers.

#### Proof And Public Input Mutations

For every valid proof fixture:

| Mutation | Expected result |
| --- | --- |
| Flip every byte of proof once. | Reject. |
| Flip every public input once. | Reject. |
| Replace a public input with `x + q`. | Reject or canonicalize consistently. |
| Add extra public inputs. | Reject. |
| Remove one public input. | Reject. |
| Reorder public inputs. | Reject. |
| Replace a used root with known-but-unused root. | Reject if canonical encoding is required. |
| Add trailing unused calldata words. | Reject. |
| Use duplicate `(treeNumber, root)` pairs. | Reject unless explicitly allowed. |
| Use wrong verifier/VK for same public-input count. | Reject. |

This targets bugs like missing base verifier length checks, where
`publicInputs.length + 1 == vk.icLen` should be enforced in the base verifier
itself, not only in callers. It also targets non-canonical commitments such as
`x` and `x + q` hashing to the same field element while events and relayer
tooling see different calldata.

#### EC And Pairing Edge Cases

Add fixtures for:

| Input | Expected result |
| --- | --- |
| G1/G2 point not on curve. | Reject. |
| G2 point not in subgroup. | Reject or prove impossible by circuit-level constraints. |
| Identity point where not allowed. | Reject. |
| Point at infinity in every EC operation path. | Correctly handled or rejected. |
| Zero denominator or inverse-of-zero path. | Reject or document defined behavior. |
| Scalars equal to `0`, `1`, `r-1`, `r`, `r+1`, `2^256-1`. | Correct accept/reject. |

This suite targets findings such as missing subgroup checks for G2 points,
lack of zero checks in inverse computation, and debug-only assertions that
disappear in release mode.

### Differential Tests: Native Verifier Versus Solidity/Yul

For each proof system, keep a reference verifier in the language where the
proof was generated.

For every generated fixture:

```text
nativeVerify(vk, proof, publicInputs)
    == solidityVerify(vk, proof, publicInputs)
```

Run this over:

1. Valid fixtures generated by the prover.
2. Invalid fixtures generated by mutating proof bytes.
3. Invalid fixtures generated by mutating public inputs.
4. Boundary fixtures for field/scalar values.
5. ABI-malformed fixtures.

This catches ABI packing errors, endianness mistakes, point encoding
differences, precompile return-length mismatches, and precompile return-value
mismatches.

For precompiles or low-level libraries, add differential tests against
known-good implementations:

```text
evmPairing(input) == arkworksPairing(input)
evmModExp(input) == bigintReferenceModExp(input)
solidityPoseidon(input) == nativePoseidon(input)
publicInputBuilderSolidity(tx) == publicInputBuilderRust(tx)
```

Worldcoin's Groth16 verifier audit is an example of this layer: optimized
Solidity assembly, compressed proof handling, constants, and pairing
precompile usage are exactly where differential tests pay off.

### Property Fuzzing

Use Foundry invariant tests for Solidity wrappers and `cargo-fuzz` or
`proptest` for Rust/native verifier code.

#### Solidity Fuzz Harness

Expose a harness with helpers such as:

```solidity
function tryVerify(bytes calldata proof, uint256[] calldata inputs) external returns (bool);
function buildPublicInputs(Request calldata r) external view returns (uint256[] memory);
function verifyAndApply(Request calldata r, bytes calldata proof) external;
```

Fuzz these properties:

| Property | Example assertion |
| --- | --- |
| No malformed input panics unexpectedly. | Only expected custom errors. |
| No accepted public input is `>= field modulus`. | `forall pi: pi < q`. |
| No accepted wrong-length public inputs. | `inputs.length == vk.icLen - 1`. |
| Canonical calldata only. | Trailing, duplicate, and unused data rejected. |
| Verifier failure has correct error class. | Field error differs from precompile failure where the API exposes that. |
| Upgrade cannot disable forced exit immediately. | Timelock or immutability invariant. |

#### Long-Horizon State Fuzzing

Run randomized action sequences as invariant tests:

```text
deposit -> epoch -> transfer -> withdrawal -> rollover
    -> forced withdrawal -> cancel -> upgrade attempt
```

Important invariants:

| Invariant | Why |
| --- | --- |
| After N rollovers, proofs are still constructible for all supported flows. | Catches tree-number/domain-size mismatches. |
| Forced withdrawal remains executable under relay censorship. | Catches exit-liveness bugs. |
| Revoked keys stop working at the intended boundary. | Catches lazy snapshot/key-race bugs. |
| Verifier upgrades cannot immediately brick exits. | Catches governance liveness risk. |
| Nullifiers cannot be both pending-forced-exit and spent elsewhere. | Catches relay race issues. |

PrivacyBoost had multiple liveness-adjacent issues around forced withdrawals,
verifier upgrades, requester-only execution, lazy auth snapshots, and
nullifier spending during the forced-withdrawal delay.

### Circuit-Level Negative Tests

For every reusable circuit gadget, add positive and negative tests.

| Gadget | Negative tests |
| --- | --- |
| `assert_equal` | Two unequal values must fail. |
| `is_zero` / inverse | `(0,0)` division must fail unless defined. |
| range check | `max`, `max+1`, `q-1`, `q`, `q+1`. |
| `num_to_bits` | Reconstruct bits to original value. |
| selector / one-hot | All-zero and multi-one vectors fail. |
| lookup / shuffle | Wrong multiplicity fails. |
| EC load | Off-curve and infinity cases fail. |
| scalar multiplication | Unreduced scalar fails or reduces explicitly. |
| KZG/IPA accumulator | Empty accumulator vector fails. |

Axiom's Halo2 audit is a strong template: it found underconstrained circuits,
debug-only validations, `0/0` division, point-at-infinity issues, non-reduced
field elements, empty KZG accumulators, and even `assert_equal` comparing a
value to itself. Basic unit tests and negative tests would have prevented
several of those findings.

For proof libraries, mirror Anza's recommendation: every `verify()` path needs
a test where the final verification equation fails. Without that negative
test, a suite may not detect an implementation that skips the final check.

### Metamorphic Canonicality Tests

These tests are especially useful for SNARK/STARK verifier wrappers:

```text
verify(proof, inputs) == false
for inputs' where inputs'[i] = inputs[i] + q

hashPublicInputs(inputs) != hashPublicInputs(inputs with trailing zeros)

buildPublicInputs(request) == buildPublicInputs(decode(encode(request)))

decode(encode(x)) == x
encode(decode(bytes)) == bytes only for canonical bytes
```

For Merkle, STARK, and STARK-like proof systems:

```text
leafHash(x) must never equal branchHash(y, z)
hash([a,b,c]) must not equal hash([hash(a,b),c])
inclusionProof(k) and nonInclusionProof(k) cannot both verify under same root
```

Scroll's zkTrie audit is a good example: missing leaf/branch domain
separation enabled proof forgery, including contradictory inclusion and
non-inclusion proofs under the same root. It also found missing proof
validation that could crash the verifier, and recommended fuzzing proof
verification routines.

### Mutation Testing

Run mutation testing weekly or before release.

For Solidity:

```bash
slither-mutate src --test-cmd "forge test" --ignore-dirs "test,script,mocks"
```

Focus mutations on:

| Mutation | Must be caught |
| --- | --- |
| Remove `input < q`. | Yes. |
| Remove `publicInputs.length` check. | Yes. |
| Replace `require(success)` after precompile with no-op. | Yes. |
| Remove subgroup check. | Yes. |
| Change VK selector key. | Yes. |
| Remove event emission for verifier upgrade. | Yes. |
| Comment out forced-exit timelock. | Yes. |

For Rust:

```bash
cargo mutants
cargo test
cargo llvm-cov --html
```

Require that mutants in verifier checks, transcript construction, range
checks, subgroup checks, and serialization are killed.

High-value mutators for this repository:

| Mutation | Should be caught by |
| --- | --- |
| Remove public-input `< r` check. | Canonicality tests. |
| Replace `< r` with `<= r`. | Boundary tests. |
| Remove point-on-curve check. | Invalid point tests. |
| Remove subgroup check. | Subgroup tests. |
| Ignore pairing output. | Corrupted proof tests. |
| Ignore `staticcall` success. | Precompile mock tests. |
| Skip one transcript absorption. | Transcript coverage tests. |
| Replace challenge with zero. | Challenge tests and invalid proof tests. |
| Remove proof length check. | Calldata tests. |
| Change one proof offset by 32 bytes. | Layout tests. |
| Remove `inv(0)` check. | Algebra tests. |
| Allow empty accumulator. | PCS tests. |
| Replace `&&` with `||` in validation. | Negative tests. |
| Remove optional component consistency check. | LogUp tests. |

Trail of Bits describes mutation testing as changing target lines and rerunning
the test suite; surviving mutants indicate coverage gaps. The practical metric
is simple: if deleting a verifier-critical check does not break a test, that
test class is missing.

### Lightweight Formal Methods

Do not start by trying to formally verify the whole verifier. First verify the
small reusable helpers where one bug is catastrophic.

#### Scribble, Foundry, Echidna, And Runtime Annotations

Annotate verifier wrappers with executable invariants:

```solidity
/// if_succeeds {:msg "public input length"} publicInputs.length + 1 == vk.icLen;
/// if_succeeds {:msg "field canonical"} forall(uint i in 0...publicInputs.length) publicInputs[i] < Q;
/// if_succeeds {:msg "vk shape"} vk.circuitId == expectedCircuitId;
/// if_succeeds {:msg "forced exit verifier not disabled"} forcedVerifier != address(0);
```

Best targets:

| Contract area | Property |
| --- | --- |
| Public input builder | Solidity output equals reference output. |
| Verifier registry | VK identity includes full circuit shape/version. |
| Upgrade functions | Exits cannot be disabled without delay. |
| Deposit/epoch/withdraw flows | Only canonical encodings accepted. |
| Forced withdrawal | Eventually executable unless user cancels or proof is invalid. |

#### Halmos Or SMTChecker

Use symbolic execution for small bounded properties:

```text
No accepted input has publicInputs[i] >= q.
No valid call reaches pairing precompile with malformed memory length.
No call to _verifyProof occurs unless publicInputs.length + 1 == vk.icLen.
Digest builder is injective for bounded request fields.
Withdrawal slot list is strictly sorted and unique.
```

This is lightweight because it does not prove SNARK soundness; it proves the
wrapper cannot violate its own validation rules.

#### Lean Transcript Checker

Model transcript structure, not the whole cryptography.

For every verifier, extract:

```text
domain separators
absorbed public inputs
absorbed commitments
challenge squeezes
MSM equations / final check terms
```

Then prove or check:

```text
Every prover-controlled value used with challenge c was absorbed before c.
Every public input is absorbed before any challenge depending on the statement.
No challenge label is reused across incompatible proof contexts.
```

Trail of Bits used this style in the Token-2022 audit: an extractor produced
transcript traces, challenge labels, and MSM structures, then Lean checked
whether prover-controlled values appeared too late relative to challenge
derivation.

#### TLA+, Alloy, Or Tamarin State Models

Use protocol-state models for liveness and authorization, not proof-system
math.

Model:

```text
trees, treeNumber, knownRoots
auth keys, revocation, snapshots
nullifiers, pending forced withdrawals, spent nullifiers
verifier upgrades, timelocks
relay censorship
```

Check:

```text
ForcedExitEventuallyPossible
NoSpentNullifierCanBeForcedWithdrawn
NoForcedExitCanBePermanentlyBlockedByRequesterFrontRun
VerifierUpgradeCannotImmediatelyDisableExit
RolloverNeverMakesAllProofsUnsatisfiable
```

Trail of Bits used Tamarin for state-machine properties in Token-2022,
including authorization and state-transition correctness. Symbolic models are
not fine-grained enough to prove ZK soundness, but they are useful for safety
and protocol-state properties.

#### Helper-Level Formal Specs

Good targets for SMT, Dafny, Why3, or Lean:

| Helper | Property |
| --- | --- |
| `inv(x)` | If returns `y`, then `x != 0 && x*y == 1 mod r`. |
| `batch_invert(xs)` | Rejects any zero or returns valid inverses for all nonzero inputs. |
| `lagrange(i, zeta)` | Correct at `zeta` in domain and outside domain. |
| `pow_mod` wrapper | Result matches mathematical exponentiation or reverts on failed precompile. |
| `validate_scalar` | Accepts iff `0 <= x < r`. |
| `validate_g1/g2` | Accepts iff canonical, on curve, subgroup-valid, and infinity policy satisfied. |
| `parse_proof` | Exact proof length; every field read once; no overlap; no out-of-bounds. |
| `transcript_absorb` | Transcript is injectively encoded with length/domain tags. |
| `pairing_wrapper` | Returns true iff call succeeds, returndata is 32 bytes, and result word is 1. |
| `success flag` | Once false, never becomes true again. |

Linea's Dafny appendix is a useful model: it did not prove the whole PLONK
verifier, but it verified targeted properties such as termination,
overflow/underflow, immutable inputs, state modification, and that
`state_success` could not be reset from false back to true.

### Core Verifier Regression Suite

For every generated verifier:

| Test | Expected |
| --- | --- |
| Reference prover valid proof. | `verify == true`. |
| Reference verifier accepts but contract rejects. | Fail test. |
| Contract accepts but reference verifier rejects. | Critical failure. |
| Flip one bit in every proof scalar/point/evaluation. | Reject. |
| Swap two proof fields. | Reject. |
| Replace each commitment with another valid curve point. | Reject. |
| Use valid proof with wrong public input. | Reject. |
| Use valid proof with wrong VK/circuit ID/domain size. | Reject. |

This catches pairing-result ignored bugs, skipped opening checks, and wrong
transcript/layout wiring.

#### Calldata And Proof Layout Tests

Run these against every entry point:

| Mutation | Expected |
| --- | --- |
| Proof length `expected - 1`. | Revert or false. |
| Proof length `expected + 1`. | Revert or false. |
| Extra trailing bytes. | Reject unless explicitly allowed and transcript-bound. |
| Truncated public input array. | Reject. |
| Extra public inputs. | Reject. |
| Dynamic ABI overlap or malformed offsets. | Reject. |
| Zero public inputs when nonzero required. | Reject. |
| Zero or multiple custom gate commitments, if variants exist. | Supported or explicitly rejected. |

This directly targets proof-size and calldata-overlap issues such as Linea's
missing proof length check.

### Field, Scalar, And Curve Validation Tests

#### Public Input Canonicality

For each public input slot:

| Value | Expected |
| --- | --- |
| `0`. | Accepted only if semantically valid. |
| `r - 1`. | Accepted only if semantically valid. |
| `r`. | Reject. |
| `r + 1`. | Reject. |
| `2^256 - 1`. | Reject. |
| `x + r` for a valid `x`. | Reject. |
| Non-canonical encoding of same semantic value. | Reject. |

Linea's audit specifically recommends public inputs be checked `< r_mod`.

#### Proof Scalar Canonicality

For every scalar proof field:

| Mutation | Expected |
| --- | --- |
| `s + r`. | Reject. |
| `r`. | Reject. |
| `2^256 - 1`. | Reject. |
| Zero where denominator/challenge must be nonzero. | Reject. |

This catches scalar-multiplication malleability where ECMUL accepts a scalar
modulo the group order unless the verifier checks it itself.

#### G1/G2 Point Validation

For each proof/VK point:

| Mutation | Expected |
| --- | --- |
| `(0,0)` / infinity encoding. | Reject unless explicitly allowed. |
| `x >= p`. | Reject. |
| `y >= p`. | Reject. |
| Valid field elements not on curve. | Reject. |
| Wrong subgroup point, if curve has cofactors. | Reject. |
| Swapped `x,y`. | Reject. |
| Valid point from another proof. | Reject. |
| Compressed point with invalid sign bit / non-residue `x`. | Reject. |

Do not rely only on later precompile failure for these in wrappers. Linea's
audit recommended explicit field, group, and curve-point checks for proof
elements.

### Precompile-Wrapper Tests

Wrap ECADD, ECMUL/G1MSM, pairing, modexp, SHA/KZG/IPA/FRI helpers behind small
internal functions and test them in isolation with a test-only mock or
precompile adapter.

| Mock behavior | Expected |
| --- | --- |
| `staticcall` fails. | Revert or false. |
| `staticcall` succeeds but returns no data. | Revert or false. |
| `staticcall` succeeds but returns 0 for pairing. | Reject. |
| `staticcall` succeeds and returns 1 for pairing. | Continue. |
| Returndata shorter than 32 bytes. | Reject. |
| Returndata longer than 32 bytes. | Reject or strictly decode first word by spec. |
| Stale memory prefilled with `1`, then failed call. | Reject. |
| Low gas to wrapper. | Reject without using stale return buffer. |

This would catch missing pairing-result checks and stale-memory/staticcall
issues where checking only call success, or reusing an old output buffer, lets
invalid proofs pass.

### Algebra Edge-Case Tests

#### Inversion And Batch Inversion

| Input | Expected |
| --- | --- |
| `inv(0)`. | Revert. |
| `inv(x) * x mod r == 1` for random nonzero `x`. | Pass. |
| Batch inversion with all nonzero elements. | Each `a[i] * inv[i] == 1`. |
| Batch inversion with one zero at every position. | Revert or documented zero-handling. |
| Empty array. | Reject unless explicitly supported. |

Linea found both "inverse of zero returns zero" and batch inversion failures
when an element becomes zero.

#### Roots Of Unity And Lagrange Evaluation

For domain `H = {omega^i}`:

| Test | Expected |
| --- | --- |
| `L_i(omega^i)`. | `1`. |
| `L_i(omega^j), i != j`. | `0`. |
| `zeta = 1`. | Special-case handled. |
| `zeta = omega^i` for every `i`. | Special-case handled. |
| Random `zeta` not in `H`. | Matches reference implementation. |
| `Z_H(zeta) == 0`. | No division by zero. |

This catches root-of-unity Lagrange bugs where an efficient formula returns an
incorrect value at domain points.

### Fiat-Shamir Transcript Tests

Create an independent transcript oracle in Rust, Go, or Python and generate
fixed test vectors.

For each transcript round:

| Test | Expected |
| --- | --- |
| Changing any public input changes all later challenges. | Yes. |
| Changing any proof commitment changes later challenges. | Yes. |
| Changing any VK/SRS/domain/circuit digest changes challenges. | Yes. |
| Changing chain ID / verifier address / app domain changes challenges. | Yes. |
| Reordering fields changes challenges. | Yes. |
| Omitting optional component length/tag changes challenges. | Yes. |
| Challenge sampling never uses modulo reduction with unacceptable bias. | Rejection sampling or proof of acceptable bias. |

Scroll flagged omitted curve parameters from Fiat-Shamir and recommends
including all public parameters in the transform. Stwo-Cairo had a
high-severity proof-forgery issue because public memory ID values were not
mixed into the Fiat-Shamir channel before interaction challenges were drawn.

A powerful mutation test is: delete one transcript absorption line and require
at least one test to fail. If no test fails, that field was not covered by the
transcript tests.

### PCS, Pairing, FRI, And Merkle Proof Tests

For SNARK/KZG/IPA:

| Mutation | Expected |
| --- | --- |
| Replace `Wz`. | Reject. |
| Replace `Wzomega`. | Reject. |
| Replace one claimed evaluation. | Reject. |
| Replace one batched commitment. | Reject. |
| Empty accumulator vector. | Reject. |
| Duplicate accumulator. | Reject unless intended. |
| Remove one opening from batch. | Reject. |

For STARK/FRI/Merkle:

| Mutation | Expected |
| --- | --- |
| Shorten queried values array. | Reject before loop. |
| Add extra queried values. | Reject. |
| Wrong Merkle sibling. | Reject. |
| Wrong query position. | Reject. |
| Wrong FRI folded value. | Reject. |
| Empty FRI layer vector. | Reject. |
| Mismatched number of decommitments. | Reject. |
| Wrong preprocessed trace/root. | Reject. |

Stwo-Cairo's audit explicitly recommends validating prover-supplied data
before it shapes verifier execution, including `zip` length checks. A shorter
prover array must never skip Merkle verification.

### Recursive Verifier And Circuit-Specific Adversarial Tests

For Halo2, Circom, and STARK recursive verifiers, happy-path proofs are not
enough. Add malicious witness tests.

#### Constraint Soundness Tests

For each gadget, build a valid witness, then mutate one witness-only value:

| Gadget class | Mutations |
| --- | --- |
| Boolean flags | Set to `2`, `-1`, or a random field element. |
| Range flags | Set `is_lt=false` for small value, `is_lt=true` for large value. |
| Lookup selector | Set unused or extra component. |
| Memory ID / table ID | Alter ID after transcript challenge. |
| Error/success selector | Make both success and error paths satisfiable. |
| Opcode selector | Mismatch opcode and execution state. |
| Gas/counter witness | Undercount or overcount by 1. |
| Public IO aggregate | Compute but do not expose/constrain. |

Scroll's findings show why: several high-impact bugs came from
underconstrained witness values, nondeterministic execution, and success/error
state overlap.

#### Determinacy Tests

For each gadget or opcode:

```text
Given the same public inputs and pre-state, there must not exist two
satisfying witnesses with different post-state/output.
```

Implementation options:

1. For small gadgets, brute-force all inputs over a small field/model.
2. For medium gadgets, use SMT over bounded integers.
3. For full circuits, run mutated-witness negative tests with
   `MockProver`/constraint checker.

Trail of Bits specifically recommended determinacy testing for gadgets that
constrain nondeterministic witnesses.

### Static Lints And Semgrep Rules

Add rules that fail CI on dangerous verifier patterns:

| Rule | Pattern |
| --- | --- |
| Unchecked precompile. | `pop(staticcall(...))`. |
| Pairing result ignored. | Pairing precompile call without checking returned word is 1. |
| Stale return buffer. | Output buffer reused without zeroing/checking returndata size. |
| Unsafe modulo inverse. | `pow(x, p-2)` without prior `x != 0`. |
| Public input reduction. | `input % r` instead of `require(input < r)`. |
| Scalar multiplication without scalar range check. | ECMUL/G1MSM called with unconstrained scalar. |
| Proof-driven `zip`. | `zip(proof_array)` without length equality assertion. |
| Optional component sum. | `Option::Some(sum)` allowed when component claim is `None`. |
| Zero-padding hash. | Hash pads without length/tag/domain separator. |
| Debug-only invariant. | `debug_assert` or release-disabled `assert` for critical checks. |
| TODO/FIXME in verifier path. | No unresolved security-relevant TODOs. |

Scroll used Semgrep to search for variants after identifying vulnerable
patterns, and its automated testing focused on dangerous Halo2-specific/API
patterns.

### CI Release Gate

Use this schedule:

```text
Every PR:
  forge test
  forge test --fuzz-runs 10000
  native unit tests
  public-input differential tests
  negative proof fixtures
  static analysis: slither, semgrep, clippy, cargo-audit

Nightly:
  forge invariant --runs high
  echidna/medusa campaign
  cargo fuzz / go fuzz proof parsers
  mutation testing subset
  long-horizon rollover simulation

Pre-release:
  full mutation testing
  native-vs-EVM verifier differential corpus
  Lean transcript extraction/check
  TLA+/Alloy/Tamarin state-machine checks
  regenerated verifier bytecode hash check
```

Minimum release blockers:

1. 100% of proof fields have at least one corruption test.
2. 100% of public inputs have canonicality tests.
3. Every precompile wrapper has failure/stale-memory tests.
4. Every transcript field has an omission mutation that fails tests.
5. Every proof-provided array/option has length/consistency tests.
6. Every generated offset is checked against a single layout manifest.
7. Every helper with division/inversion has zero tests and a small formal spec.

### Bug-To-Test Mapping

| Bug class | Best detector |
| --- | --- |
| Missing public input length check. | Unit and mutation test. |
| Non-canonical field input. | Fuzz and metamorphic test. |
| Wrong VK/circuit shape. | Differential and registry invariant. |
| ABI malleability. | Calldata fuzz and canonical decode/encode property. |
| Missing subgroup/on-curve check. | EC negative fixtures. |
| Transcript omission. | Lean transcript checker. |
| Empty accumulator accepted. | Negative proof test. |
| Underconstrained equality/range gadget. | Circuit negative tests. |
| Tree rollover liveness failure. | Long-horizon invariant fuzz. |
| Forced withdrawal can be blocked. | TLA+/Alloy state model and Foundry invariant. |
| Merkle proof forgery. | Metamorphic inclusion/non-inclusion tests. |
| Panic on malformed proof. | Fuzz proof parser/verifier. |
| Removed validation not caught by tests. | Mutation testing. |

The highest ROI is negative tests, differential tests, mutation testing, and
one lightweight transcript/state model. That combination catches a large
fraction of verifier failures in the audit corpus without requiring full
formal verification of the proof system.
