# Halo2/Midnight Solidity Verifier Specification And Architecture

This document is the implementation specification for this repository's
Halo2/Midnight Solidity verifier generator. It is intended to be complete
enough for a competent implementer to rebuild the verifier from scratch and
produce byte-compatible Solidity-facing proof verification semantics.

The normative target is the current generator in:

- `src/codegen/generator.rs`
- `src/codegen/protocol.rs`
- `src/codegen/util.rs`
- `src/codegen/pcs.rs`
- `src/codegen/evaluator.rs`
- `src/codegen/quotient/mod.rs`
- `templates/Halo2Verifier.sol`
- `templates/Halo2VerifyingKey.sol`
- `templates/Halo2QuotientEvaluator.sol`
- `templates/QuotientNumeratorBlock.yul`

Existing focused notes remain useful, especially `docs/MEMORY_LAYOUT.md` and
`docs/QUOTIENT_NUMERATOR_EVALUATOR.md`. For a template-by-template map from
Askama Solidity/Yul sections to the Midfall Rust verifier, see
`docs/ASKAMA_TEMPLATE_RUST_MAPPING.md`. This document consolidates the full
verifier contract, proof format, transcript, algebra, KZG opening check, and
split-artifact architecture.

## Midfall Comment Corpus And Porting Map

`docs/MIDFALL_PROOFS_COMMENT_CORPUS.md` preserves every Rust comment block from
`../midfall/proofs/src/**/*.rs`, grouped by upstream file and line span. Local
source and template comments intentionally adapt only the comments that map to
this generator:

- Transcript comments from `transcript/mod.rs` and `transcript/implementors.rs`
  map to `src/transcript.rs` and `templates/Halo2Verifier.sol`.
- PLONK verifier-flow comments from `plonk/verifier.rs` map to
  `src/codegen/protocol.rs`, verifier NatSpec, and proof-layout sections below.
- Identity and linearization comments from `plonk/mod.rs` and
  `plonk/linearization/verifier.rs` map to `templates/QuotientNumeratorBlock.yul`
  and `docs/QUOTIENT_NUMERATOR_EVALUATOR.md`.
- Askama template structure, generated Solidity/Yul sections, and optimization
  tradeoffs are mapped in `docs/ASKAMA_TEMPLATE_RUST_MAPPING.md`.
- KZG multi-open, dummy-query, point-set sorting, MSM, and pairing comments from
  `poly/kzg/{mod.rs,msm.rs,utils.rs}` map to `src/codegen/pcs.rs`.
- LogUp, permutation, and trash comments map to the quotient evaluator docs and
  generated Yul comments; broader circuit/dev/floor-planning comments remain in
  the corpus because they are not verifier behavior ported by this repository.

## 1. Scope

The generator emits Solidity verifiers for `midnight-proofs` / Midfall Halo2
proofs using:

- BLS12-381 KZG commitments.
- The Midnight/Midfall Keccak transcript.
- The Midnight PLONKish verifier shape, including gates, permutation, LogUp
  lookups, trash arguments, simple selectors, and KZG multi-prepare.
- Solidity `^0.8.24` with Cancun `MCOPY`.
- EIP-2537 BLS12-381 precompiles:
  - `0x0b`: G1ADD.
  - `0x0c`: G1MSM.
  - `0x0f`: PAIRING_CHECK.
- EVM modexp precompile `0x05` for scalar inversions.

Supported execution target: an Ethereum-compatible Cancun-or-newer EVM with
`MCOPY` and Prague/EIP-2537 BLS12-381 precompiles at exactly the addresses
above, implementing the EIP-2537 input encodings, subgroup checks, return sizes,
and gas schedule. The repository CI/dev runner exercises this target through
Prague-spec `revm`; deployers on L2s, forks, or alt-EVMs must run the same
precompile conformance tests against their target chain before treating the
verifier as production-safe.

The generated verifier is not a generic reusable verifier. It is
circuit-specialized. Circuit metadata, proof read order, quotient identity
program, VK payload, memory layout, and constant offsets are generated together
for one `VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>`.

### 1.1 Supported Protocol Shape

The current generator intentionally accepts only this Midfall shape:

- Exactly one proof.
- At least one advice column.
- Exactly two instance columns in the constraint system.
- Exactly one committed instance column.
- Exactly one non-committed public-input column.
- All instance queries must be at `Rotation::cur()`.
- KZG over BLS12-381.
- G1 proof elements are supplied to Solidity in EIP-2537 padded uncompressed
  form, not in the native 48-byte compressed proof form.
- If a public KZG accumulator is enabled, it must use 7 limbs of 56 bits per
  BLS12-381 base-field coordinate.

`SolidityGenerator::try_new` rejects unsupported instance-column shapes and
rotated instance queries. `SolidityGenerator::new` panics on those same errors.

### 1.2 Non-Goals

The generated verifier does not:

- Bind application semantics to public inputs. Application contracts must check
  program identifiers, state roots, expected outputs, authorization, and domain
  separation separately.
- Accept arbitrary VKs at runtime.
- Verify multiple proofs in one call.
- Parse native compressed Midnight proof bytes on chain.
- Decompress BLS12-381 points on chain.
- Provide a production audit guarantee. The repository README still marks the
  verifier as unaudited.

### 1.3 Genericity Boundary

There are two different notions of "generic" in this codebase:

1. A reusable verifier binary that accepts arbitrary verifying keys at runtime.
2. A generated verifier whose compact quotient VM can interpret a range of
   generated quotient bytecode programs stored in the VK payload.

The deployed artifact is not the first kind. Even in separate-VK mode, the
verifier pins `Halo2VerifyingKey` by exact runtime length and codehash and then
loads the pinned payload bytes with `extcodecopy`. The deployed VK runtime has a
one-byte `INVALID` prefix so direct calls cannot execute the data payload as EVM
code; the verifier copies from runtime byte `1`. The proof layout, query order,
evaluation counts, memory layout, selector buckets, lookup chunking,
permutation/trash shape, quotient frame length, and PCS point-set plan are all
generated from one `VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>`.

Before VM-case specialization, the quotient interpreter was closer to the
second kind: it rendered every opcode case supported by the selected physical
encoding. If a different pinned VK payload had contained a different valid
quotient bytecode program using another supported opcode, the interpreter
itself would probably not have been the blocker. The surrounding verifier still
would have been VK/generated-shape-specific for the reasons above.

After VM-case specialization, the interpreter is also VK-specialized: codegen
scans the finalized quotient bytecode and renders only the opcode and memory
token cases that can occur in that pinned program. This shrinks deployed
runtime while preserving fail-closed behavior for malformed bytecode: any
unrendered opcode, reserved opcode, invalid token, or invalid native callback
index reaches `revert(0, 0)`.

If a future deployment requirement is "one verifier binary for many VKs with
the same high-level CS parameters", this optimization must become optional or
be disabled for that profile. Such a generic profile would also need to revisit
VK/evaluator codehash pinning, proof-layout constants, native callbacks, and
any generated Yul that is derived from a single identity stream rather than
from runtime VK data.

## 2. Terminology

This repository follows `midnight_curves` naming, where `Fq` is used as the
native scalar field type for the BLS12-381 proof system. In this document:

- `Fr` means the BLS12-381 scalar field used for proof scalars and all PLONK
  algebra.
- `r` means the `Fr` modulus:
  `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
- `Fp` means the BLS12-381 base field used for G1/G2 coordinates.
- `p` means the BLS12-381 base-field modulus.
- `n = 2^k` means the evaluation-domain size.
- `omega` means the `n`-th root of unity from the VK domain.
- `rotation_last = -(blinding_factors + 1)`.
- `G1` points use EIP-2537 padded uncompressed layout:
  `x_hi || x_lo || y_hi || y_lo`, four 32-byte words.
- `G2` points use EIP-2537 padded Fp2 layout, eight 32-byte words:
  `x.c0_hi, x.c0_lo, x.c1_hi, x.c1_lo, y.c0_hi, y.c0_lo, y.c1_hi,
  y.c1_lo`.

All Solidity field arithmetic over `Fr` is performed with `addmod` and
`mulmod` modulo `r`. Scalar inversions use modexp `x^(r - 2) mod r`.

## 3. Artifact Architecture

The generator can emit three contracts:

- `Halo2Verifier`: the proof verifier and public ABI.
- `Halo2VerifyingKey`: a data contract whose runtime bytecode is
  `INVALID || VK payload`.
- `Halo2QuotientEvaluator`: an optional split helper for quotient numerator
  reconstruction.

### 3.1 Embedded Mode

`SolidityGenerator::render()` emits one `Halo2Verifier` contract with the VK
payload embedded as `mstore` constants. There is no external VK dependency.

### 3.2 Separate VK Mode

`SolidityGenerator::render_separately()` emits:

- `Halo2Verifier`.
- `Halo2VerifyingKey`.

The VK contract constructor writes an unconditional `INVALID` byte followed by
the payload into memory and returns that prefixed runtime bytecode. The
verifier:

1. Stores the expected VK payload length.
2. Stores the expected VK runtime length (`payload length + 1`).
3. Stores the expected VK runtime `keccak256` codehash over the prefixed
   runtime.
4. Accepts the VK address in the constructor.
5. Checks length and codehash in the constructor and again per proof.
6. Loads the VK payload using `extcodecopy(vk, VK_MPTR, 1, vk_payload_len)`.

The separate VK is a code-size split, not a new trust boundary. The generated
verifier accepts exactly the pinned runtime bytes. Because some deployments may
target forks with weaker code-immutability assumptions, `verifyProof` re-checks
the pinned length/codehash before copying payload bytes.

### 3.3 Split Quotient Mode

For large circuits, quotient numerator reconstruction is the largest generated
arithmetic block. The default separated VK render keeps that block inside
`Halo2Verifier` when the merged verifier remains below EIP-170. The generator
can still split it into `Halo2QuotientEvaluator` for larger circuits or
bytecode experiments.

Split quotient flow:

1. Render the quotient evaluator with `render_quotient_evaluator()`.
2. Compile and deploy it.
3. Compute its deployed runtime length and codehash.
4. Render the verifier and VK with
   `render_separately_with_pinned_quotient(expected_len, expected_codehash)`.
5. Deploy the VK.
6. Deploy the verifier with the VK address and quotient evaluator address.

The verifier pins the quotient evaluator exactly like the VK. The quotient
evaluator is correctness-critical; an unpinned evaluator could change the
statement being checked.

The quotient evaluator has only a fallback entry point. It receives a raw
memory frame, not normal ABI arguments:

```text
calldata[0..QUOTIENT_FRAME_LEN)
  == verifier_memory[QUOTIENT_FRAME_BASE..QUOTIENT_FRAME_BASE + QUOTIENT_FRAME_LEN)
```

It returns:

```text
word 0: QUOTIENT_MAGIC = 0x51554556414c0001
word 1: linearization_expected_eval
word 2..: one selector accumulator scalar per simple selector
```

The verifier checks the return size and magic before using the output.

## 4. Public Solidity ABI

The verifier exposes:

```solidity
function verifyProof(bytes calldata proof, uint256[] calldata instances)
    external
    view
    returns (bool);
```

Trace builds, and artifacts rendered through the explicit
`render_with_gas_checkpoints*` profiling helpers, drop `view` because they emit
logs. Enabling the `solidity-gas-checkpoints` Cargo feature alone does not make
default renders non-view; checkpoint logging in default renders also requires
`solidity-trace`.

The function selector is:

```text
verifyProof(bytes,uint256[]) = 0x1e8e1e13
```

The verifier is success-or-revert:

- Valid proof: returns `true`.
- Malformed calldata, invalid scalar, invalid point, wrong dependency code,
  failed precompile, or failed pairing: reverts, usually with empty data.

### 4.1 ABI Layout Requirements

The verifier hand-parses calldata and requires the canonical two-argument ABI
layout:

```text
0x00..0x03: function selector
0x04..0x23: proof offset, must be 0x40
0x24..0x43: instances offset, must be 0x40 + 0x20 + proof_len
0x44..0x63: proof length, must equal generated proof_len
0x64..    : proof bytes
...      : instances length word
...      : instances words
```

The concrete byte offsets are generated by `ProofCalldataLayout` from the
typed protocol plan. For the canonical ABI prefix they are:

```text
PROOF_LEN_CPTR     = 0x44
PROOF_CPTR         = 0x64
NUM_INSTANCE_CPTR  = 0x64 + proof_len
INSTANCE_CPTR      = NUM_INSTANCE_CPTR + 0x20
```

`calldatasize()` must equal:

```text
INSTANCE_CPTR + 0x20 * num_instances
```

The `instances` length must equal `VK.num_instances`. Every instance word is a
canonical big-endian `Fr` element and must be `< r`.

## 5. Solidity-Facing Proof Encoding

Native `midnight-proofs` proof bytes and Solidity proof bytes are different.

Native proof:

- G1 elements are 48-byte compressed BLS12-381 encodings.
- Scalar elements are 32-byte canonical little-endian field representations.

Solidity proof:

- Every G1 is decompressed off chain and encoded as 128 bytes:
  `x_hi || x_lo || y_hi || y_lo`.
- Every scalar is rewritten to a 32-byte big-endian EVM word.

`SolidityGenerator::repack_compressed_proof` performs this transformation and
must be used by callers that start from native proof bytes.

### 5.1 G1 Padded Encoding

For an affine non-identity G1 point:

```text
x_be = 48-byte big-endian Fp x coordinate
y_be = 48-byte big-endian Fp y coordinate

x_hi = 16 zero bytes || x_be[0..16]
x_lo = x_be[16..48]
y_hi = 16 zero bytes || y_be[0..16]
y_lo = y_be[16..48]
```

The identity is encoded as 128 zero bytes.

The verifier rejects:

- Non-zero top 16 bytes in `x_hi` or `y_hi`.
- Coordinates `>= p`.

Curve and subgroup validation are delegated to EIP-2537 precompiles when the
absorbed point is later consumed by G1MSM, G1ADD, or pairing. The protocol plan
rejects generated shapes where an absorbed proof commitment is never consumed
by a validating precompile path.

### 5.2 Proof Element Order

The Solidity proof byte stream is:

```text
1. Advice commitments, grouped by user phase.
2. Lookup multiplicity commitments, one per lookup.
3. Permutation product commitments, one per permutation set.
4. For each lookup:
   - lookup helper commitments, one per lookup chunk;
   - lookup accumulator commitment.
5. Trash commitments, one per trash argument.
6. Quotient commitment(s): one G1 point with `outer-single-h-commitment`,
   otherwise `degree - 1` G1 points.
7. Main evaluation scalars.
8. `f_com` G1.
9. `q_eval` scalars, one per PCS point set.
10. `pi` G1.
```

The corresponding transcript challenge squeezes occur between these reads, as
specified in section 7. `ProofCalldataLayout` is the Rust source of truth for
the byte range of each section, and the Solidity parser/repacker consume those
generated ranges rather than recomputing section lengths independently.

### 5.3 Main Evaluation Scalar Order

After the `x` challenge, the verifier reads `num_evals` scalar words in this
exact order:

1. Committed instance query evaluations for instance queries whose column is
   less than `num_committed_instances`.
2. Advice query evaluations, in `ConstraintSystem::advice_queries()` order.
3. Fixed query evaluations for non-simple-selector fixed columns, in
   `ConstraintSystem::fixed_queries()` order.
4. Permutation common evaluations, one for each permutation column.
5. Permutation product evaluations:
   - `z_cur` and `z_next` for every permutation set;
   - `z_last` for every set except the final set.
6. For each lookup:
   - lookup multiplicity evaluation;
   - lookup helper evaluations, one per chunk;
   - lookup accumulator `z` at rotation 0;
   - lookup accumulator `z_next` at rotation 1.
7. Trash evaluation scalars, one per trash argument.
8. Dummy eval scalars if the `outer-fewer-point-sets` feature is enabled.

Simple selector fixed-column evaluations are not read from the proof. They are
represented as selector accumulator scalars and fixed commitments in the
linearization query.

### 5.4 Proof Length

Let:

```text
total_advices              = sum advice commitments across user phases
lookup_helper_chunks_total = sum lookup chunk counts
non_quotient_g1s =
    total_advices
  + num_lookups                         // multiplicity commitments
  + num_permutation_zs                  // permutation products
  + lookup_helper_chunks_total
  + num_lookups                         // lookup accumulator commitments
  + num_trashcans

num_quotients  = 1 when outer-single-h-commitment is enabled,
                 otherwise cs.degree() - 1
batch_g1s      = 2                      // f_com, pi
num_point_sets = PCS intermediate point-set count
```

`ProofCalldataLayout` computes the final value. For the current compatible
layout this is:

```text
proof_len =
    (non_quotient_g1s + num_quotients + batch_g1s) * 128
  + (num_evals + num_point_sets) * 32
```

The verifier checks the proof bytes length exactly.

### 5.5 Outer Single-H Decider Layout

The `outer-single-h-commitment` feature mirrors Midfall's
`midnight-proofs/single-h-commitment` for the final Solidity-facing proof only.
It does not enable `single-h-commitment` in `midnight-circuits`,
`midnight-zk-stdlib`, or `midnight-aggregation`, so recursive proofs verified
inside the decider circuit remain on the multi-limb quotient layout.

Operationally, the IVC bench runs in two phases:

1. compile without `outer-single-h-commitment` and write a multi-limb leaf
   bundle containing the two leaf states, proof bytes, and final collapsed
   accumulator;
2. compile with `outer-single-h-commitment`, load that bundle, and prove the
   final Keccak decider proof with one quotient commitment.

The single-H proof requires an extended monomial SRS for the decider quotient
polynomial. For the current decider, `DECIDER_K = 20` and `cs_degree = 5`, so:

```text
extended_k = 20 + ceil_log2(5 - 1) = 22
```

The default bench therefore needs `midnight-srs-2p19`, `midnight-srs-2p20`, and
`midnight-srs-2p22`. Passing `--skip-srs-download` fails closed if `2p22` is
not already present.

For the current VK, single-H changes the final PCS linearization contribution
from `4` quotient commitment terms to `1`. The fused final MSM therefore drops
from `78` to `75` terms. The EIP-2537 G1MSM gas table makes this a marginal
runtime change. In the current profiled IVC command, PCS block 5 drops by
`17,912` gas and total transaction gas drops by `24,571`; the quotient
numerator reconstruction does not change.

## 6. Verifying Key Payload

The VK payload is a sequence of 32-byte big-endian words. In separate mode it
starts at runtime byte `1` of `Halo2VerifyingKey`; runtime byte `0` is
`INVALID` and is included in the pinned runtime length/codehash.

Header layout is generated by `VkHeaderLayout` and written through
`VkHeaderBuilder` so each field is placed by descriptor rather than append
order:

```text
word  0: vk_digest
word  1: num_instances
word  2: k
word  3: n_inv
word  4: omega
word  5: omega_inv
word  6: omega_inv_to_l = omega_inv ^ abs(rotation_last)
word  7: has_accumulator, 0 or 1
word  8: acc_offset
word  9: num_acc_limbs
word 10: num_acc_limb_bits
word 11..14: G1_BASE
word 15..22: G2_BASE
word 23..30: NEG_S_G2_BASE = -[s]G2
```

All scalar words are `Fr` values in big-endian EVM word form. `G1_BASE`,
`G2_BASE`, and `NEG_S_G2_BASE` use EIP-2537 padded encodings.

After the header. The quotient sections may have zero length in experimental
non-VM quotient modes, but are present in the default compact VM mode:

```text
word 31..: quotient constant pool
then:      quotient bytecode program, padded to whole words
then:      fixed commitments, 4 words each
then:      permutation commitments, 4 words each
```

The exact offsets for the quotient constant pool and quotient program are
computed by `VkPayloadLayout`; the verifier uses generated constants derived
from that layout.

The VK codehash pins:

- Header constants.
- SRS-derived G2 data.
- Fixed commitments.
- Permutation commitments.
- Quotient VM constants.
- Quotient VM bytecode.

## 7. Fiat-Shamir Transcript

The generated verifier implements the Midfall Keccak transcript.

### 7.1 Transcript State

The transcript state is a byte buffer.

```text
init:
    buffer = empty

common(bytes):
    buffer = buffer || bytes

squeeze():
    digest = keccak256(buffer)
    buffer = digest
    return uint256_be(digest) mod r
```

Scalar inputs are canonical 32-byte big-endian words. G1 inputs are the
128-byte EIP-2537 padded uncompressed form.

### 7.2 Absorb And Squeeze Schedule

The verifier must execute this schedule exactly:

1. Initialize empty transcript.
2. Absorb `vk_digest`.
3. Absorb `committed_pi = G1 identity` as 128 zero bytes. This mirrors the
   current `midnight-proofs` committed-instance feature shape used by the
   generator.
4. Absorb `num_instances`.
5. Absorb each public `instances` scalar in calldata order.
6. For each user phase:
   - absorb that phase's advice commitments;
   - squeeze that phase's user challenges into `CHALLENGE_MPTR`.
7. Squeeze `theta`.
8. Absorb lookup multiplicity commitments, if any.
9. Squeeze `beta`.
10. Squeeze `gamma`.
11. Absorb permutation product commitments, if any.
12. Absorb lookup helper and lookup accumulator commitments, if any.
13. Squeeze `trash_challenge`. This is unconditional.
14. Absorb trash commitments, if any.
15. Squeeze `y`.
16. Absorb quotient commitment(s).
17. Squeeze `x`.
18. Absorb all main evaluation scalars, including dummy evals if present.
19. Squeeze `x1`.
20. Squeeze `x2`.
21. Absorb `f_com`.
22. Squeeze `x3`.
23. If `truncated-challenges` is enabled, replace `x3` with its low 128 bits.
24. Absorb all `q_eval` scalars, one per PCS point set.
25. Squeeze `x4`.
26. Absorb `pi`.

The parser must consume exactly `proof_len` proof bytes after absorbing `pi`.

### 7.3 Truncated Challenges

When the crate feature `truncated-challenges` is enabled, the Solidity verifier
must mirror `midnight-proofs`:

- `x3` is masked to the lower 128 bits immediately after squeeze.
- `x1` powers used in PCS are emitted as `truncate(x1^i)`, while the internal
  power accumulator remains full precision.
- `x4` powers are emitted as `truncate(x4^i)`, while the internal power
  accumulator remains full precision.

The mask is:

```text
0xffffffffffffffffffffffffffffffff
```

Feature settings must match the prover. A mismatch produces invalid pairings.

## 8. Protocol Plan

`ProtocolPlan::from_constraint_system` is the source of truth for proof reads,
PCS queries, common polynomial needs, and quotient identity counts.

### 8.1 Derived Counts

From the constraint system:

```text
num_fixeds              = cs.num_fixed_columns()
permutation_columns     = cs.permutation().get_columns()
permutation_chunk_len   = cs.degree() - 2
num_permutation_zs      = ceil(len(permutation_columns) / permutation_chunk_len)
lookup_chunks[i]        = cs.lookups()[i].chunk_by_degree(cs.degree()).num_chunks()
num_lookups             = len(lookup_chunks)
num_trashcans           = len(cs.trashcans())
num_quotients           = 1 when outer-single-h-commitment is enabled,
                          otherwise cs.degree() - 1
num_simple_selectors    = cs.num_simple_selectors()
simple_selector_cols    = fixed columns where cs.has_simple_selector_col(idx)
rotation_last           = -(cs.blinding_factors() + 1)
```

Advice and challenge columns are remapped by phase. Commitments are still read
in phase order, but their memory column indices are compact phase-local
indices, matching the prover's read order.

### 8.2 Commitment Read Plan

The commitment plan is:

```text
advice commitments in phase-remapped order
lookup multiplicity commitments
permutation product commitments
for each lookup:
    lookup helper commitments
    lookup accumulator commitment
trash commitments
quotient commitment(s)
```

Every absorbed proof commitment must later be consumed by PCS or another
EIP-2537 validating path.

### 8.3 PCS Query Plan

The PCS query list is:

```text
advice queries
committed instance queries
permutation Z queries
lookup multiplicity queries
lookup helper queries
lookup accumulator queries
trash queries
fixed queries, excluding simple selector columns
permutation common queries
linearization query
```

The linearization query is always last.

For `PermutationZ`:

```text
Cur  -> rotation 0
Next -> rotation 1
Last -> rotation_last
```

For lookup accumulators:

```text
z      -> rotation 0
z_next -> rotation 1
```

All other special argument queries are at rotation 0 unless explicitly stated.

### 8.4 Common Polynomials

The verifier must make available:

- Every rotation point `x * omega^rot` used by PCS queries.
- `L_0(x)`, `L_last(x)`, and `L_blind(x)` when permutation or lookup arguments
  require them.
- Rotation 0 when trash arguments require it.

The generated Solidity computes these after `x` is sampled.

## 9. Public Instance Evaluation

Committed instance column evaluations are read from the proof and included in
the PCS query list.

The non-committed public input column is evaluated locally from `instances`.
The verifier computes Lagrange values at `x` and forms:

```text
instance_eval = sum_i L_i(x) * instances[i]
```

The same Lagrange block also computes:

```text
x_n
x_n_minus_1_inv
L_last(x)
L_blind(x)
L_0(x)
```

Implementation details:

1. Compute `x_n = x^(2^k)` by repeated squaring `k` times.
2. Build denominator inputs `x - omega^j` for the required negative rotations
   and public-instance positions.
3. Append `x_n - 1`.
4. Batch invert all denominators.
5. Use the common factor `(x_n - 1) * n_inv`.
6. Store the generated Lagrange values and `instance_eval`.

The batch inversion helper must fail if any inverted scalar is zero.

## 10. Quotient Numerator And Linearization Scalar

The verifier reconstructs the same identity evaluations as
`midnight-proofs::plonk::partially_evaluate_identities`, in this order:

1. Custom gate identities.
2. Permutation identities.
3. Lookup identities.
4. Trash identities.

The output is not a prover-supplied quotient evaluation. The verifier computes
the y-batched numerator scalar:

```text
nu_y(x) = y^(m-1) * e_0(x) + y^(m-2) * e_1(x) + ... + e_(m-1)(x)
```

where `e_i` are the identities in forward Rust order.

The verifier stores:

```text
linearization_expected_eval = -nu_y(x) mod r
```

This value is the claimed opening scalar for the generated linearization
commitment in the final PCS query.

### 10.1 Gate Identities

Gate expressions are lowered from `midnight_proofs::plonk::Expression<Fq>`.

Expression leaves map as follows:

- Constants: literal `Fr` constants.
- Advice queries: proof eval words by `(column, rotation)`.
- Fixed queries: proof eval words by `(column, rotation)`, except simple
  selectors.
- Simple selectors: handled as selector targets, not proof eval scalars.
- Instance queries:
  - committed instance columns use proof evals;
  - non-committed public input column uses `INSTANCE_EVAL_MPTR`.
- Challenge queries: sampled user challenges.

Expression nodes map to `addmod`, `mulmod`, and field negation.

If a gate identity is gated by a simple selector, its scalar contribution goes
into the selector bucket for that fixed column rather than into
`quotient_eval_numer`.

### 10.2 Permutation Identities

The verifier emits the same permutation constraints as the Midfall verifier:

- First-set boundary:
  `L_0(x) * (1 - z_0(x))`.
- Last-set boolean boundary:
  `L_last(x) * (z_l(x)^2 - z_l(x))`.
- Cross-set continuity for every set after the first:
  `L_0(x) * (z_i(x) - z_(i-1)(omega^last * x))`.
- Active-row product check for every set:

```text
(1 - (L_last(x) + L_blind(x))) *
(
    z_i(omega*x) * product(p(x) + beta*s_i(x) + gamma)
  - z_i(x)       * product(p(x) + delta^i*beta*x + gamma)
)
```

`delta` is the BLS12-381 `Fr::DELTA` constant used by Midfall:

```text
3793952369011177517951424454785176000433849974408744014172535497121832470999
```

### 10.3 Lookup Identities

For LogUp lookups, multi-expression inputs are compressed with `theta` in
Horner form:

```text
compressed = (((expr_0) * theta + expr_1) * theta + ...)
```

The verifier emits:

- Boundary: `(L_0(x) + L_last(x)) * Z(x)`.
- Helper constraints per lookup input chunk:

```text
h_i(x) * product_j(f_j(x) + beta)
  - sum_j product_{k != j}(f_k(x) + beta)
```

- Accumulator constraint on active rows:

```text
(
    Z(omega*x)
  - Z(x)
  - selector(x) * sum_i h_i(x)
) * (t(x) + beta)
+ m(x)
```

then multiplied by:

```text
1 - (L_last(x) + L_blind(x))
```

### 10.4 Trash Identities

Each trash argument compresses its constraint expressions with
`trash_challenge` in Horner form, then subtracts the inactive-row trash term:

```text
compressed - (1 - q(x)) * trash_eval
```

### 10.5 Y-Batching

Rust folds in reverse with powers of `y`. Solidity scans forward using Horner:

```text
acc = 0
for identity e_i in forward order:
    acc = acc * y + e_i
```

This produces the same y powers as Rust's reverse fold.

### 10.6 Simple Selector Buckets

Simple-selector identities must retain their y-batch position while grouping by
selector commitment.

The compact VM keeps:

```text
selector_bucket[j]
y_power[k] = y^k
```

Codegen knows the global positions of selector identities. For a
selector-targeted identity with scalar `e`, it emits the gap since the previous
identity for the same selector:

```text
selector_bucket[j] = selector_bucket[j] * y_power[gap] + e
```

After all identities it applies the final tail for each selector:

```text
selector_bucket[j] *= y_power[tail[j]]
```

This matches Rust's grouped selector accumulators.

### 10.7 Linearization Commitment Side

The commitment for the final linearization query is:

```text
(1 - x^n) * sum_i x_split^i * Q_i
  + sum_j selector_bucket[j] * S_j
```

where:

```text
x_split = x^(n - 1)
Q_i     = quotient commitment i
S_j     = simple selector fixed commitment j
```

In the outer single-H layout the sum has one `Q_0` term, so the quotient-side
scalar is exactly `1 - x^n`.

The scalar side is `-nu_y(x)`. The verifier does not compute or trust
`h(x) = nu_y(x) / (x^n - 1)`.

## 11. Compact Quotient VM

The default generator stores most quotient identity arithmetic as data in the
VK payload and interprets it with a small Yul stack VM.

A reimplementation may emit straight-line code instead, but it must produce
the same identity values in the same order and the same selector/main folds.
To reproduce this repository's split artifact shape, implement the VM below.
The generator decodes the finalized physical bytecode after run compaction or
packed32 lowering and rejects unknown opcodes, truncated operands, unknown
memory tokens, stack underflow, native-callback stack leaks, and non-empty
identity boundaries before pinning the program into the VK payload.

### 11.1 VM State

The VM has:

- `q_const_mptr`: base of the quotient constant pool in the copied VK payload.
- `q_program_mptr`: base of quotient bytecode in the copied VK payload.
- `q_pc`: bytecode cursor.
- `q_end`: bytecode end.
- `q_sp`: memory stack pointer.
- `q_top`: cached top-of-stack.
- `q_has_top`: whether `q_top` is live.
- Optional CSE temp words at `q_tmp_mptr`.

Push semantics:

- If `q_has_top` is true, spill `q_top` to `mstore(q_sp, q_top)` and advance
  `q_sp += 0x20`.
- Load the new value into `q_top`.
- Set `q_has_top = 1`.

Binary semantics:

- Decrement `q_sp` by `0x20`.
- Combine `mload(q_sp)` with `q_top`.
- Store the result in `q_top`.

### 11.2 Memory Tokens

Token operands map to generated memory pointers:

```text
0x01: L_0_MPTR
0x02: L_LAST_MPTR
0x03: L_BLIND_MPTR
0x04: BETA_MPTR
0x05: GAMMA_MPTR
0x06: X_MPTR
0x07: THETA_MPTR
0x08: TRASH_CHALLENGE_MPTR
0x09: INSTANCE_EVAL_MPTR
```

Token-offset instructions add a byte offset to the token pointer.

### 11.3 Byte-Oriented Opcode Table

The default physical encoding is byte-oriented. Multi-byte numeric operands are
big-endian.

```text
0x01 u16 const_idx:
    push mload(q_const_mptr + 32 * const_idx)

0x02 u32 ptr:
    push mload(ptr)

0x03 u8 token:
    push mload(ptr_for_token(token))

0x04 u8 token, u32 offset:
    push mload(ptr_for_token(token) + offset)

0x05 u16 ptr:
    push mload(ptr)

0x06:
    q_top = stack_pop() + q_top mod r

0x07:
    q_top = stack_pop() * q_top mod r

0x08:
    q_top = -q_top mod r

0x09 u8 const_idx:
    push mload(q_const_mptr + 32 * const_idx)

0x0a:
    fold main identity with q_eval = q_top

0x0b u8 selector_idx, u16 gap:
    advance that selector bucket by gap and fold q_eval = q_top

0x0c u8 const_idx:
    q_top += const[const_idx]

0x0d u8 const_idx:
    q_top *= const[const_idx]

0x0e u16 const_idx:
    q_top += const[const_idx]

0x0f u16 const_idx:
    q_top *= const[const_idx]

0x10 u16 ptr:
    q_top += mload(ptr)

0x11 u16 ptr:
    q_top *= mload(ptr)

0x12 u16 lhs, u16 rhs, u8 const_idx:
    q_top += mload(lhs) * mload(rhs) * const[const_idx]

0x13 u16 ptr, u8 const_idx:
    q_top += mload(ptr) * const[const_idx]

0x14 u16 lhs, u16 rhs:
    q_top += mload(lhs) * mload(rhs)

0x15 u16 count, repeated count times {u16 lhs, u16 rhs, u8 const_idx}:
    run form of 0x12

0x16 u16 count, repeated count times {u16 ptr, u8 const_idx}:
    run form of 0x13

0x17 u16 temp_idx:
    push mload(q_tmp_mptr + 32 * temp_idx)

0x18 u16 temp_idx:
    mstore(q_tmp_mptr + 32 * temp_idx, q_top)

0x19:
    native permutation callback

0x1a:
    reserved / unassigned

0x1b u16 native_idx:
    native heavy-gate callback

0x1c repeated 7 times {u8 const_idx, u16 ptr}:
    LIN7 = sum_i const[const_idx_i] * mload(ptr_i)

0x1d u16 lhs, repeated 7 times {u8 const_idx, u16 rhs}:
    BILIN7_ROW = mload(lhs) * sum_i const[i] * mload(rhs_i)

0x1e u16 lhs_base, u16 rhs_base, 13 bytes const_idx[0..12]:
    BILIN7_PAIRWISE =
      sum_{i=0..6,j=0..6}
        const[const_idx[i+j]]
        * mload(lhs_base + 32*i)
        * mload(rhs_base + 32*j)

0x1f:
    native lookup callback

0x20:
    q_top = q_top^5

0x21 flags, optional cond/constant, count header, fused 7-limb blocks:
    push one fused affine 7-limb identity value
```

The packed32 encoding is an alternate physical encoding where each base
instruction is a four-byte word with the opcode in the high byte and a 24-bit
operand. It must implement the same logical operations.

The full interpreter case reference, implementation notes, and audit checklist
for this VM live in `docs/QUOTIENT_NUMERATOR_EVALUATOR.md`. In particular,
native callbacks may use scratch memory that is larger than the interpreter's
operand stack. Memory planning must reserve the maximum of the VM stack depth
and any enabled native callback scratch requirement.

## 12. KZG Multi-Prepare PCS Check

The PCS emitter mirrors `midnight-proofs` KZG `multi_prepare`.

### 12.1 Raw Query List

Build queries from the protocol plan. Each query is:

```text
(commitment, rotation, claimed_eval)
```

The final query is the linearization query:

```text
(linearization_commitment, 0, linearization_expected_eval)
```

### 12.2 Fewer Point Sets

If `outer-fewer-point-sets` is enabled:

1. Group raw queries by commitment.
2. Build the union of all non-singleton point sets.
3. For each commitment group missing a point from that union, append a dummy
   query using that commitment and a new dummy eval scalar.
4. Dummy eval scalars are appended to the main evaluation block before `f_com`.

The dummy-query order is deterministic: group insertion order, then union point
in insertion order.

### 12.3 Intermediate Sets

Construct intermediate sets:

1. Deduplicate commitments by identity.
2. For each commitment, record all queried rotation points and aligned evals.
3. Bucket commitments by their set of rotation points.
4. Convert point-index sets back to rotation lists.
5. Sort point sets by ascending cardinality, with original set index as
   tiebreaker.

`num_point_sets` is the number of sorted sets. The proof contains exactly one
`q_eval` scalar for each set.

### 12.4 Rotation Points

For every distinct rotation in every point set, compute:

```text
point(rot) = x * omega^rot
```

Positive rotations walk by multiplying by `omega`. Negative rotations walk by
multiplying by `omega_inv`.

### 12.5 x1 Powers

For the maximum number of commitments in any point set, compute:

```text
x1_powers[i] = x1^i
```

If `truncated-challenges` is enabled, store `low128(x1^i)` while keeping the
internal accumulator full precision.

### 12.6 q_eval_set

For each point set `s`, and each rotation position `k` inside that set:

```text
q_eval_set[s][k] =
    sum_i x1_powers[i] * eval(commitment_i, rotation_k)
```

The storage order is flattened by set order:

```text
Q_EVAL_SET_MPTR + 32 * (sum_{t<s} len(point_set[t]) + k)
```

### 12.7 f_eval

Let `proof_q_eval[s]` be the `s`-th `q_eval` scalar from proof calldata. For
sets in reverse order, compute the evaluation of the quotient used by
multi-prepare:

For a singleton point set `{p}`:

```text
eval_s = (proof_q_eval[s] - q_eval_set[s][0]) / (x3 - p)
```

For a set with points `p_j`:

```text
dx_j       = x3 - p_j
lbasis_j   = product_{k != j} (p_j - p_k)
den_inv    = product_j dx_j^-1
eval_s     = proof_q_eval[s] * den_inv
             - sum_j q_eval_set[s][j] * dx_j^-1 * lbasis_j^-1
```

All inversions are in `Fr`. The implementation batch-inverts the `dx_j` and
`lbasis_j` values for each non-singleton set.

Fold with `x2`:

```text
f_eval = 0
for s in reverse(point_sets):
    f_eval = f_eval * x2 + eval_s
```

Store `f_eval` at `F_EVAL_MPTR`.

### 12.8 final_com And v

Compute `x4` powers:

```text
x4_pow[s] = x4^s
```

If `truncated-challenges` is enabled, emitted powers are `low128(x4^s)` while
the internal accumulator remains full precision.

Compute:

```text
v = sum_s x4_pow[s] * proof_q_eval[s]
    + x4_pow[num_point_sets] * f_eval
```

Compute:

```text
final_com =
    sum_s x4_pow[s] * q_com[s]
  + x4_pow[num_point_sets] * f_com
```

where:

```text
q_com[s] = sum_i x1_powers[i] * commitment_i
```

The implementation fuses this into one G1MSM. If a commitment is the
linearization commitment, it expands it into:

```text
for each quotient commitment Q_j:
    scalar = x4_pow[s] * x1_powers[i] * (1 - x^n) * x_split^j

for each simple selector S_j:
    scalar = x4_pow[s] * x1_powers[i] * selector_bucket[j]
```

With `outer-single-h-commitment`, there is only `Q_0`, so the quotient scalar
does not carry an extra `x_split^j` ladder beyond `j = 0`.

Identity commitments are skipped in the MSM input but still contribute to
`q_eval_set`.

### 12.9 Pairing Inputs

After the final MSM:

```text
PAIRING_LHS = pi
PAIRING_RHS = final_com - v * G1_BASE + x3 * pi
```

The final KZG pairing identity is:

```text
e(PAIRING_RHS, G2_BASE) * e(PAIRING_LHS, NEG_S_G2_BASE) == 1
```

Equivalently:

```text
e(final_com - v*G + x3*pi, [1]_2) = e(pi, [s]_2)
```

## 13. Public Accumulator Check

If `has_accumulator` is true, the verifier reconstructs a public KZG
accumulator from the `instances` array and batches its pairing equation with
the final KZG pairing equation.

This path is optional and generated-verifier-specific. It is disabled by
default (`AccumulatorEncoding = None`) and activated only by configuring the
generator:

```rust
let generator = SolidityGenerator::new(params, vk, num_instances, num_committed_instances)
    .set_acc_encoding(Some(AccumulatorEncoding::new(offset, 7, 56)));
```

`AccumulatorEncoding::new` matches `AssignedAccumulator<S>::as_public_input`:
`lhs point, lhs scalar, rhs point, rhs scalar`, with an optional fixed-base
scalar tail. Moonlight wrap proofs expose an already-collapsed point pair
instead. For that ABI, use:

```rust
let generator = SolidityGenerator::new(params, vk, num_instances, num_committed_instances)
    .set_acc_encoding(Some(AccumulatorEncoding::point_pair(offset, 7, 56)));
```

The point-pair layout is `lhs point, rhs point`; the generated verifier uses
implicit unit scalars for both sides and rejects fixed-base scalar tails.

Use `try_set_acc_encoding` instead when the public-input layout comes from
caller-controlled metadata and should return a typed `GeneratorError` instead
of panicking. Enabling the accumulator writes the expected accumulator metadata
into the generated VK payload:

```text
has_accumulator = 1
acc_offset = offset
num_acc_limbs = 7
num_acc_limb_bits = 56
```

The Solidity verifier checks those VK header words against the generator's
compiled-in expectations before it decodes public inputs. A stale VK or a
verifier rendered with the wrong accumulator metadata therefore reverts before
any accumulator point reconstruction.

The current Solidity path requires:

```text
num_limbs = 7
num_limb_bits = 56
```

### 13.1 Public Input Layout

The accumulator is not passed through a separate ABI argument. It is a public
input tail inside the normal non-committed `instances` vector, beginning at
`instances[offset]`. The circuit must constrain that public tail to equal the
carried accumulator it recomputes internally. The IVC decider does this by
formatting:

```text
[leaf public state words..., fully collapsed final accumulator public input]
```

and passing the starting index of the accumulator tail as `offset`.

At `instances[offset]`, the decoded schema is:

```text
lhs point coordinates
lhs scalar
rhs point coordinates
rhs scalar
optional RHS fixed-base scalar tail
```

The verifier computes the expected total public-input width:

```text
expected_words =
    offset
  + lhs point words
  + lhs scalar word
  + rhs point words
  + rhs scalar word
  + fixed-base scalar tail words
```

and requires `num_instances == expected_words`. This makes the accumulator a
checked tail convention, not an unchecked side channel: extra words after the
accumulator and missing accumulator words both cause verification to revert.

With 7 limbs and 56-bit limbs:

```text
limbs_per_word = 4
coord_words    = ceil(7 / 4) = 2
point_words    = 2 * coord_words = 4
```

So the collapsed no-tail layout is:

```text
lhs_x:      2 words
lhs_y:      2 words
lhs_scalar: 1 word
rhs_x:      2 words
rhs_y:      2 words
rhs_scalar: 1 word
```

If a fixed-base scalar tail exists, it is consumed as RHS MSM scalars for:

- `-G`, represented by `G1_BASE` with scalar negated modulo `r`;
- fixed commitments;
- permutation commitments.

The tail bases are sorted lexicographically by their generated names to match
Midfall's `BTreeMap` order.

### 13.2 Coordinate Reconstruction

Coordinates are exposed by Midnight circuits as limbs of `coord - 1`, packed
four limbs per native field element. The x coordinate's first packed word may
carry an identity flag by adding one raw limb base.

The verifier:

1. Checks unused high bits in each packed word.
2. Reconstructs the shifted coordinate from limbs.
3. Detects identity encodings using the generated constants for `p - 1`.
4. For non-`p - 1` values, adds 1 to undo the `coord - 1` representation.
5. Checks the reconstructed coordinate is `< p`.
6. Checks the high EIP-2537 word fits in 128 bits.
7. Stores the point as a padded G1 tuple, or stores all zeros for identity.

### 13.3 Accumulator Pairing Batch

After `PAIRING_LHS` and `PAIRING_RHS` are fixed, derive:

```text
alpha = keccak256(
    "pairing-batch-acc-kzg" domain word
    || PAIRING_RHS
    || PAIRING_LHS
    || ACC_RHS
    || ACC_LHS
) mod r
```

If `alpha == 0`, replace it with 1.

Then update:

```text
PAIRING_RHS += alpha * ACC_RHS
PAIRING_LHS += alpha * ACC_LHS
```

The final pairing check in section 12.9 is then performed once. This prevents
two bad pairing equations from cancelling deterministically; after inputs are
fixed, a bad pair can pass for at most one `alpha`.

## 14. Memory Architecture

A reimplementation may choose a different internal memory map if all observable
semantics are preserved. This repository uses absolute Yul memory addresses to
keep generated bytecode compact and to simplify precompile frames.

The codegen memory planner must ensure:

- All regions are 32-byte aligned.
- Permanent regions never overlap.
- Scratch regions overlap only when their lifetimes are disjoint.
- PCS fixed windows cannot overflow.
- Solidity-reserved memory `[0x00..0x80)` is not used for generated writes.
- The transcript buffer starts at `0x80` and lives below `VK_MPTR`.
- The VK payload remains live until all quotient/PCS code that references it
  has finished.
- External quotient evaluator frames cover every memory word the evaluator
  needs.

High-level memory order:

```text
0x00..0x7f:
    Solidity-reserved scratch, free-memory pointer, and zero slot

0x80..VK_MPTR:
    transient transcript buffer and low precompile scratch

VK_MPTR:
    copied or embedded VK payload

after VK:
    user challenge slots

THETA_MPTR:
    challenge scalars, batch-open commitments, Lagrange values,
    PCS fixed windows, decoded evals, proof commitments, selector buckets,
    quotient scratch, PCS scratch, accumulator scratch
```

Important theta-relative word offsets:

```text
0:  theta
1:  beta
2:  gamma
3:  trash_challenge
4:  y
5:  x
6:  x1
7:  x2
8:  x3
9:  x4
10: f_com, 4 words
14: pi, 4 words
18: acc_lhs, 4 words
22: acc_rhs, 4 words
26: x_n
27: x_n_minus_1_inv
28: l_last
29: l_blind
30: l_0
31: instance_eval
32: quotient_eval
33: quotient scratch, 4 words
38: f_eval
39: v
40: final_com, 4 words
44: pairing_lhs, 4 words
48: pairing_rhs, 4 words
52: rotation point window
80: x1 powers window
145: q_eval_set window
201: q_eval calldata pointer slot
209: G1 identity, 4 zero words
220: decoded evaluation buffer
220 + num_evals: decompressed proof commitments
```

Proof commitments are stored contiguously by category:

```text
advice
lookup multiplicity
permutation Z
lookup helpers
lookup accumulator Z
trash commitments
quotient commitment(s)
```

See `docs/MEMORY_LAYOUT.md` for the detailed scratch lifetime table and update
rules.

## 15. EIP-2537 And Precompile Requirements

The generated verifier constructor runs smoke tests:

- `G1ADD(identity, identity) -> identity`.
- `G1MSM([(identity, 0)]) -> identity`.
- `PAIRING_CHECK([(identity_g1, identity_g2)]) -> true`.

Deploy only on forks/chains where EIP-2537 and `MCOPY` are available with the
exact addresses, encodings, subgroup checks, return-size behavior, and gas
schedule above. The test runner uses Prague-spec `revm` and includes direct
precompile conformance coverage for malformed G1 rejection, non-identity G1ADD,
two-term and 78-term G1MSM, true and false pairings, and pairing bilinearity.

Every EIP-2537 call checks:

- `staticcall` success.
- Exact return-data size.
- For pairing, returned word is 1.

Gas caps are generated as literals instead of forwarding all remaining gas or
carrying the EIP-2537 discount table in runtime bytecode:

- G1ADD cap: `50000`.
- G1MSM cap: `50000 + k * discount[k] * 12000 / 1000`, with the EIP-2537
  discount table for `k <= 128`.
- Pairing cap: `50000 + 60000 * num_pairs`.

## 16. Codegen Configuration

Cargo features:

```text
evm
solidity-trace
solidity-gas-checkpoints
truncated-challenges
in-circuit-fewer-point-sets
outer-fewer-point-sets
outer-single-h-commitment
fewer-point-sets
rust-verifier-trace
```

Environment variables for quotient codegen experiments:

```text
HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=N
HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=N
HALO2_SOLIDITY_QUOTIENT_ENCODING=bytes|packed32
HALO2_SOLIDITY_QUOTIENT_CSE=0|1
HALO2_SOLIDITY_QUOTIENT_VM_CSE=0|1
HALO2_SOLIDITY_QUOTIENT_YUL_HELPERS=0|1
HALO2_SOLIDITY_QUOTIENT_STRUCTURED_LOOPS=0|1
HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=off|trash
HALO2_SOLIDITY_QUOTIENT_NATIVE_PERMUTATION=0|1
HALO2_SOLIDITY_QUOTIENT_NATIVE_LOOKUP=0|1
HALO2_SOLIDITY_QUOTIENT_LIMB_VM_OPS=0|1
HALO2_SOLIDITY_QUOTIENT_SHAPE_PROFILE=0|1
```

Current quotient lowering defaults:

```text
direct inline quotient identities: 4
native heavy gate callbacks:       4
quotient program encoding:         bytes
VM CSE:                            on
native permutation callback:       on
native lookup callback:            on
structured trash suffix:           on
limb VM ops:                       on for byte encoding
```

These settings are implementation choices. A reimplementation may pick a
different quotient lowering if it preserves all algebra and transcript
semantics.

## 17. Verification Algorithm

This is the complete verifier flow:

1. Check ABI head offsets.
2. Check pinned VK and quotient evaluator code, if external.
3. Load or materialize VK payload.
4. Check `proof.length == proof_len`.
5. Check `instances.length == VK.num_instances`.
6. Check total calldata length exactly.
7. If accumulator is enabled, decode public accumulator points and run the
   G1MSM validation/scaling work before transcript, quotient, PCS, and final
   pairing work.
8. Initialize transcript.
9. Absorb VK digest, committed identity, instance count, and instances.
10. Parse proof commitments and scalars in the order in section 5, absorbing
    each into the transcript and squeezing challenges in the order in section 7.
11. Range-check every scalar proof and instance word.
12. Copy all proof G1s into their generated memory slots.
13. Spill all eval scalars into `REVERSED_EVALS_MPTR`.
14. Compute Lagrange values and public `instance_eval`.
15. Reconstruct the quotient numerator and selector accumulators, either
    inline or through the pinned quotient evaluator.
16. Compute `x_split = x^(n - 1)` and `1 - x^n`.
17. Build PCS queries and intermediate point sets.
18. Compute rotation points and x1 powers.
19. Compute `q_eval_set`.
20. Compute `f_eval`.
21. Compute `final_com` and `v`.
22. Stage KZG pairing inputs:
    `pi` and `final_com - v*G + x3*pi`.
23. If accumulator is enabled, derive batching alpha from the KZG and already
    validated accumulator G1 inputs, then add alpha-weighted accumulator pairing
    inputs into the KZG pairing inputs.
24. Run final two-pair BLS12-381 pairing check.
25. Return `true`.

Any failed condition must revert.

## 18. Reimplementation Checklist

A fresh implementation is compatible if it satisfies all of the following:

- Accepts exactly the same ABI and rejects shifted or trailing calldata.
- Requires the same generated proof length.
- Uses the Solidity-facing proof layout in section 5.
- Repackages native proof bytes exactly as section 5 specifies.
- Absorbs transcript bytes in exactly the schedule in section 7.
- Samples challenges as `uint256_be(keccak256(buffer)) mod r` and reseeds the
  buffer to the digest after every squeeze.
- Uses the same `truncated-challenges` rules when that feature is enabled.
- Derives the protocol plan from the constraint system as in section 8.
- Computes local public instance evaluation as in section 9.
- Evaluates gate, permutation, lookup, and trash identities in Rust order.
- Folds main and simple-selector identities with the y powers in section 10.
- Uses `-nu_y(x)` as the linearization expected eval.
- Expands quotient commitment(s) with `(1 - x^n) * x_split^i`; in the
  outer single-H layout this has only the `i = 0` term.
- Constructs PCS intermediate sets, dummy queries, `q_eval_set`, `f_eval`,
  `final_com`, `v`, and pairing inputs as in section 12.
- Pins every external correctness-critical artifact by runtime length and
  codehash at construction/deployment time.
- Checks every scalar `< r`.
- Rejects non-canonical padded G1 coordinates before transcript absorption.
- Ensures every absorbed G1 is validated by an EIP-2537 path before success.
- Checks EIP-2537 call success and return sizes.
- Reverts on every failure.

## 19. Test Expectations

Minimum validation for a reimplementation:

- Unit-test Keccak transcript equivalence against
  `midnight_proofs::transcript::CircuitTranscript<Keccak256>`.
- Unit-test native compressed proof to Solidity padded proof repacking.
- Unit-test proof layout counts against `ProofEvaluationCounts`.
- Unit-test protocol plan ordering for circuits with:
  - advice queries at several rotations;
  - fixed queries;
  - one committed and one non-committed instance column;
  - permutation columns;
  - LogUp lookups;
  - trash arguments;
  - simple selectors.
- Unit-test PCS intermediate-set construction and dummy-query generation.
- Run Solidity compile tests with `solc 0.8.30+commit.73712a01`, `--via-ir`,
  `--evm-version cancun`, and no CBOR metadata.
- Run end-to-end EVM verification on a Prague/EIP-2537 VM.
- Run negative tests for:
  - wrong public input;
  - mutated scalar;
  - mutated G1;
  - non-canonical padded coordinate;
  - wrong proof length;
  - trailing calldata;
  - wrong VK codehash at construction;
  - wrong quotient evaluator codehash at construction.

Repository commands are documented in `README.md` and `TESTING.md`.
