# Solidity Verifier Fidelity Status

Assessed on 2026-05-03 against:

- Solidity verifier repo: `halo2-solidity-verifier-exp`
- Midfall Rust verifier: `../midfall/proofs/src`
- Midfall revision pinned in `Cargo.toml`: `53dc872f495104046d96bdac0a690f903dc0c537`

## Verdict

The Solidity verifier is a faithful specialized lowering of the pinned Midfall
Rust verifier for this repo's supported proof shape. It is not a generic
reimplementation of `midfall/proofs/src`.

For the supported profile it preserves the Rust verifier's proof-read order,
Fiat-Shamir challenge order, quotient identity algebra, linearization, KZG
batching, and final pairing equation. The main divergences are deliberate:

- the constraint system is compiled away;
- the verifying key is pinned as deployed bytecode plus digest/constants;
- public instance handling is narrowed;
- proof bytes are repacked for EIP-2537;
- the IVC carried accumulator check is extra wrapper logic beyond the Rust
  PLONK verifier.

The supported profile is approximately:

- `F = midnight_curves::Fq`;
- `CS = KZGCommitmentScheme<Bls12>`;
- Keccak transcript;
- committed-instances feature enabled;
- one proof;
- exactly one committed instance column and one non-committed instance column;
- no rotated non-committed instance queries;
- quotient limbs equal to `cs.degree() - 1`;
- matching `truncated-challenges` / `outer-fewer-point-sets` features;
- BLS12-381 EIP-2537 precompiles available.

## One-To-One Map

| Rust verifier operation | Solidity generator / template | Fidelity notes |
|---|---|---|
| `parse_trace` absorbs VK, instances, commitments, and challenges in order: `../midfall/proofs/src/plonk/verifier.rs:24` | Protocol schedule: `src/codegen/protocol.rs:241`; transcript template: `templates/Halo2Verifier.sol:1031` | Same order for the supported profile. Solidity always assumes one committed identity instance and one public instance column. |
| VK hash via `VerifyingKey::hash_into`: `../midfall/proofs/src/plonk/mod.rs:282` | VK digest generation: `src/codegen/generator.rs:550`; runtime load/check: `templates/Halo2Verifier.sol:979` | Transcript absorbs the same digest, but Solidity trusts generated/pinned VK constants instead of reconstructing the Rust VK/CS. |
| Dynamic `ConstraintSystem` and `Expression::evaluate`: `../midfall/proofs/src/plonk/circuit.rs:825` | Compile-time metadata/layout: `src/codegen/util.rs:60`; expression lowering: `src/codegen/evaluator.rs:780` | The CS is not present on-chain. Expressions are pre-lowered from the pinned CS. Faithful only if generated from the exact VK/CS being verified. |
| Master gate / permutation / lookup / trash identities via `partially_evaluate_identities`: `../midfall/proofs/src/plonk/mod.rs:488` | Quotient identity construction: `src/codegen/generator.rs:975`; evaluator blocks: `src/codegen/evaluator.rs:155`; quotient Yul: `templates/QuotientNumeratorBlock.yul:1` | Algebra matches. Simple selectors are handled structurally differently: Rust returns selector buckets; Solidity omits selector evals from proof and accumulates selector commitments in the fused MSM. |
| Linearization commitment: `../midfall/proofs/src/plonk/linearization/verifier.rs:45` | Linearization scalar prep: `templates/Halo2Verifier.sol:1450`; PCS fused expansion: `src/codegen/pcs.rs:1304` | Same commitment/evaluation relation, but Solidity fuses terms directly into the final MSM instead of materializing the full linearization object. |
| KZG `multi_prepare`: `../midfall/proofs/src/poly/kzg/mod.rs:320` | Query schedule and PCS codegen: `src/codegen/pcs.rs:83`; emitted PCS blocks: `src/codegen/pcs.rs:602` | Same batching algebra: dummy queries, point sets, `x1/x2/x3/x4`, `f_com`, `q_evals`, `pi`. Solidity uses optimized direct formulas, batch inversions, and fused MSMs. |
| Final `DualMSM::check`: `../midfall/proofs/src/poly/kzg/msm.rs:282` | Pairing inputs in PCS: `src/codegen/pcs.rs:1484`; final pairing: `templates/Halo2Verifier.sol:1723` | Equivalent equation. Solidity passes arguments swapped because its helper checks `(rhs, G2)` and `(lhs, -sG2)`. |

## CS And VK Handling

Rust keeps a full `VerifyingKey` with a live `ConstraintSystem`:

- `VerifyingKey` stores fixed commitments, permutation commitments, domain,
  and CS data.
- `VerifyingKey::from_parts` computes a transcript representation that binds
  the pinned CS debug form.
- `hash_into` absorbs that representation into the transcript.

Solidity splits this into:

- a generated VK payload containing digest, domain constants, fixed
  commitments, permutation commitments, G2 constants, quotient metadata, and
  optional accumulator metadata;
- runtime bytecode length/codehash checks for the VK and optional quotient
  evaluator;
- compile-time expression lowering from the Rust CS into Yul.

This is faithful under codehash pinning. It is not a runtime reconstruction of
the Rust VK or CS. If the VK bytecode, digest, constants, or external quotient
program were allowed to drift independently, the Solidity verifier could accept
proofs under inconsistent metadata.

## Master Gate Equation Evaluation

Rust evaluates gate expressions dynamically through `Expression::evaluate`,
using closures for fixed, advice, instance, challenge, negation, sum, product,
and scaling. `partially_evaluate_identities` then chains:

- gate identities;
- permutation identities;
- lookup/logup identities;
- trash identities.

Solidity pre-lowers this into codegen blocks:

- `Evaluator::gate_computations_tagged`;
- `Evaluator::permutation_computations`;
- `Evaluator::lookup_computations`;
- `Evaluator::trashcan_computations`;
- `QuotientNumeratorBlock.yul` or an external quotient evaluator.

The algebra is the same, but Solidity uses structural optimizations:

- common-subexpression elimination;
- special-case recognition for helper expressions such as pow5 and 7-limb
  decomposition;
- prefix/suffix product tricks for lookup helper evaluations;
- selector bucket accumulation instead of proving simple selector evals.

These are code-generation changes, not protocol changes, assuming the generated
program is pinned to the same CS.

## PCS And Batching

Rust `KZGCommitmentScheme::multi_prepare` does the following:

1. Optionally appends dummy queries.
2. Samples `x1` and `x2`.
3. Constructs and sorts intermediate point sets.
4. Folds commitments and evaluations into `q_com` and `q_eval_set` using
   powers of `x1`.
5. Reads `f_com`.
6. Samples `x3`, optionally truncating it.
7. Reads `q_evals`.
8. Computes `f_eval`.
9. Samples `x4`.
10. Computes `final_com`, `v`, and the final `DualMSM`.
11. Reads `pi`.

Solidity mirrors this in `src/codegen/pcs.rs` and the generated Yul, with these
implementation differences:

- rotations are precomputed and laid out in memory;
- intermediate sets are simulated at codegen time;
- `q_eval_set` and `q_com` traces are materialized in optimized memory slots;
- `f_eval` is computed via direct Lagrange-at-`x3` formulas rather than
  constructing an interpolation polynomial;
- final commitment accumulation is fused into one MSM;
- identity point terms are skipped where safe;
- `truncated-challenges` handling masks the challenge/powers in the same way as
  the Rust feature-gated verifier.

The batching algebra is faithful when the Rust and Solidity feature flags match.
Feature mismatches change the proof layout and challenge algebra.

## Final Pairing Check

Rust constructs:

- `left = pi`;
- `right = final_com - v * G + x3 * pi`;

and checks the KZG pairing equation through `DualMSM::check`.

Solidity computes the same two G1 values. The final call is swapped at the
template boundary because the Solidity helper checks `(arg0, G2)` and
`(arg1, -sG2)`. This is algebraically equivalent to the Rust equation.

## IVC Carried Accumulator Check

The carried proof accumulator pairing check is not part of
`midfall/proofs/src/plonk/verifier.rs`. It is Solidity-generator wrapper logic
layered on top of the PLONK verifier.

The relevant pieces are:

- `AccumulatorEncoding` in `src/codegen/mod.rs`;
- accumulator metadata in the generated VK;
- decoding helpers in `templates/Halo2Verifier.sol`;
- final accumulator batching in `templates/Halo2Verifier.sol`.

The current supported accumulator shape is a fully collapsed public accumulator
encoded as 7 limbs of 56 bits per coordinate, with shifted coordinate packing.
The template reconstructs EIP-2537 coordinates from public instance limbs and
uses the final pairing precompile to batch-check the carried accumulator
equation together with the KZG equation.

The current working tree contains an important hardening change in
`templates/Halo2Verifier.sol`: decoded accumulator LHS/RHS points are routed
through G1MSM even on identity, zero-scalar, and one-scalar paths. That prevents
malformed public accumulator points from being erased before EIP-2537 validates
them.

The accumulator check samples:

```text
alpha = keccak(domain || KZG rhs/lhs || accumulator rhs/lhs) mod r
```

then adds `alpha * accumulator_rhs` and `alpha * accumulator_lhs` into the
existing KZG pairing inputs. This is a sound random linear combination of the
two pairing equations, assuming the public inputs are bound by the surrounding
application and the accumulator encoding metadata matches the generated
verifier.

Because this check is extra Solidity wrapper logic, the Solidity verifier is
best described as:

```text
Rust PLONK verifier, specialized and lowered to Solidity
+ IVC carried accumulator post-check
```

not exactly the same function as Rust `prepare` / `multi_prepare`.

## Main Caveats

1. Generic committed instance commitments are unsupported. Solidity assumes the
   committed instance commitment is the identity point.

2. Generic instance-column shapes are unsupported. The generator validates
   exactly one committed instance column and one non-committed instance column.

3. Rotated non-committed instance queries are unsupported.

4. Multi-proof verification is not represented generically. The codegen targets
   the single-proof shape.

5. The on-chain verifier trusts pinned VK bytecode and quotient bytecode. The
   transcript absorbs the VK digest as Rust does, but runtime constants are not
   rederived from first principles.

6. The Solidity proof format is not the native Rust proof format. The repacker
   is critical: Rust consumes compressed G1 points and native scalar encoding;
   Solidity consumes EIP-2537-compatible uncompressed G1 words and big-endian
   scalars.

7. Curve and subgroup validation relies on EIP-2537 precompiles. The transcript
   can absorb point bytes before the corresponding precompile operation rejects
   malformed points, although final success remains gated on precompile success.

8. Feature mismatches such as `truncated-challenges` or
   `outer-fewer-point-sets` break equivalence.

## Evidence And Test Coverage

Existing tests provide strong evidence for the current supported profile:

- valid proof/native prepare and Solidity acceptance tests in `src/test.rs`;
- Rust/Solidity trace-equivalence tests in `src/test.rs`;
- required protocol coverage checks in `src/test.rs`;
- IVC Solidity tests in `tests/ivc_keccak_solidity.rs`, including bad
  accumulator packing and malformed accumulator point cases;
- accumulator schema/metadata/packing tests in `src/codegen/mod.rs`.

This status note is based on static source mapping. The suite was not rerun as
part of this pass.

## Bottom Line

For the pinned Midfall profile, the Solidity verifier is structurally and
algebraically faithful to the Rust verifier. It follows the same operation order
through quotient evaluation, linearization, KZG batching, and the final pairing
check.

It should not be treated as a generic Halo2/Midfall verifier. Its soundness
argument depends on the narrow supported proof shape, exact feature matching,
correct proof repacking, VK/quotient codehash pinning, and the extra IVC
accumulator wrapper semantics being the intended application semantics.
