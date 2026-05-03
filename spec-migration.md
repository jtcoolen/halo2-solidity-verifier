## Scope

Migrate the codegen-based Solidity verifier in `/Users/Julien.Coolen/halo2-solidity-verifier-exp` to consume `midnight-proofs` (path: `../midfall/proofs`) instead of vendored halo2-proofs v0.4. Target a single end-to-end success: verifying the existing `proof.bin / vk.bin / instance.be` fixtures at `/Users/Julien.Coolen/midfall/proofs/solidity-verifier/fixtures/poseidon/` produced by the keccak-branch poseidon example.

This is a multi-layer rewrite. The halo2-proofs v0.4 verifier and midnight-proofs verifier differ on at least these axes:

| Layer                  | halo2-proofs (current target)              | midnight-proofs (new target)                                       |
|------------------------|--------------------------------------------|--------------------------------------------------------------------|
| Lookup arg             | Halo2 grand-product lookup                 | LogUp (multiplicities + per-chunk helpers + accumulator)           |
| Trash arg              | --                                         | trash::Argument (selector + constraint exprs + single Z eval)      |
| PCS                    | BDFG21 / GWC19 (single nu + W openings)    | Midnight multi-prepare (x1, x2, f_com, x3, q_evals, x4, pi)        |
| Transcript hash        | Keccak256, raw byte concat + 0x01 cont     | Keccak256 with domain sep + PREFIX_COMMON/CHALLENGE + 64-byte squeeze + uniform-bytes reduction |
| G1 in transcript       | Uncompressed EIP-2537 padded (128 bytes)   | Compressed BLS (48 bytes)                                          |
| Verifier flow phases   | advice -> theta -> lookup_perm -> beta/gamma -> perm_z -> y -> quotient -> x -> evals | advice/challenges -> theta -> mults -> beta/gamma -> perm_z -> lookup_helpers/acc -> trash_challenge -> trashcans -> y -> quotient -> x -> evals |
| Permutation product    | At each rotation                           | sets, with per-set queries (cur, next, last)                       |
| Number of advice phases| Per ConstraintSystem::phases               | Same shape; midnight-proofs builds on halo2 v0.4 here              |
| committed-instances    | --                                         | feature flag (we'll keep nb_committed_instances=0 for poseidon)    |

## Layered execution plan

I'll deliver the migration in N self-contained steps, committing each so we can ship-and-iterate. Per step I'll re-run `cargo check` and the relevant tests.

### Step 1 - Dependency switch + minimal type rebind
- Replace vendored `halo2_proofs/halo2_middleware/halo2_backend` with `midnight-proofs = { path = "../midfall/proofs", features = ["keccak-transcript"] }` and `midnight-curves = "0.2.0"`.
- Drop `halo2curves` (midnight-curves carries BLS12-381 directly).
- Rebind everywhere we use `halo2_proofs::halo2curves::bls12381::*` to `midnight_curves::*` (Fq, G1Affine, G1Projective, Bls12).
- Rebind `VerifyingKey<bls12381::G1Affine>` to `VerifyingKey<midnight_curves::Fq, KZGCommitmentScheme<Bls12>>`, `ParamsKZG<bls12381::Bls12381>` to `ParamsKZG<Bls12>`.
- Move `vendor/halo2/` out of the build path (keep on disk, not in Cargo).
- Outcome: `cargo check` red until later steps; we get the type universe pinned.

### Step 2 - Transcript replacement
- Throw away the current `src/transcript.rs` (writes uncompressed EIP-2537 G1, single-keccak squeeze).
- Implement a `Keccak256VerifierTranscript` matching `midnight_proofs::transcript::CircuitTranscript<Keccak256>` byte-for-byte:
  - init: `Keccak256::new().update("Domain separator for transcript")`
  - common(input): hasher.update([1u8]); hasher.update(input)
  - common(G1): compressed 48-byte encoding (`<G1Projective as GroupEncoding>::to_bytes`)
  - squeeze: clone+update([0])+finalize() || clone+update([1])+finalize() -> 64 bytes; reseed hasher with those bytes.
  - sample Fq: `from_uniform_bytes(64)` (which is `LE_lo + LE_hi * 2^256 mod r`).
- Mirror this in Yul (see Step 5).

### Step 3 - ConstraintSystemMeta rewrite
- `src/codegen/util.rs::ConstraintSystemMeta::new` currently inspects halo2_proofs' lookups; replace its lookup section with midnight-proofs' `cs.lookups()` (BatchedArgument with chunks, helpers, multiplicities).
- Add a trashcan section: `cs.trashcans()` (Argument with selector + constraint expressions).
- Track `num_committed_instances` (keep at 0 for poseidon); track `cs.num_simple_selectors()` (midnight-proofs filters fixed evals on this).
- New per-row counts: `lookup_chunks_per_arg[]`, `trashcan_count`, `permutation_chunks` (=cols.div_ceil(degree-2)).
- `proof_len` calculation now needs: advices, multiplicities, perm prod commitments, lookup helpers + accumulators, trashcans, quotient limbs, evals (committed-inst evals + advice + fixed-non-simple + perm-common + perm-set + lookup-evals + trash), f_com, q_evals (one per point set), pi.

### Step 4 - Evaluator rewrite (partial-eval)
- `src/codegen/evaluator.rs` currently emits Yul for halo2 lookup constraints. Replace `lookup_computations` with a logup emitter that writes:
  - For each lookup (per proof): boundary `(l_0 + l_last)*Z`
  - Per chunk: `h(x) * prod_j(f_j(x)+beta) - sum_j prod_{k!=j}(f_k(x)+beta)` where each `f_j` is theta-compressed
  - Accumulator: `(Z_next - Z - selector*sum_h)*(t+beta) + m` times `(1 - l_last - l_blind)`
- Add `trashcan_computations`: per trashcan, `compress_constraints(theta) - (1-q)*trash_eval`.
- Gate emitter unchanged shape, but now reads through midnight-proofs `Expression`.

### Step 5 - PCS emitter rewrite
- Replace `src/codegen/pcs.rs` with a `multi_prepare` emitter:
  - `construct_intermediate_sets`: bucket queries by point sets (in order: advice rotations, perm cur/next/last, lookup x/x_next, trashcan x, fixed rotations, perm common at x, lin com at x).
  - `q_coms`: per set, MSM-fold commitments by `x1` powers
  - `q_eval_sets`: per set, eval_set inner product with `x1` powers
  - Sort by ascending point-set cardinality (matches midnight-proofs `(len, i)` total order)
  - Read `f_com` from proof
  - Read `len(point_sets)` `q_evals` at `x3`
  - Compute `f_eval` via Horner over reverse(point_sets) using `lagrange_interpolate(points, evals)` evaluated at `x3` (Yul: precompute `den = prod_i (x3 - point_i)`, then `(proof_eval - r_eval) * den_inv`)
  - Final commitment = `MSM(q_coms[0], 1) + MSM(q_coms[i], x4^i) + MSM(f_com, x4^(len))`
  - Final eval = `inner_product(q_evals, x4_powers) + f_eval * x4^len`
  - Read `pi`. PAIRING_LHS = pi. PAIRING_RHS = (final_com - v*G1) + x3*pi.

### Step 6 - Yul template rewrite (Halo2Verifier.sol)
- Replace transcript helpers (`squeeze_challenge`, `squeeze_challenge_cont`, `read_g1_point`) with new midnight-proofs equivalents:
  - `read_g1_compressed`: read 48 bytes, hash compressed bytes into transcript, then call modexp+sqrt to expand to 128-byte EIP-2537 form for arithmetic.
  - `squeeze_challenge_64`: emit two `keccak(state || PREFIX_CHALLENGE || 0x00)` and `keccak(state || PREFIX_CHALLENGE || 0x01)` calls, concat to 64 bytes, reduce via `(lo + hi*2^256) mod r`. Reseed state with the 64 bytes.
- Add LogUp loops in the verifier flow:
  ```
  for each proof: read num_lookups multiplicities (G1 each)
  squeeze beta, gamma
  for each proof: read perm_chunks commitments
  for each proof: for each lookup: read num_chunks helpers + 1 accumulator
  squeeze trash_challenge
  for each proof: read num_trashcans commitments
  squeeze y
  ```
- Read evaluations in midnight-proofs order (committed instance > advice > fixed-non-simple > perm-common > perm-set > lookup > trash).

### Step 7 - VK template (Halo2VerifyingKey.sol)
- Add new VK constants: `cs_degree`, `num_simple_selectors`, `num_logup_lookups`, `lookup_chunks[]`, `num_trashcans`, `permutation_chunks`, `permutation_cols`.
- Embed permutation column metadata (per-column kind + query index).
- Embed gate/lookup/trashcan expression bytecode (NEW: we'll need a small bytecode interpreter, not a per-gate Yul emitter, OR continue with Yul-emitting if we're willing to spend the tokens). My strong recommendation: keep Yul-emitting (current architecture) for poseidon and only embed the few cs scalars we need; lookups/trashcans become Yul-emitted expression evals just like gates today.

### Step 8 - Verification driver
- New example/test (ideally `examples/poseidon_verify.rs`) that:
  1. Reads `proof.bin`, `vk.bin`, `instance.be` from the midfall fixture dir.
  2. Reconstructs `VerifyingKey` via `VerifyingKey::from_bytes` (or `read_from_cs`) using the same `ZkStdLib`/`PoseidonExample` `ConstraintSystem` shape.
  3. Calls `SolidityGenerator::new(...).render(...)` to produce Halo2Verifier.sol.
  4. Compiles via `compile_solidity` (already wired through `solc`).
  5. Deploys + calls `verifyProof(proof_padded, [instance])` on revm with the Prague EVM.
  6. Asserts true.
  7. Also runs `midnight_proofs::plonk::prepare(...)` on the same proof and asserts it succeeds (cross-check).

### Step 9 - Soundness checks
- Fixture-driven negative tests (re-using existing `adversarial_fixtures.bin`):
  - Mutated proof bytes -> reject
  - Mutated public input -> reject
  - Mutated VK -> reject (codehash pin)
  - Wrong commitment ordering -> reject

## Risks / open questions

- **Fixture ConstraintSystem reconstruction.** `VerifyingKey::from_bytes` requires the matching `Circuit` type. For the poseidon example that means we'd need to import `midnight_zk_stdlib::PoseidonExample` (the dev dep transitively pulls midnight-circuits). I'll add it as a dev-dep alongside midnight-zk-stdlib. The fixture vk.bin was produced by the keccak-branch generate_ivc / generate.rs binaries on `verifier-contract`; if its serde format has drifted on `keccak`, I'll regenerate it from the live poseidon.rs example as part of Step 8.

- **Compressed G1 decompression in Solidity.** EIP-2537 precompiles consume *uncompressed* form, so before any `G1MSM`/`G1ADD` we need to decompress 48-byte BLS12-381 points in Yul. This requires a 381-bit modexp (sqrt) using `modexp` precompile (0x05) over `(lo, hi)` halves. The verifier-contract branch already has a working implementation (`_g1CompressedToEip2537`). I'll port that to Yul (~200 lines) as a helper.

- **Order of magnitude.** This is a multi-day rewrite. I'll commit each step so progress is checkpointable. End-to-end verification of the poseidon fixture inside a single session is unlikely; what's achievable in one pass is Steps 1-3 (dep + transcript + cs meta) with `cargo check` green and a unit test pinning the new transcript byte-for-byte against a midnight-proofs round-trip.

## What I'll deliver in this first session

If you approve, I'll execute Steps 1-3 in this session (dep switch + transcript + ConstraintSystemMeta), commit the result, and write a follow-up plan for Steps 4-9 in a `MIGRATION.md`. End-to-end fixture validation (Step 8) will require a follow-up session.

If you'd rather I attempt all of it in one pass even at the cost of leaving compile errors in some files (so you can review the architecture in one go), I'll do that instead -- pick from the options below.
