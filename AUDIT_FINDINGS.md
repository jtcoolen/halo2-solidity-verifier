# Solidity Verifier Codegen Audit

**Repository:** `halo2-solidity-verifier-exp`
**Scope:** halo2 → midnight-proofs port of the on-chain KZG/BLS12-381 verifier
codegen and emitted Yul.
**Files reviewed (deep read):**

- `src/codegen/util.rs`, `memory.rs`, `protocol.rs`, `transcript.rs`,
  `generator.rs`, `pcs/gwc19.rs`, `quotient/mod.rs`, `evaluator.rs`
- `templates/Halo2Verifier.sol`, `templates/QuotientNumeratorBlock.yul`
- `docs/MEMORY_LAYOUT.md`, `docs/QUOTIENT_NUMERATOR_EVALUATOR.md`

The audit explicitly looked for the bug classes the requestor flagged
(EIP-2537 padding, transcript / hash-to-challenge mismatches, MSM index
errors, batch-invert zero handling, memory-region collisions, lookup /
permutation chunk boundaries, blinding rows, `omega_inv_to_l` exponent,
dummy-eval transcript handling, `proof_total()` ↔ calldata cursor
agreement, `num_committed_instances` boundary, panics/TODOs in the
emitted artifact, EIP-2537 precompile constants, padded-G1-loaded-as-2
issues, etc.). Each individual class was instrumented by reading the
relevant emitter, the corresponding Yul, and the supporting offset
arithmetic.

Bottom line: I did **not** find a clear, exploitable correctness bug in
the production verifier path. The codebase has clearly been hardened
since the original BN254 fork — every high-risk surface I checked
(transcript domain separation, EIP-2537 canonicality, proof-cursor
agreement, batch_invert zero check, KZG fused MSM, accumulator
randomization) lines up with the documented midnight-proofs
convention. The findings below are mostly **Suspicious / Hardening**
items where the code is correct today but the invariants are subtle
enough to be worth pinning down.

---

## Critical — None identified

I traced the highest-risk vectors end-to-end and could not find a
break:

- **Transcript domain separation.** `templates/Halo2Verifier.sol`
  (lines ~990–1100) absorbs `vk_digest`, the 128-byte zero
  `committed_pi` identity, the BE `num_instances` length scalar, then
  each BE instance, before any proof bytes. This matches the patched
  `Hashable<Keccak256> for G1Projective::to_input` in midnight-proofs
  (the previous emitter used the 48-byte ZCash compressed encoding;
  the new emitter is consistent with the patched native verifier).
- **EIP-2537 padded G1 (4 words).** Every commitment read goes
  through `common_uncompressed_g1` (lines ~480–520):
  `if shr(128, x_hi_word) { revert(0,0) }`, the BLS12-381 Fp range
  check `(hi, lo) ≤ p − 1`, and a verbatim `calldatacopy` of 0x80
  bytes into the transcript. There is no path where a 2-word load
  reaches a precompile.
- **Squeeze-to-Fr.** `squeeze_to` (~line 528) reseeds with the 32-byte
  Keccak digest and samples `mod(h0, FR_MODULUS)` exactly once per
  challenge. No truncation/length mistake (`buf_len` is reset to 32).
- **`scalar_inv` location.** `scalar_inv` (~line 340) intentionally
  uses the dead transcript region just below `VK_MPTR`
  (`p := sub(VK_MPTR, 0x100)`). The verifier never calls it before
  transcript absorption is finished, and the comment correctly
  documents that this avoids collisions with PCS scratch when the VK
  payload shrinks.
- **`batch_invert` zero check.** Production `batch_invert` (~line 540)
  rejects the input batch if the **product** is zero
  (`if iszero(gp) { ret := 0; leave }`) and short-circuits the
  singleton case via `if iszero(x) { ret := 0; leave }`. With the
  current call sites (Lagrange denominators + the GWC dummy/Lagrange
  basis Montgomery batch in `gwc19.rs`) every input is provably
  non-zero by Fiat–Shamir, so the product check is sufficient.
- **EIP-2537 precompile constants.** Constructor smoke test (line 192)
  exercises `0x0b` G1ADD, `0x0c` G1MSM and `0x0f` PAIRING_CHECK at
  deploy time and reverts on absent / size-mismatched returndata.
- **Public-accumulator pairing batch.** The `acc_pair_alpha` derivation
  (lines ~1530–1610) keccaks the full
  `domain || PAIRING_RHS || PAIRING_LHS || ACC_RHS || ACC_LHS` payload
  *after* the MSM is fully constructed, defeats the trivial
  multiplicative-cancellation attack, and falls back to `1` only when
  the digest happens to be `0` (probability ≈ 2⁻²⁵⁶).
- **Quotient VM dispatch.** `templates/QuotientNumeratorBlock.yul`
  dispatch covers `0x01..0x1e`, with `default { revert(0,0) }` on the
  inner token switches (so out-of-range token indices fail closed).
  The `q_y_inv` modexp uses a separate `q_inv_scratch =
  program.stack_mptr` from `scalar_inv`’s transcript pad, eliminating
  the previous large-VK collision risk.

---

## High — None identified

I audited the calldata cursor agreement, the EIP-2537 padded
serialization, the multi-prepare KZG (Block 5) MSM term count, the
linearization expansion of the quotient limbs and selectors, the
public-accumulator decoding and identity-flag fixup, and the dummy
eval/transcript handling. All pass the consistency checks I could
construct from the code alone.

The two items I want to flag for follow-up review are below.

---

## Medium

### M1. `cd_byte` cursor groups lookup helpers/accumulators in a different physical order than the verifier reads them

**File:** `src/codegen/util.rs:443–448`

```rust
let mut cd_byte = proof_cptr_bytes;
cd_byte += G1_BYTES * meta.advice_indices.len();
cd_byte += G1_BYTES * meta.num_lookups;            // multiplicities
cd_byte += G1_BYTES * meta.num_permutation_zs;     // perm Z
cd_byte += G1_BYTES * lookup_helper_total;         // ALL helpers
cd_byte += G1_BYTES * meta.num_lookups;            // ALL accumulators
cd_byte += G1_BYTES * meta.num_trashcans;
let quotient_limb_cd = cd_byte;
```

**File:** `templates/Halo2Verifier.sol:~1130–1150`

```yul
{%- for chunks in lookup_chunks %}
// lookup {{ loop.index0 }}: {{ chunks }} helper(s) + 1 acc
for { let end := add(proof_cptr, ... ) } lt(proof_cptr, end) { } {
    ... helpers ...
}
buf_len := common_uncompressed_g1(buf_len, proof_cptr)  // accumulator
calldatacopy(lookup_z_walk, proof_cptr, 0x80)
proof_cptr := add(proof_cptr, 0x80)
{%- endfor %}
```

The on-chain reader interleaves `helpers + acc` per lookup. The
codegen-side `cd_byte` walk above sums "all helpers, then all
accumulators". The total byte count is identical
(`G1_BYTES * (Σchunks + num_lookups)`), and `cd_byte` is only used to
derive `quotient_limb_cd` / `eval_cd`, so the **current** code is
correct.

The reason this is medium and not just suspicious: any future change
that exposes a per-lookup calldata pointer (say, to read an individual
helper commitment from calldata directly during quotient evaluation)
will compute the wrong offsets if it follows this cursor convention.
The cursor walk should mirror the actual on-chain interleaving — even
when only the running total is consumed today.

**Suggested fix:** rewrite the helper/acc accumulator as a per-lookup
loop (mirroring `templates/Halo2Verifier.sol`) so the math is locally
obvious rather than relying on commutativity of the running sum.

```rust
for &chunks in &meta.lookup_chunks {
    cd_byte += G1_BYTES * chunks;   // helpers for this lookup
    cd_byte += G1_BYTES;             // accumulator for this lookup
}
```

### M2. `ProofReadPlan::commitments` stores phase-sorted `column` indices but iterates in original-column order

**File:** `src/codegen/protocol.rs:312–318`

```rust
proof.commitments.extend(
    advice_indices
        .iter()
        .copied()
        .map(|column| CommitmentRead::Advice { column }),
);
```

`advice_indices[orig_col]` holds the **proof position** of the
original column after phase sorting, so the *value* placed in
`CommitmentRead::Advice { column }` is the proof index, but the
iteration order is the original column order, not the proof
order. Concretely with phases = `[1, 0]`:

- `advice_indices = [1, 0]`
- `proof.commitments = [Advice{column=1}, Advice{column=0}]`
  ↑ but proof slot 0 in calldata is the phase-0 column (orig col 1)
  and proof slot 1 is phase-1 (orig col 0).

So `proof.commitments[i]` does not satisfy "the column read at proof
slot i" *and* the `column` field's semantic (orig vs phase-sorted)
flips depending on viewpoint. Today this is benign because the only
consumer (`proof_total()` at line 536) just reads `commitments.len()`,
but any downstream code that iterates `proof.commitments` and
dereferences `column` will get either the wrong order or the wrong
identifier mapping.

**Suggested fix (one of):**

1. Iterate phases explicitly so the resulting vector is in physical
   proof order:
   ```rust
   for phase in 0..num_phase {
       for (orig_col, p) in cs.advice_column_phase().iter().enumerate() {
           if *p as usize == phase {
               proof.commitments.push(CommitmentRead::Advice { column: orig_col });
           }
       }
   }
   ```
2. Or change the `column` field's documented meaning to "phase-sorted
   index" and add a doc-comment + unit test pinning the contract.

---

## Suspicious / hardening

### S1. `Lagrange & instance-evaluation` block depends on `num_neg_lagranges ≥ 1`

**File:** `templates/Halo2Verifier.sol:~1295–1340`

```yul
let mptr := X_N_MPTR
let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR),
                                       {{ num_neg_lagranges }})))
if iszero(mload(NUM_INSTANCES_MPTR)) {
    mptr_end := add(mptr_end, 0x20)
}
...
let l_blind := mload(add(X_N_MPTR, 0x20))
let l_i_cptr := add(X_N_MPTR, 0x40)
for { let l_i_cptr_end := add(X_N_MPTR, {{ (num_neg_lagranges * 32)|hex() }}) }
    lt(l_i_cptr, l_i_cptr_end) { l_i_cptr := add(l_i_cptr, 0x20) } {
    l_blind := addmod(l_blind, mload(l_i_cptr), r)
}
```

Reading slot `1` (`l_blind` seed) and slot `num_neg_lagranges` (`l_0`)
both assume the loop produced at least 2 Lagrange denominators. With
the standard halo2 construction `num_neg_lagranges = blinding_factors
+ 1 ≥ 2`, so this holds in practice. But the protocol-side
`rotation_last = -(blinding_factors + 1)` is computed with no lower
bound check.

**Suggested fix:** add `assert!(meta.rotation_last.unsigned_abs() >=
1, ...)` (or `>= 2` if blinding is required) early in
`ProtocolPlan::from_constraint_system` so the codegen fails fast on
edge-case constraint systems. Equivalently, render the template only
for `num_neg_lagranges >= 2`.

### S2. Linearization formula uses `x_split = x^(n-1)` (not the more common `x^n`)

**File:** `templates/Halo2Verifier.sol:~1420–1440`,
`docs/QUOTIENT_NUMERATOR_EVALUATOR.md:~452`

```yul
let x_pow_2i := x
let x_pow_2i_minus1 := 1
for { let idx := 0 } lt(idx, k) { idx := add(idx, 1) } {
    x_pow_2i_minus1 := mulmod(
        mulmod(x_pow_2i_minus1, x_pow_2i_minus1, r), x, r)
    x_pow_2i := mulmod(x_pow_2i, x_pow_2i, r)
}
let x_split := x_pow_2i_minus1            // = x^(n-1)
let one_minus_x_n := addmod(1, sub(r, x_pow_2i), r)
```

That arithmetic is *correct* given the documented midnight-proofs
convention `linear_com = (1 − x^n) · Σ_i x^(i(n−1)) · Q_i`, but it
diverges from the upstream halo2 PSE convention `Σ_i x^(in) · Q_i`,
which is the formula most reviewers will check first. If an
auditor compares the limb scalar against a halo2-PSE reference
implementation they will see a mismatch that is not, in fact, a bug.

**Suggested fix:** add a single-line comment in
`generate_pcs_computations` (Block 5) pointing to
`midfall/proofs/src/poly/kzg/mod.rs` so the convention is
self-documenting:

```yul
// midnight-proofs splits h(x) as Σ_i x^(i*(n-1)) * h_i(x) (NOT x^(i*n)).
// Matches multiopen.rs::compute_linearization_commitment.
```

### S3. `compute_dummy_queries` panics on duplicate `(comm, rotation)` pairs

**File:** `src/codegen/pcs/gwc19.rs:194–201`

```rust
Some(_) => {
    panic!(
        "duplicate (commitment, rotation) query at index {i}: \
         compute_dummy_queries cannot run on a non-deduplicated \
         query list"
    );
}
```

This is a programmer-side invariant; it is not reachable on a
well-formed PCS query schedule. But it is an unconditional panic
inside the generator, so a future bug elsewhere (e.g. duplicate
permutation queries due to a chunk-len off-by-one) would manifest as a
generator panic at codegen time rather than a structured error.

**Suggested fix:** convert the panic into a `debug_assert!` plus a
typed `Err(...)` return, threaded through `try_new`. Same for the
`unreachable!("proof_cptr must be a literal byte offset")` in
`util.rs:439`.

### S4. `f_eval` / `v` Horner direction relies on undocumented prover convention

**File:** `src/codegen/pcs/gwc19.rs:~1100–1230` (Block 4),
`src/codegen/pcs/gwc19.rs:~1290–1320` (Block 5)

The Block 4 reverse-Horner accumulator emits

```text
f_eval = Σ_{s=0..n_sets-1} π_s · x2^s
```

and Block 5 forward-Horner emits

```text
v = Σ_{s=0..n_sets-1} q_evals[s] · x4^s + x4^{n_sets} · f_eval
```

i.e. `π_0` and `q_evals[0]` get the constant coefficient `1`. This is
the midnight-proofs `multi_prepare` convention. There is no inline
comment binding the direction to a Rust source line; a reader following
the upstream halo2 PSE GWC implementation (which folds with the highest
power on the highest-index set) will see a sign/order mismatch that is
again not a real bug.

**Suggested fix:** annotate Block 4 with the Rust source-of-truth and
add a unit test that pins `f_eval` for a 2-set, 3-set fixture against
a known reference vector.

### S5. `g1msm_gas_cap` switch caps at `k = 128`; large MSMs fall through to the default branch

**File:** `templates/Halo2Verifier.sol:~700–860`

```yul
case 128 { discount := 519 }
// EIP-2537 G1MSM gas: k * discount[k] * 12000 / 1000.
cap := add(50000, div(mul(mul(k, discount), 12000), 1000))
```

If `k > 128`, `discount` keeps the initial value `519`. The downstream
formula stays well-defined and the cap is just a *gas* cap (a too-low
cap would revert the call, not corrupt state). Today the only
≥128-term call site is the fused final MSM, whose term count is
bounded by `final_msm_shape(...)`. If a future circuit ever drives
`final_msm_terms` over 128, the cap will silently use the asymptotic
discount `519` rather than the precise table value, which can
under-estimate gas and revert valid proofs.

**Suggested fix:** either extend the table up to the realistic upper
bound, or add a debug assertion in `final_msm_shape` that the term
count is `<= 128` (with a clear panic message when it's exceeded), so
the contract is rebuilt with a larger table before deployment.

### S6. `acc_pair_alpha` zero-fallback uses `1` rather than re-hashing

**File:** `templates/Halo2Verifier.sol:~1545–1555`

```yul
let acc_pair_alpha := mod(keccak256(batch_ptr, 0x220), r)
if iszero(acc_pair_alpha) { acc_pair_alpha := 1 }
```

If the keccak digest is exactly `0 mod r`, the prover knows alpha
in advance and could craft pairing inputs that satisfy the batched
equation while individually failing. The probability is 2⁻²⁵⁶, and
the security argument is fine; an auditor will flag this as a
deterministic-low-entropy-fallback hardening point.

**Suggested fix:** in the iszero branch, re-hash with a domain
prefix (`keccak256("acc-batch-alpha-fallback" || alpha_seed)`) until
non-zero, or reject the proof. The cost is a single extra keccak in a
2⁻²⁵⁶ branch, so always-rehash is cheap.

### S7. `repack_compressed_proof` panics on malformed compressed input

**File:** `src/codegen/generator.rs:~2840`

```rust
let pt: G1Affine = Option::from(<G1Affine as GroupEncoding>::from_bytes(&comp))
    .unwrap_or_else(|| {
        panic!(
            "decompress failed at compressed[{cur}..{}]: bytes = 0x{}", ...
        )
    });
```

`repack_compressed_proof` is documented as an **off-chain** shim
(it converts the native compressed proof produced by midnight-proofs
into the EIP-2537 padded form the verifier expects). Panicking on a
malformed input is acceptable for a build/test helper, but if any
caller path ever exposes this shim to untrusted bytes (e.g. a JSON-RPC
adapter inside a relayer), the `unwrap_or_else(panic!)` pattern is a
DoS vector.

**Suggested fix:** return `Result<Vec<u8>, RepackError>` from
`repack_compressed_proof`, restrict the panicking variant to the
`#[cfg(test)]` helper, and have production callers propagate the
error.

---

## Things I checked and did NOT find an issue with

This is the deliberate "no bug here" list, recorded so the next
auditor can skip the hot paths I already burned time on:

- **`omega_inv_to_l = ω^{rotation_last}`** (`generator.rs:466`).
  `rotation_last = -(blinding_factors + 1)`. The Lagrange seed loop
  walks `ω^{rot_last}, ω^{rot_last+1}, ...`, so slot 0 holds
  `L_{rot_last}(x) = l_last`, slot `num_neg_lagranges` holds `L_0(x)`.
  Aligned with halo2 PSE.
- **Advice memory layout vs phase reordering**
  (`util.rs:514`, `Halo2Verifier.sol:~1050`).
  `advice_comms[orig] = comms_base + 4·advice_indices[orig]` and the
  Yul reader stores phase 0 advice 0 at `comms_base`, phase 0 advice 1
  at `comms_base + 4`, etc. The mapping is consistent in both
  directions for any phase permutation.
- **`Data::new` calldata cursor walk**
  (`util.rs:439–520`). Total byte count agrees with
  `transcript_buffer_words_bound` (`generator.rs:2965–3022`).
- **`construct_intermediate_sets` deduplication**
  (`gwc19.rs:~270–360`). Sets are deduplicated by the underlying
  `EcPoint` memory pointer, so the dummy-query logic that depends on
  pointer equality is well-defined.
- **EVM identity convention.** `G1_IDENTITY_MPTR` is reserved as a
  4-word region, never written. EIP-2537 (0,0,0,0) is the canonical
  point-at-infinity. The "committed instances all alias
  `G1_IDENTITY_MPTR`" pattern in `util.rs:498` matches the patched
  `committed_pi = G1::identity()` in midnight-proofs.
- **Scratch lifetimes.** `MemoryArena` (`memory.rs:~200–500`) tracks
  permanent vs phase-scoped scratch and asserts non-overlap in
  `validate()`. The PCS-fixed window
  (`rot_points`, `x1_powers`, `q_eval_set`, ...) is fixed-offset
  inside the `theta`-relative slot 52+ band, with capacity sized
  by `final_msm_shape`. No collision between batch-invert scratch and
  PCS scratch; `BATCH_INV_SCRATCH_MPTR` is allocated inside the
  scratch allocator rooted at `selector_acc_mptr`.
- **`num_committed_instances` branching.** `committed_instance_evals`
  is filtered by `q.column < nb_committed_instances`
  (`protocol.rs:340–345`), and the eval read pointer is the same
  `eval_cptr` cursor used everywhere else. No double-counting.
- **`proof_total()` agreement.**
  `protocol.rs:535` returns `commitments.len() + evals.len()`, used
  only for sanity. The actual byte-level proof length is
  `transcript_buffer_words_bound` × on-chain reads, and matches
  `repack_compressed_proof`'s output length.

---

## Recommended next steps

1. Land **M1** and **M2** with unit tests pinning the calldata
   ordering (M1) and the `column` semantics (M2). Both are mechanical
   refactors.
2. Add inline "Rust source-of-truth" comments for the items in S2 and
   S4 to make future auditors faster.
3. Convert the panics in S3 / S7 to typed errors so a generator-time
   bug surfaces as a structured failure rather than a panic in CI.
4. Extend the `g1msm_gas_cap` table beyond `k = 128` (or assert the
   bound) before any circuit pushes the fused final MSM past that
   width (S5).
5. Optional: re-hash on the `acc_pair_alpha == 0` branch (S6); the
   probability is negligible, but the cost of doing it right is a
   single keccak.

No production-blocking finding. The verifier should be safe to deploy
at the current revision, modulo the engineering hygiene items above.
