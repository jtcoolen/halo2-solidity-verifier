# Halo2 BLS12-381 Solidity Verifier — Optimisation Plan

Baseline (Poseidon fixture, k=6, ZkStdLib, midnight-proofs multi-prepare PCS,
3 point sets, 19 G1 commitments + f_com + pi):

```
Poseidon proof verified on-chain in 1 589 076 gas
```

Most of that 1.59 M is sitting in the way the verifier issues **single-pair
G1MSMs in a Horner loop**. Below is a ranked list of optimisations with rough
gas estimates.

## EIP-2537 G1MSM cost reminder

```
single-pair  22 500
2-pair       28 500   (vs 45 000 if split)
4-pair       40 500   (vs 90 000)
8-pair       64 500   (vs 180 000)
16-pair      112 500  (vs 360 000)
```

The same fold done as one k-pair MSM is roughly half the gas of the same
fold done as k single-pair MSMs.

---

## 1. Batch every Horner fold into a single multi-pair G1MSM
**Biggest win: ~500-600 kg saved**

The current emitter does this everywhere:

```yul
ec_mul_acc(success, scalar)     // 22 500
mstore(0x180, ...)              // stage next point at TMP
ec_add_acc(success)             // 600
```

That's 44 × 22 500 = ~990 kg today. The exact same computation fits a
single G1MSM call per logical fold:

| fold | pairs | now | batched | saved |
|---|---|---|---|---|
| quotient limbs (4) | 4 | 92 kg | 40 kg | 52 kg |
| simple-selector adds | 4 | 92 kg | 40 kg | 52 kg |
| PCS multi-prepare set #1 | ~12 | 270 kg | ~95 kg | 175 kg |
| PCS multi-prepare set #2 | ~10 | 225 kg | ~85 kg | 140 kg |
| PCS multi-prepare set #3 | ~8 | 180 kg | ~70 kg | 110 kg |
| random-combine LHS/RHS | 2 × 1 | 45 kg | 2 × 22.5 kg | 0 |
| **subtotal** | | | | **~530 kg** |

Concretely: replace `ec_mul_acc` / `ec_add_acc` chains with a helper that
lays out `[(scalar, point), …]` contiguously in memory and issues one
staticcall at `0x0c`. Pre-compute the Horner scalars in Fr first
(each scalar is one `mulmod`, ~5 gas), then dispatch.

This is the highest-leverage change and is contained inside the Yul
emitter — the Horner loop turns into a scalar-array build + one
staticcall.

## 2. Fold `(1 − xⁿ)` into the pre-computed scalars
**~22 kg saved**

Today there's a standalone `ec_mul_acc(success, one_minus_x_n)` call.
That's a full 22.5 kg G1MSM just to apply a Fr factor. Multiply it into
every quotient/selector scalar before staging and drop the call.

## 3. Combine `random_combine` LHS + RHS into one MSM
**~16 kg saved**

`ACC_LHS, PAIRING_LHS` (and the RHS pair) can be folded with the random
challenge as one 2-pair MSM each, instead of `mul + add` × 2.

## 4. Pre-compute scalars off-chain if the verifier accepts hints
**~50 kg saved**

The Horner scalars `[1, x, x², …, xᵏ]` are deterministic from the public
challenges. They could be passed as calldata hints (with an on-chain
consistency check via one or two `mulmod`s plus a final `addmod` of
`Σ scalarᵢ · xⁱ` against a known marker). This trades ~50 calldata words
(~1.6 kg) for ~50 kg of avoided `mulmod` chains. Only worth doing if the
surrounding PCS layout supports it.

## 5. MCOPY the G2 / scratch staging
**Status: applied (Step 8/E). Saved ~1.5 kg measured.**

`ec_pairing` had two `for i in 0..8 { mstore(...) mload(...) }` loops to
copy the two G2 points into the precompile input scratch, plus two
4-line G1 mstore chains. Cancun ships MCOPY (`0x5e`); each loop is now
one `mcopy(dst, src, 0x100)` and each G1 chain is `mcopy(dst, src,
0x80)`. Same trick applied to PCS Block 5/6 EC-point staging
(q_com seed, F_COM, FINAL_COM, PAIRING_LHS/RHS, G1_BASE, PI).

Measured saving was lower than the original 5–10 kg projection (1,499
gas) because solc-via-ir was already folding many of the
mstore-then-mload pairs into stack locals; the visible win comes from
the patterns where the round-trip crossed a precompile call boundary
(which solc cannot fold).

## 6. Drop pairs whose scalar is zero
**0-30 kg, depends on circuit**

If any precomputed Horner scalar is zero (shouldn't be for honest proofs
but happens after the 1-xⁿ fold trick), skip the pair. EIP-2537 charges
per pair, so each skipped pair saves 12 kg.

## 7. Bump `--optimize-runs` back up
**~30-60 kg saved (runtime)**

`compile_solidity` forces `--optimize-runs=1` so 21+ inline `decompress_g1`
helpers don't blow EIP-170 (24 kB). If we move `decompress_g1` into a
tiny *library contract* and `delegatecall` to it, we can:

- ship the verifier with `--optimize-runs=200` (or even default 200),
  saving the per-call inlining penalty,
- amortize `decompress_g1` across all 21 sites.

Tradeoff: 13 `delegatecall`s (~700 each = ~10 kg back) vs ~30-60 kg
runtime savings. Net positive.

## 8. Reuse PCS scratch slots between sets
**~5-15 kg saved**

The 44

```yul
mstore(0x180, …)
mstore(0x1a0, …)
mstore(0x1c0, …)
mstore(0x1e0, …)
```

blocks pay for redundant memory expansion. Once we batch into one MSM
(#1), the staging area becomes a single large strip and the per-pair
`mstore` chain disappears entirely.

---

## Realistic projection

| variant | gas |
|---|---|
| today | 1 590 kg |
| + #1 (batched MSMs) | ~1 060 kg |
| + #2 (fold 1-xⁿ) | ~1 040 kg |
| + #3 (random-combine batched) | ~1 020 kg |
| + #5 (MCOPY G2 + staging) | ~1 010 kg |
| + #7 (decompress_g1 library, optimize-runs=200) | ~960 kg |

A **~600 kg reduction (~38%) is realistic** without touching the math,
just by batching MSMs and tightening memory copies. That puts the
verifier in the ~960 kg territory, which is roughly the EIP-2537 floor
for this circuit shape (3 point sets × ~10 commits + 3-pair pairing).

The single highest-leverage change is **#1 (batch G1MSMs)** — a contained
codegen-side change in the Yul emitter (the Horner loop becomes a
scalar-array build + one staticcall).

---

## Realised savings (Poseidon fixture, midfall branch)

| step | description | gas after | delta | cumulative |
|---|---|---:|---:|---:|
| 0 | baseline (single-pair Horner everywhere) | 1 589 076 | — | — |
| 1 | quotient fold + (1−xⁿ) + simple-selector adds → one (k+n_sel)-pair MSM (template-only) | 1 558 817 | −30 259 | −30 259 |
| 2 | PCS Block 3 per-set q_com fold → per-set m-pair MSM at MSM_SCRATCH=0x6100 (codegen) | 1 482 958 | −75 859 | −106 118 |
| 3 | PCS Block 5 final_com → (n_sets+1)-pair MSM | 1 488 783 | +5 825 | reverted |
| 4 | PCS Block 6 PAIRING_RHS → 3-pair MSM | (above included) | +0 | reverted |
| 5 | drop on-the-fly compressed encoding: hash uncompressed 128B verbatim in transcript (patch midnight-proofs `Hashable<Keccak256>::to_input` + EVM `common_uncompressed_g1`) | 1 475 536 | −7 422 | −113 540 |
| 6 | unroll `byte_reverse_32` (31 of 32 iterations straight-line + 1-trip guard loop). Each of the ~184 call sites drops from ~700 gas (32-iter shift loop body) to ~140 gas (32 byte-extract + or-shl ops). The trailing 1-trip loop is required to keep solc from inlining the entire 32-step body at every call site under `--via-ir`; full inlining triggers a pathology where the verifier consumes the full block gas limit. | 997 438 | −478 098 | −591 638 |
| 7 (B) | PCS Block 4 Lagrange interpolation: replace n separate `scalar_inv` calls per point set with one Montgomery batch invert (`{dx_j, lbasis_j}` for j=0..m, n=2m). Per set: 1 modexp + 3n−3 muls vs n modexp; `den_inv` becomes a free `prod_j dx_inv_j`. Soundness: dx_j non-zero by Fiat-Shamir, lbasis_j non-zero by `construct_intermediate_sets` de-dup. | 982 229 | −15 173 | −606 811 |
| 8 (E) | MCOPY EC-point staging: replace 4-line `mstore(N, mload(M))` chains and 8-iter G2 mstore loops with `mcopy(dst, src, 0x80)` / `mcopy(dst, src, 0x100)` calls in `ec_pairing` (G2_BASE + NEG_S_G2_BASE + 2 G1 inputs) and PCS Blocks 5 & 6 (q_com seed, F_COM staging, FINAL_COM persist, PAIRING_LHS/RHS staging). | 980 730 | −1 499 | −608 310 |
| 9 (D) | hoist `mload(add(ROT_POINTS_MPTR, k*0x20))` to `rot_pt_i` stack locals at the top of the f_eval block. Each rotation point is referenced O(m²) times per set across `dx_j` and `lbasis_j`; solc-via-ir cannot CSE-fold across the inline `scalar_inv` precompile boundary. | 980 125 | −605 | −608 951 |
| 10 (H1) | MCOPY q_com fold per-commit point staging in PCS block 3 (replaces 4-mstore chains for each commit's 4-word point with `mcopy(stage, src, 0x80)`). Hits all 40 commits across 3 sets (m=33+5+2) plus the m=1 short-circuit and the post-staticcall MSM result writeback. | 955 224 | −24 901 | −633 852 |
| 11 (H2) | Roll PCS block 2 (x1 powers) emission from 32 unrolled `mulmod+mstore` pairs into a Yul `for` loop. Direct saving cp18 −22 kg + downstream cp19 re-scheduling −26 kg from solc-via-ir reallocating registers across the (now smaller) basic block. | 907 030 | −48 194 | −682 046 |

**Net result: 1 589 076 → 907 030 gas (−682 046, −42.9%) on the Poseidon
fixture.** With current per-section breakdown: PCS 441 kg (49%), pairing
103 kg (11%), quotient eval 124 kg (14%), linearization MSM 72 kg (8%),
transcript+evals 80 kg (9%), other 87 kg (10%).

Findings:

- **Step 1** (template) absorbed projections #1 (quotient fold), #2
  (1−xⁿ fold), and the simple-selector ec_add_acc chain into a single
  staticcall. Saved 30 kg as predicted.
- **Step 2** (codegen, PCS Block 3) is where the bulk of the saving
  lives: set 0 alone has 33 commits, and 33 single-pair G1MSMs collapse
  into one 33-pair MSM. The first attempt staged at 0x00 and clobbered
  the VK region (VK_MPTR=0x0ee0..0x2040, set 0 needs 0x14a0 bytes).
  Relocating the staging to MSM_SCRATCH=0x6100 (above scalar_inv's
  0x6000..0x60c0 scratch) fixed it.
- **Steps 3 & 4 reverted**: for n_sets=3 (Poseidon), the 4-pair and
  3-pair MSMs cost more than the single-pair chain they replace once
  staging mstore overhead is counted. The break-even is around 5 pairs
  for these blocks. The current chain-style code seeds the accumulator
  with q_com[0]/final_com directly (no MSM call), which makes the
  effective comparison `(n-1) × 22.5 kg + (n-1) × 0.5 kg` vs
  `n-pair MSM + 4 × mstore_seed`.
- The projection table assumed all batching was uniformly beneficial;
  in practice multi-pair MSM only beats the single-pair chain at
  pair-count ≥ 4 with a non-trivial seed.

### Where the remaining gas lives

After Step 5 the bottleneck shifted to:

- `decompress_g1` calls (still ~13 sites, ~80 kg total per audit)
- `scalar_inv` Fermat-style ladder (~30 kg per call, multiple sites)
- The 3 G1MSM-1 + G1ADD chain in Block 5 (final_com fold, ~75 kg)
- Pairing precompile itself (~120 kg, can't be reduced)
- ~184 `byte_reverse_32` 32-iteration loops embedded in calldata reads
  for advice, fixed, instance, and Q_EVAL (Step 6 attacked this).

The next-highest-leverage item was originally projected to be **#7
(decompress_g1 library + --optimize-runs=200)** at 30–60 kg, but
investigation showed:

- `decompress_g1` was already removed in Step 5 (the on-the-fly compressed
  encoding is gone).
- A full sweep of `--optimize-runs ∈ {1, 50, 200, 1000, 100000}` showed
  only ~2 kg sensitivity — `--via-ir` already optimises aggressively
  regardless of the runs setting.

The actual top item turned out to be **byte_reverse_32 itself** (Step 6),
which was emitted unconditionally for every Calldata-backed Word reference
and ran a 32-iteration shift loop at each call site (~700 gas/call ×
~184 calls = ~129 kg observed plus secondary effects). Unrolling 31 of
the 32 iterations into straight-line code dropped the per-call cost to
~140 gas and saved 478 kg — far above the 30–60 kg projection for
the now-irrelevant Item #7.

---

## Cross-cutting change: uncompressed transcript hashing (Step 5)

**Status:** applied. Saves ~7.5 kg on the Poseidon fixture.

The previous emitter hashed each G1 commitment in its 48-byte ZCash
*compressed* encoding into the keccak transcript, computing the sign
bit on the fly via a 384-bit `lex(y) > lex(p − y)` ladder. We
transitioned both the prover (in `midnight-proofs`'s
`Hashable<Keccak256> for G1Projective::to_input`) and the EVM verifier
(`common_uncompressed_g1`) to hash the **uncompressed 128-byte
EIP-2537 padded form** verbatim (`x_hi || x_lo || y_hi || y_lo`,
each coord = 16 zero pad bytes + 48 BE bytes of the field element).

Wire format unchanged: proofs still carry G1 in the 48-byte compressed
encoding (`Hashable::to_bytes` / `read` are unmodified). The off-chain
`repack` step still decompresses to the 128-byte calldata form for the
EVM precompiles, just as before.

Transcript malleability is prevented by masking the 16-byte zero pad
in `_hi` words before keccak absorbtion (defeats grinding attacks
that submit non-canonical pad bytes which the EIP-2537 precompile
would only reject later in the verifier).

Files touched:

- `vendor/.../midfall/proofs/src/transcript/implementors.rs` —
  `Hashable<Keccak256> for G1Projective::to_input` returns 128 bytes
  instead of `<G1Projective as GroupEncoding>::to_bytes` (compressed).
- `src/transcript.rs::common_g1` — absorbs the same 128 bytes; the
  `common_g1_then_squeeze_matches` round-trip test pins this to
  `CircuitTranscript<Keccak256>`'s output.
- `templates/Halo2Verifier.sol::common_uncompressed_g1` — replaced a
  ~50-line sign-bit ladder with a `mstore8 + calldatacopy(0x80) + 2 ×
  mask` sequence.
- The committed-instance identity injection at the start of the
  transcript was rewritten from "0xc0 || 47*0x00" to "128 × 0x00" to
  match the new identity convention.
