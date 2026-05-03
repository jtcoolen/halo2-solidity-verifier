# Per-section gas attribution

Measured breakdowns of the Poseidon-fixture verifier and the IVC Keccak final
verifier on the midfall branch, captured via the `solidity-gas-checkpoints`
cargo feature.
This document is the measurement counterpart to `OPTIMISATION.md`: where
that one lists *what changes are available*, this one says *which sections
are actually expensive enough to be worth changing*.

The Midnight dependencies resolve from the published midfall branch:

```
https://github.com/EYBlockchain/midfall.git#keccak
```

The benchmark needs local SRS files. The helper script below downloads missing
assets into `.srs/` by default; set `SRS_DIR` to reuse an existing directory.
The current IVC Solidity bench needs Midnight `midnight-srs-2p19` for the leaf
IVC proofs and `midnight-srs-2p20` for the final tree-decider proof.

## Running the Poseidon fixture bench

The verifier emits a LOG1 at every section boundary when compiled with
`--features solidity-gas-checkpoints`. The host-side test
(`tests/poseidon_fixture.rs::dump_gas_checkpoints`) parses those logs
into a per-section delta table.

```
cargo test --features evm,solidity-gas-checkpoints \
  --test poseidon_fixture poseidon_renders_compiles_and_verifies \
  -- --ignored --nocapture
```

Topic encoding: `(id << 248) | gas()` — `id` lives in the upper byte and
the remaining 31 bytes hold the value of `gas()` at the moment the
checkpoint runs. Each LOG1 costs ~750 gas (16 sites × 750 = 12 kg total
overhead, subtracted from the printed deltas).

The 16 checkpoints sit at semantic section boundaries — see
`templates/Halo2Verifier.sol` (search for `gas_checkpoint(`).

## Running the IVC Keccak final bench

The IVC bench proves two independent one-step IVC Poseidon hash-chain leaves,
then proves a final Keccak-transcript tree decider that verifies both leaf
proofs and fully collapses the carried IVC proof accumulator. It renders
separate verifier/VK contracts for that decider proof, compiles them with
solc, deploys them in Prague-spec revm, and verifies the final proof end to
end. It self-skips unless `HALO2_SOLIDITY_RUN_IVC_BENCH=1` is set because it
is slow.

Recommended runner:

```
scripts/run_ivc_bench.sh
```

The default runner enables fewer point sets for both the recursive in-circuit
verifier and the outer Solidity-facing decider proof. To keep the recursive
verifier on fewer point sets but benchmark the outer decider proof without
dummy PCS evals:

```
scripts/run_ivc_bench.sh --no-outer-fewer-point-sets
```

Compile-only preflight:

```
scripts/run_ivc_bench.sh --check-only
```

Use an existing SRS directory or also run the off-circuit Midfall twin:

```
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
  scripts/run_ivc_bench.sh --native-midfall
```

Manual compile command:

```
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
cargo test --release \
  --features evm,truncated-challenges,in-circuit-fewer-point-sets,outer-fewer-point-sets,solidity-gas-checkpoints \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  --no-run
```

Manual full gas-checkpoint command:

```
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
cargo test --release \
  --features evm,truncated-challenges,in-circuit-fewer-point-sets,outer-fewer-point-sets,solidity-gas-checkpoints \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --nocapture
```

The test writes generated artifacts to:

```
target/ivc-keccak-solidity-dump/
```

Useful follow-up commands:

```
cat target/ivc-keccak-solidity-dump/contract-sizes.txt
ls -lh target/ivc-keccak-solidity-dump
```

### IVC Keccak final run, 2026-04-29

This historical measurement is the previous one-step SHA aggregation baseline.
Re-run the bench after fetching `midnight-srs-2p20` to populate current
Poseidon-chain tree decider numbers.

Run shape:

- 1 inner SHA proof: 0.59 s.
- IVC setup: 47.82 s.
- IVC final Keccak step: 64.22 s.
- Native `verify_final`: 10.01 ms.
- Compressed final proof: 9,952 bytes.
- Repacked EIP-2537-padded proof: 12,672 bytes.
- Calldata: 14,980 bytes, with 68 public-input field elements.

Contract size summary with `SOLC_OPTIMIZE_RUNS = 1` and no CBOR metadata:

> Historical inline-verifier baseline. Re-run `scripts/run_ivc_bench.sh` to
> refresh the contract sizes for the current circuit/VK.

```
Halo2Verifier.sol source bytes: 426,899
Halo2VerifyingKey.sol source bytes: 27,237
Halo2Verifier creation bytecode bytes: 53,571
Halo2VerifyingKey creation bytecode bytes: 5,925
Halo2Verifier deployed runtime bytes: 53,325
Halo2VerifyingKey deployed runtime bytes: 6,752
total deployed runtime bytes: 60,077
```

Gas summary:

```
total tx gas_used       = 1,617,543
real section work       = 1,374,422
checkpoint overhead     = 15,750 (21 checkpoints x 750 gas)
```

Largest sections:

| section | gas | note |
|---|---:|---|
| PCS block 3 set 0 q_com/q_eval fold | 494,377 | biggest PCS fold |
| evaluations + transcript tail | 248,795 | eval reads, challenge squeezes, proof accumulator prep |
| linearization-commitment MSM | 119,469 | verifier linearization commitment |
| quotient evaluation | 107,966 | Fr arithmetic |
| public accumulator pairing check | 105,329 | trivial one-step outer accumulator; skips identity/zero-scalar MSM calls |
| final proof ec_pairing | 103,168 | final proof/KZG accumulator pairing after PCS inputs are already prepared |
| Lagrange + instance evaluation | 55,002 | public instance evaluation |

The application-level accumulator carried in the decider state is now fully
collapsed over the inner verifier's fixed bases: it exposes only
`lhs point, lhs scalar = 1, rhs point, rhs scalar = 1`. The outer IVC
self-accumulator still follows Midfall's variable-base-collapsed shape, because
its fixed bases are the self VK; for the one-step final proof it is trivial, so
the Solidity verifier detects the packed identity encoding and skips
identity/zero-scalar MSM precompile calls.

## Measured breakdown (Poseidon fixture, k=6, midfall HEAD)

The breakdown below was captured **after** Step 6 + Optimisations B/D/E
(the `byte_reverse_32` 31-iter unroll plus PCS-block tuning, see
OPTIMISATION.md). The Step-5 baseline (1,475,560 gas before any of
this) is preserved as a comparison column — every section that
touched calldata-backed evals saw 5-30× reductions when Step 6 dropped
the per-call cost of `byte_reverse_32` from ~700 gas to ~140 gas, and
the PCS block saw a further 17 kg cut from B/D/E.

### Step 6 + B/D/E + H1/H2 (current HEAD)

```
=== gas-checkpoint breakdown (per-section deltas) ===
  id        gas_left         delta        %  section
   1      49,916,089             -        -  entry (before VK loading)
   2      49,913,842         1,497     0.2%  VK loading
   3      49,910,536         2,556     0.3%  VK digest + committed_pi + instance absorbs
   4      49,906,596         3,190     0.4%  user-phase advice reads + user challenge squeezes
   5      49,903,282         2,564     0.3%  theta squeeze + lookup multiplicities
   6      49,898,123         4,409     0.5%  beta/gamma + permutation Z products
   7      49,896,797           576     0.1%  lookup helpers + Z accumulators
   8      49,893,704         2,343     0.3%  trash_challenge + trashcans
   9      49,890,004         2,950     0.4%  y squeeze + quotient-limb reads
  10      49,834,193        55,061     6.7%  evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi
  11      49,824,712         8,731     1.1%  Lagrange + instance evaluation
  12      49,700,363       123,599    15.0%  quotient evaluation (Fr arithmetic)
  13      49,627,335        72,278     8.8%  linearization-commitment MSM
  17      49,626,337           248     0.0%  PCS block 1 (rotation points x*omega^rot)
  18      49,621,859         3,728     0.5%  PCS block 2 (x1 powers, ROLLED LOOP)
  19      49,343,701       277,408    33.7%  PCS block 3 set 0 q_com fold (m=33 MSM, MCOPY)
  20      49,288,465        54,486     6.6%  PCS block 3 set 1 q_com fold (m=5 MSM, MCOPY)
  21      49,259,880        27,835     3.4%  PCS block 3 set 2 q_com fold (m=2 MSM, MCOPY)
  22      49,248,489        10,641     1.3%  PCS block 4 (f_eval Lagrange interpolation)
  23      49,206,985        40,754     5.0%  PCS block 5 (final_com x4-power MSM + v)
  14      49,180,800        25,435     3.1%  PCS block 6 (pairing inputs LHS/RHS)
  15      49,180,011            39     0.0%  accumulator random-combine
  16      49,076,093       103,168    12.5%  final ec_pairing

  cp1 gas_left            = 49,916,089 (verifier entry)
  cp16..cp1 gas billed    = 839,996 (work between cp1 and cp16)
  - measurement overhead  = 17,250 (23 checkpoints x 750 gas)
  = real section work     = 822,746
  total tx gas_used       = 924,703 (incl. tx base + calldata + pre-cp1 + post-cp16)
```

PCS sub-block totals: cp17..cp23 + cp14 = 440,535 gas (vs 513,714
pre-H1/H2). The cp14 PCS bucket dropped from 514 kg to 441 kg
(−73 kg, −14 %). All non-PCS sections within ±20 gas of pre-H1/H2.

Per-section deltas vs Step 6 baseline:
- cp14 PCS block −88,986 (−15,173 from B + −189 from E + −572 from
  D + −25,021 from H1 + −47,981 from H2 + downstream solc-via-ir
  re-scheduling effects).
- cp16 final pairing −1,262 (E in `ec_pairing`).
- All other sections within ±20 gas of Step 6 baseline (build-noise
  / measurement jitter).

### Fine-grained PCS sub-block attribution (cp17..cp23, cp14)

The PCS section has additional checkpoints inside it that attribute
the 441-kg cp14 bucket to each of the 8 emitter sub-blocks (one
output of `pcs_computations()`). For the Poseidon fixture (3 point
sets) the emitter produces:

```
=== PCS sub-block deltas (cp17..cp23, cp14) — current HEAD (B/D/E/H1/H2) ===
  id  delta       %_PCS  %_total  section
  17     248        0.1%    0.03%  block 1: rotation points (x*omega^rot, 3 distinct)
  18   3,728        0.8%    0.4%   block 2: x1 powers (33 muls + mstore, ROLLED LOOP)
  19 277,408       62.9%   30.0%   block 3 set 0 q_com fold (m=33 MSM, MCOPY staging)
  20  54,486       12.4%    5.9%   block 3 set 1 q_com fold (m=5 MSM, MCOPY staging)
  21  27,835        6.3%    3.0%   block 3 set 2 q_com fold (m=2 MSM, MCOPY staging)
  22  10,641        2.4%    1.2%   block 4: f_eval Lagrange interpolation (3 sets)
  23  40,754        9.2%    4.4%   block 5: final_com x4-power MSM + v
  14  25,435        5.8%    2.8%   block 6: pairing inputs LHS = pi, RHS = final_com - v*G + x3*pi
total 440,535      100%    47.6%
```

Pre-H1/H2 cp14 was 514 kg; H1 (per-commit MCOPY staging) saved
~25 kg directly in cp19/cp20/cp21, and H2 (rolling block 2 x1-powers
into a Yul for-loop) saved another ~22 kg directly in cp18 plus
~25 kg downstream in cp19 from solc-via-ir re-scheduling the whole
PCS section more compactly when block 2 is no longer 32 unrolled
mulmod+mstore lines fighting block 3 for register slots.

Per-EIP-2537 G1MSM precompile contributions (cost = `k * 12000 *
discount[k] / 1000` with the discount table from EIP-2537):

| call | k | discount | precompile gas | block | EVM-side overhead |
|---|---:|---:|---:|---:|---:|
| set 0 q_com fold | 33 | 133 | 52,668 | cp19=329,365 | ~277 kg |
| set 1 q_com fold | 5 | 517 | 31,020 | cp20=54,630 | ~24 kg |
| set 2 q_com fold | 2 | 888 | 21,312 | cp21=27,907 | ~7 kg |
| block 5 final_com (3 × MSM-1 + 3 × G1ADD) | 1+1+1 | 1200 | 3 × 14,400 + 3 × 600 ≈ 45,000 | cp23=40,754 | ~−4 kg* |
| block 6 pairing RHS (2 × MSM-1 + 2 × G1ADD) | 1+1 | 1200 | 2 × 14,400 + 2 × 600 ≈ 30,000 | cp14=25,435 | ~−5 kg* |
| **PCS precompile subtotal** | | | **~ 180 kg** | of total **514 kg** | (35 %) |

\* The negative "EVM overhead" for blocks 5 and 6 means the section
delta is *less* than the precompile-only cost — solc-via-ir is folding
the staging mstore chain into the precompile call directly, so the
block 5 and 6 deltas effectively measure precompile + a few mstores.
The EIP-2537 discount table is also slightly more aggressive than
the formula above for k=1 (some implementations cap at 12,000).

Headline: **set 0's m=33 q_com fold is THE single biggest line in the
verifier**: 329 kg = 64 % of the PCS section = 36.8 % of total
verifier gas. The precompile itself only accounts for 53 kg (16 %)
of that 329 kg; the remaining 277 kg is EVM-side staging:

- 32 × `byte_reverse_32(calldataload(...))` calls in the q_eval
  Fr accumulator: ~4.5 kg (post-Step-6 unroll; was ~22 kg pre-unroll).
- 32 × `mulmod`/`addmod` in the q_eval Horner: ~0.5 kg.
- 33 × 5-mstore staging into MSM_SCRATCH (165 mstores from VK
  region into 0x6100..0x75a0): solc-via-ir compiles each
  `mstore(CONST, mload(VK_OFFSET))` to a ~30-50 gas EVM sequence
  after constant folding + stack scheduling, so ~6-8 kg.
- Memory expansion (going from ~370 words to ~941 words): ~3 kg.
- Static-call overhead: ~1 kg.

The remaining ~260 kg is "via-IR generated dispatch overhead"
similar in character to the pre-Step-6 `byte_reverse_32` cost
(many small Yul statements that solc inlines but with non-trivial
stack-juggling overhead). It's the next big optimization target — see
"Suggested optimisations" item I below.

### Step 5 baseline (pre-unroll, for comparison)

```
                                              delta (Step 5)   delta (Step 6)   reduction
   2  VK loading                                       1,497            1,497          0
   3  VK digest + committed_pi + instance absorbs      8,193            2,556     -5,637
   4  user-phase advice + challenge squeezes           3,166            3,190        +24
   5  theta + lookup multiplicities                    6,319            2,564     -3,755
   6  beta/gamma + permutation Z                      11,916            4,409     -7,507
   7  lookup helpers + Z accumulators                    570              576         +6
   8  trash_challenge + trashcans                      6,098            2,343     -3,755
   9  y squeeze + quotient-limb reads                  6,696            2,950     -3,746
  10  evals + x1..x4 + q_evals + pi                  169,674           55,061   -114,613
  11  Lagrange + instance evaluation                   8,766            8,731        -35
  12  quotient evaluation                            360,800          123,599   -237,201   <- biggest
  13  linearization MSM                               72,293           72,293          0
  14  PCS block                                      631,364          529,521  -101,843
  15  accumulator combine                                 39               39          0
  16  final pairing                                  104,430          104,430          0
                                                  ---------         ---------  ----------
  total (cp16..cp1, with overhead)                1,403,071          925,009   -478,062
```

The ~85 kg gap between `total tx gas_used` (1,010 kg) and the
inter-cp1/cp16 range (925 kg) is **tx-level fixed cost**: 21,000 base
+ ~67,000 calldata (4,484 bytes × 16 gas/non-zero) + ~1,100
`extcodecopy` of the VK contract.

## Where the gas actually goes (after Step 6)

The verification cost now concentrates in three sections (PCS,
pairing, quotient eval), with the rest being small change. Split into
precompile work and EVM work:

| section | gas | breakdown |
|---|---:|---|
| **PCS computation (cp14)** | **441 kg** | Now broken out by sub-block (cp17..cp23): **set 0 q_com fold = 277 kg (63 %)**, set 1 q_com fold = 54 kg, set 2 q_com fold = 28 kg, block 5 final_com = 41 kg, block 6 pairing inputs = 25 kg, f_eval Lagrange = 11 kg, x1 powers = 4 kg, rotation points = 0.2 kg. Per-EIP-2537 G1MSM precompile cost across all 8 PCS calls is **~180 kg (41 %)**, leaving **~261 kg (59 %) as EVM-side staging + Fr arithmetic + memory expansion**. Down 89 kg from Step 6 (B: −15 kg modexp, D: −0.6 kg mload, E: −0.2 kg mcopy, H1: −25 kg per-commit MCOPY, H2: −48 kg rolled x1-powers loop with downstream re-scheduling). |
| **Quotient evaluation (cp12)** | **124 kg** | ~587 `mulmod`/`addmod` sites in the gate evaluator. Step 6 dropped this from 361 kg by eliminating ~80 redundant 32-iter `byte_reverse_32` loops. |
| **Final pairing (cp16)** | 103 kg | EIP-2537 `BLS12_PAIRING_CHECK` for k=2: `32600 + 37700 × 2 = 108,000` minus measurement overhead. E (mcopy in `ec_pairing`) shaved ~1.3 kg of EVM overhead (point staging for the 0x300-byte input scratch); the precompile cost itself is the cryptographic floor and cannot be reduced. |
| **Linearization MSM (cp13)** | 72 kg | One 8-pair G1MSM (~33 kg) + Horner scalar prep (~30 mulmod chain) + 8-pair × 5-mstore staging. **Unchanged by Step 6 / B / D / E** (its calldata reads are not in the byte-reverse hot path; its mstore chains are inside an MSM emitter not yet retrofitted to MCOPY). |
| **Eval + transcript tail (cp10)** | 55 kg | 48 evals × ~10 gas (calldataload + byte_reverse + lt + common_word, post-unroll) + 4 keccak squeezes (challenge buffer ~1.6 KB → ~30 kg/squeeze) + 2 `common_uncompressed_g1` calls + memory growth. Step 6 cut ~115 kg here (was 170 kg). |
| transcript stage cp2..cp9 | ~16 kg | streaming-keccak absorb cycles, mostly. Step 6 cut these to a third of pre-unroll. |
| Lagrange + instance eval (cp11) | 9 kg | small batch invert + dot-product over instances |
| acc random-combine (cp15) | 0 kg | branch not taken (HAS_ACCUMULATOR_MPTR == 0 for poseidon) |
| **non-tx total** | **835 kg** | of which ~338 kg is precompile gas (40 %), ~497 kg is EVM (60 %). Cumulative EVM-side savings since the original 1,589 kg baseline: ~681 kg (largely from byte_reverse_32 unroll + Step 6 transcript work + B/H1/H2 in PCS). |

## The "catch-all" was `byte_reverse_32`

The pre-Step-6 breakdown attributed ~625 kg to "solc / inlining
overhead". Investigation showed it was **not** solc-inlining (the
optimizer-runs sweep was nearly insensitive between `runs=1` and
`runs=100000`, only ~2 kg difference). The actual cause was the
`byte_reverse_32` Yul helper, called ~184 times in the rendered
verifier and emitted as a 32-iteration `for { let i := 0 } lt(i,32)
{ i := add(i,1) } { ... }` shift loop:

- per call: 32 iters × ~22 gas/iter + ~50 gas function-call overhead
  ≈ 700–750 gas.
- 184 calls × 700 = ~129 kg directly visible.
- secondary effects (keccak input prep, modexp parameter framing,
  etc.) added another ~350 kg of indirect cost.

After Step 6 (31 of 32 iters unrolled into straight-line `byte() | shl`
ops, 1 trailing trip kept as a guard loop), each call drops to ~140
gas (32 ops × ~3 gas + ~40 gas overhead). The trailing guard loop is
required because solc with `--via-ir` aggressively inlines fully
straight-line function bodies at every call site; for this verifier
that triggers a pathology where execution hits the 50 M block gas
limit. Keeping a single-iter loop preserves the function-call
boundary.

Total measured saving: **478 kg (-32 % from baseline)**.

`--optimize-runs` was bumped from `1` to `200` as part of this work
(see `src/evm.rs::DEFAULT_OPTIMIZE_RUNS`), but the two changes are
nearly orthogonal: bumping runs alone saves ~800 gas, the unroll alone
saves ~478 kg. The runs bump is kept for two reasons: (1) it is now
safe (post-Step-5 the contract size dropped well below the 24 kB
limit, so deployment-cost bias is no longer needed), and (2) it lets
ad-hoc A/B measurement via `SOLC_OPTIMIZE_RUNS=N`.

## Suggested optimisations (ordered by ROI)

### A. ~~`decompress_g1` library + bump `--optimize-runs`~~ (closed)

**Status:** investigated, closed. `decompress_g1` was already removed
in Step 5 (the on-chain compressed→uncompressed path is gone). An
A/B sweep of `--optimize-runs ∈ {1, 50, 200, 1000, 100000}` showed
only ~2 kg sensitivity — `--via-ir` already optimises aggressively
regardless of the runs setting. The default has been raised from `1`
to `200` for hygiene (it's now safe — post-Step-5 the contract is
well under 24 kB) but the gas impact is negligible.

The actual top item turned out to be `byte_reverse_32`: see Step 6
in OPTIMISATION.md, **−478 kg measured**. That made A's projection
of 200–400 kg moot.

### B. Montgomery batched scalar inversion
**Projection: 12–18 kg saved**

The PCS block makes 14 separate `scalar_inv(x_i)` calls (each ~1.4 kg
of modexp gas + EVM overhead). Replace with one Montgomery batch
invert:

```yul
// Pseudo-Yul: invert {x_0, x_1, …, x_{n-1}} in O(n) muls + 1 modexp
let prod := x_0
let cum_0 := prod
prod := mulmod(prod, x_1, r); let cum_1 := prod
…
let prod_inv := scalar_inv(prod)
// Walk back: each x_i_inv := prod_inv * cum_{i-1} ; prod_inv := prod_inv * x_i
```

Saves 13 modexp calls (~13 × 1.4 kg = ~18 kg) at the cost of ~28 muls
(~280 gas). Net ~17 kg.

**Files:** `src/codegen/pcs.rs` (the emitter that lays out the
14 `let _ := scalar_inv(_)` lines in the PCS block). Probably a
dedicated `batch_scalar_inv` helper in the Yul prelude.

**Risk:** all inputs must be non-zero. For the PCS Lagrange basis and
`dx` denominators this is guaranteed by Fiat-Shamir (the challenges
are uniform and the basis is over distinct points), but worth keeping
the per-input zero check for defence in depth (revert if any is zero).

### C. Pre-fold `mulmod(_, 1)` / `addmod(_, 0)` in the evaluator codegen
**Projection: 5–15 kg saved**

The gate evaluator (`src/codegen/evaluator.rs`) emits `mulmod(x, 1, r)`
and `addmod(x, 0, r)` whenever a multiplicative or additive identity
appears in the constraint. With `runs=1` solc cannot constant-fold
these. Add a pass at codegen time that drops them.

**Files:** `src/codegen/evaluator.rs` (the `evaluate` recursion that
emits per-expression Yul lines).

**Risk:** must distinguish "literally constant `1`" (drop) from
"`mload(SOME_MPTR)` that *happens* to evaluate to `1` for this circuit"
(keep — it's a domain quantity, not a literal). Easy if the evaluator
already tracks ConstantExpression nodes separately.

### D. Hoist `mload(Y_MPTR)` and rotation slots in the evaluator
**Projection: 5–15 kg saved (subsumed by A but still wins on `runs=1`)**

The gate evaluator currently re-mloads `Y_MPTR`, `THETA_MPTR`,
`BETA_MPTR`, etc. inside the inner Horner step of every identity
(~50 identities × ~5 mloads each = ~250 redundant mloads at 3 gas =
0.75 kg). Cheap to fix at codegen time — emit a `let y := mload(Y_MPTR)`
at the top of the quotient block and reference `y` in each step.

**Files:** `src/codegen.rs` (the `make_block` closure that emits each
identity's Horner step), and `src/codegen/evaluator.rs` (the part that
substitutes `Y_MPTR` → local `y`).

**Risk:** none, mechanical.

### E. MCOPY the EC point staging (#5 in OPTIMISATION.md)
**Projection: 5–10 kg saved**

The 5 single-pair MSMs in the PCS Block 5 / Block 6 + the 5 G1ADDs
each repeat a 4-line `mstore(0x180, mload(...))` chain to copy
4-word points. Cancun ships MCOPY (`0x5e`); replace each chain with
one `mcopy(dst, src, 0x80)`.

**Files:** `templates/Halo2Verifier.sol` and the `pcs_computations`
emitter in `src/codegen/pcs.rs`.

**Risk:** none. EVM target is already Cancun.

### F. `truncated-challenges` (128-bit Fr challenges) — opt-in only
**Projection: 100–200 kg saved**

With 128-bit truncated challenges every `mulmod(scalar, x_i, r)` in the
gate evaluator and Horner folds becomes a 128×256 mulmod, and many of
the chains can collapse one or two operations earlier. snark-verifier
reports this saves ~150 kg on a comparable Poseidon proof (PR #9).

**Caveat:** drops Fiat-Shamir security from 256-bit to 128-bit. The
prover and verifier must both opt in. Worth measuring behind a feature
flag (`truncated-challenges`) but **not** the default path.

**Files:** prover side (`midfall/proofs/src/transcript`), verifier
codegen (every `squeeze_to` site emits a `let c := and(c, 0xff..ff_128)`
mask), and `OPTIMISATION.md` to document the security caveat.

### G. Fold the keccak squeezes in cp10
**Projection: 30–50 kg saved**

Cp10 spends ~120 kg on 4 squeeze_to keccak calls (after the eval and
q_eval loops). Each keccak operates on ~1.6 KB of buffered input —
which is fine, but the buffer is rebuilt 4 times in a row from the
same prefix. If we can compute x1 || x2 || x3 || x4 from a single
domain-separated keccak invocation (as snark-verifier does with its
`MidnightEvmHash`), we save ~3 keccak calls × ~10 kg = ~30 kg.

### H. Set-0 q_com staging streamlining
**Status: H1 + H2 applied (-73 kg measured); H3 still open.**

Pre-H1/H2 fine-grained attribution showed set 0's m=33 q_com fold
consumed 329 kg (36.8 % of verifier). Three sub-attacks were
proposed:

#### H1 — MCOPY per-commit point staging (applied, −25 kg)

Each MSM pair was emitted as 4-mstore chain pulling the point from
the VK region into MSM_SCRATCH. EcPoint guarantees the 4 words sit
at `base..base+3*0x20` (contiguous), so `mcopy(stage, src, 0x80)`
covers the whole point copy in one op. Applied to (a) m≥2 per-commit
loop in block 3, (b) post-staticcall point writeback (MSM_SCRATCH →
q_com_base), and (c) m=1 short-circuit. Measured: cp19 −26 kg, cp20
−0.1 kg, cp21 −0.1 kg. Production: 980 → 955 kg.

#### H2 — Roll x1-powers emission into a Yul `for` loop (applied, −48 kg)

Block 2 unrolled 32 mulmod+mstore pairs, costing 24-26 kg vs the
~700 gas the arithmetic itself requires. solc-via-ir's register
allocator struggles with 32 unrolled mulmods sharing one accumulator,
plus the unrolled basic block penalizes block 3's downstream
register allocation. Replacing with:

```yul
let acc := 1
let p := X1_POWERS_MPTR
for { let i := 0 } lt(i, 0x20) { i := add(i, 1) } {
    p := add(p, 0x20)
    acc := mulmod(acc, x1, r)
    mstore(p, acc)
}
```

restores the basic-block heuristic. Measured: cp18 −22 kg directly,
cp19 −26 kg as downstream re-scheduling effect, plus minor wins
elsewhere. Production: 955 → 907 kg.

The downstream effect on cp19 is the surprising win — solc-via-ir
reschedules the whole PCS section more compactly when block 2 is no
longer fighting for register slots.

#### H3 (open) — Pre-reverse calldata evals to a Fr-array
**Projection: −10 to −20 kg**

The q_eval accumulator inside each set's q_com fold reads each
commit's eval via `byte_reverse_32(calldataload(N))`. For set 0
that's 33 calls × ~145 gas = ~4.8 kg. Same evals are also read
~150-300 times in the gate evaluator (cp12 = 124 kg). Pre-reversing
all evals once at top of PCS block 0 into a contiguous Fr-array:

```yul
mstore(EVALS_REVERSED_MPTR + 0x00, byte_reverse_32(calldataload(EVAL_OFFSET_0)))
mstore(EVALS_REVERSED_MPTR + 0x20, byte_reverse_32(calldataload(EVAL_OFFSET_1)))
...
```

then replacing every later use with `mload(EVALS_REVERSED_MPTR +
i*0x20)`. Saves byte_reverse_32 cost on 100-200 references × 142 gas
= 14-28 kg, minus ~7 kg setup. Net ~7-20 kg.

**Risk**: requires plumbing through both the PCS emitter (so it
substitutes mloads for the calldata pattern) AND the gate evaluator
(so cp12 also gets the savings). Need to coordinate offsets across
the two emitters.

**Caveat:** changes the Fiat-Shamir transcript layout. Requires a
matching change to the prover (in `midnight-proofs::CircuitTranscript`)
and bumps the on-chain transcript's domain-separator epoch. Not as
cheap as it looks — cross-stack coordination.

**Files:** `midfall/proofs/src/transcript/mod.rs`,
`src/transcript.rs`, `templates/Halo2Verifier.sol`. Probably a
follow-up after A is shipped.

## Realistic projection after Step 6

| step | description | gas | delta |
|---|---|---:|---:|
| Step 5 (pre-unroll) | with instrumentation overhead | 1,488 kg | — |
| Step 5 (production) | instrumentation off | 1,476 kg | −12 kg |
| Step 6 (production) | byte_reverse_32 unrolled | 997 kg | −478 kg |
| Step 6 (instrumented) | with checkpoints overhead | 1,010 kg | — |
| Step 6 + B (production) | Montgomery batch scalar inv | 982 kg | −15 kg |
| Step 6 + B + E (production) | + MCOPY EC point staging | 981 kg | −1.5 kg |
| Step 6 + B + D + E (production) | + hoist rotation mloads | 980 kg | −0.6 kg |
| Step 6 + B + D + E + H1 (production) | + MCOPY q_com per-commit staging | 955 kg | −25 kg |
| **Step 6 + B + D + E + H1 + H2 (HEAD, production)** | **+ rolled x1-powers loop** | **907 kg** | **−48 kg** |
| Step 6 + B+D+E+H1+H2 (instrumented) | with checkpoints overhead | 924 kg | — |
| + C | constant-fold `mulmod(_, 1)` / `addmod(_, 0)` | ~895 kg | −10 kg |
| + F (opt-in) | `truncated-challenges` (128-bit) | ~770 kg | −135 kg |
| + G (cross-stack) | fold consecutive keccak squeezes | ~740 kg | −30 kg |

**Achieved non-opt-in: 907 kg (−581 kg, −36.6 % from baseline).** The
remaining ~900-kg floor is dominated by:

| component | est gas |
|---|---:|
| EIP-2537 G1MSMs (53 pairs across 9 calls) | ~225 kg |
| EIP-2537 G1ADDs (5 calls) | ~2 kg |
| EIP-2537 PAIRING (2-pair) | ~108 kg |
| modexp (1 batched scalar_inv after B) | ~2 kg |
| Keccak transcript (3 absorb + 8 squeeze) | ~25 kg |
| Tx base + calldata + extcodecopy | ~85 kg |
| EVM arithmetic (gate eval + Lagrange + interp) | ~150 kg |
| EVM helper dispatch + memory traffic | ~150 kg |
| Other (control flow, etc.) | ~200 kg |

Below ~950 kg the optimisation surface narrows to soundness-relevant
trade-offs (F) and cross-stack transcript redesign (G), and beyond that
the floor is dominated by EIP-2537 pricing and the cryptographic work.

## Notes

- The instrumentation is purely additive: with `--features
  solidity-gas-checkpoints` off, the rendered verifier is byte-for-byte
  the production output. The default test currently confirms **907,030
  gas** (post-Step-6 + B + D + E + H1 + H2); the 17.25-kg overhead
  seen with checkpoints on is exactly `23 × 750` (16 top-level +
  7 PCS sub-block checkpoints).
- `SOLC_OPTIMIZE_RUNS=N` overrides `compile_solidity`'s default at run
  time. `DEFAULT_OPTIMIZE_RUNS = 200`. An A/B sweep showed the gas
  number is essentially flat across `runs ∈ {1, 50, 200, 1000,
  100000}` (only ~2 kg spread), so `200` was chosen for hygiene
  rather than measurable savings.
- The poseidon fixture has `HAS_ACCUMULATOR_MPTR == 0` so cp15
  measures the no-op branch (~39 gas of `mload(HAS_ACCUMULATOR_MPTR) +
  iszero + jumpi`). Aggregator deployments will see real cost here
  — re-run the bench against an aggregated proof to populate cp15.
- Section attributions are *causal*: the LOG1 sits exactly at the end
  of each block, so the delta is unambiguously the gas spent in that
  section (modulo the 750-gas overhead per checkpoint, which is
  subtracted by `dump_gas_checkpoints`).
- For tighter attribution within the 631 kg PCS block, add additional
  checkpoints inside `src/codegen/pcs.rs::computations()` at the
  per-set boundaries. Currently every set's three sub-stages (point
  set group, batch invert, MSM) coalesce into the same 631 kg bucket.
