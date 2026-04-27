# Per-section gas attribution

Measured breakdown of the 1.48 M gas Poseidon-fixture verification on the
midfall branch, captured via the `solidity-gas-checkpoints` cargo feature.
This document is the measurement counterpart to `OPTIMISATION.md`: where
that one lists *what changes are available*, this one says *which sections
are actually expensive enough to be worth changing*.

## Running the bench

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

## Measured breakdown (Poseidon fixture, k=6, midfall HEAD)

The breakdown below was captured **after** Step 6 + Optimisations B/D/E
(the `byte_reverse_32` 31-iter unroll plus PCS-block tuning, see
OPTIMISATION.md). The Step-5 baseline (1,475,560 gas before any of
this) is preserved as a comparison column — every section that
touched calldata-backed evals saw 5-30× reductions when Step 6 dropped
the per-call cost of `byte_reverse_32` from ~700 gas to ~140 gas, and
the PCS block saw a further 17 kg cut from B/D/E.

### Step 6 + B/D/E (current HEAD)

```
=== gas-checkpoint breakdown (per-section deltas) ===
  id        gas_left         delta        %  section
   1      49,916,161             -        -  entry (before VK loading)
   2      49,913,914         1,497     0.2%  VK loading
   3      49,910,608         2,556     0.3%  VK digest + committed_pi + instance absorbs
   4      49,906,668         3,190     0.4%  user-phase advice reads + user challenge squeezes
   5      49,903,354         2,564     0.3%  theta squeeze + lookup multiplicities
   6      49,898,195         4,409     0.5%  beta/gamma + permutation Z products
   7      49,896,869           576     0.1%  lookup helpers + Z accumulators
   8      49,893,776         2,343     0.3%  trash_challenge + trashcans
   9      49,890,076         2,950     0.3%  y squeeze + quotient-limb reads
  10      49,834,265        55,061     6.1%  evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi
  11      49,824,784         8,731     1.0%  Lagrange + instance evaluation
  12      49,700,435       123,599    13.8%  quotient evaluation (Fr arithmetic)
  13      49,627,389        72,296     8.1%  linearization-commitment MSM
  14      49,113,052       513,587    57.3%  PCS computation block
  15      49,112,263            39     0.0%  accumulator random-combine
  16      49,008,345       103,168    11.5%  final ec_pairing

  cp1 gas_left            = 49,916,161 (verifier entry)
  cp16..cp1 gas billed    = 907,816 (work between cp1 and cp16)
  - measurement overhead  = 12,000 (16 checkpoints x 750 gas)
  = real section work     = 895,816
  total tx gas_used       = 992,451 (incl. tx base + calldata + pre-cp1 + post-cp16)
```

Per-section deltas vs Step 6 (pre-B/D/E): cp14 PCS block −15,934
(−15,173 from B + −189 from E + −572 from D); cp16 final pairing
−1,262 (E in `ec_pairing`). All other sections within ±5 gas of Step
6 baseline (build-noise / measurement jitter).

### Fine-grained PCS sub-block attribution (cp17..cp23, cp14)

The PCS section has additional checkpoints inside it that attribute
the 514-kg cp14 bucket to each of the 8 emitter sub-blocks (one
output of `pcs_computations()`). For the Poseidon fixture (3 point
sets) the emitter produces:

```
=== PCS sub-block deltas (cp17..cp23, cp14) ===
  id  delta       %_PCS  %_total  section
  17     548        0.1%    0.06%  block 1: rotation points (x*omega^rot, 3 distinct)
  18  24,434        4.7%    2.7%   block 2: x1 powers (33 muls + mstore)
  19 329,365       64.1%   36.8%   block 3 set 0 q_com fold (m=33 MSM, 1 rotation)
  20  54,630       10.6%    6.1%   block 3 set 1 q_com fold (m=5 MSM, 2 rotations)
  21  27,907        5.4%    3.1%   block 3 set 2 q_com fold (m=2 MSM, 3 rotations)
  22  10,641        2.1%    1.2%   block 4: f_eval Lagrange interpolation (3 sets)
  23  40,754        7.9%    4.6%   block 5: final_com x4-power MSM + v
  14  25,435        4.9%    2.8%   block 6: pairing inputs LHS = pi, RHS = final_com - v*G + x3*pi
total 513,714      100%    57.4%
```

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
| **PCS computation (cp14)** | **514 kg** | Now broken out by sub-block (cp17..cp23): **set 0 q_com fold = 329 kg (64 %)**, set 1 q_com fold = 55 kg, set 2 q_com fold = 28 kg, x1 powers = 24 kg, block 5 final_com = 41 kg, block 6 pairing inputs = 25 kg, f_eval Lagrange = 11 kg, rotation points = 0.5 kg. Per-EIP-2537 G1MSM precompile cost across all 8 PCS calls is **~180 kg (35 %)**, leaving **~330 kg (65 %) as EVM-side staging + Fr arithmetic + memory expansion**. Down 16 kg from Step 6 (B: −15 kg modexp, D: −0.6 kg mload, E: −0.2 kg mcopy). |
| **Quotient evaluation (cp12)** | **124 kg** | ~587 `mulmod`/`addmod` sites in the gate evaluator. Step 6 dropped this from 361 kg by eliminating ~80 redundant 32-iter `byte_reverse_32` loops. |
| **Final pairing (cp16)** | 103 kg | EIP-2537 `BLS12_PAIRING_CHECK` for k=2: `32600 + 37700 × 2 = 108,000` minus measurement overhead. E (mcopy in `ec_pairing`) shaved ~1.3 kg of EVM overhead (point staging for the 0x300-byte input scratch); the precompile cost itself is the cryptographic floor and cannot be reduced. |
| **Linearization MSM (cp13)** | 72 kg | One 8-pair G1MSM (~33 kg) + Horner scalar prep (~30 mulmod chain) + 8-pair × 5-mstore staging. **Unchanged by Step 6 / B / D / E** (its calldata reads are not in the byte-reverse hot path; its mstore chains are inside an MSM emitter not yet retrofitted to MCOPY). |
| **Eval + transcript tail (cp10)** | 55 kg | 48 evals × ~10 gas (calldataload + byte_reverse + lt + common_word, post-unroll) + 4 keccak squeezes (challenge buffer ~1.6 KB → ~30 kg/squeeze) + 2 `common_uncompressed_g1` calls + memory growth. Step 6 cut ~115 kg here (was 170 kg). |
| transcript stage cp2..cp9 | ~16 kg | streaming-keccak absorb cycles, mostly. Step 6 cut these to a third of pre-unroll. |
| Lagrange + instance eval (cp11) | 9 kg | small batch invert + dot-product over instances |
| acc random-combine (cp15) | 0 kg | branch not taken (HAS_ACCUMULATOR_MPTR == 0 for poseidon) |
| **non-tx total** | **908 kg** | of which ~338 kg is precompile gas (37 %; was overestimated as 378 kg in prior bench — refined via cp17..cp23 PCS breakdown showing 180 kg PCS precompile not 220 kg), ~570 kg is EVM (63 %) |

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

**Files:** `src/codegen/pcs/gwc19.rs` (the emitter that lays out the
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
emitter in `src/codegen/pcs/gwc19.rs`.

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
**Projection: 100-200 kg saved**

The fine-grained PCS attribution (cp17..cp23) shows that **set 0's
m=33 q_com fold consumes 329 kg = 36.8 % of the entire verifier**.
The EIP-2537 G1MSM precompile only accounts for ~53 kg of that — the
other **~277 kg is pure EVM-side staging cost** for the 33 commits ×
5 mstores staging chain (165 mstores) + 33 byte_reverse_32 calls in
the q_eval accumulator.

Three sub-attacks in priority order:

1. **Stage points + scalars in a single buffer-write pass**: the
   current emitter writes 165 individual `mstore(CONST, mload(VK_X))`
   lines. Each line compiles via solc-via-ir to a ~30-50 gas EVM
   sequence (PUSH4 dst + PUSH4 src + MLOAD + MSTORE + stack juggling).
   With Cancun MCOPY (already used for fixed 4-word point copies in
   B/E) we could `mcopy(MSM_SCRATCH + i*0xa0, vk_offset_i, 0x80)`
   to copy each point in 18 gas (3 + 3*4 words) instead of 4 mstores
   ≈ 60 gas. Saves ~7 kg over the 33 points + similar for sets 1/2.

2. **Hoist the q_eval accumulator out of the per-set block**: each
   set's q_eval_set_k is built from `byte_reverse_32(calldataload(N))`
   reads. Pre-load all 40 raw evals into a contiguous Fr-array at the
   top of the PCS block, then reference them as `mload(EVALS_MPTR +
   i*0x20)` (3 gas each). Saves the per-call `byte_reverse_32`
   overhead (~140 gas × 40 calls = ~5.6 kg) and lets solc keep the
   constant offsets across blocks.

3. **Hoist X1_POWERS_MPTR mloads to stack locals** (analogous to D
   for ROT_POINTS_MPTR): set 0's q_com fold reads each `X1_POWERS[i]`
   twice (once for q_eval, once for the MSM scalar). Pre-loading the
   33 powers into stack vars at block-3 entry would save ~33 mloads ×
   3 gas = 99 gas per set + spillover savings.

Combined projected ROI: 15–30 kg of direct savings + potentially
~50–100 kg from solc's improved register allocation when the
straight-line code sees fewer cross-block dependencies. The biggest
single win in this list, since cp19 is the largest section.

**Risk**: changing the staging layout requires re-checking memory
ranges (`MSM_SCRATCH = 0x6100`, must stay above `scalar_inv` scratch
at `0x6000..0x60c0` and below the FINAL_COM region).

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
| **Step 6 + B + D + E (HEAD, production)** | **+ hoist rotation mloads** | **980 kg** | **−0.6 kg** |
| Step 6 + B+D+E (instrumented) | with checkpoints overhead | 992 kg | — |
| + C | constant-fold `mulmod(_, 1)` / `addmod(_, 0)` | ~970 kg | −10 kg |
| + F (opt-in) | `truncated-challenges` (128-bit) | ~840 kg | −130 kg |
| + G (cross-stack) | fold consecutive keccak squeezes | ~810 kg | −30 kg |

**Achieved non-opt-in: 980 kg (−508 kg, −34 % from baseline).** The
remaining 950-kg floor is dominated by:

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
  the production output. The default test currently confirms **980,125
  gas** (post-Step-6 + B + D + E); the 12-kg overhead seen with
  checkpoints on is exactly `16 × 750`.
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
  checkpoints inside `src/codegen/pcs/gwc19.rs::computations()` at the
  per-set boundaries. Currently every set's three sub-stages (point
  set group, batch invert, MSM) coalesce into the same 631 kg bucket.
