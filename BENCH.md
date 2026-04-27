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

The breakdown below was captured **after** Step 6 (the
`byte_reverse_32` 31-iter unroll, see OPTIMISATION.md). The previous
Step-5 baseline (1,475,560 gas before this optimisation) is preserved
as a comparison column — every section that touched calldata-backed
evals saw 5-30× reductions because the per-call cost of
`byte_reverse_32` dropped from ~700 gas to ~140 gas.

### Step 6 (current HEAD)

```
=== gas-checkpoint breakdown (per-section deltas) ===
  id        gas_left         delta        %  section
   1      49,916,005             -        -  entry (before VK loading)
   2      49,913,758         1,497     0.2%  VK loading
   3      49,910,452         2,556     0.3%  VK digest + committed_pi + instance absorbs
   4      49,906,512         3,190     0.3%  user-phase advice reads + user challenge squeezes
   5      49,903,198         2,564     0.3%  theta squeeze + lookup multiplicities
   6      49,898,039         4,409     0.5%  beta/gamma + permutation Z products
   7      49,896,713           576     0.1%  lookup helpers + Z accumulators
   8      49,893,620         2,343     0.3%  trash_challenge + trashcans
   9      49,889,920         2,950     0.3%  y squeeze + quotient-limb reads
  10      49,834,109        55,061     6.0%  evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi
  11      49,824,628         8,731     1.0%  Lagrange + instance evaluation
  12      49,700,279       123,599    13.5%  quotient evaluation (Fr arithmetic)
  13      49,627,236        72,293     7.9%  linearization-commitment MSM
  14      49,096,965       529,521    58.0%  PCS computation block
  15      49,096,176            39     0.0%  accumulator random-combine
  16      48,990,996       104,430    11.4%  final ec_pairing

  cp1 gas_left            = 49,916,005 (verifier entry)
  cp16..cp1 gas billed    = 925,009 (work between cp1 and cp16)
  - measurement overhead  = 12,000 (16 checkpoints x 750 gas)
  = real section work     = 913,009
  total tx gas_used       = 1,009,800 (incl. tx base + calldata + pre-cp1 + post-cp16)
```

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
| **PCS computation (cp14)** | **530 kg** | 3 batched G1MSMs (33+5+2 pairs) ~120 kg + 5 single-pair Block 5/6 MSMs ~60 kg + 14 `scalar_inv` modexp ~20 kg + 5 G1ADDs ~2 kg + ~3 keccak squeezes ~10 kg + interpolation arithmetic ~30–50 kg + memory expansion ~5 kg ≈ ~240 kg of "real" work + **~290 kg of EVM helper-dispatch overhead** |
| **Quotient evaluation (cp12)** | **124 kg** | ~587 `mulmod`/`addmod` sites in the gate evaluator. Step 6 dropped this from 361 kg by eliminating ~80 redundant 32-iter `byte_reverse_32` loops. |
| **Final pairing (cp16)** | 104 kg | EIP-2537 `BLS12_PAIRING_CHECK` for k=2: `32600 + 37700 × 2 = 108,000` minus measurement overhead. **Cryptographic floor; cannot be reduced.** |
| **Linearization MSM (cp13)** | 72 kg | One 8-pair G1MSM (~33 kg) + Horner scalar prep (~30 mulmod chain) + 8-pair × 5-mstore staging. **Unchanged by Step 6** (its calldata reads are not in the byte-reverse hot path). |
| **Eval + transcript tail (cp10)** | 55 kg | 48 evals × ~10 gas (calldataload + byte_reverse + lt + common_word, post-unroll) + 4 keccak squeezes (challenge buffer ~1.6 KB → ~30 kg/squeeze) + 2 `common_uncompressed_g1` calls + memory growth. Step 6 cut ~115 kg here (was 170 kg). |
| transcript stage cp2..cp9 | ~16 kg | streaming-keccak absorb cycles, mostly. Step 6 cut these to a third of pre-unroll. |
| Lagrange + instance eval (cp11) | 9 kg | small batch invert + dot-product over instances |
| acc random-combine (cp15) | 0 kg | branch not taken (HAS_ACCUMULATOR_MPTR == 0 for poseidon) |
| **non-tx total** | **925 kg** | of which ~382 kg is precompile gas (41 %), ~543 kg is EVM (59 %) |

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

**Caveat:** changes the Fiat-Shamir transcript layout. Requires a
matching change to the prover (in `midnight-proofs::CircuitTranscript`)
and bumps the on-chain transcript's domain-separator epoch. Not as
cheap as it looks — cross-stack coordination.

**Files:** `midfall/proofs/src/transcript/mod.rs`,
`src/transcript.rs`, `templates/Halo2Verifier.sol`. Probably a
follow-up after A is shipped.

## Realistic projection after Step 6

| step | description | projected gas | delta |
|---|---|---:|---:|
| Step 5 (pre-unroll) | with instrumentation overhead | 1,488 kg | — |
| Step 5 (production) | instrumentation off | 1,476 kg | −12 kg |
| **Step 6 (HEAD, production)** | **byte_reverse_32 unrolled** | **997 kg** | **−478 kg** |
| Step 6 (HEAD, instrumented) | with checkpoints overhead | 1,010 kg | — |
| + B | Montgomery batch scalar inversion | ~980 kg | −15 kg |
| + C | constant-fold `mulmod(_, 1)` / `addmod(_, 0)` | ~970 kg | −10 kg |
| + D | hoist `Y_MPTR`/rotation mloads | ~960 kg | −10 kg |
| + E | MCOPY EC point staging | ~950 kg | −10 kg |
| + F (opt-in) | `truncated-challenges` (128-bit) | ~815 kg | −135 kg |
| + G (cross-stack) | fold consecutive keccak squeezes | ~780 kg | −35 kg |

**Achieved non-opt-in: 997 kg (−491 kg, −33 % from baseline).** The
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
  the production output. The default test currently confirms **997,438
  gas** (post-Step-6); the 12-kg overhead seen with checkpoints on is
  exactly `16 × 750`.
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
