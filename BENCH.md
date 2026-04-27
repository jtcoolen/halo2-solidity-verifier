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

```
=== gas-checkpoint breakdown (per-section deltas) ===
  id        gas_left         delta        %  section
   1      49,915,993             -        -  entry (before VK loading)
   2      49,913,746         1,497     0.1%  VK loading
   3      49,904,803         8,193     0.6%  VK digest + committed_pi + instance absorbs
   4      49,900,887         3,166     0.2%  user-phase advice reads + user challenge squeezes
   5      49,893,818         6,319     0.5%  theta squeeze + lookup multiplicities
   6      49,881,152        11,916     0.9%  beta/gamma + permutation Z products
   7      49,879,832           570     0.0%  lookup helpers + Z accumulators
   8      49,872,984         6,098     0.4%  trash_challenge + trashcans
   9      49,865,538         6,696     0.5%  y squeeze + quotient-limb reads
  10      49,695,114       169,674    12.2%  evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi
  11      49,685,598         8,766     0.6%  Lagrange + instance evaluation
  12      49,324,048       360,800    25.9%  quotient evaluation (Fr arithmetic)
  13      49,251,005        72,293     5.2%  linearization-commitment MSM
  14      48,618,891       631,364    45.4%  PCS computation block
  15      48,618,102            39     0.0%  accumulator random-combine
  16      48,512,922       104,430     7.5%  final ec_pairing

  cp1 gas_left            = 49,915,993 (verifier entry)
  cp16..cp1 gas billed    = 1,403,071 (work between cp1 and cp16)
  - measurement overhead  = 12,000 (16 checkpoints x 750 gas)
  = real section work     = 1,391,071
  total tx gas_used       = 1,487,754 (incl. tx base + calldata + pre-cp1 + post-cp16)
```

The ~85 kg gap between `total tx gas_used` (1,487 kg) and the inter-cp1/cp16
range (1,403 kg) is **tx-level fixed cost**: 21,000 base + ~67,000 calldata
(4,484 bytes × 16 gas/non-zero) + ~1,100 `extcodecopy` of the VK contract.

## Where the gas actually goes

The verification cost concentrates in four sections, with the rest being
small change. Split into precompile work and EVM work:

| section | gas | breakdown |
|---|---:|---|
| **PCS computation (cp14)** | **631 kg** | 3 batched G1MSMs (33+5+2 pairs) ~120 kg + 5 single-pair Block 5/6 MSMs ~60 kg + 14 `scalar_inv` modexp ~20 kg + 5 G1ADDs ~2 kg + ~3 keccak squeezes ~10 kg + interpolation arithmetic ~30–50 kg + memory expansion ~5 kg ≈ **~240 kg of "real" work + ~390 kg of solc / inlining overhead** |
| **Quotient evaluation (cp12)** | **361 kg** | ~587 `mulmod`/`addmod` sites in the gate evaluator. Pure arithmetic cost is ~5–6 kg. ≈ **~355 kg of solc / inlining overhead** |
| **Eval + transcript tail (cp10)** | 170 kg | 48 evals × ~30 gas (calldataload+byte_reverse+lt+common_word) + 4 keccak squeezes (challenge buffer ~1.6 KB → ~30 kg/squeeze) + 2 `common_uncompressed_g1` calls + memory growth ≈ ~155 kg of mostly-keccak |
| **Final pairing (cp16)** | 104 kg | EIP-2537 `BLS12_PAIRING_CHECK` for k=2: `32600 + 37700 × 2 = 108,000` minus measurement overhead. **Cryptographic floor; cannot be reduced.** |
| **Linearization MSM (cp13)** | 72 kg | One 8-pair G1MSM (~33 kg) + Horner scalar prep (~30 mulmod chain) + 8-pair × 5-mstore staging |
| transcript stage cp2..cp9 | ~44 kg | streaming-keccak `common_uncompressed_g1` is cheap; absorbs dominate over hashes |
| Lagrange + instance eval (cp11) | 9 kg | small batch invert + dot-product over instances |
| acc random-combine (cp15) | 0 kg | branch not taken (HAS_ACCUMULATOR_MPTR == 0 for poseidon) |
| **non-tx total** | **1,403 kg** | of which ~387 kg is precompile gas (28%), ~1,016 kg is EVM (72%) |

## The "catch-all" was here

The previous (analytical) breakdown left ~625 kg "unattributed". With
measurements, that bucket localises to two sections:

- **PCS solc / inlining overhead: ~390 kg** (44 % of identified overhead)
- **Quotient-eval solc / inlining overhead: ~355 kg** (40 %)

Both are caused by `compile_solidity` shipping `--optimize-runs=1` to
keep the contract under EIP-170's 24 kB limit. With that setting solc
inlines every helper (`decompress_g1` × 21, `ec_*` ops, `common_*`
absorbers, `scalar_inv` × 14, the Y-power chain in the gate evaluator)
at every call site without re-merging, and the inlined bodies are not
deduplicated. The PCS block in particular contains 5 single-pair MSM
helpers + 14 `scalar_inv` Fermat ladders + ~30 mulmod chains, and
all are duplicated across the 3 point sets.

The quotient evaluator inlines ~50 gate identities, each loading
`mload(Y_MPTR)` and the various rotated-eval slots; these mloads
should fold into stack locals with `runs=200`.

## Suggested optimisations (ordered by ROI)

### A. `decompress_g1` library + bump `--optimize-runs` (#7 in OPTIMISATION.md)
**Projection: 200–400 kg saved**

The single highest-leverage change available. Move `decompress_g1` into
a tiny library contract and `delegatecall` to it (~700 gas/call × ~13
sites = ~10 kg call overhead), then rebuild the verifier with
`--optimize-runs=200` (or default 200). With the helper deduplicated
the contract drops below 24 kB and the optimizer can:

- merge the 5 single-pair Block 5/6 MSMs in the PCS block (~50 kg);
- merge the 14 `scalar_inv` Fermat ladders into one inlined function
  with shared modexp scratch (~30–60 kg);
- hoist all `mload(Y_MPTR)` / `mload(THETA_MPTR)` / etc. out of the
  587-op gate evaluator into stack locals (~100–200 kg);
- fold long mulmod chains into linear assignments (~50–100 kg).

Expected attribution after: cp12 drops from 361 kg → ~150–200 kg, cp14
drops from 631 kg → ~350–450 kg.

**Files:** `src/evm.rs::compile_solidity` (drop `--optimize-runs=1`,
add a deploy-and-link step), `templates/Halo2Verifier.sol` (replace
inline `decompress_g1` body with a `delegatecall` stub OR call into
a constant precomputed library address baked in at deploy time).

**Risk:** needs care on the calldata ABI of the library — `delegatecall`
preserves storage but `decompress_g1` only reads scratch memory, so it
is `pure` and the indirection is safe. Verify EIP-2537 precompile
addresses still resolve from the library context (they should — they
live on the precompile address space, not on the calling contract).

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

## Realistic projection after instrumentation

| step | description | projected gas | delta |
|---|---|---:|---:|
| today (HEAD) | with instrumentation overhead | 1,488 kg | — |
| today (production) | instrumentation off | 1,476 kg | −12 kg |
| + A | decompress_g1 library + `--optimize-runs=200` | ~1,180 kg | −296 kg |
| + B | Montgomery batch scalar inversion | ~1,165 kg | −15 kg |
| + C | constant-fold `mulmod(_, 1)` / `addmod(_, 0)` | ~1,155 kg | −10 kg |
| + D | hoist `Y_MPTR`/rotation mloads | ~1,145 kg | −10 kg |
| + E | MCOPY EC point staging | ~1,135 kg | −10 kg |
| + F (opt-in) | `truncated-challenges` (128-bit) | ~1,000 kg | −135 kg |
| + G (cross-stack) | fold consecutive keccak squeezes | ~960 kg | −40 kg |

**Realistic non-opt-in target: ~1,135 kg (−341 kg, −23 % from baseline).**

The ~1,135 kg floor breaks down approximately as:

| component | est gas |
|---|---:|
| EIP-2537 G1MSMs (53 pairs across 9 calls) | ~225 kg |
| EIP-2537 G1ADDs (5 calls) | ~2 kg |
| EIP-2537 PAIRING (2-pair) | ~108 kg |
| modexp (1 batched scalar_inv) | ~2 kg |
| Keccak transcript (3 absorb + 8 squeeze) | ~25 kg |
| Tx base + calldata + extcodecopy | ~85 kg |
| EVM arithmetic (gate eval + Lagrange + interp) | ~300 kg |
| EVM helper dispatch + memory traffic | ~150 kg |
| Solc residual overhead at `runs=200` | ~150 kg |
| Other (control flow, etc.) | ~88 kg |

Below ~1,135 kg the optimisation surface narrows to soundness-relevant
trade-offs (F) and cross-stack transcript redesign (G), and beyond that
the floor is dominated by EIP-2537 pricing and the cryptographic work.

## Notes

- The instrumentation is purely additive: with `--features
  solidity-gas-checkpoints` off, the rendered verifier is byte-for-byte
  the production output. The default test confirms 1,475,560 gas (vs
  pre-instrumentation 1,475,524, sub-100 gas RNG noise).
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
