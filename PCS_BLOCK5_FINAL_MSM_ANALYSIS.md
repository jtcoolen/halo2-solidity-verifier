# PCS Block 5 Final MSM Analysis

Checkpoint:

```text
537,061 gas, 35.7%, PCS block 5, final_com x4-power MSM + v
```

The exact gas has moved slightly between benchmark runs, but this section
remains the dominant PCS cost. After the big-endian proof-scalar shim it was
still around `533k` gas, so the remaining cost is not scalar decoding.

## What This Step Does

This block is the GWC/KZG multi-opening step that folds all point-set openings
into one final commitment opening.

Earlier PCS blocks have already:

- grouped queried commitments by rotation point,
- folded each point set by `x1` into scalar-side `q_eval` values,
- read the prover's `f_com`,
- computed the interpolation correction `f_eval` at `x3`.

PCS block 5 samples or uses `x4` and computes:

```text
final_com = sum_s x4^s * q_com[s] + x4^n_sets * f_com
v         = sum_s x4^s * q_eval_at_x3[s] + x4^n_sets * f_eval
```

The Solidity generator does not materialize each intermediate `q_com[s]`.
Instead, it expands them by linearity:

```text
q_com[s] = sum_i x1^i * C[s][i]
```

so the final commitment is built directly as:

```text
final_com =
    sum_{s,i} (x4^s * x1^i) * C[s][i]
  + x4^n_sets * f_com
```

The synthetic linearization commitment is also expanded inside this same final
MSM. Its quotient-limb commitments and simple-selector commitments are staged as
ordinary MSM terms with the corresponding folded scalar.

PCS block 6 then uses this block's `final_com` and `v` to build the final KZG
pairing equation, roughly:

```text
e(final_com - v*G + x3*pi, [1]_2) = e(pi, [s]_2)
```

## Rust Verifier Correspondence

This corresponds to the `x4` batching stage in:

```text
/Users/Julien.Coolen/midfall/proofs/src/poly/kzg/mod.rs
```

around the verifier `multi_open` logic:

```rust
let x4 = transcript.squeeze_challenge_scalar();
let final_com = inner_product([q_coms..., f_com], powers(x4));
let v = inner_product([q_evals..., f_eval], powers(x4));
```

The Solidity codegen for this is in:

```text
src/codegen/pcs.rs
```

around the generated `build final_com and v` block.

The latest generated verifier dump showed:

```yul
staticcall(gas(), 0x0c, 0x8e60, 0x30c0, 0x8e60, 0x80)
```

`0x30c0 / 0xa0 = 78`, so this block is currently doing a 78-pair BLS12-381
G1MSM.

## Why It Is Expensive

The cost is dominated by the EIP-2537 G1MSM precompile over those commitment
pairs.

The surrounding scalar arithmetic is comparatively small:

- computing `x4` powers,
- computing `v`,
- multiplying by `x1` and `x4` powers,
- staging G1/scalar pairs in memory.

So this is primarily a final MSM pair-count problem, not a byte-level Yul
micro-optimization problem.

## Optimisation Options

### 1. Reduce Final MSM Pair Count

This is the main lever.

Every queried commitment that survives into `q_com` becomes a term in this
final MSM. The linearization commitment expansion also contributes quotient-limb
and simple-selector terms.

Useful targets:

- fewer queried commitments,
- fewer simple-selector commitments,
- fewer quotient limb commitments,
- fewer rotation point-set entries,
- circuit/proof-layout changes that remove commitments from the PCS query set.

This is the highest-impact path, but it is also the most protocol- and
circuit-aware.

### 2. Add Pair-Category Instrumentation

Before changing the proof layout, the generator should report the final MSM term
breakdown:

```text
normal queried commitments
linearization quotient limbs
linearization simple selectors
f_com
terms per point set
total pair count
precompile input bytes
```

That would identify which bucket contributes most of the 78 pairs and make the
next optimisation measurable instead of speculative.

### 3. Pre-Aggregate Duplicate Bases

If the same commitment appears more than once in the final MSM, it can be
combined safely:

```text
a*C + b*C = (a + b)*C
```

A quick check of the generated dump did not show obvious duplicate direct base
addresses among the parsed pairs, so this is likely low yield for the current
IVC verifier. It is still a useful generator invariant for other circuits.

### 4. A/B Test Materializing Linearization First

The current fused design is usually better because it avoids a separate
linearization MSM precompile. However, the precompile pricing is not perfectly
linear, so it is worth testing an env-flagged alternative:

```text
1. materialize LINEARIZATION_COM with a smaller MSM,
2. include LINEARIZATION_COM as one pair in the final MSM.
```

This may or may not beat the current fully fused path. It should be benchmarked
rather than assumed.

### 5. Avoid `fewer-point-sets` for This Cost Center

The real `fewer-point-sets` feature was tested earlier. It improved bytecode
size, but it did not reduce the main fused final MSM pair count in this design
and made gas worse by adding dummy scalar/evaluation work.

## Recommended Next Step

Add final-MSM term-category diagnostics to the code generator and benchmark
output. Once the 78 pairs are broken down by source, target the largest bucket.

The likely best follow-up is either:

- reducing simple-selector or queried-commitment count, if those dominate, or
- A/B testing materialized linearization if the linearization expansion is a
large share of the final MSM.
