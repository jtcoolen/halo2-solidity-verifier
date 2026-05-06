# Further Gas / Bytecode Optimisation Candidates

This note captures the next optimisation ideas after the current generator
state: compact quotient VM, split quotient evaluator, fused PCS MSM, MCOPY
staging, batch inversion, public-accumulator fast paths, and final pairing
batching are already in place.

The remaining wins are mostly profile-specific. Pin the exact benchmark shape
before measuring deltas: the gas-oriented quotient profile and the smaller
compile-stable quotient profile make different tradeoffs, and
`scripts/run_ivc_bench.sh` may also change the result depending on whether
`outer-single-h-commitment` is enabled.

## 1. Gate production quotient trace hooks

Status: applied.

`templates/QuotientNumeratorBlock.yul` maintains a trace id and calls
`trace_u256` on every quotient fold even in production. In the external
quotient evaluator the logless hook still writes to memory.

Potential win:

- Lower gas in the batched identity numerator checkpoint.
- Some bytecode reduction in the quotient evaluator.

Risk / caveat:

- Existing comments say the hook is kept to stabilize the via-IR arithmetic
  shape. Benchmark both gas and runtime size after removing or gating it.

Validation run after applying the gate:

```text
command: scripts/run_ivc_bench.sh --skip-srs-download
shape: current worktree script default, outer single-H disabled
result: PASS
total tx gas: 1,300,701
real section work: 1,143,579
batched numerator section: 313,762
verifier runtime: 12,061 bytes
VK runtime: 15,136 bytes
quotient evaluator runtime: 23,448 bytes
```

## 2. Remove the selector y^-1 fold scheme

Status: applied, but measured as a bytecode win and a small gas regression for
the current IVC Keccak bench shape.

When simple selectors exist, the quotient VM computes `y_inv` with modexp and
updates `sel_scale` / `sel_inv_scale` for every identity. The selector identity
positions are known at codegen time.

Alternative:

- Emit gap-based selector bucket updates.
- Scale selector buckets only when a selector identity appears.
- Apply the final y-power gap once at the end.

Potential win:

- Remove one modexp in the quotient evaluator.
- Reduce repeated per-identity memory loads/stores and `mulmod`s.

Risk / caveat:

- The current forward-scan logic carefully matches Rust's reverse y-power
  selector grouping. The replacement needs trace-equivalence tests.

Validation run after applying the gap fold:

```text
command: scripts/run_ivc_bench.sh --skip-srs-download
shape: current worktree script default, outer single-H disabled
result: PASS
total tx gas: 1,301,676
real section work: 1,144,410
batched numerator section: 314,581
verifier runtime: 12,061 bytes
VK runtime: 15,168 bytes
quotient evaluator runtime: 22,698 bytes
total runtime: 49,927 bytes
```

Compared with the trace-gated baseline above, this saves 750 bytes in the
quotient evaluator runtime and 718 bytes overall, but increases checkpoint 12
by 819 gas and total transaction gas by 975. Keep this change only when runtime
size is the priority, or use it as a base for a cheaper selector-power scheme.

## 3. Replace native-gate top-N selection with a byte-budget knapsack

`native_gate_indices` currently picks the heaviest remaining gate identities by
compact-VM byte length. That does not necessarily maximize gas saved per byte
of extra native Yul.

Alternative:

- Estimate native gas saved per identity.
- Estimate native bytecode growth per identity.
- Select identities under the quotient evaluator runtime budget.
- Allow skipping a problematic identity, such as the currently unsafe fifth
  native gate, while trying the next best candidate.

Potential win:

- More quotient gas reduction without crossing EIP-170.
- A safer path than simply raising `HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES`.

Risk / caveat:

- Requires full proof validation for every selected identity set.

## 4. Make pinned dependency addresses non-public

The verifier exposes `AUTHORIZED_VK` and `AUTHORIZED_QUOTIENT` as public
immutables, which generates runtime getter code.

Alternative:

- Use `internal` or `private` immutables if external callers do not need the
  getters.

Potential win:

- Small verifier runtime bytecode reduction.

Risk / caveat:

- Loses a convenient on-chain introspection API unless a separate explicit
  getter is retained.

## 5. Specialize PCS q_eval source tables

The rolled q_eval path stages eval source addresses into scratch every proof.
Many generated layouts are contiguous or fixed-stride in memory.

Alternative:

- Detect contiguous/fixed-stride eval layouts at codegen time.
- Derive source addresses directly inside the q_eval loop.
- Fall back to the current staged address table for irregular layouts.

Potential win:

- Small gas and bytecode reduction in PCS block 3 / q_eval folds.

Risk / caveat:

- Likely modest compared with quotient and final MSM costs.

## 6. Optional: defer G1 coordinate bounds to EIP-2537

`common_uncompressed_g1` checks Fp coordinate bounds before hashing absorbed
points. If every absorbed proof point is guaranteed by the generated protocol
plan to be consumed by an EIP-2537 G1MSM or pairing call, the precompile will
eventually reject invalid coordinates.

Alternative:

- Keep the high-pad-byte canonicality checks before transcript absorption.
- Defer full coordinate validity to the later EIP-2537 precompile path.

Potential win:

- Small accepted-proof gas reduction in transcript commitment reads.

Risk / caveat:

- Invalid proofs fail later and spend more gas.
- This is a policy/security-review choice, not a free micro-optimisation.

## Structural wins outside local codegen

The fused PCS final MSM is now mostly bounded by EIP-2537 pair count. Real
movement there comes from proof and circuit shape rather than local verifier
emission:

- Enable/keep outer single-H when acceptable.
- Reduce opened advice/fixed/permutation/lookup/trash commitments.
- Reduce lookup helper commitments.
- Reduce queried rotations or columns.
- Reduce quotient commitment terms.

Each removed final-MSM term is expected to save roughly `6k-8k` gas, depending
on the surrounding G1MSM size and calldata changes.
