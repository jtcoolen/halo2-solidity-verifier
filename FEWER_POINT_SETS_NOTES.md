# Fewer Point Sets And Contract Size

## Summary

Disabling `fewer-point-sets` for the outer Solidity-facing proof helps proof
size and calldata size, but it does not materially reduce smart contract size.

The reason is that dummy queries mostly affect the PCS multi-open proof layout,
not the batched identity numerator reconstruction code.

## What Improved

With outer `fewer-point-sets` disabled, the final decider proof no longer carries
dummy PCS eval scalars:

```text
proof eval scalars: 259 -> 102
dummy PCS evals:    157 -> 0
compressed proof:   9952 -> 5056 bytes
calldata:           13188 -> 8292 bytes
```

This is a real calldata/proof-size win.

## Why Contract Size Did Not Shrink

Verifier bytecode is dominated by generated verifier logic, especially the
batched identity numerator reconstruction:

```text
gates + permutation identities + lookup identities + trash identities
```

Those identities are determined by the circuit and verifying key shape. They
still require the same advice, fixed, permutation, lookup, and trash evaluations
whether dummy PCS queries exist or not.

Dummy queries do not create those identities. They only add artificial PCS
openings so multiple multi-open point sets can be merged.

## Layout Tradeoff

With dummy queries:

```text
PCS point sets: fewer
proof eval scalars: more
calldata: larger
PCS verifier code/path: smaller/simpler
```

Without dummy queries:

```text
PCS point sets: more
proof eval scalars: fewer
calldata: smaller
PCS verifier code/path: larger/more sections
```

In the IVC decider benchmark:

```text
outer fewer-point-sets on:  1 PCS point set, 259 eval scalars
outer fewer-point-sets off: 5 PCS point sets, 102 eval scalars
```

So disabling dummy queries can slightly increase verifier bytecode, because the
PCS code has to handle more point-set folds.

## MSM Effect After Fused Final Commitment

After `fb6ff8c perf(evm): fuse PCS final commitment MSM`, the main PCS
commitment fold no longer materializes per-set `q_com` points. Instead it emits
one final MSM over all non-identity commitments:

```text
final_com = sum_{s,i} (x4^s * x1^i) * C[s][i] + x4^n_sets * f_com
```

That changes the expected benefit of `fewer-point-sets`. The feature can reduce
the number of point sets, but it does not reduce the number of distinct
commitments in the fused final MSM.

### Diagnostic Run

Command:

```sh
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
cargo test --release \
  --features evm,truncated-challenges,fewer-point-sets,solidity-gas-checkpoints \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --ignored --nocapture
```

The normal run enabled the outer fewer-point-sets layout, but the generated
Solidity verifier reverted:

```text
outer proof fewer-point-sets: enabled (dummy query evals expected)
proof eval scalars total: 259 (main: 102, dummy PCS: 157)
verifier reverted at gas_used = 2,069,550
```

To observe the section costs despite the final pairing failure, the bench was
rerun with `solidity-trace`, which skips the final revert and returns the raw
`success` bit. That diagnostic run returned `0`, so it is useful only for gas
attribution, not as a passing verifier result.

### Observed MSM Shape

```text
outer fewer-point-sets off: 5 PCS point sets, 102 proof eval scalars
outer fewer-point-sets on:  1 PCS point set, 259 proof eval scalars
```

With fewer-point-sets enabled, the generated final MSM staticcall used:

```text
input length = 0x28a0 = 65 * 0xa0
```

That is still a 65-pair final MSM, the same pair count as the fused-MSM baseline.
The feature collapsed the PCS point sets, but it did not reduce the number of
commitments staged into the final MSM.

### Detailed Diagnostic Breakdown

Diagnostic command:

```sh
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
cargo test --release \
  --features evm,truncated-challenges,fewer-point-sets,solidity-gas-checkpoints,solidity-trace \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --ignored --nocapture
```

Results:

```text
total tx gas_used:       2,108,542
real section work:       1,833,230
checkpoint overhead:        15,750
verifier return value:   0
```

Contract sizes:

```text
Halo2Verifier runtime:          10,919 bytes
Halo2VerifyingKey runtime:      13,568 bytes
Halo2QuotientEvaluator runtime: 21,755 bytes
total runtime:                  46,242 bytes
```

Section breakdown:

```text
id   gas       section
2    4,528     VK loading
3    12,247    VK digest + committed_pi + instance absorbs
4    7,392     user-phase advice reads + user challenge squeezes
5    3,320     theta squeeze + lookup multiplicities
6    5,290     beta/gamma + permutation Z products
7    1,126     lookup helpers + Z accumulators
8    2,591     trash_challenge + trashcans
9    2,985     y squeeze + quotient-limb reads
10   248,795   evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi
11   18,207    Lagrange + instance evaluation
12   633,286   batched identity numerator reconstruction
13   119,616   linearization-commitment MSM
17   271       PCS block 1 (rotation points)
18   8,528     PCS block 2 (x1 powers)
19   38,146    PCS block 3 set 0 (q_eval fold)
20   5,949     PCS block 4 (f_eval Lagrange interpolation)
21   452,539   PCS block 5 (final_com x4-power MSM + v)
14   25,435    PCS block 6 (pairing inputs)
15   140,561   public accumulator pairing check
16   103,168   final proof ec_pairing
```

Relevant deltas versus the fused-MSM baseline with outer fewer-point-sets
disabled:

```text
real section work:       1,681,292 -> 1,833,230  (+151,938)
evaluations/transcript:    107,867 ->   248,795  (+140,928)
PCS q_eval folds total:     11,092 ->    38,146  (+27,054)
PCS f_eval:                 21,880 ->     5,949  (-15,931)
PCS final MSM:             458,782 ->   452,539  (-6,243)
```

### Takeaway For MSMs

`fewer-point-sets` is not a useful gas optimisation for the current fused-MSM
verifier. It reduces point-set count and shrinks verifier bytecode, but the
large final commitment MSM remains a 65-pair MSM. The extra 157 dummy evals
increase transcript/evaluation work enough to dominate the small PCS savings.

## VM vs Non-VM Identity Reconstruction

The quotient/identity representation has a much larger effect on contract size:

```text
compact VM path:       small verifier bytecode, high identity gas
non-VM inline CSE:     large verifier bytecode, low identity gas
```

Observed non-VM inline CSE run with outer dummy queries disabled:

```text
batched identity numerator reconstruction: 121,625 gas
total tx gas: 1,458,659
Halo2Verifier runtime: 60,043 bytes
VK runtime: 6,752 bytes
total runtime: 66,795 bytes
```

This confirms the main contract-size bottleneck is the inlined identity
arithmetic, not dummy PCS eval scalars.

## Practical Takeaway

Use outer `fewer-point-sets` disabled when optimizing proof size and calldata.

Use the compact VM or a sharded/helper-contract identity evaluator when targeting
the 24 KB contract-size limit.

Use non-VM inline CSE when measuring the lower bound for identity reconstruction
gas, accepting that it is not deployable as a single contract under the 24 KB
limit.
