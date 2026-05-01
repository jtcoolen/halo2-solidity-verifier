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
