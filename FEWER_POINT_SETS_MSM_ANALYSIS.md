# Fewer Point Sets MSM Analysis

Short version: `fewer-point-sets` helps bytecode size, but it does **not**
reduce the big MSM in the current fused-MSM design. It actually makes gas worse
in this bench.

I tried the real outer feature:

```sh
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
cargo test --release \
  --features evm,truncated-challenges,fewer-point-sets,solidity-gas-checkpoints \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --ignored --nocapture
```

It enabled the outer layout, but the Solidity verifier reverted:

```text
outer proof fewer-point-sets: enabled
proof eval scalars total: 259 (main: 102, dummy PCS: 157)
verifier reverted at gas_used = 2,069,550
```

Then I reran with `solidity-trace` so the final revert would not discard
checkpoint logs. That verifier returned `0`, so it is diagnostic only, but it
gives the section costs.

## Key MSM Observation

- Point sets dropped from `5` to `1`.
- Final fused MSM input stayed `65` pairs: generated staticcall input length was
  `0x28a0 = 65 * 0xa0`.
- Baseline latest commit also used a `65`-pair final MSM.
- So `fewer-point-sets` does not reduce the main MSM pair count after our
  fusion. It mostly trades point-set count for 157 dummy eval scalars.

## Fewer-Point-Sets Diagnostic Bench

```text
real section work: 1,833,230
baseline latest real section work: 1,681,292
delta: +151,938 gas
```

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
17   271       PCS block 1
18   8,528     PCS block 2 (x1 powers)
19   38,146    PCS block 3 set 0 (q_eval fold)
20   5,949     PCS block 4 (f_eval Lagrange interpolation)
21   452,539   PCS block 5 (final_com x4-power MSM + v)
14   25,435    PCS block 6
15   140,561   public accumulator pairing check
16   103,168   final proof ec_pairing
```

Relevant deltas vs latest baseline:

```text
evaluations/transcript: 107,867 -> 248,795  (+140,928)
PCS q_eval folds total: 11,092 -> 38,146    (+27,054)
PCS f_eval:             21,880 -> 5,949     (-15,931)
PCS final MSM:          458,782 -> 452,539  (-6,243)
```

Contract size does improve in the non-trace failed run:

```text
verifier runtime: 12,614 -> 10,465 bytes
total runtime:    47,937 -> 45,788 bytes
```

But for gas, it is the wrong trade here. Since the final MSM is already fused
over distinct commitments, reducing point sets no longer removes MSM terms; it
just adds dummy openings and more transcript/eval work.
