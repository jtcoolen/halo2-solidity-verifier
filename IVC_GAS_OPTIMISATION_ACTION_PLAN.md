# IVC Gas Optimisation Action Plan

Baseline command:

```sh
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
  scripts/run_ivc_bench.sh
```

Baseline result:

```text
PASS
total tx gas:                 1,843,843
real checkpointed work:       1,681,292
checkpoint overhead:             18,750
verifier runtime:               12,614 bytes
VK runtime:                     13,568 bytes
quotient evaluator runtime:     21,755 bytes
total deployed runtime:         47,937 bytes
```

## Current Cost Centers

Original baseline:

| id | gas | section |
| ---: | ---: | --- |
| 12 | 631,306 | batched identity numerator reconstruction |
| 25 | 458,782 | PCS block 5, final_com x4-power MSM + v |
| 15 | 140,561 | public accumulator pairing check |
| 13 | 119,613 | linearization-commitment MSM |
| 10 | 107,867 | evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi |
| 16 | 103,168 | final proof ec_pairing |

After applied optimisations 1, 2, and 4:

| id | gas | section |
| ---: | ---: | --- |
| 12 | 631,306 | batched identity numerator reconstruction |
| 25 | 537,088 | PCS block 5, final_com x4-power MSM + v |
| 10 | 107,867 | evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi |
| 16 | 103,168 | final proof ec_pairing |
| 15 | 38,875 | public accumulator pairing batch prep |
| 14 | 25,435 | PCS block 6, pairing inputs LHS/RHS |

## Optimisation Queue

### 1. Public Accumulator Scalar Fast Path

Status: applied and benchmarked.

The public accumulator block rebuilds accumulator points from public inputs and
then uses G1MSM even for scalar `1`. For collapsed IVC accumulators, the public
shape is commonly:

```text
lhs point, lhs scalar = 1
rhs point, rhs scalar = 1
```

Fast paths:

```text
scalar == 0 -> write G1 identity
scalar == 1 -> keep the loaded point
otherwise   -> call G1MSM
```

Expected win: `25k-45k` gas when accumulator scalars are `1`.

Risk: low. This only skips mathematically redundant scalar multiplication.

Implementation:

- LHS accumulator scalar:
  - `0` writes the identity point,
  - `1` keeps the decoded point in place,
  - any other scalar uses the existing one-pair G1MSM path.
- RHS accumulator scalar:
  - `0` skips the variable-base pair,
  - `1` keeps the decoded point directly when there is no fixed-base tail,
  - otherwise uses the existing MSM staging path.

Validation command:

```sh
cargo check --features evm,truncated-challenges,in-circuit-fewer-point-sets,solidity-gas-checkpoints

SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
  scripts/run_ivc_bench.sh
```

Benchmark result:

```text
PASS
total tx gas:                 1,819,533
real checkpointed work:       1,657,102
verifier runtime:               12,704 bytes
VK runtime:                     13,568 bytes
quotient evaluator runtime:     21,755 bytes
total deployed runtime:         48,027 bytes
```

Delta versus baseline:

```text
total tx gas:           1,843,843 -> 1,819,533  (-24,310)
real checkpointed work: 1,681,292 -> 1,657,102  (-24,190)
verifier runtime:          12,614 ->    12,704  (+90 bytes)
```

Section delta:

```text
public accumulator pairing check: 140,561 -> 116,371  (-24,190)
all other checkpoint deltas: unchanged
```

### 2. Fuse Linearization MSM Into PCS Final MSM

Status: applied and benchmarked.

Checkpoint 13 materializes:

```text
LINEARIZATION_COM =
  (1 - x^n) * sum_i x_split^i * Q_i
  + sum_j selector_acc_j * S_j
```

PCS block 5 later uses this linearized commitment as one term of the final
fused MSM. By linearity, the block 5 scalar for the linearized commitment can be
pushed into each quotient-limb and simple-selector term:

```text
lambda * LINEARIZATION_COM
```

becomes:

```text
lambda * (1 - x^n) * x_split^i * Q_i
lambda * selector_acc_j * S_j
```

Expected win: `30k-55k` gas if the extra pairs are cheaper than a separate MSM
precompile call.

Risk: medium. Requires keeping PCS query ordering, `q_eval_set`, and identity
commitment handling unchanged.

Implementation:

- Checkpoint 13 now only computes and stores `x_split` and `1 - x^n`.
- PCS block 5 recognizes the linearization commitment query and expands it into:
  - quotient-limb pairs `Q_i` with scalar
    `lambda * (1 - x^n) * x_split^i`,
  - simple-selector fixed commitment pairs with scalar
    `lambda * selector_acc_j`.
- PCS scratch was moved past the selector accumulator words. The first attempt
  reused the old scratch start, which overwrote selector accumulators before
  PCS block 5 consumed them.

Validation command:

```sh
cargo check --features evm,truncated-challenges,in-circuit-fewer-point-sets,solidity-gas-checkpoints

SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
  scripts/run_ivc_bench.sh
```

Benchmark result after optimisations 1 and 2:

```text
PASS
total tx gas:                 1,781,145
real checkpointed work:       1,618,642
verifier runtime:               12,859 bytes
VK runtime:                     13,568 bytes
quotient evaluator runtime:     21,755 bytes
total deployed runtime:         48,182 bytes
```

Delta versus original baseline:

```text
total tx gas:           1,843,843 -> 1,781,145  (-62,698)
real checkpointed work: 1,681,292 -> 1,618,642  (-62,650)
verifier runtime:          12,614 ->    12,859  (+245 bytes)
```

Delta versus optimisation 1 only:

```text
total tx gas:           1,819,533 -> 1,781,145  (-38,388)
real checkpointed work: 1,657,102 -> 1,618,642  (-38,460)
verifier runtime:          12,704 ->    12,859  (+155 bytes)
```

Section deltas versus optimisation 1 only:

```text
linearization commitment/scalar prep: 119,613 ->   2,826  (-116,787)
PCS final fused MSM:                 458,782 -> 537,088  (+78,306)
net section work:                                           -38,481
```

Latest detailed section bench:

```text
id   gas       section
2    4,528     VK loading
3    12,247    VK digest + committed_pi + instance absorbs
4    6,207     user-phase advice reads + user challenge squeezes
5    3,315     theta squeeze + lookup multiplicities
6    5,275     beta/gamma + permutation Z products
7    1,116     lookup helpers + Z accumulators
8    2,589     trash_challenge + trashcans
9    2,976     y squeeze + quotient-limb reads
10   107,867   evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi
11   18,190    Lagrange + instance evaluation
12   631,306   batched identity numerator reconstruction
13   2,826     linearization scalar prep
17   215       PCS block 1, rotation points
18   5,624     PCS block 2, x1 powers
19   6,661     PCS block 3 set 0, q_eval fold
20   241       PCS block 3 set 1, q_eval fold
21   185       PCS block 3 set 2, q_eval fold
22   2,863     PCS block 3 set 3, q_eval fold
23   1,219     PCS block 3 set 4, q_eval fold
24   21,880    PCS block 4, f_eval Lagrange interpolation
25   537,088   PCS block 5, final_com x4-power MSM + v
14   25,435    PCS block 6, pairing inputs LHS/RHS
15   116,371   public accumulator pairing check
16   103,168   final proof ec_pairing
```

### 3. Quotient Native Callbacks / VM Opcodes

Status: measured; no additional safe change applied.

Checkpoint 12 is the largest section. The current quotient evaluator fits under
24 KiB but pays VM dispatch overhead. Available knobs:

```text
HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=N
HALO2_SOLIDITY_QUOTIENT_NATIVE_PERMUTATION=1
HALO2_SOLIDITY_QUOTIENT_VM_CSE=1
HALO2_SOLIDITY_QUOTIENT_ENCODING=packed32
```

Known constraint: raising native gates too far previously broke the IVC verifier
or exhausted helper bytecode headroom. The safe next step is an A/B sweep of
small values with full bench validation and contract-size tracking.

Expected win: `50k-200k` gas if more heavy identities can be native without
breaking the quotient evaluator size budget.

Risk: medium.

Measured sweeps:

```text
default:
  native permutation: on
  native gates: 4
  VM CSE: on
  encoding: bytes
  quotient runtime: 21,755 bytes
  result: PASS

HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=5:
  quotient runtime: 24,464 bytes
  result: FAIL, verifier reverted at gas_used = 1,755,588
  note: fits just under 24 KiB but is not currently correct for this proof.

HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=6:
  quotient runtime: 30,532 bytes
  result: FAIL, over EIP-170 helper budget and verifier reverted

HALO2_SOLIDITY_QUOTIENT_ENCODING=packed32:
  quotient runtime: 21,353 bytes
  VK runtime: 16,448 bytes
  result: FAIL, verifier reverted after consuming almost the whole gas limit
```

Conclusion:

The current quotient settings are already at the safe point for this bench.
More native gate callbacks need a correctness fix before they can be used, and
`packed32` is not safe in the current generated verifier. The next quotient
work should be a targeted debugging pass for native gate 5, not a blind gas
optimisation.

### 4. Batch Public Accumulator Pairing With Final KZG Pairing

Status: applied and benchmarked.

The verifier currently performs two separate pairings:

```text
public accumulator pairing
final KZG pairing
```

The two equations use the same G2 bases, so we can combine in G1 and keep a
single 2-pair pairing check:

```text
combined_rhs = KZG_RHS + alpha * ACC_RHS
combined_lhs = KZG_LHS + alpha * ACC_LHS
check e(combined_rhs, G2) * e(combined_lhs, -sG2) == 1
```

`alpha` is derived after all four G1 pairing inputs are fixed:

```text
alpha = keccak256(domain || KZG_RHS || KZG_LHS || ACC_RHS || ACC_LHS) mod Fr
```

This avoids the unsound deterministic product check where two invalid pairing
equations could cancel.

Benchmark result after optimisations 1, 2, and 4:

```text
PASS
total tx gas:                 1,703,601
real checkpointed work:       1,541,146
verifier runtime:               13,008 bytes
VK runtime:                     13,568 bytes
quotient evaluator runtime:     21,755 bytes
total deployed runtime:         48,331 bytes
```

Delta versus optimisation 1+2:

```text
total tx gas:           1,781,145 -> 1,703,601  (-77,544)
real checkpointed work: 1,618,642 -> 1,541,146  (-77,496)
verifier runtime:          12,859 ->    13,008  (+149 bytes)
```

Delta versus original baseline:

```text
total tx gas:           1,843,843 -> 1,703,601  (-140,242)
real checkpointed work: 1,681,292 -> 1,541,146  (-140,146)
verifier runtime:          12,614 ->    13,008  (+394 bytes)
```

Section delta:

```text
public accumulator pairing check/prep: 116,371 -> 38,875  (-77,496)
final proof ec_pairing:                103,168 -> 103,168 (unchanged)
```

Latest detailed section bench:

```text
id   gas       section
2    4,528     VK loading
3    12,247    VK digest + committed_pi + instance absorbs
4    6,207     user-phase advice reads + user challenge squeezes
5    3,315     theta squeeze + lookup multiplicities
6    5,275     beta/gamma + permutation Z products
7    1,116     lookup helpers + Z accumulators
8    2,589     trash_challenge + trashcans
9    2,976     y squeeze + quotient-limb reads
10   107,867   evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi
11   18,190    Lagrange + instance evaluation
12   631,306   batched identity numerator reconstruction
13   2,826     linearization scalar prep
17   215       PCS block 1, rotation points
18   5,624     PCS block 2, x1 powers
19   6,661     PCS block 3 set 0, q_eval fold
20   241       PCS block 3 set 1, q_eval fold
21   185       PCS block 3 set 2, q_eval fold
22   2,863     PCS block 3 set 3, q_eval fold
23   1,219     PCS block 3 set 4, q_eval fold
24   21,880    PCS block 4, f_eval Lagrange interpolation
25   537,088   PCS block 5, final_com x4-power MSM + v
14   25,435    PCS block 6, pairing inputs LHS/RHS
15   38,875    public accumulator pairing batch prep
16   103,168   final proof ec_pairing
```

### 5. Proof-Shape Reduction For The 65-Pair Final MSM

Status: assessed; not implemented in this patch.

The fused PCS final MSM is a 65-pair G1MSM. Local point-set changes do not
reduce this pair count; `fewer-point-sets` was measured to keep the same
65-pair MSM and worsen gas through dummy eval overhead.

Useful changes are proof-shape changes:

- fewer opened advice commitments,
- fewer fixed/permutation/lookup/trash commitments,
- fewer lookup helper commitments,
- fewer quotient limbs,
- fewer queried rotations/columns.

Expected win: roughly `6k-8k` gas per removed commitment in the final MSM.

Risk: circuit/protocol dependent.

Conclusion:

No local verifier patch can remove these final MSM terms after the current
fusion. The earlier `fewer-point-sets` experiment confirmed that point-set
layout changes did not reduce the 65-pair fused MSM; they added dummy eval work
instead. Real savings here require changing the circuit/proof shape.

## Reporting Template

For each implemented optimisation, record:

```text
command:
result:
total tx gas:
real checkpointed work:
runtime sizes:
section deltas:
notes:
```
