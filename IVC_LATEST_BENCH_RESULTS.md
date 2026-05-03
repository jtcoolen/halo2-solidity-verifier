# Latest IVC Keccak Solidity Bench Results

## Decider Outer Proof Without Fewer Point Sets

Command:

```sh
scripts/run_ivc_bench.sh --no-outer-fewer-point-sets --skip-srs-download
```

Result: PASS. The final Keccak IVC proof for two one-step Poseidon hash-chain
leaves was accepted on-chain. This run keeps the recursive in-circuit verifier
on the fewer-point-sets layout, but scopes the outer decider proof to the
non-fewer layout.

Feature shape:

```text
evm,truncated-challenges,in-circuit-fewer-point-sets,solidity-gas-checkpoints
```

### Summary

```text
total tx gas:              1,676,195
real checkpointed work:    1,512,643
checkpoint overhead:          19,500
verifier runtime:             16,463 bytes
VK runtime:                   15,136 bytes
quotient runtime:             18,318 bytes
total deployed runtime:       49,917 bytes
proof compressed:              5,056 bytes
proof padded:                  7,776 bytes
calldata:                      8,356 bytes
public inputs:                    14 field elements
```

### Evaluation Counts

```text
proof eval scalars total: 102 (main: 102, dummy PCS: 0)
instances: 1 proof eval from committed instance queries, 1 public-input eval computed locally
advice evals: 40
fixed evals: 17 proof evals, 10 simple-selector fixed columns omitted
permutation evals: 35 total (18 common/sigma, 17 product/Z across 6 sets)
lookup evals: 8 total (2 multiplicity, 2 helper, 4 accumulator z/z_next)
trash evals: 1
PCS point sets: 5
```

### Detailed Gas Checkpoints

| id | gas | % | section |
| ---: | ---: | ---: | --- |
| 2 | 5,037 | 0.3% | VK loading |
| 3 | 1,801 | 0.1% | VK digest + committed_pi + instance absorbs |
| 4 | 9,096 | 0.6% | user-phase advice reads + user challenge squeezes |
| 5 | 1,559 | 0.1% | theta squeeze + lookup multiplicities |
| 6 | 3,090 | 0.2% | beta/gamma + permutation Z products |
| 7 | 1,889 | 0.1% | lookup helpers + Z accumulators |
| 8 | 860 | 0.1% | trash_challenge + trashcans |
| 9 | 2,031 | 0.1% | y squeeze + quotient-limb reads |
| 10 | 18,553 | 1.2% | evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi |
| 11 | 19,952 | 1.3% | Lagrange + instance evaluation |
| 12 | 705,271 | 46.6% | batched identity numerator reconstruction |
| 13 | 2,828 | 0.2% | linearization scalar prep |
| 17 | 215 | 0.0% | PCS block 1, rotation points x*omega^rot |
| 18 | 5,621 | 0.4% | PCS block 2, x1 powers |
| 19 | 6,650 | 0.4% | PCS block 3 set 0, q_eval fold |
| 20 | 241 | 0.0% | PCS block 3 set 1, q_eval fold |
| 21 | 185 | 0.0% | PCS block 3 set 2, q_eval fold |
| 22 | 2,863 | 0.2% | PCS block 3 set 3, q_eval fold |
| 23 | 1,219 | 0.1% | PCS block 3 set 4, q_eval fold |
| 24 | 5,108 | 0.3% | PCS block 3, q_com input materialization |
| 25 | 18,349 | 1.2% | PCS block 4, f_eval Lagrange interpolation |
| 26 | 531,289 | 35.1% | PCS block 5, final_com x4-power MSM + v |
| 14 | 25,596 | 1.7% | PCS block 6, pairing inputs LHS/RHS |
| 15 | 40,822 | 2.7% | public accumulator pairing batch prep |
| 16 | 103,268 | 6.8% | final proof ec_pairing |

### Contract Sizes

```text
solc optimize runs: 1
solc CBOR metadata: omitted
Halo2Verifier.sol source bytes:           112,731
Halo2VerifyingKey.sol source bytes:        57,937
Halo2QuotientEvaluator.sol source bytes:  137,130
Halo2Verifier creation bytecode bytes:     17,020
Halo2VerifyingKey creation bytecode bytes: 14,832
Halo2QuotientEvaluator creation bytes:     18,344
Halo2Verifier deployed runtime bytes:      16,463
Halo2VerifyingKey deployed runtime bytes:  15,136
Halo2QuotientEvaluator runtime bytes:      18,318
total deployed runtime bytes:              49,917
```

### Main Remaining Gas Targets

```text
batched identity numerator reconstruction: 705,271 gas
PCS final fused MSM:                       531,289 gas
final proof ec_pairing:                    103,268 gas
public accumulator pairing batch prep:      40,822 gas
Lagrange + instance evaluation:             19,952 gas
```

## Default Outer Fewer-Point-Sets Comparison

Command:

```sh
scripts/run_ivc_bench.sh --skip-srs-download
```

Result: PASS. In this default run both the recursive verifier and the outer
decider proof use fewer point sets.

```text
total tx gas:              1,793,588
real checkpointed work:    1,556,056
checkpoint overhead:          16,500
verifier runtime:             13,817 bytes
VK runtime:                   15,136 bytes
quotient runtime:             18,318 bytes
total deployed runtime:       47,271 bytes
proof compressed:              9,952 bytes
proof padded:                 12,672 bytes
calldata:                     13,252 bytes
public inputs:                    14 field elements
proof eval scalars total:        259 (main: 102, dummy PCS: 157)
PCS point sets:                    1
```

Largest default sections:

```text
batched identity numerator reconstruction: 708,897 gas
PCS final fused MSM:                       529,034 gas
final proof ec_pairing:                    103,268 gas
evaluations/transcript tail:                43,294 gas
public accumulator pairing batch prep:      40,822 gas
```
