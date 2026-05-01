# Latest IVC Keccak Solidity Bench Results

Command:

```sh
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
  scripts/run_ivc_bench.sh
```

Result: PASS. The final Keccak IVC proof was accepted on-chain.

## Summary

```text
total tx gas:              1,703,601
real checkpointed work:    1,541,146
checkpoint overhead:          18,750
verifier runtime:             13,008 bytes
VK runtime:                   13,568 bytes
quotient runtime:             21,755 bytes
total deployed runtime:       48,331 bytes
proof compressed:              5,056 bytes
proof padded:                  7,776 bytes
calldata:                      8,292 bytes
```

## Evaluation Counts

```text
proof eval scalars total: 102 (main: 102, dummy PCS: 0)
instances: 1 proof eval, 1 public-input eval computed locally
advice evals: 40
fixed evals: 17 proof evals, 10 simple-selector fixed columns omitted
permutation evals: 35 total
lookup evals: 8 total
trash evals: 1
PCS point sets: 5
```

## Detailed Gas Checkpoints

| id | gas | % | section |
| ---: | ---: | ---: | --- |
| 2 | 4,528 | 0.3% | VK loading |
| 3 | 12,247 | 0.8% | VK digest + committed_pi + instance absorbs |
| 4 | 6,207 | 0.4% | user-phase advice reads + user challenge squeezes |
| 5 | 3,315 | 0.2% | theta squeeze + lookup multiplicities |
| 6 | 5,275 | 0.3% | beta/gamma + permutation Z products |
| 7 | 1,116 | 0.1% | lookup helpers + Z accumulators |
| 8 | 2,589 | 0.2% | trash_challenge + trashcans |
| 9 | 2,976 | 0.2% | y squeeze + quotient-limb reads |
| 10 | 107,867 | 7.0% | evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi |
| 11 | 18,190 | 1.2% | Lagrange + instance evaluation |
| 12 | 631,306 | 41.0% | batched identity numerator reconstruction |
| 13 | 2,826 | 0.2% | linearization scalar prep |
| 17 | 215 | 0.0% | PCS block 1, rotation points x*omega^rot |
| 18 | 5,624 | 0.4% | PCS block 2, x1 powers |
| 19 | 6,661 | 0.4% | PCS block 3 set 0, q_eval fold |
| 20 | 241 | 0.0% | PCS block 3 set 1, q_eval fold |
| 21 | 185 | 0.0% | PCS block 3 set 2, q_eval fold |
| 22 | 2,863 | 0.2% | PCS block 3 set 3, q_eval fold |
| 23 | 1,219 | 0.1% | PCS block 3 set 4, q_eval fold |
| 24 | 21,880 | 1.4% | PCS block 4, f_eval Lagrange interpolation |
| 25 | 537,088 | 34.8% | PCS block 5, final_com x4-power MSM + v |
| 14 | 25,435 | 1.7% | PCS block 6, pairing inputs LHS/RHS |
| 15 | 38,875 | 2.5% | public accumulator pairing batch prep |
| 16 | 103,168 | 6.7% | final proof ec_pairing |

## Contract Sizes

```text
solc optimize runs: 1
solc CBOR metadata: omitted
Halo2Verifier.sol source bytes:            91,543
Halo2VerifyingKey.sol source bytes:        52,009
Halo2QuotientEvaluator.sol source bytes:  133,281
Halo2Verifier creation bytecode bytes:     13,380
Halo2VerifyingKey creation bytecode bytes: 13,047
Halo2QuotientEvaluator creation bytes:     21,781
Halo2Verifier deployed runtime bytes:      13,008
Halo2VerifyingKey deployed runtime bytes:  13,568
Halo2QuotientEvaluator runtime bytes:      21,755
total deployed runtime bytes:              48,331
```

## Main Remaining Gas Targets

```text
batched identity numerator reconstruction: 631,306 gas
PCS final fused MSM:                       537,088 gas
final proof ec_pairing:                    103,168 gas
evaluations/transcript tail:               107,867 gas
```
