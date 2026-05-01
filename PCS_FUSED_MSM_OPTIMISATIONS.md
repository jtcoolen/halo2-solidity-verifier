# PCS Fused MSM Optimisations

Latest commit documented: `fb6ff8c perf(evm): fuse PCS final commitment MSM`

This note records the PCS optimisations used by the latest commit so the
reasoning is visible outside the git commit message.

## Context

The GWC19 multi-prepare verifier builds intermediate point sets and then folds
commitments and evaluations with transcript challenges:

```text
q_com[s]      = sum_i x1^i * C[s][i]
q_eval_set[s] = sum_i x1^i * eval(C[s][i])
final_com     = sum_s x4^s * q_com[s] + x4^n_sets * f_com
v             = sum_s x4^s * q_eval[s] + x4^n_sets * f_eval
```

Before this change, generated Yul materialised each `q_com[s]` with a per-set
G1MSM and then folded those points again with `x4` powers. That paid for
intermediate commitment work even though the intermediate `q_com` points are not
needed after the final fold.

## Optimisations Used

### 1. Stop Materialising Per-Set `q_com`

PCS block 3 now computes only the scalar folds `q_eval_set[s]`.

`q_eval_set` is still required by block 4, which evaluates the interpolated
polynomial `f` at `x3`. The commitment counterpart `q_com[s]` is not required
as a standalone point once the final commitment is computed directly.

### 2. Fuse `q_com` and `final_com` Into One G1MSM

The final commitment uses linearity to combine the two old stages:

```text
final_com
  = sum_s x4^s * q_com[s] + x4^n_sets * f_com
  = sum_{s,i} (x4^s * x1^i) * C[s][i] + x4^n_sets * f_com
```

The generated verifier now stages all non-identity commitment terms into one
G1MSM input buffer and calls the EIP-2537 G1MSM precompile once.

The staged scalar for each commitment is:

```text
set 0:      x1^i
set s > 0:  x4^s * x1^i
f_com:      x4^n_sets
```

When truncated challenges are enabled, the generated `x4` powers preserve the
same semantics as Midnight proofs: the internal power accumulator is full width,
and each emitted power is truncated to 128 bits.

### 3. Skip G1 Identity Commitments in the MSM

Committed-instance commitments are represented by the G1 identity point. They
must still contribute their scalar evaluations to `q_eval_set`, but they do not
change `final_com`.

The final fused MSM filters out identity commitments while preserving their
evaluation contribution in block 3. This avoids paying a pair slot for a point
that contributes zero to the commitment fold.

### 4. Reuse PCS Scratch Memory

The codegen path now builds the point-set grouping once and reuses the same PCS
scratch region for:

- q-eval address tables,
- the final fused MSM input buffer,
- final commitment output staging.

This reduces duplicated staging logic and keeps the generated verifier smaller.

### 5. Keep `v` and `f_eval` Semantics Unchanged

The optimisation changes only the commitment-side fold. The scalar side remains:

```text
v = sum_s x4^s * q_eval[s] + x4^n_sets * f_eval
```

Block 4 still computes `f_eval` from the `q_eval_set` vectors with Lagrange
interpolation at `x3`, so the pairing equation is unchanged.

### 6. Associated Cleanup

The same commit also:

- renames gas labels from `q_com/q_eval fold` to `q_eval fold`,
- updates the IVC replay harness to deploy and wire `Halo2QuotientEvaluator`,
- scopes quotient helper arithmetic through a local `q_r := FR_MODULUS` alias to
  trim emitted helper code.

## Measured IVC Bench Result

Command:

```sh
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
  scripts/run_ivc_bench.sh
```

Result:

```text
PASS: final Keccak IVC proof accepted on-chain
total tx gas: 1,843,843
real section work: 1,681,292
checkpoint overhead: 18,750
```

Contract sizes:

| contract | runtime bytes |
| --- | ---: |
| Halo2Verifier | 12,614 |
| Halo2VerifyingKey | 13,568 |
| Halo2QuotientEvaluator | 21,755 |
| total deployed runtime | 47,937 |

Relevant PCS sections:

| id | gas | section |
| ---: | ---: | --- |
| 19 | 6,584 | PCS block 3 set 0 (q_eval fold) |
| 20 | 241 | PCS block 3 set 1 (q_eval fold) |
| 21 | 185 | PCS block 3 set 2 (q_eval fold) |
| 22 | 2,863 | PCS block 3 set 3 (q_eval fold) |
| 23 | 1,219 | PCS block 3 set 4 (q_eval fold) |
| 24 | 21,880 | PCS block 4 (f_eval Lagrange interpolation) |
| 25 | 458,782 | PCS block 5 (final_com x4-power MSM + v) |

The main benefit is that block 3 no longer pays for per-set commitment MSMs.
The remaining PCS cost is concentrated in the single fused final commitment MSM,
which is now the unavoidable large commitment fold rather than duplicate
intermediate work.

## Validation Commands

```sh
cargo check --features evm,truncated-challenges,in-circuit-fewer-point-sets,solidity-gas-checkpoints

SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
  cargo test --release \
  --features evm,truncated-challenges,solidity-gas-checkpoints \
  --test poseidon_fixture poseidon_renders_compiles_and_verifies \
  -- --ignored --nocapture

SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
  cargo test --release \
  --features evm,truncated-challenges,in-circuit-fewer-point-sets,solidity-gas-checkpoints \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --ignored --nocapture
```
