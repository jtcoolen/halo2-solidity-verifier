# Rust/Solidity Trace Variables

This file documents the differential trace shared by Midfall's native PLONK
verifier and this repo's generated Solidity verifier. The trace is used by the
IVC Keccak test in this repo and by Moonlight's wrap-decider Solidity bench.

The native side is Midfall's `midnight_proofs::plonk::solidity_trace` module.
The Solidity side is emitted by `templates/Halo2Verifier.sol` when rendered via
`SolidityGenerator::render_trace*`. Both sides key events by a numeric trace ID
and compare the raw payload bytes.

## Event Format

Each Solidity trace event is a `LOG1`:

| Payload | Solidity helper | Bytes |
| --- | --- | --- |
| Scalar / u256 | `trace_u256(id, value)` | 32-byte big-endian word |
| BLS12-381 G1 point | `trace_point(id, mptr)` | 128-byte EIP-2537 padded point |
| Variable-length diagnostic bytes | emitted from native trace only or matching Solidity point-set traces | depends on trace range |

Gas checkpoints are also `LOG1`, but they have empty data and encode
`(checkpoint_id << 248) | gas()` in the topic. Trace parsers skip empty-data
logs so gas checkpoints and differential trace events can coexist.

## Fixed IDs

| ID | Native Midfall name | Solidity source | Meaning |
| ---: | --- | --- | --- |
| 1 | `vk_digest` | `mload(VK_DIGEST_MPTR)` | Transcript representation of the verifying key digest. |
| 2 | `num_instances` | generated `num_instances` constant | Number of public instance values in the non-committed instance column. |
| 3 | `k` | generated domain `k` constant | Circuit domain size exponent. |
| 4 | `n_inv` | `mload(N_INV_MPTR)` | Inverse of domain size `n`. |
| 5 | `omega` | `mload(OMEGA_MPTR)` | Domain root of unity. |
| 6 | `omega_inv` | `mload(OMEGA_INV_MPTR)` | Inverse domain root of unity. |
| 7 | `theta` | `mload(THETA_MPTR)` | Lookup compression challenge. |
| 8 | `beta` | `mload(BETA_MPTR)` | Permutation challenge. |
| 9 | `gamma` | `mload(GAMMA_MPTR)` | Permutation challenge. |
| 10 | `y` | `mload(Y_MPTR)` | Quotient/identity batching challenge. |
| 11 | `x` | `mload(X_MPTR)` | Main evaluation challenge. |
| 12 | `trash_challenge` | `mload(TRASH_CHALLENGE_MPTR)` | Trash-argument challenge; emitted only when the circuit has trashcans. |
| 13 | `x1` | `mload(X1_MPTR)` | PCS batching challenge for point-set commitments/evaluations. |
| 14 | `x2` | `mload(X2_MPTR)` | PCS batching challenge for the `f_eval` fold. |
| 15 | `x3` | `mload(X3_MPTR)` | Evaluation point for the committed `f(X)` polynomial; truncated when `truncated-challenges` is enabled. |
| 16 | `x4` | `mload(X4_MPTR)` | Final PCS commitment/evaluation batching challenge. |
| 17 | `x_n` | `mload(X_N_MPTR)` | `x^n`, used by Lagrange and quotient reconstruction. |
| 18 | `x_n_minus_1_inv` | `mload(X_N_MINUS_1_INV_MPTR)` | `(x^n - 1)^-1`. |
| 19 | `l_last` | `mload(L_LAST_MPTR)` | Last-row Lagrange evaluation. |
| 20 | `l_blind` | `mload(L_BLIND_MPTR)` | Sum of blinding-row Lagrange evaluations. |
| 21 | `l_0` | `mload(L_0_MPTR)` | First-row Lagrange evaluation. |
| 22 | `instance_eval` | `mload(INSTANCE_EVAL_MPTR)` | Batched public-instance polynomial evaluation. |
| 23 | `linearization_expected_eval` | `mload(QUOTIENT_EVAL_MPTR)` | Expected linearization evaluation, equal to `-nu_y(x)`. |
| 24 | `linearization_scalars` | `trace_point(24, QUOTIENT_MPTR)` | 128-byte scalar payload shaped like a point: `x^(n-1)`, `1 - x^n`, `0`, `0`. |
| 25 | `f_com` | `trace_point(25, F_COM_MPTR)` | Proof commitment to the PCS accumulator polynomial `f(X)`. |
| 26 | `pi` | `trace_point(26, PI_MPTR)` | KZG opening proof point. |
| 27 | `pairing_lhs` | `trace_point(27, PAIRING_LHS_MPTR)` | Final KZG pairing left input. |
| 28 | `pairing_rhs` | `trace_point(28, PAIRING_RHS_MPTR)` | Final KZG pairing right input. |
| 29 | `acc_lhs` | `trace_point(29, ACC_LHS_MPTR)` | Generated public-accumulator check LHS point; generator-only for Solidity-facing accumulator checks. |
| 30 | `acc_rhs` | `trace_point(30, ACC_RHS_MPTR)` | Generated public-accumulator check RHS point; generator-only for Solidity-facing accumulator checks. |
| 31 | `f_eval` | `mload(F_EVAL_MPTR)` | Reconstructed evaluation of `f(X)` at `x3`. |
| 32 | `v` | `mload(V_MPTR)` | Final folded PCS evaluation scalar. |
| 33 | `final_com` | `trace_point(33, FINAL_COM_MPTR)` | Final folded PCS commitment. |
| 34 | `linearization_commitment` | trace-only MSM into `lin_scratch` | Materialized linearization commitment used to check the scalar/commitment fold. |
| 35 | `final_result` | `success` | Final pairing/precompile success word. |
| 36 | `quotient_numerator` | `-mload(QUOTIENT_EVAL_MPTR) mod Fr` | Fully grouped quotient numerator `nu_y(x)`. |

## Dynamic Ranges

| ID range | Native Midfall name | Solidity source | Meaning |
| ---: | --- | --- | --- |
| `1_000 + i` | `user_challenge` | `CHALLENGE_MPTR[i]` | User-phase challenge squeezed after phase-specific advice commitments. |
| `10_000 + i` | `proof_*_commitment` | `proof_commit_trace_id` | G1 proof commitments in transcript-read order: advice, lookup multiplicities, permutation products, lookup helpers/accumulators, trash commitments, quotient limbs, `f_com`, and `pi`. |
| `20_000 + i` | `proof_*_eval` | `proof_eval_trace_id` | Scalar proof evaluations in transcript-read order, including advice, fixed, permutation, lookup, trash, dummy PCS, and q-eval scalars. |
| `30_000 + i` | `quotient_identity_eval` | generated quotient identity trace ID | Raw partially evaluated identity term before the `y` fold. |
| `40_000 + i` | `pcs_q_com` | `trace_point(40_000 + i, ...)` from the PCS emitter | Materialized `q_com` commitment for sorted PCS point set `i`. |
| `41_000 + i` | `pcs_point_set` | serialized point-set trace from the PCS emitter | Concatenated scalar points in sorted PCS point set `i`. |
| `60_000 + i` | `selector_fold` | `SELECTOR_ACC_MPTR[i]` | Folded contribution for simple selector column `i`. |

`2_000 + i` is reserved in the codegen protocol for PCS query trace IDs, but
the current Midfall/Solidity differential does not emit that range.

## Comparison Rules

The trace tests compare every native Midfall event against a Solidity log with
the same ID and identical payload bytes. Solidity may additionally emit IDs 29
and 30 when the generated verifier checks a public accumulator, because that
check lives outside Midfall's native PLONK verifier.

The tests also require representative coverage for the challenge IDs, PCS
folds, pairing inputs, final result, `q_com` point-set commitments, serialized
PCS point sets, and selector folds. This keeps the trace from passing after a
large class of accidental instrumentation omissions.
