# Generated Verifier Memory Layout

This document explains the internal memory planner used by Solidity codegen.
The planner lives in `src/codegen/memory.rs`.

The generated verifier uses absolute Yul memory addresses. This is intentional:
it keeps verifier code compact, makes EIP-2537 and modexp precompile frames easy
to build, and lets the external quotient evaluator receive the same memory image
as the monolithic verifier. The cost is that memory safety has to be proven by
codegen, not by Solidity's free-memory pointer.

The current planner is conservative. It preserves the existing generated
addresses, but the offsets are now derived by Rust compatibility manifests
(`VerifierMemoryLayout`, `ThetaWindowLayout`, and the proof/VK layout helpers)
before being rendered into Solidity/Yul. It is not a deterministic repacker
yet.

## Solidity Memory Model Boundary

Solidity reserves the first four words of memory for compiler conventions:

- `0x00..0x3f`: scratch space;
- `0x40..0x5f`: the free-memory pointer;
- `0x60..0x7f`: the zero slot used as the initial value for dynamic memory
  arrays;
- `0x80`: the initial allocatable memory pointer.

The generated verifier intentionally does not follow Solidity allocation by
reading and bumping `mload(0x40)`. Instead, every generated absolute memory
region is planned at or above `0x80`. The streaming transcript buffer, the main
verifier return word, the split quotient return frame, the VK constructor
payload buffer, and low-memory precompile scratch all start from named
Rust-side layout constants rooted at `SOLIDITY_ALLOCATABLE_MEMORY_START`.

The code generator treats `[0x00..0x80)` as off limits for generated writes:
`VerifierMemoryLayout::validate()` rejects any registered region inside that
reserved prefix, and template tests pin the remaining hand-written return and
scratch frames to `0x80` or above.

The verifier still has a constrained generated-contract shape:

1. `verifyProof` is an external entrypoint with `calldata` arguments, so the
   proof and instances are not eagerly decoded into Solidity-managed memory.
2. The high-level Solidity work before the main verifier block is limited to
   value-type dependency checks. Accepted executions then enter the generated
   `assembly ("memory-safe")` body.
3. The main verifier assembly body is terminal: every path either reverts or
   ends with `return(RETURN_MPTR, 0x20)`.
4. The split `Halo2QuotientEvaluator` fallback has its own fresh EVM memory
   frame, copies the verifier frame into generated absolute addresses, writes
   its compact return frame at `0x80`, and immediately returns.
5. The `Halo2VerifyingKey` constructor writes `INVALID || runtime payload`
   starting at `0x80` and immediately returns that prefixed runtime as contract
   code. The verifier later skips byte `0` and copies only the payload.

Do not move the generated verifier assembly into a reusable internal Solidity
function, library routine, or wrapper that continues executing high-level
Solidity after the block without reviewing the absolute-memory strategy. Future
dynamic-allocation work should use `mload(0x40)`/`mstore(0x40, ...)` instead of
hard-coded high-water marks, but the current generator at least preserves
Solidity's reserved prefix.

Relevant Solidity references:

- Layout in memory:
  <https://docs.soliditylang.org/en/latest/internals/layout_in_memory.html>
- Inline assembly memory safety:
  <https://docs.soliditylang.org/en/latest/assembly.html#memory-safety>
- Advanced safe use of memory:
  <https://docs.soliditylang.org/en/latest/assembly.html#advanced-safe-use-of-memory>
- EVM call memory is freshly cleared per message call:
  <https://docs.soliditylang.org/en/latest/introduction-to-smart-contracts.html#storage-transient-storage-memory-and-the-stack>

## Planner APIs

`MemoryArena` owns the memory map. It has three compatibility-mode allocation
primitives:

| API | Purpose |
| --- | --- |
| `alloc_fixed(name, start, len, lifetime)` | Register a region at an explicit historical or precompile-required byte address. |
| `alloc_after(name, anchor_start, anchor_len, len, lifetime)` | Register a region immediately after an anchor range, rounded up to the next EVM word. |
| `alloc_phase_scratch(name, start, len, phase)` | Register fixed-address scratch that is live only during one `MemoryPhase`. |

`ScratchAllocator` is rooted at a fixed base and keeps one cursor per phase.
Allocations in the same phase advance sequentially; allocations in different
phases intentionally reuse the base. That models the current verifier layout
without repacking it:

```text
base = quotient_tmp_mptr

QuotientVm:
  quotient_temps -> base
  quotient_stack -> base + quotient_temps_len

PcsQEvalSourceTable:
  q_eval source table -> base

PcsQComTrace:
  optional q_com trace MSM -> base

PcsFinalMsm:
  final MSM input -> base
```

## Units

All planned regions are byte ranges, but every start and length must be aligned
to `WORD_BYTES == 0x20`.

| Name | Value | Why |
| --- | ---: | --- |
| `WORD_BYTES` | `0x20` | EVM word size; all `mload`/`mstore` and Fr scalars are word-sized. |
| `FR_WORDS` / `FR_BYTES` | `1` / `0x20` | BLS12-381 Fr scalar as one canonical calldata/memory word. |
| `G1_WORDS` / `G1_BYTES` | `4` / `0x80` | EIP-2537 padded G1: `x_hi, x_lo, y_hi, y_lo`. |
| `G2_WORDS` / `G2_BYTES` | `8` / `0x100` | EIP-2537 padded G2: two Fp2 coordinates, two words per Fp limb. |
| `G1_MSM_PAIR_BYTES` | `0xa0` | G1MSM precompile input tuple: one G1 plus one scalar. |
| `G1ADD_INPUT_BYTES` | `0x100` | G1ADD precompile input tuple: two G1 points. |
| `MODEXP_FRAME_BYTES` | `0xc0` | 32-byte base/exp/mod frame: three length words plus three values. |
| `PAIRING_PAIR_BYTES` | `0x180` | Pairing tuple: one G1 plus one G2. |
| `PAIRING_TWO_PAIR_BYTES` | `0x300` | Final KZG pairing uses two `(G1, G2)` pairs. |
| `ACC_MSM_MIN_SCRATCH_BYTES` | `0x7000` | Historical accumulator MSM floor; preserves existing generated addresses for smaller circuits. |

## Layout Construction

`SolidityGenerator` chooses a stable `VK_MPTR` after proof-shape planning. This
matters because `outer-fewer-point-sets` can add dummy evals and point sets,
which changes the transcript-buffer bound. The verifier reserves:

1. transient transcript buffer below `VK_MPTR`;
2. VK payload at `VK_MPTR`;
3. user challenge slots after the VK payload;
4. computed compatibility theta-relative slots;
5. decoded evals and decompressed commitments;
6. phase-scoped scratch regions;
7. one non-overlapping `trace_u256` log word after all live regions.

`VerifierMemoryLayout::validate()` rejects:

- unaligned starts or lengths;
- any generated region inside Solidity-reserved memory `[0x00..0x80)`;
- overlapping permanent regions;
- overlapping scratch regions that are live in the same `MemoryPhase`;
- PCS fixed-window overflows.

Intentional reuse is represented by giving the same byte range disjoint
lifetimes. For example, `batch_invert_scratch`, quotient VM scratch, q_eval
source tables, q_com trace scratch, and final MSM scratch can share bytes when
their phases do not overlap.

The `trace_u256` log word is deliberately not a historical fixed constant.
Trace hooks can run between reads from long-lived VK/eval/commitment memory, so
their one-word `mstore` must sit outside every permanent and phase-scoped
region. This avoids the old failure mode where a diagnostic log buffer inside a
large VK payload corrupted a later G1MSM input.

The external quotient evaluator has a separate EVM memory space. Its trace hook
is logless because the evaluator is called through `STATICCALL`, so it uses the
callee-local quotient return buffer at `0x80` and overwrites that word with the
return-frame magic immediately before returning. It must not use the verifier's
high `trace_u256_mptr`, which can overlap the evaluator's VM stack in the
callee.

## Theta-Relative Offsets

`THETA_MPTR` is the anchor for the historical fixed verifier state.
`ThetaWindowLayout::compatibility()` computes the window starts from named slot
sizes, historical capacities, and padding, then validation pins the resulting
addresses. The offsets below are in 32-byte words from `THETA_MPTR`.

| Offset | Region | Size | Justification |
| ---: | --- | ---: | --- |
| `0` | `theta` | 1 word | First challenge after user-phase challenges. |
| `1` | `beta` | 1 word | Permutation/lookup challenge. |
| `2` | `gamma` | 1 word | Permutation/lookup challenge. |
| `3` | `trash_challenge` | 1 word | Trashcan challenge. |
| `4` | `y` | 1 word | Identity-evaluation batching challenge. |
| `5` | `x` | 1 word | Evaluation point. |
| `6` | `x1` | 1 word | PCS multi-prepare commitment fold challenge. |
| `7` | `x2` | 1 word | PCS f_eval Horner challenge. |
| `8` | `x3` | 1 word | PCS interpolation point. |
| `9` | `x4` | 1 word | PCS final_com fold challenge. |
| `10` | `f_com` | 4 words | Trailing PCS commitment, padded G1. |
| `14` | `pi` | 4 words | Final KZG opening commitment, padded G1. |
| `18` | `acc_lhs` | 4 words | Public accumulator LHS point. |
| `22` | `acc_rhs` | 4 words | Public accumulator RHS point. |
| `26` | `x_n` | 1 word | Lagrange numerator. |
| `27` | `x_n_minus_1_inv` | 1 word | Inverse used by Lagrange terms. |
| `28` | `l_last` | 1 word | Last-row Lagrange value. |
| `29` | `l_blind` | 1 word | Blind-row Lagrange value. |
| `30` | `l_0` | 1 word | First-row Lagrange value. |
| `31` | `instance_eval` | 1 word | Locally computed public-input evaluation. |
| `32` | `quotient_eval` | 1 word | Expected opening scalar for the linearized commitment. |
| `33` | `quotient` scratch | 4 words | Production uses first two words for `x_split` and `1 - x_n`; trace treats four words as a G1-shaped point. |
| `37` | padding | 1 word | Kept unused to preserve old downstream offsets. |
| `38` | `f_eval` | 1 word | PCS aggregated evaluation. |
| `39` | `v` | 1 word | Final folded evaluation. |
| `40` | `final_com` | 4 words | Output of fused final PCS MSM. |
| `44` | `pairing_lhs` | 4 words | KZG pairing LHS G1. |
| `48` | `pairing_rhs` | 4 words | KZG pairing RHS G1. |
| `52` | `rot_points` | up to 28 words | Historical PCS fixed window for `x * omega^rot`. |
| `80` | `x1_powers` | up to 65 words | Historical PCS fixed window for powers of `x1`. |
| `145` | `q_com` / `q_eval_set` | 0 / up to 56 words | `q_com` is fused into MSM scratch, so it aliases `q_eval_set` with zero capacity. |
| `201` | `q_eval_cptr` | 1 word | Runtime calldata pointer to q_eval scalars. |
| `209` | `g1_identity` | 4 words | Zero-initialized padded G1 identity. |
| `220` | `reversed_evals` | `num_evals` words | Decoded scalar eval buffer. |
| `220 + num_evals` | commitment bases | dynamic | Decompressed proof G1s, contiguous by category. |

The gaps between fixed windows are deliberate historical padding. Do not use
them as scratch without registering a `MemoryRegion` and a phase.

## Dynamic Commitment Region

The commitment region begins at:

```text
comms_mptr_base = THETA_MPTR + (220 + num_evals) * WORD_BYTES
```

Each commitment is a padded G1 (`G1_BYTES == 0x80`). The category bases are:

```text
advice
lookup multiplicity
permutation Z
lookup helpers
lookup accumulator Z
trashcan commitments
quotient limbs
```

`selector_acc_mptr` is the first word after all decompressed commitments. The
selector accumulator words are live during final linearization and final PCS
MSM, so the generic PCS scratch begins after that selector block:

```text
quotient_tmp_mptr = selector_acc_mptr + num_simple_selectors * WORD_BYTES
PCS scratch base  = quotient_tmp_mptr
```

## Scratch Lifetimes

The planner validates by lifetime, not just by address.

| Phase | Region examples | Notes |
| --- | --- | --- |
| `Transcript` | `[0, transcript_words * 0x20)` | Must stay below `VK_MPTR`. |
| `ScalarInv` | `VK_MPTR - 0x100` frame | Historical modexp scratch near the VK payload. |
| `LagrangeBatchInvert` | `batch_invert_scratch_mptr` | Reuses selector bytes before selector accumulators are live. |
| `QuotientVm` | quotient temps and stack | Used before PCS final MSM. |
| `PcsQEvalSourceTable` | rolled q_eval address table | Aliases `pcs_scratch_mptr`. |
| `PcsQComTrace` | optional q_com trace MSM | Aliases `pcs_scratch_mptr`; trace-only. |
| `PcsFinalMsm` | final MSM input and selector accumulators | Selector accumulators and final MSM must not overlap in this phase. |
| `AccumulatorMsm` | public accumulator MSM input | Length is derived from accumulator/VK shape. |
| `AccumulatorPairingBatch` | `[0x100, 0x320)` | Hash domain plus four G1 points for accumulator pairing batching. |
| `FinalPairing` | two-pair KZG pairing frame | Low-memory final precompile frame. |

## Update Rules

When changing generated memory usage:

1. Add or update the named region in `VerifierMemoryLayout`.
2. Register it through `MemoryArena` with the narrowest correct lifetime.
3. Use named constants (`WORD_BYTES`, `G1_BYTES`, `G1_MSM_PAIR_BYTES`, etc.)
   instead of raw byte literals when the literal describes layout.
4. If a fixed theta-relative offset changes, update `ThetaWindowLayout`, this
   document, and the synthetic layout test.
5. If a scratch region can grow from circuit/VK shape, add it to
   `PcsMemoryRequirements` or `VerifierMemoryLayoutConfig`.
6. Run `cargo test --lib --all-features` at minimum; for verifier-impacting
   changes also run the ignored Poseidon/IVC commands from `TESTING.md`.
