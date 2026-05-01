# Quotient Evaluation Contract Size Optimization

## Context

The generated Solidity verifier currently emits the batched identity numerator
reconstruction as straight-line Yul/Solidity arithmetic. Historically we called
this "quotient evaluation", but the verifier is not directly evaluating
`h(x)`. It reconstructs `nu_y(x)` from alleged polynomial evaluations and stores
`-nu_y(x)` as the expected opening scalar for the linearized commitment. For
large Halo2/Midnight-ZK circuits this can produce thousands of arithmetic
statements. The runtime cost is pure `Fr` arithmetic, but the generated code
occupies a large amount of verifier bytecode.

This matters because the main verifier contract must stay under the EIP-170
runtime bytecode limit of 24 KiB when it is deployed on a normal EVM chain. Even
when the verifier is split from the verifying-key contract, the quotient evaluation
section can dominate the verifier bytecode.

## Goal

Reduce verifier bytecode size by replacing straight-line quotient identity code
with a compact interpreter:

- Store the quotient identity computation as a dense bytecode-like program.
- Emit a small Yul interpreter loop once.
- Execute the program at verification time to reconstruct/evaluate the quotient
  scalar.

This trades higher verification gas for much smaller generated contract bytecode.
It is likely the best single-contract size reduction path for the quotient
evaluation section.

## Current Shape

The current generator expands quotient evaluation into direct arithmetic:

- Load challenges, evaluations, constants, and powers.
- Multiply and add terms for each identity contribution.
- Accumulate the quotient numerator.
- Divide by the vanishing polynomial term or apply the equivalent reconstructed
  quotient evaluation logic.

The compiler sees all of this as unique code. Even if many identities share the
same pattern, the emitted bytecode still grows with the number of terms.

## Proposed Shape: Compact Identity Interpreter

Instead of emitting each identity as Yul statements, generate a compact program
plus a tiny interpreter.

Example opcode vocabulary:

| Opcode | Meaning |
| --- | --- |
| `LOAD_EVAL idx` | Push advice/fixed/instance evaluation `idx` |
| `LOAD_CHALLENGE idx` | Push transcript challenge `idx` |
| `LOAD_CONST idx` | Push constant field element `idx` |
| `LOAD_ACC idx` | Push accumulator/register `idx` |
| `ADD` | Pop two field elements, push `addmod(a, b, r)` |
| `SUB` | Pop two field elements, push `addmod(a, sub(r, b), r)` |
| `MUL` | Pop two field elements, push `mulmod(a, b, r)` |
| `MUL_CONST idx` | Pop one field element, multiply by constant `idx` |
| `NEG` | Pop one field element, push `r - a` |
| `STORE_ACC idx` | Pop one field element into accumulator/register `idx` |
| `END` | Stop interpretation |

The exact opcode set should be chosen after inspecting the generated identity
IR. The best set is the smallest one that avoids excessive stack/register
traffic for common Halo2 identity patterns.

## Program Encoding

The generated verifier can pack the program into Solidity bytecode as a compact
constant blob.

Possible encodings:

1. One-byte opcodes with fixed-size immediate fields.
2. One-byte opcodes plus variable-width immediates for small indices.
3. Packed 16-bit or 32-bit instructions for simpler decoding.

### Option 2 Benchmark: Common-Subexpression Elimination

An experimental no-VM quotient CSE mode was added behind:

```sh
HALO2_SOLIDITY_QUOTIENT_CSE=1
```

This is the pure option 2 shape: it disables the quotient VM payload and renders
straight-line Yul for quotient evaluation. The generator parses the generated
quotient expression trees, counts repeated composite subexpressions, and stores
worthwhile repeats in a small memory temp area. Reuses become direct `mload`
references. There is no interpreter loop and no quotient bytecode program in the
VK.

Command used:

```sh
HALO2_SOLIDITY_QUOTIENT_CSE=1 \
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
scripts/run_ivc_bench.sh --skip-srs-download
```

Results against the byte-VM baseline below:

| Mode | Verifier runtime | VK runtime | Total runtime | Quotient checkpoint | Total tx gas |
| --- | ---: | ---: | ---: | ---: | ---: |
| byte VM | 11,592 bytes | 19,712 bytes | 31,304 bytes | 1,029,944 gas | 2,484,560 gas |
| no-VM straight-line CSE | 57,487 bytes | 6,752 bytes | 64,239 bytes | 121,574 gas | 1,566,594 gas |

This confirms the tradeoff: removing the VM cuts quotient-eval gas dramatically,
but it is not a contract-size optimization. The VK shrinks by 12,960 bytes
because the quotient program is gone, but the verifier grows by 45,895 bytes
because the arithmetic is emitted as straight-line code. Total deployed runtime
grows by 32,935 bytes, far beyond the 24 KiB verifier limit.

For completeness, a separate VM-side CSE experiment is available behind:

```sh
HALO2_SOLIDITY_QUOTIENT_VM_CSE=1
```

That experiment keeps the quotient VM and CSEs inside the VM payload. It is not
pure option 2.

This now uses the most relevant `snark-verifier` optimization for quotient
evaluation: a loader-style expression cache across the full quotient expression,
instead of rebuilding the cache for each identity. The generator builds one
global CSE plan for the VM suffix, emits the first selected repeated expression
into a temp slot, and replaces later appearances with `PUSH_TEMP`.

Command used:

```sh
HALO2_SOLIDITY_QUOTIENT_VM_CSE=1 \
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
scripts/run_ivc_bench.sh --skip-srs-download
```

Results against the byte-VM baseline:

| Mode | Verifier runtime | VK runtime | Total runtime | Quotient checkpoint | Total tx gas |
| --- | ---: | ---: | ---: | ---: | ---: |
| byte VM | 11,592 bytes | 19,712 bytes | 31,304 bytes | 1,029,944 gas | 2,484,560 gas |
| byte VM + global CSE | 11,707 bytes | 18,208 bytes | 29,915 bytes | 1,020,561 gas | 2,468,545 gas |

The main verifier grows by 115 bytes because the VM needs the temp load/store
cases, but the VK payload shrinks by 1,504 bytes. Net deployed runtime shrinks
by 1,389 bytes and gas is roughly neutral/slightly better for this tree-decider
bench.

### snark-verifier-style Sum/Product Folding

The quotient evaluator also applies the same idea as `snark-verifier`'s
`sum_with_coeff_and_const` / `sum_products_with_coeff_and_const` helpers before
VM lowering:

- flatten additive chains,
- fold constant terms and signs,
- fold `Scaled` coefficients into each term,
- emit `coeff * (lhs * rhs)` as one scaled product term when possible.

This keeps the same quotient VM but gives the lowerer a tighter expression shape
and lets the existing fused add-mul opcodes trigger more often.

Command used:

```sh
HALO2_SOLIDITY_QUOTIENT_VM_CSE=1 \
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
scripts/run_ivc_bench.sh --skip-srs-download
```

Results against the global-CSE VM run above:

| Mode | Verifier runtime | VK runtime | Total runtime | Quotient checkpoint | Total tx gas |
| --- | ---: | ---: | ---: | ---: | ---: |
| byte VM + global CSE | 11,707 bytes | 18,208 bytes | 29,915 bytes | 1,020,561 gas | 2,468,545 gas |
| byte VM + global CSE + sum/product folding | 11,707 bytes | 18,208 bytes | 29,915 bytes | 1,013,113 gas | 2,461,095 gas |

This saves 7,448 gas in the quotient checkpoint without changing deployed
runtime size. It is worthwhile, but it does not change the main conclusion: the
interpreter dispatch dominates, so larger gas wins require hybrid inlining,
more fused VM opcodes, or a sharded/helper straight-line evaluator.

The other `snark-verifier` compact-backend idea is to move the whole program
into data-page contracts and run a generic interpreter. That is useful when a
single generated contract cannot fit EIP-170, but it is less attractive here
because the quotient-specific VM already keeps both the verifier and VK contracts
below 24 KiB individually and has a much smaller interpreter than the full
generic backend.

### Option 3 Benchmark: Yul Helper Functions

The no-VM CSE path can also call small Yul helper functions for repeated
arithmetic shapes:

```sh
HALO2_SOLIDITY_QUOTIENT_CSE=1 \
HALO2_SOLIDITY_QUOTIENT_YUL_HELPERS=1
```

The helper mode currently emits:

- `q_add(a, b)`
- `q_mul(a, b)`
- `q_neg(a)`
- `q_madd(a, b, c)` for `a * b + c`
- `q_addmul(a, b, c)` for `a + b * c`

Command used:

```sh
HALO2_SOLIDITY_QUOTIENT_CSE=1 \
HALO2_SOLIDITY_QUOTIENT_YUL_HELPERS=1 \
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
scripts/run_ivc_bench.sh --skip-srs-download
```

Results:

| Mode | Verifier runtime | VK runtime | Total runtime | Quotient checkpoint | Total tx gas |
| --- | ---: | ---: | ---: | ---: | ---: |
| no-VM straight-line CSE | 57,487 bytes | 6,752 bytes | 64,239 bytes | 121,574 gas | 1,566,594 gas |
| no-VM CSE + Yul helpers | 55,970 bytes | 6,752 bytes | 62,722 bytes | 118,077 gas | 1,563,224 gas |

Plain helpers reduce the verifier by 1,517 bytes and save 3,497 gas in the
quotient checkpoint, but the verifier is still far above the 24 KiB deployment
limit. This is useful if gas matters more than bytecode size, but it does not
solve deployability.

A forced no-inline variant using one-trip loops in each helper reduced generated
source size further, but made `solc --via-ir` compile for roughly 25 minutes
without finishing on this verifier. That shape is not practical.

### Hardcoded Structured-Loop Experiment

A verifier-specific structured-loop mode was added behind:

```sh
HALO2_SOLIDITY_QUOTIENT_STRUCTURED_LOOPS=1
```

This is not a generic verifier path. It still emits a verifier tied to the
current VK, but it uses the VK metadata to hardcode the permutation quotient
family as loops over known memory tables:

- permutation column evaluations,
- permutation sigma evaluations,
- `z_cur`, `z_next`, and non-final `z_last` evaluations,
- fixed `num_sets`, `num_cols`, and `chunk_len`.

The remaining gate, lookup, and trash identities stay as direct generated Yul.
Simple-selector quotient targets use the same scaled memory accumulator scheme
as the quotient VM path: `q_sel_scale`, `q_sel_inv_scale`, and one final scaling
pass over `SELECTOR_ACC_MPTR`.

Command used:

```sh
HALO2_SOLIDITY_QUOTIENT_STRUCTURED_LOOPS=1 \
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
scripts/run_ivc_bench.sh --skip-srs-download
```

Result:

| Mode | Verifier source | Verifier runtime | VK runtime | Total runtime | Quotient checkpoint | Total tx gas |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| hardcoded structured loops | 383,306 bytes | 51,955 bytes | 6,752 bytes | 58,707 bytes | 117,694 gas | 1,566,405 gas |

The experiment verifies end to end, but it is only a small bytecode win because
the permutation quotient family is not the dominant source of deployed bytecode
for this VK. The more important takeaway is architectural: hardcoded loops are
viable for regular quotient families, but we need to loop or table-drive the
large gate and lookup identities before this can materially reduce the verifier
below the current straight-line size.

### Packed 32-bit Instruction Encoding Benchmark

An experimental packed-32 mode was added behind:

```sh
HALO2_SOLIDITY_QUOTIENT_ENCODING=packed32
```

The default remains the byte-oriented VM because packed32 made the total deployed
system larger and more expensive for the current two-leaf IVC Keccak bench.

Command used:

```sh
HALO2_SOLIDITY_QUOTIENT_ENCODING=packed32 \
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
cargo test --release \
  --features evm,truncated-challenges,fewer-point-sets,solidity-gas-checkpoints \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --ignored --nocapture
```

Byte-VM baseline command:

```sh
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
cargo test --release \
  --features evm,truncated-challenges,fewer-point-sets,solidity-gas-checkpoints \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --ignored --nocapture
```

Results:

| Encoding | Verifier runtime | VK runtime | Total runtime | Quotient checkpoint | Total tx gas |
| --- | ---: | ---: | ---: | ---: | ---: |
| byte VM | 11,592 bytes | 19,712 bytes | 31,304 bytes | 1,029,944 gas | 2,484,560 gas |
| packed32 | 11,179 bytes | 26,176 bytes | 37,355 bytes | 1,586,710 gas | 3,044,269 gas |

Packed32 reduced the main verifier by 413 bytes, but increased the VK runtime by
6,464 bytes and increased the quotient-eval checkpoint by 556,766 gas. For this
circuit shape it is not a good default.

A simple first version can use fixed-width instructions:

```text
u8 opcode
u16 operand0
u16 operand1
```

This is not maximally dense, but it keeps the interpreter small and easy to
audit. Once the shape is proven, the generator can specialize common cases into
shorter instruction formats.

## Interpreter Sketch

The verifier would emit one Yul helper similar to:

```yul
function evalQuotientProgram(programOffset, programLen, evalsPtr, challengesPtr, constsPtr) -> out {
    let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617
    let pc := programOffset
    let end := add(programOffset, programLen)
    let sp := 0

    for { } lt(pc, end) { } {
        let op := byte(0, mload(pc))
        pc := add(pc, 1)

        switch op
        case 0x01 {
            // LOAD_EVAL idx
        }
        case 0x02 {
            // LOAD_CHALLENGE idx
        }
        case 0x03 {
            // ADD
        }
        case 0x04 {
            // MUL
        }
        case 0xff {
            out := /* final accumulator */
            break
        }
    }
}
```

The real implementation should avoid an unbounded memory stack if possible.
Options include:

- Use a small fixed stack in memory.
- Use a register file for identity accumulators.
- Generate stack-depth metadata and assert it at codegen time.
- Use specialized opcodes such as `MUL_ADD_ACC` to avoid stack churn.

## Expected Tradeoff

Benefits:

- Large verifier bytecode reduction for circuits with many quotient terms.
- More stable contract size as circuit identity count grows.
- Keeps the verifier as a single contract if helper-contract splitting is not
  desired.
- Easier to inspect quotient structure as data.

Costs:

- Higher verification gas due to interpreter dispatch and memory loads.
- More complex codegen and more careful auditing required.
- Debugging generated programs is less direct than reading straight-line Yul.
- Solc optimization may help less because the arithmetic is data-driven.

## Implementation Plan

1. Identify the internal representation used when emitting quotient evaluation.
2. Add a codegen mode for interpreted quotient evaluation.
3. Lower each quotient identity expression into compact instructions.
4. Emit constant tables for:
   - Fixed field constants.
   - Evaluation indices.
   - Challenge indices.
   - Optional register metadata.
5. Emit one Yul interpreter helper.
6. Replace the straight-line quotient evaluation block with a call into the
   interpreter.
7. Keep the straight-line evaluator behind a feature flag or generator option
   for comparison.
8. Add tests that compare interpreted and straight-line quotient scalars for the
   same generated proof.
9. Benchmark:
   - Verifier runtime bytecode size.
   - Total deployment bytecode size.
   - Verification gas.
   - Solidity compile time.

## Benchmark Commands

For the IVC Keccak Solidity end-to-end benchmark:

```sh
SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
cargo test --release \
  --features evm,truncated-challenges,fewer-point-sets,solidity-gas-checkpoints \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --ignored --nocapture
```

For the Poseidon-style Solidity gas checkpoint benchmark:

```sh
cargo test --features evm,solidity-gas-checkpoints \
  --test poseidon_fixture poseidon_renders_compiles_and_verifies \
  -- --ignored --nocapture
```

Compare these metrics before and after enabling the interpreted quotient
evaluation:

- `verifier runtime`
- `vk runtime`
- `total runtime`
- `total tx gas_used`
- The checkpoint labeled `batched identity numerator reconstruction`

## Open Questions

- Should the program be stored directly in verifier code, immutable data, or
  calldata-like memory initialized during verification?
- What is the best minimal opcode set for Halo2 quotient identities?
- Can common subexpressions be recovered before lowering to the program?
- Should fixed-base accumulator terms be pre-collapsed before this stage so the
  quotient program only handles the truly dynamic part?
- Is a register-machine interpreter smaller than a stack-machine interpreter
  after Solidity/Yul compilation?
- Should this mode be the default only when the straight-line verifier exceeds a
  bytecode threshold?

## Recommendation

Start with a simple fixed-width instruction format and a small Yul stack
interpreter. The first milestone should prove semantic equivalence and measure
bytecode reduction. After that, tune opcode density and add fused operations only
where the generated program profile shows real wins.
