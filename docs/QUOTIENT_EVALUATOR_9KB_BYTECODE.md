# How the Halo2 Quotient Evaluator Reached 9 KB

This note explains the engineering path that took the split
`Halo2QuotientEvaluator` down to a `9646` byte deployed runtime in the IVC
Keccak bench.

The number is for the historical split-evaluator shape, measured before the IVC
bench was switched back to a merged verifier. The current IVC bench renders the
same optimized quotient numerator body directly inside `Halo2Verifier`, because
that merged verifier now fits under EIP-170.

## Benchmark Shape

The `9646` byte result was measured with:

```text
solc:                         0.8.30
optimizer runs:               1
CBOR metadata:                omitted
outer single-H commitment:    disabled in the local bench script
quotient representation:      compact VM plus selected native callbacks
```

Measured split artifacts:

```text
Halo2Verifier runtime:            12,061 bytes
Halo2VerifyingKey runtime:        17,024 bytes
Halo2QuotientEvaluator runtime:    9,646 bytes
total runtime:                    38,731 bytes

checkpoint 12:                   328,105 gas
total tx gas:                  1,315,829 gas
```

The later merged-verifier run removed the separate evaluator and measured:

```text
Halo2Verifier runtime:            21,374 bytes
Halo2VerifyingKey runtime:        17,024 bytes
total runtime:                    38,398 bytes

checkpoint 12:                   312,018 gas
total tx gas:                  1,296,262 gas
```

So the 9 KB evaluator was not the final deployment goal by itself. It was the
bytecode reduction that made the quotient body small enough to merge back into
the verifier.

## The Short Version

The evaluator became small because the generator stopped emitting every quotient
identity as straight-line Yul bytecode. Instead it moved most identity arithmetic
into a compact program stored in the verifying-key payload, and kept only a
small interpreter plus carefully chosen native callbacks in evaluator bytecode.

That changed the split from:

```text
one generated Yul block per identity
```

to:

```text
fixed interpreter bytecode
+ VK-resident q_program bytes
+ VK-resident constant table
+ native callbacks only when the byte/gas trade is worth it
```

This is a code-size trade: some information moved out of evaluator runtime code
and into VK data. The verifier still checks the same quotient numerator
relationship.

## Step 1: Split the Quotient Numerator Body

The original reason for `Halo2QuotientEvaluator` was EIP-170 pressure. The
quotient numerator reconstruction is the largest scalar arithmetic section of
the generated verifier.

In split mode, the main verifier:

1. Loads the VK payload.
2. Samples transcript challenges.
3. Decodes proof evaluations.
4. Computes shared values such as `x^n`, Lagrange values, and public input
   evaluation.
5. Calls the quotient evaluator with a raw memory frame.

The evaluator receives the already prepared frame and only reconstructs:

```text
linearization expected scalar = -nu_y(x)
simple selector accumulator buckets
```

This split did not make the quotient arithmetic itself cheap, but it gave the
quotient body a separate EIP-170 budget and a much smaller interface than a
normal ABI call.

## Step 2: Move Identities Into a Compact VM

The largest win was the compact quotient VM.

Instead of rendering most identities as Yul source, the generator lowers them to
a small bytecode language in `src/codegen/quotient/mod.rs`. The runtime consumer
is `templates/QuotientNumeratorBlock.yul`.

The VK payload carries:

- a deduplicated Fr constant table;
- an encoded quotient program;
- offsets to both tables.

The evaluator bytecode carries:

- the interpreter loop;
- only the opcode switch arms used by the generated program;
- native callbacks selected by the generator.

For the measured IVC shape, the profile showed a compact program of roughly
`4931` bytes and `189` constants. Those bytes live in the VK payload, not as
unrolled evaluator runtime code.

## Step 3: Make the VM Dense

A naive stack VM would still be too large and too slow. The quotient VM uses
several density tricks:

- memory tokens for common verifier slots such as `beta`, `gamma`, `x`,
  `theta`, `L_0`, and `L_last`;
- short encodings for small constants and offsets;
- packed instruction forms where possible;
- run opcodes for repeated add/mul shapes;
- VM CSE temp slots for repeated subexpressions;
- domain-specific limb opcodes for repeated 7-limb foreign-field arithmetic;
- optional opcode switch arms, so unused interpreter cases do not get rendered.

The important idea is that the VM is not a general EVM-in-EVM. It is a small
quotient-expression machine tailored to the shapes this generator emits.

## Step 4: Keep Native Code Only Where It Pays

Some identities are bad VM candidates. For those, native Yul is still cheaper at
runtime, but native Yul costs bytecode. The generator therefore keeps a bounded
native-callback budget.

The first heuristic selected the heaviest VM identities by byte length. That was
too crude: a large VM identity is not always a good bytecode purchase.

The current selector builds candidates with:

```text
VM byte estimate
VM gas estimate
native Yul byte estimate
native Yul gas proxy
```

Then it solves a small byte-budget knapsack. In the bytecode-lean `9646` byte
profile, the score is conservative:

```text
estimated saving = VM gas - discounted native Yul gas
```

That kept the small profitable native callbacks and avoided spending runtime
bytecode on large callbacks that were not worth their deployed-size cost.

Tuning hooks:

```text
HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=N
HALO2_SOLIDITY_QUOTIENT_NATIVE_GATE_BYTE_BUDGET=N
```

The default count remains `4`, but the selected four are chosen by estimated
gas saved under the byte budget rather than by top-N VM byte length.

## Step 5: Keep Structured Family Callbacks

Permutation and lookup identities have regular product-loop structure. Encoding
those loops entirely as generic VM opcodes would save bytecode but cost too much
gas.

The generator keeps structured native callbacks for these families when enabled:

```text
HALO2_SOLIDITY_QUOTIENT_NATIVE_PERMUTATION=1
HALO2_SOLIDITY_QUOTIENT_NATIVE_LOOKUP=1
```

These callbacks reuse the quotient VM stack base as scratch, so the Rust memory
planner reserves enough words for the larger of:

- interpreted operand stack needs;
- native callback scratch-table needs.

This was necessary to make the compact path safe without overallocating memory
in unrelated verifier sections.

## Step 6: Remove the Selector Inverse Fold

Simple selector identities are known at codegen time. Earlier versions still
computed `y^-1` at runtime and maintained selector scale/inverse-scale state
while walking identities.

The replacement is a gap-based selector fold:

1. Codegen records the distance between selector identity positions.
2. Runtime precomputes only the needed `y^k` powers.
3. A selector bucket is scaled only when that selector appears.
4. A final tail gap is applied after the VM scan.

This removed one runtime modexp and repeated per-identity selector maintenance.
In the measured path it was mainly a deployed-size win, and it simplified the
state that the VM has to maintain.

## Step 7: Gate Production Trace Hooks

Trace-equivalence builds need quotient identity trace events. Production builds
do not.

The quotient numerator block previously carried trace-id state and called the
trace hook even in production. In the split evaluator the logless trace hook
still did memory work, and the surrounding shape affected generated bytecode.

The production path now gates trace emission behind trace builds. That saves
both gas and bytecode in the quotient section while preserving trace builds for
differential testing.

## Step 8: Include Helpers Only When Used

`QuotientHelpers.yul` is shared by monolithic and split paths, but the generator
tracks which helper shapes are actually referenced:

- `q_pow5`
- `q_limb7`
- `q_limb7_wide`

Unused helpers are not emitted into the quotient runtime. This matters because
helper bodies are small individually, but the quotient evaluator was being
optimized under a tight bytecode budget.

## What Did Not Change

The 9 KB result did not come from weakening the verifier.

The generated Solidity still:

- reconstructs the same y-batched quotient numerator `nu_y(x)`;
- stores `-nu_y(x)` as the expected linearization scalar;
- accumulates simple selector buckets for the final linearization commitment;
- checks the proof through the same PCS and pairing flow;
- uses the same transcript challenge order.

The optimization is representational: arithmetic moved from unrolled runtime
Yul into compact VK-resident data plus a small interpreter.

## Why 9 KB Was Enough to Merge Back

After the quotient body reached `9646` bytes as a split evaluator, the merged
verifier could fit under EIP-170:

```text
merged Halo2Verifier runtime: 21,374 bytes
EIP-170 limit:               24,576 bytes
headroom:                     3,202 bytes
```

Merging removes:

- the quotient evaluator deployment;
- the verifier constructor's quotient address argument;
- quotient runtime length/codehash pinning;
- the `STATICCALL`;
- frame copy and output-frame validation.

That is why the merged benchmark improved checkpoint 12 from `328,105` to
`312,018` gas and total transaction gas from `1,315,829` to `1,296,262`.

## Reproduction Notes

The exact `9646` byte standalone evaluator number belongs to the split path
before the IVC bench switched to the merged verifier. The commit that recorded
that shape was:

```text
226c124 Select native quotient gates by gas-byte knapsack
```

The command used was:

```sh
scripts/run_ivc_bench.sh --skip-srs-download
```

with the local bench script setting:

```text
OUTER_SINGLE_H_COMMITMENT=0
```

The current IVC bench no longer writes `Halo2QuotientEvaluator.sol`; it writes a
merged `Halo2Verifier.sol` instead. To inspect the standalone evaluator on the
current code, use the generator's `render_quotient_evaluator()` API directly or
check out the split-path commit above.

