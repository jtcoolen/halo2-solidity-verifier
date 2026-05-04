# Architecture Notes

This document records implementation techniques that affect the generated
Solidity verifier shape. `BENCH.md` keeps measured gas tables; this file
explains the design choices behind the code generator.

## Compact Quotient Identity Interpreter

The Halo2/Midnight verifier must evaluate the quotient numerator identities at
the Fiat-Shamir challenge `x`. The straightforward emitter renders every
identity as straight-line Yul:

```yul
let v0 := mulmod(...)
let v1 := addmod(...)
...
```

That style is cheap to execute, but it makes the generated verifier source and
runtime bytecode grow with the number of identity operations. In the IVC Keccak
decider this quotient block was the dominant contract-size contributor.

The compact interpreter changes only the representation of those same
arithmetic identities:

1. The existing Rust evaluator still derives the identity expressions from the
   circuit metadata and proof layout.
2. The code generator parses those Yul-like evaluator lines into expression
   trees.
3. Repeated field constants are moved into a constant pool.
4. Expressions are encoded as dense bytecode opcodes.
5. The generated VK runtime stores the constant pool and packed quotient
   bytecode.
6. The generated Solidity verifier includes a small Yul stack VM that reads
   that pinned VK payload, executes the bytecode, and folds each identity into
   `quotient_eval_numer` or a simple-selector accumulator.

The verifier semantics do not change. The transcript, proof format, public
inputs, PCS checks, and final pairing checks are the same. The tradeoff is
explicit: smaller deployed code, more interpreter overhead.

### Memory Model

The interpreter uses three generated memory regions:

- `stack_mptr`: temporary stack for expression evaluation.
- `const_mptr`: table of pooled `Fr` constants.
- `program_mptr`: packed quotient bytecode.

`const_mptr` and `program_mptr` point inside the VK runtime bytes that the
verifier already copied with `extcodecopy`. The permanent memory layout places
the challenge region after the full VK runtime, so the quotient payload remains
available until the quotient interpreter executes.

Only the VM stack is scratch memory. It is placed after the proof
commitment/evaluation regions so it does not clobber VK data, transcript
challenges, PCS scratch space, or selector accumulators.

### Pinned VK Payload

Earlier compact-interpreter versions embedded the quotient constant pool and
program in the verifier as many `PUSH32` + `mstore` immediates. That kept the VK
small, but it left the verifier just above the 24KB EIP-170 runtime limit.

The current generator moves that static payload into `Halo2VerifyingKey.sol`.
The verifier still pins the VK by both runtime length and codehash, so calldata
cannot redirect or mutate the program. This is a size split, not a trust-model
change: the quotient program is still generated from the same circuit metadata,
and a verifier deployment accepts exactly one VK runtime hash.

This pinned-artifact model is the reason later code-size optimizations may
specialize the quotient interpreter itself. The verifier is not intended to
accept arbitrary VK runtimes at a single deployed address; it accepts one
generated VK runtime hash. Therefore the rendered VM can omit opcode and memory
token switch arms that the finalized pinned bytecode never uses. That is a
runtime-size optimization over the generated artifact, not a change to the
Rust verifier semantics.

### Opcode Strategy

The base VM supports compact forms for:

- pushing pooled constants;
- pushing memory-backed proof/VK/evaluation words;
- challenge and Lagrange memory tokens;
- `addmod`, `mulmod`, and negation;
- folding one completed identity into the quotient accumulator;
- folding one completed identity into a simple-selector accumulator.

Two important optimizations sit on top of the base VM.

#### Top-Of-Stack Cache

The Yul interpreter keeps the current stack top in a local variable. Push
operations spill the old top to memory only when there is already a cached
value. Binary operations pop one value from memory and combine it with the
cached top.

This reduces repeated `mstore`/`mload` traffic without changing the bytecode
format for normal opcodes.

#### Product-Add Macro Opcodes

The IVC quotient identities contain long runs of this shape:

```text
acc += mem_a * mem_b * const
```

Encoding that as primitive VM bytecode costs several dispatches:

```text
push mem_a
mul mem_b
mul const
add
```

The generator recognizes product leaves and emits macro opcodes such as:

- `add_mul_mem_mem_const_u8`
- `add_mul_const_u8_mem_u16`
- `add_mul_mem_mem`

The interpreter executes each macro with one dispatch, while still using the
same `addmod` and `mulmod` arithmetic. Repeated adjacent macro terms are then
packed into run opcodes, so a long sequence of product-add terms is interpreted
by one outer dispatch and a tight Yul loop over packed operands.

This is the main gas recovery technique after moving from straight-line Yul to
an interpreter.

### Current IVC Result

The two-leaf IVC Keccak decider bench verifies end to end on-chain with this
interpreter and macro encoding.

Latest measured result:

```text
Halo2Verifier.sol source bytes:            94,591
Halo2VerifyingKey.sol source bytes:        60,263
Halo2QuotientEvaluator.sol source bytes:  162,152
Halo2Verifier deployed runtime bytes:      12,061
Halo2VerifyingKey deployed runtime bytes:  14,016
Halo2QuotientEvaluator runtime bytes:      23,221
total deployed runtime bytes:              49,298

compressed proof bytes:                     5,056
EIP-2537 padded proof bytes:                7,776
calldata bytes:                             8,356

quotient numerator gas:                   412,748
PCS final MSM gas:                        533,202
total tx gas:                           1,399,196
```

Compared to the first compact interpreter commit, the product-add and run macro
layer reduced the quotient section from `2,578,177` gas to `1,045,546` gas and
the verifier runtime from `30,278` bytes to `25,598` bytes.

Moving the quotient payload into the pinned VK then reduced the verifier
runtime from `25,598` bytes to `11,432` bytes. The VK grew from `6,752` bytes to
`19,712` bytes, so both deployable contracts are now independently below the
24KB EIP-170 limit.

The latest default also enables limb-aware quotient VM opcodes. In the current
IVC VK they compress `14` seven-limb linear forms and `7` seven-limb row
products, saving about `13k` gas in the numerator checkpoint while keeping each
runtime artifact below the EIP-170 limit.

### Validation Commands

Small Solidity smoke:

```sh
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
cargo test --features evm,truncated-challenges,fewer-point-sets,solidity-gas-checkpoints \
  --test poseidon_fixture poseidon_renders_compiles_and_verifies \
  -- --ignored --nocapture
```

Full IVC Solidity bench:

```sh
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
./scripts/run_ivc_bench.sh --skip-srs-download
```

Generated artifacts are written to:

```text
target/ivc-keccak-solidity-dump/
```
