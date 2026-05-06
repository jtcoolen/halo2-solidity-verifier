# Askama Template And Rust Verifier Mapping

This note explains how the generated Solidity/Yul artifacts map back to the
Midfall Rust verifier in `../midfall/proofs/src/plonk` and to the local
codegen modules that feed the Askama templates.

The short version: Askama is the last mile, not the planner. Rust code in
`src/codegen` computes the proof layout, memory layout, VK payload, quotient
program, and PCS emitter blocks. The templates render those already-planned
facts into Solidity/Yul with mostly fixed control flow.

## Template Inventory

| Template | Askama struct | Rendered artifact | Primary Rust source of truth |
| --- | --- | --- | --- |
| `templates/Halo2Verifier.sol` | `src/codegen/template.rs::Halo2Verifier` | Main verifier contract and `verifyProof` ABI | `../midfall/proofs/src/plonk/verifier.rs::{parse_trace,verify_algebraic_constraints,prepare}` |
| `templates/Halo2VerifyingKey.sol` | `src/codegen/template.rs::Halo2VerifyingKey` | Data-only VK runtime payload contract | `../midfall/proofs/src/plonk/mod.rs::VerifyingKey` |
| `templates/Halo2QuotientEvaluator.sol` | `src/codegen/template.rs::Halo2QuotientEvaluator` | Optional split quotient numerator evaluator | `../midfall/proofs/src/plonk/mod.rs::partially_evaluate_identities` and `linearization/verifier.rs::compute_linearization_commitment` |
| `templates/QuotientNumeratorBlock.yul` | included by the verifier/evaluator templates | Generated numerator reconstruction body | `../midfall/proofs/src/plonk/{mod.rs,permutation.rs,logup.rs,trash.rs}` |
| `templates/QuotientHelpers.yul` | included by `QuotientNumeratorBlock.yul` | Optional arithmetic helpers for generated quotient snippets | Local lowering helpers in `src/codegen/evaluator.rs` and `src/codegen/quotient/mod.rs` |

The main generator entry points are in `src/codegen/generator.rs`:

- `render()` and `render_into()` produce an embedded-VK verifier.
- `render_separately()` produces `Halo2Verifier` plus `Halo2VerifyingKey`.
- `render_quotient_evaluator()` produces the split quotient evaluator first.
- `render_separately_with_pinned_quotient()` produces verifier/VK/evaluator
  artifacts where the verifier pins the evaluator runtime length and codehash.

## Data Flow Into Askama

Askama structs are deliberately plain data bags:

1. `SolidityGenerator::try_new` validates the supported Midfall shape and
   derives `ConstraintSystemMeta`.
2. `src/codegen/proof_layout.rs` derives the exact calldata sections for proof
   commitments, scalar evaluations, KZG `q_evals`, `f_com`, and `pi`.
3. `src/codegen/memory.rs` assigns stable memory addresses for VK words,
   challenges, decoded evaluations, commitments, quotient state, PCS scratch,
   and optional accumulator state.
4. `src/codegen/artifact.rs` validates the VK payload section map: header,
   quotient constants, quotient program, fixed commitments, and permutation
   commitments.
5. `src/codegen/evaluator.rs` lowers gates, permutation, LogUp, and trash
   expressions into scalar Yul fragments.
6. `src/codegen/quotient/mod.rs` optionally turns those fragments into a
   compact quotient program plus native callback markers.
7. `src/codegen/pcs.rs` simulates Midfall KZG `multi_prepare` and emits the
   final PCS Yul blocks.
8. `src/codegen/template.rs` packages all of the above into Askama structs.
9. The templates render Solidity/Yul without recomputing protocol layout.

That separation is intentional. When a template contains a numeric memory
constant, byte offset, or loop bound, it should already have been checked by a
Rust-side layout test or generator assertion.

## `Halo2Verifier.sol` Section Map

`Halo2Verifier.sol` is the on-chain version of:

```text
parse_trace(...)
verify_algebraic_constraints(...)
CS::multi_prepare(...)
guard.verify(params)
```

with Midfall transcript and KZG details rendered directly into Yul.

| Generated section | What it does | Midfall Rust mapping | Local codegen owner |
| --- | --- | --- | --- |
| Contract header, pinned dependencies, constants | Declares VK/evaluator codehash pins, calldata offsets, memory addresses, field/precompile constants | `plonk/mod.rs::VerifyingKey` metadata and KZG verifier params | `template.rs::{Halo2Verifier,TemplateConstants}`, `layout.rs`, `memory.rs`, `artifact.rs` |
| Constructors and EIP-2537 smoke tests | Checks G1ADD, G1MSM, and pairing precompiles, then pins VK and optional quotient evaluator | Deployment-only safety wrapper around the verifier params | `templates/Halo2Verifier.sol`, `layout::precompile` |
| `verifyProof` ABI head checks | Confirms ABI offsets, generated proof length, instance length, and calldata end | `verifier.rs` instance-shape checks before transcript work | `proof_layout.rs`, `generator.rs` |
| Helper functions | Implements scalar inverse, transcript append/squeeze, G1 validation/copy, G1MSM/g1add/pairing wrappers, batch inversion, accumulator decoding, trace/gas hooks | `transcript/*`, `poly/domain.rs::l_i_range`, KZG verifier helpers | `templates/Halo2Verifier.sol`, `TemplateConstants` |
| VK loading | Either emits `mstore` constants or `extcodecopy`s the payload from the pinned `INVALID || VK payload` runtime, then validates accumulator header fields | `vk.hash_into(transcript)` uses `vk.transcript_repr`; fixed/permutation commitments are verifier key data | `generate_vk`, `Halo2VerifyingKey`, `VkPayloadLayout` |
| VK digest and public input transcript absorption | Absorbs `vk_digest`, committed-instance identity commitment, public input length, and public input scalars | `verifier.rs::parse_trace`, from `vk.hash_into` through instance `transcript.common` calls | `proof_layout.rs::TranscriptBufferLayout`, `common_word`, `common_uncompressed_g1` |
| Per-user-phase advice reads | Reads and absorbs advice commitments by phase, then squeezes user challenges | `parse_trace`: phase loop over advice commitments and `challenge_phase` | `Protocol` metadata, `UserPhase` |
| `theta`, lookup multiplicities | Squeezes `theta`, then reads lookup multiplicity commitments | `parse_trace`: `theta`, `ChunkedArgument::read_multiplicities` | `proof_layout.rs`, `logup/verifier.rs` mapping |
| `beta`, `gamma`, permutation products | Squeezes permutation challenges and reads permutation product commitments | `parse_trace`: `beta`, `gamma`, `Argument::read_product_commitments` | `permutation/verifier.rs` mapping |
| Lookup helper/accumulator commitments | Reads each LogUp helper commitment and accumulator commitment | `CommittedMultiplicities::read_commitment` | `proof_layout.rs::ProofLookupCommitmentsLayout` |
| `trash_challenge`, trash commitments | Squeezes trash challenge unconditionally, then reads trash commitments when present | `parse_trace`: trash challenge and `trash::Argument::read_committed` | `trash/verifier.rs` mapping |
| `y`, quotient commitment(s) | Squeezes identity-batching challenge and reads quotient commitment(s) | `verify_algebraic_constraints`: `read_n(transcript, nb_quotient_coms)` before `x` | `proof_layout.rs`, `memory.rs` |
| `x` and evaluation scalars | Squeezes opening challenge, range-checks proof evals, stores them in `REVERSED_EVALS_MPTR`, and absorbs them | `verify_algebraic_constraints`: committed-instance evals, advice evals, fixed evals, permutation/common evals, lookup evals, trash evals | `Protocol` eval order, `proof_layout.rs`, `evaluator.rs` |
| `x1`, `x2`, `f_com`, `x3`, `q_evals`, `x4`, `pi` | Completes Midfall KZG transcript for multi-opening proof | KZG `multi_prepare` in `../midfall/proofs/src/poly/kzg` | `pcs.rs`, `proof_layout.rs` |
| Lagrange and instance evaluation | Computes `x^n`, `(x^n-1)^-1`, `l_last`, `l_blind`, `l_0`, and the public instance evaluation | `verify_algebraic_constraints`: `domain.l_i_range` and `compute_inner_product` | `templates/Halo2Verifier.sol`, `memory.rs` |
| Batched identity numerator reconstruction | Reconstructs `nu_y(x)` from the claimed evals and stores the linearization expected scalar `-nu_y(x)` | `plonk/mod.rs::partially_evaluate_identities`; trace loop for `quotient_numerator` and selector folds | `evaluator.rs`, `quotient/mod.rs`, `QuotientNumeratorBlock.yul` |
| Linearization scalar prep | Computes `x_split = x^(n-1)` and `1 - x^n`; prepares selector buckets and quotient-limb scalars | `linearization/verifier.rs::compute_linearization_commitment` | `templates/Halo2Verifier.sol`, `pcs.rs` |
| PCS computation blocks | Constructs point sets, folds evaluations/commitments, computes `f_eval`, `v`, final commitment, and pairing inputs | `CS::multi_prepare` and KZG final guard verification | `src/codegen/pcs.rs` |
| Public accumulator pairing batch | Decodes public IVC accumulator points/scalars and batches the accumulator pairing equation with KZG | Repository-specific IVC extension around Midfall KZG | `templates/Halo2Verifier.sol`, `layout::accumulator` |
| Final pairing | Calls EIP-2537 pairing on the KZG or batched KZG+accumulator equation | `poly/kzg/msm.rs::DualMSM::check` | `ec_pairing` helper, `pcs.rs` |
| Trace and gas checkpoints | Emits trace ids and gas deltas for Rust/Solidity equivalence and profiling | `plonk/solidity_trace.rs` trace ids | Template trace/gas flags and bench scripts |

Two naming caveats matter while reading the generated Solidity:

- `QUOTIENT_EVAL_MPTR` is a legacy name. It stores the linearization expected
  scalar `-nu_y(x)`, not a trusted quotient evaluation `h(x)`.
- `PAIRING_LHS_MPTR` and `PAIRING_RHS_MPTR` follow the internal dual-MSM naming.
  The final `ec_pairing` call swaps them into EIP-2537 pairing argument order.

## `Halo2VerifyingKey.sol`

The VK template emits a constructor that returns `INVALID || payload` as runtime
bytecode. Runtime byte `0` is an unconditional `INVALID` opcode so direct calls
cannot execute payload bytes as EVM instructions. The verifier pins the full
prefixed runtime length/codehash but loads only the payload with:

```yul
extcodecopy(vk, VK_MPTR, 0x01, vk_payload_len)
```

Its payload layout is:

1. Header words: `vk_digest`, domain constants, accumulator metadata, KZG bases.
2. Optional compact quotient VM constant table.
3. Optional compact quotient VM bytecode words.
4. Fixed-column commitments.
5. Permutation commitments.

This mirrors the Rust `VerifyingKey` inputs used by `vk.hash_into(transcript)`
and by `verify_algebraic_constraints`. The local `VkPayloadLayout` keeps the
payload section map append-only so `Halo2VerifyingKey.bytes()`, the prefixed
runtime length/codehash, `extcodecopy`, and tests all agree.

Important optimisation: quotient constants and bytecode live in the pinned VK
payload rather than as verifier `PUSH32`/`mstore` immediates. That reduces main
verifier runtime size while keeping the program covered by the VK codehash.

## `Halo2QuotientEvaluator.sol`

The split evaluator is a specialized scalar helper for the expensive numerator
reconstruction section. It receives a raw verifier-memory frame, rehydrates it
to the same absolute memory addresses, includes `QuotientHelpers.yul` and
`QuotientNumeratorBlock.yul`, then returns:

```text
word 0: magic/version
word 1: linearization_expected_eval = -nu_y(x)
word 2..: simple-selector accumulator buckets
```

This contract maps to the scalar side of:

- `plonk/mod.rs::partially_evaluate_identities`
- `plonk/linearization/verifier.rs::compute_linearization_commitment`
- `plonk/permutation.rs::expressions`
- `plonk/logup.rs` / `plonk/logup/verifier.rs`
- `plonk/trash.rs::Evaluated::expressions`

It does not read proof calldata, sample challenges, evaluate `h(x)`, or check
commitments. The main verifier has already done transcript parsing and later
binds the returned scalar to the quotient commitment(s) through KZG.

Because the main verifier calls the evaluator with `STATICCALL`, evaluator-local
trace hooks are logless in split mode. The main verifier still traces proof
scalars, `q_evals`, selector folds returned from the evaluator, and the final
reconstructed scalar. Monolithic trace tests can additionally compare internal
quotient identity trace ids because they do not cross a `STATICCALL` boundary.

## `QuotientNumeratorBlock.yul`

This included Yul block is the concrete lowering of Midfall identity evaluation:

```text
for identity in partially_evaluate_identities(...):
    if identity is fully evaluated:
        quotient_numerator = quotient_numerator * y + identity(x)
    if identity is gated by a simple selector:
        selector_bucket[selector] += y_power * identity(x)

QUOTIENT_EVAL_MPTR = -quotient_numerator
```

The block preserves the Rust identity order:

1. Gate identities from `vk.cs.gates`.
2. Permutation identities from `plonk/permutation.rs`.
3. LogUp identities from `plonk/logup.rs`.
4. Trash identities from `plonk/trash.rs`.

The direct, VM, and native-callback paths are all different encodings of this
same ordered stream. Each identity consumes exactly one position in the global
`y` batch, including simple-selector identities.

### Assembly Section Walkthrough

`QuotientNumeratorBlock.yul` is included inside an existing Solidity/Yul
function body. It assumes the verifier/evaluator has already populated fixed
memory addresses for transcript challenges, proof evaluations, Lagrange values,
public-instance evaluation, quotient VM payload pointers, and selector bucket
scratch.

The top-level template shape is:

```text
{
    match quotient_program:
      Some(program) => compact VM/native/direct-hybrid path
      None          => legacy direct numerator path
}
```

The compact path is the production path. Its generated assembly sections are:

| Template section | Main variables | What it does | Rust/verifier meaning |
| --- | --- | --- | --- |
| Load batching challenge | `y := mload(Y_MPTR)` | Reads the identity-batching challenge sampled by the main verifier. | `verify_algebraic_constraints` has already squeezed `y`. |
| Bind VM payload pointers | `q_const_mptr`, `q_program_mptr`, optional `q_tmp_mptr` | Points at quotient constants, quotient bytecode, and CSE temporary scratch. | These are generated from `QuotientProgramBuild` and stored in the VK payload. |
| Initialize main fold state | `program.eval_numer_mptr`, `program.trace_id_mptr` | Zeros the Horner accumulator for fully evaluated identities and sets the trace id base. | This accumulator becomes `nu_y(x)` for the Rust `None` identity group. |
| Initialize selector buckets | `SELECTOR_ACC_MPTR`, `program.selector_power_mptr` | Zeros selector accumulators and precomputes the `y^k` powers needed by codegen-known selector gaps and tails. | Mirrors Rust's grouped simple-selector scalars in `compute_linearization_commitment`. |
| Direct inline prefix | `quotient_inline_computations` | Renders a short prefix of generated identity Yul before the VM loop. | Same identity stream, but cheaper than interpreter dispatch. |
| VM register setup | `q_pc`, `q_end`, `q_sp`, `q_top`, `q_has_top` | Initializes the stack interpreter over the VK-backed bytecode. | Implements lowered `partially_evaluate_identities` fragments. |
| Packed32 interpreter branch | `program.packed32 == true` | Reads 4-byte instruction words: high byte opcode, low 24 bits operand. | Alternative physical encoding chosen by codegen. |
| Byte interpreter branch | `program.packed32 == false` | Reads one opcode byte plus variable-width operands. Also supports dynamic run and limb opcodes. | Default compact encoding for the gas-capped verifier. |
| Native callback cases | generated callback blocks | VM markers reset the stack pointer and run generated Yul for permutation, lookup, or heavy gates. | Replaces regular identity fragments without changing order or y-batch positions. |
| Structured post-VM suffix | `quotient_post_vm_computations` | Emits regular identity families, currently trash, after the VM. | Keeps identity order while avoiding expensive interpreted tail work. |
| Final selector scaling | `program.selector_tail_updates` | Applies each selector bucket's codegen-known final y-power tail. | Converts gap-folded selector buckets into Rust's reverse-fold powers. |
| Linearization scalar store | `QUOTIENT_EVAL_MPTR` | Stores `-mload(eval_numer_mptr)`. | This is the expected scalar for the linearization query, not `h(x)`. |

The legacy `None` branch is intentionally smaller conceptually:

1. Load `delta`, `y`, and `q_trace_id`.
2. Render `quotient_eval_numer_computations` directly as Yul.
3. Store `-quotient_eval_numer` to `QUOTIENT_EVAL_MPTR`.

That branch is used for older monolithic or experimental modes where the
compact VM is disabled. It follows the same Rust algebra, but the source is
large because every expression is unrolled into the template output.

### Compact Quotient VM

When compact quotient mode is active, most identities are encoded as q_program
bytecode stored in the VK payload. The Yul interpreter supports:

- memory and constant loads;
- `add`, `mul`, and `neg` over `Fr`;
- fused add-mul forms for common expression shapes;
- temp loads/stores for quotient CSE;
- native callback markers for whole identity families;
- limb-aware opcodes for recurring 7-limb foreign-field expressions.

The VM saves runtime bytecode and compile pressure. The tradeoff is gas: each
interpreted identity pays dispatch, stack/memory movement, and fold-state
loads/stores. Inline and native paths are larger but cheaper at runtime.

The interpreter uses a cached-top stack:

```text
q_pc      current bytecode pointer
q_end     end of bytecode
q_sp      memory stack pointer for spilled operands
q_top     cached top-of-stack field element
q_has_top whether q_top is live
```

Push-like cases spill the previous `q_top` to `mstore(q_sp, q_top)` and advance
`q_sp` when `q_has_top` is set. Binary stack cases decrement `q_sp`, combine
`mload(q_sp)` with `q_top`, and keep the result in `q_top`. Accumulator cases
mutate `q_top` directly. Fold cases consume `q_top` and advance the global
identity-batching state.

### VM Switch Cases In The Template

The Yul template has two switch blocks:

- Packed32 branch: decodes each instruction as one 4-byte word
  `(opcode << 24) | operand`, with an extra word for the two-pointer fused
  cases.
- Byte branch: decodes one opcode byte followed by variable-width operands.
  This is the only branch with dynamic run opcodes and limb-aware opcodes.

The logical cases are:

| Opcode | Case | Packed32 handling | Byte handling | Effect |
| --- | --- | --- | --- | --- |
| `0x01` | `push_const` | `q_arg` is const index | next 2 bytes are const index | Spill old top if any, then load `const[const_idx]` into `q_top`. |
| `0x02` | `push_mem_literal` | `q_arg` is a 24-bit pointer | next 4 bytes are pointer | Spill old top if any, then load `mload(ptr)` into `q_top`. |
| `0x03` | `push_mem_token` | `q_arg` is token | next byte is token | Resolve token through the token switch and push `mload(ptr)`. Unknown token reverts. |
| `0x04` | `push_mem_token_offset` | high 8 bits token, low 16 bits offset | next byte token, next 4 bytes offset | Resolve token, add byte offset, and push `mload(ptr + offset)`. |
| `0x05` | `push_mem_u16` | `q_arg` is pointer | next 2 bytes are pointer | Short pointer load; push `mload(ptr)`. |
| `0x06` | `add` | no operand | no operand | Pop one spilled value and set `q_top = popped + q_top mod Fr`. |
| `0x07` | `mul` | no operand | no operand | Pop one spilled value and set `q_top = popped * q_top mod Fr`. |
| `0x08` | `neg` | no operand | no operand | Set `q_top = -q_top mod Fr`. |
| `0x09` | `push_const_u8` | `q_arg` is const index | next byte is const index | Short const load. |
| `0x0a` | `fold_main` | no operand | no operand | Trace `q_top`, clear it, and do `eval_numer = eval_numer * y + q_top`. |
| `0x0b` | `fold_selector` | `q_arg` packs selector index and gap | next 3 bytes are selector index plus gap | Trace `q_top`, clear it, advance the global y position, multiply that selector bucket by `y^gap`, and add `q_top`. |
| `0x0c` | `add_const_u8` | `q_arg` is const index | next byte is const index | Mutate `q_top += const[const_idx]`. |
| `0x0d` | `mul_const_u8` | `q_arg` is const index | next byte is const index | Mutate `q_top *= const[const_idx]`. |
| `0x0e` | `add_const` | `q_arg` is const index | next 2 bytes are const index | Wider const add. |
| `0x0f` | `mul_const` | `q_arg` is const index | next 2 bytes are const index | Wider const multiply. |
| `0x10` | `add_mem_u16` | `q_arg` is pointer | next 2 bytes are pointer | Mutate `q_top += mload(ptr)`. |
| `0x11` | `mul_mem_u16` | `q_arg` is pointer | next 2 bytes are pointer | Mutate `q_top *= mload(ptr)`. |
| `0x12` | `add_mul_mem_mem_const_u8` | `q_arg` is const index; extra word packs `lhs,rhs` | next `lhs,rhs,const` operands | Mutate `q_top += mload(lhs) * mload(rhs) * const[const_idx]`. |
| `0x13` | `add_mul_const_u8_mem_u16` | `q_arg` packs `const_idx,ptr` | next `ptr,const` operands | Mutate `q_top += mload(ptr) * const[const_idx]`. |
| `0x14` | `add_mul_mem_mem` | extra word packs `lhs,rhs` | next `lhs,rhs` operands | Mutate `q_top += mload(lhs) * mload(rhs)`. |
| `0x15` | `run_add_mul_mem_mem_const_u8` | not emitted in packed32 | byte-only dynamic run | Loop over repeated `0x12` payloads and accumulate each into `q_top`. |
| `0x16` | `run_add_mul_const_u8_mem_u16` | not emitted in packed32 | byte-only dynamic run | Loop over repeated `0x13` payloads and accumulate each into `q_top`. |
| `0x17` | `push_temp` | `q_arg` is temp index | next 2 bytes are temp index | Push `mload(q_tmp_mptr + 32 * temp_idx)`. Rendered only when CSE temps exist. |
| `0x18` | `store_temp` | `q_arg` is temp index | next 2 bytes are temp index | Store `q_top` to `q_tmp_mptr + 32 * temp_idx`; `q_top` remains live. Rendered only when CSE temps exist. |
| `0x19` | `native_permutation` | no operand | no operand | Reset VM top/stack and splice in the generated permutation identity callback. |
| `0x1a` | reserved | no case | no case | Falls to `default { revert(0, 0) }` if present. |
| `0x1b` | `native_identity` | `q_arg` is callback index | next 2 bytes are callback index | Reset VM top/stack and switch into one generated heavy-gate callback. |
| `0x1c` | `lin7` | not emitted in packed32 | byte-only limb opcode | Push a 7-term table-backed linear combination. |
| `0x1d` | `bilin7_row` | not emitted in packed32 | byte-only limb opcode | Push one memory value times a 7-term weighted row. |
| `0x1e` | `bilin7_pairwise` | not emitted in packed32 | byte-only limb opcode | Push a 7-by-7 weighted convolution over two contiguous limb vectors. |
| `0x1f` | `native_lookup` | no operand | no operand | Reset VM top/stack and splice in the generated LogUp lookup callback. |

The token switch shared by `push_mem_token` and `push_mem_token_offset` maps:

| Token | Template pointer |
| --- | --- |
| `0x01` | `L_0_MPTR` |
| `0x02` | `L_LAST_MPTR` |
| `0x03` | `L_BLIND_MPTR` |
| `0x04` | `BETA_MPTR` |
| `0x05` | `GAMMA_MPTR` |
| `0x06` | `X_MPTR` |
| `0x07` | `THETA_MPTR` |
| `0x08` | `TRASH_CHALLENGE_MPTR` |
| `0x09` | `INSTANCE_EVAL_MPTR` |

Every unrecognized opcode, token, or native identity index goes to
`revert(0, 0)`. This is intentional: the VM program is generated and pinned in
the VK payload, so malformed bytecode means a generator or artifact mismatch,
not a recoverable proof failure.

### Direct Inline Prefix

`HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES` keeps a prefix of identities
as direct generated Yul before entering the VM. This is useful for gas-capping
large IVC proofs because the earliest high-cost identities avoid interpreter
dispatch while the remaining identities stay compact.

### Native Callbacks

Native callbacks are domain-shaped superinstructions:

- native permutation preserves `permutation.rs` identity order but emits a
  structured product loop instead of many interpreted operations;
- native lookup preserves LogUp order while sharing prefix/suffix scratch;
- native heavy identity callbacks are used for recognized expensive gate
  identities.

They are not semantic shortcuts. They still produce the same identity values and
advance the same `y` batch positions as the Rust verifier.

### Simple-Selector Buckets

Midfall does not require proof eval scalars for simple multiplicative selector
columns. Rust `compute_linearization_commitment` groups those identities by
selector commitment and puts the grouped scalar into the linearization MSM.

The Yul block mirrors this with `SELECTOR_ACC_MPTR`. In forward VM order it uses
an inverse-`y` scale, then applies a final scale to match Rust's reverse fold.
The main verifier later expands each bucket into the fused final PCS MSM.

### Structured Trash Tail

The structured trash suffix can emit trash identities as direct structured Yul
after the VM. This trades some runtime bytes for lower gas on circuits where the
trash tail is expensive to interpret. The default gas-capped profile enables
this suffix.

## PCS Yul Blocks

`src/codegen/pcs.rs` is the local equivalent of Midfall KZG `multi_prepare`.
It computes the query plan at codegen time, then emits fixed Yul blocks for the
generated circuit:

1. Build the query list, skipping simple-selector fixed queries because the
   linearization query carries those commitments.
2. Partition queries into point sets in the same way as
   `poly/kzg/utils.rs::construct_intermediate_sets`.
3. Read prover `q_evals` and fold evaluations with `x1`.
4. Fold commitments with `x2`.
5. Interpolate the folded polynomial at `x3` to compute `f_eval`.
6. Fold the final commitment with `x4`.
7. Produce the two G1 inputs for the final KZG pairing.

The linearization commitment is not materialized in production. Instead, its
quotient-limb terms and simple-selector terms are expanded directly into the
already-fused PCS MSM. Trace builds may materialize the point only for
comparison against the instrumented Rust verifier.

## Optimisation Map

| Optimisation | Where | Benefit | Tradeoff / invariant |
| --- | --- | --- | --- |
| Separate VK payload contract | `Halo2VerifyingKey.sol`, `VkPayloadLayout` | Moves large constants and commitments out of verifier runtime | Runtime is prefixed with `INVALID`; constructor and per-proof checks pin length/codehash |
| Split quotient evaluator | `Halo2QuotientEvaluator.sol` | Moves the largest scalar arithmetic body out of main verifier bytecode | Evaluator is correctness-critical and constructor-pinned |
| Compact quotient VM | `quotient/mod.rs`, `QuotientNumeratorBlock.yul` | Reduces Solidity/Yul bytecode and improves compile stability | Higher runtime gas for interpreted identities |
| Inline identity prefix | `quotient_program_plan` | Lowers gas for the first expensive identities | Increases verifier/evaluator runtime size |
| Native permutation/lookup callbacks | `generator.rs`, `QuotientNumeratorBlock.yul` | Avoids interpreter overhead on structured product loops | Callback scratch must be reserved by the memory planner |
| Structured trash suffix | `QuotientStructuredTailMode::Trash` | Avoids interpreting trash identities | Increases generated Yul size |
| Quotient constants/program in VK payload | `artifact.rs`, `generate_vk` | Avoids verifier-side immediate constants | VK hash changes when the quotient program changes |
| Decoded eval spill buffer | `REVERSED_EVALS_MPTR` | Turns later eval references into cheap `mload`s | Proof scalar order must match protocol metadata exactly |
| Off-chain proof repacking | `quotient::RepackedProofLayoutPlan` and ABI docs | On-chain verifier consumes BE scalar words and EIP-2537 G1s directly | Calldata is Solidity-facing, not native Midnight proof bytes |
| Lagrange batch inversion | `batch_invert` helper | Computes all needed inverse denominators with one modexp | Scratch region must not overlap permanent memory |
| Simple-selector bucket grouping | `compute_linearization_commitment`, `SELECTOR_ACC_MPTR` | Removes simple selector proof evals and groups MSM terms | Selector identity order and final `y` scaling must match Rust |
| Fused linearization into PCS MSM | `pcs.rs` | Avoids a standalone production G1MSM for linearization | Trace builds may materialize it only for comparison |
| Point-set planning at codegen time | `pcs.rs::intermediate_sets` | Removes dynamic query sorting/grouping from Solidity | Generated verifier is circuit-specialized |
| Fewer point sets / dummy queries | `pcs.rs::compute_dummy_queries` | Can reduce KZG point-set work for selected profiles | Proof layout and transcript must include matching dummy evals |
| Truncated PCS challenges | `truncated-challenges` feature | Mirrors Midfall KZG challenge truncation where enabled | Only the specified challenges/powers are truncated |
| Accumulator pairing batch | `Halo2Verifier.sol` accumulator section | Combines public accumulator pairing with final KZG pairing | Batch randomizer is derived after all four G1 inputs are fixed |
| EIP-2537 gas caps and return-size checks | `TemplateConstants`, `layout::precompile::*_gas_cap` | Catches missing or incompatible precompiles without a runtime gas-table helper | Gas constants must match target fork assumptions |
| Gas checkpoints | `render_with_gas_checkpoints*` | Gives stable section-level gas deltas | Not a `view` verifier; profiling only |

## Trace Coverage

Trace builds compare the Solidity verifier against the instrumented Rust
verifier for:

- VK/domain values and Fiat-Shamir challenges;
- proof commitments and proof evaluations, including `q_evals`;
- reconstructed linearization expected scalar;
- selector fold buckets;
- PCS intermediate outputs and final pairing success.

In split quotient mode, the evaluator is invoked via `STATICCALL`, so it cannot
emit internal `LOG` trace records. That means the monolithic path can compare
per-identity quotient trace ids, while the external IVC path compares the
inputs, returned scalar, selector buckets, and downstream PCS binding.

## Reading The Generated Code

When auditing a rendered verifier, read it in this order:

1. Confirm the pinned VK/evaluator runtime lengths and codehashes.
2. Check the proof layout constants against `ProofCalldataLayout`.
3. Follow transcript absorption order through the challenge comments.
4. Confirm the evaluation buffer order matches `Protocol` metadata.
5. Read `QuotientNumeratorBlock.yul` as the lowering of
   `partially_evaluate_identities`.
6. Read the linearization scalar block as the scalar half of
   `compute_linearization_commitment`.
7. Read `pcs_computations` as the specialized KZG `multi_prepare` emitter.
8. Check final pairing and optional accumulator batching.

The generated contracts are intentionally verbose around these boundaries. Most
bugs in this style of verifier are not arithmetic typos in a single expression;
they are order, layout, or challenge-binding mismatches between the Rust
verifier and the Solidity-facing proof format.
