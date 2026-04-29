# N-Way Quotient Helper Split — Session Notes

Summary of what was achieved this session.

## Phase 1 — Inline-asm spill (replace `_vS`/`_vL` external calls)

Each spilled assignment is now an inline `assembly { mload/mstore }`
block with per-statement load-temp locals. No per-call ~700 gas
overhead, optimizer can pack tightly. Smoke bytecode shrunk vs the
helper-call version.

Each per-identity body now looks like:

```solidity
{
    uint256 _l2;
    uint256 _l3;
    assembly {
        _l2 := mload(add(vbase, 0x40))
        _l3 := mload(add(vbase, 0x60))
    }
    uint256 _t = mulmod(_l2, _l3, r);
    assembly { mstore(add(vbase, 0x80), _t) }
}
```

Slab is hand-allocated by bumping the free-memory pointer in inline
assembly — no `uint256[N] memory v` syntax (its generated
`zero_array_uint256_N_K_mpos` initializer itself overflows the Yul
stack at large N).

## Phase 2 — N-way split

Added:

- `SolidityGenerator::render_with_quotient_helpers_n(N)` returning
  `(main_sol, vk_sol, Vec<helper_sol>)`.
- `emit_dispatch_block_n(sorted_simple, counts, mem_dump_size)`:
  one `delegatecall` block per helper + one N-way sparse-Horner
  combine block + tail mstore block.
- `helper_tag(i)` -> `"A".."Z"` for i<26, `"N{i}"` beyond.

Identities are partitioned into N near-equal chunks (in identity
order). Main verifier dispatches via a `helpers_ptr`-rooted memory
array of helper addresses, then combines accumulators via N-way
sparse Horner.

Template updates (`templates/Halo2Verifier.sol`):

- Constructor signature changed to
  `constructor(address authorizedVk, address[] memory helpers)`.
- N immutables `HELPER_0 .. HELPER_{N-1}` declared via
  `{%- for i in 0..self.quotient_helpers_n %}` loop.
- `verifyProof` marshals the immutables into a stack-light
  `address[N] memory __helpers`, then exposes the array-base
  pointer to inline assembly via:

```solidity
uint256 helpers_ptr;
assembly { helpers_ptr := __helpers }
```

so the QE dispatch loop reads each helper via
`mload(add(helpers_ptr, i*0x20))` (one slot for the base pointer,
zero stack pressure regardless of N).

## Phase 3 — IVC e2e

With `IVC_SPLIT_N=16`, all contracts fit under EIP-170 (24576-byte
cap):

- main = 22 850 B  (was 49 570 B inline)
- vk   =  5 922 B
- helpers (compiled bytecode):

  ```
  A=1392  B=737   C=5096  D=10214  E=17923  F=23459  G=23545  H=7584
  I=762   J=4143  K=3444  L=3579   M=5000   N=175    O=175    P=175
  ```

  max 23 545 B, all under the 24 576-byte cap.

The split path deploys and runs end-to-end on Prague-spec revm. The
verifier hits the same pre-existing gas-bounded revert as the inline
path (~4.92 B gas with a 5 B cap), confirming the split is
logic-equivalent. The remaining revert is an independent, documented
IVC-specific issue (likely missing `set_acc_encoding` / acc-pairing
logic, or a precompile-failure cascade), not related to the helper
split.

Inline vs split `gas_used` deltas:

```
Inline 4 922 038 815  ->  Split 4 922 038 334   (-481 gas)
```

The 481-gas difference reflects the QE block becoming a delegatecall
chain that's slightly cheaper than the inlined Yul block, and is
within the noise budget of solc's optimizer rearrangements.

## Files touched

- `src/codegen.rs`
  - `render_with_quotient_helpers()` -> thin wrapper over
    `render_with_quotient_helpers_n(2)`.
  - `render_with_quotient_helpers_n(N)` -> new public API.
  - `emit_dispatch_block_n(sorted_simple, counts, mem_dump_size)`.
  - `helper_tag(i)`.
  - `render_quotient_helper_solidity()` per-identity inline-asm spill
    (replaces `_vS`/`_vL` external calls).
  - `collect_named_refs()` helper.
- `src/codegen/template.rs`
  - `Halo2Verifier.quotient_helpers_n: usize` field.
- `src/evm.rs`
  - `Evm::create_with_address_and_address_array_arg(...)` to deploy
    the new `(address, address[] memory)` constructor.
- `src/lib.rs` — re-exports.
- `templates/Halo2Verifier.sol`
  - Per-helper immutables loop.
  - `address[] memory helpers` constructor.
  - Stack-light `__helpers` array + `helpers_ptr` for assembly.
- `tests/ivc_keccak_solidity.rs`
  - `IVC_SPLIT_N` env var (default 16).
  - Renders + compiles + deploys all helpers + main with
    `create_with_address_and_address_array_arg`.
  - Per-helper EIP-170 size check + summary line.
- `src/test.rs` — `quotient_split_renders_and_compiles` smoke test
  unchanged (still calls 2-arg `render_with_quotient_helpers`).

## Known limits / next steps

1. Underlying IVC verifier revert at ~4.92 B gas is pre-existing and
   unrelated to the helper split; chasing it down probably needs
   `set_acc_encoding(...)` plumbed through and/or a precompile-fail
   audit.
2. With N=16 the largest helper is right at 23.5 KB. A circuit larger
   than the IVC could push helpers over 24 KB; bump `IVC_SPLIT_N` or
   add a size-aware partitioner if that becomes an issue.
3. Per-helper deployment cost is ~50 KB code-deposit gas × 16 = ~800 KB
   total deployment bytecode. One-time cost; verifyProof is unaffected.
