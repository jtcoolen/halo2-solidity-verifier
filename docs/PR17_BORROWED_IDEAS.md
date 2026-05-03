# Borrowed Ideas From privacy-ethereum PR #17

This repo borrows a narrow set of engineering ideas from
`privacy-ethereum/halo2-solidity-verifier` PR #17 without adopting its full
runtime-reusable verifier architecture.

## What We Borrow

- **Typed artifact payload layout.** Generated VK bytecode is treated as named
  sections: header, quotient constants, quotient program, fixed commitments,
  and permutation commitments. `VkPayloadLayout` validates that these sections
  are monotonic, non-overlapping, and byte-length consistent with the rendered
  `Halo2VerifyingKey.sol` runtime.
- **Explicit packed-program codec.** Quotient VM bytecode is packed into
  32-byte VK words through `PackedProgramCodec`, with tests for explicit byte
  lengths, out-of-capacity lengths, and non-zero padding.
- **Artifact mutation tests.** The Solidity regression suite now mutates each
  correctness-critical VK payload section and checks that the pinned verifier
  rejects the changed artifact.

## What We Do Not Borrow

- No `Halo2VerifierReusable` contract.
- No dynamic verifier configuration loaded from an untrusted runtime artifact.
- No BN254/PSE Halo2 assumptions.
- No selector-compression, mvlookup, or logup code from that PR.
- No replacement of this repo's Askama templates, external pinned quotient
  evaluator, compact quotient VM/native callbacks, fused PCS MSM, Keccak
  transcript, or BLS12-381/EIP-2537 backend.

## Why Static And Pinned

This verifier generator targets Midfall/Midnight proof shapes and treats the
Rust verifier plus Rust/Solidity trace equivalence as the source of truth. The
VK and quotient evaluator are deployed as separate contracts for code-size
reasons, but both are pinned by expected runtime length and codehash before
verification.

That static shape is intentional:

- the verifier bytecode still commits to one concrete protocol plan;
- external artifacts cannot silently swap computation tables;
- trace equivalence continues to compare deterministic Solidity checkpoints
  against the real Rust verifier;
- gas remains driven by the current optimized verifier rather than a broad
  dynamic interpreter.

The borrowed PR #17 ideas therefore live only at the generator-validation layer:
they make payload offsets, packed bytecode, and mutation coverage more explicit
without changing the verifier's runtime trust model.

## Regression Hooks

Useful checks after touching artifact layout or quotient program packing:

```bash
cargo test --lib \
  --features evm,rust-verifier-trace,truncated-challenges,in-circuit-fewer-point-sets \
  -- --nocapture
```

```bash
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
HALO2_SOLIDITY_RUN_EVM_TESTS=1 \
cargo test --lib \
  --features evm,rust-verifier-trace,truncated-challenges,in-circuit-fewer-point-sets \
  vk_payload_section_mutations_are_rejected \
  -- --nocapture
```

Then run the full IVC trace-equivalence and detailed bench commands from
`README.md` before treating the change as production-relevant.
