# BN254 -> BLS12-381 Porting Notes

This branch (`bls`) is a **work-in-progress** port of the Halo2 Solidity
verifier from BN254 to BLS12-381 with the EIP-2537 precompiles. Read this
document **before** trying to use the generated Solidity for anything other
than reviewing its shape -- there are open ends.

## Goals

1. Replace BN254 (precompiles `0x06`, `0x07`, `0x08`) with BLS12-381 EIP-2537
   precompiles (`0x0b`, `0x0c`, `0x0f`).
2. Switch all field/curve constants and calldata layouts to BLS12-381.
3. Keep the codegen pipeline driving the Rust crate working so we can iterate
   on the verifier template, calldata encoding, and tests.

## Current state

| Layer                                  | State                                     |
|----------------------------------------|-------------------------------------------|
| `templates/Halo2Verifier.sol`          | Rewritten for BLS12-381 / EIP-2537        |
| `templates/Halo2VerifyingKey.sol`      | Rewritten for 4-word G1 / EIP-2537 layout |
| `src/codegen/template.rs`              | `G1Words = (U256;4)`; VK length doubled   |
| `src/codegen/util.rs`                  | New BLS helpers + Data stride 4 words     |
| `src/codegen.rs`                       | Emits BLS-shape constants (see caveats)   |
| `src/transcript.rs`                    | **Unchanged** -- still BN254-shape        |
| `src/codegen/pcs/{bdfg21,gwc19}.rs`    | **Unchanged** -- emits BN254-flavoured Yul|
| `src/test.rs` heavy tests              | `#[ignore]`'d                             |
| Generated artifacts under `generated/` | Stale (BN254 outputs from `main`)         |

Everything in the **Unchanged** rows still needs work; see "What's missing"
below.

## What works

* `cargo check`, `cargo test --lib function_signature` pass cleanly.
* `templates/Halo2VerifyingKey.sol` and the prelude of
  `templates/Halo2Verifier.sol` produce a 100% BLS12-381 / EIP-2537 layout:
  G1 = 4 words, G2 = 8 words, EIP-2537 padding (16 zero bytes + 48 byte
  value per Fp coord), BLS12-381 scalar field modulus, precompile calls to
  `0x0b` / `0x0c` / `0x0f`.
* The Rust crate now exposes the `halo2curves::bls12381` types via the
  `halo2curves = "0.7"` dependency (`halo2_proofs` v0.3 still uses 0.6
  internally, which is fine -- both versions co-exist in the dep tree).

## Known cryptographic caveats

### 1. The Rust prover backend is still BN254

The fundamental blocker is that **`halo2_proofs` v0.3 has no KZG backend
for BLS12-381**. The PSE main branch (`v0.4`) pulls `halo2curves 0.7` (which
*does* have BLS12-381) but the API has been split into multiple crates and
the porting work is much larger than this diff. Until a halo2 KZG-BLS
backend is wired in:

* `SolidityGenerator::new` still takes `&ParamsKZG<bn256::Bn256>` and
  `&VerifyingKey<bn256::G1Affine>`.
* `src/codegen.rs::generate_vk` calls `bls_g1_pad_from_bn254_bytes` /
  `bls_g2_pad_from_bn254_bytes` which **zero-extend the 32-byte BN254
  coordinates to 48 bytes** before splitting per EIP-2537. The resulting
  bytes are *not* valid BLS12-381 curve points -- they're shape-correct
  scaffolding so the rest of the codegen pipeline keeps working.
* The pairing precompile call will revert at runtime because the embedded
  points aren't on the BLS curve. **This is expected** until we have a
  real BLS prover.

### 2. In-EVM Fp arithmetic in `pcs/{bdfg21,gwc19}.rs` is broken

The BN254 verifier did some Fp arithmetic inline in EVM (e.g. computing the
quotient commitment via `mulmod`, evaluating PCS opening polynomials in
`Fp`). For BLS12-381:

* `Fp` is 381 bits, so `mulmod(_, _, p)` is not expressible in EVM (uint256
  cap). Any in-EVM Fp arithmetic must be replaced with EIP-2537 precompile
  calls plus modular helpers expressed over (hi, lo) splits.
* `EcPoint` in `src/codegen/util.rs` still tracks only `x` and `y` as single
  u256 words. We bumped its stride to 4 (so memory layout is correct), but
  the actual Yul emitters in `pcs/bdfg21.rs` and `pcs/gwc19.rs` still treat
  points as `(x, y)` of single u256 each.

The pcs blocks therefore emit Yul that **won't compile cleanly** against the
new BLS12-381 layout. The `#[ignore]`'d render tests would surface this if
you re-enabled them.

### 3. Transcript is still BN254-shape

`src/transcript.rs` writes 32 bytes per Fp coord; for BLS12-381 it should
write 48 bytes (or 64 with EIP-2537 zero padding). The transcript module
needs new `read_point` / `write_point` paths. Same for `encode_calldata` if
we want strict typing -- `encode_calldata` currently treats `proof` as
opaque bytes which is fine, but the proof bytes a real BLS halo2 fork emits
will have a different layout from what the test fixtures here produce.

### 4. Generated artifacts under `generated/`

The committed `generated/Halo2Verifier.sol` is a stale BN254 artifact from
`main`. It is **not** regenerated against the BLS pipeline. Once the gaps
above are closed we should regenerate it.

## What's still to do

1. **Find / write a halo2 KZG-BLS backend.** Most likely path: upgrade to
   `halo2_proofs v0.4` (PSE main) which uses `halo2curves 0.7` with
   `bls12381`. Confirm that `ParamsKZG<E>` works with `bls12_381::Bls12`
   (since `ParamsKZG` is generic over `E: Engine`, and `bls12_381::Bls12`
   does implement `Engine`). The crate API split between `halo2_middleware`
   / `halo2_backend` / `halo2_frontend` will require touch-ups across
   `src/test.rs` and `examples/`.
2. **Rewrite `src/codegen/pcs/{bdfg21,gwc19}.rs`.** The PCS opening checks
   need to call `BLS12_G1ADD` / `BLS12_G1MSM` / `BLS12_PAIRING_CHECK`
   instead of doing Fp arithmetic inline. `EcPoint` must grow `(x_hi, x_lo,
   y_hi, y_lo)` fields and the Yul emitters must reflect that.
3. **Update `src/transcript.rs`.** `Keccak256Transcript` should read 96
   bytes per G1 commitment (48 + 48 BE) and append them to the running hash.
   Scalar (Fr) reads stay at 32 bytes.
4. **Refresh `generated/`.** Regenerate the canonical Solidity outputs once
   (1)-(3) are done, and add a deterministic-render snapshot test.
5. **Reactivate `#[ignore]` tests.** As each layer is ported the
   corresponding render / pbt tests should be re-enabled. The
   `function_signature` smoke test is the minimum hurdle; `render_*`
   require a working BLS prover; `pbt_*` require `cargo test --release`.

## Useful pointers

* EIP-2537 spec: https://eips.ethereum.org/EIPS/eip-2537
* `halo2curves` BLS12-381 module:
  `~/.cargo/registry/src/.../halo2curves-0.7.0/src/bls12381/`
* PSE halo2 main (v0.4 with halo2curves 0.7):
  https://github.com/privacy-scaling-explorations/halo2

## Quick health check

```
cargo check --lib              # Should build clean
cargo check --tests --examples # Should build clean (warnings ok)
cargo test --lib function_signature
```

If any of those fail, something has regressed in the scaffolding layer; fix
that before chasing pcs / transcript work.
