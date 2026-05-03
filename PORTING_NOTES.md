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

| Layer                                  | State                                                   |
|----------------------------------------|---------------------------------------------------------|
| `templates/Halo2Verifier.sol`          | Rewritten for BLS12-381 / EIP-2537                      |
| `templates/Halo2VerifyingKey.sol`      | Rewritten for 4-word G1 / EIP-2537 layout               |
| `src/codegen/template.rs`              | `G1Words = (U256;4)`; VK length doubled                 |
| `src/codegen/util.rs`                  | EcPoint{base: Ptr} 4-word stride; Value signed offsets  |
| `src/codegen/pcs.rs`                   | Rewritten as an EIP-2537 Yul emitter                    |
| `src/codegen.rs`                       | Emits BLS-shape constants + `proof_to_bls_padded`        |
| `src/evm.rs`                           | revm 19, Prague spec, EIP-2537 precompiles (commit f028b99) |
| `src/codegen.rs::encode_calldata_bls_padded` | New crate-root export (commit c041bcb)             |
| `src/transcript.rs`                    | **Unchanged** -- still BN254-shape                      |
| `src/test.rs` heavy tests              | `#[ignore]`'d (need BLS prover)                         |
| `vendor/halo2/` (uncommitted)          | v0.4 trimmed to 4 sub-crates + 4 surgical patches       |
| Cargo.toml `halo2_proofs` dep          | Still v0.3 (pre-vendor switch)                          |
| Generated artifacts under `generated/` | Stale (BN254 outputs from `main`)                       |

Stages landed:

* **Stage A** (commit f028b99): revm 3.5 -> 19, Prague spec, EIP-2537
  precompiles wired in, plus a hand-assembled `prague_evm_runs_eip2537_g1add_to_identity`
  smoke test that calls `0x0b` with `2 * G1` and asserts non-zero output.
* **Stage B** (commit c041bcb): `SolidityGenerator::proof_to_bls_padded()`
  walks the proof byte-stream using `ConstraintSystemMeta` and the
  scheme's `num_trailing_g1_points`, expanding each G1 from 64 -> 128
  bytes to match what the BLS Solidity verifier reads. New crate-root
  export `encode_calldata_bls_padded()`. `examples/separately.rs` now
  deploys both contracts on the Prague EVM and reports outcome
  categorically (currently: revert at pairing with ~100k gas, which
  confirms the precompiles execute).

Stage C (in progress, not yet wired into Cargo.toml):

* `vendor/halo2/` carries a trimmed copy of upstream halo2 v0.4.0 with
  4 surgical patches (see `vendor/halo2/PATCHES.md`):
  1. `VerifyingKey::cs()` `pub(crate)` -> `pub`
  2. `VerifyingKey::permutation()` accessor (new)
  3. `permutation::VerifyingKey` + `commitments()` accessor (made `pub`)
  4. `ParamsKZG::{g, g2, s_g2}` accessors (new)
* The vendored workspace compiles cleanly under `cargo check
  --workspace` from `vendor/halo2/`.
* The project root `Cargo.toml` still pins halo2_proofs to v0.3 git tag
  so Stages A and B remain green; flipping to the vendored path requires
  porting every v0.3 -> v0.4 API call site (`Any::Advice` tuple variant,
  `ConstraintSystemBack`, `Repr<32>` vs `[u8; 32]`, `compile_circuit`,
  etc.) in `src/codegen.rs`, `src/transcript.rs`, `src/test.rs`, and
  `examples/separately.rs`. That is a multi-day effort and is intentionally
  not bundled in the same commit.

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

### 2. In-EVM Fp arithmetic in `pcs.rs` is broken

The BN254 verifier did some Fp arithmetic inline in EVM (e.g. computing the
quotient commitment via `mulmod`, evaluating PCS opening polynomials in
`Fp`). For BLS12-381:

* `Fp` is 381 bits, so `mulmod(_, _, p)` is not expressible in EVM (uint256
  cap). Any in-EVM Fp arithmetic must be replaced with EIP-2537 precompile
  calls plus modular helpers expressed over (hi, lo) splits.
* `EcPoint` in `src/codegen/util.rs` still tracks only `x` and `y` as single
  u256 words. We bumped its stride to 4 (so memory layout is correct), but
  the actual Yul emitter in `pcs.rs` still treats
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

1. **Wire the vendored halo2 v0.4 in.** `vendor/halo2/` is the prepared
   landing pad with 4 surgical patches applied (see
   `vendor/halo2/PATCHES.md`). To activate it:
   * Switch root `Cargo.toml` from
     `halo2_proofs = { git = "...", tag = "v0.3.0" }` to
     `halo2_proofs = { path = "vendor/halo2/halo2_proofs" }`.
   * Find a v0.4-compatible replacement for the `halo2_maingate` dev-dep
     (current pin v2024_01_31 is v0.3-shaped). Either bump to a newer
     maingate tag, or replace the `MainGate` test circuit with a custom
     one that doesn't depend on maingate.
   * Update every v0.3 -> v0.4 API call site:
     - `Any::Advice` is no longer a tuple variant -- destructuring patterns
       in `src/codegen.rs::ConstraintSystemMeta::new` need to be rewritten.
     - `ConstraintSystem` -> `ConstraintSystemBack` for downstream codegen
       reads.
     - `Repr<32>` vs `[u8; 32]` differences in `src/transcript.rs`.
     - `compile_circuit` is required between v0.4 frontend and backend.
     - `ProverSHPLONK` / `VerifierSHPLONK` / `ParamsKZG` API tweaks.
2. **Switch SolidityGenerator types from BN254 to BLS12-381.** Once v0.4
   compiles, the only remaining cryptographic gap is replacing
   `&ParamsKZG<bn256::Bn256>` / `&VerifyingKey<bn256::G1Affine>` with
   `&ParamsKZG<bls12_381::Bls12381>` / `&VerifyingKey<bls12_381::G1Affine>`
   throughout `src/codegen.rs` and the prover side in `examples/separately.rs`.
   The codegen helpers `g1_to_u256s` and `g2_to_u256s` already speak the
   correct EIP-2537 layout for real BLS points.
3. **Update `src/transcript.rs`.** `Keccak256Transcript` should read 96
   bytes per G1 commitment (48 + 48 BE) and append them to the running hash.
   Scalar (Fr) reads stay at 32 bytes.
4. **Refresh `generated/`.** Regenerate the canonical Solidity outputs once
   the BLS prover swap is done, and add a deterministic-render snapshot test.
5. **Reactivate `#[ignore]` tests.** As each layer is ported the
   corresponding render / pbt tests should be re-enabled. `function_signature`,
   the BLS codegen smoke tests, and
   `prague_evm_runs_eip2537_g1add_to_identity` already pass; `render_*`
   require a working BLS prover; `pbt_*` require `cargo test --release`.

## Useful pointers

* EIP-2537 spec: https://eips.ethereum.org/EIPS/eip-2537
* `halo2curves` BLS12-381 module:
  `~/.cargo/registry/src/.../halo2curves-0.7.0/src/bls12381/`
* PSE halo2 main (v0.4 with halo2curves 0.7):
  https://github.com/privacy-scaling-explorations/halo2

## Quick health check

```
cargo check --lib                              # Should build clean
cargo check --tests --examples --features evm  # Should build clean (warnings ok)
cargo test --lib                                # 3 pass, 17 ignored
cargo run --example separately --features evm   # Deploys + calls verifier per k

# Verify the vendored halo2 v0.4 still compiles on its own:
( cd vendor/halo2 && cargo check --workspace )
```

If any of those fail, something has regressed in the scaffolding layer; fix
that before chasing pcs / transcript work.
