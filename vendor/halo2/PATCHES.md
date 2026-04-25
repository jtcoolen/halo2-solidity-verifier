# vendor/halo2/ patches

This directory is a trimmed copy of the upstream halo2 v0.4.0 workspace
(`https://github.com/privacy-scaling-explorations/halo2`, tag `v0.4.0`),
with four surgical patches applied so the Solidity codegen pipeline can
read the parts of the verifying key and KZG params that v0.4 keeps
`pub(crate)` upstream.

## Members removed

The upstream workspace ships seven members; we keep four:

* `halo2_proofs` (re-export facade)
* `halo2_frontend` (`Circuit`, `ConstraintSystem`, etc.)
* `halo2_middleware` (intermediate plonk types)
* `halo2_backend` (KZG + verifier + transcript)

Removed: `halo2`, `halo2_debug`, `p3_frontend` (none are reachable from
the codegen pipeline). The dev-dependency on `halo2_debug` in
`halo2_proofs/Cargo.toml` is commented out.

## Patches

### 1. `halo2_backend/src/plonk.rs` -- `VerifyingKey::cs()`

```diff
- pub(crate) fn cs(&self) -> &ConstraintSystemBack<C::Scalar> {
+ pub fn cs(&self) -> &ConstraintSystemBack<C::Scalar> {
```

Why: `ConstraintSystemMeta::new` walks the constraint system to count
columns, queries, lookup args, etc. Without a public `cs()` accessor
the codegen has to re-implement the v0.4 `ConstraintSystemBack` from
scratch out of the (also partly private) `Circuit` config.

### 2. `halo2_backend/src/plonk.rs` -- `VerifyingKey::permutation()` (new)

```rust
pub fn permutation(&self) -> &permutation::VerifyingKey<C> {
    &self.permutation
}
```

Why: The Solidity codegen pastes per-column permutation commitments
into `Halo2VerifyingKey.sol`. Upstream there is no public path to
those commitments at all.

### 3. `halo2_backend/src/plonk/permutation.rs` -- `VerifyingKey` + `commitments()`

```diff
- pub(crate) struct VerifyingKey<C: CurveAffine> {
+ pub struct VerifyingKey<C: CurveAffine> {
     commitments: Vec<C>,
  }

  impl<C: CurveAffine> VerifyingKey<C> {
+     pub fn commitments(&self) -> &[C] {
+         &self.commitments
+     }
```

Why: paired with patch 2, this exposes the actual `Vec<C>` to the
codegen.

### 4. `halo2_backend/src/poly/kzg/commitment.rs` -- `ParamsKZG::{g, g2, s_g2}` (new)

```rust
pub fn g(&self) -> &[E::G1Affine]   { &self.g }
pub fn g2(&self) -> E::G2Affine     { self.g2 }
pub fn s_g2(&self) -> E::G2Affine   { self.s_g2 }
```

Why: `g[0]` is needed for the BDFG21 batch-open emitter; `g2` and
`s_g2` are written into the verifier as the pairing's right-hand-side
points.

## Wiring

Once the rest of the migration is done (every v0.3->v0.4 API rename in
`src/codegen.rs`, `src/transcript.rs`, `src/test.rs` is fixed), the
project root `Cargo.toml` switches from

```toml
halo2_proofs = { git = "...halo2", tag = "v0.3.0" }
```

to

```toml
halo2_proofs = { path = "vendor/halo2/halo2_proofs" }
```

The `halo2_maingate` dev-dep also needs a path/tag bump because v0.3
maingate doesn't compile against v0.4 halo2_proofs. See
`PORTING_NOTES.md` in the project root for the migration checklist.
