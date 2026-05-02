# Quotient Numerator Evaluator

This note documents the split `Halo2QuotientEvaluator` contract and how it
maps to the real Midfall Rust verifier. The Solidity path is intentionally not
a second protocol definition: it reconstructs the same values the Rust verifier
derives after the transcript samples `x`.

## What The Solidity Contract Computes

`Halo2QuotientEvaluator` receives a verifier memory frame from
`Halo2Verifier`, copies it to the same memory addresses, and runs the generated
batched identity numerator block. Its output frame contains:

- word 0: quotient evaluator magic;
- word 1: `linearization_expected_eval`;
- following words: simple-selector linearization accumulators.

The evaluator reconstructs the y-batched identity numerator `nu_y(x)` from
proof evaluations, fixed verifier data, public-input Lagrange evaluation, and
Fiat-Shamir challenges. It stores `-nu_y(x)` as the expected scalar for the
linearized commitment opening.

It does not evaluate `h(x)` and it does not trust an `h(x)` scalar from the
proof. The commitment side already adds the quotient limb commitments with the
factor `(1 - x^n) * sum_i splitting_factor^i * Q_i`, so the scalar side is the
negated numerator, not `nu_y(x) / (x^n - 1)`.

## Rust Source Of Truth

The verifier control flow lives in:

- `/Users/Julien.Coolen/midfall/proofs/src/plonk/verifier.rs`
- `/Users/Julien.Coolen/midfall/proofs/src/plonk/mod.rs`
- `/Users/Julien.Coolen/midfall/proofs/src/plonk/linearization/verifier.rs`
- `/Users/Julien.Coolen/midfall/proofs/src/plonk/logup.rs`
- `/Users/Julien.Coolen/midfall/proofs/src/plonk/trash.rs`

`verifier.rs` first reads commitments and transcript challenges, then reads the
quotient limb commitments before sampling `x`. After `x`, it reads or computes
the evaluations used by the identity numerator:

- committed and non-committed instance evaluations;
- advice evaluations;
- fixed evaluations, with simple-selector fixed columns omitted from the proof
  and filled with `1`;
- permutation common/sigma/product evaluations;
- lookup multiplicity, helper, and accumulator evaluations;
- trash evaluations.

The Solidity verifier performs the same evaluation read order before calling
the external quotient evaluator. The frame passed to the evaluator contains
those values at the same generated memory addresses.

## Identity Order And Selector Handling

`mod.rs::partially_evaluate_identities` returns `Vec<(Option<usize>, F)>`.
Its order is:

1. gate identities, each tagged with `Some(simple_selector_col)` if the gate is
   guarded by a simple selector, otherwise `None`;
2. permutation identities, always `None`;
3. lookup identities, always `None`;
4. trash identities, always `None`.

The generated quotient program preserves that order. Main identities fold into
the fully evaluated numerator. Simple-selector identities fold into selector
accumulator buckets and are later added to the linearization commitment as
fixed-selector commitments.

Rust linearization folds the identities in reverse:

```text
for (selector, eval) in expressions.iter().rev() {
    grouped[selector] += y_pow * eval
    y_pow *= y
}
```

Solidity scans forward and updates:

```text
quotient_eval_numer = quotient_eval_numer * y + eval
```

This is algebraically the same y-power assignment. For selectors, Solidity
adds `eval * y^-k` to the selector bucket at step `k`, then multiplies every
selector bucket by the final `y^m`. That yields `eval * y^(m-k)`, matching the
Rust reverse fold.

## Linearization Commitment

`linearization/verifier.rs::compute_linearization_commitment` builds a
`VerifierQuery` at `x`:

- quotient limb commitments receive scalars
  `(1 - x^n), (1 - x^n) * splitting_factor, ...`;
- simple selector buckets become fixed commitment scalars;
- fully evaluated `None` identities are subtracted into `expected_eval`.

The generated Solidity mirrors the same split. `Halo2Verifier` builds the
commitment side, while `Halo2QuotientEvaluator` returns the expected scalar and
selector bucket scalars.

## Permutation, Lookup, And Trash

Permutation expressions correspond to the iterator chained from
`permutation::expressions` inside `partially_evaluate_identities`. The
generated evaluator keeps the product checks looped over sets/chunks and uses
the same `l_0`, `l_last`, `l_blind`, `beta`, `gamma`, `x`, and `delta` values.

Lookup expressions correspond to `logup.rs::Evaluated::expressions`:

- boundary: `(l_0 + l_last) * Z(x)`;
- helper constraints:
  `h_i(x) * product_j(f_j(x) + beta) - sum_j product_{k != j}(f_k(x) + beta)`;
- accumulator constraint on active rows:
  `(Z(omega*x) - Z(x) - selector * sum_i h_i(x)) * (t(x) + beta) + m(x)`.

Trash expressions correspond to `trash.rs::Evaluated::expressions`. The Rust
code compresses each trash argument by Horner folding with
`trash_challenge`, then subtracts `(1 - q) * trash_eval`.

## Compact/Gas Policy

The default split evaluator is gas-capped compact mode:

- direct inline prefix: first four gate identities;
- native callbacks: four heaviest remaining gate identities;
- native permutation loop;
- structured trash suffix;
- all other identities: compact `q_program` VM stored in the VK payload.

This default was selected because the release IVC trace-equivalent run stayed
below the hard gas gate and gave comfortable evaluator bytecode margin:

- total gas: `1,614,572`;
- quotient runtime: `21,774` bytes;
- verifier runtime: `12,885` bytes;
- VK runtime: `13,568` bytes.

The gas-checkpoint bench for the same default reported total tx gas
`1,594,941`, real checkpointed section work `1,432,403`, and batched identity
numerator reconstruction `631,289`.

The env var `HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=N` remains an experimental
tuning hook. Any non-default setting must pass the native Rust/Solidity trace
differential and the release IVC bench before it is treated as safe.
