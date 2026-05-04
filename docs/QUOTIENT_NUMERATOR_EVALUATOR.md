# Quotient Numerator Evaluator

This document explains the generated `Halo2QuotientEvaluator` contract: what
data it receives, what it computes, how the result is consumed by
`Halo2Verifier`, and how every step maps back to the Midfall Rust verifier.

The important mental model is:

```text
Rust verifier:
  partially_evaluate_identities(...)
  compute_linearization_commitment(...)

Solidity split verifier:
  Halo2Verifier prepares the same transcript challenges and evaluations
  Halo2QuotientEvaluator reconstructs the same batched numerator scalar data
  Halo2Verifier folds those scalar data into the final PCS check
```

The Solidity evaluator is not a second verifier design. It is a lowered,
size-aware implementation of the same Rust verifier steps.

The complete upstream comment corpus is preserved in
`docs/MIDFALL_PROOFS_COMMENT_CORPUS.md`. This document adapts only the comments
that directly explain the generated quotient path: identity ordering, simple
selector handling, LogUp/permutation/trash evaluations, and the linearization
commitment sign convention.

## Contract Role

`Halo2QuotientEvaluator` is an external helper contract used by the split
Solidity verifier. It exists because the batched identity numerator is the
largest generated arithmetic block. Keeping it in a separate pinned contract
lets the main verifier and the quotient evaluator each stay below the EIP-170
runtime-code limit.

The evaluator:

1. receives a raw memory frame from `Halo2Verifier`;
2. copies that frame into the same generated memory addresses;
3. runs the generated batched identity numerator reconstruction;
4. returns a compact output frame containing the linearization expected scalar
   and simple-selector accumulator scalars.

The evaluator does not:

- parse the public ABI;
- read proof calldata directly;
- perform transcript hashing;
- evaluate a prover-supplied quotient scalar;
- build or check elliptic-curve commitments.

Those jobs stay in `Halo2Verifier`.

## Trust Boundary

The quotient evaluator is correctness-critical. A malicious evaluator could
return a different expected scalar or different selector accumulators, changing
the statement the verifier checks. For that reason the main verifier pins the
quotient evaluator by generated runtime length and codehash:

```solidity
EXPECTED_QUOTIENT_LENGTH
EXPECTED_QUOTIENT_CODEHASH
```

The verifier checks those constants at construction and again before proof
verification. The evaluator output also carries a generated magic word, and
the verifier rejects outputs with the wrong size or wrong magic.

## Frame ABI

`Halo2QuotientEvaluator` has only a fallback entry point. Its calldata is not
normal Solidity ABI. It is exactly the verifier memory image:

```text
calldata[0..QUOTIENT_FRAME_LEN) == memory[QUOTIENT_FRAME_BASE..+QUOTIENT_FRAME_LEN)
```

The fallback rejects any calldata length other than `QUOTIENT_FRAME_LEN`:

```yul
if iszero(eq(calldatasize(), QUOTIENT_FRAME_LEN)) { revert(0, 0) }
calldatacopy(QUOTIENT_FRAME_BASE, 0, QUOTIENT_FRAME_LEN)
```

The copied frame contains:

- verifier-key words, including domain constants and the quotient VM payload;
- Fiat-Shamir challenges already sampled by `Halo2Verifier`;
- proof evaluations already decoded and range-checked by `Halo2Verifier`;
- Lagrange values `l_last`, `l_blind`, and `l_0`;
- the locally computed public-instance evaluation;
- scratch/output space for selector accumulators.

The output frame is compact:

```text
word 0: QUOTIENT_MAGIC
word 1: linearization_expected_eval
word 2..: simple-selector accumulator scalars, one word each
```

`Halo2Verifier` writes `word 1` to `QUOTIENT_EVAL_MPTR` and copies the
selector words back to `SELECTOR_ACC_MPTR`.

## Rust Source Of Truth

The relevant Rust files are:

- `midfall/proofs/src/plonk/verifier.rs`
- `midfall/proofs/src/plonk/mod.rs`
- `midfall/proofs/src/plonk/linearization/verifier.rs`
- `midfall/proofs/src/plonk/permutation.rs`
- `midfall/proofs/src/plonk/logup.rs`
- `midfall/proofs/src/plonk/trash.rs`

When this repository copies or adapts those comments into Solidity/Yul, it keeps
the upstream role intact: the comments explain the Rust verifier behavior first,
then name the local memory slot or generated block that ports it.

The Rust verifier flow around the quotient numerator is:

1. read quotient limb commitments from the transcript;
2. sample the evaluation challenge `x`;
3. compute `splitting_factor = x^(n - 1)` and `x^n`;
4. read or compute all evaluations used by identities;
5. call `partially_evaluate_identities`;
6. call `compute_linearization_commitment`;
7. add the linearization query to the PCS multi-open check.

The generated Solidity follows the same order. The external evaluator begins
only after `Halo2Verifier` has completed steps 1 through 4.

## Quotient Commitments Are Not Quotient Scalars

The Rust comment in `verifier.rs` says the verifier reads commitments to:

```text
h(X) = nu(X) / (X^n - 1)
```

In the multi-limb case, the prover commits to limbs of `h`. Those are G1
commitments, not scalar evaluations trusted from the proof.

The Solidity evaluator reconstructs the numerator side:

```text
nu_y(x)
```

and stores:

```text
linearization_expected_eval = -nu_y(x)
```

It does not compute:

```text
h(x) = nu_y(x) / (x^n - 1)
```

The commitment side supplies the quotient factor separately:

```text
(1 - x^n) * sum_i splitting_factor^i * Q_i
```

Since `(1 - x^n) = -(x^n - 1)`, this is the same sign convention as the Rust
linearization formula, just arranged so the scalar side is `-nu_y(x)`.

## Evaluation Inputs

After `x` is sampled, Rust reads or computes the evaluations that feed
`partially_evaluate_identities`.

### Instance Evaluations

For committed instance columns, Rust reads the evaluation from the transcript.
For public instance columns, Rust computes the evaluation locally by Lagrange
interpolation against the public inputs.

Solidity mirrors this split: committed instance evaluations are proof scalars,
while the non-committed public input evaluation is computed in the Lagrange
block and stored in the quotient frame.

### Advice Evaluations

Rust reads one evaluation for each advice query and each proof. Solidity reads
the same scalars into generated memory slots after transcript challenge `x`.

### Fixed Evaluations And Simple Selectors

Rust reads:

```text
num_fixed_columns - num_simple_selectors
```

fixed evaluations from the transcript. Then it inserts `F::ONE` into the
missing positions for simple selector columns. The Rust comment explains that
the proof does not contain evaluations for multiplicative simple selectors.

Solidity uses the same convention. Simple selector identities are not fully
evaluated into the scalar numerator. Instead, they are accumulated into
selector buckets and later paired with fixed selector commitments in the
linearization MSM.

### Permutation, Lookup, And Trash Evaluations

Rust obtains these through their argument-specific `evaluate` methods. Solidity
has already decoded their corresponding proof scalars before the external
quotient call:

- permutation common/sigma evaluations and product polynomial evaluations;
- lookup multiplicity, helper, accumulator, and next-accumulator evaluations;
- trash evaluation scalars.

## Identity List Shape

`mod.rs::partially_evaluate_identities` returns:

```text
Vec<(Option<usize>, F)>
```

The `Option<usize>` is the linearization target:

- `Some(selector_column_index)` means the identity is gated by a simple fixed
  selector and should become a selector commitment scalar;
- `None` means the identity is fully evaluated and contributes only to the
  expected opening scalar.

The Rust iterator order is:

1. custom gate identities;
2. permutation identities;
3. lookup identities;
4. trash identities.

The generated quotient program preserves this order exactly.

## Gate Identities

For each custom gate polynomial, Rust evaluates the expression with:

- constants mapped directly;
- fixed/advice/instance queries mapped to their evaluations at `x`;
- challenge queries mapped to sampled challenges;
- expression nodes lowered through negation, addition, multiplication, and
  scalar multiplication.

Virtual selectors are expected to have been removed during optimization.

For each gate, Rust finds the first queried simple selector, if any, and
returns that selector column index alongside the evaluated identity. Solidity
does the same classification during code generation.

## Permutation Identities

The Rust comments in `permutation.rs` describe four kinds of constraints.
Solidity emits the same sequence.

### First Set Boundary

Only the first set enforces:

```text
l_0(x) * (1 - z_0(x))
```

### Last Set Boolean Boundary

Only the last set enforces:

```text
l_last(x) * (z_l(x)^2 - z_l(x))
```

### Cross-Set Continuity

For every set after the first, Rust enforces:

```text
l_0(x) * (z_i(x) - z_{i-1}(omega^last * x))
```

The verifier reads the previous set's last-row product evaluation for this.

### Active-Row Product Check

For every set, Rust enforces on active rows:

```text
(1 - (l_last(x) + l_blind(x))) *
(
    z_i(omega*x) * product(p(x) + beta*s_i(x) + gamma)
  - z_i(x)       * product(p(x) + delta^i*beta*x + gamma)
)
```

The generated Solidity keeps this product looped over permutation chunks. It
uses the same `delta`, `beta`, `gamma`, `x`, `l_last`, and `l_blind` values.

## Lookup Identities

`logup.rs::Evaluated::expressions` documents the LogUp checks. When a lookup
has multiple columns, Rust compresses expressions with `theta`:

```text
acc = acc * theta + eval
```

Both input values `f_j` and table value `t` are compressed this way.

The emitted identities are:

### Boundary

```text
(l_0(x) + l_last(x)) * Z(x)
```

### Helper Constraints

For each lookup input chunk:

```text
h_i(x) * product_j(f_j(x) + beta)
  - sum_j product_{k != j}(f_k(x) + beta)
```

### Accumulator Constraint

On active rows:

```text
(
    Z(omega*x)
  - Z(x)
  - selector(x) * sum_i h_i(x)
) * (t(x) + beta)
+ m(x)
```

then multiplied by:

```text
1 - (l_last(x) + l_blind(x))
```

The Rust comment notes that the selector gates only the input-side helper sum.
Multiplicities are always subtracted so table-side balance is maintained.
Solidity follows that same convention.

## Trash Identities

`trash.rs::Evaluated::expressions` compresses each trash argument's constraint
expressions with `trash_challenge` using Horner form:

```text
compressed = (((expr_0) * trash_challenge + expr_1) ...)
```

Then it subtracts the inactive-row trash term:

```text
compressed - (1 - q(x)) * trash_eval
```

The Rust `required_degree` comment notes that the degree is at least two
because of the `(1 - q) * trash` product. Solidity emits the same formula in
the structured trash suffix by default. Set
`HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=off` to leave trash identities in the
VM for the smaller compile-stable fallback.

## Y-Batching Algebra

Rust linearization groups identity evaluations in reverse:

```text
y_pow = 1
for (selector, eval) in expressions.rev():
    grouped[selector] += y_pow * eval
    y_pow *= y
```

If the forward identity order is:

```text
e_0, e_1, ..., e_{m-1}
```

then the Rust scalar for `e_i` is:

```text
y^(m - 1 - i) * e_i
```

Solidity scans forward with Horner form:

```text
acc = 0
for e_i in forward_order:
    acc = acc * y + e_i
```

After all identities, this is:

```text
y^(m-1)*e_0 + y^(m-2)*e_1 + ... + e_{m-1}
```

which matches Rust.

## Selector Accumulator Algebra

Simple selector identities must keep the same y-batch position but cannot be
added to the fully evaluated numerator. Rust groups them by selector commitment
in a `BTreeMap<Option<usize>, F>`.

Solidity maintains three values:

```text
quotient_eval_numer
q_sel_scale      = y^k
q_sel_inv_scale  = y^-k
```

At identity step `k`, Solidity first advances both scales:

```text
q_sel_scale *= y
q_sel_inv_scale *= y^-1
```

For a selector identity with evaluation `eval`, it stores:

```text
selector_bucket += eval * q_sel_inv_scale
```

At the end, every bucket is multiplied by the final `q_sel_scale`. If the
total number of identities is `m`, an evaluation at step `k` receives:

```text
eval * y^-k * y^m = eval * y^(m-k)
```

This is the same power assigned by the Rust reverse fold. The small index
difference comes from Solidity advancing the scale before the fold, so `k`
is one-based in that derivation.

## Linearization Output

`linearization/verifier.rs::compute_linearization_commitment` builds one
linear query at `x`.

The Rust comment describes the linearized commitment as:

```text
S_0 * id_0(x) + y*S_1*id_1(x) + ...
  - (h_0 + x^(n-1)*h_1 + ... ) * (x^n - 1)
```

where each `S_j` is either:

- a fixed commitment for a simple selector; or
- the constant polynomial `1` for fully evaluated identities.

In implementation terms:

- quotient limb commitments are added with powers of `splitting_factor`;
- simple selector buckets become fixed commitment scalars;
- `None` identities are subtracted into `expected_eval`.

Solidity splits this across two contracts:

- `Halo2QuotientEvaluator` returns `expected_eval` and selector buckets;
- `Halo2Verifier` expands quotient limbs and selector commitments into the
  fused PCS final MSM.

## Generated Evaluator Structure

The generated evaluator has four execution regions.

### Direct Inline Prefix

The first few gate identities are emitted directly. This is a small,
well-tested anchor and avoids routing every identity through the VM.

### Compact `q_program` VM

Most identity arithmetic is stored as a compact bytecode program in the VK
payload. The evaluator reads constants and program words from the copied frame
and interprets them with a small stack machine.

The VM has opcodes for:

- pushing constants;
- loading memory-backed evaluations/challenges;
- field add/mul/neg;
- fused add/mul forms used by expression lowering;
- optional limb-aware non-SHA foreign-field shapes;
- folding main identities;
- folding selector identities;
- invoking native callbacks.

The VM is the bytecode-size lever: moving identities into it usually shrinks
deployed bytecode but costs more runtime gas.

The limb-aware opcodes are behind:

```text
HALO2_SOLIDITY_QUOTIENT_LIMB_VM_OPS=1
```

They are opt-in until the IVC gas/size/trace gates are rebenchmarked. The
default remains the gas-capped compact path. The generator also validates
that the expanded VK quotient payload does not overlap the challenge/evaluation
memory frame; if an experiment would overrun that reserved space, rendering
fails closed instead of producing a verifier with corrupted transcript state.
To inspect what the structural matcher found in the opt-in lowering path,
run generation with both:

```text
HALO2_SOLIDITY_QUOTIENT_LIMB_VM_OPS=1
HALO2_SOLIDITY_QUOTIENT_SHAPE_PROFILE=1
```

The profile reports counts for `LIN7`, `BILIN7_ROW`,
`BILIN7_PAIRWISE`, and fallback VM operations.

### Native Callbacks

Large recognized identities can be emitted as native Yul callbacks. The
default gas-capped compact mode keeps four heavy gate identities native, plus
the native permutation and lookup loops.

Native callbacks preserve identity order because the VM stream contains an
opcode at the exact identity position. The callback computes the evaluation
and then returns to the shared fold logic.

The lookup callback is a whole-family superinstruction for the LogUp block. It
replaces the interpreted boundary, helper-chunk, and accumulator identities
with a generated structured loop that shares `f + beta`, prefix-product, and
suffix-product scratch tables.

### Structured Trash Suffix

The default emits trash identities as a structured Yul suffix. This is a
measured gas/size trade because trash is regular enough to avoid too much
bytecode while saving VM dispatch overhead. Set
`HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=off` to keep trash in the VM for the
smaller compile-stable fallback.

## Limb Helpers

The generated source may include:

```text
q_pow5
q_limb7
q_limb7_wide
LIN7
BILIN7_ROW
BILIN7_PAIRWISE
```

These helpers are not protocol rules. They are code-size/gas helpers for
recurring Midfall arithmetic shapes. The expression lowering still decides
what values are computed; the helpers only replace repeated Yul chains with
shared local functions when the generator recognizes an exact pattern.

Unrecognized expressions fall back to the compact VM or direct generated Yul.

### Are These Limbs Emulating A Different Field?

Yes, but with an important verifier-side caveat.

The Midfall foreign-field chips represent values from an emulated modulus `m`
as limbs:

```text
value = limb_0 + limb_1 * B + ... + limb_6 * B^6
```

where `B = 2^LOG2_BASE`, and the powers are reduced modulo `m`. The relevant
Rust source is:

```text
circuits/src/field/foreign/params.rs::base_powers
circuits/src/field/foreign/params.rs::double_base_powers
circuits/src/field/foreign/util.rs::sum_exprs
circuits/src/field/foreign/util.rs::pair_wise_prod
```

The circuit uses this representation to emulate arithmetic in a different
field or modulus inside the native proving field. The Solidity verifier does
not perform arithmetic in that foreign field directly. It evaluates the PLONK
identity polynomial over the native BLS12-381 scalar field `Fr`, exactly as the
Rust verifier does in:

```text
proofs/src/plonk/mod.rs::partially_evaluate_identities
proofs/src/plonk/verifier.rs
proofs/src/plonk/linearization/verifier.rs::compute_linearization_commitment
```

So the limb helpers are a compact lowering of already-generated constraint
expressions. They do not introduce a new trust assumption or a new runtime
field; they encode the same Fr polynomial identities that enforce congruences
modulo the foreign modulus `m` inside the circuit.

### Rust Gate Mapping

The helper names are Solidity codegen names. The Rust verifier does not call
`q_pow5`, `q_limb7`, or `q_limb7_wide`. Instead,
`mod.rs::partially_evaluate_identities` walks `vk.cs.gates`, evaluates each
gate polynomial, and returns the resulting `(Option<selector>, F)` items. The
Solidity generator sees those same expression trees and replaces a few common
subexpressions with helpers.

`q_pow5(x)` is the Poseidon S-box shape:

```text
q_pow5(x) = x^5 mod Fr = x * (x^2)^2 mod Fr
```

Rust source:

```text
circuits/src/hash/poseidon/poseidon_chip.rs::sbox
circuits/src/hash/poseidon/poseidon_chip.rs::full_round_gate
circuits/src/hash/poseidon/poseidon_chip.rs::partial_round_gate
circuits/src/hash/poseidon/round_skips.rs::RoundId::to_expression
```

Those gates use quintic Poseidon terms either directly or through skipped-round
linear combinations. When the lowered expression contains five identical
multiplicative factors, the generator emits `q_pow5(base)` instead of repeating
the multiplication chain at every site. The same helper may appear in the trash
suffix when trash identities compress expressions that originated from
Poseidon-like constraints.

`q_limb7(x0, ..., x6)` is the compact form of a 7-limb foreign-field linear
combination using `FieldEmulationParams::base_powers()`:

```text
q_limb7(x0..x6)
  = x0
  + c1*x1
  + c2*x2
  + c3*x3
  + c4*x4
  + c5*x5
  + c6*x6
  mod Fr
```

Rust source:

```text
circuits/src/field/foreign/params.rs::base_powers
circuits/src/field/foreign/gates/norm.rs::Foreign-field normalization
circuits/src/field/foreign/gates/mul.rs::Foreign-field multiplication
```

In normalization, this corresponds to terms such as:

```text
sum_exprs(base_powers, shifted_x) - sum_exprs(base_powers, zs)
```

In multiplication, it corresponds to the `sum_x`, `sum_y`, and `sum_z` limb
packing terms:

```text
sum_exprs(base_powers, xs)
sum_exprs(base_powers, ys)
sum_exprs(base_powers, zs)
```

The constants in `q_limb7` are the generated Fr residues for this verifier's
7-limb foreign-field basis. They are not dynamic proof inputs.

`LIN7` is the VM form of the same idea, but table-backed:

```text
LIN7(values, coeffs) = sum_{i=0..6} coeff[i] * values[i] mod Fr
```

The generator emits it only after structurally recognizing a 7-term linear
combination over literal memory-backed evaluations. Coefficients are inserted
into the generated quotient constant table; proof calldata never selects
coefficient tables.

`BILIN7_ROW` is the row form:

```text
BILIN7_ROW(lhs, rhs[0..6], coeffs)
  = sum_{i=0..6} coeff[i] * lhs * rhs[i] mod Fr
```

This is useful for foreign-field multiplication and EC formulas where one limb
is multiplied across a 7-limb vector.

`q_limb7_wide(x0, ..., x6)` is the analogous helper for the product-convolution
side of the foreign-field multiplication gate. Rust computes all pairwise limb
products and weights them with `FieldEmulationParams::double_base_powers()`:

```text
xys = pair_wise_prod(xs, ys)
sum_exprs(double_base_powers, xys)
```

The generated native gate code groups repeated 7-term slices of this wide basis
into calls to `q_limb7_wide`. This is why the native multiplication callbacks
contain many terms of the form `q_limb7_wide(a_i * b_0, ..., a_i * b_6)`.

`BILIN7_PAIRWISE` is the VM form of the full 7-by-7 convolution:

```text
BILIN7_PAIRWISE(lhs[0..6], rhs[0..6], coeff_by_sum[0..12])
  = sum_{i=0..6} sum_{j=0..6}
      coeff_by_sum[i + j] * lhs[i] * rhs[j] mod Fr
```

It structurally corresponds to:

```text
pair_wise_prod(xs, ys)
sum_exprs(double_base_powers, pair_wise_prod(xs, ys))
```

from the foreign-field multiplication gates. The opcode is generic enough for
the foreign-field EC gates too, including `is_on_curve`, lambda-slope,
`assert_tangent`, and `assert_lambda_squared`, whenever their lowered
expressions contain the same 7-limb bilinear shape.

This pass deliberately does not add SHA256, SHA512, RIPEMD, or spread
decomposition recognizers. Those chips are outside the current IVC verifier
scope, so recognizing them would add codegen surface without a measured win.

These helpers therefore relate to these specific Rust circuit gates:

| Helper/opcode | Rust gate source | Meaning |
|---|---|---|
| `q_pow5` | Poseidon full/partial/skipped-round gates | Poseidon S-box `x^5` |
| `q_limb7` | foreign-field normalization and multiplication | base-power limb packing |
| `q_limb7_wide` | foreign-field multiplication | double-base pairwise-product packing |
| `LIN7` | foreign-field normalization/multiplication and EC gates | table-backed 7-term linear limb packing |
| `BILIN7_ROW` | foreign-field multiplication and EC gates | one limb times a 7-limb weighted row |
| `BILIN7_PAIRWISE` | foreign-field multiplication and EC gates | 7-by-7 double-base bilinear convolution |

## Failure Modes

The evaluator reverts if:

- calldata length does not equal `QUOTIENT_FRAME_LEN`;
- `y` is zero when selector inverse batching is needed;
- the modular exponentiation precompile used for `y^-1` fails;
- the quotient VM sees an invalid opcode or malformed native callback index;
- a generated arithmetic path explicitly detects an impossible state.

The main verifier reverts if:

- the quotient contract length/codehash is wrong;
- the staticcall fails;
- returned data length is wrong;
- returned magic is wrong.

Invalid proof handling is therefore success-or-revert for this path.

## Trace And Checkpoint Coverage

The IVC trace-equivalence test compares native Rust verifier trace points
against generated Solidity trace logs for the main verifier path. The critical
quotient-facing trace points include:

- `x`;
- `x^n`;
- `(x^n - 1)^-1`;
- `l_last`;
- `l_blind`;
- `l_0`;
- public instance evaluation;
- `linearization_expected_eval`;
- linearization scalars.

The proof evaluation stream is also traced by the main verifier, including the
prover-supplied `q_evals` that are read after `x3`. Those values are compared
against the instrumented Rust verifier like the other proof scalar reads.

There is one important external-evaluator boundary. In the IVC bench the
quotient numerator is reconstructed in `Halo2QuotientEvaluator` via
`STATICCALL`. Because EVM logs are forbidden under `STATICCALL`, the evaluator's
internal quotient identity trace hooks are deliberately logless. The IVC trace
test therefore excludes the per-identity quotient-evaluation trace id range:

```text
30_000..40_000
```

For that external path, trace equivalence still checks the reconstructed scalar
returned to the main verifier:

- trace id `23`: `linearization_expected_eval = -nu_y(x)`;
- trace id `36`: reconstructed numerator `nu_y(x)`;
- trace ids `60_000..61_000`: selector accumulator folds.

Monolithic and non-IVC trace tests do not cross the external `STATICCALL`
boundary, so they require the `30_000..40_000` quotient identity-evaluation
range and compare those internal batched evaluations directly.

The gas-checkpoint bench reports the evaluator work under:

```text
batched identity numerator reconstruction
```

For the gas-capped compact profile that is now the default, the latest recorded
trace/gas-checkpoint run was:

```text
release trace-equivalent total gas: 1,614,572
gas-checkpoint tx gas:             1,594,941
checkpointed section work:         1,432,403
batched numerator section:           631,289
verifier runtime:                    12,885 bytes
VK runtime:                          13,568 bytes
quotient evaluator runtime:          21,774 bytes
```

Defaulting summary:

- gas-checkpoint tx gas: `1,594,941`;
- quotient runtime: `21,774` bytes.

The checkpoint build includes debug logs, so its total gas is not identical to
the non-checkpoint trace-equivalence run. Use it for section deltas and
regression comparison, not as the production gas number.

### Why A Compile-Stable Profile Was Around 700k Gas

A historical `~700k` batched-numerator measurement came from using the smaller
compile-stable compact quotient VM profile instead of the older gas-capped
compact profile.

The old `~631k` run used:

```text
direct inline identities: 4
native gate callbacks:   4
native permutation:      on
native lookup:           on
structured trash suffix: on
```

The compile-stable profile used:

```text
direct inline identities: 0
native gate callbacks:   4
native permutation:      on
native lookup:           on
structured trash suffix: off
remaining identities:    q_program VM
```

That change moved more numerator arithmetic through the interpreted
`q_program` VM. The VM saves bytecode, but every interpreted identity pays
dispatch, stack/memory traffic, and fold-state loads/stores. The measured trade
was:

```text
batched numerator section: 631,289 -> 726,361 gas
quotient evaluator runtime: 21,774 -> 18,385 bytes
```

The non-trace IVC docs recorded the same band:

```text
batched identity numerator reconstruction: 705,271 gas
quotient runtime: 18,318 bytes
```

The change was introduced by `c9b1567 Make verifier variants compile in CI`,
which changed `DEFAULT_HYBRID_QUOTIENT_INLINE_IDENTITIES` from `4` to `0` and
changed the structured trash-tail default from `Trash` to `Off`.

So the `~700k` number was not mainly a proof-shape or fewer-point-sets effect.
It was the bytecode/compile-stability tradeoff. The gas-capped shape can be
selected explicitly with:

```sh
HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=4 \
HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=trash \
scripts/run_ivc_bench.sh --no-outer-fewer-point-sets --skip-srs-download
```

This repository now defaults back to that gas-capped shape; the `0/off` profile
remains useful as the smaller compile-stable fallback if a generated variant
hits pinned-solc size or stack-pressure limits.

## Defaulting Policy

The default is gas-capped compact mode:

```text
direct inline identities: 4
native gate callbacks:   4
native permutation:      on
structured trash suffix: on
remaining identities:    q_program VM
```

This default was selected to keep the IVC quotient-numerator gas near the
previous `~631k` band while staying below the external quotient evaluator size
budget:

- quotient runtime is below `23,500` bytes;
- every deployed runtime is below `24,576` bytes;
- Rust/Solidity trace equivalence passes byte-for-byte.

`HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=N`,
`HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=N`,
`HALO2_SOLIDITY_QUOTIENT_NATIVE_LOOKUP=0|1`, and
`HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=off|trash` remain tuning hooks. If a
variant hits pinned-solc compile pressure, the smaller compile-stable fallback
is:

```text
HALO2_SOLIDITY_HYBRID_QUOTIENT_INLINE_IDENTITIES=0
HALO2_SOLIDITY_QUOTIENT_STRUCTURED_TAIL=off
```

Non-default values must pass the full trace-equivalence test, the variant
compile matrix, and the detailed bench before being treated as safe. For
example, `N=3` produced much smaller bytecode in one trial but failed trace
equivalence, so it is not a valid default.

## Commands

Run the detailed IVC gas bench:

```bash
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
scripts/run_ivc_bench.sh
```

Run the full IVC Rust/Solidity trace-equivalence test:

```bash
SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
HALO2_SOLIDITY_RUN_IVC_BENCH=1 \
cargo test --release \
  --features evm,rust-verifier-trace,truncated-challenges,in-circuit-fewer-point-sets \
  --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
  -- --nocapture
```
