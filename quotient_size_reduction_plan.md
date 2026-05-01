# Quotient Size Reduction Plan

Yes - the main issue is that the Rust implementation is an iterator over
identity expressions, while the Yul is an expression compiler that emitted the
whole AST as bytecode. The Rust function `partially_evaluate_identities`
evaluates gates, then chains permutation, lookup, and trash expressions into a
vector of `(Option<selector>, F)` results; simple selectors remain partially
linearized, while `None` identities are fully accumulated. ([GitHub][1])

For contract size, optimize in this order.

## 1. Centralize the y-batching step

This repeated block is everywhere:

```yul
quotient_eval_numer := mulmod(quotient_eval_numer, y, r)
q_sel_scale := mulmod(q_sel_scale, y, r)
q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)
...
```

Make every identity call one shared absorber:

```yul
// Put these in scratch memory, not outer Yul locals, so the function
// does not need many parameters.
let QN_PTR := 0x7f00
let QSCALE_PTR := 0x7f20
let QISCALE_PTR := 0x7f40
let QYINV_PTR := 0x7f60

mstore(QN_PTR, 0)
mstore(QSCALE_PTR, 1)
mstore(QISCALE_PTR, 1)
mstore(QYINV_PTR, q_y_inv)

function absorb_identity(eval, selector_off, r, y, selector_acc_ptr, qn_ptr, qscale_ptr, qis_ptr, qyinv_ptr) {
    let qn := mulmod(mload(qn_ptr), y, r)
    let qscale := mulmod(mload(qscale_ptr), y, r)
    let qis := mulmod(mload(qis_ptr), mload(qyinv_ptr), r)

    mstore(qn_ptr, qn)
    mstore(qscale_ptr, qscale)
    mstore(qis_ptr, qis)

    // selector_off == not(0) means fully evaluated / None selector
    switch eq(selector_off, not(0))
    case 1 {
        mstore(qn_ptr, addmod(qn, eval, r))
    }
    default {
        let p := add(selector_acc_ptr, selector_off)
        mstore(p, addmod(mload(p), mulmod(eval, qis, r), r))
    }
}
```

Then each identity becomes:

```yul
absorb_identity(eval, 0x80, r, y, SELECTOR_ACC_MPTR, QN_PTR, QSCALE_PTR, QISCALE_PTR, QYINV_PTR)
```

or for fully evaluated identities:

```yul
absorb_identity(eval, not(0), r, y, SELECTOR_ACC_MPTR, QN_PTR, QSCALE_PTR, QISCALE_PTR, QYINV_PTR)
```

This removes a large amount of repeated bytecode and makes the code match the
Rust shape: "compute an eval, then batch it".

Also loop these:

```yul
for { let off := 0 } lt(off, 0x140) { off := add(off, 0x20) } {
    mstore(add(SELECTOR_ACC_MPTR, off), 0)
}
...
let final_scale := mload(QSCALE_PTR)
for { let off := 0 } lt(off, 0x140) { off := add(off, 0x20) } {
    mstore(add(SELECTOR_ACC_MPTR, off), mulmod(mload(add(SELECTOR_ACC_MPTR, off)), final_scale, r))
}
```

## 2. Do not emit every gate polynomial as code

The huge blocks like the 7-limb / wide 7-limb arithmetic are the real bytecode
killer. They should become data plus a small evaluator.

You have many repeated shapes:

```yul
q_limb7(a_0, ..., a_6)
q_limb7_wide(a_0, ..., a_6)
sum coeff[i][j] * lhs[i] * rhs[j]
sum coeff[i] * pow5(a[i])
```

These should be generated as compact term tables, not unrolled code.

For example, replace this style:

```yul
let var48 := mulmod(a_2, a_0_next_1, r)
let var49 := mulmod(var6, var48, r)
let var50 := addmod(var47, var49, r)
...
```

with a generic bilinear evaluator:

```yul
function eval_bilinear7(lhs_ptr, rhs_ptr, coeff_ptr, r) -> acc {
    acc := 0

    for { let i := 0 } lt(i, 7) { i := add(i, 1) } {
        let li := mload(add(lhs_ptr, shl(5, i)))

        for { let j := 0 } lt(j, 7) { j := add(j, 1) } {
            let coeff := mload(add(coeff_ptr, shl(5, add(mul(i, 7), j))))
            let rj := mload(add(rhs_ptr, shl(5, j)))
            acc := addmod(acc, mulmod(coeff, mulmod(li, rj, r), r), r)
        }
    }
}
```

You can then have two coefficient tables:

```text
LIMB7_MUL_COEFFS
LIMB7_WIDE_MUL_COEFFS
```

and reuse the same evaluator for all those 200+ line blocks.

This is probably the biggest win.

## 3. Encode custom gates as a small instruction stream

For maximum size reduction, generate something closer to an interpreter:

```text
IDENTITY {
  selector_offset: 0x80,
  terms: [
    CONST * A0 * A0_NEXT,
    CONST * A0 * A1_NEXT,
    ...
    CONST,
    -A7_NEXT * CONST,
    ...
  ]
}
```

Then one Yul evaluator handles sparse products:

```yul
function eval_terms(ptr, end, r) -> acc {
    acc := 0

    for { } lt(ptr, end) { } {
        let coeff := mload(ptr)
        ptr := add(ptr, 0x20)

        let n_factors := mload(ptr)
        ptr := add(ptr, 0x20)

        let term := coeff
        for { let k := 0 } lt(k, n_factors) { k := add(k, 1) } {
            let value_ptr := mload(ptr)
            ptr := add(ptr, 0x20)
            term := mulmod(term, mload(value_ptr), r)
        }

        acc := addmod(acc, term, r)
    }
}
```

Then the generated code per identity is just:

```yul
let eval := eval_terms(TABLE_PTR, TABLE_END, r)
absorb_identity(eval, 0x80, r, y, SELECTOR_ACC_MPTR, QN_PTR, QSCALE_PTR, QISCALE_PTR, QYINV_PTR)
```

This trades gas for size, but for a verifier near EIP-170, it is the right
trade. EIP-170 rejects creation if the returned contract code is larger than
`MAX_CODE_SIZE = 0x6000`, i.e. 24,576 bytes. ([Ethereum Improvement
Proposals][2])

## 4. Move constants into tables, preferably not duplicated as PUSH32

Every unique `PUSH32` costs about 33 bytes before surrounding opcodes. Your code
repeats many large constants across narrow/wide/current/next/prev variants.

Options:

### Same contract, compact table

Use one table copied into memory once:

```yul
codecopy(CONST_TABLE_PTR, dataoffset("constants"), datasize("constants"))
```

This still counts toward runtime bytecode if the data is in the deployed code,
but it removes duplication.

### External constants contract

Put large coefficient tables in a separate deployed blob / constants contract
and load with `EXTCODECOPY`. This reduces the main verifier's runtime size at
the cost of extra gas and an extra deployment dependency.

### External libraries

If you split evaluators into external libraries, their code is separate from the
verifier's EIP-170 limit. Be careful: internal library functions are normally
compiled into the caller, but linked external libraries remain separate.
Solidity's compiler docs describe library placeholders/linking for separate
library bytecode. ([docs.soliditylang.org][3])

## 5. Loop the permutation packing too

This part:

```yul
mstore(add(q_perm_vals, 0x0), mload(0x5e00))
mstore(add(q_perm_sigmas, 0x0), mload(0x6020))
...
```

should be table-driven:

```yul
let val_srcs := 0x8000
let sig_srcs := 0x8240

// Fill val_srcs/sig_srcs once using codecopy/table,
// then:
for { let i := 0 } lt(i, 18) { i := add(i, 1) } {
    let off := shl(5, i)
    mstore(add(q_perm_vals, off), mload(mload(add(val_srcs, off))))
    mstore(add(q_perm_sigmas, off), mload(mload(add(sig_srcs, off))))
}
```

The nested permutation product loops are already close to the right form. The
packing before them is still too unrolled.

## 6. Trash block: convert to matrix-vector + Horner

The trash block is a perfect candidate:

```text
row_0 = f0 + c00*a0 + c01*a1 + c02*pow5(a2) + ...
row_1 = f1 + c10*a0 + c11*a1 + c12*pow5(a2) + ...
...
batched = (((row0 * tau + row1) * tau + row2) ...)
```

Precompute:

```yul
mstore(pow_ptr + 0x00, q_pow5(a_2))
mstore(pow_ptr + 0x20, q_pow5(a_3))
...
```

Then:

```yul
function eval_trash_rows(row_coeffs, base_terms, rows, cols, tau, r) -> acc {
    acc := 0

    for { let row := 0 } lt(row, rows) { row := add(row, 1) } {
        let row_eval := 0

        for { let col := 0 } lt(col, cols) { col := add(col, 1) } {
            let coeff := mload(add(row_coeffs, shl(5, add(mul(row, cols), col))))
            let val := mload(add(base_terms, shl(5, col)))
            row_eval := addmod(row_eval, mulmod(coeff, val, r), r)
        }

        acc := addmod(mulmod(acc, tau, r), row_eval, r)
    }
}
```

This replaces hundreds of lines of constants and repeated `mulmod/addmod`.

## 7. Compiler settings: optimize for size, not runtime

Use low optimizer runs:

```json
{
  "optimizer": {
    "enabled": true,
    "runs": 1
  },
  "evmVersion": "shanghai"
}
```

Solidity's docs explicitly describe `--optimize-runs=1` as producing shorter
but more expensive code, while higher runs produce longer but more gas-efficient
code. ([docs.solidity.org][4])

Also compile for at least `shanghai` if your target chain supports it, because
`PUSH0` can reduce code size and gas. The Solidity docs note smaller code size
and gas savings from `push0` in the Shanghai target. ([docs.soliditylang.org][3])

One warning: the optimizer can inline functions. Solidity's Yul optimizer
includes function inlining, and its docs note that inlining can increase code
size in many cases. ([docs.solidity.org][4]) So after introducing helpers like
`absorb_identity`, check the optimized IR/bytecode. If the helper is inlined
back into every identity, either lower runs further, make it less attractive to
inline, or customize the Yul optimization sequence.

## Recommended target structure

Refactor the generated Solidity/Yul into this pipeline:

```text
1. Load all evaluations into memory arrays:
   advice_cur, advice_next, advice_prev, fixed, instance, permutation, lookup, trash

2. Initialize:
   quotient_eval_numer = 0
   selector_acc[0..9] = 0
   q_sel_scale = 1
   q_sel_inv_scale = 1
   q_y_inv = y^-1

3. For each gate identity:
   eval = eval_terms(...) or eval_bilinear7(...)
   absorb_identity(eval, selector_offset)

4. Permutation:
   existing loops, but table-drive the packing

5. Lookup:
   keep loops, simplify length-1 cases manually

6. Trash:
   matrix-vector evaluator + Horner in tau

7. Final:
   scale selector_acc by q_sel_scale
   QUOTIENT_EVAL_MPTR = -quotient_eval_numer
```

The most important change is: stop generating arithmetic expressions as Yul
statements. Generate a compact table/instruction stream and a few reusable
evaluators. That is the Solidity equivalent of the Rust iterator design, and it
is the route that will materially reduce deployed bytecode.

[1]: https://raw.githubusercontent.com/EYBlockchain/midfall/f6feca8b33fa62798905d668961a35f9736302d2/proofs/src/plonk/mod.rs "raw.githubusercontent.com"
[2]: https://eips.ethereum.org/EIPS/eip-170 "EIP-170: Contract code size limit"
[3]: https://docs.soliditylang.org/en/latest/using-the-compiler.html?highlight=optimize-runs "Using the Compiler - Solidity 0.8.36-develop documentation"
[4]: https://docs.solidity.org/en/latest/internals/optimizer.html "The Optimizer - Solidity 0.8.36-develop documentation"
