# Halo2 Solidity Verifier — Bug Audit (BLS12-381 Port)

Bugs found in `templates/Halo2Verifier.sol` (and its rendered output under
`generated/`). The focus is on issues that are NEW or were introduced by the
BN254 → BLS12-381 / EIP-2537 port. Some pre-existing items carry over from
the BN254 baseline; they are noted in the final section.

---

## 1. CRITICAL — Random-combine challenge is hashed over the wrong memory range — **FIXED**

> **Status: fixed in `templates/Halo2Verifier.sol`.** The verifier now stages
> `ACC_LHS`, `ACC_RHS`, `PAIRING_LHS`, `PAIRING_RHS` contiguously into
> scratch memory (`0x000..0x200`) before hashing, so the random-combine
> challenge binds to all four points (matches the BN254 reference).

Original bug:

```solidity
if mload(HAS_ACCUMULATOR_MPTR) {
    let h := keccak256(ACC_LHS_MPTR, 0x200) // 4 G1 points = 4*128 = 0x200
    let challenge := mod(h, r)
    ...
}
```

In the upstream BN254 verifier, the challenge that combines the accumulator
with the pairing inputs is bound to **four** G1 points by first copying
them into scratch memory:

```solidity
mstore(0x00, ACC_LHS_X) ... mstore(0x60, ACC_RHS_Y)
mstore(0x80, PAIRING_LHS_X) ... mstore(0xe0, PAIRING_RHS_Y)
let challenge := mod(keccak256(0x00, 0x100), r)
```

The BLS port preserved the *count* (`4*128 = 0x200` matches the size of
four BLS G1 points) but skipped the staging step and now hashes 0x200
contiguous bytes starting at `ACC_LHS_MPTR`. With the actual layout
(`theta_mptr+8` … `theta_mptr+32`) those 16 words are:

| offset (words)        | content                                |
|-----------------------|----------------------------------------|
| theta+8 .. theta+11   | ACC_LHS (4 words)                      |
| theta+12 .. theta+15  | ACC_RHS (4 words)                      |
| theta+16              | X_N                                    |
| theta+17              | X_N_MINUS_1_INV                        |
| theta+18              | L_LAST                                 |
| theta+19              | L_BLIND                                |
| theta+20              | L_0                                    |
| theta+21              | INSTANCE_EVAL                          |
| theta+22              | QUOTIENT_EVAL                          |
| theta+23              | QUOTIENT.x_hi (just the first word!)   |

So the challenge:
- does **not** include `PAIRING_LHS` or `PAIRING_RHS` at all,
- does include unrelated derived state (Lagrange evals, the
  instance/quotient evals) and *part of* the quotient point (only the
  first of its four words).

Consequence (Fiat–Shamir): the challenge `c` used for the random linear
combination
`pairing_lhs += c·acc_lhs ; pairing_rhs += c·acc_rhs`
is no longer a function of all four points being combined. The
Schwartz–Zippel argument that justifies collapsing two pairing equations
into one no longer applies, so a malicious prover that can set up
favorable `(acc_lhs, acc_rhs, pairing_lhs, pairing_rhs)` can cause the
combined check to pass even when one of the two original equations does
not. Combined with bug #4 below (limb decomposition is non-injective)
the prover gains an extra grinding axis.

Fix: stage the four points contiguously in scratch memory before
hashing, exactly like the BN254 reference, and hash 0x200 bytes from
there.

---

## 2. HIGH — `read_g1_point` only zero-checks the upper 16 bytes; never enforces `coord < p` — **FIXED**

> **Status: fixed in `templates/Halo2Verifier.sol`.** `read_g1_point` now
> performs an explicit lexicographic `(hi, lo) < p` comparison against the
> BLS12-381 base-field modulus before mstoring the coordinate into the
> transcript, eliminating the malleability window.

Original bug:

```solidity
ret0 := and(success, iszero(shr(128, x_hi)))
ret0 := and(ret0,    iszero(shr(128, y_hi)))
mstore(hash_mptr,            x_hi)
mstore(add(hash_mptr, 0x20), x_lo)
mstore(add(hash_mptr, 0x40), y_hi)
mstore(add(hash_mptr, 0x60), y_lo)
```

The function rejects encodings whose top 16 bytes are non-zero (good),
but it never checks that `(x_hi · 2^256 + x_lo) < p` or
`(y_hi · 2^256 + y_lo) < p`, where `p` is the BLS12-381 base-field
modulus (≈ 2^381). Since `2p < 2^384`, there is a whole range
`[p, 2p)` of representations that pass the 16-byte zero check, are
accepted into the transcript, but will be rejected by the EIP-2537
precompile later.

Implications:
- The transcript hash is computed **before** any precompile call
  validates the point. The same on-curve point therefore admits two
  distinct encodings inside the running Fiat-Shamir hash, giving a
  malicious prover an extra grinding knob.
- Because the precompile rejects out-of-range coordinates, this is
  malleability rather than a direct soundness break, but it is a clear
  hygiene regression vs. the BN254 original which required
  `lt(x, q) && lt(y, q)` plus the on-curve check.

Fix: implement an explicit `(hi, lo) < p` check (BLS12-381 `p` doesn't
fit in u256, but one comparison branch on `hi` against the upper half
of `p` plus `lt(lo, p_lo_when_hi_eq)` or `lt(hi, p_hi)` covers it). Or,
defensively, also subtract `p` and check overflow.

---

## 3. HIGH — Accumulator limb reconstruction has dead code / impossible conditional — **FIXED**

> **Status: fixed in `templates/Halo2Verifier.sol`.** The convoluted
> `switch and(coord, 1)` block (with its provably-dead
> `if and(eq(coord,1), 0)` branch and empty `coord == 3` case) has been
> replaced with the obvious two-line equivalent:
>
> ```solidity
> dst := add(dst, 0x40)
> if eq(coord, 1) { dst := ACC_RHS_MPTR }
> ```

Original bug:

```solidity
switch and(coord, 1)
case 0 { dst := add(dst, 0x40) }
case 1 {
    if eq(coord, 1) { dst := ACC_RHS_MPTR }
    if eq(coord, 3) { /* done */ }
    if and(eq(coord, 1), 0) { dst := add(dst, 0x40) }   // <-- always false
    if iszero(or(eq(coord, 1), eq(coord, 3))) { dst := add(dst, 0x40) }
}
```

Tracing through `coord ∈ {0,1,2,3}` the function happens to land in
the right place, but the block contains:
- `if and(eq(coord, 1), 0)` — the `, 0` makes this provably dead.
- `if eq(coord, 3) { /* done */ }` — empty body that looks intentional
  but is just a comment.
- `if iszero(or(eq(coord,1), eq(coord,3)))` — for `coord ∈ {0,2}`
  this code is unreachable because `and(coord,1) == 0` already routed
  those into `case 0`.

This is not currently a soundness bug, but the asymmetric, redundant
structure is exactly the kind of thing that breaks under a small
refactor (e.g. someone widens `coord` to support more points). Replace
it with the obvious equivalent:

```solidity
dst := add(dst, 0x40)
if eq(coord, 1) { dst := ACC_RHS_MPTR }
```

---

## 4. MEDIUM — Limb decomposition still uses native `add`/`shl` (BLS port preserved the BN254 footgun)

```solidity
let in_lo := shl(shift, limb)
...
lo := add(lo, in_lo)              // mod 2^256, not mod p
hi := add(hi, carry_to_hi)
...
success := and(success, lt(limb, shl(num_limb_bits, 1)))
success := and(success, iszero(shr(128, hi)))
```

Each limb is constrained to `< 2^num_limb_bits`, but the addition is
modular over `2^256`, never over `p`. With realistic params
(`num_limbs=4, num_limb_bits=68`) that's ≤ 272 effective bits packed
into the (hi, lo) pair, so wrap-around inside `lo` is rare but
possible, and the function does not enforce `(hi * 2^256 + lo) < p`.
As a result distinct limb tuples can decode to either:
- the same on-curve point (because the precompile reduces mod p
  later), or
- a point that would be rejected by the precompile.

In both cases the *limbs themselves* enter the public-instance hash
earlier in the verifier, so a prover has multiple equivalent limb
tuples to choose from when grinding favorable challenges.

Fix: enforce `lt(hi, P_HI) || (eq(hi, P_HI) && lt(lo, P_LO))` once the
limbs are summed, where `(P_HI, P_LO)` is the BLS12-381 base-field
modulus split into hi/lo.

---

## 5. MEDIUM — `batch_invert` reads/writes one slot past the end when the range has size 1 (carried over from BN254)

```solidity
let mptr := add(mptr_start, 0x20)
for {} lt(mptr, sub(mptr_end, 0x20)) {} { ... }
gp := mulmod(gp, mload(mptr), r)         // mptr == mptr_end when size==1
...
let inv_first  := mulmod(all_inv, mload(second_mptr), r)
let inv_second := mulmod(all_inv, mload(first_mptr), r)
mstore(first_mptr, inv_first)
mstore(second_mptr, inv_second)          // also out-of-range when size==1
```

When `mptr_end == mptr_start + 0x20` (one element), `mptr` already
equals `mptr_end` before the post-loop `mulmod`, so the verifier
reads/writes one word past the declared range and the returned inverse
is garbage. The path is reached when the batch-opening grouping yields
`sets.len() == 1`. Same issue in the upstream; the BLS port did not
fix it.

---

## 6. LOW — `pop(y)`, `pop(delta)` are cosmetic; same for the dropped `pop(q)`

```solidity
pop(y)
pop(delta)
```

`pop` only discards a Yul stack slot — it does not zero memory. These
look like defensive scrubs but are no-ops. Carried over from BN254.

---

## 7. LOW — `squeeze_challenge_cont` leaves a stale `0x01` byte at memory offset 0x20

```solidity
mstore8(0x20, 0x01)
let hash := keccak256(0x00, 0x21)
mstore(challenge_mptr, mod(hash, r))
mstore(0x00, hash)             // 0x20 still has 0x01 here
```

Currently safe because the very next transcript write either calls
`squeeze_challenge_cont` again (which rewrites 0x20) or
`read_g1_point` with `hash_mptr = 0x20` (which overwrites it as
`x_hi`). But it's a fragile invariant — anything that calls
`squeeze_challenge_cont` and then peeks at `0x20` without first
mstore'ing will silently see `0x01` in the high byte. Defensively,
write `mstore(0x20, 0)` after the keccak.

---

## 8. LOW — Trace mode flips `verifyProof` from `view` to non-view and emits intermediate state via LOG1

```solidity
function verifyProof(...) public {%- if self.trace %} returns (bool) {%- else %} view returns (bool) {%- endif %}
```

`render_trace_separately` keeps `success := …` paths going past
failures and emits everything via `log1` (vk digest, all transcript
challenges, `INSTANCE_EVAL`, `QUOTIENT_EVAL`, plus the four key G1
points). Nothing is secret, but if a deployer ships the trace template
by mistake they pay extra gas on every call and break the `view`
contract for callers that depend on it. Fence the trace API behind a
clearly-named `unsafe_*` constructor or `cfg(test)` equivalent in
codegen.

---

## Pre-existing items still applicable

The original BN254 audit issue (caller-controlled `vk` in the legacy
`generated/Halo2Verifier-*.sol`) is addressed in the new template via
`AUTHORIZED_VK` + `EXPECTED_VK_CODEHASH`, but it is still present in
any *previously* deployed instances of the legacy artifact.

The lack of an explicit G2 subgroup check on VK-supplied curve points
is also still unfixed — the BLS port relies entirely on EIP-2537 to
validate G2, and EIP-2537 only checks subgroup for the precompile
inputs at call time, not for VK constants stored once in code. If the
deployment pipeline lets an attacker influence the VK bytes (and the
`EXPECTED_VK_CODEHASH` is the only barrier), a non-subgroup G2 element
can still bypass the pairing.

---

## TL;DR of the **new** BLS-specific bugs

1. `keccak256(ACC_LHS_MPTR, 0x200)` hashes the wrong memory —
   `PAIRING_LHS/RHS` are no longer in the random-combine challenge.
2. `read_g1_point` does not enforce `coord < p`, only that the top 16
   bytes of the high word are zero — Fiat-Shamir malleability.
3. The accumulator coordinate switch contains dead/redundant branches;
   one `if and(..., 0)` is provably never true.

Items 4–8 are pre-existing BN254 issues that were preserved in the
port.
