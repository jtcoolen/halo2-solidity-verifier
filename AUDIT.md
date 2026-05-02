# CTF Vulnerability Analysis: Halo2 Solidity Verifier

## 2026-05-01 audit pass: current split BLS12-381 verifier generator

Scope: current Halo2/Midnight Solidity verifier generator, especially:

- `templates/Halo2Verifier.sol`
- `templates/Halo2QuotientEvaluator.sol`
- `src/codegen.rs`
- `src/codegen/pcs/gwc19.rs`
- `src/transcript.rs`

This pass focuses on verifier soundness, fail-closed behavior, transcript
equivalence, deployment binding, and proof-input canonicality.

### Findings overview

| ID | Severity | Title |
| --- | --- | --- |
| C-1 | High | Verifier can be deployed with an arbitrary quotient evaluator |
| C-2 | High | Missing precompile-existence and return-size checks can fail open on wrong chains |
| C-3 | Medium | Not all proof G1 commitments are validated at parse time |
| C-4 | Medium | Rust transcript reader/writer are asymmetric for G1 |
| C-5 | Low/Medium | Denominator-zero cases silently compute inverse as zero |
| C-6 | Informational | Add an end-of-proof cursor check |

### C-1. Verifier can be deployed with an arbitrary quotient evaluator

Severity: High.

The verifier pins the VK by expected length and codehash, but the external
quotient evaluator is only checked as non-empty code at construction time. The
constructor then stores whatever `authorizedQuotient.codehash` was passed in and
trusts that contract forever.

Relevant code:

- `templates/Halo2Verifier.sol`: `AUTHORIZED_QUOTIENT`
- `templates/Halo2Verifier.sol`: quotient constructor branches
- `templates/Halo2Verifier.sol`: external quotient call in the batched identity
  numerator reconstruction block
- `templates/Halo2QuotientEvaluator.sol`: expected fallback return frame

The quotient evaluator returns:

```text
word 0: magic/version
word 1: linearization expected eval
word 2..: simple-selector accumulators
```

The verifier checks only the magic word and then stores the returned
linearization scalar and selector accumulators:

```yul
if iszero(staticcall(... quotientEvaluator ...)) { revert(0, 0) }
if iszero(eq(mload(q_out), QUOTIENT_MAGIC)) { revert(0, 0) }
mstore(QUOTIENT_EVAL_MPTR, mload(add(q_out, 0x20)))
```

Impact:

- A malicious deployment can wire a quotient evaluator that returns
  attacker-chosen linearization values.
- That effectively removes or rewrites the algebraic constraint check enforced
  by the quotient numerator block.
- This is not caller-exploitable after an honest deployment, but it is a serious
  deployment-integrity footgun for factories, registries, copied deployment
  scripts, and third-party verifier addresses.

Recommendation:

- Generate and hard-code `EXPECTED_QUOTIENT_CODEHASH`, mirroring
  `EXPECTED_VK_CODEHASH`.
- Optionally also hard-code `EXPECTED_QUOTIENT_LENGTH`.
- Include both VK and quotient evaluator hashes in deployment artifacts.
- Add a deployment test that rejects a quotient evaluator with the same ABI but
  different runtime bytecode.

### C-2. Missing precompile-existence and return-size checks can fail open on wrong chains

Severity: High.

The verifier assumes the EIP-2537 BLS12-381 precompiles exist at:

```text
0x0b BLS12_G1ADD
0x0c BLS12_G1MSM
0x0f BLS12_PAIRING_CHECK
```

Most helper paths check only the `staticcall` success bit. A call to a
non-existent address can succeed with empty returndata and leave the output
memory unchanged. The code then consumes whatever was already in that memory
slot.

Relevant code:

- `templates/Halo2Verifier.sol`: `ec_add_acc`
- `templates/Halo2Verifier.sol`: `ec_mul_acc`
- `templates/Halo2Verifier.sol`: `ec_add_tmp`
- `templates/Halo2Verifier.sol`: `ec_mul_tmp`
- `templates/Halo2Verifier.sol`: `ec_pairing`
- `src/codegen/pcs/gwc19.rs`: generated final MSM and pairing-input calls

Impact:

- On chains or local forks without EIP-2537 at those exact addresses, invalid
  proofs may be accepted.
- This is catastrophic for wrong-chain deployment and dangerous for test
  environments that do not faithfully model the precompiles.

Recommendation:

- After every precompile call, require the exact expected `returndatasize()`:
  - `0x80` for G1 point outputs,
  - `0x20` for pairing/modexp scalar outputs.
- Add a constructor or first-call self-test for G1ADD, G1MSM, and PAIRING.
- Fail closed if any precompile behavior differs from the expected EIP-2537
  semantics.

### C-3. Not all proof G1 commitments are validated at parse time

Severity: Medium.

Proof G1 commitments are absorbed into the transcript and copied from calldata
directly. They are validated only if they later participate in an EIP-2537
precompile call.

Relevant code:

- `templates/Halo2Verifier.sol`: `common_uncompressed_g1`
- `templates/Halo2Verifier.sol`: proof commitment read loops
- `src/codegen/pcs/gwc19.rs`: query construction and final MSM staging

The query builder includes advice commitments only when they appear in the
verifier query list. A circuit with a committed column that is transcript-
absorbed but never queried could allow invalid G1 bytes to influence the
Fiat-Shamir transcript without ever being rejected by a precompile.

Impact:

- Generated verifiers can accept transcripts the native verifier would reject.
- For dead commitments this is mostly a challenge-grinding or verifier-
  equivalence issue, but the invariant is fragile as circuits and query sets
  change.

Recommendation:

- Validate every proof G1 as it is read, or prove/enforce at codegen time that
  every absorbed G1 is later validated by a precompile.
- Reject non-zero EIP-2537 padding bytes rather than only masking them before
  hashing.
- Add negative tests with unused malformed commitments for circuits that contain
  unqueried committed columns.

### C-4. Rust transcript reader/writer are asymmetric for G1

Severity: Medium.

The Rust helper transcript writes G1 points by absorbing the EIP-2537 padded
128-byte uncompressed form:

```rust
pub fn write_g1(&mut self, point: &G1Projective) -> io::Result<()> {
    self.common_g1(point)?;
    let repr = point.to_bytes();
    self.stream.write_all(repr.as_ref())
}
```

But `read_g1` absorbs the raw compressed bytes before decompressing:

```rust
self.absorb_bytes(bytes.as_ref());
G1Projective::from_bytes(&bytes)
```

Relevant code:

- `src/transcript.rs`: `common_g1`
- `src/transcript.rs`: `read_g1`
- `src/transcript.rs`: `write_g1`

Impact:

- Rust-side proof generation and Rust-side verification can diverge when this
  transcript is used for both.
- Trace comparison or fixture tooling may certify a different Fiat-Shamir
  transcript than the Solidity verifier.
- This directly contradicts the file-level transcript spec, which says G1
  input is the 128-byte EIP-2537 padded uncompressed form.

Recommendation:

- In `read_g1`, read and decompress the compressed point first, then call
  `common_g1(&point)`.
- Add a round-trip test that `write_g1` and `read_g1` produce the same
  transcript state for a non-identity point and for the identity point.

### C-5. Denominator-zero cases silently compute inverse as zero

Severity: Low/Medium.

Several verifier paths call `scalar_inv` on values that are expected to be
non-zero by Fiat-Shamir. If the denominator is zero, the modexp-based inverse
returns zero and the verifier continues with bogus arithmetic.

Relevant code:

- `templates/Halo2Verifier.sol`: `scalar_inv`
- `templates/Halo2Verifier.sol`: Lagrange batch inversion around
  `x_n_minus_1`
- `src/codegen/pcs/gwc19.rs`: PCS interpolation at `x3`

Examples:

- `x^n - 1 = 0` in the Lagrange/instance evaluation block.
- `x3 = rotation_point` in PCS interpolation.

Impact:

- The event is Fiat-Shamir-negligible under the configured challenge sampling,
  but continuing after a zero denominator makes the soundness error implicit
  and harder to reason about.

Recommendation:

- Explicitly reject zero denominators before inversion.
- Treat this as defensive hardening with tiny gas cost compared to the proof.

### C-6. Add an end-of-proof cursor check

Severity: Informational.

The ABI length checks make this likely redundant today, but the verifier should
assert the transcript parser consumed exactly the expected proof bytes.

Relevant code:

- `templates/Halo2Verifier.sol`: proof length check
- `templates/Halo2Verifier.sol`: transcript proof cursor after `pi`

Recommendation:

- After reading `pi`, assert:

```yul
success := and(success, eq(proof_cptr, NUM_INSTANCE_CPTR))
```

This catches future proof-layout drift cheaply and makes the raw calldata parser
less brittle.

### Recommended fix priority

1. Pin the quotient evaluator by generated codehash and length.
2. Add `returndatasize()` checks and precompile self-tests.
3. Fix `read_g1` transcript absorption to match `write_g1` and Solidity.
4. Validate every absorbed proof G1 or enforce that every absorbed G1 is later
   precompile-validated.
5. Reject zero inversion denominators.
6. Add the end-of-proof cursor check.

---

## 2026-04-30 audit addendum: current Halo2 BLS12-381 Solidity/Yul verifier

Scope: `templates/Halo2Verifier.sol`, `src/codegen.rs`, and the compact quotient
interpreter generated for the current IVC verifier branch.

This pass focuses on verifier soundness, fail-closed behavior, proof/call-data
canonicality, and deployment risks in the generated Solidity/Yul verifier.

### Findings overview

| ID | Severity | Title |
| --- | --- | --- |
| A-1 | Medium/High | EIP-2537 precompile calls can fail open on unsupported or mismatched chains |
| A-2 | Medium | Non-canonical G1 encodings are transcript-normalized instead of rejected |
| A-3 | Low/Medium | `verifyProof(bytes,uint256[])` hand-parses calldata but does not enforce canonical ABI offsets |
| A-4 | Low | Compact quotient VM is correctness-critical and needs differential tests |
| A-5 | Informational | Current verifier remains over the 24KB EIP-170 runtime limit |

### A-1. EIP-2537 precompile calls can fail open on unsupported or mismatched chains

Severity: Medium/High, depending on deployment target.

The verifier assumes the BLS12-381 precompiles at `0x0b`, `0x0c`, and `0x0f`
exist and implement the expected EIP-2537 semantics. The helper functions only
use the `staticcall` success bit, and `ec_pairing` additionally reads
`mload(scratch)` without checking that the call returned exactly one word.

Relevant code:

- `templates/Halo2Verifier.sol`: `ec_add_acc`, `ec_mul_acc`, `ec_add_tmp`,
  `ec_mul_tmp`
- `templates/Halo2Verifier.sol`: `ec_pairing`
- `templates/Halo2Verifier.sol`: public accumulator MSM calls
- `templates/Halo2Verifier.sol`: final proof pairing check

On a chain where those precompiles are absent or incompatible, a call to an
empty account can return success with zero return data. In that case output
memory may contain stale values. The pairing helper is especially sensitive:

```yul
ret := staticcall(gas(), 0x0f, pairing_input_mptr, 0x240, scratch, 0x20)
ret := and(ret, mload(scratch))
```

If the precompile is absent, `ret` may be true and `mload(scratch)` is not a
trusted pairing result.

Impact:

- Invalid proofs may be accepted on an unsupported or mismatched EVM fork.
- The verifier does not fail closed when its required cryptographic precompiles
  are unavailable.

Recommendation:

- After every precompile call, require the exact expected `returndatasize()`.
- Require `0x80` bytes for G1 add/MSM-style point outputs.
- Require `0x20` bytes for pairing and scalar inversion/modexp-style outputs.
- Add a constructor self-test that rejects deployment if the target chain does
  not implement the expected BLS12-381 precompile semantics.

### A-2. Non-canonical G1 encodings are transcript-normalized instead of rejected

Severity: Medium.

`common_uncompressed_g1` copies 128 bytes from calldata, masks the high 16 bytes
of `x_hi` and `y_hi` before transcript absorption, but does not reject nonzero
padding.

Relevant code:

- `templates/Halo2Verifier.sol`: `common_uncompressed_g1`
- `templates/Halo2Verifier.sol`: proof commitment reads that call
  `read_g1_point`

This creates proof malleability: multiple calldata encodings can hash to the
same transcript point. The current design is only safe if every absorbed point
is later validated by an EIP-2537 precompile in a way that rejects the original
non-canonical bytes. That invariant is fragile for generated verifiers because a
commitment can become unused, zero-weighted, or protocol-dependent.

Impact:

- Non-canonical proofs can be accepted.
- Callers that commit to calldata or proof bytes may observe multiple encodings
  of the same transcript.
- Future circuits or codegen changes can accidentally absorb a malformed point
  that is never validated by a precompile.

Recommendation:

- Reject nonzero padding in `x_hi` and `y_hi` at transcript read time.
- Reject coordinates outside the BLS12-381 base field before absorption.
- Prefer validating every absorbed G1 point independently of whether it later
  appears in an MSM.

### A-3. `verifyProof(bytes,uint256[])` hand-parses calldata but does not enforce canonical ABI offsets

Severity: Low/Medium.

The public Solidity signature uses dynamic ABI arguments:

```solidity
function verifyProof(bytes calldata proof, uint256[] calldata instances)
    public
    view
    returns (bool)
```

The assembly body ignores Solidity's decoded `proof` and `instances` offsets
and instead reads fixed calldata locations such as `PROOF_LEN_CPTR`,
`PROOF_CPTR`, and `INSTANCE_CPTR`. The verifier checks the assumed proof length,
instance count, and total `calldatasize()`, but does not check that the ABI head
offsets actually point to those locations.

Relevant code:

- `templates/Halo2Verifier.sol`: `verifyProof` signature
- `templates/Halo2Verifier.sol`: proof length, instance count, and calldata size
  checks

This is probably not a direct soundness break because the verifier consistently
uses its raw calldata layout. It is still calldata malleability and can surprise
wrappers, calldata hash commitments, relayers, and off-chain tooling that expect
canonical ABI encoding.

Recommendation:

- Either use `proof.offset`, `proof.length`, `instances.offset`, and
  `instances.length` directly in assembly.
- Or explicitly assert that the ABI head offsets match the expected canonical
  layout before parsing proof bytes.

### A-4. Compact quotient VM is correctness-critical and needs differential tests

Severity: Low.

The compact quotient identity interpreter introduces a generated bytecode
program plus a Yul VM. The program is not user-controlled, so this is not an
injection issue. However, a compiler or optimizer bug in this layer can silently
change the quotient identity that the verifier checks.

Relevant code:

- `src/codegen.rs`: compact quotient opcode definitions
- `src/codegen.rs`: identity expression parser and program builder
- `templates/Halo2Verifier.sol`: quotient VM dispatch loop

Recommended tests:

- Render both the old straight-line quotient evaluator and the compact VM for
  the same circuit, then assert identical quotient values.
- Fuzz identity expression trees against the VM lowering.
- Include gates, simple selectors, lookups, permutations, constants, rotations,
  trash challenges, and zero-term edge cases.
- Keep a debug render mode that can emit both implementations for differential
  testing.

### A-5. Current verifier remains over the 24KB EIP-170 runtime limit

Severity: Informational.

The latest IVC architecture notes report:

- verifier runtime: approximately 25,598 bytes
- EIP-170 limit: 24,576 bytes

Relevant code/documentation:

- `ARCHITECTURE.md`: compact quotient VM results and remaining size budget

This is not a proof-soundness issue, but it is a deployment blocker on
mainnet-like chains that enforce EIP-170 unless the verifier is split further or
the target chain disables/raises the contract size limit.

### Open questions

- Is the deployment target guaranteed to support the exact EIP-2537 precompile
  addresses and return semantics used by this verifier?
- Is calldata uniqueness important for the consuming protocol?
- Are proof bytes or calldata hashes committed elsewhere by relayers, bridges,
  settlement contracts, or off-chain indexers?
- Should the generated verifier be treated as a generic Halo2 verifier, or as a
  Midnight/Midfall-specific verifier with a fixed transcript, accumulator
  encoding, and proof layout?

---

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


   Halo2 BLS12-381 Solidity Verifier - Security Audit (informal)

   Scope: src/codegen.rs, src/codegen/{template.rs, util.rs, pcs.rs, pcs/gwc19.rs, evaluator.rs}, src/transcript.rs, src/evm.rs, templates/Halo2Verifier.sol, 
   templates/Halo2VerifyingKey.sol, generated/Halo2Verifier-*.sol.
   Curve: BLS12-381 via EIP-2537 precompiles (0x0b / 0x0c / 0x0f).
   Out of scope: halo2 prover correctness (vendored vendor/halo2/), revm/Prague EVM precompile implementations, the underlying KZG security assumption.

   ──────────────────────────────────────────

   1. Findings overview

   ID   │ Severity      │ Title                                                                                                                                                
   -----+---------------+------------------------------------------------------------------------------------------------------------------------------------------------------
   F-1  │ **Critical**  │ `static_working_memory_size` keeps the BN254 stride (`n*2+1`); the keccak buffer can overwrite challenges/VK at runtime
   F-2  │ High          │ Fiat-Shamir desynchronisation when a phase has zero advice columns (Yul does not append the trailing `0x01`)
   F-3  │ High          │ `read_g1_point` hashes attacker-controlled raw bytes into the transcript even when the EIP-2537 padding check fails
   F-4  │ Medium        │ Accumulator reconstruction relies on `add` / `shl` (not `addmod`) and on contract-side limb checks, with a misleading dead branch
   F-5  │ Medium        │ `g1_to_u256s` / `g2_to_u256s` `unwrap()` on the point-at-infinity, panicking VK generation
   F-6  │ Medium        │ `delta` is a hard-coded scalar with no compile-time agreement check against `bls12381::Fr::DELTA`
   F-7  │ Low           │ Trace-mode verifier silently returns `bool` instead of reverting and is no longer `view`; deploying it in production breaks callers using `try/catch`
   F-8  │ Low           │ `pop(y)` / `pop(delta)` are cosmetic and do not clear memory
   F-9  │ Low           │ `if mload(HAS_ACCUMULATOR_MPTR)` is read from VK but it is not cross-checked against the codegen-side `acc_encoding`
   I-10 │ Informational │ Generator forces `vk.cs().num_instance_columns() <= 1` and `Rotation::cur()` only - silent "not yet implemented" panics if violated
   I-11 │ Informational │ `n_inv` and `omega_inv_to_l` are never re-derived from `k`/`omega` on chain - a malicious VK that bypasses the codehash pin can lie
   I-12 │ Informational │ `mod(hash, r)` introduces ~2^-255 bias; standard practice, kept for completeness

   The mitigations that have already landed (in particular the AUTHORIZED_VK + EXPECTED_VK_CODEHASH pinning at constructor time, commit 54b2943) close the original 
   "caller-controlled VK" hole from AUDIT.md finding #1, and the EIP-2537 pairing precompile transitively covers G2 subgroup checks (BN254 audit finding #2).

   ──────────────────────────────────────────

   2. Critical: keccak buffer overruns on wide circuits

   F-1 - `static_working_memory_size` keeps BN254 stride

   Location: src/codegen.rs::SolidityGenerator::static_working_memory_size, around the // Keccak256 input (can overwrite vk) block.

   rust
     itertools::max([
         // Keccak256 input (can overwrite vk)
         itertools::max(chain![
             self.meta.num_advices().into_iter().map(|n| n * 2 + 1),   // <-- BN254 stride
             [self.meta.num_evals + 1],
         ])
         .unwrap()
         .saturating_sub(vk.len() / 0x20),
         // PCS computation
         pcs_computation,
         // Pairing: 2 G1 points (4 words each) + 2 G2 points (8 words each) = 24 + 1 buf
         25,
     ])
     .unwrap()
     * 0x20

   After the BLS port a single G1 commitment occupies 4 EVM words, not 2 (cf. EcPoint::range in src/codegen/util.rs and read_g1_point in templates/Halo2Verifier.sol). The keccak 
   input that the verifier accumulates between two squeezes therefore needs

     phase_words = num_advices_phase * 4 + 1   (one extra word for the rolling hash at 0x00)

   words, i.e. exactly twice what the formula budgets. The same understatement applies to the W phase (1 + num_rotations * 4), which is not represented at all in the chain.

   The constant vk_mptr = static_working_memory_size becomes the floor of every memory layout in the contract:

     0x00..hash_mptr_max          : keccak input, grows between squeezes
     vk_mptr..vk_mptr + vk_len    : VK area (mirrored into memory by extcodecopy)
     challenge_mptr..              : THETA / BETA / GAMMA / Y / X / NU / MU
     theta_mptr + offsets         : ACC_LHS, ACC_RHS, X_N, ..., PAIRING_LHS/RHS

   When phase_words > vk_mptr / 0x20 + vk_len / 0x20, the loop body inside read_g1_point

   yul
     mstore(hash_mptr,            x_hi)
     mstore(add(hash_mptr, 0x20), x_lo)
     mstore(add(hash_mptr, 0x40), y_hi)
     mstore(add(hash_mptr, 0x60), y_lo)
     ret2 := add(hash_mptr, 0x80)

   writes through CHALLENGE_MPTR and beyond, overwriting THETA_MPTR / BETA_MPTR / GAMMA_MPTR / Y_MPTR / X_MPTR / NU_MPTR / MU_MPTR. Since challenges are written at squeeze time 
   (mstore(challenge_mptr, mod(hash, r)) in squeeze_challenge) and read much later (e.g. let theta := mload(THETA_MPTR) inside evaluator::lookup_computations), the corrupted values
    silently propagate into the constraint check.

   Concrete trigger

   For the standard Plonk fixture used in test::create_property_standard_plonk_fixture we have vk_len ≈ 60 * 32 and pcs_computation = 12 + num_rotations*4 ≈ 28 words, so the 
   formula returns 25 * 0x20. With n = 22 advice columns in any phase the corrected formula is

     n * 4 + 1       = 89 words   (correct BLS budget)
     n * 2 + 1       = 45 words   (used by codegen)
     saturating_sub(60) = 0          (under-counts)

   and vk_mptr is computed as if 25 working words sufficed. The keccak buffer of phase-1 then extends to address 0x00 + 89 * 0x20 = 0x720, overwriting CHALLENGE_MPTR = vk_mptr + 
   vk_len ≈ 0x500. The squeezed theta/beta/gamma are clobbered by subsequent read_g1_point writes for phase-2 advices and the verifier ends up evaluating quotient_eval_numer with 
   attacker-aliased inputs.

   Impact

   •  Soundness: The corrupted challenges feed evaluator::gate_computations, permutation_computations, and lookup_computations. An attacker who knows the corruption pattern (purely
       a function of public num_advices / num_evals / vk_len) can craft proofs that the verifier folds against the wrong polynomial relation. We did not construct an end-to-end 
      forgery in scope, but the corruption is deterministic and aligns 32-byte words with THETA_MPTR / BETA_MPTR, so we treat this as an exploitable soundness hole rather than mere
       DoS.
   •  Liveness: Honest proofs from any halo2 circuit with ≥ 22 advices in some phase (every reasonably sized halo2 chip stack: ECDSA, Poseidon, range-check tables, aggregation 
      circuits) will be silently rejected.

   Recommendation

   1. Replace n * 2 + 1 with n * 4 + 1 for the BLS path, and add an instances term (1 + num_instances + num_advices_phase1 * 4) for phase 1.
   2. Add the W phase budget (1 + num_rotations * 4).
   3. Add a debug-time assertion in Halo2Verifier::render that the rendered Yul never writes past vk_mptr for any input shape.
   4. Long term, switch to a memory layout where the keccak buffer is allocated after all permanent state (or at a fixed bumped offset) so the formula becomes a one-shot ceiling 
      rather than an arithmetic obligation.

   ──────────────────────────────────────────

   3. High-severity findings

   F-2 - Fiat-Shamir mismatch on empty advice phases

   Locations:
   •  prover: src/transcript.rs::Keccak256Transcript::squeeze_challenge (the if buf_len == 0x20 { Some(1) } branch).
   •  verifier: phase loop in templates/Halo2Verifier.sol calling squeeze_challenge (no 0x01 byte) vs. squeeze_challenge_cont (appends 0x01).

   The Rust transcript appends a 0x01 byte every time it is asked to squeeze and buf happens to contain only the previous hash (buf_len == 0x20). The Yul template only emulates 
   that semantics through squeeze_challenge_cont, which is emitted explicitly by the for-loop

   jinja
     challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
     {%- for _ in 0..num_challenges[loop.index0] - 1 %}
     challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)
     {%- endfor %}

   When a phase contains zero advice commitments (num_advices_phase_i == 0) the inner read_g1_point loop does not execute, hash_mptr stays at 0x20, and the squeeze_challenge call 
   hashes exactly 32 bytes (the previous hash) without the trailing 0x01. The Rust transcript, on the other hand, sees buf_len == 0x20 in that exact same situation and appends 
   0x01. The two sides diverge.

   Reachability. halo2 v0.4 allows phases with no advice columns: ConstraintSystemMeta::new derives num_user_advices from cs.advice_column_phase() whose distribution is set per 
   advice column - if all advices are pinned to phases 0 and 2, num_user_advices = [k0, 0, k2]. The num_advices() chain that is then iterated in the Yul template includes that 
   explicit zero. Most production circuits today put every column in phase 0, so the bug is dormant; but it ships as a correctness footgun for any upcoming multi-phase circuit 
   (lookups + custom challenges, RAM sub-arguments, etc.).

   Impact. Honest proofs are rejected (completeness). For soundness, the verifier's challenges become a known function of the prover's challenges (they differ only by the 0x01 
   byte), so an adaptive attacker could in principle replay grinding attacks across the two derivations - we did not classify this as fully exploitable but it is a non-zero 
   soundness erosion.

   Recommendation. Mirror the Rust logic in Yul: if the buffer length at squeeze time equals 0x20 (i.e. nothing has been appended since the last squeeze), call 
   squeeze_challenge_cont. Concretely, the codegen can detect the empty phase and emit squeeze_challenge_cont instead of squeeze_challenge.

   F-3 - `read_g1_point` hashes raw calldata before validating the EIP-2537 padding

   Location: templates/Halo2Verifier.sol, read_g1_point.

   yul
     function read_g1_point(success, proof_cptr, hash_mptr) -> ret0, ret1, ret2 {
         let x_hi := calldataload(proof_cptr)
         ...
         ret0 := and(success, iszero(shr(128, x_hi)))
         ret0 := and(ret0,    iszero(shr(128, y_hi)))
         mstore(hash_mptr,            x_hi)        // <-- written even when ret0 = 0
         mstore(add(hash_mptr, 0x20), x_lo)
         mstore(add(hash_mptr, 0x40), y_hi)
         mstore(add(hash_mptr, 0x60), y_lo)
         ...
     }

   The four mstores execute regardless of whether the padding check passed. Today this is benign because the verifier reverts via the global if iszero(success) { revert(0, 0) } 
   long before any precompile observes the corrupted bytes, and the Fiat-Shamir transcript that consumes those bytes will simply produce a wrong challenge on the failing path. 
   However:

   1. The transcript hash is consumed inside squeeze_challenge_cont and then influences memory addresses (mload(NU_MPTR), mload(MU_MPTR), etc.) that drive subsequent calldata 
      reads. A future refactor that turns one of those reads into a load through a derived pointer would let an attacker steer pointer arithmetic with under-validated bytes.
   2. The exact same read_g1_point is reused for the W openings (4 in total), the quotient commitments, and the random commitment - i.e. for every G1 read in the proof. Any later 
      optimisation that routes x_hi/y_hi through mod / shl arithmetic before the padding check is verified would lose the guarantee.

   Recommendation. Reverse the order: set ret0 before the four mstores, and make the mstores gated on ret0 (or only write (x_lo, y_lo) and zero out the hi halves so the transcript 
   content is canonical even on failure).

   ──────────────────────────────────────────

   4. Medium-severity findings

   F-4 - Accumulator limb reconstruction

   Location: templates/Halo2Verifier.sol, the if mload(HAS_ACCUMULATOR_MPTR) block.

   Two sub-issues:

   1. Native `add` / `shl` instead of `addmod`. The reconstruction sums limb << shift into (hi, lo) using EVM add. We verified that the typical (num_limbs, num_limb_bits) 
      configurations (e.g. 4×96, 4×88) keep the bit-ranges disjoint so there is no overflow. But the verifier silently accepts any (num_limbs, num_limb_bits) from the VK, including
       pathological ones such as num_limb_bits = 0 (the lt(limb, shl(num_limb_bits, 1)) check becomes lt(limb, 2), accepting only 0 or 1) or num_limb_bits >= 256 (shl(256, 1) == 0,
       accepting nothing). Because the VK is now pinned through EXPECTED_VK_CODEHASH, abuse requires bypassing the pin, but a misconfigured trusted setup ceremony could still 
      encode a foot-gun there.
   2. Misleading dead code. Inside the per-coord switch:

   yul
        if and(eq(coord, 1), 0) { dst := add(dst, 0x40) }   // never executes (literal 0)
        if iszero(or(eq(coord, 1), eq(coord, 3))) {         // can never hold inside `case 1`
            dst := add(dst, 0x40)
        }

      Both branches are unreachable inside the case 1 arm (where coord ∈ {1, 3}). Reviewers can be misled into thinking they actively guard against a path they don't.

   Recommendation. Use addmod for the limb sums (cheap insurance), enforce 1 ≤ num_limb_bits ≤ 128 and num_limbs * num_limb_bits ≤ 384 at the top of the block, and delete the dead 
   branches.

   F-5 - VK generation panics on identity G1/G2

   Location: src/codegen/util.rs::g1_to_u256s / g2_to_u256s.

   rust
     let coords = ec_point.borrow().coordinates().unwrap();

   Coordinates::from(...) returns None for the point at infinity. A trusted-setup output with any commitment equal to the identity (e.g. an empty fixed column) crashes the codegen 
   pipeline. Not exploitable on chain, but fragile against malformed VKs and inconvenient for tooling that wants to generate a verifier first and decide later. Same concern in 
   transcript.rs::common_point and write_point, which unwrap() after a fallible coordinate extraction.

   Recommendation. Treat the identity as the all-zero EIP-2537 encoding [0; 4] / [0; 8] and propagate a Result instead of panicking.

   F-6 - `delta` constant is hard-coded and only checked off-line

   Location: templates/Halo2Verifier.sol

   yul
     let delta := 3793952369011177517951424454785176000433849974408744014172535497121832470999 // BLS12-381 Fr::DELTA

   We verified the value matches bls12381::Fr::DELTA by running examples/check_delta.rs. However the value is embedded as a literal in the template; nothing in the build forces a 
   regeneration if halo2curves ships a different DELTA (e.g. after a future curve update). The audit trail in the template has already shown a stale value being silently kept 
   (4131629893567559867359510883348571134090853742863529169391034518566172092834).

   Recommendation. Inject delta from the codegen side by computing it directly from bls12381::Fr::DELTA at render time, then have the template consume it via the templating engine.
    That removes the off-line-only check and makes future curve swaps a one-liner.

   ──────────────────────────────────────────

   5. Low-severity & informational findings

   F-7 - Trace-mode verifier returns a `bool` instead of reverting

   jinja
     function verifyProof(...) public {%- if self.trace %} returns (bool) {%- else %} view returns (bool) {%- endif %}

   In trace mode the function:
   •  drops view (logs are emitted),
   •  returns success (1 or 0) instead of revert-ing on failure,
   •  leaks the entire challenge transcript and the intermediate PAIRING_LHS / PAIRING_RHS via LOG1.

   The challenges are not secret (they are derivable from public proof + VK), but a deployer that ships render_trace_separately() in production changes the failure semantics from 
   revert to return false. Callers using try { verifier.verifyProof(...) } catch { ... } then silently misclassify rejected proofs as "verifier executed successfully, said no, but 
   we will treat the absence of revert as success." Recommendation: gate the trace constructor behind an unsafe_* factory and emit a runtime require(false) if a non-trace caller 
   invokes it.

   F-8 - `pop(y) / pop(delta)`

   Cosmetic. Yul pop only discards the top stack element; the local Yul variable is already destined to go out of scope. No memory is actually cleared. Already noted in AUDIT.md 
   for the BN254 path; carried over verbatim.

   F-9 - VK-driven `HAS_ACCUMULATOR_MPTR` is not cross-checked

   The verifier blindly trusts the VK constants has_accumulator, acc_offset, num_acc_limbs, num_acc_limb_bits. With the AUTHORIZED_VK codehash pin in place this is fine; without it
    (or after an upgrade that forgets to re-pin), a VK contract can lie about has_accumulator = 1 while the Rust generator was constructed without AccumulatorEncoding. The verifier
    then drains num_limbs * 4 = 16 instance slots as accumulator limbs, mis-decodes them as G1 points, and feeds garbage to 0x0c / 0x0f. The pairing precompile reverts (no 
   soundness break), but the user gets an inscrutable failure mode.

   Recommendation. Hash the (has_accumulator, acc_offset, num_acc_limbs, num_acc_limb_bits) tuple into the codehash explicitly (it already is, transitively), and have the codegen 
   emit a require on the constructor side that the deployer's acc_encoding agrees with vk.has_accumulator.

   I-10 - Silent generator restrictions

   rust
     assert_ne!(vk.cs().num_advice_columns(), 0);
     assert!(vk.cs().num_instance_columns() <= 1, "Multiple instance columns is not yet implemented");
     assert!(!vk.cs().instance_queries().iter().any(|(_, rotation)| *rotation != Rotation::cur()), ...);

   These are user-facing panics rather than Results. A deployer integrating the codegen into a CI pipeline gets an opaque crash. Convert to Result<…, GeneratorError>.

   I-11 - `n_inv` and `omega_inv_to_l` are never re-derived on chain

   The verifier uses n_inv (= 1/2^k mod r) and omega_inv_to_l (= ω^{-l}) from the VK without recomputing them from k and omega at runtime. With the codehash pin in place this is 
   fine (the codehash binds the entire VK byte string). Without it, a malicious VK could substitute n_inv := 1 and omega_inv_to_l := 1, which would silently yield a different 
   Lagrange basis at evaluation time. The pin closes this; we mention it because future "upgradeable VK" deployments would need to be aware that these are non-redundant trust 
   roots.

   I-12 - Bias in `mod(hash, r)`

   r = 0x73eda7…00000001 ≈ 2^254.86. With a 256-bit hash, the bias is ~2^256 / r - 1 ≈ 2^-254, completely negligible. Standard practice; no action.

   ──────────────────────────────────────────

   6. Compatibility / hygiene observations

   •  proof_to_bls_padded (src/codegen.rs) and the prover-side transcript (src/transcript.rs::common_point) agree byte-for-byte on the 16-zero-byte EIP-2537 prefix per Fp 
      coordinate. Good.
   •  g1_to_u256s reads Fq::to_repr() (LE) and reverses; g2_to_u256s reads Fq::to_bytes() (BE). We verified this difference against halo2derive 0.1.0's impl_field! macro:

   rust
     fn to_repr(&self) -> Self::Repr { /* hard-coded LE */ }
     pub fn to_bytes(&self) -> [u8; …] { /* honors `endian = "big"` setting for Fq */ }

   so the asymmetry is correct, but it is exactly the kind of footgun that breaks silently if a future halo2curves release changes the macro - we recommend asserting Fq::ENDIAN == 
   BE once at the top of util.rs so a regression would be immediately observable.

   •  The trailing mstore(0x00, 1); return(0x00, 0x20) in non-trace mode means the function only ever returns true or reverts; declare it view returns () and rely on revert-or-not 
      semantics, or drop the bool return entirely. The current shape misleads callers into believing false is a possible return.

   ──────────────────────────────────────────

   7. Suggested follow-ups (in priority order)

   1. Fix F-1. Recompute static_working_memory_size for the BLS layout (multiply advice stride by 4, add the W-phase term, add a phase-1 instances term). Add a unit test that 
      builds a wide circuit (say 64 advices in phase 1) and asserts the rendered Yul never reads/writes through CHALLENGE_MPTR mid-transcript.
   2. Fix F-2. Mirror the Rust buf_len == 0x20 semantics on the Yul side; the cleanest way is to track buffer occupancy in the codegen and emit squeeze_challenge_cont on empty 
      phases.
   3. Fix F-3. Reorder the writes in read_g1_point so the transcript only sees padded bytes when ret0 is true.
   4. Re-enable the ignored property tests (pbt_solidity_* in src/test.rs) once the BLS prover backend is wired up; this is the only end-to-end witness for soundness assertions.
   5. Add a cargo xtask audit target that re-runs examples/check_delta.rs and asserts the value found in templates/Halo2Verifier.sol matches at build time.
   6. Tighten the g*_to_u256s helpers to handle the identity case (F-5) and propagate richer errors out of SolidityGenerator::new (I-10).

   ──────────────────────────────────────────

   8. Summary

   The BLS12-381 / EIP-2537 port is structurally sound: pairing inputs are laid out per spec, the pinned-VK pattern correctly closes the largest historical hole in this codebase, 
   and the EIP-2537 precompiles transitively cover G2 subgroup checks. The most consequential issue we found, F-1, is a numeric mistake in the static memory layout calculation that
    survives from the BN254 era and is large enough to corrupt Fiat-Shamir state on routinely-sized circuits. F-2 breaks completeness for circuits with empty intermediate phases. 
   F-3 is currently latent but is the kind of memory-vs-validation ordering bug that becomes exploitable under any future refactor. The remaining items are hardening and ergonomics
    work.

   Recommended next actions: fix F-1 immediately (it gates re-enablement of the ignored render / pbt tests), schedule F-2/F-3 for the next correctness sprint, and treat F-4 through
    F-9 as code-review polish.

   Plan updated

⛬  The audit found one critical issue (F-1: BN254-era stride n*2+1 in static_working_memory_size can overflow keccak buffer into challenge memory on circuits with ≥22 advices in 
   any phase), two high-severity issues (F-2: Fiat-Shamir mismatch on empty advice phases; F-3: read_g1_point hashes raw calldata before validating EIP-2537 padding), and a handful
    of medium/low items around accumulator decoding, identity-point handling, the hard-coded delta constant, and trace-mode footguns. The pinned-VK + EXPECTED_VK_CODEHASH pattern 
   correctly closes the original BN254 caller-controlled-VK hole, and EIP-2537 transitively gives the G2 subgroup check that the BN254 path was missing.

## 2026-05-02 production-readiness findings: IVC verifier artifact

Scope note: these findings are about the generated IVC verifier artifact and
its production hardening. Challenge truncation is intentionally out of scope
for this note: the compiler keeps that behavior optional, and this review
looked at an IVC build that enables the option.

Conclusion: the verifier is not production-ready yet. Several issues are
deployment-integrity, fail-closed, or integration hazards rather than immediate
cryptographic breaks, but they should be closed before shipping.

### High-priority findings

#### A-1. Production builds must pin the quotient evaluator hash and length

Severity: High.

The verifier pins the VK with an expected runtime length and codehash. The
quotient evaluator must be treated the same way, because the external quotient
contract reconstructs the batched identity numerator, the linearization
expected evaluation, and the simple-selector accumulators. It is not merely a
gas optimization.

The template now supports an `EXPECTED_QUOTIENT_LENGTH` /
`EXPECTED_QUOTIENT_CODEHASH` path, but the fallback path still accepts any
non-empty quotient evaluator in the constructor and pins whatever codehash was
passed:

```solidity
require(authorizedQuotient.code.length != 0, "invalid quotient");
AUTHORIZED_QUOTIENT_CODEHASH = authorizedQuotient.codehash;
```

Impact:

- A malicious or mistaken deployment can wire a quotient evaluator that returns
  forged `QUOTIENT_EVAL_MPTR` and selector accumulators.
- The rest of the verifier can then verify a different statement than the one
  implied by the intended circuit and VK.
- This is especially dangerous for factories, registries, copied deployment
  scripts, and third-party verifier addresses.

Recommendation:

- Generate and deploy production IVC verifiers only through the hard-coded
  quotient hash path.
- Make `EXPECTED_QUOTIENT_LENGTH` and `EXPECTED_QUOTIENT_CODEHASH` mandatory
  for external quotient evaluator builds.
- Add a negative deployment test that rejects a quotient evaluator with the
  same ABI and different runtime bytecode.

#### A-2. Invalid G1/G2 points can burn almost all supplied gas

Severity: High.

The verifier forwards `gas()` to EIP-2537 precompiles:

```yul
staticcall(gas(), 0x0c, ...)
staticcall(gas(), 0x0f, ...)
```

EIP-2537 specifies that failed precompile calls burn all gas supplied to the
precompile. It also requires errors for invalid encodings, non-curve points,
points outside the subgroup for MSM/pairing, and invalid input length. The
verifier range-checks G1 coordinates before transcript absorption, but
curve-membership and subgroup checks are deferred to MSM/pairing precompiles.

Impact:

- A caller can submit field-canonical but off-curve proof points and cause a
  later G1MSM or pairing call to burn nearly all remaining gas.
- If users call the verifier directly this is a UX/DoS issue. If another
  protocol calls the verifier, the gas griefing is more serious.

Recommendation:

- Use bounded-gas wrappers for EIP-2537 calls, sized from the expected valid
  input length plus a safety margin.
- Check exact return sizes after every precompile call.
- Add negative tests for off-curve G1, wrong-subgroup G1 in MSM, malformed G2,
  and invalid pairing inputs.

#### A-3. Accumulator RHS fixed-base scalar handling must be schema-checked

Severity: High for general codegen, low/medium for the current IVC artifact.

The accumulator block documents an RHS layout containing point limbs, one
scalar, and fixed-base scalars in `BTreeMap` key order. The current code walks
`fixed_scalar_ptr` only when generated fixed-base points exist; for the concrete
IVC layout there appears to be no tail, so the current artifact is probably
consistent. The template still needs an explicit schema assertion.

Impact:

- A future circuit with fixed-base accumulator terms could silently verify the
  wrong accumulator equation if the codegen metadata, comments, and instance
  layout diverge.
- Without a schema assertion, a layout mismatch fails unclearly.

Recommendation:

- For the concrete IVC verifier, assert that the accumulator layout consumes
  exactly the expected instance words.
- For general codegen, either implement the documented fixed-base tail MSM for
  every generated fixed-base term or make the zero-tail invariant explicit in
  VK/codegen metadata and generated tests.

#### A-4. Accumulator limb decoding is non-canonical

Severity: High/Medium.

`load_acc_coord_shifted` extracts packed accumulator limbs with masks:

```yul
let limb := and(shr(mul(mod(i, limbs_per_word), bits), packed), mask)
```

For 56-bit limbs, a coordinate is split across words with unused high bits. The
verifier checks each public-input word is `< Fr`, but it does not reject unused
high bits in the packed words. Those bits are silently ignored by the
accumulator decoder.

Impact:

- Multiple public-input encodings can decode to the same BLS point.
- The transcript absorbs the full public-input words, so this is not
  automatically a bypass, but it is a canonicality hole.
- It can become a soundness bug if the circuit-side public-input packing does
  not enforce the same unused-bit zero constraints.

Recommendation:

- Add verifier-side checks that unused high bits are zero for every packed
  accumulator coordinate word.
- For the identity encoding, accept only the exact full-point identity form and
  require strict packing for all non-identity coordinates.
- Add negative tests for high unused accumulator bits.

### Medium-priority findings

#### A-5. Gas checkpoints must not be present in production builds

Severity: Medium.

`gas_checkpoint()` emits `LOG1` repeatedly during verification when the gas
checkpoint build path is enabled. That makes the verifier non-`view`, prevents
safe `staticcall` usage, leaks profiling artifacts into logs, and adds gas to
every proof.

Implementation note: the checkpoint helper and all call sites are Askama
branches in `templates/Halo2Verifier.sol`, guarded by `self.gas_checkpoints`.
Default render paths set this from the `solidity-gas-checkpoints` Cargo feature,
while `render_with_gas_checkpoints*` helpers force it on for benchmarking. The
separate `Halo2QuotientEvaluator.sol` template does not currently emit
checkpoint logs; it copies the verifier frame, runs the quotient numerator
block, and returns the fixed output frame.

Recommendation:

- Keep gas checkpoints only in explicit debug/bench artifacts.
- Ensure production generation disables trace/gas flags and emits:

```solidity
function verifyProof(
    bytes calldata proof,
    uint256[] calldata instances
) external view returns (bool)
```

#### A-6. The Solidity pragma is too loose for the generated opcode set

Severity: Medium.

The generated templates currently use:

```solidity
pragma solidity ^0.8.0;
```

The verifier uses Yul `mcopy`, which requires compiler support for Cancun-era
opcodes. The generated source should require a compiler version that supports
the emitted Yul and should be compiled for an EVM target that supports both
MCOPY and EIP-2537 on the destination chain.

Recommendation:

- Pin the generated templates to at least Solidity `^0.8.24`, or a narrower
  exact compiler version used by CI.
- Compile with the intended EVM version and record the compiler/EVM target in
  deployment artifacts.

#### A-7. Invalid proofs mostly revert despite a bool-returning API

Severity: Medium.

The public API returns `bool`, but many invalid proof paths use
`revert(0, 0)`. Only some early deployment-binding checks return `false`.

Impact:

- Integrators may expect invalid proofs to return `false`, while malformed
  proofs, invalid scalars, invalid points, denominator failures, bad quotient
  output, and bad pairings mostly revert.
- The API is harder to safely compose in other contracts.

Recommendation:

- Decide on one policy:
  - revert on all invalid proofs and document that behavior; or
  - consistently return `false`.
- Prefer custom errors or clear NatSpec if reverting remains the production
  policy.

#### A-8. The manual ABI parser should check dynamic offsets

Severity: Medium.

The verifier hardcodes calldata locations such as:

```yul
PROOF_LEN_CPTR
PROOF_CPTR
NUM_INSTANCE_CPTR
INSTANCE_CPTR
```

It should also assert the dynamic ABI heads match the hand-rolled parser:

```yul
success := and(success, eq(calldataload(0x04), 0x40))
success := and(success, eq(calldataload(0x24), EXPECTED_INSTANCE_HEAD))
```

Recommendation:

- Add canonical ABI-offset checks for `proof` and `instances`.
- Alternatively, use Solidity's `proof.offset`, `proof.length`,
  `instances.offset`, and `instances.length` values directly in the assembly.

#### A-9. Check the quotient evaluator against EIP-170 in CI

Severity: Medium.

The external quotient evaluator is close to Ethereum's `0x6000` runtime
code-size limit. Contract creation fails when returned runtime code exceeds
24,576 bytes.

Recommendation:

- Compile the exact production evaluator with the intended optimizer and EVM
  target in CI.
- Assert deployed runtime length is below 24,576 bytes with margin.
- Split the evaluator or move static data if the margin becomes too small.

### Lower-priority hardening

#### A-10. Comments still describe compressed proof commitments

Severity: Low.

Some template comments still describe proof commitments as zcash-compressed
points that are decompressed inline. The current verifier expects
EIP-2537-padded uncompressed G1 points in calldata and hashes that 128-byte
form into the transcript.

Recommendation:

- Update stale comments around proof serialization, transcript absorption, and
  commitment memory layout.
- Treat serialization comments as security-sensitive because off-chain repack
  bugs cause hard-to-debug transcript mismatches.

#### A-11. Add generated layout invariant tests

Severity: Low.

This verifier is layout-sensitive. A cheap generated test suite should assert
relationships such as:

```text
PROOF_CPTR + proof_len == NUM_INSTANCE_CPTR
INSTANCE_CPTR == NUM_INSTANCE_CPTR + 0x20
ADVICE_COMMS_MPTR_BASE + advice_count * 0x80 == LOOKUP_M_COMMS_MPTR_BASE
```

Recommendation:

- Generate Foundry/Hardhat or Rust-side tests for the rendered constants.
- Keep these as CI checks rather than runtime production assertions unless the
  cost is negligible.

#### A-12. Remove unused constants and dead paths

Severity: Low.

Examples observed in generated or adjacent code include unused quotient cursor
constants, scratch constants, and stale helper paths.

Recommendation:

- Remove dead constants and helpers from production renders.
- Keep debug-only helpers behind explicit trace/bench flags.

### Things that looked internally consistent

- The proof parser's section lengths appear internally consistent for the IVC
  artifact.
- VK runtime length and verifier `extcodecopy` layout agree in the generated
  artifact.
- EIP-2537 coordinate canonicality checks reject non-zero top padding bytes and
  accept coordinates up to `p - 1`.
- The final KZG pairing argument order appears consistent with the helper's
  `e(arg0, G2_BASE) * e(arg1, NEG_S_G2_BASE) == 1` convention.

### Recommended action list

1. Make expected quotient codehash/length mandatory for external quotient
   evaluator production builds.
2. Remove gas checkpoints from production artifacts and make production
   `verifyProof` `external view`.
3. Add bounded-gas wrappers and exact return-size checks for EIP-2537 calls.
4. Add canonical packed-limb checks for accumulator public inputs.
5. Assert accumulator schemas consume all expected instance words, or implement
   the documented fixed-base tail in general codegen.
6. Require a Solidity compiler/EVM target that supports the emitted Yul and
   target-chain precompiles.
7. Add ABI dynamic-offset checks for the hand-rolled parser.
8. Add CI checks for quotient evaluator runtime size under EIP-170.
9. Add negative tests for malformed/off-curve/wrong-subgroup points, high
   accumulator padding bits, wrong quotient codehash, wrong ABI offsets, wrong
   proof length, and mutated quotient output.

References:

- EIP-2537: https://eips.ethereum.org/EIPS/eip-2537
- Solidity 0.8.24 release notes: https://www.soliditylang.org/blog/2024/01/26/solidity-0.8.24-release-announcement/
- Ethereum Pectra announcement: https://blog.ethereum.org/2025/04/23/pectra-mainnet
- EIP-170: https://eips.ethereum.org/EIPS/eip-170

## 2026-05-02 follow-up audit notes: accumulator and batching edge cases

I found no obvious "any random proof passes" bug in the main KZG pairing path,
but this verifier should still not be treated as production-ready without
resolving the items below. The highest-risk items are accumulator handling and
challenge truncation, because both can silently make the Solidity verifier
check a different statement than the native Midnight/Halo2 verifier.

### Findings overview

| Severity | Issue | Why it matters |
| --- | --- | --- |
| Resolved / clarified | Accumulator RHS fixed-base tail appears documented but not verified | The current IVC verifier fully collapses the carried proof accumulator, so no fixed-base scalar tail remains in public instances. The generator now renders the no-tail layout explicitly and emits `fixed_scalar_ptr` only for future non-collapsed layouts with generated fixed bases. |
| Resolved / confirmed mirrored | `x1` and `x4` powers are truncated to 128 bits, not just `x3` | Confirmed against Midfall `proofs/src/poly/kzg/mod.rs`: with `truncated-challenges`, Rust truncates x3 directly and uses `truncated_powers(x1)` / `truncated_powers(x4)` for PCS batching. Solidity intentionally mirrors this by masking stored powers, while keeping x1/x4 accumulators full precision. |
| Resolved / debug-only | Gas logging is live in production path | Production renders do not emit `gas_checkpoint()` and keep `verifyProof` as `external view`. Checkpoints are available only through the `solidity-gas-checkpoints` feature or explicit gas-checkpoint render helpers. |
| Clarified / integration requirement | Raw `verifyProof` does not bind application semantics | The raw generated verifier intentionally checks only "this proof is valid for these public instances under this VK." Generated NatSpec now requires wrappers to bind state roots, program ID, expected IVC output, chain/domain, and related application semantics. |
| Resolved / deployment guard | Precompile assumptions should be explicit | Constructors now run a deployment-time smoke test for EIP-2537 G1ADD, G1MSM, and pairing using identity inputs, and generated comments state the Solidity/EVM target requirement. |
| Resolved / fail-fast | Malformed calldata and failed `success` states keep executing expensive work | ABI/proof/instance shape failures now revert before transcript parsing, Lagrange failures revert before quotient reconstruction, and EIP-2537 calls are guarded with `if success` instead of `and(success, staticcall(...))`. |
| Clarified / plan-enforced | Point validation is indirect | `common_uncompressed_g1` checks canonical Fp encoding before transcript absorption, while curve/subgroup validation is delegated to EIP-2537 G1MSM/pairing. `ProtocolPlan::validate` rejects absorbed proof commitments that are not opened/consumed, and ignored negative tests mutate every proof G1 to non-canonical/off-curve encodings. |

### F-1. Accumulator fixed-base terms look omitted

Status: Resolved / clarified.

This block is suspicious:

```solidity
// RHS layout: point limbs (x,y), scalar, then fixed-base
// scalars in BTreeMap key order (`-G`, fixed_i, perm_i ...)
let fixed_scalar_ptr := add(rhs_scalar_ptr, 0x20)
let acc_msm_len := sub(acc_pair_ptr, acc_scratch)
```

The current IVC verifier fully collapses the carried proof accumulator before it
is exposed as public input. That means the on-chain accumulator schema is:

```text
acc_offset
  LHS point limbs x/y, LHS scalar
  RHS point limbs x/y, RHS scalar
```

No `-G`, fixed commitment, or permutation commitment scalar tail remains for
this verifier. The generator now states this directly in the rendered
`Halo2Verifier.sol` comments and renders `fixed_scalar_ptr` only when
`acc_fixed_bases.len() > 0`, which is reserved for future partially-collapsed
layouts. The instance-count check remains explicit:

```solidity
acc_expected_words = acc_offset + lhs_point + lhs_scalar + rhs_point + rhs_scalar + fixed_tail_len
```

For the current fully-collapsed IVC layout, `fixed_tail_len == 0`.

This does not mean the decider proof has no fixed bases anywhere. The final
KZG pairing check still uses fixed, permutation, quotient, advice, lookup, and
accumulator commitments as verifier-key/proof bases in the PCS MSM. The
clarification is narrower: those bases are not encoded as an extra
public-input scalar tail on `ACC_RHS_MPTR` for the carried proof accumulator.

### F-2. Challenge truncation looks inconsistent

Status: Resolved / confirmed mirrored.

This comment says:

```solidity
// truncated-challenges: x3 is the f_com evaluation point ...
// midnight-proofs truncates it to 128 bits at squeeze time
mstore(X3_MPTR, and(mload(X3_MPTR), 0xffffffffffffffffffffffffffffffff))
```

But later the verifier also truncates powers of `x1`:

```solidity
acc := mulmod(acc, x1, r)
mstore(p, and(acc, 0xffffffffffffffffffffffffffffffff))
```

and powers of `x4`:

```solidity
x4_pow_full := mulmod(x4_pow_full, x4, r)
let x4_pow_1 := and(x4_pow_full, 0xffffffffffffffffffffffffffffffff)
```

This is not the same as "the challenge is 128-bit." It uses the low 128 bits of
each emitted Fr power. That behavior has now been checked against the native
source of truth:

- `midfall/proofs/src/poly/kzg/mod.rs` truncates `x3` directly when
  `truncated-challenges` is enabled.
- The same Rust file builds `powers_x1` with `truncated_powers(x1)`.
- The final commitment/evaluation fold uses `truncated_powers(x4)`.

The Solidity code mirrors that shape: `x1` and `x4` themselves remain full
squeezed Fr words, their internal power accumulators remain full precision, and
only the emitted batching powers are masked to 128 bits before use. Existing
trace hooks cover the squeezed challenges, `f_eval`, `v`, `final_com`, and
pairing inputs; richer per-power trace IDs would still be useful diagnostics,
but the current masks are not a Solidity-only divergence.
The remaining protocol/documentation item is to state the resulting 128-bit
batching-soundness target wherever the IVC verifier profile is described.

### F-3. Gas logging should be a separate trace build

Status: Resolved / debug-only.

The verifier may emit logs when compiled with gas checkpoints:

```solidity
function gas_checkpoint(id) {
    log1(0, 0, or(shl(248, id), gas()))
}
```

Production artifacts do not include this. The generated template gates the
function and every call site behind `self.gas_checkpoints`; the default renderer
sets that flag from the optional `solidity-gas-checkpoints` feature, while
explicit `render_with_gas_checkpoints*` helpers force it for benchmarking.

Live checkpoint logs would have three production problems:

1. `verifyProof` cannot be safely exposed as `view`.
2. Any contract using `staticcall` to query verification will fail because
   `LOG` is not allowed in a static context.
3. Logs add recurring gas and noisy events.

The production ABI remains `external view returns (bool)` unless trace or gas
checkpoint output is intentionally enabled.

### F-4. Raw `verifyProof` does not bind application semantics

Status: Clarified / integration requirement.

The generated `verifyProof(bytes,uint256[])` ABI verifies only that the supplied
proof is valid for the supplied public instances under this pinned verifier key
and protocol layout. It does not know what a particular application's first
non-accumulator instance means.

This is intentional for a reusable generated verifier, but it must be handled by
the application wrapper. The wrapper must bind the expected state roots, program
identifier, expected IVC output, chain/domain separation, and any
protocol-specific authorization before treating a successful proof as meaningful
for that application. The generated NatSpec now states this explicitly.

### F-5. Precompile assumptions should be explicit

Status: Resolved / deployment guard.

The code depends on EIP-2537 addresses:

```text
0x0b BLS12_G1ADD
0x0c BLS12_G1MSM
0x0f BLS12_PAIRING_CHECK
```

The EIP defines those addresses and the 64-byte Fp encoding rules, including
canonical field-element validation. The generated verifier constructor now runs
a deployment-time smoke test:

- `G1ADD(identity, identity)` must return the 128-byte identity encoding.
- `G1MSM([(identity, 0)])` must return the 128-byte identity encoding.
- `PAIRING_CHECK([(identity_g1, identity_g2)])` must return the 32-byte value
  `1`.

This catches absent precompile implementations, short return data, and obviously
incompatible semantics before the verifier can be deployed. The source comments
also state the compiler/chain requirement: Solidity `>=0.8.24` and a target EVM
supporting MCOPY and EIP-2537.

One item not flagged: using `sub(r, v)` as an MSM scalar can produce `r` when
`v == 0`, but EIP-2537 scalars for multiplication are not required to be less
than the subgroup order.

### F-6. Make failed parsing fail earlier

Status: Resolved / fail-fast.

Malformed ABI/proof length sets `success`, but parsing can continue:

```solidity
success := and(success, eq(0x1e60, calldataload(PROOF_LEN_CPTR)))
...
if iszero(success) { revert(0, 0) }
```

For bad calldata, the verifier could still perform many transcript reads before
reverting. Later, failed states could still evaluate expensive `staticcall`
expressions because Yul builtins are not short-circuiting.

Resolution:

- After VK header, proof length, instance count, and calldata size checks, the
  verifier now immediately reverts.
- If Lagrange/common-polynomial setup fails, the verifier now reverts before
  external quotient reconstruction.
- EIP-2537 calls in the PCS and accumulator paths now use:

```solidity
if success {
    success := staticcall(...)
}
```

instead of:

```solidity
success := and(success, staticcall(...))
```

This prevents already-failed verifier states from entering G1MSM/G1ADD/pairing
precompiles.

### F-7. Point validation and targeted negative tests

Status: Clarified / plan-enforced, with remaining negative-test backlog.

`common_uncompressed_g1` validates canonical EIP-2537 Fp encoding before a proof
point is absorbed into the transcript. It intentionally does not run a separate
curve/subgroup precompile call at read time. Instead:

- `ProtocolPlan::validate` enforces that absorbed proof advice commitments are
  opened by PCS; the other absorbed proof commitment categories are generated
  into the PCS or accumulator MSM/pairing paths.
- EIP-2537 G1MSM and pairing perform the actual curve/subgroup validation for
  those consumed points.
- Ignored EVM-heavy tests already mutate every proof G1 into non-canonical and
  off-curve encodings and assert both native/Solidity rejection paths.

Remaining useful negative tests:

1. Flip each proof G1 into a wrong-subgroup point if one can be generated;
   every mutation must revert.
2. Set every public instance once to `r`; each Fr value
   must reject.
3. Mutate high bits of `x1`/`x4`-power-dependent openings; the result must
   disagree with Rust if masks are wrong.
4. Malform accumulator identity encodings:
   - x identity flag with nonzero y;
   - `p - 1` without identity flag;
   - unused high bits in packed limb words.
5. Add a nonzero accumulator fixed-base tail test if the tail is part of the
   real IVC relation.
6. `staticcall` the production verifier; it should succeed once logging is
   removed.

The two items to resolve first are the accumulator RHS layout mismatch and the
`x1`/`x4` truncation. Those are the most likely to become real soundness or
"Solidity verifies a different protocol" bugs.

Reference:

- EIP-2537: https://eips.ethereum.org/EIPS/eip-2537
