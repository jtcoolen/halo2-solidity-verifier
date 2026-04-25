// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

// Halo2 KZG verifier for the BLS12-381 curve.
//
// Differences vs the original BN254 template (kept as inline comments so a
// reviewer cross-checking the audit can follow the porting):
//
//   * BLS12-381 base field Fp is 381 bits and does *not* fit in a uint256.
//     EVM cannot evaluate `mulmod(_, _, p)` with a 381-bit modulus, so the
//     explicit y^2 == x^3 + b on-curve check is gone. Validation is delegated
//     to the EIP-2537 precompiles, which always revert on malformed inputs
//     (bad subgroup, off-curve, out-of-range limbs).
//   * Each Fp coordinate is encoded in the EIP-2537 padded form: 64 bytes per
//     coordinate (16 leading zero bytes + 48 bytes of value). A G1 point is
//     therefore 128 bytes (4 words); a G2 point is 256 bytes (8 words).
//   * Precompile addresses change:
//       0x06 (BN254 G1ADD)      -> 0x0b (BLS12_G1ADD)
//       0x07 (BN254 G1MUL)      -> 0x0c (BLS12_G1MSM, single-pair mode)
//       0x08 (BN254 PAIRING)    -> 0x0f (BLS12_PAIRING_CHECK)
//   * `r` is the BLS12-381 scalar field modulus (255 bits, fits in a uint256).
contract Halo2Verifier {
    {%- match self.expected_vk_codehash %}
    {%- when Some with (expected_vk_codehash) %}
    address public immutable AUTHORIZED_VK;
    uint256 internal constant EXPECTED_VK_LENGTH = {{ vk_len }};
    bytes32 internal constant EXPECTED_VK_CODEHASH = bytes32({{ expected_vk_codehash|hex_padded(64) }});
    {%- when None %}
    {%- endmatch %}

    uint256 internal constant    PROOF_LEN_CPTR = {{ proof_cptr - 1 }};
    uint256 internal constant        PROOF_CPTR = {{ proof_cptr }};
    uint256 internal constant NUM_INSTANCE_CPTR = {{ proof_cptr + (proof_len / 32) }};
    uint256 internal constant     INSTANCE_CPTR = {{ proof_cptr + (proof_len / 32) + 1 }};

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = {{ quotient_comm_cptr }};
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = {{ quotient_comm_cptr + 4 * (num_quotients - 1) }};

    uint256 internal constant                VK_MPTR = {{ vk_mptr }};
    uint256 internal constant         VK_DIGEST_MPTR = {{ vk_mptr }};
    uint256 internal constant     NUM_INSTANCES_MPTR = {{ vk_mptr + 1 }};
    uint256 internal constant                 K_MPTR = {{ vk_mptr + 2 }};
    uint256 internal constant             N_INV_MPTR = {{ vk_mptr + 3 }};
    uint256 internal constant             OMEGA_MPTR = {{ vk_mptr + 4 }};
    uint256 internal constant         OMEGA_INV_MPTR = {{ vk_mptr + 5 }};
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = {{ vk_mptr + 6 }};
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = {{ vk_mptr + 7 }};
    uint256 internal constant        ACC_OFFSET_MPTR = {{ vk_mptr + 8 }};
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = {{ vk_mptr + 9 }};
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = {{ vk_mptr + 10 }};
    // G1 and G2 generators / setup powers are stored as raw EIP-2537 words.
    // G1 point: 4 consecutive words = (x_hi, x_lo, y_hi, y_lo). G2 point: 8.
    uint256 internal constant            G1_BASE_MPTR = {{ vk_mptr + 11 }};
    uint256 internal constant            G2_BASE_MPTR = {{ vk_mptr + 15 }};
    uint256 internal constant        NEG_S_G2_BASE_MPTR = {{ vk_mptr + 23 }};

    uint256 internal constant CHALLENGE_MPTR = {{ challenge_mptr }};

    uint256 internal constant THETA_MPTR = {{ theta_mptr }};
    uint256 internal constant  BETA_MPTR = {{ theta_mptr + 1 }};
    uint256 internal constant GAMMA_MPTR = {{ theta_mptr + 2 }};
    uint256 internal constant     Y_MPTR = {{ theta_mptr + 3 }};
    uint256 internal constant     X_MPTR = {{ theta_mptr + 4 }};
    uint256 internal constant    NU_MPTR = {{ theta_mptr + 5 }};
    uint256 internal constant    MU_MPTR = {{ theta_mptr + 6 }};

    // EC accumulators each occupy a full G1 point (4 words).
    uint256 internal constant       ACC_LHS_MPTR = {{ theta_mptr + 8 }};
    uint256 internal constant       ACC_RHS_MPTR = {{ theta_mptr + 12 }};
    uint256 internal constant             X_N_MPTR = {{ theta_mptr + 16 }};
    uint256 internal constant X_N_MINUS_1_INV_MPTR = {{ theta_mptr + 17 }};
    uint256 internal constant          L_LAST_MPTR = {{ theta_mptr + 18 }};
    uint256 internal constant         L_BLIND_MPTR = {{ theta_mptr + 19 }};
    uint256 internal constant             L_0_MPTR = {{ theta_mptr + 20 }};
    uint256 internal constant   INSTANCE_EVAL_MPTR = {{ theta_mptr + 21 }};
    uint256 internal constant   QUOTIENT_EVAL_MPTR = {{ theta_mptr + 22 }};
    uint256 internal constant      QUOTIENT_MPTR = {{ theta_mptr + 23 }};   // 4 words
    uint256 internal constant       G1_SCALAR_MPTR = {{ theta_mptr + 27 }};
    uint256 internal constant   PAIRING_LHS_MPTR = {{ theta_mptr + 28 }}; // 4 words
    uint256 internal constant   PAIRING_RHS_MPTR = {{ theta_mptr + 32 }}; // 4 words

    {%- match self.embedded_vk %}
    {%- when None %}
    constructor(address authorizedVk) {
        require(
            authorizedVk.code.length == EXPECTED_VK_LENGTH
                && authorizedVk.codehash == EXPECTED_VK_CODEHASH,
            "invalid vk"
        );
        AUTHORIZED_VK = authorizedVk;
    }
    {%- else %}
    {%- endmatch %}

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public {%- if self.trace %} returns (bool) {%- else %} view returns (bool) {%- endif %} {
        {%- match self.embedded_vk %}
        {%- when None %}
        address vk = AUTHORIZED_VK;
        if (vk.code.length != EXPECTED_VK_LENGTH || vk.codehash != EXPECTED_VK_CODEHASH) {
            return false;
        }
        {%- else %}
        {%- endmatch %}
        assembly {
            // ---------------------------------------------------------------
            // Helpers -- EIP-2537 wrappers.
            //
            // Every G1 helper expects/produces 128-byte EIP-2537 encoded
            // points: (x_hi, x_lo, y_hi, y_lo) where each pair of words
            // represents one Fp coordinate (16 leading zero bytes + 48-byte
            // value). ANY out-of-range or off-curve input causes the
            // precompile to return zero output bytes; we propagate that as
            // success := 0 and revert at the end.
            // ---------------------------------------------------------------

            // Read a G1 point (4 words = 128 bytes) from calldata at
            // proof_cptr, append it to the running transcript at hash_mptr,
            // and return the advanced pointers. EIP-2537 will validate the
            // point on a later precompile call; we don't enforce y^2 = x^3+4
            // here because Fp is 381 bits and EVM has no native 381-bit mod.
            function read_g1_point(success, proof_cptr, hash_mptr) -> ret0, ret1, ret2 {
                let x_hi := calldataload(proof_cptr)
                let x_lo := calldataload(add(proof_cptr, 0x20))
                let y_hi := calldataload(add(proof_cptr, 0x40))
                let y_lo := calldataload(add(proof_cptr, 0x60))
                // EIP-2537 only allows zeros in the top 16 bytes of each
                // 64-byte coord; check that here so badly-encoded calldata
                // is rejected before we hash it into the transcript.
                ret0 := and(success, iszero(shr(128, x_hi)))
                ret0 := and(ret0,    iszero(shr(128, y_hi)))
                mstore(hash_mptr,            x_hi)
                mstore(add(hash_mptr, 0x20), x_lo)
                mstore(add(hash_mptr, 0x40), y_hi)
                mstore(add(hash_mptr, 0x60), y_lo)
                ret1 := add(proof_cptr, 0x80)
                ret2 := add(hash_mptr, 0x80)
            }

            // Squeeze a Fiat-Shamir challenge from memory[0..hash_mptr].
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze an additional challenge in the same Fiat-Shamir round
            // by appending 0x01 to the previous hash.
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Montgomery-style batch inversion in Fr. Identical to the
            // BN254 implementation (Fr fits in u256 in both curves).
            function batch_invert(success, mptr_start, mptr_end, r) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for {} lt(mptr, sub(mptr_end, 0x20)) {} {
                    gp := mulmod(gp, mload(mptr), r)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), r)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(r, 2))
                mstore(add(gp_mptr, 0xa0), r)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for {} lt(second_mptr, mptr) {} {
                    let inv := mulmod(all_inv, mload(gp_mptr), r)
                    all_inv := mulmod(all_inv, mload(mptr), r)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), r)
                let inv_second := mulmod(all_inv, mload(first_mptr), r)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // BLS12_G1ADD (precompile 0x0b): adds the G1 point at memory
            // 0x80..0x100 (4 words) into the accumulator at 0x00..0x80.
            // Cost: 375 gas (EIP-2537 §3).
            function ec_add_acc(success) -> ret {
                ret := and(success, staticcall(gas(), 0x0b, 0x00, 0x100, 0x00, 0x80))
            }

            // BLS12_G1MSM (precompile 0x0c): scalar multiplication. Single
            // (point, scalar) pair => one MSM input row of 160 bytes
            // (128-byte point + 32-byte scalar). Reads from 0x00; result
            // overwrites the accumulator.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x80, scalar)
                ret := and(success, staticcall(gas(), 0x0c, 0x00, 0xa0, 0x00, 0x80))
            }

            // Same as ec_add_acc but uses the scratch slot at 0x80..0x100
            // as the second operand and writes to 0x80 (parallel
            // accumulator).
            function ec_add_tmp(success) -> ret {
                ret := and(success, staticcall(gas(), 0x0b, 0x80, 0x100, 0x80, 0x80))
            }

            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0x100, scalar)
                ret := and(success, staticcall(gas(), 0x0c, 0x80, 0xa0, 0x80, 0x80))
            }

            // BLS12_PAIRING_CHECK (precompile 0x0f). Each pair is 128B (G1)
            // + 256B (G2) = 384 bytes. We pass two pairs (LHS, G2) and
            // (RHS, NEG_S_G2) and assert the product equals 1.
            function ec_pairing(success, lhs_mptr, rhs_mptr) -> ret {
                // Layout the precompile expects: P0 G1, P0 G2, P1 G1, P1 G2.
                // Copy LHS at 0x00, then G2 at 0x80, then RHS at 0x180,
                // then NEG_S_G2 at 0x200.
                mstore(0x00,  mload(lhs_mptr))
                mstore(0x20,  mload(add(lhs_mptr, 0x20)))
                mstore(0x40,  mload(add(lhs_mptr, 0x40)))
                mstore(0x60,  mload(add(lhs_mptr, 0x60)))
                let g2 := G2_BASE_MPTR
                for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                    mstore(add(0x80, mul(i, 0x20)), mload(add(g2, mul(i, 0x20))))
                }
                mstore(0x180, mload(rhs_mptr))
                mstore(0x1a0, mload(add(rhs_mptr, 0x20)))
                mstore(0x1c0, mload(add(rhs_mptr, 0x40)))
                mstore(0x1e0, mload(add(rhs_mptr, 0x60)))
                let nsg2 := NEG_S_G2_BASE_MPTR
                for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                    mstore(add(0x200, mul(i, 0x20)), mload(add(nsg2, mul(i, 0x20))))
                }
                ret := and(success, staticcall(gas(), 0x0f, 0x00, 0x300, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            {%- if self.trace %}
            function trace_u256(id, value) {
                mstore(0x00, value)
                log1(0x00, 0x20, id)
            }
            function trace_point(id, mptr) {
                log1(mptr, 0x80, id)
            }
            {%- endif %}

            // BLS12-381 scalar field modulus.
            let r := 52435875175126190479447740508185965837690552500527637822603658699938581184513

            let success := true

            {
                {%- match self.embedded_vk %}
                {%- when Some with (embedded_vk) %}
                {%- for (name, chunk) in embedded_vk.constants[..2] %}
                mstore({{ vk_mptr + 32 * loop.index0 }}, {{ chunk|hex_padded(64) }}) // {{ name }}
                {%- endfor %}
                {%- when None %}
                extcodecopy(vk, VK_MPTR, 0x00, 0x40)
                {%- endmatch %}

                success := and(success, eq({{ proof_len|hex() }}, calldataload(PROOF_LEN_CPTR)))

                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, calldataload(NUM_INSTANCE_CPTR)))
                success := and(
                    success,
                    eq(calldatasize(), add(INSTANCE_CPTR, mul(0x20, num_instances)))
                )

                mstore(0x00, mload(VK_DIGEST_MPTR))

                let hash_mptr := 0x20
                let instance_cptr := INSTANCE_CPTR
                for { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {} {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := PROOF_CPTR
                let challenge_mptr := CHALLENGE_MPTR
                {%- for num_advices in num_advices %}

                // Phase {{ loop.index }}
                for { let proof_cptr_end := add(proof_cptr, {{ (4 * 32 * num_advices)|hex() }}) }
                    lt(proof_cptr, proof_cptr_end)
                    {} {
                    success, proof_cptr, hash_mptr := read_g1_point(success, proof_cptr, hash_mptr)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                {%- for _ in 0..num_challenges[loop.index0] - 1 %}
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)
                {%- endfor %}
                {%- endfor %}

                // Read evaluations (each 32 bytes; Fr fits in u256)
                for { let proof_cptr_end := add(proof_cptr, {{ (32 * num_evals)|hex() }}) }
                    lt(proof_cptr, proof_cptr_end)
                    {} {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and squeeze its challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // nu

                for { let proof_cptr_end := add(proof_cptr, {{ (4 * 32 * num_rotations)|hex() }}) }
                    lt(proof_cptr, proof_cptr_end)
                    {} {
                    success, proof_cptr, hash_mptr := read_g1_point(success, proof_cptr, hash_mptr)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                {%~ match self.embedded_vk %}
                {%- when Some with (embedded_vk) %}
                {%- for (name, chunk) in embedded_vk.constants %}
                mstore({{ vk_mptr + 32 * loop.index0 }}, {{ chunk|hex_padded(64) }}) // {{ name }}
                {%- endfor %}
                {%- for (x_hi, x_lo, y_hi, y_lo) in embedded_vk.fixed_comms %}
                {%- let offset_b = 32 * embedded_vk.constants.len() %}
                mstore({{ vk_mptr + offset_b + 128 * loop.index0 }}, {{ x_hi|hex_padded(64) }})
                mstore({{ vk_mptr + offset_b + 128 * loop.index0 + 32 }}, {{ x_lo|hex_padded(64) }})
                mstore({{ vk_mptr + offset_b + 128 * loop.index0 + 64 }}, {{ y_hi|hex_padded(64) }})
                mstore({{ vk_mptr + offset_b + 128 * loop.index0 + 96 }}, {{ y_lo|hex_padded(64) }})
                {%- endfor %}
                {%- for (x_hi, x_lo, y_hi, y_lo) in embedded_vk.permutation_comms %}
                {%- let offset_b = 32 * embedded_vk.constants.len() + 128 * embedded_vk.fixed_comms.len() %}
                mstore({{ vk_mptr + offset_b + 128 * loop.index0 }}, {{ x_hi|hex_padded(64) }})
                mstore({{ vk_mptr + offset_b + 128 * loop.index0 + 32 }}, {{ x_lo|hex_padded(64) }})
                mstore({{ vk_mptr + offset_b + 128 * loop.index0 + 64 }}, {{ y_hi|hex_padded(64) }})
                mstore({{ vk_mptr + offset_b + 128 * loop.index0 + 96 }}, {{ y_lo|hex_padded(64) }})
                {%- endfor %}
                {%- when None %}
                extcodecopy(vk, VK_MPTR, 0x00, {{ vk_len|hex() }})
                {%- endmatch %}

                // Read accumulator (G1 LHS / G1 RHS encoded as scalar limbs
                // among the public instances). Same idea as BN254 except
                // the reconstructed coordinate is now an Fp-381 element
                // packed into the EIP-2537 encoding (4 words per point).
                if mload(HAS_ACCUMULATOR_MPTR) {
                    // The expected layout in instances[acc_offset ..] is the
                    // limb decomposition of (lhs.x, lhs.y, rhs.x, rhs.y),
                    // each as `num_limbs` little-endian limbs of
                    // `num_limb_bits` bits. We reconstruct each Fp into two
                    // u256 halves (hi/lo) and store as EIP-2537 padded
                    // 4 words per G1 point.
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)
                    let cptr := add(INSTANCE_CPTR, mul(mload(ACC_OFFSET_MPTR), 0x20))

                    // Reconstruct four Fp values (lhs.x, lhs.y, rhs.x, rhs.y)
                    // by streaming `num_limbs` per coordinate. Each Fp is
                    // up to 381 bits, so we maintain (hi, lo) where
                    // value = hi * 2^256 + lo. The hi/lo split is masked to
                    // EIP-2537's 16-zero / 48-byte padding (`shr(128, hi)`
                    // must be zero).
                    let dst := ACC_LHS_MPTR
                    for { let coord := 0 } lt(coord, 4) { coord := add(coord, 1) } {
                        let hi := 0
                        let lo := 0
                        let shift := 0
                        for { let i := 0 } lt(i, num_limbs) { i := add(i, 1) } {
                            let limb := calldataload(cptr)
                            // limb_shifted = limb << shift, split into hi/lo.
                            // We require shift < 384 (true for sane params).
                            switch lt(shift, 256)
                            case 1 {
                                let in_lo := shl(shift, limb)
                                let carry_to_hi := 0
                                if iszero(iszero(shift)) {
                                    carry_to_hi := shr(sub(256, shift), limb)
                                }
                                lo := add(lo, in_lo)
                                hi := add(hi, carry_to_hi)
                            }
                            default {
                                hi := add(hi, shl(sub(shift, 256), limb))
                            }
                            success := and(success, lt(limb, shl(num_limb_bits, 1)))
                            shift := add(shift, num_limb_bits)
                            cptr := add(cptr, 0x20)
                        }
                        // Enforce EIP-2537 padding: top 16 bytes of `hi` zero.
                        success := and(success, iszero(shr(128, hi)))
                        mstore(dst,            hi)
                        mstore(add(dst, 0x20), lo)
                        // Advance dst by 64B (one Fp coord). Coordinate
                        // ordering is x_hi,x_lo,y_hi,y_lo per G1 point.
                        switch and(coord, 1)
                        case 0 { dst := add(dst, 0x40) }
                        case 1 {
                            // After y of LHS we jump to start of RHS.
                            if eq(coord, 1) {
                                dst := ACC_RHS_MPTR
                            }
                            if eq(coord, 3) {
                                // done
                            }
                            if and(eq(coord, 1), 0) { dst := add(dst, 0x40) }
                            // For (coord==1) we already moved to ACC_RHS_MPTR;
                            // for (coord==3) we leave dst alone.
                            if iszero(or(eq(coord, 1), eq(coord, 3))) {
                                dst := add(dst, 0x40)
                            }
                        }
                    }
                }
            }

            if iszero(success) { revert(0, 0) }

            // ----------------------------------------------------------------
            // Lagrange & instance-evaluation block (pure Fr arithmetic; the
            // BN254 logic carries over unchanged because Fr fits in u256).
            // ----------------------------------------------------------------
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for { let idx := 0 } lt(idx, k) { idx := add(idx, 1) } {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), {{ num_neg_lagranges }})))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) } {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20), r)

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) } {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for { let l_i_cptr_end := add(X_N_MPTR, {{ (num_neg_lagranges * 32)|hex() }}) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) } {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for {
                        let instance_cptr := INSTANCE_CPTR
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    { instance_cptr := add(instance_cptr, 0x20)
                      l_i_cptr := add(l_i_cptr, 0x20) } {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, {{ (num_neg_lagranges * 32)|hex() }}))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // ----------------------------------------------------------------
            // Quotient evaluation. Pure Fr arithmetic (BN254 code carries
            // over verbatim).
            // ----------------------------------------------------------------
            {
                let quotient_eval_numer
                let delta := 3793952369011177517951424454785176000433849974408744014172535497121832470999 // BLS12-381 Fr::DELTA = mul_gen^(2^s); see halo2curves bls12381::Fr
                let y := mload(Y_MPTR)

                {%- for code_block in quotient_eval_numer_computations %}
                {
                    {%- for line in code_block %}
                    {{ line }}
                    {%- endfor %}
                }
                {%- endfor %}

                pop(y)
                pop(delta)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // ----------------------------------------------------------------
            // Fold the quotient commitment via Horner with x_n as scalar.
            // The G1 ops use BLS12_G1ADD / BLS12_G1MSM precompiles. Each
            // commitment in calldata is 128 bytes (4 words).
            // ----------------------------------------------------------------
            {
                // Seed the accumulator with the last quotient commitment.
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                mstore(0x40, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x40)))
                mstore(0x60, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x60)))
                let x_n := mload(X_N_MPTR)
                for {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x80)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x80)
                    }
                    lt(cptr_end, cptr)
                    {} {
                    success := ec_mul_acc(success, x_n)
                    mstore(0x80, calldataload(cptr))
                    mstore(0xa0, calldataload(add(cptr, 0x20)))
                    mstore(0xc0, calldataload(add(cptr, 0x40)))
                    mstore(0xe0, calldataload(add(cptr, 0x60)))
                    success := ec_add_acc(success)
                    cptr := sub(cptr, 0x80)
                }
                // Save accumulated quotient.
                mstore(QUOTIENT_MPTR,            mload(0x00))
                mstore(add(QUOTIENT_MPTR, 0x20), mload(0x20))
                mstore(add(QUOTIENT_MPTR, 0x40), mload(0x40))
                mstore(add(QUOTIENT_MPTR, 0x60), mload(0x60))
            }

            // ----------------------------------------------------------------
            // PCS-specific computation (BDFG21 / GWC19). The codegen emits
            // memory ops that already use the new EIP-2537 layout.
            // ----------------------------------------------------------------
            {
                {%- for code_block in pcs_computations %}
                {
                    {%- for line in code_block %}
                    {{ line }}
                    {%- endfor %}
                }
                {%- endfor %}
            }

            // Random linear combine with the accumulator (when present).
            if mload(HAS_ACCUMULATOR_MPTR) {
                // Hash the four points to get a Fr challenge.
                let h := keccak256(ACC_LHS_MPTR, 0x200) // 4 G1 points = 4*128 = 0x200
                let challenge := mod(h, r)

                // pairing_lhs += challenge * acc_lhs
                mstore(0x00, mload(ACC_LHS_MPTR))
                mstore(0x20, mload(add(ACC_LHS_MPTR, 0x20)))
                mstore(0x40, mload(add(ACC_LHS_MPTR, 0x40)))
                mstore(0x60, mload(add(ACC_LHS_MPTR, 0x60)))
                success := ec_mul_acc(success, challenge)
                mstore(0x80, mload(PAIRING_LHS_MPTR))
                mstore(0xa0, mload(add(PAIRING_LHS_MPTR, 0x20)))
                mstore(0xc0, mload(add(PAIRING_LHS_MPTR, 0x40)))
                mstore(0xe0, mload(add(PAIRING_LHS_MPTR, 0x60)))
                success := ec_add_acc(success)
                mstore(PAIRING_LHS_MPTR,            mload(0x00))
                mstore(add(PAIRING_LHS_MPTR, 0x20), mload(0x20))
                mstore(add(PAIRING_LHS_MPTR, 0x40), mload(0x40))
                mstore(add(PAIRING_LHS_MPTR, 0x60), mload(0x60))

                // pairing_rhs += challenge * acc_rhs
                mstore(0x00, mload(ACC_RHS_MPTR))
                mstore(0x20, mload(add(ACC_RHS_MPTR, 0x20)))
                mstore(0x40, mload(add(ACC_RHS_MPTR, 0x40)))
                mstore(0x60, mload(add(ACC_RHS_MPTR, 0x60)))
                success := ec_mul_acc(success, challenge)
                mstore(0x80, mload(PAIRING_RHS_MPTR))
                mstore(0xa0, mload(add(PAIRING_RHS_MPTR, 0x20)))
                mstore(0xc0, mload(add(PAIRING_RHS_MPTR, 0x40)))
                mstore(0xe0, mload(add(PAIRING_RHS_MPTR, 0x60)))
                success := ec_add_acc(success)
                mstore(PAIRING_RHS_MPTR,            mload(0x00))
                mstore(add(PAIRING_RHS_MPTR, 0x20), mload(0x20))
                mstore(add(PAIRING_RHS_MPTR, 0x40), mload(0x40))
                mstore(add(PAIRING_RHS_MPTR, 0x60), mload(0x60))
            }

            success := ec_pairing(success, PAIRING_LHS_MPTR, PAIRING_RHS_MPTR)

            {%- if self.trace %}
            // In trace builds we always run to the end so the host-side
            // comparison can collect every emitted log. The final return
            // value still encodes whether the pairing accepted.
            {%- else %}
            if iszero(success) { revert(0x00, 0x00) }
            {%- endif %}

            {%- if self.trace %}
            trace_u256(1,  mload(VK_DIGEST_MPTR))
            trace_u256(2,  mload(NUM_INSTANCES_MPTR))
            trace_u256(3,  mload(K_MPTR))
            trace_u256(4,  mload(N_INV_MPTR))
            trace_u256(5,  mload(OMEGA_MPTR))
            trace_u256(6,  mload(OMEGA_INV_MPTR))
            trace_u256(7,  mload(THETA_MPTR))
            trace_u256(8,  mload(BETA_MPTR))
            trace_u256(9,  mload(GAMMA_MPTR))
            trace_u256(10, mload(Y_MPTR))
            trace_u256(11, mload(X_MPTR))
            trace_u256(13, mload(NU_MPTR))
            trace_u256(14, mload(MU_MPTR))
            trace_u256(15, mload(X_N_MPTR))
            trace_u256(16, mload(X_N_MINUS_1_INV_MPTR))
            trace_u256(17, mload(L_LAST_MPTR))
            trace_u256(18, mload(L_BLIND_MPTR))
            trace_u256(19, mload(L_0_MPTR))
            trace_u256(20, mload(INSTANCE_EVAL_MPTR))
            trace_u256(21, mload(QUOTIENT_EVAL_MPTR))
            trace_point(22, QUOTIENT_MPTR)
            trace_point(23, PAIRING_LHS_MPTR)
            trace_point(24, PAIRING_RHS_MPTR)
            if mload(HAS_ACCUMULATOR_MPTR) {
                trace_point(25, ACC_LHS_MPTR)
                trace_point(26, ACC_RHS_MPTR)
            }
            mstore(0x00, success)
            return(0x00, 0x20)
            {%- else %}
            mstore(0x00, 1)
            return(0x00, 0x20)
            {%- endif %}
        }
    }
}
