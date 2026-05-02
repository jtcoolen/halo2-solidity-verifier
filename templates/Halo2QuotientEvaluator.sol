pragma solidity ^0.8.24;

// Native quotient evaluator for Halo2Verifier.
//
// The verifier passes a contiguous memory image beginning at
// QUOTIENT_FRAME_BASE as raw calldata. This contract copies it back to the
// same memory addresses, runs the generated quotient numerator block, and
// returns a compact fixed frame consumed by the verifier.
contract Halo2QuotientEvaluator {
    uint256 internal constant FR_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    uint256 internal constant                VK_MPTR = {{ vk_mptr }};
    uint256 internal constant        CHALLENGE_MPTR = {{ challenge_mptr }};
    uint256 internal constant            THETA_MPTR = {{ theta_mptr }};
    uint256 internal constant             BETA_MPTR = {{ theta_mptr + 1 }};
    uint256 internal constant            GAMMA_MPTR = {{ theta_mptr + 2 }};
    uint256 internal constant TRASH_CHALLENGE_MPTR = {{ theta_mptr + 3 }};
    uint256 internal constant                Y_MPTR = {{ theta_mptr + 4 }};
    uint256 internal constant                X_MPTR = {{ theta_mptr + 5 }};
    uint256 internal constant               X1_MPTR = {{ theta_mptr + 6 }};
    uint256 internal constant               X2_MPTR = {{ theta_mptr + 7 }};
    uint256 internal constant               X3_MPTR = {{ theta_mptr + 8 }};
    uint256 internal constant               X4_MPTR = {{ theta_mptr + 9 }};
    uint256 internal constant              X_N_MPTR = {{ theta_mptr + 26 }};
    uint256 internal constant  X_N_MINUS_1_INV_MPTR = {{ theta_mptr + 27 }};
    uint256 internal constant           L_LAST_MPTR = {{ theta_mptr + 28 }};
    uint256 internal constant          L_BLIND_MPTR = {{ theta_mptr + 29 }};
    uint256 internal constant              L_0_MPTR = {{ theta_mptr + 30 }};
    uint256 internal constant     INSTANCE_EVAL_MPTR = {{ theta_mptr + 31 }};
    uint256 internal constant     QUOTIENT_EVAL_MPTR = {{ theta_mptr + 32 }};
    uint256 internal constant     REVERSED_EVALS_MPTR = {{ reversed_evals_mptr }};
    uint256 internal constant      SELECTOR_ACC_MPTR = {{ selector_acc_mptr|hex() }};

    uint256 internal constant QUOTIENT_FRAME_BASE = {{ quotient_external.frame_base|hex() }};
    uint256 internal constant QUOTIENT_FRAME_LEN = {{ quotient_external.frame_len|hex() }};
    uint256 internal constant QUOTIENT_OUTPUT_LEN = {{ quotient_external.output_len|hex() }};
    uint256 internal constant QUOTIENT_MAGIC = {{ quotient_external.magic|hex_padded(64) }};

    fallback() external {
        assembly {
            if iszero(eq(calldatasize(), QUOTIENT_FRAME_LEN)) { revert(0, 0) }
            calldatacopy(QUOTIENT_FRAME_BASE, 0, QUOTIENT_FRAME_LEN)

            {%- if self.quotient_pow5_helper %}
            function q_pow5(x) -> z {
                let q_r := FR_MODULUS
                let x2 := mulmod(x, x, q_r)
                z := mulmod(x, mulmod(x2, x2, q_r), q_r)
            }
            {%- endif %}

            {%- if self.quotient_limb7_helper %}
            function q_limb7(x0, x1, x2, x3, x4, x5, x6) -> z {
                let q_r := FR_MODULUS
                z := addmod(x0, mulmod(0x100000000000000, x1, q_r), q_r)
                z := addmod(z, mulmod(0x10000000000000000000000000000, x2, q_r), q_r)
                z := addmod(z, mulmod(0x400000000, x3, q_r), q_r)
                z := addmod(z, mulmod(0x40000000000000000000000, x4, q_r), q_r)
                z := addmod(z, mulmod(0x1000, x5, q_r), q_r)
                z := addmod(z, mulmod(0x100000000000000000, x6, q_r), q_r)
            }
            {%- endif %}

            {%- if self.quotient_wide_limb7_helper %}
            function q_limb7_wide(x0, x1, x2, x3, x4, x5, x6) -> z {
                let q_r := FR_MODULUS
                z := addmod(x0, mulmod(0x100000000000000, x1, q_r), q_r)
                z := addmod(z, mulmod(0x10000000000000000000000000000, x2, q_r), q_r)
                z := addmod(z, mulmod(0x1000000000000000000000000000000000000000000, x3, q_r), q_r)
                z := addmod(z, mulmod(0x100000000000000000000000000000000000000000000000000000000, x4, q_r), q_r)
                z := addmod(z, mulmod(0x6bc66e553973f396854f5626172ba135587d41e37a68209402355093fdcaaf6c, x5, q_r), q_r)
                z := addmod(z, mulmod(0x63f31e3f446953960c9d6964474300df43ab29179970f642a28e39d6c883c74b, x6, q_r), q_r)
            }
            {%- endif %}

            let r := FR_MODULUS
            {%- include "QuotientNumeratorBlock.yul" %}

            mstore(0x00, QUOTIENT_MAGIC)
            mstore(0x20, mload(QUOTIENT_EVAL_MPTR))
            {%- if simple_selector_cols.len() > 0 %}
            for { let q_i := 0 } lt(q_i, {{ simple_selector_cols.len() }}) { q_i := add(q_i, 1) } {
                mstore(add(0x40, shl(5, q_i)), mload(add(SELECTOR_ACC_MPTR, shl(5, q_i))))
            }
            {%- endif %}
            return(0x00, QUOTIENT_OUTPUT_LEN)
        }
    }
}
