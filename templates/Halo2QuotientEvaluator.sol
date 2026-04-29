pragma solidity ^0.8.0;

// Generated quotient-evaluation helper for Halo2Verifier.
//
// The main verifier builds this contract's calldata from its own verified
// memory state and calls it with STATICCALL. The verifier also pins both
// runtime length and codehash, so user calldata cannot redirect the quotient
// state machine to different code.
contract Halo2QuotientEvaluator{{ helper.index }} {
    uint256 internal constant                VK_MPTR = {{ vk_mptr }};
    uint256 internal constant         VK_DIGEST_MPTR = {{ vk_mptr }};
    uint256 internal constant     NUM_INSTANCES_MPTR = {{ vk_mptr + 1 }};
    uint256 internal constant                 K_MPTR = {{ vk_mptr + 2 }};
    uint256 internal constant             N_INV_MPTR = {{ vk_mptr + 3 }};
    uint256 internal constant             OMEGA_MPTR = {{ vk_mptr + 4 }};
    uint256 internal constant         OMEGA_INV_MPTR = {{ vk_mptr + 5 }};
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = {{ vk_mptr + 6 }};

    uint256 internal constant CHALLENGE_MPTR = {{ challenge_mptr }};
    uint256 internal constant            THETA_MPTR = {{ theta_mptr }};
    uint256 internal constant             BETA_MPTR = {{ theta_mptr + 1 }};
    uint256 internal constant            GAMMA_MPTR = {{ theta_mptr + 2 }};
    uint256 internal constant TRASH_CHALLENGE_MPTR = {{ theta_mptr + 3 }};
    uint256 internal constant                Y_MPTR = {{ theta_mptr + 4 }};
    uint256 internal constant                X_MPTR = {{ theta_mptr + 5 }};
    uint256 internal constant           L_LAST_MPTR = {{ theta_mptr + 28 }};
    uint256 internal constant          L_BLIND_MPTR = {{ theta_mptr + 29 }};
    uint256 internal constant              L_0_MPTR = {{ theta_mptr + 30 }};
    uint256 internal constant     INSTANCE_EVAL_MPTR = {{ theta_mptr + 31 }};
    uint256 internal constant     REVERSED_EVALS_MPTR = {{ reversed_evals_mptr }};
    uint256 internal constant      SELECTOR_ACC_MPTR = {{ selector_acc_mptr|hex() }};

    uint256 internal constant FR_MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffeffffffff00000001;

    fallback() external {
        assembly ("memory-safe") {
            if iszero(eq(calldatasize(), {{ helper.input_len()|hex() }})) {
                revert(0, 0)
            }

            let quotient_eval_numer := calldataload(0)

            calldatacopy(0, {{ helper.io_len()|hex() }}, {{ helper.state_len|hex() }})
            {%- for col in helper.simple_selector_cols %}
            mstore(
                add(SELECTOR_ACC_MPTR, {{ (loop.index0 * 0x20)|hex() }}),
                calldataload({{ ((loop.index0 + 1) * 0x20)|hex() }})
            )
            {%- endfor %}

            let r := FR_MODULUS
            let delta := 3793952369011177517951424454785176000433849974408744014172535497121832470999
            let y := mload(Y_MPTR)

            {%- for code_block in helper.code_blocks %}
            {%- for line in code_block %}
            {{ line }}
            {%- endfor %}
            {%- endfor %}

            pop(y)
            pop(delta)

            mstore(0, quotient_eval_numer)
            {%- for col in helper.simple_selector_cols %}
            mstore(
                {{ ((loop.index0 + 1) * 0x20)|hex() }},
                mload(add(SELECTOR_ACC_MPTR, {{ (loop.index0 * 0x20)|hex() }}))
            )
            {%- endfor %}
            return(0, {{ helper.io_len()|hex() }})
        }
    }
}
