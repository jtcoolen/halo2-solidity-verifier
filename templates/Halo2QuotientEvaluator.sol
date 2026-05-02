pragma solidity ^0.8.24;

// Native quotient evaluator for Halo2Verifier.
//
// This contract is the split-out implementation of the expensive
// `partially_evaluate_identities` / `compute_linearization_commitment` scalar
// side from the Midfall Rust verifier. It is deliberately tiny at the ABI
// boundary: the main verifier has already parsed calldata, checked proof
// scalar ranges, sampled Fiat-Shamir challenges, loaded the VK payload, and
// computed local Lagrange/public-input values.
//
// Instead of receiving structured Solidity arguments, the evaluator receives
// the verifier's memory frame as raw calldata:
//
//   calldata[0..QUOTIENT_FRAME_LEN)
//      == memory[QUOTIENT_FRAME_BASE..QUOTIENT_FRAME_BASE+QUOTIENT_FRAME_LEN)
//
// The fallback copies that frame back into the same generated memory
// addresses. All constants below are therefore memory addresses inside that
// copied frame, not ABI offsets.
//
// Output is a compact fixed frame consumed by Halo2Verifier:
//
//   word 0: QUOTIENT_MAGIC, a generated version/magic guard
//   word 1: linearization_expected_eval
//   word 2..: simple-selector accumulator scalars
//
// This contract reconstructs the Rust verifier's y-batched identity numerator
// nu_y(x) and returns the linearization expected scalar -nu_y(x). It does not
// evaluate or trust a quotient scalar h(x).
//
// The quotient limb commitments are handled by Halo2Verifier on the commitment
// side as (1 - x^n) * sum_i x_split^i * Q_i. That is why this scalar side is
// -nu_y(x), not h(x) = nu_y(x) / (x^n - 1).
//
// See docs/QUOTIENT_NUMERATOR_EVALUATOR.md for the full Rust/Solidity mapping.
contract Halo2QuotientEvaluator {
    // BLS12-381 scalar field modulus. All arithmetic in this contract is over
    // Fr and uses addmod/mulmod with this modulus.
    uint256 internal constant FR_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // Start of the copied verifier-key payload in memory. The VK payload also
    // carries the compact quotient VM constant/program tables used by the
    // included numerator block.
    uint256 internal constant                VK_MPTR = {{ vk_mptr }};

    // Fiat-Shamir challenge slots. Halo2Verifier sampled these in transcript
    // order before the external call. The evaluator only reads them.
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

    // Common polynomial values at x. Halo2Verifier computes these once after
    // sampling x and places them in the frame so the numerator block can share
    // the exact Rust verifier inputs.
    uint256 internal constant              X_N_MPTR = {{ theta_mptr + 26 }};
    uint256 internal constant  X_N_MINUS_1_INV_MPTR = {{ theta_mptr + 27 }};
    uint256 internal constant           L_LAST_MPTR = {{ theta_mptr + 28 }};
    uint256 internal constant          L_BLIND_MPTR = {{ theta_mptr + 29 }};
    uint256 internal constant              L_0_MPTR = {{ theta_mptr + 30 }};
    uint256 internal constant     INSTANCE_EVAL_MPTR = {{ theta_mptr + 31 }};
    uint256 internal constant     QUOTIENT_EVAL_MPTR = {{ theta_mptr + 32 }};

    // Proof evaluation table. Values are already decoded as canonical Fr words
    // by Halo2Verifier. The generated numerator code indexes this table by the
    // same query order as the Rust verifier.
    uint256 internal constant     REVERSED_EVALS_MPTR = {{ reversed_evals_mptr }};

    // Scratch/output region for simple-selector linearization accumulators.
    // The numerator block writes one bucket per simple selector, then the
    // fallback copies those buckets into the compact return frame.
    uint256 internal constant      SELECTOR_ACC_MPTR = {{ selector_acc_mptr|hex() }};

    // External-call frame metadata. The main verifier staticcalls this
    // contract with exactly QUOTIENT_FRAME_LEN bytes starting at
    // QUOTIENT_FRAME_BASE, then checks the return length and QUOTIENT_MAGIC.
    uint256 internal constant QUOTIENT_FRAME_BASE = {{ quotient_external.frame_base|hex() }};
    uint256 internal constant QUOTIENT_FRAME_LEN = {{ quotient_external.frame_len|hex() }};
    uint256 internal constant QUOTIENT_OUTPUT_LEN = {{ quotient_external.output_len|hex() }};
    uint256 internal constant QUOTIENT_MAGIC = {{ quotient_external.magic|hex_padded(64) }};

    fallback() external {
        assembly ("memory-safe") {
            // Reject malformed calls. This contract is not a general-purpose
            // ABI endpoint; accepting partial or shifted frames would make the
            // generated memory addresses point at the wrong data.
            if iszero(eq(calldatasize(), QUOTIENT_FRAME_LEN)) { revert(0, 0) }

            // Rehydrate the verifier memory image. From this point onward the
            // generated Yul can use the same MPTR constants as the monolithic
            // verifier path.
            calldatacopy(QUOTIENT_FRAME_BASE, 0, QUOTIENT_FRAME_LEN)

            {%- if self.quotient_pow5_helper %}
            // Reusable x^5 helper for recurring Midfall custom-gate terms.
            //
            // Rust source shape:
            //   circuits/src/hash/poseidon/poseidon_chip.rs::sbox
            //   full_round_gate / partial_round_gate
            //   circuits/src/hash/poseidon/round_skips.rs::RoundId
            //
            // The Rust verifier only sees this as an Expression tree from
            // `vk.cs.gates`; the generator emits q_pow5 after recognizing five
            // equal multiplicative factors. It is a codegen shortcut for the
            // Poseidon S-box x^5, not a separate verifier rule.
            function q_pow5(x) -> z {
                let q_r := FR_MODULUS
                let x2 := mulmod(x, x, q_r)
                z := mulmod(x, mulmod(x2, x2, q_r), q_r)
            }
            {%- endif %}

            {%- if self.quotient_limb7_helper %}
            // Compact evaluator for a recurring 7-limb linear combination.
            //
            // Rust source shape:
            //   circuits/src/field/foreign/params.rs::base_powers
            //   foreign/gates/norm.rs::Foreign-field normalization
            //   foreign/gates/mul.rs::Foreign-field multiplication
            //
            // This is the Fr evaluation of sum_i base_powers[i] * limb_i for
            // the generated 7-limb foreign-field basis. It is used for the
            // normalization gate and the sum_x/sum_y/sum_z pieces of the
            // multiplication gate. The constants are VK/codegen constants,
            // never proof-selected values.
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
            // Wide variant for the pairwise-product side of foreign-field
            // multiplication.
            //
            // Rust source shape:
            //   foreign/gates/mul.rs::Foreign-field multiplication
            //   xys = pair_wise_prod(xs, ys)
            //   sum_exprs(double_base_powers, xys)
            //
            // The native multiplication callbacks group repeated 7-term slices
            // of the double-base product-convolution basis into q_limb7_wide.
            // This keeps the lowered quotient expression smaller while
            // computing the same gate polynomial over Fr.
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

            // This included block is the main body of the evaluator. It:
            //   1. evaluates gate/permutation/lookup/trash identities in the
            //      same order as Rust `partially_evaluate_identities`;
            //   2. y-batches fully evaluated identities into
            //      quotient_eval_numer;
            //   3. y-batches simple-selector identities into
            //      SELECTOR_ACC_MPTR buckets;
            //   4. writes -quotient_eval_numer to QUOTIENT_EVAL_MPTR.
            //
            // Depending on codegen settings, some identities are native Yul
            // callbacks and the rest are executed by the compact q_program VM
            // stored in the copied VK payload.
            {%- include "QuotientNumeratorBlock.yul" %}

            // Return the compact output frame. Halo2Verifier checks the magic,
            // stores word 1 as the linearization expected eval, then expands
            // selector buckets into the fused final PCS MSM.
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
