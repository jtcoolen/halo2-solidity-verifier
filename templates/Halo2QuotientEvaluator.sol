pragma solidity ^0.8.24;

/// @title Split Halo2 quotient numerator evaluator.
/// @notice Reconstructs the scalar side of the linearization query for a generated verifier.
/// @dev This is the split-out implementation of the expensive
/// `partially_evaluate_identities` / `compute_linearization_commitment` side
/// from the Midfall Rust verifier:
/// - `midfall/proofs/src/plonk/mod.rs::partially_evaluate_identities`
/// - `midfall/proofs/src/plonk/linearization/verifier.rs::compute_linearization_commitment`
/// - `midfall/proofs/src/plonk/{permutation,logup,trash}.rs`
/// @dev The main verifier has already parsed calldata, checked proof scalar
/// ranges, sampled Fiat-Shamir challenges, loaded the VK payload, and computed
/// local Lagrange/public-input values before making the staticcall.
///
/// Instead of receiving structured Solidity arguments, the evaluator receives
/// the verifier's memory frame as raw calldata:
///
///   calldata[0..QUOTIENT_FRAME_LEN)
///      == memory[QUOTIENT_FRAME_BASE..QUOTIENT_FRAME_BASE+QUOTIENT_FRAME_LEN)
///
/// The fallback copies that frame back into the same generated memory
/// addresses. All constants below are therefore memory addresses inside that
/// copied frame, not ABI offsets.
///
/// Output is a compact fixed frame consumed by Halo2Verifier:
///
///   word 0: QUOTIENT_MAGIC, a generated version/magic guard
///   word 1: linearization_expected_eval
///   word 2..: simple-selector accumulator scalars
///
/// This contract reconstructs the Rust verifier's y-batched identity numerator
/// nu_y(x) and returns the linearization expected scalar -nu_y(x). It does not
/// evaluate or trust a quotient scalar h(x).
///
/// The quotient limb commitments are handled by Halo2Verifier on the commitment
/// side as (1 - x^n) * sum_i x_split^i * Q_i. That is why this scalar side is
/// -nu_y(x), not h(x) = nu_y(x) / (x^n - 1).
///
/// See docs/QUOTIENT_NUMERATOR_EVALUATOR.md for the full Rust/Solidity mapping.
contract Halo2QuotientEvaluator {
    // BLS12-381 scalar field modulus. All arithmetic in this contract is over
    // Fr and uses addmod/mulmod with this modulus.
    uint256 internal constant FR_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // Start of the copied verifier-key payload in memory. The VK payload also
    // carries the compact quotient VM constant/program tables used by the
    // included numerator block.
    uint256 internal constant                VK_MPTR = {{ memory.vk_mptr }};

    // Fiat-Shamir challenge slots. Halo2Verifier sampled these in transcript
    // order before the external call. The evaluator only reads them.
    uint256 internal constant        CHALLENGE_MPTR = {{ memory.challenge_mptr }};
    uint256 internal constant            THETA_MPTR = {{ memory.theta_mptr }};
    uint256 internal constant             BETA_MPTR = {{ memory.beta_mptr }};
    uint256 internal constant            GAMMA_MPTR = {{ memory.gamma_mptr }};
    uint256 internal constant TRASH_CHALLENGE_MPTR = {{ memory.trash_challenge_mptr }};
    uint256 internal constant                Y_MPTR = {{ memory.y_mptr }};
    uint256 internal constant                X_MPTR = {{ memory.x_mptr }};
    uint256 internal constant               X1_MPTR = {{ memory.x1_mptr }};
    uint256 internal constant               X2_MPTR = {{ memory.x2_mptr }};
    uint256 internal constant               X3_MPTR = {{ memory.x3_mptr }};
    uint256 internal constant               X4_MPTR = {{ memory.x4_mptr }};

    // Common polynomial values at x. Halo2Verifier computes these once after
    // sampling x and places them in the frame so the numerator block can share
    // the exact Rust verifier inputs.
    uint256 internal constant              X_N_MPTR = {{ memory.x_n_mptr }};
    uint256 internal constant  X_N_MINUS_1_INV_MPTR = {{ memory.x_n_minus_1_inv_mptr }};
    uint256 internal constant           L_LAST_MPTR = {{ memory.l_last_mptr }};
    uint256 internal constant          L_BLIND_MPTR = {{ memory.l_blind_mptr }};
    uint256 internal constant              L_0_MPTR = {{ memory.l_0_mptr }};
    uint256 internal constant     INSTANCE_EVAL_MPTR = {{ memory.instance_eval_mptr }};
    uint256 internal constant     QUOTIENT_EVAL_MPTR = {{ memory.quotient_eval_mptr }};

    // Proof evaluation table. Values are already decoded as canonical Fr words
    // by Halo2Verifier. The generated numerator code indexes this table by the
    // same query order as the Rust verifier.
    uint256 internal constant     REVERSED_EVALS_MPTR = {{ memory.reversed_evals_mptr }};

    // Scratch/output region for simple-selector linearization accumulators.
    // The numerator block writes one bucket per simple selector, then the
    // fallback copies those buckets into the compact return frame.
    uint256 internal constant      SELECTOR_ACC_MPTR = {{ memory.selector_acc_mptr|hex() }};
    // Callee-local scratch for trace hooks. Trace-enabled verifier builds call
    // this evaluator with CALL so quotient identity logs can be compared with
    // the native Rust trace. Production verifier builds keep using STATICCALL
    // and render this evaluator without trace hooks.
    uint256 internal constant        TRACE_U256_MPTR = {{ memory.quotient_return_mptr|hex() }};
    uint256 internal constant    QUOTIENT_OUTPUT_MPTR = {{ memory.quotient_return_mptr|hex() }};

    // External-call frame metadata. The main verifier calls this contract with
    // exactly QUOTIENT_FRAME_LEN bytes starting at
    // QUOTIENT_FRAME_BASE, then checks the return length and QUOTIENT_MAGIC.
    uint256 internal constant QUOTIENT_FRAME_BASE = {{ quotient_external.frame_base|hex() }};
    uint256 internal constant QUOTIENT_FRAME_LEN = {{ quotient_external.frame_len|hex() }};
    uint256 internal constant QUOTIENT_OUTPUT_LEN = {{ quotient_external.output_len|hex() }};
    uint256 internal constant QUOTIENT_MAGIC = {{ quotient_external.magic|hex_padded(64) }};

    /// @notice Evaluate the generated quotient numerator block for one verifier memory frame.
    /// @dev Calldata is exactly the raw frame, not ABI-encoded arguments. Returns `QUOTIENT_MAGIC`, the linearization expected eval, and selector buckets.
    /// @dev This fallback also uses generated absolute memory addresses and
    /// returns directly from assembly. Its compact return frame starts at
    /// `0x80`, preserving Solidity's reserved memory words.
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

            let r := FR_MODULUS

            {%- if self.trace %}
            function trace_u256(id, value) {
                mstore(TRACE_U256_MPTR, value)
                log1(TRACE_U256_MPTR, 0x20, id)
            }
            {%- endif %}

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
            //
            // The upstream Rust comments call out that simple multiplicative
            // selectors do not appear as normal proof eval scalars. The Yul
            // block mirrors that rule by accumulating those identities into
            // SELECTOR_ACC_MPTR buckets for later multiplication by fixed
            // selector commitments, while fully evaluated identities contribute
            // to the negated expected scalar.
            {%- include "QuotientHelpers.yul" %}
            {%- include "QuotientNumeratorBlock.yul" %}

            // Return the compact output frame. Halo2Verifier checks the magic,
            // stores word 1 as the linearization expected eval, then expands
            // selector buckets into the fused final PCS MSM.
            mstore(QUOTIENT_OUTPUT_MPTR, QUOTIENT_MAGIC)
            mstore(add(QUOTIENT_OUTPUT_MPTR, 0x20), mload(QUOTIENT_EVAL_MPTR))
            {%- if simple_selector_cols.len() > 0 %}
            for { let q_i := 0 } lt(q_i, {{ simple_selector_cols.len() }}) { q_i := add(q_i, 1) } {
                mstore(add(QUOTIENT_OUTPUT_MPTR, add(0x40, shl(5, q_i))), mload(add(SELECTOR_ACC_MPTR, shl(5, q_i))))
            }
            {%- endif %}
            return(QUOTIENT_OUTPUT_MPTR, QUOTIENT_OUTPUT_LEN)
        }
    }
}
