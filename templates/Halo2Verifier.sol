
pragma solidity ^0.8.24;

/// @title Halo2 BLS12-381 KZG verifier.
/// @notice Circuit-specialized verifier for Midfall/midnight-proofs Halo2
/// proofs rendered by this repository's Rust generator.
/// @dev This contract ports the verifier flow from
/// `midfall/proofs/src/plonk/verifier.rs`, the Keccak transcript comments from
/// `midfall/proofs/src/transcript/implementors.rs`, and the KZG multi-open
/// comments from `midfall/proofs/src/poly/kzg/mod.rs`.
/// @dev It is not a generic verifier. The proof layout, VK payload, quotient
/// identity program, memory layout, and optional quotient evaluator are all
/// generated for one `VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>`.
///
/// Halo2 KZG verifier for the BLS12-381 curve, midnight-proofs flavour.
///
/// Differences vs the original BN254 / halo2 v0.4 template:
//
/// - BLS12-381 base field Fp is 381 bits and does not fit in a uint256.
///   Each Fp coord is encoded EIP-2537 padded (16 zero bytes + 48 bytes).
///   A G1 point is 128 bytes (4 words); a G2 point is 256 bytes (8).
/// - Calldata carries G1 commitments in uncompressed EIP-2537 padded
///   form (4 words = 128 bytes per point: x_hi, x_lo, y_hi, y_lo). The
///   proof bytes produced by midnight-proofs prover are repacked off
///   chain (compressed -> uncompressed) before being passed to
///   `verifyProof`. The verifier hashes the uncompressed 128-byte form into
///   the transcript verbatim, matching `Hashable<Keccak256> for
///   G1Projective::to_input`; see `common_uncompressed_g1`.
/// - Transcript `common` absorbs raw inputs in order. `squeeze` computes one
///   Keccak digest, resets the transcript buffer to that digest, then samples
///   by interpreting the digest as a big-endian integer modulo r.
/// - Scalar inversion uses modexp(scalar, r-2, r).
/// - Constructors run a deployment-time smoke test for the EIP-2537
///   precompiles using identity inputs. Compile with Solidity >=0.8.24 and
///   deploy only on chains/forks that support MCOPY and EIP-2537.
contract Halo2Verifier {
    /// @notice Reverts when a pinned verifier dependency no longer matches its generated code hash.
    /// @dev Covers the external verifying-key contract and, in split mode, the quotient evaluator.
    error InvalidVerifierDependency();

    {%- match self.expected_vk_codehash %}
    {%- when Some with (expected_vk_codehash) %}
    /// @notice Verifying-key contract address authorized for this verifier.
    /// @dev The runtime length and codehash are pinned by generated constants and checked at construction and verification time.
    address public immutable AUTHORIZED_VK;
    uint256 internal constant EXPECTED_VK_LENGTH = {{ vk_len }};
    bytes32 internal constant EXPECTED_VK_CODEHASH = bytes32({{ expected_vk_codehash|hex_padded(64) }});
    {%- when None %}
    {%- endmatch %}
    {%- match quotient_external %}
    {%- when Some with (_) %}
    /// @notice Quotient evaluator contract authorized for split quotient reconstruction.
    /// @dev The evaluator returns the linearization expected scalar and selector buckets; its runtime may be pinned by generated constants.
    address public immutable AUTHORIZED_QUOTIENT;
    {%- match self.expected_quotient_codehash %}
    {%- when Some with (expected_quotient_codehash) %}
    uint256 internal constant EXPECTED_QUOTIENT_LENGTH = {{ self.expected_quotient_len.unwrap() }};
    bytes32 internal constant EXPECTED_QUOTIENT_CODEHASH = bytes32({{ expected_quotient_codehash|hex_padded(64) }});
    {%- when None %}
    {%- endmatch %}
    {%- when None %}
    {%- endmatch %}

    uint256 internal constant    PROOF_LEN_CPTR = {{ proof_cptr - 1 }};
    uint256 internal constant        PROOF_CPTR = {{ proof_cptr }};
    uint256 internal constant NUM_INSTANCE_CPTR = {{ num_instance_cptr|hex_padded(2) }};
    uint256 internal constant     INSTANCE_CPTR = {{ instance_cptr|hex_padded(2) }};

    // ----------------------------------------------------------------------
    // Verifying-key memory map. The VK header lives at VK_MPTR, followed
    // by the quotient VM payload and commitments. After the full VK
    // runtime comes the challenge slots (challenge_mptr..) and the
    // per-stage scratch (theta_mptr..).
    // ----------------------------------------------------------------------
    uint256 internal constant                VK_MPTR = {{ memory.vk_mptr }};
    uint256 internal constant         VK_DIGEST_MPTR = {{ memory.vk_mptr }};
    uint256 internal constant     NUM_INSTANCES_MPTR = {{ memory.vk_mptr + 1 }};
    uint256 internal constant                 K_MPTR = {{ memory.vk_mptr + 2 }};
    uint256 internal constant             N_INV_MPTR = {{ memory.vk_mptr + 3 }};
    uint256 internal constant             OMEGA_MPTR = {{ memory.vk_mptr + 4 }};
    uint256 internal constant         OMEGA_INV_MPTR = {{ memory.vk_mptr + 5 }};
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = {{ memory.vk_mptr + 6 }};
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = {{ memory.vk_mptr + 7 }};
    uint256 internal constant        ACC_OFFSET_MPTR = {{ memory.vk_mptr + 8 }};
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = {{ memory.vk_mptr + 9 }};
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = {{ memory.vk_mptr + 10 }};
    uint256 internal constant            G1_BASE_MPTR = {{ memory.vk_mptr + 11 }};
    uint256 internal constant            G2_BASE_MPTR = {{ memory.vk_mptr + 15 }};
    uint256 internal constant      NEG_S_G2_BASE_MPTR = {{ memory.vk_mptr + 23 }};

    uint256 internal constant CHALLENGE_MPTR = {{ memory.challenge_mptr }};

    // Challenge layout. Squeeze order in midnight-proofs:
    //   user_phase challenges (variable count)
    //   theta -> beta, gamma -> trash_challenge -> y -> x ->
    //   x1, x2 -> x3 -> x4
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

    // Batch-open commitments live in 4-word EIP-2537 padded slots.
    uint256 internal constant             F_COM_MPTR = {{ memory.f_com_mptr }};
    uint256 internal constant                PI_MPTR = {{ memory.pi_mptr }};

    // Accumulator (KZG IVC).
    uint256 internal constant          ACC_LHS_MPTR = {{ memory.acc_lhs_mptr }};
    uint256 internal constant          ACC_RHS_MPTR = {{ memory.acc_rhs_mptr }};

    // Lagrange / linearization scratch.
    uint256 internal constant              X_N_MPTR = {{ memory.x_n_mptr }};
    uint256 internal constant  X_N_MINUS_1_INV_MPTR = {{ memory.x_n_minus_1_inv_mptr }};
    uint256 internal constant           L_LAST_MPTR = {{ memory.l_last_mptr }};
    uint256 internal constant          L_BLIND_MPTR = {{ memory.l_blind_mptr }};
    uint256 internal constant              L_0_MPTR = {{ memory.l_0_mptr }};
    uint256 internal constant     INSTANCE_EVAL_MPTR = {{ memory.instance_eval_mptr }};
    // Legacy name: this is not h(x). It stores the expected opening
    // scalar for the linearized commitment, i.e. the negated y-batched
    // identity numerator reconstructed from the alleged evals at x.
    uint256 internal constant     QUOTIENT_EVAL_MPTR = {{ memory.quotient_eval_mptr }};
    uint256 internal constant         QUOTIENT_MPTR = {{ memory.quotient_mptr }};   // 4 words
    uint256 internal constant            F_EVAL_MPTR = {{ memory.f_eval_mptr }};
    uint256 internal constant                 V_MPTR = {{ memory.v_mptr }};
    uint256 internal constant         FINAL_COM_MPTR = {{ memory.final_com_mptr }};   // 4 words
    uint256 internal constant      PAIRING_LHS_MPTR = {{ memory.pairing_lhs_mptr }};   // 4 words
    uint256 internal constant      PAIRING_RHS_MPTR = {{ memory.pairing_rhs_mptr }};   // 4 words

    // Multi-prepare scratch (sized at codegen time).
    uint256 internal constant       ROT_POINTS_MPTR = {{ memory.rot_points_mptr }};
    uint256 internal constant       X1_POWERS_MPTR = {{ memory.x1_powers_mptr }};
    // Q_COM materialization is currently fused into the final MSM scratch,
    // so this marker intentionally aliases Q_EVAL_SET_MPTR and has zero
    // reserved capacity until a future emitter starts writing Q_COM_MPTR.
    uint256 internal constant            Q_COM_MPTR = {{ memory.q_com_mptr }};
    uint256 internal constant      Q_EVAL_SET_MPTR = {{ memory.q_eval_set_mptr }};

    // Q_EVAL_CPTR is set at runtime once the verifier reaches the q_evals
    // block of the proof; we keep it as a memory slot for symmetry.
    uint256 internal constant         Q_EVAL_CPTR_MPTR = {{ memory.q_eval_cptr_mptr }};

    // Reserved 4-word slot for the G1 identity (point at infinity) in
    // EIP-2537 padded form. EVM memory is zero-initialised, and we
    // never write to this region, so the four `mload`s below produce
    // 0,0,0,0 which is exactly the identity encoding the EIP-2537
    // ec_add / ec_mul precompiles accept.
    uint256 internal constant       G1_IDENTITY_MPTR = {{ memory.g1_identity_mptr }};

    // Decoded polynomial-eval buffer (Optimisation H3). The off-chain
    // Solidity proof shim rewrites proof scalars into canonical BE words,
    // so `calldataload` gives the field element directly. The transcript-
    // side `evaluations` loop range-checks and spills that value here so
    // downstream eval references (gate evaluator + PCS q_eval Horner)
    // become 3-gas `mload(...)` instead of calldata reads.
    uint256 internal constant     REVERSED_EVALS_MPTR = {{ memory.reversed_evals_mptr }};
    uint256 internal constant      SELECTOR_ACC_MPTR = {{ memory.selector_acc_mptr|hex() }};
    uint256 internal constant  BATCH_INV_SCRATCH_MPTR = {{ memory.batch_invert_scratch_mptr|hex() }};
    uint256 internal constant        TRACE_U256_MPTR = {{ memory.trace_u256_mptr|hex() }};

    // ----------------------------------------------------------------------
    // Per-category bases for EIP-2537 padded G1 commitments. The proof
    // calldata carries 128-byte uncompressed/padded G1s after the off-chain
    // proof shim repacks midnight-proofs' native compressed stream; this
    // region stores the 4-word slots used by PCS / quotient-fold sections.
    //
    // Cumulative offsets (in words from `comms_mptr_base`):
    //   ADVICE_COMMS_MPTR_BASE          + 0
    //   LOOKUP_M_COMMS_MPTR_BASE        + 4*total_advices
    //   PERM_Z_COMMS_MPTR_BASE          + 4*total_advices + 4*num_lookups
    //   LOOKUP_HELPER_COMMS_MPTR_BASE   + ... + 4*num_permutation_zs
    //   LOOKUP_Z_COMMS_MPTR_BASE        + ... + 4*lookup_helper_chunks_total
    //   TRASHCAN_COMMS_MPTR_BASE        + ... + 4*num_lookups
    //   QUOTIENT_LIMB_COMMS_MPTR_BASE   + ... + 4*num_trashcans
    // ----------------------------------------------------------------------
    uint256 internal constant         ADVICE_COMMS_MPTR_BASE = {{ memory.advice_comms_mptr_base }};
    uint256 internal constant       LOOKUP_M_COMMS_MPTR_BASE = {{ memory.lookup_m_comms_mptr_base }};
    uint256 internal constant         PERM_Z_COMMS_MPTR_BASE = {{ memory.perm_z_comms_mptr_base }};
    uint256 internal constant  LOOKUP_HELPER_COMMS_MPTR_BASE = {{ memory.lookup_helper_comms_mptr_base }};
    uint256 internal constant       LOOKUP_Z_COMMS_MPTR_BASE = {{ memory.lookup_z_comms_mptr_base }};
    uint256 internal constant     TRASHCAN_COMMS_MPTR_BASE = {{ memory.trashcan_comms_mptr_base }};
    uint256 internal constant QUOTIENT_LIMB_COMMS_MPTR_BASE = {{ memory.quotient_limb_comms_mptr_base }};

    // Fr modulus.
    uint256 internal constant FR_MODULUS        = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // BLS12-381 Fp modulus minus one, split like an EIP-2537 coordinate:
    // high word = 16 zero bytes || top 16 coordinate bytes, low word =
    // bottom 32 coordinate bytes.
    uint256 internal constant BLS_P_HI             = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 internal constant BLS_P_MINUS_ONE_LO   = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa;
    uint256 internal constant BLS_P_MINUS_ONE_PACKED_0 = 0x00000000f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa;
    uint256 internal constant BLS_P_MINUS_ONE_PACKED_0_WITH_ID_FLAG = 0x00000000f38512bf6730d2a0f6b0f6241eabfffeb153ffffbafeffffffffaaaa;
    uint256 internal constant BLS_P_MINUS_ONE_PACKED_1 = 0x0000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84;

    /// @notice Smoke-check the BLS12-381 precompiles required by the verifier.
    /// @dev Uses identity inputs to catch absent EIP-2537 implementations, short return data, and incompatible pairing semantics at deployment.
    function require_eip2537_precompiles() private view {
        assembly ("memory-safe") {
            let scratch := 0x80
            for { let off := 0 } lt(off, 0x180) { off := add(off, 0x20) } {
                mstore(add(scratch, off), 0)
            }

            // G1ADD(identity, identity) -> identity, 128-byte return.
            if iszero(staticcall(50000, 0x0b, scratch, 0x100, scratch, 0x80)) { revert(0, 0) }
            if iszero(eq(returndatasize(), 0x80)) { revert(0, 0) }
            if or(or(mload(scratch), mload(add(scratch, 0x20))), or(mload(add(scratch, 0x40)), mload(add(scratch, 0x60)))) {
                revert(0, 0)
            }

            // G1MSM([(identity, 0)]) -> identity, 128-byte return.
            if iszero(staticcall(60000, 0x0c, scratch, 0xa0, scratch, 0x80)) { revert(0, 0) }
            if iszero(eq(returndatasize(), 0x80)) { revert(0, 0) }
            if or(or(mload(scratch), mload(add(scratch, 0x20))), or(mload(add(scratch, 0x40)), mload(add(scratch, 0x60)))) {
                revert(0, 0)
            }

            // PAIRING_CHECK([(identity_g1, identity_g2)]) -> true,
            // 32-byte return. This catches absent pairing precompiles,
            // short return data, and obviously incompatible semantics.
            if iszero(staticcall(120000, 0x0f, scratch, 0x180, scratch, 0x20)) { revert(0, 0) }
            if iszero(eq(returndatasize(), 0x20)) { revert(0, 0) }
            if iszero(eq(mload(scratch), 1)) { revert(0, 0) }
        }
    }

    {%- match self.expected_vk_codehash %}
    {%- when Some with (_) %}
    {%- match quotient_external %}
    {%- when Some with (_) %}
    /// @notice Create a verifier pinned to a verifying key and quotient evaluator.
    /// @dev Checks EIP-2537 availability and verifies both dependency runtimes before storing their addresses.
    /// @param authorizedVk Address of the generated `Halo2VerifyingKey` runtime.
    /// @param authorizedQuotient Address of the generated `Halo2QuotientEvaluator` runtime.
    constructor(address authorizedVk, address authorizedQuotient) {
        require_eip2537_precompiles();
        require(
            authorizedVk.code.length == EXPECTED_VK_LENGTH
                && authorizedVk.codehash == EXPECTED_VK_CODEHASH,
            "invalid vk"
        );
        {%- match self.expected_quotient_codehash %}
        {%- when Some with (_) %}
        require(
            authorizedQuotient.code.length == EXPECTED_QUOTIENT_LENGTH
                && authorizedQuotient.codehash == EXPECTED_QUOTIENT_CODEHASH,
            "invalid quotient"
        );
        {%- when None %}
        {%- endmatch %}
        AUTHORIZED_VK = authorizedVk;
        AUTHORIZED_QUOTIENT = authorizedQuotient;
        {%- match self.expected_quotient_codehash %}
        {%- when Some with (_) %}
        {%- when None %}
        {%- endmatch %}
    }
    {%- when None %}
    /// @notice Create a verifier pinned to a generated verifying key.
    /// @dev Checks EIP-2537 availability and verifies the VK runtime before storing its address.
    /// @param authorizedVk Address of the generated `Halo2VerifyingKey` runtime.
    constructor(address authorizedVk) {
        require_eip2537_precompiles();
        require(
            authorizedVk.code.length == EXPECTED_VK_LENGTH
                && authorizedVk.codehash == EXPECTED_VK_CODEHASH,
            "invalid vk"
        );
        AUTHORIZED_VK = authorizedVk;
    }
    {%- endmatch %}
    {%- when None %}
    {%- match quotient_external %}
    {%- when Some with (_) %}
    /// @notice Create a verifier pinned to a quotient evaluator.
    /// @dev Used when the VK is embedded in the verifier but quotient reconstruction is split out.
    /// @param authorizedQuotient Address of the generated `Halo2QuotientEvaluator` runtime.
    constructor(address authorizedQuotient) {
        require_eip2537_precompiles();
        {%- match self.expected_quotient_codehash %}
        {%- when Some with (_) %}
        require(
            authorizedQuotient.code.length == EXPECTED_QUOTIENT_LENGTH
                && authorizedQuotient.codehash == EXPECTED_QUOTIENT_CODEHASH,
            "invalid quotient"
        );
        {%- when None %}
        {%- endmatch %}
        AUTHORIZED_QUOTIENT = authorizedQuotient;
        {%- match self.expected_quotient_codehash %}
        {%- when Some with (_) %}
        {%- when None %}
        {%- endmatch %}
    }
    {%- when None %}
    /// @notice Create a verifier with embedded verifier data.
    /// @dev Checks EIP-2537 availability at deployment.
    constructor() {
        require_eip2537_precompiles();
    }
    {%- endmatch %}
    {%- endmatch %}

    /// @notice Verify a Halo2/Midfall proof for the generated verifying key.
    /// @dev This checks only that `proof` verifies for the supplied public
    /// `instances` under this pinned VK/protocol. Application contracts must
    /// bind the meaning of those instances separately: state roots, program
    /// identifiers, expected IVC outputs, chain/domain separation, and any
    /// protocol-specific authorization are outside this raw verifier ABI.
    /// @dev Production renders are success-or-revert: accepted proofs return
    /// `true`, while malformed calldata, invalid proof material, failed
    /// precompiles, or mismatched pinned dependency code revert. Trace and gas
    /// renders keep the same failure policy.
    /// @param proof Solidity-facing proof bytes, with G1 elements repacked into EIP-2537 padded uncompressed form.
    /// @param instances Public instance scalars encoded as canonical BLS12-381 scalar-field words.
    /// @return Always `true` for accepted proofs; invalid proofs revert instead of returning `false`.
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) external {%- if self.trace || self.gas_checkpoints %} returns (bool) {%- else %} view returns (bool) {%- endif %} {
        assembly ("memory-safe") {
            if iszero(and(eq(calldataload(0x04), 0x40), eq(calldataload(0x24), sub(NUM_INSTANCE_CPTR, 4)))) {
                revert(0, 0)
            }
        }

        {%- match self.embedded_vk %}
        {%- when None %}
        address vk = AUTHORIZED_VK;
        if (vk.code.length != EXPECTED_VK_LENGTH || vk.codehash != EXPECTED_VK_CODEHASH) {
            revert InvalidVerifierDependency();
        }
        {%- else %}
        {%- endmatch %}
        {%- match quotient_external %}
        {%- when Some with (_) %}
        address quotientEvaluator = AUTHORIZED_QUOTIENT;
        {%- match self.expected_quotient_codehash %}
        {%- when Some with (_) %}
        if (
            quotientEvaluator.code.length != EXPECTED_QUOTIENT_LENGTH
                || quotientEvaluator.codehash != EXPECTED_QUOTIENT_CODEHASH
        ) {
            revert InvalidVerifierDependency();
        }
        {%- when None %}
        {%- endmatch %}
        {%- when None %}
        {%- endmatch %}
        assembly ("memory-safe") {
            // ===============================================================
            // Helpers: modexp, transcript, EIP-2537 calls
            // ===============================================================

            // Inverse of a Fr scalar via modexp(x, r-2, r). The verifier
            // calls this only after transcript absorption is complete, so it
            // reuses the dead transcript buffer just below VK_MPTR instead of
            // a fixed post-VK address that can collide with live PCS scratch
            // when the VK payload becomes smaller.
            function scalar_inv(x) -> inv {
                if iszero(x) { revert(0, 0) }
                let p := sub(VK_MPTR, 0x100)
                mstore(p,            0x20)        // base len
                mstore(add(p, 0x20), 0x20)        // exp len
                mstore(add(p, 0x40), 0x20)        // mod len
                mstore(add(p, 0x60), x)
                mstore(add(p, 0x80), sub(FR_MODULUS, 2))
                mstore(add(p, 0xa0), FR_MODULUS)
                if iszero(staticcall(gas(), 0x05, p, 0xc0, p, 0x20)) { revert(0, 0) }
                if iszero(eq(returndatasize(), 0x20)) { revert(0, 0) }
                inv := mload(p)
            }

            {%- if self.quotient_pow5_helper %}
            // VK-specialized identity helper for Poseidon S-box terms.
            //
            // Rust source shape:
            //   circuits/src/hash/poseidon/poseidon_chip.rs::sbox
            //   full_round_gate / partial_round_gate
            //   circuits/src/hash/poseidon/round_skips.rs::RoundId
            //
            // The Rust verifier only sees this as an Expression tree from
            // `vk.cs.gates`; the generator emits q_pow5 after recognizing five
            // equal multiplicative factors. It is a codegen shortcut for x^5,
            // not a separate verifier rule.
            function q_pow5(x) -> z {
                let x2 := mulmod(x, x, FR_MODULUS)
                z := mulmod(x, mulmod(x2, x2, FR_MODULUS), FR_MODULUS)
            }

            {%- endif %}
            {%- if self.quotient_limb7_helper %}
            // Compact evaluator for a recurring 7-limb foreign-field linear
            // combination.
            //
            // Rust source shape:
            //   circuits/src/field/foreign/params.rs::base_powers
            //   foreign/gates/norm.rs::Foreign-field normalization
            //   foreign/gates/mul.rs::Foreign-field multiplication
            //
            // This evaluates sum_i base_powers[i] * limb_i over Fr for this
            // generated 7-limb basis. It is used for normalization and the
            // sum_x/sum_y/sum_z pieces of multiplication.
            function q_limb7(x0, x1, x2, x3, x4, x5, x6) -> z {
                z := addmod(x0, mulmod(0x100000000000000, x1, FR_MODULUS), FR_MODULUS)
                z := addmod(z, mulmod(0x10000000000000000000000000000, x2, FR_MODULUS), FR_MODULUS)
                z := addmod(z, mulmod(0x400000000, x3, FR_MODULUS), FR_MODULUS)
                z := addmod(z, mulmod(0x40000000000000000000000, x4, FR_MODULUS), FR_MODULUS)
                z := addmod(z, mulmod(0x1000, x5, FR_MODULUS), FR_MODULUS)
                z := addmod(z, mulmod(0x100000000000000000, x6, FR_MODULUS), FR_MODULUS)
            }

            {%- endif %}
            {%- if self.quotient_wide_limb7_helper %}
            // Wide helper for the pairwise-product side of foreign-field
            // multiplication.
            //
            // Rust source shape:
            //   foreign/gates/mul.rs::Foreign-field multiplication
            //   xys = pair_wise_prod(xs, ys)
            //   sum_exprs(double_base_powers, xys)
            //
            // Native multiplication callbacks group repeated 7-term slices of
            // the double-base product-convolution basis into q_limb7_wide.
            function q_limb7_wide(x0, x1, x2, x3, x4, x5, x6) -> z {
                z := addmod(x0, mulmod(0x100000000000000, x1, FR_MODULUS), FR_MODULUS)
                z := addmod(z, mulmod(0x10000000000000000000000000000, x2, FR_MODULUS), FR_MODULUS)
                z := addmod(z, mulmod(0x1000000000000000000000000000000000000000000, x3, FR_MODULUS), FR_MODULUS)
                z := addmod(z, mulmod(0x100000000000000000000000000000000000000000000000000000000, x4, FR_MODULUS), FR_MODULUS)
                z := addmod(z, mulmod(0x6bc66e553973f396854f5626172ba135587d41e37a68209402355093fdcaaf6c, x5, FR_MODULUS), FR_MODULUS)
                z := addmod(z, mulmod(0x63f31e3f446953960c9d6964474300df43ab29179970f642a28e39d6c883c74b, x6, FR_MODULUS), FR_MODULUS)
            }

            {%- endif %}
            {%- if self.quotient_yul_helpers %}
            // Tiny quotient arithmetic helpers for the no-VM quotient-CSE
            // mode. These intentionally stay simple; forcing no-inline loops
            // reduces source size but can make solc --via-ir compile time
            // explode on the IVC verifier.
            function q_add(a, b) -> z {
                z := addmod(a, b, FR_MODULUS)
            }
            function q_mul(a, b) -> z {
                z := mulmod(a, b, FR_MODULUS)
            }
            function q_neg(a) -> z {
                z := addmod(0, sub(FR_MODULUS, a), FR_MODULUS)
            }
            function q_madd(a, b, c) -> z {
                z := addmod(mulmod(a, b, FR_MODULUS), c, FR_MODULUS)
            }
            function q_addmul(a, b, c) -> z {
                z := addmod(a, mulmod(b, c, FR_MODULUS), FR_MODULUS)
            }

            {%- endif %}
            // ---------- Streaming Keccak256 transcript helpers ----------
            //
            // The transcript buffer lives at memory[0x00..buf_len). On
            // verifier entry it starts empty. Each common(input) appends
            // raw bytes. squeeze_*(buf_len) computes one Keccak digest,
            // reseeds the buffer with that 32-byte digest, and samples a
            // Fq element as uint256(digest_be) mod r.

            function transcript_init() -> buf_len {
                buf_len := 0
            }

            // Append word[0..32] at the current end of the transcript
            // buffer.
            function common_word(buf_len, word) -> ret {
                mstore(buf_len, word)
                ret := add(buf_len, 32)
            }

            // Absorb a BLS12-381 G1 point in EIP-2537 padded
            // uncompressed form (4 calldata words = 128 bytes:
            // x_hi || x_lo || y_hi || y_lo, each coord = 16 zero
            // pad bytes + 48 big-endian field bytes) into the
            // transcript buffer at `buf_len`.
            //
            // Matches the patched `Hashable<Keccak256> for
            // midnight_curves::G1Projective::to_input` in
            // midnight-proofs, which now emits the same 128-byte form
            // (`midfall/proofs/src/transcript/implementors.rs`). The
            // previous emitter hashed the 48-byte ZCash compressed
            // encoding instead and ran a 384-bit `lex(y) > lex(p − y)`
            // ladder + identity flag fixup to derive the sign bit on
            // the fly; switching to the uncompressed form drops that
            // ladder entirely.
            //
            // Canonicality: reject non-zero bytes in the top 16 bytes
            // of each `_hi` calldata word and reject coordinates
            // outside Fp. Normalizing those bytes before hashing would
            // make multiple calldata encodings share one transcript.
            //
            // This helper does not run an independent curve/subgroup
            // check. Instead, ProtocolPlan::validate rejects generated
            // plans where an absorbed proof commitment would not later be
            // consumed by an EIP-2537 G1MSM or pairing path, and those
            // precompiles perform the curve/subgroup validation.
            //
            // The point's uncompressed form remains in calldata; the
            // call site is responsible for `calldatacopy`-ing it into
            // memory afterwards if it needs the on-curve coordinates.
            function common_uncompressed_g1(buf_len, cptr) -> ret {
                let x_hi_word := calldataload(cptr)
                let x_lo := calldataload(add(cptr, 0x20))
                let y_hi_word := calldataload(add(cptr, 0x40))
                let y_lo := calldataload(add(cptr, 0x60))
                if shr(128, x_hi_word) { revert(0, 0) }
                if shr(128, y_hi_word) { revert(0, 0) }

                let x_hi := and(x_hi_word, 0xffffffffffffffffffffffffffffffff)
                let y_hi := and(y_hi_word, 0xffffffffffffffffffffffffffffffff)
                if iszero(or(lt(x_hi, BLS_P_HI), and(eq(x_hi, BLS_P_HI), iszero(gt(x_lo, BLS_P_MINUS_ONE_LO))))) {
                    revert(0, 0)
                }
                if iszero(or(lt(y_hi, BLS_P_HI), and(eq(y_hi, BLS_P_HI), iszero(gt(y_lo, BLS_P_MINUS_ONE_LO))))) {
                    revert(0, 0)
                }

                // Memcpy the 4 calldata words (128 bytes) verbatim
                // into the keccak buffer.
                calldatacopy(buf_len, cptr, 0x80)
                ret := add(buf_len, 0x80)
            }

            // One Keccak finalization + reseed. Returns the new buffer
            // length (= 32) and stores the squeezed Fq at `mptr`.
            function squeeze_to(buf_len, mptr) -> ret {
                let h0 := keccak256(0x00, buf_len)
                // Reseed: write the 32-byte digest at start of buffer.
                mstore(0x00, h0)
                let r := FR_MODULUS
                // Sample Fq as uint256(keccak_digest_be) mod r.
                mstore(mptr, mod(h0, r))
                ret := 32
            }

            // ---------- EC primitives (EIP-2537 wrappers) ----------
            //
            // These mirror the BN254 helpers but operate on 4-word G1
            // points. They use the [0x100..0x500) memory window as
            // scratch; the streaming transcript buffer at [0x00..buf_len)
            // is no longer needed once all challenges are squeezed.

            function batch_invert(success, mptr_start, mptr_end, scratch_mptr, r) -> ret {
                ret := success
                if iszero(ret) { leave }
                if lt(mptr_end, mptr_start) {
                    ret := 0
                    leave
                }

                let count_bytes := sub(mptr_end, mptr_start)
                if iszero(count_bytes) { leave }

                if eq(count_bytes, 0x20) {
                    let x := mload(mptr_start)
                    if iszero(x) {
                        ret := 0
                        leave
                    }

                    let single_scratch := scratch_mptr
                    mstore(single_scratch, 0x20)
                    mstore(add(single_scratch, 0x20), 0x20)
                    mstore(add(single_scratch, 0x40), 0x20)
                    mstore(add(single_scratch, 0x60), x)
                    mstore(add(single_scratch, 0x80), sub(r, 2))
                    mstore(add(single_scratch, 0xa0), r)
                    ret := staticcall(gas(), 0x05, single_scratch, 0xc0, single_scratch, 0x20)
                    ret := and(ret, eq(returndatasize(), 0x20))
                    if ret { mstore(mptr_start, mload(single_scratch)) }
                    leave
                }

                let gp_mptr := scratch_mptr
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for {} lt(mptr, sub(mptr_end, 0x20)) {} {
                    gp := mulmod(gp, mload(mptr), r)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), r)
                if iszero(gp) {
                    ret := 0
                    leave
                }

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(r, 2))
                mstore(add(gp_mptr, 0xa0), r)
                ret := staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20)
                ret := and(ret, eq(returndatasize(), 0x20))
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

            function g1add_gas_cap() -> cap {
                cap := 50000
            }

            function g1msm_gas_cap(input_len) -> cap {
                let k := div(input_len, 0xa0)
                let discount := 519
                switch k
                case 0 { discount := 0 }
                case 1 { discount := 1000 }
                case 2 { discount := 949 }
                case 3 { discount := 848 }
                case 4 { discount := 797 }
                case 5 { discount := 764 }
                case 6 { discount := 750 }
                case 7 { discount := 738 }
                case 8 { discount := 728 }
                case 9 { discount := 719 }
                case 10 { discount := 712 }
                case 11 { discount := 705 }
                case 12 { discount := 698 }
                case 13 { discount := 692 }
                case 14 { discount := 687 }
                case 15 { discount := 682 }
                case 16 { discount := 677 }
                case 17 { discount := 673 }
                case 18 { discount := 669 }
                case 19 { discount := 665 }
                case 20 { discount := 661 }
                case 21 { discount := 658 }
                case 22 { discount := 654 }
                case 23 { discount := 651 }
                case 24 { discount := 648 }
                case 25 { discount := 645 }
                case 26 { discount := 642 }
                case 27 { discount := 640 }
                case 28 { discount := 637 }
                case 29 { discount := 635 }
                case 30 { discount := 632 }
                case 31 { discount := 630 }
                case 32 { discount := 627 }
                case 33 { discount := 625 }
                case 34 { discount := 623 }
                case 35 { discount := 621 }
                case 36 { discount := 619 }
                case 37 { discount := 617 }
                case 38 { discount := 615 }
                case 39 { discount := 613 }
                case 40 { discount := 611 }
                case 41 { discount := 609 }
                case 42 { discount := 608 }
                case 43 { discount := 606 }
                case 44 { discount := 604 }
                case 45 { discount := 603 }
                case 46 { discount := 601 }
                case 47 { discount := 599 }
                case 48 { discount := 598 }
                case 49 { discount := 596 }
                case 50 { discount := 595 }
                case 51 { discount := 593 }
                case 52 { discount := 592 }
                case 53 { discount := 591 }
                case 54 { discount := 589 }
                case 55 { discount := 588 }
                case 56 { discount := 586 }
                case 57 { discount := 585 }
                case 58 { discount := 584 }
                case 59 { discount := 582 }
                case 60 { discount := 581 }
                case 61 { discount := 580 }
                case 62 { discount := 579 }
                case 63 { discount := 577 }
                case 64 { discount := 576 }
                case 65 { discount := 575 }
                case 66 { discount := 574 }
                case 67 { discount := 573 }
                case 68 { discount := 572 }
                case 69 { discount := 570 }
                case 70 { discount := 569 }
                case 71 { discount := 568 }
                case 72 { discount := 567 }
                case 73 { discount := 566 }
                case 74 { discount := 565 }
                case 75 { discount := 564 }
                case 76 { discount := 563 }
                case 77 { discount := 562 }
                case 78 { discount := 561 }
                case 79 { discount := 560 }
                case 80 { discount := 559 }
                case 81 { discount := 558 }
                case 82 { discount := 557 }
                case 83 { discount := 556 }
                case 84 { discount := 555 }
                case 85 { discount := 554 }
                case 86 { discount := 553 }
                case 87 { discount := 552 }
                case 88 { discount := 551 }
                case 89 { discount := 550 }
                case 90 { discount := 549 }
                case 91 { discount := 548 }
                case 92 { discount := 547 }
                case 93 { discount := 547 }
                case 94 { discount := 546 }
                case 95 { discount := 545 }
                case 96 { discount := 544 }
                case 97 { discount := 543 }
                case 98 { discount := 542 }
                case 99 { discount := 541 }
                case 100 { discount := 540 }
                case 101 { discount := 540 }
                case 102 { discount := 539 }
                case 103 { discount := 538 }
                case 104 { discount := 537 }
                case 105 { discount := 536 }
                case 106 { discount := 536 }
                case 107 { discount := 535 }
                case 108 { discount := 534 }
                case 109 { discount := 533 }
                case 110 { discount := 532 }
                case 111 { discount := 532 }
                case 112 { discount := 531 }
                case 113 { discount := 530 }
                case 114 { discount := 529 }
                case 115 { discount := 528 }
                case 116 { discount := 528 }
                case 117 { discount := 527 }
                case 118 { discount := 526 }
                case 119 { discount := 525 }
                case 120 { discount := 525 }
                case 121 { discount := 524 }
                case 122 { discount := 523 }
                case 123 { discount := 522 }
                case 124 { discount := 522 }
                case 125 { discount := 521 }
                case 126 { discount := 520 }
                case 127 { discount := 520 }
                case 128 { discount := 519 }
                // EIP-2537 G1MSM gas: k * discount[k] * 12000 / 1000.
                // The generated call sites pass input_len constants derived
                // from the circuit/VK-specific MSM term counts.
                cap := add(50000, div(mul(mul(k, discount), 12000), 1000))
            }

            function pairing_gas_cap(input_len) -> cap {
                // Pairing inputs are 0x180 bytes per (G1, G2) pair.
                cap := add(50000, mul(div(input_len, 0x180), 60000))
            }

            function ec_pairing(success, lhs_mptr, rhs_mptr) -> ret {
                ret := success
                if iszero(ret) { leave }
                // Lay out two (G1, G2) pairs at scratch..scratch+0x300:
                //   [lhs_g1 (0x80) | G2_BASE (0x100) | rhs_g1 (0x80) | NEG_S_G2_BASE (0x100)]
                // Cancun MCOPY (3 + 3·words gas) replaces what used to
                // be a 4-step mstore chain for each G1 (~60 gas) and an
                // 8-iter mstore loop for each G2 (~240 gas). Net saving
                // here is ~500 gas per ec_pairing call.
                let scratch := 0x300
                mcopy(scratch,              lhs_mptr,                 0x80)
                mcopy(add(scratch, 0x80),   G2_BASE_MPTR,             0x100)
                mcopy(add(scratch, 0x180),  rhs_mptr,                 0x80)
                mcopy(add(scratch, 0x200),  NEG_S_G2_BASE_MPTR,       0x100)
                ret := staticcall(pairing_gas_cap(0x300), 0x0f, scratch, 0x300, scratch, 0x20)
                ret := and(ret, eq(returndatasize(), 0x20))
                ret := and(ret, mload(scratch))
                if iszero(ret) { revert(0, 0) }
                ret := 1
            }

            // ---------- IVC accumulator public-input decoding ----------
            //
            // `AssignedForeignPoint<BLS12-381>` exposes each base-field coordinate
            // through `AssignedField::as_public_input`: seven radix-2^56 limbs of
            // (coord - 1) are packed four-at-a-time into native field elements.
            // The x coordinate's first packed word carries the identity flag by
            // adding one raw radix base. Rebuild EIP-2537 padded
            // (x_hi, x_lo, y_hi, y_lo) words from that encoding.
            function load_acc_coord_shifted(src, bits, n, base, limbs_per_word, first_adjust) -> hi, lo {
                let mask := sub(base, 1)
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    let packed := calldataload(add(src, mul(div(i, limbs_per_word), 0x20)))
                    if and(iszero(div(i, limbs_per_word)), first_adjust) {
                        packed := sub(packed, first_adjust)
                    }
                    let limb := and(shr(mul(mod(i, limbs_per_word), bits), packed), mask)

                    let shift := mul(i, bits)
                    if lt(shift, 256) {
                        lo := add(lo, shl(shift, limb))
                        if gt(add(shift, bits), 256) {
                            hi := add(hi, shr(sub(256, shift), limb))
                        }
                    }
                    if iszero(lt(shift, 256)) {
                        hi := add(hi, shl(sub(shift, 256), limb))
                    }
                }
            }

            function is_bls_p_minus_one(hi, lo) -> yes {
                yes := and(eq(hi, BLS_P_HI), eq(lo, BLS_P_MINUS_ONE_LO))
            }

            function is_acc_encoded_identity(src) -> yes {
                yes := and(
                    and(
                        eq(calldataload(src), BLS_P_MINUS_ONE_PACKED_0_WITH_ID_FLAG),
                        eq(calldataload(add(src, 0x20)), BLS_P_MINUS_ONE_PACKED_1)
                    ),
                    and(
                        eq(calldataload(add(src, 0x40)), BLS_P_MINUS_ONE_PACKED_0),
                        eq(calldataload(add(src, 0x60)), BLS_P_MINUS_ONE_PACKED_1)
                    )
                )
            }

            function check_acc_coord_packing(src, bits, n, limbs_per_word) -> ok {
                ok := 1
                let coord_words := div(add(n, sub(limbs_per_word, 1)), limbs_per_word)
                for { let word_idx := 0 } lt(word_idx, coord_words) { word_idx := add(word_idx, 1) } {
                    let remaining := sub(n, mul(word_idx, limbs_per_word))
                    let limbs_in_word := limbs_per_word
                    if lt(remaining, limbs_per_word) {
                        limbs_in_word := remaining
                    }
                    let used_bits := mul(limbs_in_word, bits)
                    if lt(used_bits, 256) {
                        ok := and(ok, lt(calldataload(add(src, mul(word_idx, 0x20))), shl(used_bits, 1)))
                    }
                }
            }

            function load_acc_coord(src, allow_id, bits, n, base, limbs_per_word) -> ok, hi, lo, is_id {
                ok := check_acc_coord_packing(src, bits, n, limbs_per_word)
                if and(allow_id, iszero(lt(calldataload(src), base))) {
                    let adj_hi, adj_lo := load_acc_coord_shifted(src, bits, n, base, limbs_per_word, base)
                    is_id := is_bls_p_minus_one(adj_hi, adj_lo)
                }

                hi, lo := load_acc_coord_shifted(src, bits, n, base, limbs_per_word, mul(is_id, base))
                ok := and(
                    ok,
                    or(lt(hi, BLS_P_HI), and(eq(hi, BLS_P_HI), iszero(gt(lo, BLS_P_MINUS_ONE_LO))))
                )

                let was_p_minus_one := is_bls_p_minus_one(hi, lo)
                if was_p_minus_one {
                    hi := 0
                    lo := 0
                }
                if iszero(was_p_minus_one) {
                    let next_lo := add(lo, 1)
                    hi := add(hi, lt(next_lo, lo))
                    lo := next_lo
                }

                // EIP-2537 pads each 48-byte Fp coordinate to 64 bytes,
                // so the high word must fit in its low 128 bits.
                ok := and(ok, lt(hi, shl(128, 1)))
            }

            function load_acc_point(dst, src, bits, n, base) -> ok, is_id {
                is_id := is_acc_encoded_identity(src)
                if is_id {
                    ok := 1
                    mstore(dst, 0)
                    mstore(add(dst, 0x20), 0)
                    mstore(add(dst, 0x40), 0)
                    mstore(add(dst, 0x60), 0)
                }
                if iszero(is_id) {
                    let limbs_per_word := 4
                    let coord_words := div(add(n, sub(limbs_per_word, 1)), limbs_per_word)
                    let x_ok, x_hi, x_lo, x_is_id := load_acc_coord(src, 1, bits, n, base, limbs_per_word)
                    let y_ok, y_hi, y_lo, y_id := load_acc_coord(
                        add(src, mul(coord_words, 0x20)),
                        0,
                        bits,
                        n,
                        base,
                        limbs_per_word
                    )
                    pop(y_id)
                    ok := and(x_ok, y_ok)
                    is_id := x_is_id

                    if is_id {
                        ok := and(ok, iszero(or(or(x_hi, x_lo), or(y_hi, y_lo))))
                        mstore(dst, 0)
                        mstore(add(dst, 0x20), 0)
                        mstore(add(dst, 0x40), 0)
                        mstore(add(dst, 0x60), 0)
                    }
                    if iszero(is_id) {
                        mstore(dst, x_hi)
                        mstore(add(dst, 0x20), x_lo)
                        mstore(add(dst, 0x40), y_hi)
                        mstore(add(dst, 0x60), y_lo)
                    }
                }
            }

            // Quotient arithmetic emits this hook in both production and
            // trace builds so solc via-IR sees the same arithmetic shape.
            // Production keeps it logless; trace builds emit the value.
            function trace_u256(id, value) {
                {%- if self.trace %}
                mstore(TRACE_U256_MPTR, value)
                log1(TRACE_U256_MPTR, 0x20, id)
                {%- else %}
                pop(id)
                mstore(TRACE_U256_MPTR, value)
                {%- endif %}
            }
            {%- if self.trace %}
            function trace_point(id, mptr) {
                log1(mptr, 0x80, id)
            }
            {%- endif %}
            {%- if self.gas_checkpoints %}
            // Section-boundary gas-attribution checkpoint. Emits a
            // single LOG1 (no data) with topic = (id << 248) | gas().
            // Cost: 375 (LOG base) + 375 (1 topic) = 750 gas/call.
            // Host-side parses the topic into (id, gas_left) and prints
            // pairwise deltas (see `dump_gas_checkpoints`).
            function gas_checkpoint(id) {
                log1(0, 0, or(shl(248, id), gas()))
            }
            {%- endif %}

            let r := FR_MODULUS
            let success := true

            {%- if self.gas_checkpoints %}
            gas_checkpoint(1) // entry: before VK loading
            {%- endif %}

            // ===============================================================
            // VK loading: either bake in the embedded VK bytes or fetch
            // them from the linked AUTHORIZED_VK contract.
            // ===============================================================
            {
                {%- match self.embedded_vk %}
                {%- when Some with (embedded_vk) %}
                {%- for (name, chunk) in embedded_vk.constants %}
                mstore({{ vk_mptr + loop.index0 }}, {{ chunk|hex_padded(64) }}) // {{ name }}
                {%- endfor %}
                {%- for (x_hi, x_lo, y_hi, y_lo) in embedded_vk.fixed_comms %}
                {%- let offset = embedded_vk.constants.len() %}
                mstore({{ vk_mptr + offset + 4 * loop.index0 }}, {{ x_hi|hex_padded(64) }})
                mstore({{ vk_mptr + offset + 4 * loop.index0 + 1 }}, {{ x_lo|hex_padded(64) }})
                mstore({{ vk_mptr + offset + 4 * loop.index0 + 2 }}, {{ y_hi|hex_padded(64) }})
                mstore({{ vk_mptr + offset + 4 * loop.index0 + 3 }}, {{ y_lo|hex_padded(64) }})
                {%- endfor %}
                {%- for (x_hi, x_lo, y_hi, y_lo) in embedded_vk.permutation_comms %}
                {%- let offset = embedded_vk.constants.len() + 4 * embedded_vk.fixed_comms.len() %}
                mstore({{ vk_mptr + offset + 4 * loop.index0 }}, {{ x_hi|hex_padded(64) }})
                mstore({{ vk_mptr + offset + 4 * loop.index0 + 1 }}, {{ x_lo|hex_padded(64) }})
                mstore({{ vk_mptr + offset + 4 * loop.index0 + 2 }}, {{ y_hi|hex_padded(64) }})
                mstore({{ vk_mptr + offset + 4 * loop.index0 + 3 }}, {{ y_lo|hex_padded(64) }})
                {%- endfor %}
                {%- when None %}
                extcodecopy(vk, VK_MPTR, 0x00, {{ vk_len|hex() }})
                {%- endmatch %}

                // The code generator knows whether this verifier expects
                // public accumulator limbs and how they are packed. Check
                // the VK header agrees before decoding instance words under
                // the wrong schema.
                success := and(success, eq(mload(HAS_ACCUMULATOR_MPTR), {%- if self.expected_has_accumulator %} 1 {%- else %} 0 {%- endif %}))
                success := and(success, eq(mload(ACC_OFFSET_MPTR), {{ self.expected_acc_offset }}))
                success := and(success, eq(mload(NUM_ACC_LIMBS_MPTR), {{ self.expected_num_acc_limbs }}))
                success := and(success, eq(mload(NUM_ACC_LIMB_BITS_MPTR), {{ self.expected_num_acc_limb_bits }}))

                success := and(success, eq({{ proof_len|hex() }}, calldataload(PROOF_LEN_CPTR)))

                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, calldataload(NUM_INSTANCE_CPTR)))
                success := and(
                    success,
                    eq(calldatasize(), add(INSTANCE_CPTR, mul(0x20, num_instances)))
                )
                if iszero(success) { revert(0, 0) }
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(2) // after VK loading
            {%- endif %}

            // ===============================================================
            // Transcript: VK digest + instances + proof.
            // ===============================================================
            let buf_len := transcript_init()
            // VK_DIGEST_MPTR holds the digest as a BE 32-byte word (the
            // VK contract stores it via `mstore`, which matches the
            // Keccak Fq transcript input).
            buf_len := common_word(buf_len, mload(VK_DIGEST_MPTR))

            // Absorb committed_pi = G1Affine::identity() when the
            // `committed-instances` feature is on in midnight-proofs.
            // Under the patched `Hashable<Keccak256>::to_input` (see
            // `midfall/proofs/src/transcript/implementors.rs`), the
            // identity hashes as 128 zero bytes (EIP-2537 (0,0)
            // convention), NOT the 48-byte ZCash compressed form
            // 0xc0||47*0x00 that the previous emitter produced.
            // Native verifier absorbs this BEFORE the instance count.
            {
                // 128 zero bytes: zero out 4 consecutive 32-byte words
                // at buf_len.
                mstore(buf_len, 0)
                mstore(add(buf_len, 0x20), 0)
                mstore(add(buf_len, 0x40), 0)
                mstore(add(buf_len, 0x60), 0)
                buf_len := add(buf_len, 0x80)
            }

            {
                let num_instances := mload(NUM_INSTANCES_MPTR)
                // Native verifier absorbs a length scalar before instance
                // values; Keccak Fq transcript input is canonical BE.
                buf_len := common_word(buf_len, num_instances)

                let instance_cptr := INSTANCE_CPTR
                for { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    { instance_cptr := add(instance_cptr, 0x20) } {
                    let inst_be := calldataload(instance_cptr)
                    success := and(success, lt(inst_be, r))
                    // Instances are passed BE in calldata, matching the
                    // Keccak Fq transcript input.
                    buf_len := common_word(buf_len, inst_be)
                }
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(3) // after VK digest + committed_pi + instance absorbs
            {%- endif %}

            // ===============================================================
            // Per-user-phase reads + challenge squeezes.
            //
            // Each proof G1 is already EIP-2537 padded in calldata. The
            // verifier validates and absorbs that 128-byte form, then copies
            // it into the corresponding per-category MPTR. The PCS /
            // quotient-fold blocks below dereference those MPTRs.
            // ===============================================================
            let proof_cptr := PROOF_CPTR
            let advice_walk := ADVICE_COMMS_MPTR_BASE
            {%- if self.trace %}
            let proof_commit_trace_id := 10000
            let proof_eval_trace_id := 20000
            {%- endif %}

            {%- for phase in user_phases %}
            // ---- User phase {{ loop.index }} ----
            for { let end := add(proof_cptr, {{ (phase.num_advices * 128)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_uncompressed_g1(buf_len, proof_cptr)
                calldatacopy(advice_walk, proof_cptr, 0x80)
                {%- if self.trace %}
                trace_point(proof_commit_trace_id, advice_walk)
                proof_commit_trace_id := add(proof_commit_trace_id, 1)
                {%- endif %}
                advice_walk := add(advice_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x80)
            }
            {%- for j in 0..phase.num_challenges %}
            buf_len := squeeze_to(buf_len, add(CHALLENGE_MPTR, {{ ((phase.challenge_offset + j) * 32)|hex() }}))
            {%- endfor %}
            {%- endfor %}

            {%- if self.gas_checkpoints %}
            gas_checkpoint(4) // after user-phase advice reads + user challenge squeezes
            {%- endif %}

            // ---- theta ----
            buf_len := squeeze_to(buf_len, THETA_MPTR)

            {%- if num_lookups != 0 %}
            // ---- multiplicities (one G1 per lookup) ----
            let lookup_m_walk := LOOKUP_M_COMMS_MPTR_BASE
            for { let end := add(proof_cptr, {{ (num_lookups * 128)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_uncompressed_g1(buf_len, proof_cptr)
                calldatacopy(lookup_m_walk, proof_cptr, 0x80)
                {%- if self.trace %}
                trace_point(proof_commit_trace_id, lookup_m_walk)
                proof_commit_trace_id := add(proof_commit_trace_id, 1)
                {%- endif %}
                lookup_m_walk := add(lookup_m_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x80)
            }
            {%- endif %}

            {%- if self.gas_checkpoints %}
            gas_checkpoint(5) // after theta squeeze + lookup multiplicities
            {%- endif %}

            // ---- beta, gamma ----
            buf_len := squeeze_to(buf_len, BETA_MPTR)
            buf_len := squeeze_to(buf_len, GAMMA_MPTR)

            {%- if num_permutation_zs != 0 %}
            // ---- permutation Z products ----
            let perm_z_walk := PERM_Z_COMMS_MPTR_BASE
            for { let end := add(proof_cptr, {{ (num_permutation_zs * 128)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_uncompressed_g1(buf_len, proof_cptr)
                calldatacopy(perm_z_walk, proof_cptr, 0x80)
                {%- if self.trace %}
                trace_point(proof_commit_trace_id, perm_z_walk)
                proof_commit_trace_id := add(proof_commit_trace_id, 1)
                {%- endif %}
                perm_z_walk := add(perm_z_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x80)
            }
            {%- endif %}

            {%- if self.gas_checkpoints %}
            gas_checkpoint(6) // after beta/gamma + permutation Z products
            {%- endif %}

            {%- if lookup_h_plus_acc != 0 %}
            // ---- lookup helpers + accumulators (per-lookup) ----
            let lookup_helper_walk := LOOKUP_HELPER_COMMS_MPTR_BASE
            let lookup_z_walk := LOOKUP_Z_COMMS_MPTR_BASE
            {%- for chunks in lookup_chunks %}
            // lookup {{ loop.index0 }}: {{ chunks }} helper(s) + 1 acc
            for { let end := add(proof_cptr, {{ (chunks * 128)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_uncompressed_g1(buf_len, proof_cptr)
                calldatacopy(lookup_helper_walk, proof_cptr, 0x80)
                {%- if self.trace %}
                trace_point(proof_commit_trace_id, lookup_helper_walk)
                proof_commit_trace_id := add(proof_commit_trace_id, 1)
                {%- endif %}
                lookup_helper_walk := add(lookup_helper_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x80)
            }
            buf_len := common_uncompressed_g1(buf_len, proof_cptr)
            calldatacopy(lookup_z_walk, proof_cptr, 0x80)
            {%- if self.trace %}
            trace_point(proof_commit_trace_id, lookup_z_walk)
            proof_commit_trace_id := add(proof_commit_trace_id, 1)
            {%- endif %}
            lookup_z_walk := add(lookup_z_walk, 0x80)
            proof_cptr := add(proof_cptr, 0x80)
            {%- endfor %}
            {%- endif %}

            {%- if self.gas_checkpoints %}
            gas_checkpoint(7) // after lookup helpers + Z accumulators
            {%- endif %}

            // ---- trash_challenge ----
            // Midnight squeezes this challenge unconditionally, even when the
            // circuit has no trash arguments.
            buf_len := squeeze_to(buf_len, TRASH_CHALLENGE_MPTR)
            {%- if num_trashcans != 0 %}
            // ---- trashcans ----
            let trashcan_walk := TRASHCAN_COMMS_MPTR_BASE
            for { let end := add(proof_cptr, {{ (num_trashcans * 128)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_uncompressed_g1(buf_len, proof_cptr)
                calldatacopy(trashcan_walk, proof_cptr, 0x80)
                {%- if self.trace %}
                trace_point(proof_commit_trace_id, trashcan_walk)
                proof_commit_trace_id := add(proof_commit_trace_id, 1)
                {%- endif %}
                trashcan_walk := add(trashcan_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x80)
            }
            {%- endif %}

            {%- if self.gas_checkpoints %}
            gas_checkpoint(8) // after trash_challenge + trashcans
            {%- endif %}

            // ---- y ----
            buf_len := squeeze_to(buf_len, Y_MPTR)

            // ---- quotient limbs ----
            // Each uncompressed limb is calldatacopied directly to
            // QUOTIENT_LIMB_COMMS_MPTR_BASE; the Horner fold below reads
            // them back from memory. common_uncompressed_g1 absorbs the
            // 128-byte calldata form into the transcript verbatim.
            let quotient_walk := QUOTIENT_LIMB_COMMS_MPTR_BASE
            for { let end := add(proof_cptr, {{ (num_quotients * 128)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_uncompressed_g1(buf_len, proof_cptr)
                calldatacopy(quotient_walk, proof_cptr, 0x80)
                {%- if self.trace %}
                trace_point(proof_commit_trace_id, quotient_walk)
                proof_commit_trace_id := add(proof_commit_trace_id, 1)
                {%- endif %}
                quotient_walk := add(quotient_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x80)
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(9) // after y squeeze + quotient-limb reads
            {%- endif %}

            // ---- x ----
            buf_len := squeeze_to(buf_len, X_MPTR)

            // ---- evaluations ----
            // Optimisation H3: the off-chain Solidity proof shim rewrites
            // proof scalars into BE calldata words. Spill each decoded eval
            // into REVERSED_EVALS_MPTR in the same iteration we range-check
            // it, so downstream references can use cheap mload.
            {
                let eval_buf := REVERSED_EVALS_MPTR
                for { let end := add(proof_cptr, {{ (num_evals * 32)|hex() }}) }
                    lt(proof_cptr, end)
                    {} {
                    let eval := calldataload(proof_cptr)
                    if iszero(lt(eval, r)) { revert(0, 0) }
                    mstore(eval_buf, eval)
                    eval_buf := add(eval_buf, 0x20)
                    buf_len := common_word(buf_len, eval)
                    {%- if self.trace %}
                    trace_u256(proof_eval_trace_id, eval)
                    proof_eval_trace_id := add(proof_eval_trace_id, 1)
                    {%- endif %}
                    proof_cptr := add(proof_cptr, 0x20)
                }
            }

            // ---- x1, x2 ----
            buf_len := squeeze_to(buf_len, X1_MPTR)
            buf_len := squeeze_to(buf_len, X2_MPTR)

            // ---- f_com (1 uncompressed G1) ----
            buf_len := common_uncompressed_g1(buf_len, proof_cptr)
            calldatacopy(F_COM_MPTR, proof_cptr, 0x80)
            {%- if self.trace %}
            trace_point(proof_commit_trace_id, F_COM_MPTR)
            proof_commit_trace_id := add(proof_commit_trace_id, 1)
            {%- endif %}
            proof_cptr := add(proof_cptr, 0x80)

            // ---- x3 ----
            buf_len := squeeze_to(buf_len, X3_MPTR)
            {%- if truncated_challenges %}
            // truncated-challenges mirrors midnight-proofs
            // proofs/src/poly/kzg/mod.rs:
            //   - x3 is the f_com evaluation point and is truncated
            //     immediately after squeeze.
            //   - x1 and x4 remain full squeezed Fr words, but later PCS
            //     batching stores truncate(x1^i) and truncate(x4^i) while
            //     keeping the internal power accumulators full precision.
            // This direct x3 mask is therefore one part of the PCS truncation
            // rule, not the only truncated value used by the verifier.
            mstore(X3_MPTR, and(mload(X3_MPTR), 0xffffffffffffffffffffffffffffffff))
            {%- endif %}

            // ---- q_evals (one Fq per point set) ----
            mstore(Q_EVAL_CPTR_MPTR, proof_cptr)
            for { let end := add(proof_cptr, {{ (num_point_sets * 32)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                let eval := calldataload(proof_cptr)
                if iszero(lt(eval, r)) { revert(0, 0) }
                buf_len := common_word(buf_len, eval)
                {%- if self.trace %}
                trace_u256(proof_eval_trace_id, eval)
                proof_eval_trace_id := add(proof_eval_trace_id, 1)
                {%- endif %}
                proof_cptr := add(proof_cptr, 0x20)
            }

            // ---- x4 ----
            buf_len := squeeze_to(buf_len, X4_MPTR)

            // ---- pi (1 uncompressed G1) ----
            buf_len := common_uncompressed_g1(buf_len, proof_cptr)
            calldatacopy(PI_MPTR, proof_cptr, 0x80)
            {%- if self.trace %}
            trace_point(proof_commit_trace_id, PI_MPTR)
            proof_commit_trace_id := add(proof_commit_trace_id, 1)
            {%- endif %}
            proof_cptr := add(proof_cptr, 0x80)

            // The hand-rolled proof parser must consume exactly the ABI
            // `proof` bytes before the `instances` length word. This is
            // redundant with the generated proof length today, but makes
            // future proof-layout drift fail closed.
            if iszero(eq(proof_cptr, NUM_INSTANCE_CPTR)) { revert(0, 0) }

            if iszero(success) { revert(0, 0) }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(10) // after evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi (transcript done)
            {%- endif %}

            // ===============================================================
            // Lagrange & instance-evaluation block (pure Fr arithmetic).
            // ===============================================================
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
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20), BATCH_INV_SCRATCH_MPTR, r)

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

            {%- if self.gas_checkpoints %}
            gas_checkpoint(11) // after Lagrange + instance evaluation block
            {%- endif %}

            if iszero(success) { revert(0, 0) }

            {%- match quotient_external %}
            {%- when Some with (qext) %}
            // ===============================================================
            // External batched identity numerator reconstruction.
            //
            // The quotient evaluator receives the verifier memory image from
            // QUOTIENT_FRAME_BASE..+QUOTIENT_FRAME_LEN, reconstructs the same
            // y-batched numerator, and returns:
            //   word 0: magic/version
            //   word 1: linearization expected eval
            //   word 2..: simple-selector accumulators
            // ===============================================================
            {
                let q_out := SELECTOR_ACC_MPTR
                if iszero(staticcall(gas(), quotientEvaluator, {{ qext.frame_base|hex() }}, {{ qext.frame_len|hex() }}, q_out, {{ qext.output_len|hex() }})) { revert(0, 0) }
                if iszero(eq(returndatasize(), {{ qext.output_len|hex() }})) { revert(0, 0) }
                if iszero(eq(mload(q_out), {{ qext.magic|hex_padded(64) }})) { revert(0, 0) }
                mstore(QUOTIENT_EVAL_MPTR, mload(add(q_out, 0x20)))
                {%- if simple_selector_cols.len() > 0 %}
                for { let q_i := 0 } lt(q_i, {{ simple_selector_cols.len() }}) { q_i := add(q_i, 1) } {
                    mstore(add(SELECTOR_ACC_MPTR, shl(5, q_i)), mload(add(q_out, add(0x40, shl(5, q_i)))))
                }
                {%- endif %}
            }
            {%- when None %}
            {%- include "QuotientNumeratorBlock.yul" %}
            {%- endmatch %}

            {%- if self.gas_checkpoints %}
            gas_checkpoint(12) // after batched identity numerator reconstruction
            {%- endif %}

            // ===============================================================
            // Prepare linearization scalars for the final PCS MSM.
            //
            // The linearized commitment is
            //   (1 - x^n) * Σ_i x_split^i * Q_i
            // + Σ_j sel_acc_j * S_j_com,
            // where x_split = x^(n-1). Instead of materializing that point
            // with a standalone G1MSM here, PCS block 5 expands the
            // linearized commitment into its quotient-limb and selector
            // pairs inside the already-fused final MSM.
            //
            // QUOTIENT_MPTR is no longer a G1 point in this path. Its first
            // two words carry:
            //   word 0: x_split
            //   word 1: one_minus_x_n
            // ===============================================================
            {
                let x := mload(X_MPTR)
                let k := mload(K_MPTR)
                let x_pow_2i := x
                let x_pow_2i_minus1 := 1
                for { let idx := 0 } lt(idx, k) { idx := add(idx, 1) } {
                    x_pow_2i_minus1 := mulmod(
                        mulmod(x_pow_2i_minus1, x_pow_2i_minus1, r),
                        x,
                        r
                    )
                    x_pow_2i := mulmod(x_pow_2i, x_pow_2i, r)
                }
                let x_split := x_pow_2i_minus1
                let one_minus_x_n := addmod(1, sub(r, x_pow_2i), r)

                mstore(QUOTIENT_MPTR, x_split)
                mstore(add(QUOTIENT_MPTR, 0x20), one_minus_x_n)
            }

            {%- if self.trace %}
            // Materialize the linearization commitment for trace comparison.
            // The production path expands the same terms directly into the
            // fused final PCS MSM below.
            {
                let lin_scratch := add(SELECTOR_ACC_MPTR, {{ (simple_selector_cols.len() * 0x20)|hex() }})
                let lin_pair := lin_scratch
                let lin_cur_scalar := mload(add(QUOTIENT_MPTR, 0x20))
                {%- for _ in 0..num_quotients %}
                mcopy(lin_pair, add(QUOTIENT_LIMB_COMMS_MPTR_BASE, {{ (loop.index0 * 0x80)|hex() }}), 0x80)
                mstore(add(lin_pair, 0x80), lin_cur_scalar)
                lin_pair := add(lin_pair, 0xa0)
                {%- if !loop.last %}
                lin_cur_scalar := mulmod(lin_cur_scalar, mload(QUOTIENT_MPTR), r)
                {%- endif %}
                {%- endfor %}
                {%- for col in simple_selector_cols %}
                mcopy(lin_pair, {{ (fixed_comm_mptr + col * 0x80)|hex() }}, 0x80)
                mstore(add(lin_pair, 0x80), mload(add(SELECTOR_ACC_MPTR, {{ (loop.index0 * 0x20)|hex() }})))
                lin_pair := add(lin_pair, 0xa0)
                {%- endfor %}
                let lin_trace_ok := staticcall(g1msm_gas_cap({{ ((num_quotients + simple_selector_cols.len()) * 0xa0)|hex() }}), 0x0c, lin_scratch, {{ ((num_quotients + simple_selector_cols.len()) * 0xa0)|hex() }}, lin_scratch, 0x80)
                lin_trace_ok := and(lin_trace_ok, eq(returndatasize(), 0x80))
                if iszero(lin_trace_ok) {
                    mstore(0, 34)
                    revert(0, 0x20)
                }
                trace_point(34, lin_scratch)
            }
            {%- endif %}

            {%- if self.gas_checkpoints %}
            gas_checkpoint(13) // after linearization scalar prep
            {%- endif %}

            // ===============================================================
            // PCS computation (multi-prepare emitter from Step 5).
            // ===============================================================
            {
                {%- for code_block in pcs_computations %}
                {
                    {%- for line in code_block %}
                    {{ line }}
                    {%- endfor %}
                }
                {%- if self.gas_checkpoints && !loop.last %}
                gas_checkpoint({{ 17 + loop.index0 }}) // after PCS sub-block {{ loop.index }}
                {%- endif %}
                {%- endfor %}
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(14) // after PCS computation block (= sub-block 6)
            {%- endif %}

            {%- if self.trace %}
            trace_point(27, PAIRING_LHS_MPTR)
            trace_point(28, PAIRING_RHS_MPTR)
            {%- endif %}

            // Rebuild the public IVC accumulator from `instances` and batch
            // its pairing equation into the final KZG pairing.
            //
            // We do not simply multiply the two pairing equations together:
            // two bad equations could cancel. Instead, after all four G1
            // pairing inputs are fixed, derive a verifier-local randomizer
            // alpha and check:
            //
            //   e(kzg_rhs + alpha * acc_rhs, G2_BASE)
            // * e(kzg_lhs + alpha * acc_lhs, NEG_S_G2_BASE) == 1
            //
            // If either original equation is bad, this combined equation
            // holds for at most one alpha in Fr.
            if mload(HAS_ACCUMULATOR_MPTR) {
                let bits := mload(NUM_ACC_LIMB_BITS_MPTR)
                let n := mload(NUM_ACC_LIMBS_MPTR)
                // The BLS12-381 self-emulation currently exposes Fp
                // coordinates as 7 radix-2^56 limbs.
                success := and(success, eq(bits, 56))
                success := and(success, eq(n, 7))

                let limb_base := shl(bits, 1)
                let limbs_per_word := 4
                let coord_words := div(add(n, sub(limbs_per_word, 1)), limbs_per_word)
                let acc_expected_words := add(add(mload(ACC_OFFSET_MPTR), add(mul(4, coord_words), 2)), {{ acc_fixed_bases.len() }})
                success := and(success, eq(mload(NUM_INSTANCES_MPTR), acc_expected_words))
                let acc_instance_ptr := add(INSTANCE_CPTR, mul(mload(ACC_OFFSET_MPTR), 0x20))

                // LHS layout: point limbs (x,y), scalar. The collapsed
                // accumulator has no fixed-base scalars on the LHS.
                let lhs_scalar_ptr := add(acc_instance_ptr, mul(mul(2, coord_words), 0x20))
                let lhs_ok, lhs_is_id := load_acc_point(ACC_LHS_MPTR, acc_instance_ptr, bits, n, limb_base)
                success := and(success, lhs_ok)
                let acc_scratch := {{ memory.acc_msm_scratch|hex() }}
                if iszero(lhs_is_id) {
                    let lhs_scalar := calldataload(lhs_scalar_ptr)
                    switch lhs_scalar
                    case 0 {
                        mstore(ACC_LHS_MPTR, 0)
                        mstore(add(ACC_LHS_MPTR, 0x20), 0)
                        mstore(add(ACC_LHS_MPTR, 0x40), 0)
                        mstore(add(ACC_LHS_MPTR, 0x60), 0)
                    }
                    case 1 {
                        // ACC_LHS_MPTR already holds 1 * point.
                    }
                    default {
                        mcopy(acc_scratch, ACC_LHS_MPTR, 0x80)
                        mstore(add(acc_scratch, 0x80), lhs_scalar)
                        if success {
                            success := staticcall(g1msm_gas_cap(0xa0), 0x0c, acc_scratch, 0xa0, ACC_LHS_MPTR, 0x80)
                            success := and(success, eq(returndatasize(), 0x80))
                        }
                    }
                }

                {%- if acc_fixed_bases.len() == 0 %}
                // RHS layout for this generated verifier is fully collapsed:
                // point limbs (x,y), scalar. There is no fixed-base scalar
                // tail; fixed-base contributions were already folded into
                // ACC_RHS by the circuit/native accumulator construction.
                {%- else %}
                // RHS layout for this generated verifier is partially
                // collapsed: point limbs (x,y), scalar, then fixed-base
                // scalars in BTreeMap key order (`-G`, fixed_i, perm_i
                // lexicographically by name). Each tail scalar is consumed
                // below and appended to the RHS MSM with its generated base.
                {%- endif %}
                let rhs_instance_ptr := add(lhs_scalar_ptr, 0x20)
                let rhs_scalar_ptr := add(rhs_instance_ptr, mul(mul(2, coord_words), 0x20))
                let rhs_ok, rhs_is_id := load_acc_point(ACC_RHS_MPTR, rhs_instance_ptr, bits, n, limb_base)
                success := and(success, rhs_ok)
                let acc_pair_ptr := acc_scratch
                let rhs_kept_direct := 0
                if iszero(rhs_is_id) {
                    let rhs_scalar := calldataload(rhs_scalar_ptr)
                    switch rhs_scalar
                    case 0 {
                        // No variable-base RHS contribution.
                    }
                    case 1 {
                        {%- if acc_fixed_bases.len() == 0 %}
                        // With no fixed-base tail, ACC_RHS_MPTR already
                        // holds the complete 1 * point result.
                        rhs_kept_direct := 1
                        {%- else %}
                        mcopy(acc_pair_ptr, ACC_RHS_MPTR, 0x80)
                        mstore(add(acc_pair_ptr, 0x80), 1)
                        acc_pair_ptr := add(acc_pair_ptr, 0xa0)
                        {%- endif %}
                    }
                    default {
                        mcopy(acc_pair_ptr, ACC_RHS_MPTR, 0x80)
                        mstore(add(acc_pair_ptr, 0x80), rhs_scalar)
                        acc_pair_ptr := add(acc_pair_ptr, 0xa0)
                    }
                }
                {%- if acc_fixed_bases.len() > 0 %}
                let fixed_scalar_ptr := add(rhs_scalar_ptr, 0x20)
                {%- for (base_mptr, negate_scalar) in acc_fixed_bases %}
                let fixed_scalar_{{ loop.index0 }} := calldataload(fixed_scalar_ptr)
                {%- if negate_scalar %}
                fixed_scalar_{{ loop.index0 }} := mod(sub(r, fixed_scalar_{{ loop.index0 }}), r)
                {%- endif %}
                if fixed_scalar_{{ loop.index0 }} {
                    mcopy(acc_pair_ptr, {{ base_mptr|hex() }}, 0x80)
                    mstore(add(acc_pair_ptr, 0x80), fixed_scalar_{{ loop.index0 }})
                    acc_pair_ptr := add(acc_pair_ptr, 0xa0)
                }
                fixed_scalar_ptr := add(fixed_scalar_ptr, 0x20)
                {%- endfor %}
                {%- endif %}
                let acc_msm_len := sub(acc_pair_ptr, acc_scratch)
                if acc_msm_len {
                    if success {
                        success := staticcall(
                            g1msm_gas_cap(acc_msm_len),
                            0x0c,
                            acc_scratch,
                            acc_msm_len,
                            ACC_RHS_MPTR,
                            0x80
                        )
                        success := and(success, eq(returndatasize(), 0x80))
                    }
                }
                if and(iszero(acc_msm_len), iszero(rhs_kept_direct)) {
                    mstore(ACC_RHS_MPTR, 0)
                    mstore(add(ACC_RHS_MPTR, 0x20), 0)
                    mstore(add(ACC_RHS_MPTR, 0x40), 0)
                    mstore(add(ACC_RHS_MPTR, 0x60), 0)
                }

                {
                    let batch_ptr := 0x100

                    // Domain || KZG rhs/lhs || accumulator rhs/lhs.
                    mstore(batch_ptr, 0x70616972696e672d62617463682d6163632d6b7a670000000000000000)
                    mcopy(add(batch_ptr, 0x20),  PAIRING_RHS_MPTR, 0x80)
                    mcopy(add(batch_ptr, 0xa0),  PAIRING_LHS_MPTR, 0x80)
                    mcopy(add(batch_ptr, 0x120), ACC_RHS_MPTR,     0x80)
                    mcopy(add(batch_ptr, 0x1a0), ACC_LHS_MPTR,     0x80)
                    let acc_pair_alpha := mod(keccak256(batch_ptr, 0x220), r)
                    if iszero(acc_pair_alpha) { acc_pair_alpha := 1 }

                    // PAIRING_RHS_MPTR += alpha * ACC_RHS_MPTR.
                    mcopy(batch_ptr, ACC_RHS_MPTR, 0x80)
                    mstore(add(batch_ptr, 0x80), acc_pair_alpha)
                    if success {
                        success := staticcall(g1msm_gas_cap(0xa0), 0x0c, batch_ptr, 0xa0, batch_ptr, 0x80)
                        success := and(success, eq(returndatasize(), 0x80))
                    }
                    mcopy(add(batch_ptr, 0x80), PAIRING_RHS_MPTR, 0x80)
                    if success {
                        success := staticcall(g1add_gas_cap(), 0x0b, batch_ptr, 0x100, PAIRING_RHS_MPTR, 0x80)
                        success := and(success, eq(returndatasize(), 0x80))
                    }

                    // PAIRING_LHS_MPTR += alpha * ACC_LHS_MPTR.
                    mcopy(batch_ptr, ACC_LHS_MPTR, 0x80)
                    mstore(add(batch_ptr, 0x80), acc_pair_alpha)
                    if success {
                        success := staticcall(g1msm_gas_cap(0xa0), 0x0c, batch_ptr, 0xa0, batch_ptr, 0x80)
                        success := and(success, eq(returndatasize(), 0x80))
                    }
                    mcopy(add(batch_ptr, 0x80), PAIRING_LHS_MPTR, 0x80)
                    if success {
                        success := staticcall(g1add_gas_cap(), 0x0b, batch_ptr, 0x100, PAIRING_LHS_MPTR, 0x80)
                        success := and(success, eq(returndatasize(), 0x80))
                    }
                }
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(15) // after public accumulator pairing batch prep (no-op when HAS_ACCUMULATOR_MPTR == 0)
            {%- endif %}

            // The Yul `ec_pairing` helper checks
            //   e(arg0, G2_BASE) * e(arg1, NEG_S_G2_BASE) == 1
            // i.e.  e(arg0, [1]_2) = e(arg1, [s]_2).
            //
            // The KZG pairing identity is
            //   e(final_com - v*G + x3*pi, [1]_2) = e(pi, [s]_2),
            // so arg0 must be (final_com - v*G + x3*pi) and arg1 must be
            // pi. The PAIRING_*_MPTR slots store
            //   PAIRING_LHS_MPTR := pi
            //   PAIRING_RHS_MPTR := final_com - v*G + x3*pi
            // -- the historical "LHS"/"RHS" naming follows the dual MSM
            // accumulator (left = pi, right = combined) and *not* the
            // pairing argument order. Pass them swapped to ec_pairing.
            if iszero(success) { revert(0, 0) }
            success := ec_pairing(success, PAIRING_RHS_MPTR, PAIRING_LHS_MPTR)

            {%- if self.gas_checkpoints %}
            gas_checkpoint(16) // after final ec_pairing
            {%- endif %}

            {%- if self.trace %}
            trace_u256(1,  mload(VK_DIGEST_MPTR))
            trace_u256(2,  mload(NUM_INSTANCES_MPTR))
            trace_u256(3,  mload(K_MPTR))
            trace_u256(4,  mload(N_INV_MPTR))
            trace_u256(5,  mload(OMEGA_MPTR))
            trace_u256(6,  mload(OMEGA_INV_MPTR))
            {%- for phase in user_phases %}
            {%- for j in 0..phase.num_challenges %}
            trace_u256({{ 1000 + phase.challenge_offset + j }}, mload(add(CHALLENGE_MPTR, {{ ((phase.challenge_offset + j) * 32)|hex() }})))
            {%- endfor %}
            {%- endfor %}
            trace_u256(7,  mload(THETA_MPTR))
            trace_u256(8,  mload(BETA_MPTR))
            trace_u256(9,  mload(GAMMA_MPTR))
            trace_u256(10, mload(Y_MPTR))
            trace_u256(11, mload(X_MPTR))
            {%- if num_trashcans != 0 %}
            trace_u256(12, mload(TRASH_CHALLENGE_MPTR))
            {%- endif %}
            trace_u256(13, mload(X1_MPTR))
            trace_u256(14, mload(X2_MPTR))
            trace_u256(15, mload(X3_MPTR))
            trace_u256(16, mload(X4_MPTR))
            trace_u256(17, mload(X_N_MPTR))
            trace_u256(18, mload(X_N_MINUS_1_INV_MPTR))
            trace_u256(19, mload(L_LAST_MPTR))
            trace_u256(20, mload(L_BLIND_MPTR))
            trace_u256(21, mload(L_0_MPTR))
            trace_u256(22, mload(INSTANCE_EVAL_MPTR))
            trace_u256(23, mload(QUOTIENT_EVAL_MPTR))
            trace_u256(36, addmod(0, sub(r, mload(QUOTIENT_EVAL_MPTR)), r))
            mstore(add(QUOTIENT_MPTR, 0x40), 0)
            mstore(add(QUOTIENT_MPTR, 0x60), 0)
            trace_point(24, QUOTIENT_MPTR)
            trace_point(25, F_COM_MPTR)
            trace_point(26, PI_MPTR)
            trace_u256(31, mload(F_EVAL_MPTR))
            trace_u256(32, mload(V_MPTR))
            trace_point(33, FINAL_COM_MPTR)
            trace_u256(35, success)
            {%- for _ in simple_selector_cols %}
            trace_u256({{ 60000 + loop.index0 }}, mload(add(SELECTOR_ACC_MPTR, {{ (loop.index0 * 32)|hex() }})))
            {%- endfor %}
            if mload(HAS_ACCUMULATOR_MPTR) {
                trace_point(29, ACC_LHS_MPTR)
                trace_point(30, ACC_RHS_MPTR)
            }
            {%- endif %}

            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}
