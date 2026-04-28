
pragma solidity ^0.8.0;

// Halo2 KZG verifier for the BLS12-381 curve, midnight-proofs flavour.
//
// Differences vs the original BN254 / halo2 v0.4 template:
//
//   * BLS12-381 base field Fp is 381 bits and does not fit in a uint256.
//     Each Fp coord is encoded EIP-2537 padded (16 zero bytes + 48 bytes).
//     A G1 point is 128 bytes (4 words); a G2 point is 256 bytes (8).
//   * Calldata carries G1 commitments in uncompressed EIP-2537 padded
//     form (4 words = 128 bytes per point: x_hi, x_lo, y_hi, y_lo). The
//     proof bytes produced by midnight-proofs prover are repacked off
//     chain (compressed -> uncompressed) before being passed to
//     `verifyProof`. The verifier hashes the **uncompressed** 128-byte
//     form into the transcript verbatim (matches the patched
//     `Hashable<Keccak256> for G1Projective::to_input` in
//     midnight-proofs); see `common_uncompressed_g1`.
//   * Transcript is a streaming Keccak256 with domain separator
//     "Domain separator for transcript" + PREFIX_COMMON (0x01) before
//     each absorbed value + PREFIX_CHALLENGE (0x00) before each squeeze.
//     Squeeze is a two-fork: clone state || 0x00 then clone state ||
//     0x01, finalize each, concat to 64 bytes, reseed.
//   * Fq sampling: from_uniform_bytes(64) = a0 + a1 * 2^256 (mod r),
//     where a0 = LE int of bytes[0..32], a1 = LE int of bytes[32..64].
//   * Scalar inversion uses modexp(scalar, r-2, r).
//   * Precompiles:
//       0x05 modexp (used for Fr inversion)
//       0x0b BLS12_G1ADD
//       0x0c BLS12_G1MSM
//       0x0f BLS12_PAIRING_CHECK
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
    uint256 internal constant NUM_INSTANCE_CPTR = {{ num_instance_cptr|hex_padded(2) }};
    uint256 internal constant     INSTANCE_CPTR = {{ instance_cptr|hex_padded(2) }};

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = {{ quotient_comm_cptr }};
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = {{ quotient_comm_cptr + 4 * (num_quotients - 1) }};

    // ----------------------------------------------------------------------
    // Verifying-key memory map. The VK header lives at VK_MPTR; the
    // commitments live just above. After VK comes the challenge slots
    // (challenge_mptr..) and the per-stage scratch (theta_mptr..).
    // ----------------------------------------------------------------------
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
    uint256 internal constant            G1_BASE_MPTR = {{ vk_mptr + 11 }};
    uint256 internal constant            G2_BASE_MPTR = {{ vk_mptr + 15 }};
    uint256 internal constant      NEG_S_G2_BASE_MPTR = {{ vk_mptr + 23 }};

    uint256 internal constant CHALLENGE_MPTR = {{ challenge_mptr }};

    // Challenge layout. Squeeze order in midnight-proofs:
    //   user_phase challenges (variable count)
    //   theta -> beta, gamma -> trash_challenge -> y -> x ->
    //   x1, x2 -> x3 -> x4
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

    // Decompressed batch-open commitments live in 4-word slots.
    uint256 internal constant             F_COM_MPTR = {{ theta_mptr + 10 }};
    uint256 internal constant                PI_MPTR = {{ theta_mptr + 14 }};

    // Accumulator (KZG IVC).
    uint256 internal constant          ACC_LHS_MPTR = {{ theta_mptr + 18 }};
    uint256 internal constant          ACC_RHS_MPTR = {{ theta_mptr + 22 }};

    // Lagrange / quotient scratch.
    uint256 internal constant              X_N_MPTR = {{ theta_mptr + 26 }};
    uint256 internal constant  X_N_MINUS_1_INV_MPTR = {{ theta_mptr + 27 }};
    uint256 internal constant           L_LAST_MPTR = {{ theta_mptr + 28 }};
    uint256 internal constant          L_BLIND_MPTR = {{ theta_mptr + 29 }};
    uint256 internal constant              L_0_MPTR = {{ theta_mptr + 30 }};
    uint256 internal constant     INSTANCE_EVAL_MPTR = {{ theta_mptr + 31 }};
    uint256 internal constant     QUOTIENT_EVAL_MPTR = {{ theta_mptr + 32 }};
    uint256 internal constant         QUOTIENT_MPTR = {{ theta_mptr + 33 }};   // 4 words
    uint256 internal constant        G1_SCALAR_MPTR = {{ theta_mptr + 37 }};
    uint256 internal constant            F_EVAL_MPTR = {{ theta_mptr + 38 }};
    uint256 internal constant                 V_MPTR = {{ theta_mptr + 39 }};
    uint256 internal constant         FINAL_COM_MPTR = {{ theta_mptr + 40 }};   // 4 words
    uint256 internal constant      PAIRING_LHS_MPTR = {{ theta_mptr + 44 }};   // 4 words
    uint256 internal constant      PAIRING_RHS_MPTR = {{ theta_mptr + 48 }};   // 4 words

    // Multi-prepare scratch (sized at codegen time).
    uint256 internal constant       ROT_POINTS_MPTR = {{ theta_mptr + 52 }};
    uint256 internal constant       X1_POWERS_MPTR = {{ theta_mptr + 80 }};
    uint256 internal constant            Q_COM_MPTR = {{ theta_mptr + 112 }};
    uint256 internal constant      Q_EVAL_SET_MPTR = {{ theta_mptr + 144 }};

    // Q_EVAL_CPTR is set at runtime once the verifier reaches the q_evals
    // block of the proof; we keep it as a memory slot for symmetry.
    uint256 internal constant         Q_EVAL_CPTR_MPTR = {{ theta_mptr + 200 }};

    // Reserved 4-word slot for the G1 identity (point at infinity) in
    // EIP-2537 padded form. EVM memory is zero-initialised, and we
    // never write to this region, so the four `mload`s below produce
    // 0,0,0,0 which is exactly the identity encoding the EIP-2537
    // ec_add / ec_mul precompiles accept.
    uint256 internal constant       G1_IDENTITY_MPTR = {{ theta_mptr + 208 }};

    // Pre-reversed polynomial-eval buffer (Optimisation H3). Each Fq
    // evaluation in the proof byte stream is LE-encoded (`Fq::to_repr`)
    // but Yul's `calldataload` reads BE, so every reference would
    // normally pay ~145 gas of `byte_reverse_32(calldataload(...))`.
    // The transcript-side `evaluations` loop already computes the
    // byte-reversed value once (for range-checking `eval_le < r`); we
    // spill it to this buffer so the 174 downstream eval references
    // (in the gate evaluator + PCS q_eval Horner) become 3-gas
    // `mload(...)` instead.
    uint256 internal constant     REVERSED_EVALS_MPTR = {{ reversed_evals_mptr }};

    // ----------------------------------------------------------------------
    // Per-category bases for decompressed G1 commitments. The proof emits
    // G1 commitments in zcash-compressed form (48 bytes each); this region
    // holds the decompressed EIP-2537 padded form (4 words = 128 bytes
    // each) used by the PCS / quotient-fold sections.
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
    uint256 internal constant         ADVICE_COMMS_MPTR_BASE = {{ comms_mptr_base }};
    uint256 internal constant       LOOKUP_M_COMMS_MPTR_BASE = {{ comms_mptr_base + 4 * total_advices }};
    uint256 internal constant         PERM_Z_COMMS_MPTR_BASE = {{ comms_mptr_base + 4 * total_advices + 4 * num_lookups }};
    uint256 internal constant  LOOKUP_HELPER_COMMS_MPTR_BASE = {{ comms_mptr_base + 4 * total_advices + 4 * num_lookups + 4 * num_permutation_zs }};
    uint256 internal constant       LOOKUP_Z_COMMS_MPTR_BASE = {{ comms_mptr_base + 4 * total_advices + 4 * num_lookups + 4 * num_permutation_zs + 4 * lookup_helper_chunks_total }};
    uint256 internal constant     TRASHCAN_COMMS_MPTR_BASE = {{ comms_mptr_base + 4 * total_advices + 4 * num_lookups + 4 * num_permutation_zs + 4 * lookup_helper_chunks_total + 4 * num_lookups }};
    uint256 internal constant QUOTIENT_LIMB_COMMS_MPTR_BASE = {{ comms_mptr_base + 4 * total_advices + 4 * num_lookups + 4 * num_permutation_zs + 4 * lookup_helper_chunks_total + 4 * num_lookups + 4 * num_trashcans }};

    // Fr modulus and Montgomery constant 2^256 mod r used by from_uniform_bytes.
    uint256 internal constant FR_MODULUS        = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    uint256 internal constant FR_R_2POW256_MOD  = 0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe;

    // Prefix bytes for the Keccak256 transcript (matches the `Domain
    // separator for transcript` literal in midnight-proofs). The string
    // is 31 bytes; the bottom byte of this bytes32 is zero padding and
    // is overwritten by the first absorb in `transcript_init`.
    bytes32 internal constant DOMAIN_SEPARATOR = "Domain separator for transcript";

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
    ) public {%- if self.trace || self.gas_checkpoints %} returns (bool) {%- else %} view returns (bool) {%- endif %} {
        {%- match self.embedded_vk %}
        {%- when None %}
        address vk = AUTHORIZED_VK;
        if (vk.code.length != EXPECTED_VK_LENGTH || vk.codehash != EXPECTED_VK_CODEHASH) {
            return false;
        }
        {%- else %}
        {%- endmatch %}
        assembly ("memory-safe") {
            // ===============================================================
            // Helpers: byte-order, modexp, decompress, transcript
            // ===============================================================

            // Reverse the byte order of a 32-byte word. Used for Fq LE
            // scalars read from calldata that need to be interpreted as
            // big-endian integers (or vice versa).
            // 256-bit byte reversal. We unroll 31 of the 32 iterations
            // and leave the last as a trivial 1-trip loop. The loop
            // guard is what stops solc from inlining the entire 32-step
            // body at every call site (~184 sites in this verifier);
            // when fully unrolled, solc inlines aggressively under
            // `--via-ir` and the resulting bytecode triggers a
            // pathology where the verifier consumes the full block
            // gas limit instead of the expected ~1.5 M. Keeping a
            // single-iter loop preserves the function-call boundary
            // and saves ~480 kg vs the original 32-iter loop. Each
            // call site goes from ~700 gas (loop overhead × 32 iters)
            // to ~140 gas (32 byte-extracts + ORs, function-call
            // overhead).
            function byte_reverse_32(x) -> r {
                r := byte(0, x)
                r := or(r, shl(8, byte(1, x)))
                r := or(r, shl(16, byte(2, x)))
                r := or(r, shl(24, byte(3, x)))
                r := or(r, shl(32, byte(4, x)))
                r := or(r, shl(40, byte(5, x)))
                r := or(r, shl(48, byte(6, x)))
                r := or(r, shl(56, byte(7, x)))
                r := or(r, shl(64, byte(8, x)))
                r := or(r, shl(72, byte(9, x)))
                r := or(r, shl(80, byte(10, x)))
                r := or(r, shl(88, byte(11, x)))
                r := or(r, shl(96, byte(12, x)))
                r := or(r, shl(104, byte(13, x)))
                r := or(r, shl(112, byte(14, x)))
                r := or(r, shl(120, byte(15, x)))
                r := or(r, shl(128, byte(16, x)))
                r := or(r, shl(136, byte(17, x)))
                r := or(r, shl(144, byte(18, x)))
                r := or(r, shl(152, byte(19, x)))
                r := or(r, shl(160, byte(20, x)))
                r := or(r, shl(168, byte(21, x)))
                r := or(r, shl(176, byte(22, x)))
                r := or(r, shl(184, byte(23, x)))
                r := or(r, shl(192, byte(24, x)))
                r := or(r, shl(200, byte(25, x)))
                r := or(r, shl(208, byte(26, x)))
                r := or(r, shl(216, byte(27, x)))
                r := or(r, shl(224, byte(28, x)))
                r := or(r, shl(232, byte(29, x)))
                r := or(r, shl(240, byte(30, x)))
                for { let i := 31 } lt(i, 32) { i := add(i, 1) } {
                    r := or(r, shl(mul(i, 8), byte(i, x)))
                }
            }

            // Inverse of a Fr scalar via modexp(x, r-2, r). Uses memory
            // [0x6000..0x60e0] as scratch — chosen to live ABOVE every
            // labeled MPTR in this verifier so callers don't have to
            // worry about clobbering theta/beta/gamma (originally placed
            // at 0x2000, which collided with `THETA_MPTR = 0x2040`,
            // `BETA_MPTR = 0x2060`, `GAMMA_MPTR = 0x2080` and silently
            // overwrote the squeezed challenges with the modexp input
            // bytes — a ~960k-gas pairing rejection that took a few
            // hours to track down). The full memory map ends at the
            // last QUOTIENT_LIMB_COMMS_MPTR_BASE slot (well below
            // 0x5000 even for 32-quotient-limb circuits), so 0x6000 is
            // a safe permanent home; if a future codegen change moves
            // any MPTR past 0x6000, bump this constant in lock-step.
            function scalar_inv(x) -> inv {
                let p := 0x6000
                mstore(p,            0x20)        // base len
                mstore(add(p, 0x20), 0x20)        // exp len
                mstore(add(p, 0x40), 0x20)        // mod len
                mstore(add(p, 0x60), x)
                mstore(add(p, 0x80), sub(FR_MODULUS, 2))
                mstore(add(p, 0xa0), FR_MODULUS)
                if iszero(staticcall(gas(), 0x05, p, 0xc0, p, 0x20)) { revert(0, 0) }
                inv := mload(p)
            }

            // ---------- Streaming Keccak256 transcript helpers ----------
            //
            // The transcript buffer lives at memory[0x00..buf_len). On
            // verifier entry we seed it with the 30-byte domain separator;
            // every common(input) prepends a single PREFIX_COMMON byte and
            // then writes the input bytes. squeeze_*(buf_len) computes the
            // 64-byte two-fork keccak output, reseeds the buffer, and
            // samples a Fq element via from_uniform_bytes.

            function transcript_init() -> buf_len {
                // Write the 31-byte domain separator. The literal is
                // stored left-aligned in DOMAIN_SEPARATOR; the trailing
                // byte (zero) is overwritten by the first PREFIX_COMMON
                // absorb.
                mstore(0x00, DOMAIN_SEPARATOR)
                buf_len := 31
            }

            // Append PREFIX_COMMON || word[0..32] at the current end of the
            // transcript buffer.
            function common_word(buf_len, word) -> ret {
                mstore8(buf_len, 0x01)
                mstore(add(buf_len, 1), word)
                ret := add(buf_len, 33)
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
            // Malleability: an attacker could submit non-zero bytes
            // in the top 16 bytes of each `_hi` calldata word (the
            // EIP-2537 precompile would reject those later, but only
            // after they had been hashed). We mask those padding
            // bytes to zero before the keccak absorb so the
            // transcript only ever commits to the canonical form.
            //
            // The point's uncompressed form remains in calldata; the
            // call site is responsible for `calldatacopy`-ing it into
            // memory afterwards if it needs the on-curve coordinates.
            function common_uncompressed_g1(buf_len, cptr) -> ret {
                // Append PREFIX_COMMON.
                mstore8(buf_len, 0x01)
                // Memcpy the 4 calldata words (128 bytes) verbatim
                // into the keccak buffer right after PREFIX_COMMON.
                calldatacopy(add(buf_len, 1), cptr, 0x80)
                // Mask the top 16 bytes of x_hi and y_hi to zero so
                // that an attacker cannot grind the transcript by
                // submitting non-canonical padding bytes. EIP-2537
                // requires the top 16 bytes of each `_hi` word to be
                // zero; we enforce it here at the hash boundary
                // rather than at the precompile boundary so that the
                // hash commits to canonical bytes only.
                let x_hi_off := add(buf_len, 1)
                let y_hi_off := add(buf_len, 0x41)
                mstore(x_hi_off, and(mload(x_hi_off), 0xffffffffffffffffffffffffffffffff))
                mstore(y_hi_off, and(mload(y_hi_off), 0xffffffffffffffffffffffffffffffff))
                ret := add(buf_len, 0x81)
            }

            // PREFIX_CHALLENGE + two-fork keccak + reseed. Returns the new
            // buffer length (= 64) and stores the squeezed Fq at `mptr`.
            function squeeze_to(buf_len, mptr) -> ret {
                // Append PREFIX_CHALLENGE (0x00) at buf_len. midnight-proofs
                // (`midfall/proofs/src/transcript/mod.rs:15`) defines
                // `KECCAK256_PREFIX_CHALLENGE: u8 = 0`. Earlier verifier
                // generations targeting the upstream halo2 BN254 transcript
                // hard-coded `0x02` here, which silently rerouted the
                // challenge stream onto a different domain and produced
                // garbage scalars; we keep the byte writable so the next
                // line can overlay the per-fork tag (0x00 / 0x01) without
                // moving the cursor.
                mstore8(buf_len, 0x00)
                // Append 0x00; first fork.
                mstore8(add(buf_len, 1), 0x00)
                let h0 := keccak256(0x00, add(buf_len, 2))
                // Append 0x01 (overwrites the previous 0x00); second fork.
                mstore8(add(buf_len, 1), 0x01)
                let h1 := keccak256(0x00, add(buf_len, 2))
                // Reseed: write 64 bytes at start of buffer.
                mstore(0x00, h0)
                mstore(0x20, h1)
                // Sample Fq via from_uniform_bytes(64 bytes LE).
                // h0 is the BE-loaded 32-byte int of bytes [0..32];
                // we need its LE int interpretation. Same for h1.
                let a0 := byte_reverse_32(h0)
                let a1 := byte_reverse_32(h1)
                let r := FR_MODULUS
                mstore(mptr,
                    addmod(
                        mod(a0, r),
                        mulmod(mod(a1, r), FR_R_2POW256_MOD, r),
                        r
                    )
                )
                ret := 64
            }

            // ---------- EC primitives (EIP-2537 wrappers) ----------
            //
            // These mirror the BN254 helpers but operate on 4-word G1
            // points. They use the [0x100..0x500) memory window as
            // scratch; the streaming transcript buffer at [0x00..buf_len)
            // is no longer needed once all challenges are squeezed.

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

            function ec_add_acc(success) -> ret {
                ret := and(success, staticcall(gas(), 0x0b, 0x100, 0x100, 0x100, 0x80))
            }
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x180, scalar)
                ret := and(success, staticcall(gas(), 0x0c, 0x100, 0xa0, 0x100, 0x80))
            }
            function ec_add_tmp(success) -> ret {
                ret := and(success, staticcall(gas(), 0x0b, 0x180, 0x100, 0x180, 0x80))
            }
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0x200, scalar)
                ret := and(success, staticcall(gas(), 0x0c, 0x180, 0xa0, 0x180, 0x80))
            }

            function ec_pairing(success, lhs_mptr, rhs_mptr) -> ret {
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
                ret := and(success, staticcall(gas(), 0x0f, scratch, 0x300, scratch, 0x20))
                ret := and(ret, mload(scratch))
            }

            {%- if self.trace %}
            function trace_u256(id, value) {
                mstore(0x5e00, value)
                log1(0x5e00, 0x20, id)
            }
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

                success := and(success, eq({{ proof_len|hex() }}, calldataload(PROOF_LEN_CPTR)))

                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, calldataload(NUM_INSTANCE_CPTR)))
                success := and(
                    success,
                    eq(calldatasize(), add(INSTANCE_CPTR, mul(0x20, num_instances)))
                )
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(2) // after VK loading
            {%- endif %}

            // ===============================================================
            // Transcript: domain sep + VK digest + instances + proof.
            // ===============================================================
            let buf_len := transcript_init()
            // VK_DIGEST_MPTR holds the digest as a BE 32-byte word (the
            // VK contract stores it via `mstore`, which is BE). Native
            // midnight-proofs hashes `Fq::to_repr()` (LE bytes), so we
            // byte-reverse before absorbing.
            buf_len := common_word(buf_len, byte_reverse_32(mload(VK_DIGEST_MPTR)))

            // Absorb committed_pi = G1Affine::identity() when the
            // `committed-instances` feature is on in midnight-proofs.
            // Under the patched `Hashable<Keccak256>::to_input` (see
            // `midfall/proofs/src/transcript/implementors.rs`), the
            // identity hashes as 128 zero bytes (EIP-2537 (0,0)
            // convention), NOT the 48-byte ZCash compressed form
            // 0xc0||47*0x00 that the previous emitter produced.
            // Native verifier absorbs this BEFORE the instance count.
            {
                // PREFIX_COMMON (0x01) at buf_len.
                mstore8(buf_len, 0x01)
                // 128 zero bytes: zero out 4 consecutive 32-byte words
                // at buf_len+1.
                mstore(add(buf_len, 1),    0)
                mstore(add(buf_len, 0x21), 0)
                mstore(add(buf_len, 0x41), 0)
                mstore(add(buf_len, 0x61), 0)
                buf_len := add(buf_len, 0x81)
            }

            {
                let num_instances := mload(NUM_INSTANCES_MPTR)
                // common(num_instances as Fq scalar in LE-32). The number is
                // small so its LE int = its value; the BE-int form (what
                // mstore would write) needs to be byte-reversed before
                // hashing.
                buf_len := common_word(buf_len, byte_reverse_32(num_instances))

                let instance_cptr := INSTANCE_CPTR
                for { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    { instance_cptr := add(instance_cptr, 0x20) } {
                    let inst_be := calldataload(instance_cptr)
                    success := and(success, lt(inst_be, r))
                    // Instances are passed BE in calldata (uint256[]); convert
                    // to LE to match midnight-proofs Fq::to_repr().
                    buf_len := common_word(buf_len, byte_reverse_32(inst_be))
                }
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(3) // after VK digest + committed_pi + instance absorbs
            {%- endif %}

            // ===============================================================
            // Per-user-phase reads + challenge squeezes.
            //
            // Each compressed G1 absorbed into the transcript is also
            // decompressed inline and stored at the corresponding
            // per-category MPTR (4-word EIP-2537 padded form). The PCS
            // / quotient-fold blocks below dereference those MPTRs.
            // ===============================================================
            let proof_cptr := PROOF_CPTR
            let advice_walk := ADVICE_COMMS_MPTR_BASE

            {%- for phase in user_phases %}
            // ---- User phase {{ loop.index }} ----
            for { let end := add(proof_cptr, {{ (phase.num_advices * 128)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_uncompressed_g1(buf_len, proof_cptr)
                calldatacopy(advice_walk, proof_cptr, 0x80)
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
                lookup_helper_walk := add(lookup_helper_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x80)
            }
            buf_len := common_uncompressed_g1(buf_len, proof_cptr)
            calldatacopy(lookup_z_walk, proof_cptr, 0x80)
            lookup_z_walk := add(lookup_z_walk, 0x80)
            proof_cptr := add(proof_cptr, 0x80)
            {%- endfor %}
            {%- endif %}

            {%- if self.gas_checkpoints %}
            gas_checkpoint(7) // after lookup helpers + Z accumulators
            {%- endif %}

            {%- if num_trashcans != 0 %}
            // ---- trash_challenge ----
            buf_len := squeeze_to(buf_len, TRASH_CHALLENGE_MPTR)
            // ---- trashcans ----
            let trashcan_walk := TRASHCAN_COMMS_MPTR_BASE
            for { let end := add(proof_cptr, {{ (num_trashcans * 128)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_uncompressed_g1(buf_len, proof_cptr)
                calldatacopy(trashcan_walk, proof_cptr, 0x80)
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
                quotient_walk := add(quotient_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x80)
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(9) // after y squeeze + quotient-limb reads
            {%- endif %}

            // ---- x ----
            buf_len := squeeze_to(buf_len, X_MPTR)

            // ---- evaluations ----
            // Optimisation H3: spill the byte-reversed eval_le into the
            // REVERSED_EVALS_MPTR buffer in the same iteration we
            // already compute it for range-checking. ~5 gas amortised
            // per iter; replaces ~145 gas of byte_reverse_32 per
            // downstream reference (174 references in the verifier,
            // ~25 kg total saving).
            {
                let eval_buf := REVERSED_EVALS_MPTR
                for { let end := add(proof_cptr, {{ (num_evals * 32)|hex() }}) }
                    lt(proof_cptr, end)
                    {} {
                    let eval_be := calldataload(proof_cptr)
                    let eval_le := byte_reverse_32(eval_be)
                    success := and(success, lt(eval_le, r))
                    mstore(eval_buf, eval_le)
                    eval_buf := add(eval_buf, 0x20)
                    buf_len := common_word(buf_len, eval_be)
                    proof_cptr := add(proof_cptr, 0x20)
                }
            }

            // ---- x1, x2 ----
            buf_len := squeeze_to(buf_len, X1_MPTR)
            buf_len := squeeze_to(buf_len, X2_MPTR)

            // ---- f_com (1 uncompressed G1) ----
            buf_len := common_uncompressed_g1(buf_len, proof_cptr)
            calldatacopy(F_COM_MPTR, proof_cptr, 0x80)
            proof_cptr := add(proof_cptr, 0x80)

            // ---- x3 ----
            buf_len := squeeze_to(buf_len, X3_MPTR)
            {%- if truncated_challenges %}
            // truncated-challenges: x3 is the f_com evaluation point and
            // is used directly (not as a power base); midnight-proofs
            // truncates it to 128 bits at squeeze time, so we must mirror
            // that here. The `and` cost (~3 gas) is negligible compared to
            // the modexp ladders downstream that consume x3.
            mstore(X3_MPTR, and(mload(X3_MPTR), 0xffffffffffffffffffffffffffffffff))
            {%- endif %}

            // ---- q_evals (one Fq per point set) ----
            mstore(Q_EVAL_CPTR_MPTR, proof_cptr)
            for { let end := add(proof_cptr, {{ (num_point_sets * 32)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                let eval_be := calldataload(proof_cptr)
                let eval_le := byte_reverse_32(eval_be)
                success := and(success, lt(eval_le, r))
                buf_len := common_word(buf_len, eval_be)
                proof_cptr := add(proof_cptr, 0x20)
            }

            // ---- x4 ----
            buf_len := squeeze_to(buf_len, X4_MPTR)

            // ---- pi (1 uncompressed G1) ----
            buf_len := common_uncompressed_g1(buf_len, proof_cptr)
            calldatacopy(PI_MPTR, proof_cptr, 0x80)
            proof_cptr := add(proof_cptr, 0x80)

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

            {%- if self.gas_checkpoints %}
            gas_checkpoint(11) // after Lagrange + instance evaluation block
            {%- endif %}

            // ===============================================================
            // Quotient evaluation. Pure Fr arithmetic.
            // ===============================================================
            {
                let delta := 3793952369011177517951424454785176000433849974408744014172535497121832470999 // BLS12-381 Fr::DELTA
                let y := mload(Y_MPTR)

                {%- for code_block in quotient_eval_numer_computations %}
                {%- for line in code_block %}
                {{ line }}
                {%- endfor %}
                {%- endfor %}


                pop(y)
                pop(delta)

                // The linearization-poly target eval at x is the (negated)
                // sum of fully-evaluated identities — see
                // `compute_linearization_commitment` in
                // midfall/proofs/src/plonk/linearization/verifier.rs:
                //
                //   expected_eval -= eval     (for col_idx == None)
                //
                // For our setting (num_simple_selectors == 0) every
                // identity is fully evaluated, so the target eval is
                // -quotient_eval_numer. The point is paired with a
                // commitment that already includes the (1 - x^n)
                // factor (see splitting_pow init below), so we do
                // NOT divide by (x^n - 1) here.
                let quotient_eval := sub(r, quotient_eval_numer)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(12) // after quotient evaluation (Fr arithmetic)
            {%- endif %}

            // ===============================================================
            // Compute the linearization commitment as a single
            // multi-pair G1MSM (optimisation #1, OPTIMISATION.md).
            //
            // Native math (from `compute_linearization_commitment`):
            //   QUOTIENT = (1 - x^n) * Σ_i x_split^i * Q_i
            //            + Σ_j sel_acc_j * S_j_com
            // where x_split = x^(n-1) is the splitting factor and Q_i are
            // the quotient limbs at QUOTIENT_LIMB_COMMS_MPTR_BASE.
            //
            // The naive emitter does
            //   k × ec_mul_acc + k × ec_add_acc  (Horner fold)
            //   + 1 × ec_mul_acc                 ((1-x^n) scale)
            //   + n_sel × (ec_mul_tmp + ec_add_acc)
            // = (k + 1 + n_sel) single-pair G1MSMs.
            //
            // EIP-2537 G1MSM gas is concave in pair count, so we
            // pre-compute the Fr scalars
            //   [(1-x^n)·1, (1-x^n)·x_split, …, (1-x^n)·x_split^{k-1},
            //    sel_acc_0, sel_acc_1, …, sel_acc_{n_sel-1}]
            // stage all (point, scalar) pairs contiguously at
            // 0x100, and dispatch one staticcall(0x0c). The pair
            // layout (160 bytes per pair) is the EIP-2537 BLS12_G1MSM
            // input format: 4 words point || 1 word scalar.
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

                // MSM input staging at 0x100 (free during this block —
                // the per-pair ec_mul_acc / ec_add_acc temporaries that
                // used 0x100..0x300 are gone). Each pair = 0xa0 bytes.
                let p := 0x100
                let cur_scalar := one_minus_x_n
                let q := QUOTIENT_LIMB_COMMS_MPTR_BASE

                // Quotient-limb pairs: (Q_i, (1-x^n) · x_split^i).
                // Use Cancun MCOPY to copy each 4-word point in one
                // op (~18 gas) instead of the 4-mstore chain which
                // solc-via-ir compiles to ~60-100 gas.
                for { let i := 0 } lt(i, {{ num_quotients }}) { i := add(i, 1) } {
                    mcopy(p, q, 0x80)
                    mstore(add(p, 0x80), cur_scalar)
                    cur_scalar := mulmod(cur_scalar, x_split, r)
                    p := add(p, 0xa0)
                    q := add(q, 0x80)
                }

                {%- if simple_selector_cols.len() > 0 %}
                // Simple-selector pairs: (S_j_com, sel_acc_j). Mirrors
                // the `Some(col_idx)` branch of
                // `compute_linearization_commitment`. MCOPY each 4-word
                // point in one op.
                {%- for col in simple_selector_cols %}
                mcopy(p, {{ (fixed_comm_mptr + col * 0x80)|hex() }}, 0x80)
                mstore(add(p, 0x80), mload({{ (0x5000 + loop.index0 * 0x20)|hex() }}))
                p := add(p, 0xa0)
                {%- endfor %}
                {%- endif %}

                // One multi-pair MSM. Result = QUOTIENT (4 words at 0x100).
                success := and(
                    success,
                    staticcall(
                        gas(),
                        0x0c,
                        0x100,
                        {{ (0xa0 * (num_quotients + simple_selector_cols.len()))|hex() }},
                        0x100,
                        0x80
                    )
                )

                // MCOPY the 4-word MSM result back to QUOTIENT_MPTR.
                mcopy(QUOTIENT_MPTR, 0x100, 0x80)
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(13) // after linearization-commitment MSM
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

            // Random-linear combine accumulator into pairing inputs.
            if mload(HAS_ACCUMULATOR_MPTR) {
                let h := keccak256(ACC_LHS_MPTR, 0x200) // 4 G1 points = 4*128 = 0x200
                let challenge := mod(h, r)

                mstore(0x100, mload(ACC_LHS_MPTR))
                mstore(0x120, mload(add(ACC_LHS_MPTR, 0x20)))
                mstore(0x140, mload(add(ACC_LHS_MPTR, 0x40)))
                mstore(0x160, mload(add(ACC_LHS_MPTR, 0x60)))
                success := ec_mul_acc(success, challenge)
                mstore(0x180, mload(PAIRING_LHS_MPTR))
                mstore(0x1a0, mload(add(PAIRING_LHS_MPTR, 0x20)))
                mstore(0x1c0, mload(add(PAIRING_LHS_MPTR, 0x40)))
                mstore(0x1e0, mload(add(PAIRING_LHS_MPTR, 0x60)))
                success := ec_add_acc(success)
                mstore(PAIRING_LHS_MPTR,            mload(0x100))
                mstore(add(PAIRING_LHS_MPTR, 0x20), mload(0x120))
                mstore(add(PAIRING_LHS_MPTR, 0x40), mload(0x140))
                mstore(add(PAIRING_LHS_MPTR, 0x60), mload(0x160))

                mstore(0x100, mload(ACC_RHS_MPTR))
                mstore(0x120, mload(add(ACC_RHS_MPTR, 0x20)))
                mstore(0x140, mload(add(ACC_RHS_MPTR, 0x40)))
                mstore(0x160, mload(add(ACC_RHS_MPTR, 0x60)))
                success := ec_mul_acc(success, challenge)
                mstore(0x180, mload(PAIRING_RHS_MPTR))
                mstore(0x1a0, mload(add(PAIRING_RHS_MPTR, 0x20)))
                mstore(0x1c0, mload(add(PAIRING_RHS_MPTR, 0x40)))
                mstore(0x1e0, mload(add(PAIRING_RHS_MPTR, 0x60)))
                success := ec_add_acc(success)
                mstore(PAIRING_RHS_MPTR,            mload(0x100))
                mstore(add(PAIRING_RHS_MPTR, 0x20), mload(0x120))
                mstore(add(PAIRING_RHS_MPTR, 0x40), mload(0x140))
                mstore(add(PAIRING_RHS_MPTR, 0x60), mload(0x160))
            }

            {%- if self.gas_checkpoints %}
            gas_checkpoint(15) // after accumulator random-combine (no-op when HAS_ACCUMULATOR_MPTR == 0)
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
            success := ec_pairing(success, PAIRING_RHS_MPTR, PAIRING_LHS_MPTR)

            {%- if self.gas_checkpoints %}
            gas_checkpoint(16) // after final ec_pairing
            {%- endif %}

            {%- if self.trace %}
            // In trace builds we always run to the end so the host-side
            // comparison can collect every emitted log.
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
            trace_point(24, QUOTIENT_MPTR)
            trace_point(25, F_COM_MPTR)
            trace_point(26, PI_MPTR)
            trace_u256(31, mload(F_EVAL_MPTR))
            trace_u256(32, mload(V_MPTR))
            trace_point(33, FINAL_COM_MPTR)
            trace_point(27, PAIRING_LHS_MPTR)
            trace_point(28, PAIRING_RHS_MPTR)
            if mload(HAS_ACCUMULATOR_MPTR) {
                trace_point(29, ACC_LHS_MPTR)
                trace_point(30, ACC_RHS_MPTR)
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
