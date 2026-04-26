
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
//     `verifyProof`. The verifier still hashes the *compressed* 48-byte
//     encoding into the transcript (to match the native verifier); the
//     compressed bytes are reconstructed on the fly inside
//     `common_uncompressed_g1` from the four uncompressed words.
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

    // ----------------------------------------------------------------------
    // BLS12-381 base-field constants used by `common_uncompressed_g1` to
    // compute the sign(y) bit of the on-the-fly compressed encoding.
    // p is 381 bits so it spans 48 BE bytes (top 32 bytes in BLS_P_TOP32,
    // bottom 16 bytes left-aligned in BLS_P_BOT16_LEFT).
    // ----------------------------------------------------------------------
    uint256 internal constant BLS_P_TOP32        = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624;
    uint256 internal constant BLS_P_BOT16_LEFT   = 0x1eabfffeb153ffffb9feffffffffaaab00000000000000000000000000000000;

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
    ) public {%- if self.trace %} returns (bool) {%- else %} view returns (bool) {%- endif %} {
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
            function byte_reverse_32(x) -> r {
                r := 0
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
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

            // Read an uncompressed BLS12-381 G1 point from calldata
            // (4 words = 128 bytes; EIP-2537 padded form: x_hi, x_lo,
            // y_hi, y_lo) and absorb its compressed 48-byte zcash
            // encoding into the transcript buffer at `buf_len`.
            //
            // Compressed encoding (48 bytes):
            //   byte 0 high 3 bits = (compression=1, infinity, sign)
            //   x = 381 bits big-endian, top 3 bits cleared
            //
            // The compression bit is always set. The infinity bit is
            // set iff the point is the identity (all 4 words = 0). The
            // sign bit is `lex(y) > lex(p - y)`, computed with a
            // 384-bit limb subtraction (no precompiles, no modexp).
            //
            // The point's uncompressed form remains in calldata; the
            // call site is responsible for `calldatacopy`-ing it into
            // memory afterwards if it needs the on-curve coordinates.
            function common_uncompressed_g1(buf_len, cptr) -> ret {
                let x_hi_word := calldataload(cptr)
                let x_lo_word := calldataload(add(cptr, 0x20))
                let y_hi_word := calldataload(add(cptr, 0x40))
                let y_lo_word := calldataload(add(cptr, 0x60))

                // x_hi/x_lo are EIP-2537 padded: top 16 bytes of each
                // word are zero, payload sits in the bottom 16 bytes
                // for x_hi and the full 32 bytes for x_lo.
                let x_hi_payload := and(x_hi_word, 0xffffffffffffffffffffffffffffffff)
                let x_lo_payload := x_lo_word
                let y_hi_payload := and(y_hi_word, 0xffffffffffffffffffffffffffffffff)
                let y_lo_payload := y_lo_word

                let is_identity := iszero(or(or(or(x_hi_payload, x_lo_payload), y_hi_payload), y_lo_payload))

                // Default flag = 0x80 (compression bit). For identity
                // we OR in the infinity bit (0x40), giving 0xc0 and
                // zero out the x bytes.
                let flag := 0x80
                if is_identity {
                    flag := 0xc0
                    x_hi_payload := 0
                    x_lo_payload := 0
                }

                if iszero(is_identity) {
                    // ---- Determine sign by comparing y vs p - y ----
                    // p - y: subtract y from p (381-bit subtraction).
                    // y < p so this never underflows.
                    let p_top_int := BLS_P_TOP32
                    let p_bot_int := shr(128, BLS_P_BOT16_LEFT)
                    let p_l0 := shr(128, p_top_int)
                    let p_l1 := and(p_top_int, 0xffffffffffffffffffffffffffffffff)
                    let p_l2 := p_bot_int
                    let y_l0 := y_hi_payload
                    let y_l1 := shr(128, y_lo_payload)
                    let y_l2 := and(y_lo_payload, 0xffffffffffffffffffffffffffffffff)

                    let borrow := 0
                    let py_l2  := 0
                    switch lt(p_l2, y_l2)
                    case 1 {
                        py_l2 := sub(add(p_l2, 0x100000000000000000000000000000000), y_l2)
                        borrow := 1
                    }
                    default {
                        py_l2 := sub(p_l2, y_l2)
                    }
                    let py_l1 := 0
                    let p_l1_b := sub(p_l1, borrow)
                    switch lt(p_l1_b, y_l1)
                    case 1 {
                        py_l1 := sub(add(p_l1_b, 0x100000000000000000000000000000000), y_l1)
                        borrow := 1
                    }
                    default {
                        py_l1 := sub(p_l1_b, y_l1)
                        borrow := 0
                    }
                    let py_l0 := sub(sub(p_l0, borrow), y_l0)

                    // Compare y vs py limb-wise (l0, l1, l2 from MSB to LSB).
                    let lex_y_larger := 0
                    switch gt(y_l0, py_l0)
                    case 1 { lex_y_larger := 1 }
                    default {
                        switch eq(y_l0, py_l0)
                        case 1 {
                            switch gt(y_l1, py_l1)
                            case 1 { lex_y_larger := 1 }
                            default {
                                switch eq(y_l1, py_l1)
                                case 1 {
                                    if gt(y_l2, py_l2) { lex_y_larger := 1 }
                                }
                                default {}
                            }
                        }
                        default {}
                    }

                    if lex_y_larger {
                        flag := or(flag, 0x20)
                    }
                }

                // Build the 48 compressed bytes:
                //   byte 0: flag | (x_hi top byte)
                //   byte 1..16: rest of x_hi
                //   byte 16..48: x_lo
                // x_hi_payload occupies the low 128 bits (16 bytes) of
                // x_hi_word. The top 3 bits of the 381-bit x are zero
                // by construction (since x < p < 2^381 < 2^384), so
                // OR-ing the flag byte into the top byte is safe.
                //
                // Compressed-as-32-bytes top word:
                //   shl(128, x_hi_payload | (flag << 120))
                // i.e. the 16 payload bytes left-shifted by 128 bits
                // and the flag in the very top byte (byte 0 of the
                // memory word).
                mstore8(buf_len, 0x01)
                let comp_top := or(shl(128, x_hi_payload), shl(248, flag))
                mstore(add(buf_len, 1), comp_top)
                // Bytes 16..48 of the compressed encoding = x_lo.
                mstore(add(buf_len, 17), x_lo_payload)
                ret := add(buf_len, 49)
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
                let scratch := 0x300
                mstore(scratch,                  mload(lhs_mptr))
                mstore(add(scratch, 0x20),       mload(add(lhs_mptr, 0x20)))
                mstore(add(scratch, 0x40),       mload(add(lhs_mptr, 0x40)))
                mstore(add(scratch, 0x60),       mload(add(lhs_mptr, 0x60)))
                let g2 := G2_BASE_MPTR
                for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                    mstore(add(scratch, add(0x80, mul(i, 0x20))), mload(add(g2, mul(i, 0x20))))
                }
                mstore(add(scratch, 0x180), mload(rhs_mptr))
                mstore(add(scratch, 0x1a0), mload(add(rhs_mptr, 0x20)))
                mstore(add(scratch, 0x1c0), mload(add(rhs_mptr, 0x40)))
                mstore(add(scratch, 0x1e0), mload(add(rhs_mptr, 0x60)))
                let nsg2 := NEG_S_G2_BASE_MPTR
                for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                    mstore(add(scratch, add(0x200, mul(i, 0x20))), mload(add(nsg2, mul(i, 0x20))))
                }
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

            let r := FR_MODULUS
            let success := true

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

            // ===============================================================
            // Transcript: domain sep + VK digest + instances + proof.
            // ===============================================================
            let buf_len := transcript_init()
            // VK_DIGEST_MPTR holds the digest as a BE 32-byte word (the
            // VK contract stores it via `mstore`, which is BE). Native
            // midnight-proofs hashes `Fq::to_repr()` (LE bytes), so we
            // byte-reverse before absorbing.
            buf_len := common_word(buf_len, byte_reverse_32(mload(VK_DIGEST_MPTR)))

            // Absorb committed_pi = G1Affine::identity() (48 bytes:
            // 0xc0 || 47 zero bytes -- BLS12-381 compressed identity
            // encoding) when the `committed-instances` feature is on
            // in midnight-proofs. The Hashable<G1>::to_bytes path uses
            // the curve's GroupEncoding which yields these 48 bytes.
            // Native verifier absorbs this BEFORE the instance count.
            {
                // PREFIX_COMMON (0x01) at buf_len.
                mstore8(buf_len, 0x01)
                // 48-byte compressed identity = 0xc0 || 47 * 0x00.
                // Write 48 bytes of zeros starting at buf_len+1, then
                // set the very first byte to 0xc0.
                mstore(add(buf_len, 1), 0)
                mstore(add(buf_len, 33), 0)
                mstore8(add(buf_len, 1), 0xc0)
                buf_len := add(buf_len, 49)
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

            // ---- y ----
            buf_len := squeeze_to(buf_len, Y_MPTR)

            // ---- quotient limbs ----
            // Each uncompressed limb is calldatacopied directly to
            // QUOTIENT_LIMB_COMMS_MPTR_BASE; the Horner fold below reads
            // them back from memory. The compressed form is reconstructed
            // on the fly inside common_uncompressed_g1 for transcript
            // hashing only.
            let quotient_walk := QUOTIENT_LIMB_COMMS_MPTR_BASE
            for { let end := add(proof_cptr, {{ (num_quotients * 128)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_uncompressed_g1(buf_len, proof_cptr)
                calldatacopy(quotient_walk, proof_cptr, 0x80)
                quotient_walk := add(quotient_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x80)
            }

            // ---- x ----
            buf_len := squeeze_to(buf_len, X_MPTR)

            // ---- evaluations ----
            for { let end := add(proof_cptr, {{ (num_evals * 32)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                let eval_be := calldataload(proof_cptr)
                let eval_le := byte_reverse_32(eval_be)
                success := and(success, lt(eval_le, r))
                buf_len := common_word(buf_len, eval_be)
                proof_cptr := add(proof_cptr, 0x20)
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

            // ===============================================================
            // Fold the quotient commitment via Horner with x_n as scalar.
            // The decompressed quotient limbs live at
            // QUOTIENT_LIMB_COMMS_MPTR_BASE (4 words per limb); fold
            // from the last limb back to the first.
            // ===============================================================
            {
                let last_limb := add(QUOTIENT_LIMB_COMMS_MPTR_BASE, {{ (0x80 * (num_quotients - 1))|hex() }})
                mstore(0x100, mload(last_limb))
                mstore(0x120, mload(add(last_limb, 0x20)))
                mstore(0x140, mload(add(last_limb, 0x40)))
                mstore(0x160, mload(add(last_limb, 0x60)))

                // The native verifier folds the quotient limbs with the
                // *splitting factor* `x^(n-1)`, not `x^n` — see
                // `compute_linearization_commitment` in
                // midfall/proofs/src/plonk/linearization/verifier.rs.
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

                for {
                        let mptr := sub(last_limb, 0x80)
                        let mptr_end := sub(QUOTIENT_LIMB_COMMS_MPTR_BASE, 0x80)
                    }
                    lt(mptr_end, mptr)
                    {} {
                    success := ec_mul_acc(success, x_split)
                    mstore(0x180, mload(mptr))
                    mstore(0x1a0, mload(add(mptr, 0x20)))
                    mstore(0x1c0, mload(add(mptr, 0x40)))
                    mstore(0x1e0, mload(add(mptr, 0x60)))
                    success := ec_add_acc(success)
                    mptr := sub(mptr, 0x80)
                }
                // Scale Q_folded by (1 - x^n). This matches
                // `splitting_pow := F::ONE - *xn` in
                // `compute_linearization_commitment`. The full scalar
                // sequence over the limbs is then
                //   (1-x^n), (1-x^n)*x^(n-1), (1-x^n)*x^(2(n-1)), ...
                // i.e. (1-x^n) factored out across the Horner fold.
                {
                    let one_minus_x_n := addmod(1, sub(r, mload(X_N_MPTR)), r)
                    success := ec_mul_acc(success, one_minus_x_n)
                }
                {%- if simple_selector_cols.len() > 0 %}
                // Add Σ S_i_com * sel_acc_i (one MSM term per simple
                // selector). Mirrors the `Some(col_idx)` branch of
                // `compute_linearization_commitment`: each gate carrying
                // a simple selector contributes its (selector-substituted-
                // to-1) eval to `selector_acc[col]`, and the MSM picks
                // up `vk.fixed_commitments[col]` with that scalar.
                {%- for col in simple_selector_cols %}
                {
                    let sel_com := {{ (fixed_comm_mptr + col * 0x80)|hex() }}
                    mstore(0x180, mload(sel_com))
                    mstore(0x1a0, mload(add(sel_com, 0x20)))
                    mstore(0x1c0, mload(add(sel_com, 0x40)))
                    mstore(0x1e0, mload(add(sel_com, 0x60)))
                    success := ec_mul_tmp(success, mload({{ (0x5000 + loop.index0 * 0x20)|hex() }}))
                    success := ec_add_acc(success)
                }
                {%- endfor %}
                {%- endif %}
                mstore(QUOTIENT_MPTR,            mload(0x100))
                mstore(add(QUOTIENT_MPTR, 0x20), mload(0x120))
                mstore(add(QUOTIENT_MPTR, 0x40), mload(0x140))
                mstore(add(QUOTIENT_MPTR, 0x60), mload(0x160))
            }

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
                {%- endfor %}
            }

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
