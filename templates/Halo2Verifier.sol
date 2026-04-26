
pragma solidity ^0.8.0;

// Halo2 KZG verifier for the BLS12-381 curve, midnight-proofs flavour.
//
// Differences vs the original BN254 / halo2 v0.4 template:
//
//   * BLS12-381 base field Fp is 381 bits and does not fit in a uint256.
//     Each Fp coord is encoded EIP-2537 padded (16 zero bytes + 48 bytes).
//     A G1 point is 128 bytes (4 words); a G2 point is 256 bytes (8).
//   * Calldata carries G1 commitments in their 48-byte compressed form
//     (zcash convention: top 3 flag bits + 381-bit x). The verifier
//     decompresses to EIP-2537 padded form via modexp(x, (p+1)/4, p).
//   * Transcript is a streaming Keccak256 with domain separator
//     "Domain separator for transcript" + PREFIX_COMMON (0x01) before
//     each absorbed value + PREFIX_CHALLENGE (0x00) before each squeeze.
//     Squeeze is a two-fork: clone state || 0x00 then clone state ||
//     0x01, finalize each, concat to 64 bytes, reseed.
//   * Fq sampling: from_uniform_bytes(64) = a0 + a1 * 2^256 (mod r),
//     where a0 = LE int of bytes[0..32], a1 = LE int of bytes[32..64].
//   * Scalar inversion uses modexp(scalar, r-2, r).
//   * Precompiles:
//       0x05 modexp (used for G1 sqrt and Fr inversion)
//       0x0b BLS12_G1ADD
//       0x0c BLS12_G1MSM (single-pair mode)
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
    // BLS12-381 base-field arithmetic constants used by `decompress_g1`
    // and `scalar_inv`. p is 381 bits so it spans 48 BE bytes (top 16
    // bytes go in word 0, bottom 32 bytes go in word 1 — both stored
    // left-aligned so an mstore lands them at the right offset).
    // ----------------------------------------------------------------------
    uint256 internal constant BLS_P_TOP32        = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624;
    uint256 internal constant BLS_P_BOT16_LEFT   = 0x1eabfffeb153ffffb9feffffffffaaab00000000000000000000000000000000;
    uint256 internal constant BLS_SQRT_EXP_TOP32      = 0x0680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9cc34a83dac3d89;
    uint256 internal constant BLS_SQRT_EXP_BOT16_LEFT = 0x07aaffffac54ffffee7fbfffffffeaab00000000000000000000000000000000;

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
                r := or(shl(8,  and(x, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)),
                        shr(8,  and(x, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)))
                r := or(shl(16, and(r, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)),
                        shr(16, and(r, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)))
                r := or(shl(32, and(r, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)),
                        shr(32, and(r, 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)))
                r := or(shl(64, and(r, 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff)),
                        shr(64, and(r, 0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000)))
                r := or(shl(128, and(r, 0xffffffffffffffffffffffffffffffff)), shr(128, r))
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

            // Decompress a 48-byte compressed BLS12-381 G1 point (zcash
            // convention) into a 4-word EIP-2537 padded form at `dst`.
            // Returns updated success flag.
            //
            // Compressed encoding (48 bytes):
            //   byte 0 high 3 bits = (compression=1, infinity, sign)
            //   x = 381 bits big-endian, top 3 bits cleared
            //
            // Decompression:
            //   if infinity: dst <- (0,0,0,0)
            //   else:
            //     y_sq = x^3 + 4                  // potentially > p, ok
            //     y = y_sq^((p+1)/4) mod p         // modexp reduces y_sq
            //     if sign != lex(y): y = p - y
            //
            // Memory budget: scratch from 0x2200..0x2400 placed well
            // above the streaming transcript buffer. Staticcall outputs
            // are written back into the input region to save memory.
            // `src` is a CALLDATA pointer (`proof_cptr`) into the
            // 48-byte compressed G1 region; the function reads via
            // `calldataload` rather than `mload`.
            function decompress_g1(success, src, dst) -> ret {
                let head := calldataload(src)             // 32 bytes [0..32]
                let tail := calldataload(add(src, 0x20))  // 32 bytes [32..64], we use [32..48]
                let flag_byte := byte(0, head)
                let comp_flag := and(shr(7, flag_byte), 1)
                let inf_flag  := and(shr(6, flag_byte), 1)
                let sign_flag := and(shr(5, flag_byte), 1)
                ret := and(success, comp_flag)

                switch inf_flag
                case 1 {
                    mstore(dst,            0)
                    mstore(add(dst, 0x20), 0)
                    mstore(add(dst, 0x40), 0)
                    mstore(add(dst, 0x60), 0)
                }
                default {
                    // x_hi = top 16 bytes (with top 3 flag bits cleared).
                    let x_hi := shr(128, head)
                    x_hi := and(x_hi, 0x1fffffffffffffffffffffffffffffff)
                    let head_bot16 := and(head, 0xffffffffffffffffffffffffffffffff)
                    let tail_top16 := shr(128, tail)
                    let x_lo := or(shl(128, head_bot16), tail_top16)

                    // -------- modexp(x, 3, p) -> x^3 mod p --------
                    //
                    // Layout at p..p+0xe0:
                    //   p+0x00..0x20: B_size = 48
                    //   p+0x20..0x40: E_size = 1
                    //   p+0x40..0x60: M_size = 48
                    //   p+0x60..0x90: B = x (48 BE bytes; top 16 = x_hi, bot 32 = x_lo)
                    //   p+0x90..0x91: E = 0x03
                    //   p+0x91..0xc1: M = p (48 BE bytes; top 32 = BLS_P_TOP32, bot 16 = BLS_P_BOT16_LEFT)
                    let p := 0x2200
                    mstore(p,            0x30)
                    mstore(add(p, 0x20), 0x01)
                    mstore(add(p, 0x40), 0x30)
                    // B = x as 48 BE bytes:
                    mstore(add(p, 0x60), shl(128, x_hi))   // bytes 0..16 = x_hi
                    mstore(add(p, 0x70), x_lo)             // bytes 16..48 = x_lo
                    // E = 0x03 (one byte).
                    mstore8(add(p, 0x90), 0x03)
                    // M = p (48 BE bytes).
                    mstore(add(p, 0x91), BLS_P_TOP32)
                    mstore(add(p, 0xb1), BLS_P_BOT16_LEFT)
                    // Total input: 0x60 + 0x30 + 0x01 + 0x30 = 0xc1
                    if iszero(staticcall(gas(), 0x05, p, 0xc1, add(p, 0xd0), 0x30)) { revert(0, 0) }

                    // Read x^3 (48 bytes) back as (xc_top32, xc_bot16_left).
                    let xc_top32 := mload(add(p, 0xd0))
                    let xc_bot16_left := mload(add(p, 0xf0))

                    // y_sq = x^3 + 4. Add to bottom 16 bytes (left-aligned).
                    let xc_bot16_int := shr(128, xc_bot16_left)
                    let y_sq_bot_int := add(xc_bot16_int, 4)
                    let y_sq_top32 := xc_top32
                    // Propagate carry if y_sq_bot_int overflowed 128 bits.
                    if iszero(lt(y_sq_bot_int, 0x100000000000000000000000000000000)) {
                        y_sq_bot_int := sub(y_sq_bot_int, 0x100000000000000000000000000000000)
                        y_sq_top32 := add(y_sq_top32, 1)
                    }
                    let y_sq_bot_left := shl(128, y_sq_bot_int)

                    // -------- modexp(y_sq, (p+1)/4, p) -> y --------
                    //
                    // Layout at q..q+0x101:
                    //   q+0x00..0x20: B_size = 48
                    //   q+0x20..0x40: E_size = 48
                    //   q+0x40..0x60: M_size = 48
                    //   q+0x60..0x90: B = y_sq
                    //   q+0x90..0xc0: E = (p+1)/4
                    //   q+0xc0..0xf0: M = p
                    let q := 0x2300
                    mstore(q,            0x30)
                    mstore(add(q, 0x20), 0x30)
                    mstore(add(q, 0x40), 0x30)
                    mstore(add(q, 0x60), y_sq_top32)
                    mstore(add(q, 0x80), y_sq_bot_left)
                    mstore(add(q, 0x90), BLS_SQRT_EXP_TOP32)
                    mstore(add(q, 0xb0), BLS_SQRT_EXP_BOT16_LEFT)
                    mstore(add(q, 0xc0), BLS_P_TOP32)
                    mstore(add(q, 0xe0), BLS_P_BOT16_LEFT)
                    if iszero(staticcall(gas(), 0x05, q, 0xf0, add(q, 0x100), 0x30)) { revert(0, 0) }
                    let y_top32 := mload(add(q, 0x100))
                    let y_bot16_left := mload(add(q, 0x120))

                    // ---- Determine sign by comparing y vs p - y ----
                    // p - y: subtract y from p (381-bit subtraction). y < p so
                    // this never underflows.
                    let y_top_int  := y_top32
                    let y_bot_int  := shr(128, y_bot16_left)
                    let p_top_int  := BLS_P_TOP32
                    let p_bot_int  := shr(128, BLS_P_BOT16_LEFT)

                    // Compute (p_lo, p_hi) - (y_lo, y_hi) where the value is
                    //   hi * 2^256 + lo
                    // and the "halves" carry the BE byte split:
                    //   y_hi_int (32 bytes int)  + (y_bot_int << 128) is the
                    // total 384-bit y. Same for p.
                    // For the comparison we want py = p - y; sign = (y > py).

                    // 384-bit subtraction. Encode as (hi, mid, lo) bytes via:
                    //   p_total = (p_top_int << 128) | p_bot_int   // doesn't fit in 256
                    // Easier: do direct 16-byte limb sub.
                    //   Limb0 = bytes [0..16]   = byte 0..16 (BE)  = top 128 bits
                    //   Limb1 = bytes [16..32]
                    //   Limb2 = bytes [32..48]
                    let p_l0 := shr(128, p_top_int)
                    let p_l1 := and(p_top_int, 0xffffffffffffffffffffffffffffffff)
                    let p_l2 := p_bot_int
                    let y_l0 := shr(128, y_top_int)
                    let y_l1 := and(y_top_int, 0xffffffffffffffffffffffffffffffff)
                    let y_l2 := y_bot_int

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

                    let need_negate := xor(lex_y_larger, sign_flag)
                    if need_negate {
                        y_top_int := or(shl(128, py_l0), py_l1)
                        y_bot_int := py_l2
                    }
                    let y_bot_left := shl(128, y_bot_int)

                    // Encode (x, y) in EIP-2537 padded form at `dst`.
                    // x_hi word: 16 zero + x_hi (already in lower 128 bits) = x_hi
                    // x_lo word: x_lo (already 32 bytes)
                    mstore(dst,            x_hi)
                    mstore(add(dst, 0x20), x_lo)
                    // y_hi word: 16 zero + y_top16. y_top_int = y_top32 BE; the
                    // top 16 bytes of y are in the high half of y_top_int, but
                    // we want them in the low half of the y_hi word (with 16
                    // zero pad above). So y_hi_word = shr(128, y_top_int).
                    mstore(add(dst, 0x40), shr(128, y_top_int))
                    // y_lo word: bottom 32 bytes of y = (y_top_int low 16 bytes) || y_bot16
                    let y_top_bot16 := and(y_top_int, 0xffffffffffffffffffffffffffffffff)
                    mstore(add(dst, 0x60), or(shl(128, y_top_bot16), shr(128, y_bot_left)))
                }
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

            // Append PREFIX_COMMON || compressed_g1[0..48]. The 48-byte
            // compressed encoding is read directly from calldata at cptr.
            function common_compressed_g1(buf_len, cptr) -> ret {
                mstore8(buf_len, 0x01)
                let head := calldataload(cptr)
                let tail := calldataload(add(cptr, 0x20))
                // Place 48 bytes starting at buf_len+1.
                mstore(add(buf_len, 1), head)
                // The next mstore overlaps; we write only top 16 bytes of tail
                // by aligning at offset +1+32 = +33 with the upper 16 bytes
                // of `tail` (which are exactly the 16 bytes we want).
                // mstore writes 32 bytes; we'll then overwrite bytes 49..81
                // with the next absorb, but that's fine since the call site
                // only relies on bytes 0..49.
                mstore(add(buf_len, 33), tail)
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
                mstore(0x00, value)
                log1(0x00, 0x20, id)
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
            for { let end := add(proof_cptr, {{ (phase.num_advices * 48)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_compressed_g1(buf_len, proof_cptr)
                success := decompress_g1(success, proof_cptr, advice_walk)
                advice_walk := add(advice_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x30)
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
            for { let end := add(proof_cptr, {{ (num_lookups * 48)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_compressed_g1(buf_len, proof_cptr)
                success := decompress_g1(success, proof_cptr, lookup_m_walk)
                lookup_m_walk := add(lookup_m_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x30)
            }
            {%- endif %}

            // ---- beta, gamma ----
            buf_len := squeeze_to(buf_len, BETA_MPTR)
            buf_len := squeeze_to(buf_len, GAMMA_MPTR)

            {%- if num_permutation_zs != 0 %}
            // ---- permutation Z products ----
            let perm_z_walk := PERM_Z_COMMS_MPTR_BASE
            for { let end := add(proof_cptr, {{ (num_permutation_zs * 48)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_compressed_g1(buf_len, proof_cptr)
                success := decompress_g1(success, proof_cptr, perm_z_walk)
                perm_z_walk := add(perm_z_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x30)
            }
            {%- endif %}

            {%- if lookup_h_plus_acc != 0 %}
            // ---- lookup helpers + accumulators (per-lookup) ----
            let lookup_helper_walk := LOOKUP_HELPER_COMMS_MPTR_BASE
            let lookup_z_walk := LOOKUP_Z_COMMS_MPTR_BASE
            {%- for chunks in lookup_chunks %}
            // lookup {{ loop.index0 }}: {{ chunks }} helper(s) + 1 acc
            for { let end := add(proof_cptr, {{ (chunks * 48)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_compressed_g1(buf_len, proof_cptr)
                success := decompress_g1(success, proof_cptr, lookup_helper_walk)
                lookup_helper_walk := add(lookup_helper_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x30)
            }
            buf_len := common_compressed_g1(buf_len, proof_cptr)
            success := decompress_g1(success, proof_cptr, lookup_z_walk)
            lookup_z_walk := add(lookup_z_walk, 0x80)
            proof_cptr := add(proof_cptr, 0x30)
            {%- endfor %}
            {%- endif %}

            {%- if num_trashcans != 0 %}
            // ---- trash_challenge ----
            buf_len := squeeze_to(buf_len, TRASH_CHALLENGE_MPTR)
            // ---- trashcans ----
            let trashcan_walk := TRASHCAN_COMMS_MPTR_BASE
            for { let end := add(proof_cptr, {{ (num_trashcans * 48)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_compressed_g1(buf_len, proof_cptr)
                success := decompress_g1(success, proof_cptr, trashcan_walk)
                trashcan_walk := add(trashcan_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x30)
            }
            {%- endif %}

            // ---- y ----
            buf_len := squeeze_to(buf_len, Y_MPTR)

            // ---- quotient limbs ----
            // Each compressed limb is decompressed inline and stored at
            // QUOTIENT_LIMB_COMMS_MPTR_BASE; the Horner fold below reads
            // them back from memory.
            let quotient_walk := QUOTIENT_LIMB_COMMS_MPTR_BASE
            for { let end := add(proof_cptr, {{ (num_quotients * 48)|hex() }}) }
                lt(proof_cptr, end)
                {} {
                buf_len := common_compressed_g1(buf_len, proof_cptr)
                success := decompress_g1(success, proof_cptr, quotient_walk)
                quotient_walk := add(quotient_walk, 0x80)
                proof_cptr := add(proof_cptr, 0x30)
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

            // ---- f_com (1 compressed G1) ----
            buf_len := common_compressed_g1(buf_len, proof_cptr)
            success := decompress_g1(success, proof_cptr, F_COM_MPTR)
            proof_cptr := add(proof_cptr, 0x30)

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

            // ---- pi (1 compressed G1) ----
            buf_len := common_compressed_g1(buf_len, proof_cptr)
            success := decompress_g1(success, proof_cptr, PI_MPTR)
            proof_cptr := add(proof_cptr, 0x30)

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
                let quotient_eval_numer
                let delta := 3793952369011177517951424454785176000433849974408744014172535497121832470999 // BLS12-381 Fr::DELTA
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

            success := ec_pairing(success, PAIRING_LHS_MPTR, PAIRING_RHS_MPTR)

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
