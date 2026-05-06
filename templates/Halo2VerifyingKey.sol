// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

/// @title Halo2 BLS12-381 verifying-key payload.
/// @notice Contract whose deployed runtime is `INVALID || generated verifier-key payload`.
/// @dev Byte 0 is an unconditional INVALID opcode so direct calls cannot execute payload bytes as code. The linked verifier pins the full runtime by length/codehash and copies the payload starting at byte 1.
/// @dev The layout follows the verifier inputs derived from
/// `midfall/proofs/src/plonk/mod.rs::VerifyingKey` and the transcript
/// `vk.hash_into` behavior used by `midfall/proofs/src/plonk/verifier.rs`.
///
/// Layout (in 32-byte words, big-endian). The header slots are generated from
/// Rust's `VkHeaderLayout`; the byte offsets are absolute from the start of the
/// VK payload, not from byte 0 of the runtime. Runtime byte 0 is the INVALID
/// prefix; the verifier loads the payload via
/// `extcodecopy(vk, VK_MPTR, 0x01, vk_payload_len)` and then references each
/// slot by `VK_MPTR + i`.
///
///   word  0  : vk_digest                    (Fq, transcript_repr of the CS)
///   word  1  : num_instances
///   word  2  : k                            (log2 of the domain size)
///   word  3  : n_inv                        (1/n in Fr)
///   word  4  : omega                        (n-th primitive root of unity)
///   word  5  : omega_inv
///   word  6  : omega_inv_to_l               (omega_inv ^ |rotation_last|)
///   word  7  : has_accumulator              (0 or 1)
///   word  8  : acc_offset                   (instance index of the accumulator)
///   word  9  : num_acc_limbs
///   word 10  : num_acc_limb_bits
///   word 11..14 : G1_BASE                   (4 words, EIP-2537 padded)
///   word 15..22 : G2_BASE                   (8 words, EIP-2537 padded)
///   word 23..30 : NEG_S_G2_BASE             (8 words, EIP-2537 padded)
///   word 31..30 + Q_PAYLOAD      : quotient VM constants + packed bytecode
///   word 31 + Q_PAYLOAD ..       : fixed_comms (4 words each)
///   word 31 + Q_PAYLOAD + 4*N_FIXED ..
///                                : permutation_comms (4 words each)
///
/// Notes:
/// - `extcodehash` of this contract is pinned by the linked verifier via
///   `EXPECTED_VK_CODEHASH`, so any byte tweak is detected at deploy time.
/// - The quotient identity interpreter's static program is stored in this
///   pinned VK runtime. The verifier reads it from memory after `extcodecopy`,
///   avoiding verifier-side PUSH32/mstore immediates while keeping the program
///   covered by `EXPECTED_VK_CODEHASH`.
/// - The midnight-proofs migration bakes the per-lookup chunk counts, trashcan
///   structure, and `num_simple_selectors` into the generated verifier code.
contract Halo2VerifyingKey {
    /// @notice Deploy the verifying-key payload as this contract's runtime bytecode.
    /// @dev The constructor writes an INVALID byte followed by generated words into memory and returns that prefixed runtime.
    /// @dev The transient construction buffer starts at `0x80`, preserving Solidity's reserved memory words.
    constructor() {
        assembly {
            let runtime := {{ constructor_payload_mptr|hex() }}
            let payload := add(runtime, 0x01)
            mstore8(runtime, 0xfe)
            {%- for (name, chunk) in constants %}
            mstore(add(payload, {{ (32 * loop.index0)|hex_padded(4) }}), {{ chunk|hex_padded(64) }}) // {{ name }}
            {%- endfor %}
            {%- for (x_hi, x_lo, y_hi, y_lo) in fixed_comms %}
            {%- let offset = constants.len() %}
            mstore(add(payload, {{ (32 * (offset + 4 * loop.index0))|hex_padded(4) }}), {{ x_hi|hex_padded(64) }}) // fixed_comms[{{ loop.index0 }}].x_hi
            mstore(add(payload, {{ (32 * (offset + 4 * loop.index0 + 1))|hex_padded(4) }}), {{ x_lo|hex_padded(64) }}) // fixed_comms[{{ loop.index0 }}].x_lo
            mstore(add(payload, {{ (32 * (offset + 4 * loop.index0 + 2))|hex_padded(4) }}), {{ y_hi|hex_padded(64) }}) // fixed_comms[{{ loop.index0 }}].y_hi
            mstore(add(payload, {{ (32 * (offset + 4 * loop.index0 + 3))|hex_padded(4) }}), {{ y_lo|hex_padded(64) }}) // fixed_comms[{{ loop.index0 }}].y_lo
            {%- endfor %}
            {%- for (x_hi, x_lo, y_hi, y_lo) in permutation_comms %}
            {%- let offset = constants.len() + 4 * fixed_comms.len() %}
            mstore(add(payload, {{ (32 * (offset + 4 * loop.index0))|hex_padded(4) }}), {{ x_hi|hex_padded(64) }}) // permutation_comms[{{ loop.index0 }}].x_hi
            mstore(add(payload, {{ (32 * (offset + 4 * loop.index0 + 1))|hex_padded(4) }}), {{ x_lo|hex_padded(64) }}) // permutation_comms[{{ loop.index0 }}].x_lo
            mstore(add(payload, {{ (32 * (offset + 4 * loop.index0 + 2))|hex_padded(4) }}), {{ y_hi|hex_padded(64) }}) // permutation_comms[{{ loop.index0 }}].y_hi
            mstore(add(payload, {{ (32 * (offset + 4 * loop.index0 + 3))|hex_padded(4) }}), {{ y_lo|hex_padded(64) }}) // permutation_comms[{{ loop.index0 }}].y_lo
            {%- endfor %}

            return(runtime, {{ (1 + 32 * (constants.len() + 4 * fixed_comms.len() + 4 * permutation_comms.len()))|hex() }})
        }
    }
}
