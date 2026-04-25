// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

// BLS12-381 verifying key contract.
// Layout (in 32-byte words, big-endian):
//   constants[0..N_CONSTS]  : scalar-field words (vk_digest, num_instances, k, n_inv,
//                             omega, omega_inv, omega_inv_to_l, has_accumulator,
//                             acc_offset, num_acc_limbs, num_acc_limb_bits) and
//                             G1/G2 powers-of-tau in EIP-2537 padded form.
//   constants[N_CONSTS..]   : G1 commitments (fixed + permutation), each
//                             encoded as 4 words = (x_hi, x_lo, y_hi, y_lo)
//                             with 16 leading zero bytes per coordinate.
contract Halo2VerifyingKey {
    constructor() {
        assembly {
            {%- for (name, chunk) in constants %}
            mstore({{ (32 * loop.index0)|hex_padded(4) }}, {{ chunk|hex_padded(64) }}) // {{ name }}
            {%- endfor %}
            {%- for (x_hi, x_lo, y_hi, y_lo) in fixed_comms %}
            {%- let offset = constants.len() %}
            mstore({{ (32 * (offset + 4 * loop.index0))|hex_padded(4) }}, {{ x_hi|hex_padded(64) }}) // fixed_comms[{{ loop.index0 }}].x_hi
            mstore({{ (32 * (offset + 4 * loop.index0 + 1))|hex_padded(4) }}, {{ x_lo|hex_padded(64) }}) // fixed_comms[{{ loop.index0 }}].x_lo
            mstore({{ (32 * (offset + 4 * loop.index0 + 2))|hex_padded(4) }}, {{ y_hi|hex_padded(64) }}) // fixed_comms[{{ loop.index0 }}].y_hi
            mstore({{ (32 * (offset + 4 * loop.index0 + 3))|hex_padded(4) }}, {{ y_lo|hex_padded(64) }}) // fixed_comms[{{ loop.index0 }}].y_lo
            {%- endfor %}
            {%- for (x_hi, x_lo, y_hi, y_lo) in permutation_comms %}
            {%- let offset = constants.len() + 4 * fixed_comms.len() %}
            mstore({{ (32 * (offset + 4 * loop.index0))|hex_padded(4) }}, {{ x_hi|hex_padded(64) }}) // permutation_comms[{{ loop.index0 }}].x_hi
            mstore({{ (32 * (offset + 4 * loop.index0 + 1))|hex_padded(4) }}, {{ x_lo|hex_padded(64) }}) // permutation_comms[{{ loop.index0 }}].x_lo
            mstore({{ (32 * (offset + 4 * loop.index0 + 2))|hex_padded(4) }}, {{ y_hi|hex_padded(64) }}) // permutation_comms[{{ loop.index0 }}].y_hi
            mstore({{ (32 * (offset + 4 * loop.index0 + 3))|hex_padded(4) }}, {{ y_lo|hex_padded(64) }}) // permutation_comms[{{ loop.index0 }}].y_lo
            {%- endfor %}

            return(0, {{ (32 * (constants.len() + 4 * fixed_comms.len() + 4 * permutation_comms.len()))|hex() }})
        }
    }
}
