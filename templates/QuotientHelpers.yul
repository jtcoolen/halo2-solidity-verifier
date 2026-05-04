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
                let q_r := FR_MODULUS
                let x2 := mulmod(x, x, q_r)
                z := mulmod(x, mulmod(x2, x2, q_r), q_r)
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
                let q_r := FR_MODULUS
                {%- for coeff in limb7_yul_coeffs %}
                {%- if loop.first %}
                z := addmod(x0, mulmod({{ coeff }}, x{{ loop.index }}, q_r), q_r)
                {%- else %}
                z := addmod(z, mulmod({{ coeff }}, x{{ loop.index }}, q_r), q_r)
                {%- endif %}
                {%- endfor %}
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
                let q_r := FR_MODULUS
                {%- for coeff in wide_limb7_yul_coeffs %}
                {%- if loop.first %}
                z := addmod(x0, mulmod({{ coeff }}, x{{ loop.index }}, q_r), q_r)
                {%- else %}
                z := addmod(z, mulmod({{ coeff }}, x{{ loop.index }}, q_r), q_r)
                {%- endif %}
                {%- endfor %}
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
