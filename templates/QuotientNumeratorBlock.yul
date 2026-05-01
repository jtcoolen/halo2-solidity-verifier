            // ===============================================================
            // Batched identity numerator / linearization target.
            //
            // This block does not evaluate the quotient polynomial h(x), and
            // the proof does not provide an h(x) scalar to trust. Instead it:
            //
            //   1. Reconstructs the y-batched constraint numerator nu_y(x)
            //      from the alleged polynomial evaluations read after the
            //      transcript sampled x.
            //   2. Stores -nu_y(x) as the expected opening scalar for the
            //      linearized commitment.
            //
            // The commitment side is built in the next block from the quotient
            // limb commitments as (1 - x^n) * Σ_i x_split^i * Q_i, plus any
            // simple-selector commitments. The PCS check later binds that
            // linearized commitment to this expected scalar at x.
            // ===============================================================
            {
                {%- match quotient_program %}
                {%- when Some with (program) %}
                let y := mload(Y_MPTR)
                let q_const_mptr := {{ program.const_mptr|hex() }}
                let q_program_mptr := {{ program.program_mptr|hex() }}
                {%- if program.cse_temps > 0 %}
                let q_tmp_mptr := {{ program.tmp_mptr|hex() }}
                {%- endif %}

                let quotient_eval_numer := 0
                {%- if simple_selector_cols.len() > 0 %}
                for { let q_sel_zero_off := 0 } lt(q_sel_zero_off, {{ (simple_selector_cols.len() * 0x20)|hex() }}) { q_sel_zero_off := add(q_sel_zero_off, 0x20) } {
                    mstore(add(SELECTOR_ACC_MPTR, q_sel_zero_off), 0)
                }
                let q_sel_scale := 1
                let q_sel_inv_scale := 1
                let q_y_inv := 0
                {
                    // Keep this inversion away from scalar_inv's fixed 0x6000
                    // scratch: large separated VKs occupy that range.
                    let q_inv_scratch := {{ program.stack_mptr|hex() }}
                    if iszero(y) { revert(0, 0) }
                    mstore(q_inv_scratch,            0x20)
                    mstore(add(q_inv_scratch, 0x20), 0x20)
                    mstore(add(q_inv_scratch, 0x40), 0x20)
                    mstore(add(q_inv_scratch, 0x60), y)
                    mstore(add(q_inv_scratch, 0x80), sub(FR_MODULUS, 2))
                    mstore(add(q_inv_scratch, 0xa0), FR_MODULUS)
                    if iszero(staticcall(gas(), 0x05, q_inv_scratch, 0xc0, q_inv_scratch, 0x20)) { revert(0, 0) }
                    if iszero(eq(returndatasize(), 0x20)) { revert(0, 0) }
                    q_y_inv := mload(q_inv_scratch)
                }
                {%- endif %}

                {%- for code_block in quotient_inline_computations %}
                {%- for line in code_block %}
                {{ line }}
                {%- endfor %}
                {%- endfor %}

                let q_pc := q_program_mptr
                let q_end := add(q_program_mptr, {{ program.len|hex() }})
                let q_sp := {{ program.stack_mptr|hex() }}
                let q_top := 0
                let q_has_top := 0

                {%- if program.packed32 %}
                for { } lt(q_pc, q_end) { } {
                    let q_inst := shr(224, mload(q_pc))
                    q_pc := add(q_pc, 4)
                    let q_op := shr(24, q_inst)
                    let q_arg := and(q_inst, 0xffffff)

                    switch q_op
                    case 0x01 {
                        let qconst := q_arg
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_const_mptr, shl(5, qconst)))
                        q_has_top := 1
                    }
                    case 0x02 {
                        let q_ptr := q_arg
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    case 0x03 {
                        let q_token := q_arg
                        let q_ptr := 0
                        switch q_token
                        case 0x01 { q_ptr := L_0_MPTR }
                        case 0x02 { q_ptr := L_LAST_MPTR }
                        case 0x03 { q_ptr := L_BLIND_MPTR }
                        case 0x04 { q_ptr := BETA_MPTR }
                        case 0x05 { q_ptr := GAMMA_MPTR }
                        case 0x06 { q_ptr := X_MPTR }
                        case 0x07 { q_ptr := THETA_MPTR }
                        case 0x08 { q_ptr := TRASH_CHALLENGE_MPTR }
                        case 0x09 { q_ptr := INSTANCE_EVAL_MPTR }
                        default { revert(0, 0) }
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    case 0x04 {
                        let q_token := shr(16, q_arg)
                        let q_off := and(q_arg, 0xffff)
                        let q_ptr := 0
                        switch q_token
                        case 0x01 { q_ptr := add(L_0_MPTR, q_off) }
                        case 0x02 { q_ptr := add(L_LAST_MPTR, q_off) }
                        case 0x03 { q_ptr := add(L_BLIND_MPTR, q_off) }
                        case 0x04 { q_ptr := add(BETA_MPTR, q_off) }
                        case 0x05 { q_ptr := add(GAMMA_MPTR, q_off) }
                        case 0x06 { q_ptr := add(X_MPTR, q_off) }
                        case 0x07 { q_ptr := add(THETA_MPTR, q_off) }
                        case 0x08 { q_ptr := add(TRASH_CHALLENGE_MPTR, q_off) }
                        case 0x09 { q_ptr := add(INSTANCE_EVAL_MPTR, q_off) }
                        default { revert(0, 0) }
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    case 0x05 {
                        let q_ptr := q_arg
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    case 0x06 {
                        q_sp := sub(q_sp, 0x20)
                        q_top := addmod(mload(q_sp), q_top, r)
                    }
                    case 0x07 {
                        q_sp := sub(q_sp, 0x20)
                        q_top := mulmod(mload(q_sp), q_top, r)
                    }
                    case 0x08 {
                        q_top := sub(r, q_top)
                    }
                    case 0x09 {
                        let qconst := q_arg
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_const_mptr, shl(5, qconst)))
                        q_has_top := 1
                    }
                    case 0x0c {
                        q_top := addmod(q_top, mload(add(q_const_mptr, shl(5, q_arg))), r)
                    }
                    case 0x0d {
                        q_top := mulmod(q_top, mload(add(q_const_mptr, shl(5, q_arg))), r)
                    }
                    case 0x0e {
                        q_top := addmod(q_top, mload(add(q_const_mptr, shl(5, q_arg))), r)
                    }
                    case 0x0f {
                        q_top := mulmod(q_top, mload(add(q_const_mptr, shl(5, q_arg))), r)
                    }
                    case 0x10 {
                        q_top := addmod(q_top, mload(q_arg), r)
                    }
                    case 0x11 {
                        q_top := mulmod(q_top, mload(q_arg), r)
                    }
                    case 0x12 {
                        let q_pair := shr(224, mload(q_pc))
                        q_pc := add(q_pc, 4)
                        let q_lhs := shr(16, q_pair)
                        let q_rhs := and(q_pair, 0xffff)
                        q_top := addmod(
                            q_top,
                            mulmod(
                                mulmod(mload(q_lhs), mload(q_rhs), r),
                                mload(add(q_const_mptr, shl(5, q_arg))),
                                r
                            ),
                            r
                        )
                    }
                    case 0x13 {
                        let qconst := shr(16, q_arg)
                        let q_ptr := and(q_arg, 0xffff)
                        q_top := addmod(
                            q_top,
                            mulmod(mload(q_ptr), mload(add(q_const_mptr, shl(5, qconst))), r),
                            r
                        )
                    }
                    case 0x14 {
                        let q_pair := shr(224, mload(q_pc))
                        q_pc := add(q_pc, 4)
                        let q_lhs := shr(16, q_pair)
                        let q_rhs := and(q_pair, 0xffff)
                        q_top := addmod(q_top, mulmod(mload(q_lhs), mload(q_rhs), r), r)
                    }
                    {%- if program.cse_temps > 0 %}
                    case 0x17 {
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_tmp_mptr, shl(5, q_arg)))
                        q_has_top := 1
                    }
                    case 0x18 {
                        mstore(add(q_tmp_mptr, shl(5, q_arg)), q_top)
                    }
                    {%- endif %}
                    {%- if quotient_native_permutation_computation.len() > 0 %}
                    case 0x19 {
                        q_top := 0
                        q_has_top := 0
                        q_sp := {{ program.stack_mptr|hex() }}
                        {%- for line in quotient_native_permutation_computation %}
                        {{ line }}
                        {%- endfor %}
                    }
                    {%- endif %}
                    {%- if quotient_native_trash_computation.len() > 0 %}
                    case 0x1a {
                        q_top := 0
                        q_has_top := 0
                        q_sp := {{ program.stack_mptr|hex() }}
                        {%- for line in quotient_native_trash_computation %}
                        {{ line }}
                        {%- endfor %}
                    }
                    {%- endif %}
                    {%- if quotient_native_identity_computations.len() > 0 %}
                    case 0x1b {
                        let q_native_idx := q_arg
                        q_top := 0
                        q_has_top := 0
                        q_sp := {{ program.stack_mptr|hex() }}
                        switch q_native_idx
                        {%- for code_block in quotient_native_identity_computations %}
                        case {{ loop.index0 }} {
                            {%- for line in code_block %}
                            {{ line }}
                            {%- endfor %}
                        }
                        {%- endfor %}
                        default { revert(0, 0) }
                    }
                    {%- endif %}
                    case 0x0a {
                        let q_eval := q_top
                        q_has_top := 0
                        quotient_eval_numer := mulmod(quotient_eval_numer, y, r)
                        {%- if simple_selector_cols.len() > 0 %}
                        q_sel_scale := mulmod(q_sel_scale, y, r)
                        q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)
                        {%- endif %}
                        quotient_eval_numer := addmod(quotient_eval_numer, q_eval, r)
                    }
                    case 0x0b {
                        let q_sel_idx := q_arg
                        let q_eval := q_top
                        q_has_top := 0
                        quotient_eval_numer := mulmod(quotient_eval_numer, y, r)
                        {%- if simple_selector_cols.len() > 0 %}
                        q_sel_scale := mulmod(q_sel_scale, y, r)
                        q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)
                        {%- endif %}
                        let q_target_ptr := add(SELECTOR_ACC_MPTR, shl(5, q_sel_idx))
                        mstore(q_target_ptr, addmod(mload(q_target_ptr), mulmod(q_eval, q_sel_inv_scale, r), r))
                    }
                    default {
                        revert(0, 0)
                    }
                }
                {%- else %}
                for { } lt(q_pc, q_end) { } {
                    let q_op := byte(0, mload(q_pc))
                    q_pc := add(q_pc, 1)

                    switch q_op
                    case 0x01 {
                        let qconst := shr(240, mload(q_pc))
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_const_mptr, shl(5, qconst)))
                        q_has_top := 1
                        q_pc := add(q_pc, 2)
                    }
                    case 0x02 {
                        let q_ptr := shr(224, mload(q_pc))
                        q_pc := add(q_pc, 4)
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    case 0x03 {
                        let q_token := byte(0, mload(q_pc))
                        q_pc := add(q_pc, 1)
                        let q_ptr := 0
                        switch q_token
                        case 0x01 { q_ptr := L_0_MPTR }
                        case 0x02 { q_ptr := L_LAST_MPTR }
                        case 0x03 { q_ptr := L_BLIND_MPTR }
                        case 0x04 { q_ptr := BETA_MPTR }
                        case 0x05 { q_ptr := GAMMA_MPTR }
                        case 0x06 { q_ptr := X_MPTR }
                        case 0x07 { q_ptr := THETA_MPTR }
                        case 0x08 { q_ptr := TRASH_CHALLENGE_MPTR }
                        case 0x09 { q_ptr := INSTANCE_EVAL_MPTR }
                        default { revert(0, 0) }
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    case 0x04 {
                        let q_token := byte(0, mload(q_pc))
                        let q_off := shr(224, mload(add(q_pc, 1)))
                        q_pc := add(q_pc, 5)
                        let q_ptr := 0
                        switch q_token
                        case 0x01 { q_ptr := add(L_0_MPTR, q_off) }
                        case 0x02 { q_ptr := add(L_LAST_MPTR, q_off) }
                        case 0x03 { q_ptr := add(L_BLIND_MPTR, q_off) }
                        case 0x04 { q_ptr := add(BETA_MPTR, q_off) }
                        case 0x05 { q_ptr := add(GAMMA_MPTR, q_off) }
                        case 0x06 { q_ptr := add(X_MPTR, q_off) }
                        case 0x07 { q_ptr := add(THETA_MPTR, q_off) }
                        case 0x08 { q_ptr := add(TRASH_CHALLENGE_MPTR, q_off) }
                        case 0x09 { q_ptr := add(INSTANCE_EVAL_MPTR, q_off) }
                        default { revert(0, 0) }
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    case 0x05 {
                        let q_ptr := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    case 0x06 {
                        q_sp := sub(q_sp, 0x20)
                        q_top := addmod(mload(q_sp), q_top, r)
                    }
                    case 0x07 {
                        q_sp := sub(q_sp, 0x20)
                        q_top := mulmod(mload(q_sp), q_top, r)
                    }
                    case 0x08 {
                        q_top := sub(r, q_top)
                    }
                    case 0x09 {
                        let qconst := byte(0, mload(q_pc))
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_const_mptr, shl(5, qconst)))
                        q_has_top := 1
                        q_pc := add(q_pc, 1)
                    }
                    case 0x0c {
                        let qconst := byte(0, mload(q_pc))
                        q_pc := add(q_pc, 1)
                        q_top := addmod(q_top, mload(add(q_const_mptr, shl(5, qconst))), r)
                    }
                    case 0x0d {
                        let qconst := byte(0, mload(q_pc))
                        q_pc := add(q_pc, 1)
                        q_top := mulmod(q_top, mload(add(q_const_mptr, shl(5, qconst))), r)
                    }
                    case 0x0e {
                        let qconst := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        q_top := addmod(q_top, mload(add(q_const_mptr, shl(5, qconst))), r)
                    }
                    case 0x0f {
                        let qconst := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        q_top := mulmod(q_top, mload(add(q_const_mptr, shl(5, qconst))), r)
                    }
                    case 0x10 {
                        let q_ptr := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        q_top := addmod(q_top, mload(q_ptr), r)
                    }
                    case 0x11 {
                        let q_ptr := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        q_top := mulmod(q_top, mload(q_ptr), r)
                    }
                    case 0x12 {
                        let q_lhs := shr(240, mload(q_pc))
                        let q_rhs := shr(240, mload(add(q_pc, 2)))
                        let qconst := byte(0, mload(add(q_pc, 4)))
                        q_pc := add(q_pc, 5)
                        q_top := addmod(
                            q_top,
                            mulmod(
                                mulmod(mload(q_lhs), mload(q_rhs), r),
                                mload(add(q_const_mptr, shl(5, qconst))),
                                r
                            ),
                            r
                        )
                    }
                    case 0x13 {
                        let q_ptr := shr(240, mload(q_pc))
                        let qconst := byte(0, mload(add(q_pc, 2)))
                        q_pc := add(q_pc, 3)
                        q_top := addmod(
                            q_top,
                            mulmod(mload(q_ptr), mload(add(q_const_mptr, shl(5, qconst))), r),
                            r
                        )
                    }
                    case 0x14 {
                        let q_lhs := shr(240, mload(q_pc))
                        let q_rhs := shr(240, mload(add(q_pc, 2)))
                        q_pc := add(q_pc, 4)
                        q_top := addmod(q_top, mulmod(mload(q_lhs), mload(q_rhs), r), r)
                    }
                    {%- if program.cse_temps > 0 %}
                    case 0x17 {
                        let q_tmp_idx := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_tmp_mptr, shl(5, q_tmp_idx)))
                        q_has_top := 1
                    }
                    case 0x18 {
                        let q_tmp_idx := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        mstore(add(q_tmp_mptr, shl(5, q_tmp_idx)), q_top)
                    }
                    {%- endif %}
                    case 0x15 {
                        let q_count := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        let q_run_end := add(q_pc, mul(q_count, 5))
                        for { } lt(q_pc, q_run_end) { } {
                            let q_lhs := shr(240, mload(q_pc))
                            let q_rhs := shr(240, mload(add(q_pc, 2)))
                            let qconst := byte(0, mload(add(q_pc, 4)))
                            q_pc := add(q_pc, 5)
                            q_top := addmod(
                                q_top,
                                mulmod(
                                    mulmod(mload(q_lhs), mload(q_rhs), r),
                                    mload(add(q_const_mptr, shl(5, qconst))),
                                    r
                                ),
                                r
                            )
                        }
                    }
                    case 0x16 {
                        let q_count := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        let q_run_end := add(q_pc, mul(q_count, 3))
                        for { } lt(q_pc, q_run_end) { } {
                            let q_ptr := shr(240, mload(q_pc))
                            let qconst := byte(0, mload(add(q_pc, 2)))
                            q_pc := add(q_pc, 3)
                            q_top := addmod(
                                q_top,
                                mulmod(mload(q_ptr), mload(add(q_const_mptr, shl(5, qconst))), r),
                                r
                            )
                        }
                    }
                    {%- if quotient_native_permutation_computation.len() > 0 %}
                    case 0x19 {
                        q_top := 0
                        q_has_top := 0
                        q_sp := {{ program.stack_mptr|hex() }}
                        {%- for line in quotient_native_permutation_computation %}
                        {{ line }}
                        {%- endfor %}
                    }
                    {%- endif %}
                    {%- if quotient_native_trash_computation.len() > 0 %}
                    case 0x1a {
                        q_top := 0
                        q_has_top := 0
                        q_sp := {{ program.stack_mptr|hex() }}
                        {%- for line in quotient_native_trash_computation %}
                        {{ line }}
                        {%- endfor %}
                    }
                    {%- endif %}
                    {%- if quotient_native_identity_computations.len() > 0 %}
                    case 0x1b {
                        let q_native_idx := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        q_top := 0
                        q_has_top := 0
                        q_sp := {{ program.stack_mptr|hex() }}
                        switch q_native_idx
                        {%- for code_block in quotient_native_identity_computations %}
                        case {{ loop.index0 }} {
                            {%- for line in code_block %}
                            {{ line }}
                            {%- endfor %}
                        }
                        {%- endfor %}
                        default { revert(0, 0) }
                    }
                    {%- endif %}
                    case 0x0a {
                        let q_eval := q_top
                        q_has_top := 0
                        quotient_eval_numer := mulmod(quotient_eval_numer, y, r)
                        {%- if simple_selector_cols.len() > 0 %}
                        q_sel_scale := mulmod(q_sel_scale, y, r)
                        q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)
                        {%- endif %}
                        quotient_eval_numer := addmod(quotient_eval_numer, q_eval, r)
                    }
                    case 0x0b {
                        let q_sel_idx := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        let q_eval := q_top
                        q_has_top := 0
                        quotient_eval_numer := mulmod(quotient_eval_numer, y, r)
                        {%- if simple_selector_cols.len() > 0 %}
                        q_sel_scale := mulmod(q_sel_scale, y, r)
                        q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)
                        {%- endif %}
                        let q_target_ptr := add(SELECTOR_ACC_MPTR, shl(5, q_sel_idx))
                        mstore(q_target_ptr, addmod(mload(q_target_ptr), mulmod(q_eval, q_sel_inv_scale, r), r))
                    }
                    default {
                        revert(0, 0)
                    }
                }
                {%- endif %}

                {%- for code_block in quotient_post_vm_computations %}
                {%- for line in code_block %}
                {{ line }}
                {%- endfor %}
                {%- endfor %}

                {%- if simple_selector_cols.len() > 0 %}
                for { let q_i := 0 } lt(q_i, {{ simple_selector_cols.len() }}) { q_i := add(q_i, 1) } {
                    let q_sel_ptr := add(SELECTOR_ACC_MPTR, shl(5, q_i))
                    mstore(q_sel_ptr, mulmod(mload(q_sel_ptr), q_sel_scale, r))
                }
                {%- endif %}

                let linearization_expected_eval := sub(r, quotient_eval_numer)
                mstore(QUOTIENT_EVAL_MPTR, linearization_expected_eval)
                pop(y)
                {%- when None %}
                let delta := 3793952369011177517951424454785176000433849974408744014172535497121832470999 // BLS12-381 Fr::DELTA
                let y := mload(Y_MPTR)

                {%- for code_block in quotient_eval_numer_computations %}
                {%- for line in code_block %}
                {{ line }}
                {%- endfor %}
                {%- endfor %}


                pop(y)
                pop(delta)

                // Store the expected opening scalar for the linearized
                // commitment at x: the negated sum of fully-evaluated
                // identities. See
                // `compute_linearization_commitment` in
                // midfall/proofs/src/plonk/linearization/verifier.rs:
                //
                //   expected_eval -= eval     (for col_idx == None)
                //
                // The commitment side already includes the quotient-limb
                // factor (1 - x^n), so this scalar is -nu_y(x), not
                // h(x) = nu_y(x) / (x^n - 1).
                let linearization_expected_eval := sub(r, quotient_eval_numer)
                mstore(QUOTIENT_EVAL_MPTR, linearization_expected_eval)
                {%- endmatch %}
            }
