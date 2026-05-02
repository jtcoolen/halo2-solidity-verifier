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
            //
            // Rust source-of-truth:
            //   - verifier.rs reads quotient commitments, samples x, then
            //     reads/computes all evaluations used below.
            //   - mod.rs::partially_evaluate_identities returns identities in
            //     gate, permutation, lookup, trash order.
            //   - linearization/verifier.rs::compute_linearization_commitment
            //     reverse-folds those identities by powers of y, sends
            //     simple-selector identities to selector commitment scalars,
            //     and subtracts fully-evaluated identities into expected_eval.
            //
            // This template is shared by the monolithic and external quotient
            // paths. In the external path, Halo2QuotientEvaluator first copies
            // the verifier memory frame into the same generated addresses.
            // ===============================================================
            {
                {%- match quotient_program %}
                {%- when Some with (program) %}
                // Compact quotient-program mode.
                //
                // The largest identity expressions are not all emitted as
                // unrolled Yul. Instead, most arithmetic is encoded as a small
                // q_program bytecode stored in the VK payload. This block
                // interprets that program, while selected heavy identities may
                // still be emitted as native callbacks for gas.
                let y := mload(Y_MPTR)

                // q_const_mptr points to Fr constants used by the VM.
                // q_program_mptr points to the bytecode stream.
                let q_const_mptr := {{ program.const_mptr|hex() }}
                let q_program_mptr := {{ program.program_mptr|hex() }}
                {%- if program.cse_temps > 0 %}
                // Optional CSE temp area used by q_program STORE_TEMP/LOAD_TEMP
                // opcodes. It is scratch within this evaluator call.
                let q_tmp_mptr := {{ program.tmp_mptr|hex() }}
                {%- endif %}

                // Running Horner accumulator for fully evaluated identities.
                // After all identities, this is nu_y(x) for the `None`
                // identity group.
                let quotient_eval_numer := 0
                {%- if simple_selector_cols.len() > 0 %}
                // Simple selectors are grouped into separate linearization
                // buckets. They start at zero for every proof.
                for { let q_sel_zero_off := 0 } lt(q_sel_zero_off, {{ (simple_selector_cols.len() * 0x20)|hex() }}) { q_sel_zero_off := add(q_sel_zero_off, 0x20) } {
                    mstore(add(SELECTOR_ACC_MPTR, q_sel_zero_off), 0)
                }

                // q_sel_scale tracks the final y^m multiplier for selector
                // buckets. q_sel_inv_scale tracks y^-k at each identity so a
                // selector bucket can be accumulated during a forward scan and
                // scaled once at the end to match Rust's reverse y-fold.
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

                // Direct inline prefix. These identities are generated as Yul
                // before entering the VM. They use the same fold snippets as
                // VM/native identities, so they occupy the same y-batch order.
                {%- for code_block in quotient_inline_computations %}
                {%- for line in code_block %}
                {{ line }}
                {%- endfor %}
                {%- endfor %}

                // VM registers:
                //   q_pc      current bytecode pointer
                //   q_end     end of bytecode stream
                //   q_sp      memory stack pointer for non-top stack values
                //   q_top     cached top-of-stack value
                //   q_has_top whether q_top currently holds a stack value
                //
                // The cached top reduces memory traffic in the interpreter.
                let q_pc := q_program_mptr
                let q_end := add(q_program_mptr, {{ program.len|hex() }})
                let q_sp := {{ program.stack_mptr|hex() }}
                let q_top := 0
                let q_has_top := 0

                // q_program opcode summary:
                //   0x01/0x09 push const       0x02/0x05 push memory
                //   0x03/0x04 push token ptr   0x06 add, 0x07 mul, 0x08 neg
                //   0x0a fold main identity    0x0b fold selector identity
                //   0x0c..0x11 add/mul const or memory into top
                //   0x12..0x16 fused add-mul runs
                //   0x17/0x18 load/store CSE temp
                //   0x19 native permutation    0x1a native trash
                //   0x1b native heavy identity
                //   0x1c LIN7                 0x1d BILIN7_ROW
                //   0x1e BILIN7_PAIRWISE
                //
                // There are two physical encodings for the same logical VM:
                // packed32 and byte-oriented. The generator chooses one; both
                // branches implement the same opcodes.
                {%- if program.packed32 %}
                // Packed32 encoding: each base instruction is one 4-byte word
                // with the opcode in the high byte and a 24-bit operand.
                // Some fused opcodes consume an extra packed word.
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
                    // Native permutation callback. It evaluates the
                    // permutation identities from permutation.rs at this exact
                    // VM position, preserving the Rust identity order while
                    // avoiding a large interpreted product loop.
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
                    // Native trash callback. Currently unused by the default
                    // IVC path, but kept for the structured/native experiment.
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
                    // Native heavy-gate callback. The VM stream contains this
                    // opcode at the identity's original position, so the
                    // native Yul block keeps the same y-batching order as the
                    // compact interpreted identities.
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
                        // Fully-evaluated identity: qn = qn*y + eval.
                        // This forward Horner fold matches Rust's reverse
                        // y-power fold after all identities have been read.
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
                        // Simple-selector identity: advance the global y
                        // position, then accumulate into the selector bucket
                        // with y^-k. The final selector scaling restores the
                        // same y power used by Rust's grouped selector MSM.
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
                // Byte-oriented encoding: opcodes are one byte followed by
                // operand bytes. This is usually smaller in VK data, while the
                // packed32 branch can be cheaper to decode in some settings.
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
                    // Limb-aware opcodes are opt-in compact forms for
                    // structurally recognized non-SHA foreign-field shapes.
                    // Coefficients are indexes into q_const_mptr, which is
                    // generated from VK/program data, never from proof
                    // calldata.
                    //
                    // Rust source shape:
                    //   proofs/src/plonk/mod.rs::partially_evaluate_identities
                    //   circuits/src/field/foreign/util.rs::{sum_exprs,pair_wise_prod}
                    //   circuits/src/field/foreign/params.rs::{base_powers,double_base_powers}
                    //
                    // "Foreign field" means the circuit represents elements
                    // modulo another modulus m as 7 limbs in base
                    // 2^LOG2_BASE. The verifier does not switch fields; it
                    // evaluates the lowered identity over BLS12-381 Fr, using
                    // Fr coefficients equal to base^i mod m or base^(i+j) mod m.
                    case 0x1c {
                        // LIN7: sum_i coeff[i] * value[i] over Fr.
                        // Typical Rust origin: foreign/gates/norm.rs
                        // normalization and foreign/gates/mul.rs base-power
                        // sums for x/y/z limbs.
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        let q_acc := 0
                        for { let q_i := 0 } lt(q_i, 7) { q_i := add(q_i, 1) } {
                            let qconst := byte(0, mload(q_pc))
                            let q_ptr := shr(240, mload(add(q_pc, 1)))
                            q_pc := add(q_pc, 3)
                            q_acc := addmod(
                                q_acc,
                                mulmod(mload(add(q_const_mptr, shl(5, qconst))), mload(q_ptr), r),
                                r
                            )
                        }
                        q_top := q_acc
                        q_has_top := 1
                    }
                    case 0x1d {
                        // BILIN7_ROW: lhs * sum_i coeff[i] * rhs[i].
                        // Typical Rust origin: one row/slice of
                        // pair_wise_prod in foreign multiplication and EC
                        // on_curve/slope/tangent/lambda_squared gates.
                        let q_lhs := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        let q_lhs_value := mload(q_lhs)
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        let q_acc := 0
                        for { let q_i := 0 } lt(q_i, 7) { q_i := add(q_i, 1) } {
                            let qconst := byte(0, mload(q_pc))
                            let q_rhs := shr(240, mload(add(q_pc, 1)))
                            q_pc := add(q_pc, 3)
                            q_acc := addmod(
                                q_acc,
                                mulmod(
                                    mulmod(q_lhs_value, mload(q_rhs), r),
                                    mload(add(q_const_mptr, shl(5, qconst))),
                                    r
                                ),
                                r
                            )
                        }
                        q_top := q_acc
                        q_has_top := 1
                    }
                    case 0x1e {
                        // BILIN7_PAIRWISE:
                        //   sum_{i=0..6,j=0..6} coeff[i+j] * lhs[i] * rhs[j].
                        // Bases point to contiguous 7-word limb vectors.
                        // Typical Rust origin:
                        //   sum_exprs(double_base_powers,
                        //             pair_wise_prod(lhs, rhs))
                        // where double_base_powers[k] = base^k mod m.
                        let q_lhs_base := shr(240, mload(q_pc))
                        let q_rhs_base := shr(240, mload(add(q_pc, 2)))
                        q_pc := add(q_pc, 4)
                        let q_coeff_pc := q_pc
                        q_pc := add(q_pc, 13)
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        let q_acc := 0
                        for { let q_i := 0 } lt(q_i, 7) { q_i := add(q_i, 1) } {
                            let q_lhs_value := mload(add(q_lhs_base, shl(5, q_i)))
                            for { let q_j := 0 } lt(q_j, 7) { q_j := add(q_j, 1) } {
                                let qconst := byte(0, mload(add(q_coeff_pc, add(q_i, q_j))))
                                q_acc := addmod(
                                    q_acc,
                                    mulmod(
                                        mulmod(q_lhs_value, mload(add(q_rhs_base, shl(5, q_j))), r),
                                        mload(add(q_const_mptr, shl(5, qconst))),
                                        r
                                    ),
                                    r
                                )
                            }
                        }
                        q_top := q_acc
                        q_has_top := 1
                    }
                    {%- if quotient_native_permutation_computation.len() > 0 %}
                    // Native permutation callback. It evaluates the
                    // permutation identities from permutation.rs at this exact
                    // VM position, preserving the Rust identity order while
                    // avoiding a large interpreted product loop.
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
                    // Native trash callback. Currently unused by the default
                    // IVC path, but kept for the structured/native experiment.
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
                    // Native callbacks are generated only for the heaviest
                    // recognized Midfall gate identities. All other gate,
                    // lookup, and non-native identity arithmetic remains in
                    // the compact q_program VM above, preserving the Rust
                    // `partially_evaluate_identities` order.
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
                        // Fully-evaluated identity: qn = qn*y + eval.
                        // This matches the reverse y-power fold in Rust
                        // linearization once all identities have been read.
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
                        // Simple-selector identity: keep the same y-batch
                        // position as main identities, but defer the final
                        // y^m scaling so equal selector commitments are
                        // grouped like Rust's BTreeMap accumulator.
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

                // Structured post-VM suffix. The current default uses this for
                // regular trash constraints: it is smaller than fully unrolled
                // Yul and cheaper than interpreting every trash operation.
                {%- for code_block in quotient_post_vm_computations %}
                {%- for line in code_block %}
                {{ line }}
                {%- endfor %}
                {%- endfor %}

                {%- if simple_selector_cols.len() > 0 %}
                // Finish selector buckets. During the forward scan each
                // selector contribution was multiplied by y^-k. Multiplying
                // all buckets by the final q_sel_scale restores the same
                // y power that Rust's reverse fold assigns to that identity.
                for { let q_i := 0 } lt(q_i, {{ simple_selector_cols.len() }}) { q_i := add(q_i, 1) } {
                    let q_sel_ptr := add(SELECTOR_ACC_MPTR, shl(5, q_i))
                    mstore(q_sel_ptr, mulmod(mload(q_sel_ptr), q_sel_scale, r))
                }
                {%- endif %}

                // Fully evaluated identities are the constant-polynomial side
                // of the linearization query. Rust subtracts that grouped
                // scalar into expected_eval, so Solidity stores -nu_y(x).
                let linearization_expected_eval := sub(r, quotient_eval_numer)
                mstore(QUOTIENT_EVAL_MPTR, linearization_expected_eval)
                pop(y)
                {%- when None %}
                // Legacy/direct mode. This path emits the numerator
                // reconstruction directly instead of interpreting q_program.
                // It is used for monolithic/experimental generation modes.
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
