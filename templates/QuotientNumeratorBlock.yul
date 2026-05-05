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
                mstore({{ program.eval_numer_mptr|hex() }}, 0)
                mstore({{ program.trace_id_mptr|hex() }}, {{ quotient_identity_trace_base }})
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
                mstore({{ program.sel_scale_mptr|hex() }}, 1)
                mstore({{ program.sel_inv_scale_mptr|hex() }}, 1)
                mstore({{ program.y_inv_mptr|hex() }}, 0)
                {
                    // Keep this inversion away from scalar_inv's fixed 0x6000
                    // scratch: large separated VKs occupy that range.
                    let q_inv_scratch := {{ program.stack_mptr|hex() }}
                    if iszero(y) { revert(0, 0) }
                    mstore(add(q_inv_scratch, {{ template_constants.modexp.base_len_offset|hex() }}), {{ template_constants.word_bytes|hex() }})
                    mstore(add(q_inv_scratch, {{ template_constants.modexp.exp_len_offset|hex() }}), {{ template_constants.word_bytes|hex() }})
                    mstore(add(q_inv_scratch, {{ template_constants.modexp.mod_len_offset|hex() }}), {{ template_constants.word_bytes|hex() }})
                    mstore(add(q_inv_scratch, {{ template_constants.modexp.base_offset|hex() }}), y)
                    mstore(add(q_inv_scratch, {{ template_constants.modexp.exp_offset|hex() }}), sub(FR_MODULUS, 2))
                    mstore(add(q_inv_scratch, {{ template_constants.modexp.mod_offset|hex() }}), FR_MODULUS)
                    if iszero(staticcall(gas(), {{ template_constants.modexp.address|hex() }}, q_inv_scratch, {{ template_constants.modexp.frame_bytes|hex() }}, q_inv_scratch, {{ template_constants.modexp.output_bytes|hex() }})) { revert(0, 0) }
                    if iszero(eq(returndatasize(), {{ template_constants.modexp.output_bytes|hex() }})) { revert(0, 0) }
                    mstore({{ program.y_inv_mptr|hex() }}, mload(q_inv_scratch))
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
                // q_sp's registered range must cover the interpreted operand
                // stack plus any native callback scratch that reuses this base
                // pointer. In particular, the native permutation callback
                // writes a structured scratch table at program.stack_mptr.
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
                //   0x19 native permutation    0x1b native heavy identity
                //   0x1c LIN7                 0x1d BILIN7_ROW
                //   0x1e BILIN7_PAIRWISE      0x1f native lookup
                //   0x20 POW5
                //
                // There are two physical encodings for the same logical VM:
                // packed32 and byte-oriented. Packed32 implements the fixed
                // base cases; byte-oriented mode also carries dynamic runs and
                // optional limb-aware cases.
                {#
                Template-only switch/case reference.

                This comment documents the interpreter source without being
                emitted into generated Solidity. Runtime behavior lives in the
                two switch blocks below; opcode numbers and operand layouts are
                defined in src/codegen/quotient/mod.rs.

                Shared stack model:
                - q_top caches the top stack value.
                - q_has_top records whether q_top is live.
                - q_sp points just past spilled stack words.
                - push-like cases spill the old q_top when q_has_top is set.
                - ADD/MUL pop by moving q_sp back one word.
                - accumulator cases mutate q_top in place.
                - FOLD_* cases consume q_top and advance the y-batch state.
                - native callbacks reset q_top/q_sp and perform their own
                  fold calls inside generated callback code.

                Case map:
                0x01 push_const
                  bytes:    u16 const_idx
                  packed32: q_arg = const_idx
                  effect:   push q_const_mptr[const_idx]

                0x02 push_mem_literal
                  bytes:    u32 ptr
                  packed32: q_arg = ptr, limited to 24 bits
                  effect:   push mload(ptr)

                0x03 push_mem_token
                  bytes:    u8 token
                  packed32: q_arg = token
                  effect:   resolve token to a generated pointer and push it

                0x04 push_mem_token_offset
                  bytes:    u8 token, u32 offset
                  packed32: q_arg = (token << 16) | u16 offset
                  effect:   resolve token, add byte offset, and push mload

                0x05 push_mem_u16
                  bytes:    u16 ptr
                  packed32: q_arg = ptr
                  effect:   compact pointer load

                0x06 add
                  effect: q_top = stack_pop() + q_top mod Fr

                0x07 mul
                  effect: q_top = stack_pop() * q_top mod Fr

                0x08 neg
                  effect: q_top = -q_top mod Fr

                0x09 push_const_u8
                  bytes:    u8 const_idx
                  packed32: q_arg = const_idx
                  effect:   short form of push_const

                0x0a fold_main
                  effect: trace q_top, advance q_eval_numer = q_eval_numer*y
                          + q_top, and advance selector scaling if present

                0x0b fold_selector
                  bytes:    u16 selector_idx
                  packed32: q_arg = selector_idx
                  effect: trace q_top, advance the global y position, and add
                          q_top * q_sel_inv_scale to selector bucket

                0x0c add_const_u8
                  effect: q_top += q_const_mptr[u8 const_idx]

                0x0d mul_const_u8
                  effect: q_top *= q_const_mptr[u8 const_idx]

                0x0e add_const
                  effect: q_top += q_const_mptr[u16 const_idx]

                0x0f mul_const
                  effect: q_top *= q_const_mptr[u16 const_idx]

                0x10 add_mem_u16
                  effect: q_top += mload(u16 ptr)

                0x11 mul_mem_u16
                  effect: q_top *= mload(u16 ptr)

                0x12 add_mul_mem_mem_const_u8
                  bytes:    u16 lhs, u16 rhs, u8 const_idx
                  packed32: q_arg = const_idx, extra word = (lhs << 16) | rhs
                  effect:   q_top += mload(lhs) * mload(rhs) * const

                0x13 add_mul_const_u8_mem_u16
                  bytes:    u16 ptr, u8 const_idx
                  packed32: q_arg = (const_idx << 16) | ptr
                  effect:   q_top += mload(ptr) * const

                0x14 add_mul_mem_mem
                  bytes:    u16 lhs, u16 rhs
                  packed32: extra word = (lhs << 16) | rhs
                  effect:   q_top += mload(lhs) * mload(rhs)

                0x15 run_add_mul_mem_mem_const_u8
                  bytes only: u16 count, then count * {u16 lhs, u16 rhs, u8 c}
                  effect: repeated 0x12 in one dispatch

                0x16 run_add_mul_const_u8_mem_u16
                  bytes only: u16 count, then count * {u16 ptr, u8 c}
                  effect: repeated 0x13 in one dispatch

                0x17 push_temp
                  effect: push q_tmp_mptr[temp_idx]; emitted only with CSE temps

                0x18 store_temp
                  effect: store q_top to q_tmp_mptr[temp_idx], leaving q_top live

                0x19 native_permutation
                  effect: evaluate and fold the generated permutation identity
                          family at this VM stream position

                0x1a reserved
                  effect: no switch case; default branch reverts

                0x1b native_identity
                  effect: dispatch to one generated heavy-gate callback by index

                0x1c lin7
                  bytes only: seven {u8 const_idx, u16 ptr} pairs
                  effect: push sum_i const_i * mload(ptr_i)

                0x1d bilin7_row
                  bytes only: u16 lhs, seven {u8 const_idx, u16 rhs} pairs
                  effect: push mload(lhs) * sum_i const_i * mload(rhs_i)

                0x1e bilin7_pairwise
                  bytes only: u16 lhs_base, u16 rhs_base, 13 const indexes
                  effect: push sum_{i,j} const_{i+j} * lhs_i * rhs_j

                0x1f native_lookup
                  effect: evaluate and fold LogUp boundary/helper/accumulator
                          identities at this VM stream position

                0x20 pow5
                  effect: q_top = q_top^5

                Memory token map used by 0x03/0x04:
                0x01 L_0_MPTR
                0x02 L_LAST_MPTR
                0x03 L_BLIND_MPTR
                0x04 BETA_MPTR
                0x05 GAMMA_MPTR
                0x06 X_MPTR
                0x07 THETA_MPTR
                0x08 TRASH_CHALLENGE_MPTR
                0x09 INSTANCE_EVAL_MPTR
                #}
                {%- if program.packed32 %}
                // Packed32 encoding: each base instruction is one 4-byte word
                // with the opcode in the high byte and a 24-bit operand.
                // Some fused opcodes consume an extra packed word.
                for { } lt(q_pc, q_end) { } {
                    let q_inst := shr(224, mload(q_pc))
                    q_pc := add(q_pc, {{ template_constants.quotient_vm.packed_instruction_bytes|hex() }})
                    let q_op := shr(24, q_inst)
                    let q_arg := and(q_inst, {{ template_constants.quotient_vm.packed_arg_mask|hex() }})

                    switch q_op
                    {%- if program.op_usage.push_const %}
                    {# VM 0x01 PUSH_CONST (packed32): q_arg is a quotient constant-table slot. #}
                    case {{ template_constants.quotient_vm.op.push_const|hex() }} {
                        let qconst := q_arg
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_const_mptr, shl(5, qconst)))
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_mem_literal %}
                    {# VM 0x02 PUSH_MEM_LITERAL (packed32): q_arg is a 24-bit memory pointer. #}
                    case {{ template_constants.quotient_vm.op.push_mem_literal|hex() }} {
                        let q_ptr := q_arg
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_mem_token %}
                    {# VM 0x03 PUSH_MEM_TOKEN (packed32): q_arg selects a symbolic memory pointer. #}
                    case {{ template_constants.quotient_vm.op.push_mem_token|hex() }} {
                        let q_token := q_arg
                        let q_ptr := 0
                        {# Token cases decode generated symbolic memory addresses. #}
                        switch q_token
                        {%- if program.mem_usage.l0 %}
                        case {{ template_constants.quotient_vm.mem.l0|hex() }} { q_ptr := L_0_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.l_last %}
                        case {{ template_constants.quotient_vm.mem.l_last|hex() }} { q_ptr := L_LAST_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.l_blind %}
                        case {{ template_constants.quotient_vm.mem.l_blind|hex() }} { q_ptr := L_BLIND_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.beta %}
                        case {{ template_constants.quotient_vm.mem.beta|hex() }} { q_ptr := BETA_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.gamma %}
                        case {{ template_constants.quotient_vm.mem.gamma|hex() }} { q_ptr := GAMMA_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.x %}
                        case {{ template_constants.quotient_vm.mem.x|hex() }} { q_ptr := X_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.theta %}
                        case {{ template_constants.quotient_vm.mem.theta|hex() }} { q_ptr := THETA_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.trash_challenge %}
                        case {{ template_constants.quotient_vm.mem.trash_challenge|hex() }} { q_ptr := TRASH_CHALLENGE_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.instance_eval %}
                        case {{ template_constants.quotient_vm.mem.instance_eval|hex() }} { q_ptr := INSTANCE_EVAL_MPTR }
                        {%- endif %}
                        default { revert(0, 0) }
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_mem_token_offset %}
                    {# VM 0x04 PUSH_MEM_TOKEN_OFFSET (packed32): q_arg packs token and u16 byte offset. #}
                    case {{ template_constants.quotient_vm.op.push_mem_token_offset|hex() }} {
                        let q_token := shr(16, q_arg)
                        let q_off := and(q_arg, 0xffff)
                        let q_ptr := 0
                        {# Token-offset cases reuse the same token table, then add q_off. #}
                        switch q_token
                        {%- if program.mem_usage.l0 %}
                        case {{ template_constants.quotient_vm.mem.l0|hex() }} { q_ptr := add(L_0_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.l_last %}
                        case {{ template_constants.quotient_vm.mem.l_last|hex() }} { q_ptr := add(L_LAST_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.l_blind %}
                        case {{ template_constants.quotient_vm.mem.l_blind|hex() }} { q_ptr := add(L_BLIND_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.beta %}
                        case {{ template_constants.quotient_vm.mem.beta|hex() }} { q_ptr := add(BETA_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.gamma %}
                        case {{ template_constants.quotient_vm.mem.gamma|hex() }} { q_ptr := add(GAMMA_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.x %}
                        case {{ template_constants.quotient_vm.mem.x|hex() }} { q_ptr := add(X_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.theta %}
                        case {{ template_constants.quotient_vm.mem.theta|hex() }} { q_ptr := add(THETA_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.trash_challenge %}
                        case {{ template_constants.quotient_vm.mem.trash_challenge|hex() }} { q_ptr := add(TRASH_CHALLENGE_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.instance_eval %}
                        case {{ template_constants.quotient_vm.mem.instance_eval|hex() }} { q_ptr := add(INSTANCE_EVAL_MPTR, q_off) }
                        {%- endif %}
                        default { revert(0, 0) }
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_mem_u16 %}
                    {# VM 0x05 PUSH_MEM_U16 (packed32): q_arg is a short memory pointer. #}
                    case {{ template_constants.quotient_vm.op.push_mem_u16|hex() }} {
                        let q_ptr := q_arg
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.add %}
                    {# VM 0x06 ADD: pop one spilled stack word and add it to q_top. #}
                    case {{ template_constants.quotient_vm.op.add|hex() }} {
                        q_sp := sub(q_sp, 0x20)
                        q_top := addmod(mload(q_sp), q_top, r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.mul %}
                    {# VM 0x07 MUL: pop one spilled stack word and multiply it by q_top. #}
                    case {{ template_constants.quotient_vm.op.mul|hex() }} {
                        q_sp := sub(q_sp, 0x20)
                        q_top := mulmod(mload(q_sp), q_top, r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.neg %}
                    {# VM 0x08 NEG: replace q_top with its Fr negation. #}
                    case {{ template_constants.quotient_vm.op.neg|hex() }} {
                        q_top := addmod(0, sub(r, q_top), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.pow5 %}
                    {# VM 0x20 POW5: replace q_top with q_top^5. #}
                    case {{ template_constants.quotient_vm.op.pow5|hex() }} {
                        let q2 := mulmod(q_top, q_top, r)
                        q_top := mulmod(q_top, mulmod(q2, q2, r), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_const_u8 %}
                    {# VM 0x09 PUSH_CONST_U8 (packed32): q_arg is an 8-bit constant slot. #}
                    case {{ template_constants.quotient_vm.op.push_const_u8|hex() }} {
                        let qconst := q_arg
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_const_mptr, shl(5, qconst)))
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.add_const_u8 %}
                    {# VM 0x0c ADD_CONST_U8: add a small constant-table slot into q_top. #}
                    case {{ template_constants.quotient_vm.op.add_const_u8|hex() }} {
                        q_top := addmod(q_top, mload(add(q_const_mptr, shl(5, q_arg))), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.mul_const_u8 %}
                    {# VM 0x0d MUL_CONST_U8: multiply q_top by a small constant-table slot. #}
                    case {{ template_constants.quotient_vm.op.mul_const_u8|hex() }} {
                        q_top := mulmod(q_top, mload(add(q_const_mptr, shl(5, q_arg))), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.add_const %}
                    {# VM 0x0e ADD_CONST: add a wider constant-table slot into q_top. #}
                    case {{ template_constants.quotient_vm.op.add_const|hex() }} {
                        q_top := addmod(q_top, mload(add(q_const_mptr, shl(5, q_arg))), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.mul_const %}
                    {# VM 0x0f MUL_CONST: multiply q_top by a wider constant-table slot. #}
                    case {{ template_constants.quotient_vm.op.mul_const|hex() }} {
                        q_top := mulmod(q_top, mload(add(q_const_mptr, shl(5, q_arg))), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.add_mem_u16 %}
                    {# VM 0x10 ADD_MEM_U16: add mload(q_arg) into q_top. #}
                    case {{ template_constants.quotient_vm.op.add_mem_u16|hex() }} {
                        q_top := addmod(q_top, mload(q_arg), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.mul_mem_u16 %}
                    {# VM 0x11 MUL_MEM_U16: multiply q_top by mload(q_arg). #}
                    case {{ template_constants.quotient_vm.op.mul_mem_u16|hex() }} {
                        q_top := mulmod(q_top, mload(q_arg), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.add_mul_mem_mem_const_u8 %}
                    {# VM 0x12 ADD_MUL_MEM_MEM_CONST_U8: fused q_top += lhs * rhs * const. #}
                    case {{ template_constants.quotient_vm.op.add_mul_mem_mem_const_u8|hex() }} {
                        let q_pair := shr(224, mload(q_pc))
                        q_pc := add(q_pc, {{ template_constants.quotient_vm.packed_instruction_bytes|hex() }})
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
                    {%- endif %}
                    {%- if program.op_usage.add_mul_const_u8_mem_u16 %}
                    {# VM 0x13 ADD_MUL_CONST_U8_MEM_U16: fused q_top += mem * const. #}
                    case {{ template_constants.quotient_vm.op.add_mul_const_u8_mem_u16|hex() }} {
                        let qconst := shr(16, q_arg)
                        let q_ptr := and(q_arg, 0xffff)
                        q_top := addmod(
                            q_top,
                            mulmod(mload(q_ptr), mload(add(q_const_mptr, shl(5, qconst))), r),
                            r
                        )
                    }
                    {%- endif %}
                    {%- if program.op_usage.add_mul_mem_mem %}
                    {# VM 0x14 ADD_MUL_MEM_MEM: fused q_top += lhs * rhs. #}
                    case {{ template_constants.quotient_vm.op.add_mul_mem_mem|hex() }} {
                        let q_pair := shr(224, mload(q_pc))
                        q_pc := add(q_pc, {{ template_constants.quotient_vm.packed_instruction_bytes|hex() }})
                        let q_lhs := shr(16, q_pair)
                        let q_rhs := and(q_pair, 0xffff)
                        q_top := addmod(q_top, mulmod(mload(q_lhs), mload(q_rhs), r), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_temp %}
                    {# VM 0x17 PUSH_TEMP: push a CSE temp from q_tmp_mptr. #}
                    case {{ template_constants.quotient_vm.op.push_temp|hex() }} {
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_tmp_mptr, shl(5, q_arg)))
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.store_temp %}
                    {# VM 0x18 STORE_TEMP: store q_top into a CSE temp without consuming it. #}
                    case {{ template_constants.quotient_vm.op.store_temp|hex() }} {
                        mstore(add(q_tmp_mptr, shl(5, q_arg)), q_top)
                    }
                    {%- endif %}
                    {%- if program.op_usage.native_permutation && quotient_native_permutation_computation.len() > 0 %}
                    // Native permutation callback. It evaluates the
                    // permutation identities from permutation.rs at this exact
                    // VM position, preserving the Rust identity order while
                    // avoiding a large interpreted product loop.
                    {# VM 0x19 NATIVE_PERMUTATION: marker for the generated permutation callback. #}
                    case {{ template_constants.quotient_vm.op.native_permutation|hex() }} {
                        q_top := 0
                        q_has_top := 0
                        // The generated loop below uses program.stack_mptr as
                        // its scratch-table base, not as a conventional VM
                        // stack. The Rust memory planner must reserve enough
                        // words for structured_permutation_scratch_words(meta)
                        // whenever this opcode can appear.
                        q_sp := {{ program.stack_mptr|hex() }}
                        {%- for line in quotient_native_permutation_computation %}
                        {{ line }}
                        {%- endfor %}
                    }
                    {%- endif %}
                    {%- if program.op_usage.native_lookup && quotient_native_lookup_computation.len() > 0 %}
                    // Native lookup callback. This whole-family opcode
                    // evaluates the LogUp boundary, helper-chunk, and
                    // accumulator identities at this VM position, preserving
                    // the Rust y-batch order while avoiding many interpreted
                    // product-loop opcodes.
                    {# VM 0x1f NATIVE_LOOKUP: marker for the generated LogUp lookup callback. #}
                    case {{ template_constants.quotient_vm.op.native_lookup|hex() }} {
                        q_top := 0
                        q_has_top := 0
                        // The generated loop below uses program.stack_mptr as
                        // f+beta/prefix/suffix scratch rather than as a
                        // conventional VM stack. The Rust memory planner must
                        // reserve structured_lookup_scratch_words(meta).
                        q_sp := {{ program.stack_mptr|hex() }}
                        {%- for line in quotient_native_lookup_computation %}
                        {{ line }}
                        {%- endfor %}
                    }
                    {%- endif %}
                    {%- if program.op_usage.native_identity && quotient_native_identity_computations.len() > 0 %}
                    // Native heavy-gate callback. The VM stream contains this
                    // opcode at the identity's original position, so the
                    // native Yul block keeps the same y-batching order as the
                    // compact interpreted identities.
                    {# VM 0x1b NATIVE_IDENTITY: marker for generated heavy-gate callbacks. #}
                    case {{ template_constants.quotient_vm.op.native_identity|hex() }} {
                        let q_native_idx := q_arg
                        q_top := 0
                        q_has_top := 0
                        q_sp := {{ program.stack_mptr|hex() }}
                        {# Native identity sub-cases are generated from selected heavy gate identities. #}
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
                    {%- if program.op_usage.fold_main %}
                    {# VM 0x0a FOLD_MAIN: consume q_top into the fully evaluated numerator fold. #}
                    case {{ template_constants.quotient_vm.op.fold_main|hex() }} {
                        let q_eval := q_top
                        q_has_top := 0
                        trace_u256(mload({{ program.trace_id_mptr|hex() }}), q_eval)
                        mstore({{ program.trace_id_mptr|hex() }}, add(mload({{ program.trace_id_mptr|hex() }}), 1))
                        // Fully-evaluated identity: qn = qn*y + eval.
                        // This forward Horner fold matches Rust's reverse
                        // y-power fold after all identities have been read.
                        mstore({{ program.eval_numer_mptr|hex() }}, mulmod(mload({{ program.eval_numer_mptr|hex() }}), y, r))
                        {%- if simple_selector_cols.len() > 0 %}
                        mstore({{ program.sel_scale_mptr|hex() }}, mulmod(mload({{ program.sel_scale_mptr|hex() }}), y, r))
                        mstore({{ program.sel_inv_scale_mptr|hex() }}, mulmod(mload({{ program.sel_inv_scale_mptr|hex() }}), mload({{ program.y_inv_mptr|hex() }}), r))
                        {%- endif %}
                        mstore({{ program.eval_numer_mptr|hex() }}, addmod(mload({{ program.eval_numer_mptr|hex() }}), q_eval, r))
                    }
                    {%- endif %}
                    {%- if program.op_usage.fold_selector %}
                    {# VM 0x0b FOLD_SELECTOR: consume q_top into one simple-selector bucket. #}
                    case {{ template_constants.quotient_vm.op.fold_selector|hex() }} {
                        let q_sel_idx := q_arg
                        let q_eval := q_top
                        q_has_top := 0
                        trace_u256(mload({{ program.trace_id_mptr|hex() }}), q_eval)
                        mstore({{ program.trace_id_mptr|hex() }}, add(mload({{ program.trace_id_mptr|hex() }}), 1))
                        // Simple-selector identity: advance the global y
                        // position, then accumulate into the selector bucket
                        // with y^-k. The final selector scaling restores the
                        // same y power used by Rust's grouped selector MSM.
                        mstore({{ program.eval_numer_mptr|hex() }}, mulmod(mload({{ program.eval_numer_mptr|hex() }}), y, r))
                        {%- if simple_selector_cols.len() > 0 %}
                        mstore({{ program.sel_scale_mptr|hex() }}, mulmod(mload({{ program.sel_scale_mptr|hex() }}), y, r))
                        mstore({{ program.sel_inv_scale_mptr|hex() }}, mulmod(mload({{ program.sel_inv_scale_mptr|hex() }}), mload({{ program.y_inv_mptr|hex() }}), r))
                        {%- endif %}
                        let q_target_ptr := add(SELECTOR_ACC_MPTR, shl(5, q_sel_idx))
                        mstore(q_target_ptr, addmod(mload(q_target_ptr), mulmod(q_eval, mload({{ program.sel_inv_scale_mptr|hex() }}), r), r))
                    }
                    {%- endif %}
                    {# Invalid generated bytecode should fail closed. 0x1a intentionally lands here. #}
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
                    {%- if program.op_usage.push_const %}
                    {# VM 0x01 PUSH_CONST (bytes): next two bytes are a constant-table slot. #}
                    case {{ template_constants.quotient_vm.op.push_const|hex() }} {
                        let qconst := shr(240, mload(q_pc))
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_const_mptr, shl(5, qconst)))
                        q_has_top := 1
                        q_pc := add(q_pc, 2)
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_mem_literal %}
                    {# VM 0x02 PUSH_MEM_LITERAL (bytes): next four bytes are a memory pointer. #}
                    case {{ template_constants.quotient_vm.op.push_mem_literal|hex() }} {
                        let q_ptr := shr(224, mload(q_pc))
                        q_pc := add(q_pc, {{ template_constants.quotient_vm.packed_instruction_bytes|hex() }})
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_mem_token %}
                    {# VM 0x03 PUSH_MEM_TOKEN (bytes): next byte selects a symbolic memory pointer. #}
                    case {{ template_constants.quotient_vm.op.push_mem_token|hex() }} {
                        let q_token := byte(0, mload(q_pc))
                        q_pc := add(q_pc, 1)
                        let q_ptr := 0
                        {# Token cases decode generated symbolic memory addresses. #}
                        switch q_token
                        {%- if program.mem_usage.l0 %}
                        case {{ template_constants.quotient_vm.mem.l0|hex() }} { q_ptr := L_0_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.l_last %}
                        case {{ template_constants.quotient_vm.mem.l_last|hex() }} { q_ptr := L_LAST_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.l_blind %}
                        case {{ template_constants.quotient_vm.mem.l_blind|hex() }} { q_ptr := L_BLIND_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.beta %}
                        case {{ template_constants.quotient_vm.mem.beta|hex() }} { q_ptr := BETA_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.gamma %}
                        case {{ template_constants.quotient_vm.mem.gamma|hex() }} { q_ptr := GAMMA_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.x %}
                        case {{ template_constants.quotient_vm.mem.x|hex() }} { q_ptr := X_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.theta %}
                        case {{ template_constants.quotient_vm.mem.theta|hex() }} { q_ptr := THETA_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.trash_challenge %}
                        case {{ template_constants.quotient_vm.mem.trash_challenge|hex() }} { q_ptr := TRASH_CHALLENGE_MPTR }
                        {%- endif %}
                        {%- if program.mem_usage.instance_eval %}
                        case {{ template_constants.quotient_vm.mem.instance_eval|hex() }} { q_ptr := INSTANCE_EVAL_MPTR }
                        {%- endif %}
                        default { revert(0, 0) }
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_mem_token_offset %}
                    {# VM 0x04 PUSH_MEM_TOKEN_OFFSET (bytes): token byte plus u32 byte offset. #}
                    case {{ template_constants.quotient_vm.op.push_mem_token_offset|hex() }} {
                        let q_token := byte(0, mload(q_pc))
                        let q_off := shr(224, mload(add(q_pc, 1)))
                        q_pc := add(q_pc, 5)
                        let q_ptr := 0
                        {# Token-offset cases reuse the same token table, then add q_off. #}
                        switch q_token
                        {%- if program.mem_usage.l0 %}
                        case {{ template_constants.quotient_vm.mem.l0|hex() }} { q_ptr := add(L_0_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.l_last %}
                        case {{ template_constants.quotient_vm.mem.l_last|hex() }} { q_ptr := add(L_LAST_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.l_blind %}
                        case {{ template_constants.quotient_vm.mem.l_blind|hex() }} { q_ptr := add(L_BLIND_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.beta %}
                        case {{ template_constants.quotient_vm.mem.beta|hex() }} { q_ptr := add(BETA_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.gamma %}
                        case {{ template_constants.quotient_vm.mem.gamma|hex() }} { q_ptr := add(GAMMA_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.x %}
                        case {{ template_constants.quotient_vm.mem.x|hex() }} { q_ptr := add(X_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.theta %}
                        case {{ template_constants.quotient_vm.mem.theta|hex() }} { q_ptr := add(THETA_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.trash_challenge %}
                        case {{ template_constants.quotient_vm.mem.trash_challenge|hex() }} { q_ptr := add(TRASH_CHALLENGE_MPTR, q_off) }
                        {%- endif %}
                        {%- if program.mem_usage.instance_eval %}
                        case {{ template_constants.quotient_vm.mem.instance_eval|hex() }} { q_ptr := add(INSTANCE_EVAL_MPTR, q_off) }
                        {%- endif %}
                        default { revert(0, 0) }
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_mem_u16 %}
                    {# VM 0x05 PUSH_MEM_U16 (bytes): next two bytes are a short memory pointer. #}
                    case {{ template_constants.quotient_vm.op.push_mem_u16|hex() }} {
                        let q_ptr := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(q_ptr)
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.add %}
                    {# VM 0x06 ADD: pop one spilled stack word and add it to q_top. #}
                    case {{ template_constants.quotient_vm.op.add|hex() }} {
                        q_sp := sub(q_sp, 0x20)
                        q_top := addmod(mload(q_sp), q_top, r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.mul %}
                    {# VM 0x07 MUL: pop one spilled stack word and multiply it by q_top. #}
                    case {{ template_constants.quotient_vm.op.mul|hex() }} {
                        q_sp := sub(q_sp, 0x20)
                        q_top := mulmod(mload(q_sp), q_top, r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.neg %}
                    {# VM 0x08 NEG: replace q_top with its Fr negation. #}
                    case {{ template_constants.quotient_vm.op.neg|hex() }} {
                        q_top := addmod(0, sub(r, q_top), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.pow5 %}
                    {# VM 0x20 POW5: replace q_top with q_top^5. #}
                    case {{ template_constants.quotient_vm.op.pow5|hex() }} {
                        let q2 := mulmod(q_top, q_top, r)
                        q_top := mulmod(q_top, mulmod(q2, q2, r), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_const_u8 %}
                    {# VM 0x09 PUSH_CONST_U8 (bytes): next byte is a constant-table slot. #}
                    case {{ template_constants.quotient_vm.op.push_const_u8|hex() }} {
                        let qconst := byte(0, mload(q_pc))
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_const_mptr, shl(5, qconst)))
                        q_has_top := 1
                        q_pc := add(q_pc, 1)
                    }
                    {%- endif %}
                    {%- if program.op_usage.add_const_u8 %}
                    {# VM 0x0c ADD_CONST_U8: add a small constant-table slot into q_top. #}
                    case {{ template_constants.quotient_vm.op.add_const_u8|hex() }} {
                        let qconst := byte(0, mload(q_pc))
                        q_pc := add(q_pc, 1)
                        q_top := addmod(q_top, mload(add(q_const_mptr, shl(5, qconst))), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.mul_const_u8 %}
                    {# VM 0x0d MUL_CONST_U8: multiply q_top by a small constant-table slot. #}
                    case {{ template_constants.quotient_vm.op.mul_const_u8|hex() }} {
                        let qconst := byte(0, mload(q_pc))
                        q_pc := add(q_pc, 1)
                        q_top := mulmod(q_top, mload(add(q_const_mptr, shl(5, qconst))), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.add_const %}
                    {# VM 0x0e ADD_CONST: add a wider constant-table slot into q_top. #}
                    case {{ template_constants.quotient_vm.op.add_const|hex() }} {
                        let qconst := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        q_top := addmod(q_top, mload(add(q_const_mptr, shl(5, qconst))), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.mul_const %}
                    {# VM 0x0f MUL_CONST: multiply q_top by a wider constant-table slot. #}
                    case {{ template_constants.quotient_vm.op.mul_const|hex() }} {
                        let qconst := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        q_top := mulmod(q_top, mload(add(q_const_mptr, shl(5, qconst))), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.add_mem_u16 %}
                    {# VM 0x10 ADD_MEM_U16: add a short memory load into q_top. #}
                    case {{ template_constants.quotient_vm.op.add_mem_u16|hex() }} {
                        let q_ptr := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        q_top := addmod(q_top, mload(q_ptr), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.mul_mem_u16 %}
                    {# VM 0x11 MUL_MEM_U16: multiply q_top by a short memory load. #}
                    case {{ template_constants.quotient_vm.op.mul_mem_u16|hex() }} {
                        let q_ptr := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        q_top := mulmod(q_top, mload(q_ptr), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.add_mul_mem_mem_const_u8 %}
                    {# VM 0x12 ADD_MUL_MEM_MEM_CONST_U8: fused q_top += lhs * rhs * const. #}
                    case {{ template_constants.quotient_vm.op.add_mul_mem_mem_const_u8|hex() }} {
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
                    {%- endif %}
                    {%- if program.op_usage.add_mul_const_u8_mem_u16 %}
                    {# VM 0x13 ADD_MUL_CONST_U8_MEM_U16: fused q_top += mem * const. #}
                    case {{ template_constants.quotient_vm.op.add_mul_const_u8_mem_u16|hex() }} {
                        let q_ptr := shr(240, mload(q_pc))
                        let qconst := byte(0, mload(add(q_pc, 2)))
                        q_pc := add(q_pc, 3)
                        q_top := addmod(
                            q_top,
                            mulmod(mload(q_ptr), mload(add(q_const_mptr, shl(5, qconst))), r),
                            r
                        )
                    }
                    {%- endif %}
                    {%- if program.op_usage.add_mul_mem_mem %}
                    {# VM 0x14 ADD_MUL_MEM_MEM: fused q_top += lhs * rhs. #}
                    case {{ template_constants.quotient_vm.op.add_mul_mem_mem|hex() }} {
                        let q_lhs := shr(240, mload(q_pc))
                        let q_rhs := shr(240, mload(add(q_pc, 2)))
                        q_pc := add(q_pc, {{ template_constants.quotient_vm.packed_instruction_bytes|hex() }})
                        q_top := addmod(q_top, mulmod(mload(q_lhs), mload(q_rhs), r), r)
                    }
                    {%- endif %}
                    {%- if program.op_usage.push_temp %}
                    {# VM 0x17 PUSH_TEMP: push a CSE temp from q_tmp_mptr. #}
                    case {{ template_constants.quotient_vm.op.push_temp|hex() }} {
                        let q_tmp_idx := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        q_top := mload(add(q_tmp_mptr, shl(5, q_tmp_idx)))
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.store_temp %}
                    {# VM 0x18 STORE_TEMP: store q_top into a CSE temp without consuming it. #}
                    case {{ template_constants.quotient_vm.op.store_temp|hex() }} {
                        let q_tmp_idx := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        mstore(add(q_tmp_mptr, shl(5, q_tmp_idx)), q_top)
                    }
                    {%- endif %}
                    {%- if program.op_usage.run_add_mul_mem_mem_const_u8 %}
                    {# VM 0x15 RUN_ADD_MUL_MEM_MEM_CONST_U8: byte-only loop over fused 0x12 payloads. #}
                    case {{ template_constants.quotient_vm.op.run_add_mul_mem_mem_const_u8|hex() }} {
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
                    {%- endif %}
                    {%- if program.op_usage.run_add_mul_const_u8_mem_u16 %}
                    {# VM 0x16 RUN_ADD_MUL_CONST_U8_MEM_U16: byte-only loop over fused 0x13 payloads. #}
                    case {{ template_constants.quotient_vm.op.run_add_mul_const_u8_mem_u16|hex() }} {
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
                    {%- endif %}
                    {%- if program.op_usage.lin7 || program.op_usage.bilin7_row || program.op_usage.bilin7_pairwise || program.op_usage.modarith7 %}
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
                    {%- endif %}
                    {%- if program.op_usage.lin7 %}
                    {# VM 0x1c LIN7: byte-only 7-term foreign-field linear form. #}
                    case {{ template_constants.quotient_vm.op.lin7|hex() }} {
                        // LIN7: sum_i coeff[i] * value[i] over Fr.
                        // Typical Rust origin: foreign/gates/norm.rs
                        // normalization and foreign/gates/mul.rs base-power
                        // sums for x/y/z limbs.
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        let q_acc := 0
                        for { let q_i := 0 } lt(q_i, {{ template_constants.quotient_vm.limb_count }}) { q_i := add(q_i, 1) } {
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
                    {%- endif %}
                    {%- if program.op_usage.bilin7_row %}
                    {# VM 0x1d BILIN7_ROW: byte-only lhs times a 7-term weighted row. #}
                    case {{ template_constants.quotient_vm.op.bilin7_row|hex() }} {
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
                        for { let q_i := 0 } lt(q_i, {{ template_constants.quotient_vm.limb_count }}) { q_i := add(q_i, 1) } {
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
                    {%- endif %}
                    {%- if program.op_usage.bilin7_pairwise %}
                    {# VM 0x1e BILIN7_PAIRWISE: byte-only 7-by-7 weighted convolution. #}
                    case {{ template_constants.quotient_vm.op.bilin7_pairwise|hex() }} {
                        // BILIN7_PAIRWISE:
                        //   sum_{i=0..6,j=0..6} coeff[i+j] * lhs[i] * rhs[j].
                        // Bases point to contiguous 7-word limb vectors.
                        // Typical Rust origin:
                        //   sum_exprs(double_base_powers,
                        //             pair_wise_prod(lhs, rhs))
                        // where double_base_powers[k] = base^k mod m.
                        let q_lhs_base := shr(240, mload(q_pc))
                        let q_rhs_base := shr(240, mload(add(q_pc, 2)))
                        q_pc := add(q_pc, {{ template_constants.quotient_vm.packed_instruction_bytes|hex() }})
                        let q_coeff_pc := q_pc
                        q_pc := add(q_pc, {{ template_constants.quotient_vm.limb_pairwise_coeffs }})
                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }
                        let q_acc := 0
                        for { let q_i := 0 } lt(q_i, {{ template_constants.quotient_vm.limb_count }}) { q_i := add(q_i, 1) } {
                            let q_lhs_value := mload(add(q_lhs_base, shl(5, q_i)))
                            for { let q_j := 0 } lt(q_j, {{ template_constants.quotient_vm.limb_count }}) { q_j := add(q_j, 1) } {
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
                    {%- endif %}
                    {%- if program.op_usage.modarith7 %}
                    {# VM 0x21 MODARITH7: byte-only fused affine 7-limb foreign-field/ECC identity. #}
                    case {{ template_constants.quotient_vm.op.modarith7|hex() }} {
                        // MODARITH7:
                        //   maybe_cond * (
                        //       c
                        //     + sum LIN7 blocks
                        //     + sum BILIN7_ROW blocks
                        //     + sum BILIN7_PAIRWISE blocks
                        //     + sum coeff[k] * mload(ptr[k])
                        //   )
                        // It is a dispatch/operand-load optimization only;
                        // all coefficients still come from the generated
                        // quotient constant table.
                        let q_flags := byte(0, mload(q_pc))
                        q_pc := add(q_pc, 1)
                        let q_cond_ptr := 0
                        if and(q_flags, 0x01) {
                            q_cond_ptr := shr(240, mload(q_pc))
                            q_pc := add(q_pc, 2)
                        }

                        let q_acc := 0
                        if and(q_flags, 0x02) {
                            let qconst := byte(0, mload(q_pc))
                            q_pc := add(q_pc, 1)
                            q_acc := mload(add(q_const_mptr, shl(5, qconst)))
                        }

                        let q_lin_count := byte(0, mload(q_pc))
                        let q_row_count := byte(0, mload(add(q_pc, 1)))
                        let q_pairwise_count := byte(0, mload(add(q_pc, 2)))
                        let q_mem_count := byte(0, mload(add(q_pc, 3)))
                        q_pc := add(q_pc, 4)

                        if q_has_top {
                            mstore(q_sp, q_top)
                            q_sp := add(q_sp, 0x20)
                        }

                        for { let q_lin_block := 0 } lt(q_lin_block, q_lin_count) { q_lin_block := add(q_lin_block, 1) } {
                            for { let q_i := 0 } lt(q_i, {{ template_constants.quotient_vm.limb_count }}) { q_i := add(q_i, 1) } {
                                let qconst := byte(0, mload(q_pc))
                                let q_ptr := shr(240, mload(add(q_pc, 1)))
                                q_pc := add(q_pc, 3)
                                q_acc := addmod(
                                    q_acc,
                                    mulmod(mload(add(q_const_mptr, shl(5, qconst))), mload(q_ptr), r),
                                    r
                                )
                            }
                        }

                        for { let q_row_block := 0 } lt(q_row_block, q_row_count) { q_row_block := add(q_row_block, 1) } {
                            let q_lhs := shr(240, mload(q_pc))
                            q_pc := add(q_pc, 2)
                            let q_lhs_value := mload(q_lhs)
                            for { let q_i := 0 } lt(q_i, {{ template_constants.quotient_vm.limb_count }}) { q_i := add(q_i, 1) } {
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
                        }

                        for { let q_pair_block := 0 } lt(q_pair_block, q_pairwise_count) { q_pair_block := add(q_pair_block, 1) } {
                            let q_lhs_base := shr(240, mload(q_pc))
                            let q_rhs_base := shr(240, mload(add(q_pc, 2)))
                            q_pc := add(q_pc, {{ template_constants.quotient_vm.packed_instruction_bytes|hex() }})
                            let q_coeff_pc := q_pc
                            q_pc := add(q_pc, {{ template_constants.quotient_vm.limb_pairwise_coeffs }})
                            for { let q_i := 0 } lt(q_i, {{ template_constants.quotient_vm.limb_count }}) { q_i := add(q_i, 1) } {
                                let q_lhs_value := mload(add(q_lhs_base, shl(5, q_i)))
                                for { let q_j := 0 } lt(q_j, {{ template_constants.quotient_vm.limb_count }}) { q_j := add(q_j, 1) } {
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
                        }

                        for { let q_mem_block := 0 } lt(q_mem_block, q_mem_count) { q_mem_block := add(q_mem_block, 1) } {
                            let qconst := byte(0, mload(q_pc))
                            let q_ptr := shr(240, mload(add(q_pc, 1)))
                            q_pc := add(q_pc, 3)
                            q_acc := addmod(
                                q_acc,
                                mulmod(mload(add(q_const_mptr, shl(5, qconst))), mload(q_ptr), r),
                                r
                            )
                        }

                        if and(q_flags, 0x01) {
                            q_acc := mulmod(mload(q_cond_ptr), q_acc, r)
                        }
                        q_top := q_acc
                        q_has_top := 1
                    }
                    {%- endif %}
                    {%- if program.op_usage.native_permutation && quotient_native_permutation_computation.len() > 0 %}
                    // Native permutation callback. It evaluates the
                    // permutation identities from permutation.rs at this exact
                    // VM position, preserving the Rust identity order while
                    // avoiding a large interpreted product loop.
                    {# VM 0x19 NATIVE_PERMUTATION: marker for the generated permutation callback. #}
                    case {{ template_constants.quotient_vm.op.native_permutation|hex() }} {
                        q_top := 0
                        q_has_top := 0
                        // The generated loop below uses program.stack_mptr as
                        // its scratch-table base, not as a conventional VM
                        // stack. The Rust memory planner must reserve enough
                        // words for structured_permutation_scratch_words(meta)
                        // whenever this opcode can appear.
                        q_sp := {{ program.stack_mptr|hex() }}
                        {%- for line in quotient_native_permutation_computation %}
                        {{ line }}
                        {%- endfor %}
                    }
                    {%- endif %}
                    {%- if program.op_usage.native_lookup && quotient_native_lookup_computation.len() > 0 %}
                    // Native lookup callback. This whole-family opcode
                    // evaluates the LogUp boundary, helper-chunk, and
                    // accumulator identities at this VM position, preserving
                    // the Rust y-batch order while avoiding many interpreted
                    // product-loop opcodes.
                    {# VM 0x1f NATIVE_LOOKUP: marker for the generated LogUp lookup callback. #}
                    case {{ template_constants.quotient_vm.op.native_lookup|hex() }} {
                        q_top := 0
                        q_has_top := 0
                        // The generated loop below uses program.stack_mptr as
                        // f+beta/prefix/suffix scratch rather than as a
                        // conventional VM stack. The Rust memory planner must
                        // reserve structured_lookup_scratch_words(meta).
                        q_sp := {{ program.stack_mptr|hex() }}
                        {%- for line in quotient_native_lookup_computation %}
                        {{ line }}
                        {%- endfor %}
                    }
                    {%- endif %}
                    {%- if program.op_usage.native_identity && quotient_native_identity_computations.len() > 0 %}
                    // Native callbacks are generated only for the heaviest
                    // recognized Midfall gate identities. All other gate and
                    // non-native identity arithmetic remains in
                    // the compact q_program VM above, preserving the Rust
                    // `partially_evaluate_identities` order.
                    {# VM 0x1b NATIVE_IDENTITY: marker for generated heavy-gate callbacks. #}
                    case {{ template_constants.quotient_vm.op.native_identity|hex() }} {
                        let q_native_idx := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        q_top := 0
                        q_has_top := 0
                        q_sp := {{ program.stack_mptr|hex() }}
                        {# Native identity sub-cases are generated from selected heavy gate identities. #}
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
                    {%- if program.op_usage.fold_main %}
                    {# VM 0x0a FOLD_MAIN: consume q_top into the fully evaluated numerator fold. #}
                    case {{ template_constants.quotient_vm.op.fold_main|hex() }} {
                        let q_eval := q_top
                        q_has_top := 0
                        trace_u256(mload({{ program.trace_id_mptr|hex() }}), q_eval)
                        mstore({{ program.trace_id_mptr|hex() }}, add(mload({{ program.trace_id_mptr|hex() }}), 1))
                        // Fully-evaluated identity: qn = qn*y + eval.
                        // This matches the reverse y-power fold in Rust
                        // linearization once all identities have been read.
                        mstore({{ program.eval_numer_mptr|hex() }}, mulmod(mload({{ program.eval_numer_mptr|hex() }}), y, r))
                        {%- if simple_selector_cols.len() > 0 %}
                        mstore({{ program.sel_scale_mptr|hex() }}, mulmod(mload({{ program.sel_scale_mptr|hex() }}), y, r))
                        mstore({{ program.sel_inv_scale_mptr|hex() }}, mulmod(mload({{ program.sel_inv_scale_mptr|hex() }}), mload({{ program.y_inv_mptr|hex() }}), r))
                        {%- endif %}
                        mstore({{ program.eval_numer_mptr|hex() }}, addmod(mload({{ program.eval_numer_mptr|hex() }}), q_eval, r))
                    }
                    {%- endif %}
                    {%- if program.op_usage.fold_selector %}
                    {# VM 0x0b FOLD_SELECTOR: consume q_top into one simple-selector bucket. #}
                    case {{ template_constants.quotient_vm.op.fold_selector|hex() }} {
                        let q_sel_idx := shr(240, mload(q_pc))
                        q_pc := add(q_pc, 2)
                        let q_eval := q_top
                        q_has_top := 0
                        trace_u256(mload({{ program.trace_id_mptr|hex() }}), q_eval)
                        mstore({{ program.trace_id_mptr|hex() }}, add(mload({{ program.trace_id_mptr|hex() }}), 1))
                        // Simple-selector identity: keep the same y-batch
                        // position as main identities, but defer the final
                        // y^m scaling so equal selector commitments are
                        // grouped like Rust's BTreeMap accumulator.
                        mstore({{ program.eval_numer_mptr|hex() }}, mulmod(mload({{ program.eval_numer_mptr|hex() }}), y, r))
                        {%- if simple_selector_cols.len() > 0 %}
                        mstore({{ program.sel_scale_mptr|hex() }}, mulmod(mload({{ program.sel_scale_mptr|hex() }}), y, r))
                        mstore({{ program.sel_inv_scale_mptr|hex() }}, mulmod(mload({{ program.sel_inv_scale_mptr|hex() }}), mload({{ program.y_inv_mptr|hex() }}), r))
                        {%- endif %}
                        let q_target_ptr := add(SELECTOR_ACC_MPTR, shl(5, q_sel_idx))
                        mstore(q_target_ptr, addmod(mload(q_target_ptr), mulmod(q_eval, mload({{ program.sel_inv_scale_mptr|hex() }}), r), r))
                    }
                    {%- endif %}
                    {# Invalid generated bytecode should fail closed. 0x1a intentionally lands here. #}
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
                    mstore(q_sel_ptr, mulmod(mload(q_sel_ptr), mload({{ program.sel_scale_mptr|hex() }}), r))
                }
                {%- endif %}

                // Fully evaluated identities are the constant-polynomial side
                // of the linearization query. Rust subtracts that grouped
                // scalar into expected_eval, so Solidity stores -nu_y(x).
                let linearization_expected_eval := addmod(0, sub(r, mload({{ program.eval_numer_mptr|hex() }})), r)
                mstore(QUOTIENT_EVAL_MPTR, linearization_expected_eval)
                pop(y)
                {%- when None %}
                // Legacy/direct mode. This path emits the numerator
                // reconstruction directly instead of interpreting q_program.
                // It is used for monolithic/experimental generation modes.
                let delta := {{ fr_delta }} // BLS12-381 Fr::DELTA
                let y := mload(Y_MPTR)
                let q_trace_id := {{ quotient_identity_trace_base }}

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
                let linearization_expected_eval := addmod(0, sub(r, quotient_eval_numer), r)
                mstore(QUOTIENT_EVAL_MPTR, linearization_expected_eval)
                {%- endmatch %}
            }
