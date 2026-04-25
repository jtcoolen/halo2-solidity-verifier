#![allow(clippy::useless_format)]

use crate::codegen::{
    pcs::{queries, Query},
    util::{
        for_loop, group_backward_adjacent_ec_points, group_backward_adjacent_words,
        ConstraintSystemMeta, Data, EcPoint, Location, Ptr, Word,
    },
};
use itertools::{chain, izip, Itertools};
use std::collections::BTreeMap;

pub(super) fn static_working_memory_size(meta: &ConstraintSystemMeta, _: &Data) -> usize {
    // Returns the size in *words*. For BLS each EIP-2537 G1 point is 4
    // words; we reserve 0x180 bytes (= 12 words) for the ACC + TMP +
    // operand scratch starting at 0x00, plus 4 words per rotation point.
    12 + meta.num_rotations * 4
}

pub(super) fn computations(meta: &ConstraintSystemMeta, data: &Data) -> Vec<Vec<String>> {
    let sets = rotation_sets(&queries(meta, data));
    let rots = sets.iter().map(|set| set.rot).collect_vec();
    let (min_rot, max_rot) = rots
        .iter()
        .copied()
        .minmax()
        .into_option()
        .unwrap_or_default();

    let ws = EcPoint::range(data.w_cptr).take(sets.len()).collect_vec();

    // Scratch starts after the two 4-word accumulator slots (0x00..0x100).
    // Each `point_w` is a 4-word G1 point; consecutive points are 0x80
    // bytes apart, matching the BLS EIP-2537 stride.
    let point_w_mptr = Ptr::memory(0x180);
    let point_ws = izip!(rots, EcPoint::range(point_w_mptr)).collect::<BTreeMap<_, _>>();

    let eval_computations = {
        chain![
            [
                "let nu := mload(NU_MPTR)",
                "let mu := mload(MU_MPTR)",
                "let eval_acc",
                "let eval_tmp",
            ]
            .map(str::to_string),
            sets.iter().enumerate().rev().flat_map(|(set_idx, set)| {
                let is_last_set = set_idx == sets.len() - 1;
                let eval_acc = &format!("eval_{}", if is_last_set { "acc" } else { "tmp" });
                let eval_groups = group_backward_adjacent_words(set.evals().iter().rev().skip(1));

                chain![
                    set.evals()
                        .last()
                        .map(|eval| format!("{eval_acc} := {}", eval)),
                    eval_groups.iter().flat_map(|(loc, evals)| {
                        if evals.len() < 3 {
                            evals
                                .iter()
                                .map(|eval| {
                                    format!(
                                        "{eval_acc} := addmod(mulmod({eval_acc}, nu, r), {eval}, r)"
                                    )
                                })
                                .collect_vec()
                        } else {
                            assert_eq!(*loc, Location::Calldata);
                            let eval = "calldataload(cptr)";
                            for_loop(
                                [
                                    format!("let cptr := {}", evals[0].ptr()),
                                    format!("let cptr_end := {}", evals[0].ptr() - evals.len()),
                                ],
                                "lt(cptr_end, cptr)",
                                ["cptr := sub(cptr, 0x20)"],
                                [format!(
                                    "{eval_acc} := addmod(mulmod({eval_acc}, nu, r), {eval}, r)"
                                )],
                            )
                        }
                    }),
                    (!is_last_set)
                        .then_some([
                            "eval_acc := mulmod(eval_acc, mu, r)",
                            "eval_acc := addmod(eval_acc, eval_tmp, r)",
                        ])
                        .into_iter()
                        .flatten()
                        .map(str::to_string),
                ]
                .collect_vec()
            }),
            ["mstore(G1_SCALAR_MPTR, sub(r, eval_acc))".to_string()],
        ]
        .collect_vec()
    };

    // We re-use the *first* word of each 4-word `point_w` slot to first
    // stash the scalar `x_pow_of_omega^|rot|`. `point_w_computations` later
    // overwrites the whole 4-word slot with the resulting G1 point.
    let point_computations = chain![
        [
            "let x := mload(X_MPTR)",
            "let omega := mload(OMEGA_MPTR)",
            "let omega_inv := mload(OMEGA_INV_MPTR)",
            "let x_pow_of_omega := mulmod(x, omega, r)"
        ]
        .map(str::to_string),
        (1..=max_rot).flat_map(|rot| {
            chain![
                point_ws
                    .get(&rot)
                    .map(|point| format!("mstore({}, x_pow_of_omega)", point.ptr())),
                (rot != max_rot)
                    .then(|| "x_pow_of_omega := mulmod(x_pow_of_omega, omega, r)".to_string())
            ]
        }),
        [
            format!("mstore({}, x)", point_ws[&0].ptr()),
            format!("x_pow_of_omega := mulmod(x, omega_inv, r)")
        ],
        (min_rot..0).rev().flat_map(|rot| {
            chain![
                point_ws
                    .get(&rot)
                    .map(|point| format!("mstore({}, x_pow_of_omega)", point.ptr())),
                (rot != min_rot).then(|| {
                    "x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)".to_string()
                })
            ]
        })
    ]
    .collect_vec();

    // For each rotation set we have a calldata G1 point W and a cached
    // scalar x_pow_of_omega^|rot| at `mptr` (first word of the 4-word
    // slot). We compute `W * scalar` via the EIP-2537 BLS12_G1MSM
    // precompile, leaving the result in ACC slot, then persist all four
    // words back into the slot. Cptr/mptr both stride by 0x80 (4 words).
    let point_w_computations = for_loop(
        [
            format!("let cptr := {}", data.w_cptr),
            format!("let mptr := {point_w_mptr}"),
            format!("let mptr_end := {}", point_w_mptr + 4 * sets.len()),
        ],
        "lt(mptr, mptr_end)".to_string(),
        ["mptr := add(mptr, 0x80)", "cptr := add(cptr, 0x80)"].map(str::to_string),
        [
            "mstore(0x00, calldataload(cptr))",
            "mstore(0x20, calldataload(add(cptr, 0x20)))",
            "mstore(0x40, calldataload(add(cptr, 0x40)))",
            "mstore(0x60, calldataload(add(cptr, 0x60)))",
            "success := ec_mul_acc(success, mload(mptr))",
            "mstore(mptr, mload(0x00))",
            "mstore(add(mptr, 0x20), mload(0x20))",
            "mstore(add(mptr, 0x40), mload(0x40))",
            "mstore(add(mptr, 0x60), mload(0x60))",
        ]
        .map(str::to_string),
    );

    // -----------------------------------------------------------------
    // BLS12-381 / EIP-2537 pairing-input emission. Same memory layout as
    // bdfg21::pairing_input_computations -- accumulator slot at 0x00..0x80
    // for the *last* set processed (which lands in ACC), TMP slot at
    // 0x80..0x100 for earlier sets, and a 4-word operand slot one stride
    // further out.
    // -----------------------------------------------------------------
    let pairing_lhs_computations = chain![
        ["let nu := mload(NU_MPTR)", "let mu := mload(MU_MPTR)"].map(str::to_string),
        sets.iter().enumerate().rev().flat_map(|(set_idx, set)| {
            let is_last_set = set_idx == sets.len() - 1;
            let track = if is_last_set { "acc" } else { "tmp" };
            let ec_add = format!("ec_add_{track}");
            let ec_mul = format!("ec_mul_{track}");
            let acc_base = Ptr::memory(0x00) + if is_last_set { 0 } else { 4 };
            let operand_base = acc_base + 4;
            let point_w = &point_ws[&set.rot];
            let comm_groups = group_backward_adjacent_ec_points(set.comms().iter().rev().skip(1));

            let emit_mstore_words = move |comm: &EcPoint| {
                let words = comm.words();
                [
                    format!("mstore({}, {})", operand_base, words[0]),
                    format!("mstore({}, {})", operand_base + 1, words[1]),
                    format!("mstore({}, {})", operand_base + 2, words[2]),
                    format!("mstore({}, {})", operand_base + 3, words[3]),
                ]
            };

            chain![
                // Pre-multiply ACC by mu BEFORE building this set's TMP.
                // Doing it after would corrupt the TMP G1 point because
                // `ec_mul_acc` writes the scalar at 0x80, the same word
                // where the TMP point's x_hi lives.
                (!is_last_set)
                    .then_some(["success := ec_mul_acc(success, mu)"])
                    .into_iter()
                    .flatten()
                    .map(str::to_string),
                // Seed accumulator with the last commitment of the set.
                set.comms()
                    .last()
                    .map(|comm| {
                        let words = comm.words();
                        [
                            format!("mstore({}, {})", acc_base, words[0]),
                            format!("mstore({}, {})", acc_base + 1, words[1]),
                            format!("mstore({}, {})", acc_base + 2, words[2]),
                            format!("mstore({}, {})", acc_base + 3, words[3]),
                        ]
                    })
                    .into_iter()
                    .flatten(),
                comm_groups.into_iter().flat_map({
                    let ec_add = ec_add.clone();
                    let ec_mul = ec_mul.clone();
                    move |(loc, comms)| {
                        let ptr = comms.first().unwrap().ptr();
                        // The `ptr_end = ptr - 4 * comms.len()` calculation
                        // can go negative when the calldata range starts
                        // close to offset 0 (e.g. advice commitments at
                        // 0x64 with BLS's 0x80 stride). The EVM's `lt` is
                        // unsigned, so a negative ptr_end (rendered as
                        // `sub(0, X)` = 2^256 - X) makes the loop body
                        // never execute. Detect that case at codegen time
                        // and inline instead.
                        let ptr_end_underflow = if let crate::codegen::util::Value::Integer(p) =
                            ptr.value()
                        {
                            p - (4 * comms.len() as isize) * 0x20 < 0
                        } else {
                            false
                        };
                        if comms.len() < 3 || ptr_end_underflow {
                            comms
                                .iter()
                                .flat_map(|comm| {
                                    chain![
                                        [format!("success := {ec_mul}(success, nu)")],
                                        emit_mstore_words(comm),
                                        [format!("success := {ec_add}(success)")],
                                    ]
                                    .collect_vec()
                                })
                                .collect_vec()
                        } else {
                            let ptr_end = ptr - 4 * comms.len();
                            let opcode = match loc {
                                Location::Calldata => "calldataload",
                                Location::Memory => "mload",
                            };
                            for_loop(
                                [
                                    format!("let ptr := {ptr}"),
                                    format!("let ptr_end := {ptr_end}"),
                                ],
                                "lt(ptr_end, ptr)",
                                ["ptr := sub(ptr, 0x80)".to_string()],
                                [
                                    format!("success := {ec_mul}(success, nu)"),
                                    format!("mstore({}, {opcode}(ptr))", operand_base),
                                    format!(
                                        "mstore({}, {opcode}(add(ptr, 0x20)))",
                                        operand_base + 1
                                    ),
                                    format!(
                                        "mstore({}, {opcode}(add(ptr, 0x40)))",
                                        operand_base + 2
                                    ),
                                    format!(
                                        "mstore({}, {opcode}(add(ptr, 0x60)))",
                                        operand_base + 3
                                    ),
                                    format!("success := {ec_add}(success)"),
                                ],
                            )
                        }
                    }
                }),
                // Add the precomputed point_w (4 words at point_w.ptr())
                // into the running accumulator.
                {
                    let pw = point_w.ptr();
                    [
                        format!("mstore({}, mload({}))", operand_base, pw),
                        format!("mstore({}, mload({}))", operand_base + 1, pw + 1),
                        format!("mstore({}, mload({}))", operand_base + 2, pw + 2),
                        format!("mstore({}, mload({}))", operand_base + 3, pw + 3),
                        format!("success := {ec_add}(success)"),
                    ]
                },
                (!is_last_set)
                    .then_some([
                        // ACC was already multiplied by mu at the top of
                        // this iteration; just fold TMP (= inner_msm of
                        // this set, sitting at 0x80..0x100) into ACC.
                        // ec_add_acc reads the operand from 0x80..0x100,
                        // which is exactly where TMP lives, so no extra
                        // copy is needed.
                        "success := ec_add_acc(success)",
                    ])
                    .into_iter()
                    .flatten()
                    .map(str::to_string),
            ]
            .collect_vec()
        }),
        // Final mix-in: + G1_BASE * G1_SCALAR, then persist as PAIRING_LHS.
        [
            format!("mstore(0x80, mload(G1_BASE_MPTR))"),
            format!("mstore(0xa0, mload(add(G1_BASE_MPTR, 0x20)))"),
            format!("mstore(0xc0, mload(add(G1_BASE_MPTR, 0x40)))"),
            format!("mstore(0xe0, mload(add(G1_BASE_MPTR, 0x60)))"),
            format!("success := ec_mul_tmp(success, mload(G1_SCALAR_MPTR))"),
            format!("success := ec_add_acc(success)"),
            format!("mstore(PAIRING_LHS_MPTR, mload(0x00))"),
            format!("mstore(add(PAIRING_LHS_MPTR, 0x20), mload(0x20))"),
            format!("mstore(add(PAIRING_LHS_MPTR, 0x40), mload(0x40))"),
            format!("mstore(add(PAIRING_LHS_MPTR, 0x60), mload(0x60))"),
        ],
    ]
    .collect_vec();

    // PAIRING_RHS = sum_i mu^i * W_i (folded right-to-left).
    let pairing_rhs_computations = chain![
        [format!("let mu := mload(MU_MPTR)")],
        // Seed ACC with the last W (4 words from calldata).
        {
            let last = ws.last().unwrap();
            let words = last.words();
            [
                format!("mstore(0x00, {})", words[0]),
                format!("mstore(0x20, {})", words[1]),
                format!("mstore(0x40, {})", words[2]),
                format!("mstore(0x60, {})", words[3]),
            ]
        },
        ws.iter()
            .nth_back(1)
            .map(|w_second_last| {
                for_loop(
                    [
                        format!("let cptr := {}", w_second_last.ptr()),
                        format!("let cptr_end := {}", ws[0].ptr() - 1),
                    ],
                    "lt(cptr_end, cptr)",
                    ["cptr := sub(cptr, 0x80)"],
                    [
                        "success := ec_mul_acc(success, mu)".to_string(),
                        "mstore(0x80, calldataload(cptr))".to_string(),
                        "mstore(0xa0, calldataload(add(cptr, 0x20)))".to_string(),
                        "mstore(0xc0, calldataload(add(cptr, 0x40)))".to_string(),
                        "mstore(0xe0, calldataload(add(cptr, 0x60)))".to_string(),
                        "success := ec_add_acc(success)".to_string(),
                    ],
                )
            })
            .into_iter()
            .flatten(),
        [
            format!("mstore(PAIRING_RHS_MPTR, mload(0x00))"),
            format!("mstore(add(PAIRING_RHS_MPTR, 0x20), mload(0x20))"),
            format!("mstore(add(PAIRING_RHS_MPTR, 0x40), mload(0x40))"),
            format!("mstore(add(PAIRING_RHS_MPTR, 0x60), mload(0x60))"),
        ],
    ]
    .collect_vec();

    vec![
        eval_computations,
        point_computations,
        point_w_computations,
        pairing_lhs_computations,
        pairing_rhs_computations,
    ]
}

#[derive(Debug)]
struct RotationSet {
    rot: i32,
    comms: Vec<EcPoint>,
    evals: Vec<Word>,
}

impl RotationSet {
    fn comms(&self) -> &[EcPoint] {
        &self.comms
    }

    fn evals(&self) -> &[Word] {
        &self.evals
    }
}

fn rotation_sets(queries: &[Query]) -> Vec<RotationSet> {
    queries.iter().fold(Vec::new(), |mut sets, query| {
        if let Some(pos) = sets.iter().position(|set| set.rot == query.rot) {
            sets[pos].comms.push(query.comm);
            sets[pos].evals.push(query.eval);
        } else {
            sets.push(RotationSet {
                rot: query.rot,
                comms: vec![query.comm],
                evals: vec![query.eval],
            });
        }
        sets
    })
}
