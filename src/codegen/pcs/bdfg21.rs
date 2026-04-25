#![allow(clippy::useless_format)]

use crate::codegen::{
    pcs::{queries, Query},
    util::{
        for_loop, group_backward_adjacent_ec_points, group_backward_adjacent_words,
        ConstraintSystemMeta, Data, EcPoint, Location, Ptr, Word,
    },
};
use itertools::{chain, izip, Itertools};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn static_working_memory_size(meta: &ConstraintSystemMeta, data: &Data) -> usize {
    let (superset, sets) = rotation_sets(&queries(meta, data));
    let num_coeffs = sets.iter().map(|set| set.rots().len()).sum::<usize>();
    2 * (1 + num_coeffs) + 6 + 2 * superset.len() + 1 + 3 * sets.len()
}

pub(super) fn computations(meta: &ConstraintSystemMeta, data: &Data) -> Vec<Vec<String>> {
    let (superset, sets) = rotation_sets(&queries(meta, data));
    let min_rot = *superset.first().unwrap();
    let max_rot = *superset.last().unwrap();
    let num_coeffs = sets.iter().map(|set| set.rots().len()).sum::<usize>();

    // Each G1 point is a 4-word EIP-2537 quad in calldata.
    let w = EcPoint::from(data.w_cptr);
    let w_prime = EcPoint::from(data.w_cptr + 4);

    let diff_0 = Word::from(Ptr::memory(0x00));
    let coeffs = sets
        .iter()
        .scan(diff_0.ptr() + 1, |state, set| {
            let ptrs = Word::range(*state).take(set.rots().len()).collect_vec();
            *state = *state + set.rots().len();
            Some(ptrs)
        })
        .collect_vec();

    let first_batch_invert_end = diff_0.ptr() + 1 + num_coeffs;
    let second_batch_invert_end = diff_0.ptr() + sets.len();
    let free_mptr = diff_0.ptr() + 2 * (1 + num_coeffs) + 6;

    let point_mptr = free_mptr;
    let mu_minus_point_mptr = point_mptr + superset.len();
    let vanishing_0_mptr = mu_minus_point_mptr + superset.len();
    let diff_mptr = vanishing_0_mptr + 1;
    let r_eval_mptr = diff_mptr + sets.len();
    let sum_mptr = r_eval_mptr + sets.len();

    let point_vars =
        izip!(&superset, (0..).map(|idx| format!("point_{idx}"))).collect::<BTreeMap<_, _>>();
    let points = izip!(&superset, Word::range(point_mptr)).collect::<BTreeMap<_, _>>();
    let mu_minus_points =
        izip!(&superset, Word::range(mu_minus_point_mptr)).collect::<BTreeMap<_, _>>();
    let vanishing_0 = Word::from(vanishing_0_mptr);
    let diffs = Word::range(diff_mptr).take(sets.len()).collect_vec();
    let r_evals = Word::range(r_eval_mptr).take(sets.len()).collect_vec();
    let sums = Word::range(sum_mptr).take(sets.len()).collect_vec();

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
                points
                    .get(&rot)
                    .map(|point| format!("mstore({}, x_pow_of_omega)", point.ptr())),
                (rot != max_rot)
                    .then(|| "x_pow_of_omega := mulmod(x_pow_of_omega, omega, r)".to_string())
            ]
        }),
        [
            format!("mstore({}, x)", points[&0].ptr()),
            format!("x_pow_of_omega := mulmod(x, omega_inv, r)")
        ],
        (min_rot..0).rev().flat_map(|rot| {
            chain![
                points
                    .get(&rot)
                    .map(|point| format!("mstore({}, x_pow_of_omega)", point.ptr())),
                (rot != min_rot).then(|| {
                    "x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)".to_string()
                })
            ]
        })
    ]
    .collect_vec();

    let vanishing_computations = chain![
        ["let mu := mload(MU_MPTR)".to_string()],
        {
            let mptr = mu_minus_points.first_key_value().unwrap().1.ptr();
            let mptr_end = mptr + mu_minus_points.len();
            for_loop(
                [
                    format!("let mptr := {mptr}"),
                    format!("let mptr_end := {mptr_end}"),
                    format!("let point_mptr := {free_mptr}"),
                ],
                "lt(mptr, mptr_end)",
                [
                    "mptr := add(mptr, 0x20)",
                    "point_mptr := add(point_mptr, 0x20)",
                ],
                ["mstore(mptr, addmod(mu, sub(r, mload(point_mptr)), r))"],
            )
        },
        ["let s".to_string()],
        chain![
            [format!(
                "s := {}",
                mu_minus_points[sets[0].rots().first().unwrap()]
            )],
            chain![sets[0].rots().iter().skip(1)]
                .map(|rot| { format!("s := mulmod(s, {}, r)", mu_minus_points[rot]) }),
            [format!("mstore({}, s)", vanishing_0.ptr())],
        ],
        ["let diff".to_string()],
        izip!(0.., &sets, &diffs).flat_map(|(set_idx, set, diff)| {
            chain![
                [set.diffs()
                    .first()
                    .map(|rot| format!("diff := {}", mu_minus_points[rot]))
                    .unwrap_or_else(|| "diff := 1".to_string())],
                chain![set.diffs().iter().skip(1)]
                    .map(|rot| { format!("diff := mulmod(diff, {}, r)", mu_minus_points[rot]) }),
                [format!("mstore({}, diff)", diff.ptr())],
                (set_idx == 0).then(|| format!("mstore({}, diff)", diff_0.ptr())),
            ]
        })
    ]
    .collect_vec();

    let coeff_computations = izip!(&sets, &coeffs)
        .map(|(set, coeffs)| {
            let coeff_points = set
                .rots()
                .iter()
                .map(|rot| &point_vars[rot])
                .enumerate()
                .map(|(i, rot_i)| {
                    set.rots()
                        .iter()
                        .map(|rot| &point_vars[rot])
                        .enumerate()
                        .filter_map(|(j, rot_j)| (i != j).then_some((rot_i, rot_j)))
                        .collect_vec()
                })
                .collect_vec();
            chain![
                set.rots()
                    .iter()
                    .map(|rot| format!("let {} := {}", &point_vars[rot], points[rot])),
                ["let coeff".to_string()],
                izip!(set.rots(), &coeff_points, coeffs).flat_map(
                    |(rot_i, coeff_points, coeff)| chain![
                        [coeff_points
                            .first()
                            .map(|(point_i, point_j)| {
                                format!("coeff := addmod({point_i}, sub(r, {point_j}), r)")
                            })
                            .unwrap_or_else(|| "coeff := 1".to_string())],
                        coeff_points.iter().skip(1).map(|(point_i, point_j)| {
                            let item = format!("addmod({point_i}, sub(r, {point_j}), r)");
                            format!("coeff := mulmod(coeff, {item}, r)")
                        }),
                        [
                            format!("coeff := mulmod(coeff, {}, r)", mu_minus_points[rot_i]),
                            format!("mstore({}, coeff)", coeff.ptr())
                        ],
                    ]
                )
            ]
            .collect_vec()
        })
        .collect_vec();

    let normalized_coeff_computations = chain![
        [
            format!("success := batch_invert(success, 0, {first_batch_invert_end}, r)"),
            format!("let diff_0_inv := {diff_0}"),
            format!("mstore({}, diff_0_inv)", diffs[0].ptr()),
        ],
        for_loop(
            [
                format!("let mptr := {}", diffs[0].ptr() + 1),
                format!("let mptr_end := {}", diffs[0].ptr() + sets.len()),
            ],
            "lt(mptr, mptr_end)",
            ["mptr := add(mptr, 0x20)"],
            ["mstore(mptr, mulmod(mload(mptr), diff_0_inv, r))"],
        ),
    ]
    .collect_vec();

    let r_evals_computations = izip!(0.., &sets, &coeffs, &diffs, &r_evals).map(
        |(set_idx, set, coeffs, set_coeff, r_eval)| {
            let is_single_rot_set = set.rots().len() == 1;
            chain![
                is_single_rot_set.then(|| format!("let coeff := {}", coeffs[0])),
                ["let zeta := mload(ZETA_MPTR)", "let r_eval"].map(str::to_string),
                if is_single_rot_set {
                    let evals = set.evals().iter().map(|evals| evals[0]).collect_vec();
                    let eval_groups = group_backward_adjacent_words(evals.iter().rev().skip(1));
                    chain![
                        evals
                            .last()
                            .map(|eval| format!("r_eval := mulmod(coeff, {eval}, r)")),
                        eval_groups.iter().flat_map(|(loc, evals)| {
                            if evals.len() < 3 {
                                evals
                                    .iter()
                                    .flat_map(|eval| {
                                        let item = format!("mulmod(coeff, {eval}, r)");
                                        [
                                            format!("r_eval := mulmod(r_eval, zeta, r)"),
                                            format!("r_eval := addmod(r_eval, {item}, r)"),
                                        ]
                                    })
                                    .collect_vec()
                            } else {
                                assert_eq!(*loc, Location::Calldata);
                                let item = "mulmod(coeff, calldataload(cptr), r)";
                                for_loop(
                                    [
                                        format!("let cptr := {}", evals[0].ptr()),
                                        format!("let cptr_end := {}", evals[0].ptr() - evals.len()),
                                    ],
                                    "lt(cptr_end, cptr)",
                                    ["cptr := sub(cptr, 0x20)"],
                                    [format!(
                                        "r_eval := addmod(mulmod(r_eval, zeta, r), {item}, r)"
                                    )],
                                )
                            }
                        })
                    ]
                    .collect_vec()
                } else {
                    chain![set.evals().iter().enumerate().rev()]
                        .flat_map(|(idx, evals)| {
                            chain![
                                izip!(evals, coeffs).map(|(eval, coeff)| {
                                    let item = format!("mulmod({coeff}, {eval}, r)");
                                    format!("r_eval := addmod(r_eval, {item}, r)")
                                }),
                                (idx != 0).then(|| format!("r_eval := mulmod(r_eval, zeta, r)")),
                            ]
                        })
                        .collect_vec()
                },
                (set_idx != 0).then(|| format!("r_eval := mulmod(r_eval, {set_coeff}, r)")),
                [format!("mstore({}, r_eval)", r_eval.ptr())],
            ]
            .collect_vec()
        },
    );

    let coeff_sums_computation = izip!(&coeffs, &sums).map(|(coeffs, sum)| {
        let (coeff_0, rest_coeffs) = coeffs.split_first().unwrap();
        chain![
            [format!("let sum := {coeff_0}")],
            rest_coeffs
                .iter()
                .map(|coeff_mptr| format!("sum := addmod(sum, {coeff_mptr}, r)")),
            [format!("mstore({}, sum)", sum.ptr())],
        ]
        .collect_vec()
    });

    let r_eval_computations = chain![
        for_loop(
            [
                format!("let mptr := 0x00"),
                format!("let mptr_end := {second_batch_invert_end}"),
                format!("let sum_mptr := {}", sums[0].ptr()),
            ],
            "lt(mptr, mptr_end)",
            ["mptr := add(mptr, 0x20)", "sum_mptr := add(sum_mptr, 0x20)"],
            ["mstore(mptr, mload(sum_mptr))"],
        ),
        [
            format!("success := batch_invert(success, 0, {second_batch_invert_end}, r)"),
            format!(
                "let r_eval := mulmod(mload({}), {}, r)",
                second_batch_invert_end - 1,
                r_evals.last().unwrap()
            )
        ],
        for_loop(
            [
                format!("let sum_inv_mptr := {}", second_batch_invert_end - 2),
                format!("let sum_inv_mptr_end := {second_batch_invert_end}"),
                format!("let r_eval_mptr := {}", r_evals[r_evals.len() - 2].ptr()),
            ],
            "lt(sum_inv_mptr, sum_inv_mptr_end)",
            [
                "sum_inv_mptr := sub(sum_inv_mptr, 0x20)",
                "r_eval_mptr := sub(r_eval_mptr, 0x20)"
            ],
            [
                "r_eval := mulmod(r_eval, mload(NU_MPTR), r)",
                "r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), r), r)"
            ],
        ),
        ["mstore(G1_SCALAR_MPTR, sub(r, r_eval))".to_string()],
    ]
    .collect_vec();

    // -----------------------------------------------------------------
    // BLS12-381 / EIP-2537 pairing-input emission.
    //
    // Each G1 point is 4 words (x_hi, x_lo, y_hi, y_lo). The runtime EVM
    // helpers in Halo2Verifier.sol expect:
    //
    //   ec_add_acc(success):
    //     reads acc      from 0x00..0x80
    //     reads operand  from 0x80..0x100
    //     writes acc     to   0x00..0x80
    //   ec_mul_acc(success, scalar):
    //     reads acc      from 0x00..0x80
    //     puts scalar    at   0x80
    //     writes acc     to   0x00..0x80
    //   ec_add_tmp / ec_mul_tmp: same shape shifted by 0x80.
    //
    // So when we want to fold a commitment `C` into ACC we mstore the four
    // words of `C` to 0x80..0x100 and call `ec_add_acc(success)`. For the
    // TMP-track the operand goes to 0x100..0x180 and we call
    // `ec_add_tmp(success)`.
    // -----------------------------------------------------------------
    let pairing_input_computations = chain![
        ["let zeta := mload(ZETA_MPTR)", "let nu := mload(NU_MPTR)"].map(str::to_string),
        izip!(0.., &sets, &diffs).flat_map(|(set_idx, set, set_coeff)| {
            let is_first_set = set_idx == 0;
            let is_last_set = set_idx == sets.len() - 1;
            let track = if is_first_set { "acc" } else { "tmp" };
            let ec_add = format!("ec_add_{track}");
            let ec_mul = format!("ec_mul_{track}");
            // Accumulator base: ACC slot at 0x00 for the first set, TMP slot
            // at 0x80 for the rest. The matching operand slot is one slot
            // further along (0x80 / 0x100 respectively).
            let acc_base = Ptr::memory(0x00) + if is_first_set { 0 } else { 4 };
            let operand_base = acc_base + 4;
            let comm_groups = group_backward_adjacent_ec_points(set.comms().iter().rev().skip(1));

            // Closure: emit the four mstores moving a commitment word-quad
            // (in calldata or memory) into the operand slot at `operand_base`.
            let emit_mstore_words = |comm: &EcPoint| {
                let words = comm.words();
                [
                    format!("mstore({}, {})", operand_base, words[0]),
                    format!("mstore({}, {})", operand_base + 1, words[1]),
                    format!("mstore({}, {})", operand_base + 2, words[2]),
                    format!("mstore({}, {})", operand_base + 3, words[3]),
                ]
            };

            chain![
                // Seed the running accumulator with the last commitment of the
                // set: just write its four words to the accumulator slot.
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
                comm_groups.into_iter().flat_map(move |(loc, comms)| {
                    if comms.len() < 3 {
                        comms
                            .iter()
                            .flat_map(|comm| {
                                chain![
                                    [format!("success := {ec_mul}(success, zeta)")],
                                    emit_mstore_words(comm),
                                    [format!("success := {ec_add}(success)")],
                                ]
                                .collect_vec()
                            })
                            .collect_vec()
                    } else {
                        // Stride between commitments is 4 words = 0x80 bytes.
                        let ptr = comms.first().unwrap().ptr();
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
                            ["ptr := sub(ptr, 0x80)"],
                            [
                                format!("success := {ec_mul}(success, zeta)"),
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
                }),
                (!is_first_set)
                    .then(|| {
                        let scalar = format!("mulmod(nu, {set_coeff}, r)");
                        // After folding the TMP-track set into a single G1
                        // (in TMP slot 0x80..0x100), multiply by the
                        // composite nu*set_coeff and add into ACC.
                        chain![
                            [format!("success := ec_mul_tmp(success, {scalar})")],
                            // ec_add_acc reads operand from 0x80..0x100, which
                            // is exactly where TMP already lives -- no copy
                            // needed.
                            [format!("success := ec_add_acc(success)")],
                            (!is_last_set).then(|| format!("nu := mulmod(nu, mload(NU_MPTR), r)"))
                        ]
                    })
                    .into_iter()
                    .flatten(),
            ]
            .collect_vec()
        }),
        // ----- Final mix-in steps. Each step loads a G1 point into TMP
        //       (0x80..0x100), multiplies by a scalar, then adds into ACC.
        chain![
            // + G1_BASE * G1_SCALAR
            [
                format!("mstore(0x80, mload(G1_BASE_MPTR))"),
                format!("mstore(0xa0, mload(add(G1_BASE_MPTR, 0x20)))"),
                format!("mstore(0xc0, mload(add(G1_BASE_MPTR, 0x40)))"),
                format!("mstore(0xe0, mload(add(G1_BASE_MPTR, 0x60)))"),
                format!("success := ec_mul_tmp(success, mload(G1_SCALAR_MPTR))"),
                format!("success := ec_add_acc(success)"),
            ],
            // + (-vanishing_0) * W
            {
                let w_words = w.words();
                [
                    format!("mstore(0x80, {})", w_words[0]),
                    format!("mstore(0xa0, {})", w_words[1]),
                    format!("mstore(0xc0, {})", w_words[2]),
                    format!("mstore(0xe0, {})", w_words[3]),
                    format!("success := ec_mul_tmp(success, sub(r, {vanishing_0}))"),
                    format!("success := ec_add_acc(success)"),
                ]
            },
            // + mu * W'
            {
                let wp_words = w_prime.words();
                [
                    format!("mstore(0x80, {})", wp_words[0]),
                    format!("mstore(0xa0, {})", wp_words[1]),
                    format!("mstore(0xc0, {})", wp_words[2]),
                    format!("mstore(0xe0, {})", wp_words[3]),
                    format!("success := ec_mul_tmp(success, mload(MU_MPTR))"),
                    format!("success := ec_add_acc(success)"),
                ]
            },
            // Persist ACC as PAIRING_LHS (4 words) and W' as PAIRING_RHS.
            [
                format!("mstore(PAIRING_LHS_MPTR, mload(0x00))"),
                format!("mstore(add(PAIRING_LHS_MPTR, 0x20), mload(0x20))"),
                format!("mstore(add(PAIRING_LHS_MPTR, 0x40), mload(0x40))"),
                format!("mstore(add(PAIRING_LHS_MPTR, 0x60), mload(0x60))"),
                format!("mstore(PAIRING_RHS_MPTR, {})", w_prime.x_hi()),
                format!("mstore(add(PAIRING_RHS_MPTR, 0x20), {})", w_prime.x_lo()),
                format!("mstore(add(PAIRING_RHS_MPTR, 0x40), {})", w_prime.y_hi()),
                format!("mstore(add(PAIRING_RHS_MPTR, 0x60), {})", w_prime.y_lo()),
            ],
        ],
    ]
    .collect_vec();

    chain![
        [point_computations, vanishing_computations],
        coeff_computations,
        [normalized_coeff_computations],
        r_evals_computations,
        coeff_sums_computation,
        [r_eval_computations, pairing_input_computations],
    ]
    .collect_vec()
}

#[derive(Debug)]
struct RotationSet {
    rots: BTreeSet<i32>,
    diffs: BTreeSet<i32>,
    comms: Vec<EcPoint>,
    evals: Vec<Vec<Word>>,
}

impl RotationSet {
    fn rots(&self) -> &BTreeSet<i32> {
        &self.rots
    }

    fn diffs(&self) -> &BTreeSet<i32> {
        &self.diffs
    }

    fn comms(&self) -> &[EcPoint] {
        &self.comms
    }

    fn evals(&self) -> &[Vec<Word>] {
        &self.evals
    }
}

fn rotation_sets(queries: &[Query]) -> (BTreeSet<i32>, Vec<RotationSet>) {
    let mut superset = BTreeSet::new();
    let comm_queries = queries.iter().fold(
        Vec::<(EcPoint, BTreeMap<i32, Word>)>::new(),
        |mut comm_queries, query| {
            superset.insert(query.rot);
            if let Some(pos) = comm_queries
                .iter()
                .position(|(comm, _)| comm == &query.comm)
            {
                let (_, queries) = &mut comm_queries[pos];
                assert!(!queries.contains_key(&query.rot));
                queries.insert(query.rot, query.eval);
            } else {
                comm_queries.push((query.comm, BTreeMap::from_iter([(query.rot, query.eval)])));
            }
            comm_queries
        },
    );
    let superset = superset;
    let sets =
        comm_queries
            .into_iter()
            .fold(Vec::<RotationSet>::new(), |mut sets, (comm, queries)| {
                if let Some(pos) = sets
                    .iter()
                    .position(|set| itertools::equal(&set.rots, queries.keys()))
                {
                    let set = &mut sets[pos];
                    if !set.comms.contains(&comm) {
                        set.comms.push(comm);
                        set.evals.push(queries.into_values().collect_vec());
                    }
                } else {
                    let diffs = BTreeSet::from_iter(
                        superset
                            .iter()
                            .filter(|rot| !queries.contains_key(rot))
                            .copied(),
                    );
                    let set = RotationSet {
                        rots: BTreeSet::from_iter(queries.keys().copied()),
                        diffs,
                        comms: vec![comm],
                        evals: vec![queries.into_values().collect()],
                    };
                    sets.push(set);
                }
                sets
            });
    (superset, sets)
}
