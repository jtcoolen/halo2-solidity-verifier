//! Phase 1 size probe for the IVC final-step Solidity verification plan.
//!
//! Goal: gate the multi-day implementation effort behind a quick
//! constraint-system feasibility check. We want to know - BEFORE
//! committing to the codegen + aggregation-crate work - whether the
//! IVC verifier circuit (k=19, ProofAggregation transition) at all
//! fits the Solidity codegen's existing assumptions and the EVM's
//! 24 KB contract size limit / ~5 M gas tolerance for L1.
//!
//! This probe is METADATA-ONLY: it configures the IVC's
//! ConstraintSystem via `ZkStdLib::configure` (which depends only on
//! the architectural arch flags, not on any SRS / proof / VK), and
//! reports the structural numbers that drive the Solidity verifier's
//! size and gas profile.
//!
//! Run with:
//!   cargo test --test ivc_size_probe -- --ignored --nocapture
//!
//! No SRS or solc dependency. Runs in <1 s on the host.

use midnight_proofs::plonk::ConstraintSystem;
use midnight_zk_stdlib::{ZkStdLib, ZkStdLibArch};

type F = midnight_curves::Fq;

/// Mirror of `IvcCircuit::<ProofAggregation>::arch()` from
/// midfall/aggregation/src/ivc/circuit.rs:104.
///
/// IVC always enables `bls12_381 = true` (for the in-circuit verifier
/// gadget) and `poseidon = true` (for the in-circuit transcript). The
/// `ProofAggregation::arch()` overlay (from
/// midfall/aggregation/examples/single_circuit_aggregation.rs:201)
/// sets `nr_pow2range_cols = 4`.
fn ivc_arch() -> ZkStdLibArch {
    ZkStdLibArch {
        poseidon: true,
        bls12_381: true,
        nr_pow2range_cols: 4,
        ..ZkStdLibArch::default()
    }
}

#[test]
#[ignore = "metadata probe; run with --ignored --nocapture for go/no-go decision"]
fn ivc_size_probe_at_k19() {
    const IVC_K: u32 = 19;

    // Configure the IVC circuit's constraint system the same way
    // `ivc::setup` does (minus the synthesis pass, which we don't
    // need for metadata).
    let mut cs: ConstraintSystem<F> = ConstraintSystem::default();
    ZkStdLib::configure(&mut cs, (ivc_arch(), (IVC_K - 1) as u8));

    // ------------------------------------------------------------
    // Pull every cs metric the Solidity codegen consumes.
    // ------------------------------------------------------------
    let num_advice = cs.num_advice_columns();
    let num_fixed = cs.num_fixed_columns();
    let num_instance = cs.num_instance_columns();
    let num_selectors = cs.num_selectors();
    let cs_degree = cs.degree();
    let num_quotients = cs_degree - 1;

    let num_lookups = cs.lookups().len();
    let lookup_chunks: Vec<usize> = cs
        .lookups()
        .iter()
        .map(|l| l.chunk_by_degree(cs_degree).num_chunks())
        .collect();
    let lookup_helper_total: usize = lookup_chunks.iter().sum();
    let num_trashcans = cs.trashcans().len();

    let num_perm_columns = cs.permutation().columns.len();
    let num_perm_zs = if num_perm_columns == 0 {
        0
    } else {
        cs.permutation()
            .columns
            .chunks(cs_degree - 2)
            .count()
    };
    let perm_set_evals = if num_perm_zs == 0 {
        0
    } else {
        3 * num_perm_zs - 1
    };

    let advice_queries = cs.advice_queries().len();
    let fixed_queries = cs.fixed_queries().len();
    let instance_queries = cs.instance_queries().len();
    let num_simple_selectors = cs.num_simple_selectors();
    let num_fixed_non_simple = num_fixed - num_simple_selectors;

    // num_committed_instances drives the committed-instance eval slot
    // count in num_evals; ZkStdLib's prover always passes
    // NB_COMMITTED_INSTANCES = 1 (matches the IVC IvcInstance layout
    // since the vk_repr field is committed-style).
    let num_committed_instances = 1usize;
    let num_committed_instance_evals = cs
        .instance_queries()
        .iter()
        .filter(|(col, _)| col.index() < num_committed_instances)
        .count();

    // num_evals = committed_instance + advice + fixed_non_simple +
    //             permutation_columns + perm_set_evals +
    //             per_lookup(1 + chunks + 1 + 1) + trashcans
    let lookup_eval_count: usize = cs
        .lookups()
        .iter()
        .map(|l| 1 + l.chunk_by_degree(cs_degree).num_chunks() + 1 + 1)
        .sum();
    let num_evals = num_committed_instance_evals
        + advice_queries
        + num_fixed_non_simple
        + num_perm_columns
        + perm_set_evals
        + lookup_eval_count
        + num_trashcans;

    // ------------------------------------------------------------
    // G1 commitment counts in the proof byte stream.
    // ------------------------------------------------------------
    // (mirrors the prefix walk in tests/poseidon_fixture.rs:226-272)
    let advice_phase = cs.advice_column_phase();
    let max_phase = *advice_phase.iter().max().unwrap_or(&0);
    let mut prefix_g1: usize = 0;
    let mut g1_groups: Vec<(&'static str, usize)> = Vec::new();
    for phase in 0..=max_phase {
        let n = advice_phase.iter().filter(|p| **p == phase).count();
        if n > 0 {
            g1_groups.push(("advice", n));
            prefix_g1 += n;
        }
    }
    if num_lookups > 0 {
        g1_groups.push(("lookup_m", num_lookups));
        prefix_g1 += num_lookups;
        g1_groups.push(("lookup_helpers_total", lookup_helper_total));
        prefix_g1 += lookup_helper_total;
        g1_groups.push(("lookup_z", num_lookups));
        prefix_g1 += num_lookups;
    }
    if num_perm_zs > 0 {
        g1_groups.push(("perm_z", num_perm_zs));
        prefix_g1 += num_perm_zs;
    }
    if num_trashcans > 0 {
        g1_groups.push(("trashcan", num_trashcans));
        prefix_g1 += num_trashcans;
    }
    g1_groups.push(("quotient_limbs", num_quotients));
    prefix_g1 += num_quotients;

    // After the prefix G1s come num_evals scalars, then f_com (1 G1),
    // then num_point_sets q_evals, then pi (1 G1).
    let trailing_g1: usize = 2; // f_com + pi
    let total_g1_in_proof = prefix_g1 + trailing_g1;

    // num_point_sets is the post-merge distinct-point-set count from
    // `construct_intermediate_sets`. For a CS with this query
    // distribution, an upper bound is the count of distinct rotations
    // across all queries. The actual figure depends on
    // (a) the construct_intermediate_sets clustering algorithm and
    // (b) whether `fewer-point-sets` is enabled (which appends dummy
    // queries to merge sets).
    //
    // We approximate using the distinct-rotations upper bound.
    let rotation_last = -((cs.blinding_factors() as i32) + 1);
    let mut rotations: std::collections::HashSet<i32> = std::collections::HashSet::new();
    for q in cs.advice_queries().iter() {
        rotations.insert(q.1.0);
    }
    for q in cs.fixed_queries().iter() {
        rotations.insert(q.1.0);
    }
    for q in cs.instance_queries().iter() {
        if q.0.index() < num_committed_instances {
            rotations.insert(q.1.0);
        }
    }
    if num_perm_zs > 0 {
        rotations.insert(0);
        rotations.insert(1);
    }
    if num_perm_zs > 1 {
        rotations.insert(rotation_last);
    }
    if num_lookups > 0 {
        rotations.insert(0);
        rotations.insert(1);
    }
    if num_trashcans > 0 {
        rotations.insert(0);
    }
    let num_distinct_rotations_upper_bound = rotations.len();

    // ------------------------------------------------------------
    // Proof byte size estimates.
    // ------------------------------------------------------------
    // Compressed proof (zcash-encoded G1): 48 bytes per G1.
    let compressed_proof_bytes_min =
        prefix_g1 * 48 + num_evals * 32 + 48 /*f_com*/ + 1 * 32 /*one q_eval at minimum*/ + 48 /*pi*/;
    // The actual is + (num_point_sets - 1) * 32 if num_point_sets > 1.
    let compressed_proof_bytes_max =
        prefix_g1 * 48 + num_evals * 32 + 48 + num_distinct_rotations_upper_bound * 32 + 48;

    // Repacked (EIP-2537 padded) proof: 128 bytes per G1.
    let repacked_proof_bytes_min =
        prefix_g1 * 128 + num_evals * 32 + 128 + 1 * 32 + 128;
    let repacked_proof_bytes_max =
        prefix_g1 * 128 + num_evals * 32 + 128 + num_distinct_rotations_upper_bound * 32 + 128;

    // ------------------------------------------------------------
    // Solidity bytecode and gas heuristics.
    // ------------------------------------------------------------
    //
    // EVM contract code-size hard cap = 24576 bytes (EIP-170).
    //
    // Comparable Poseidon-fixture numbers (from current main):
    //   k=6, advice=4, fixed=10, lookups=0, num_evals=48,
    //     prefix_g1=19, num_point_sets=3, num_quotients=4
    //   verifier.sol = 106 936 bytes (rendered Solidity, NOT compiled),
    //   compiled bytecode ~= 18-20 KB after solc with optimizer-runs=200.
    //   on-chain verify gas = 760 564 (k=6, post H1+H2+H3+cp13).
    //
    // The verifier bytecode scales roughly with:
    //   - num_advices * 0.45 KB    (advice transcript + reading)
    //   - num_lookups * 0.6 KB     (logup logic + helpers)
    //   - num_quotients * 0.3 KB   (quotient-limb fold)
    //   - num_evals * 0.04 KB      (eval transcript + REVERSED_EVALS)
    //   - num_perm_zs * 0.3 KB     (permutation Z folding)
    //   - constant overhead ~8 KB  (ec_pairing, transcript helpers, etc.)
    //
    // Coefficients calibrated against the Poseidon k=6 fixture's REAL
    // solc --via-ir runtime bytecode = 13 792 bytes (13.8 KB) at
    // num_advice=6, num_lookups=0, num_quotients=4, num_evals=48,
    // num_perm_zs=1: heuristic = 8 + 2.7 + 0 + 1.2 + 1.92 + 0.3 = 14.1 KB
    // (within ~2 % of measured).
    //
    // gas scales with:
    //   - num_advices * 1-2 kg (advice transcript common_uncompressed_g1)
    //   - num_lookups * 3-5 kg (lookup product + logup helpers)
    //   - num_quotients * 0.2 kg (quotient_eval Horner)
    //   - num_evals * ~10 gas (REVERSED_EVALS pre-reversal loop) - tiny
    //   - 1 G1MSM(33+m) precompile per set = up to ~200 kg (set 0)
    //   - 1 BLS12_PAIRING = ~103 kg (final pairing)
    //   - tx base + calldata = ~85 kg
    let est_bytecode_kb = 8.0
        + (num_advice as f64) * 0.45
        + (num_lookups as f64) * 0.6
        + (num_quotients as f64) * 0.3
        + (num_evals as f64) * 0.04
        + (num_perm_zs as f64) * 0.3;
    let est_gas_kg = 200.0  // PCS set 0 G1MSM (assumes m ~ prefix_g1)
        + 100.0  // pairing
        + 85.0   // tx + calldata
        + (num_advice as f64) * 1.5
        + (num_lookups as f64) * 4.0
        + (num_quotients as f64) * 0.2
        + (num_evals as f64) * 0.01;

    // ------------------------------------------------------------
    // Report
    // ------------------------------------------------------------
    println!();
    println!("=== IVC size probe (k = {IVC_K}, ProofAggregation transition, no SRS) ===");
    println!();
    println!("CONSTRAINT SYSTEM TOPOLOGY");
    println!("  cs_degree                     = {cs_degree}");
    println!("  num_quotients (cs.degree-1)   = {num_quotients}");
    println!("  num_advice_columns            = {num_advice}");
    println!("  num_fixed_columns             = {num_fixed}");
    println!("  num_simple_selectors          = {num_simple_selectors}");
    println!("  num_fixed_non_simple          = {num_fixed_non_simple}");
    println!("  num_selectors                 = {num_selectors}");
    println!("  num_instance_columns          = {num_instance}");
    println!("  num_lookups                   = {num_lookups}");
    println!("  lookup_chunks (per lookup)    = {lookup_chunks:?}");
    println!("  lookup_helper_total           = {lookup_helper_total}");
    println!("  num_trashcans                 = {num_trashcans}");
    println!("  num_permutation_columns       = {num_perm_columns}");
    println!("  num_permutation_zs            = {num_perm_zs}");
    println!("  perm_set_evals                = {perm_set_evals}");
    println!();
    println!("QUERY COUNTS");
    println!("  advice_queries                = {advice_queries}");
    println!("  fixed_queries                 = {fixed_queries}");
    println!("  instance_queries              = {instance_queries}");
    println!("  num_committed_instance_evals  = {num_committed_instance_evals}");
    println!("  distinct_rotations (upper)    = {num_distinct_rotations_upper_bound}");
    println!();
    println!("EVAL & G1 COUNTS");
    println!("  num_evals (proof scalars)     = {num_evals}");
    for (label, n) in &g1_groups {
        println!("    {label:25} = {n}");
    }
    println!("  prefix_g1 (sum)               = {prefix_g1}");
    println!("  trailing_g1 (f_com + pi)      = {trailing_g1}");
    println!("  total_g1_in_proof             = {total_g1_in_proof}");
    println!();
    println!("PROOF SIZE ESTIMATES");
    println!(
        "  compressed proof (1 set)      = {compressed_proof_bytes_min} bytes (~{:.1} KB)",
        compressed_proof_bytes_min as f64 / 1024.0
    );
    println!(
        "  compressed proof ({} sets)    = {compressed_proof_bytes_max} bytes (~{:.1} KB)",
        num_distinct_rotations_upper_bound,
        compressed_proof_bytes_max as f64 / 1024.0
    );
    println!(
        "  repacked  proof (1 set)       = {repacked_proof_bytes_min} bytes (~{:.1} KB)",
        repacked_proof_bytes_min as f64 / 1024.0
    );
    println!(
        "  repacked  proof ({} sets)     = {repacked_proof_bytes_max} bytes (~{:.1} KB)",
        num_distinct_rotations_upper_bound,
        repacked_proof_bytes_max as f64 / 1024.0
    );
    println!();
    println!("VERIFIER COST HEURISTICS");
    println!("  estimated bytecode size       = ~{est_bytecode_kb:.1} KB");
    println!("    Poseidon k=6 real bytecode  = 13.8 KB (calibration anchor)");
    println!("    EIP-170 contract limit      = 24.0 KB");
    println!(
        "    headroom                    = {:.1} KB",
        24.0 - est_bytecode_kb
    );
    println!("  estimated verify gas          = ~{est_gas_kg:.0} kg");
    println!("    L1 reasonable budget        = 5000 kg");
    println!();
    println!("GO / NO-GO GATES");
    let bytecode_ok = est_bytecode_kb < 24.0;
    let gas_ok = est_gas_kg < 5000.0;
    println!(
        "  bytecode <  24 KB ?           = {} (est {:.1} KB)",
        if bytecode_ok { "OK" } else { "FAIL" },
        est_bytecode_kb
    );
    println!(
        "  verify gas < 5000 kg ?        = {} (est {:.0} kg)",
        if gas_ok { "OK" } else { "FAIL" },
        est_gas_kg
    );
    println!();

    if !bytecode_ok || !gas_ok {
        println!("VERDICT: Probe FAILED at least one gate. The full implementation");
        println!("         plan (Phases 2-4) should NOT proceed without revisiting");
        println!("         either the codegen tightening or splitting the verifier.");
    } else {
        println!("VERDICT: Probe PASSED both gates. Proceed with Phase 2 (aggregation");
        println!("         crate Keccak final mode) and Phase 3 (codegen support).");
        println!("         Re-run an SRS-backed probe later to confirm rendered");
        println!("         contract size after solc compilation.");
    }
    println!();
}
