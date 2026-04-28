//! Step 8 end-to-end smoke test for the midnight-proofs Solidity
//! verifier on BLS12-381 / EIP-2537.
//!
//! The test rebuilds the same circuit the midfall poseidon fixture
//! (`midfall/proofs/solidity-verifier/fixtures/poseidon/`) was generated
//! from - `ZkStdLib`-backed `PoseidonExample` at `k = 6` - generates a
//! fresh proof against the local Filecoin SRS, renders the
//! `Halo2Verifier.sol` + `Halo2VerifyingKey.sol` pair through
//! `SolidityGenerator::render_separately`, compiles them with `solc`,
//! deploys both to a Prague-spec revm (so EIP-2537 BLS12-381
//! precompiles `0x0b` / `0x0c` / `0x0f` are routed to revm's bundled
//! implementations), encodes the calldata via `encode_calldata_bls_padded`
//! and finally calls `verifyProof`. Pass condition is `output ==
//! 0x...01` (the verifier accepted the proof) AND a successful native
//! `midnight_zk_stdlib::verify` against the same proof.
//!
//! Gated behind `feature = "evm"`. Skipped automatically when the host
//! lacks the local SRS / `solc` binary; otherwise it asserts both the
//! Yul renders cleanly and the Prague-spec EVM accepts the proof.
//!
//! NOTE: this test depends on `midnight-zk-stdlib` + `midnight-circuits`
//! (path deps under `../midfall/`) which carry the full poseidon chip
//! configuration. The crate's `Cargo.toml` `[patch.crates-io]` block
//! redirects every `midnight-*` reference to the local midfall checkout
//! so cargo resolves a single canonical crate copy across the whole
//! dep graph.

#![cfg(feature = "evm")]

use std::env;
use std::path::Path;

use ff::Field;
use midnight_circuits::{
    hash::poseidon::PoseidonChip,
    instructions::{hash::HashCPU, AssignmentInstructions, PublicInputInstructions},
};
use midnight_curves::Fq;
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::{utils::plonk_api::srs_for_test, Relation, ZkStdLib, ZkStdLibArch};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha3::Keccak256;

use halo2_solidity_verifier::{
    compile_solidity, encode_calldata_bls_padded, BatchOpenScheme::Gwc19, Evm, SolidityGenerator,
};

type F = Fq;

#[derive(Clone, Default)]
struct PoseidonExample;

impl Relation for PoseidonExample {
    type Instance = F;

    type Witness = [F; 3];

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(vec![*instance])
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let assigned_message = std_lib.assign_many(layouter, &witness.transpose_array())?;
        let output = std_lib.poseidon(layouter, &assigned_message)?;
        std_lib.constrain_as_public_input(layouter, &output)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            poseidon: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(PoseidonExample)
    }
}

fn srs_dir() -> String {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../midfall/zk_stdlib/examples/assets"
    )
    .to_string()
}

/// Step 8 end-to-end smoke. Marked `#[ignore]` because it depends on
/// the local midfall checkout, Filecoin SRS asset, solc, and Prague
/// EIP-2537 precompile support. Run explicitly via
///   cargo test --features evm --test poseidon_fixture -- --ignored --nocapture
/// Enable Solidity trace logs with:
///   cargo test --features evm,solidity-trace --test poseidon_fixture -- --ignored --nocapture
#[test]
#[ignore = "requires local midfall assets and Prague EIP-2537 precompiles"]
fn poseidon_renders_compiles_and_verifies() {
    const K: u32 = 6;

    // The Filecoin SRS file is loaded by `srs_for_test` via the
    // `SRS_DIR` env var. Skip the test cleanly if the asset is
    // unavailable on the host (e.g. fresh checkout where the SRS
    // hasn't been downloaded yet).
    let srs_dir = srs_dir();
    let srs_path = format!("{srs_dir}/bls_filecoin_2p{K}");
    if !Path::new(&srs_path).exists() {
        eprintln!(
            "skipping poseidon end-to-end smoke: SRS not found at {srs_path}. \
             Set SRS_DIR or fetch the asset under midfall/zk_stdlib."
        );
        return;
    }
    env::set_var("SRS_DIR", &srs_dir);

    let relation = PoseidonExample;
    let srs = srs_for_test(&relation, Some(K));
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let witness: [F; 3] = core::array::from_fn(|_| F::random(&mut rng));
    let instance = <PoseidonChip<F> as HashCPU<F, F>>::hash(&witness);

    let prover_rng = ChaCha8Rng::seed_from_u64(0xdebd);
    let proof = midnight_zk_stdlib::prove::<PoseidonExample, Keccak256>(
        &srs, &pk, &relation, &instance, witness, prover_rng,
    )
    .expect("Proof generation should not fail");

    // Sanity-check via the native verifier first. If this fails, the
    // proof itself is broken so any Solidity-side mismatch downstream
    // is meaningless.
    midnight_zk_stdlib::verify::<PoseidonExample, Keccak256>(
        &srs.verifier_params(),
        &vk,
        &instance,
        None,
        &proof,
    )
    .expect("native verify should accept the proof");

    // Render Halo2Verifier.sol + Halo2VerifyingKey.sol against the
    // same VK. ZkStdLib creates two instance columns (one committed,
    // one non-committed); set num_committed_instances accordingly.
    let num_instances = 1;
    let generator =
        SolidityGenerator::new(&srs, vk.vk(), Gwc19, num_instances).set_num_committed_instances(1);
    let trace_solidity = halo2_solidity_verifier::SOLIDITY_TRACE_ENABLED;
    let gas_checkpoints_enabled = halo2_solidity_verifier::SOLIDITY_GAS_CHECKPOINTS_ENABLED;
    let (verifier_solidity, vk_solidity) = generator
        .render_separately()
        .expect("render_separately should succeed");

    // Persist for post-mortem inspection.
    let dump_dir = format!(
        "{}/target/poseidon-fixture-dump",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::create_dir_all(&dump_dir).ok();
    std::fs::write(format!("{dump_dir}/Halo2Verifier.sol"), &verifier_solidity).ok();
    std::fs::write(format!("{dump_dir}/Halo2VerifyingKey.sol"), &vk_solidity).ok();
    std::fs::write(format!("{dump_dir}/proof.bin"), &proof).ok();
    std::fs::write(
        format!("{dump_dir}/instance.be"),
        &<F as ff::PrimeField>::to_repr(&instance).as_ref(),
    )
    .ok();
    eprintln!(
        "[poseidon_fixture] proof = {} bytes, vk_solidity = {} bytes, verifier_solidity = {} bytes; \
         dumps under {dump_dir}",
        proof.len(),
        vk_solidity.len(),
        verifier_solidity.len()
    );

    // Skip the EVM portion if `solc` is not on PATH.
    if std::process::Command::new("solc")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipping poseidon end-to-end smoke: solc not found");
        return;
    }

    let vk_creation_code = compile_solidity(&vk_solidity);
    let verifier_creation_code = compile_solidity(&verifier_solidity);

    // Deploy on Prague-spec revm (EIP-2537 routed via blst).
    let mut evm = Evm::default();
    let vk_address = evm.create(vk_creation_code);
    let verifier_address = evm.create_with_address_arg(verifier_creation_code, vk_address);

    // Re-pack the prover's 48-byte compressed G1 commitments into the
    // 128-byte EIP-2537 form expected by the generated Solidity.
    let repacked = generator.repack_compressed_proof(&proof);

    let calldata = encode_calldata_bls_padded(&generator, &repacked, &[instance]);
    std::fs::write(format!("{dump_dir}/calldata.bin"), &calldata).ok();
    eprintln!(
        "[poseidon_fixture] calldata = {} bytes (compressed_proof={}, repacked={}, instances={})",
        calldata.len(),
        proof.len(),
        repacked.len(),
        1
    );

    use halo2_solidity_verifier::CallOutcome;
    match evm.try_call_with_gas(verifier_address, calldata, 5_000_000_000) {
        CallOutcome::Success {
            logs,
            gas_used,
            output,
        } => {
            if trace_solidity {
                dump_trace_logs(&logs);
            }
            if gas_checkpoints_enabled {
                dump_gas_checkpoints(&logs, gas_used);
            }
            let expected: Vec<u8> = [vec![0u8; 31], vec![1]].concat();
            assert_eq!(
                output,
                expected,
                "verifier should accept the proof; gas_used = {gas_used}, output = 0x{}",
                hex::encode(&output)
            );
            println!("Poseidon proof verified on-chain in {gas_used} gas");
        }
        CallOutcome::Revert { gas_used, output } => {
            panic!(
                "verifier reverted with gas_used = {gas_used}, output = 0x{}",
                hex::encode(&output)
            );
        }
        CallOutcome::Halt { gas_used, reason } => {
            panic!("verifier halted with gas_used = {gas_used}, reason = {reason}");
        }
    }
}

fn dump_trace_logs(logs: &[halo2_solidity_verifier::revm::primitives::Log]) {
    for log in logs {
        let topic = log.data.topics()[0];
        let id = u64::from_be_bytes(topic.as_slice()[24..32].try_into().unwrap());
        let data = log.data.data.as_ref();
        let name = match id {
            1 => "vk_digest",
            2 => "num_instances",
            3 => "k",
            4 => "n_inv",
            5 => "omega",
            6 => "omega_inv",
            7 => "theta",
            8 => "beta",
            9 => "gamma",
            10 => "y",
            11 => "x",
            13 => "x1",
            14 => "x2",
            15 => "x3",
            16 => "x4",
            17 => "x_n",
            18 => "x_n_minus_1_inv",
            19 => "l_last",
            20 => "l_blind",
            21 => "l_0",
            22 => "instance_eval",
            23 => "quotient_eval",
            24 => "quotient",
            25 => "f_com",
            26 => "pi",
            27 => "pairing_lhs",
            28 => "pairing_rhs",
            29 => "acc_lhs",
            30 => "acc_rhs",
            31 => "f_eval",
            32 => "v",
            33 => "final_com",
            _ => "unknown",
        };
        if matches!(id, 24..=30 | 33) {
            eprintln!("[yul-trace] {name}");
            for (slot, word) in ["x_hi", "x_lo", "y_hi", "y_lo"]
                .iter()
                .zip(data.chunks_exact(32))
            {
                eprintln!("[yul-trace]   {slot} = 0x{}", hex::encode(word));
            }
        } else {
            eprintln!("[yul-trace] {name}[{id}] = 0x{}", hex::encode(&data[0..32]));
        }
    }
}

/// Parse LOG1 events emitted by the rendered verifier when compiled
/// with `--features solidity-gas-checkpoints` and print a per-section
/// gas-delta breakdown.
///
/// Topic format: `(id << 248) | gas()`. `id` lives in the upper 8
/// bits and the remaining 248 bits hold `gas()`. We discard topics
/// where the upper byte is outside `1..=31` because the trace helpers
/// (`trace_u256` / `trace_point`) emit unrelated LOG1 events with
/// small `id` topics that may collide; here we filter to our own
/// checkpoint range. The poseidon fixture is built without the
/// `solidity-trace` feature in CI, so in practice the only LOG1
/// events are ours.
///
/// IDs 1..=16 are the top-level section boundaries (entry, VK,
/// transcript stages, quotient, linearization, PCS, accumulator,
/// pairing). IDs 17.. sit *inside* the PCS computation block (one
/// emitted between every pair of `pcs_computations` sub-blocks; the
/// last sub-block ends at cp14) and let us attribute the 514-kg PCS
/// bucket to each emitter sub-block. The exact mapping of id->block
/// depends on the circuit layout (one emitter block per (block 1,
/// block 2, *each* set in block 3, block 4, block 5, block 6) — for
/// the Poseidon fixture with 3 point sets that's 8 emitter blocks
/// and 7 mid-PCS checkpoints (cp17..=cp23) so this dumper allocates
/// space up to id=31 to leave headroom for larger circuits.
fn dump_gas_checkpoints(logs: &[halo2_solidity_verifier::revm::primitives::Log], gas_used: u64) {
    fn name_of(id: u8) -> &'static str {
        match id {
            1 => "entry (before VK loading)",
            2 => "VK loading",
            3 => "VK digest + committed_pi + instance absorbs",
            4 => "user-phase advice reads + user challenge squeezes",
            5 => "theta squeeze + lookup multiplicities",
            6 => "beta/gamma + permutation Z products",
            7 => "lookup helpers + Z accumulators",
            8 => "trash_challenge + trashcans",
            9 => "y squeeze + quotient-limb reads",
            10 => "evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi",
            11 => "Lagrange + instance evaluation",
            12 => "quotient evaluation (Fr arithmetic)",
            13 => "linearization-commitment MSM",
            14 => "PCS block 6 (pairing inputs LHS/RHS)",
            15 => "accumulator random-combine",
            16 => "final ec_pairing",
            // Poseidon-specific PCS sub-block layout (3 point sets):
            //   set 0: m=33 commits, 1 rotation
            //   set 1: m=5  commits, 2 rotations
            //   set 2: m=2  commits, 3 rotations
            17 => "PCS block 1 (rotation points x*omega^rot)",
            18 => "PCS block 2 (x1 powers)",
            19 => "PCS block 3 set 0 q_com fold (m=33 MSM, 1 rot)",
            20 => "PCS block 3 set 1 q_com fold (m=5 MSM, 2 rots)",
            21 => "PCS block 3 set 2 q_com fold (m=2 MSM, 3 rots)",
            22 => "PCS block 4 (f_eval Lagrange interpolation)",
            23 => "PCS block 5 (final_com x4-power MSM + v)",
            _ => "<unknown>",
        }
    }

    let mut events: Vec<(u8, u64)> = logs
        .iter()
        .filter_map(|log| {
            let topic = log.data.topics().first()?;
            let bytes = topic.as_slice();
            // Upper byte = checkpoint id; lower 31 bytes = gas() (only
            // the lowest 8 are non-zero in practice for gas values
            // < 2^64). We read the lowest 8 bytes as u64.
            let id = bytes[0];
            if !(1..=31).contains(&id) {
                return None;
            }
            let gas = u64::from_be_bytes(bytes[24..32].try_into().ok()?);
            Some((id, gas))
        })
        .collect();
    // Sort by execution order: gas_left is monotonically decreasing,
    // so descending-gas == earliest-emitted-first. This is more
    // robust than sort-by-id because the PCS sub-block ids
    // (17..=21) are emitted *between* cp13 and cp14.
    events.sort_by(|a, b| b.1.cmp(&a.1));

    if events.is_empty() {
        eprintln!(
            "[gas-checkpoints] no checkpoint events found in {} LOG entries",
            logs.len()
        );
        return;
    }

    eprintln!();
    eprintln!("=== gas-checkpoint breakdown (per-section deltas) ===");
    eprintln!(
        "{:>4}  {:>14}  {:>12}  {:>7}  section",
        "id", "gas_left", "delta", "%"
    );

    // Each checkpoint costs ~750 gas (LOG1 base 375 + 1 topic 375 +
    // 0 data bytes). Subtract that from each delta so the printed
    // numbers reflect "real" section work, not measurement overhead.
    const CHECKPOINT_COST: u64 = 750;

    let total_billed = (events[events.len() - 1].1 < events[0].1)
        .then(|| events[0].1.saturating_sub(events[events.len() - 1].1))
        .unwrap_or(0);
    let total_real_work = total_billed.saturating_sub(events.len() as u64 * CHECKPOINT_COST);

    let mut prev_gas = events[0].1;
    let cp1_gas = events[0].1;
    eprintln!(
        "{:>4}  {:>14}  {:>12}  {:>7}  {}",
        events[0].0,
        format_u64(prev_gas),
        "-",
        "-",
        name_of(events[0].0),
    );

    for (id, gas) in events.iter().skip(1) {
        let raw_delta = prev_gas.saturating_sub(*gas);
        let net_delta = raw_delta.saturating_sub(CHECKPOINT_COST);
        let pct = if total_real_work > 0 {
            (net_delta as f64 / total_real_work as f64) * 100.0
        } else {
            0.0
        };
        eprintln!(
            "{:>4}  {:>14}  {:>12}  {:>6.1}%  {}",
            id,
            format_u64(*gas),
            format_u64(net_delta),
            pct,
            name_of(*id),
        );
        prev_gas = *gas;
    }

    eprintln!();
    eprintln!(
        "  cp1 gas_left            = {} (verifier entry)",
        format_u64(cp1_gas)
    );
    eprintln!(
        "  cp16..cp1 gas billed    = {} (work between cp1 and cp16)",
        format_u64(total_billed)
    );
    eprintln!(
        "  - measurement overhead  = {} ({} checkpoints x {} gas)",
        format_u64(events.len() as u64 * CHECKPOINT_COST),
        events.len(),
        CHECKPOINT_COST
    );
    eprintln!(
        "  = real section work     = {}",
        format_u64(total_real_work)
    );
    eprintln!(
        "  total tx gas_used       = {} (incl. tx base + calldata + pre-cp1 + post-cp16)",
        format_u64(gas_used)
    );
}

fn format_u64(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}
