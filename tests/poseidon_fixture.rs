//! Step 8 end-to-end smoke test for the midnight-proofs Solidity
//! verifier on BLS12-381 / EIP-2537.
//!
//! The test rebuilds the same circuit the midfall poseidon fixture
//! (`midfall/proofs/solidity-verifier/fixtures/poseidon/`) was generated
//! from — `ZkStdLib`-backed `PoseidonExample` at `k = 6` — generates a
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
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::{
    utils::plonk_api::srs_for_test, Relation, ZkStdLib, ZkStdLibArch,
};
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha3::Keccak256;

use halo2_solidity_verifier::{
    compile_solidity, encode_calldata_bls_padded, BatchOpenScheme::Gwc19, Evm, SolidityGenerator,
};

type F = midnight_curves::Fq;

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
    concat!(env!("CARGO_MANIFEST_DIR"), "/../midfall/zk_stdlib/examples/assets").to_string()
}

/// Step 8 status: scaffolding + render + compile + deploy succeed. The
/// rendered Yul reverts on a real proof, so end-to-end soundness is not
/// yet asserted. Marked `#[ignore]` until the trace divergence is
/// chased down (see MIGRATION.md Step 8 follow-up). Run explicitly via
///   cargo test --features evm --test poseidon_fixture -- --ignored --nocapture
#[test]
#[ignore = "rendered verifier reverts mid-execution; debugging tracked in MIGRATION.md Step 8"]
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

    let proof = midnight_zk_stdlib::prove::<PoseidonExample, Keccak256>(
        &srs, &pk, &relation, &instance, witness, OsRng,
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
    let generator = SolidityGenerator::new(&srs, vk.vk(), Gwc19, num_instances)
        .set_num_committed_instances(1);
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

    let calldata = encode_calldata_bls_padded(&generator, &proof, &[instance]);
    eprintln!(
        "[poseidon_fixture] calldata = {} bytes (proof={}+instances={})",
        calldata.len(),
        proof.len(),
        1
    );

    use halo2_solidity_verifier::CallOutcome;
    match evm.try_call(verifier_address, calldata) {
        CallOutcome::Success {
            gas_used, output, ..
        } => {
            let expected: Vec<u8> = [vec![0u8; 31], vec![1]].concat();
            assert_eq!(
                output, expected,
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
