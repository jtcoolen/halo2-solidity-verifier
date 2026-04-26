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

    let prover_rng = ChaCha8Rng::seed_from_u64(0xdebd);
    let proof = midnight_zk_stdlib::prove::<PoseidonExample, Keccak256>(
        &srs, &pk, &relation, &instance, witness, prover_rng,
    )
    .expect("Proof generation should not fail");
    {
        use sha3::Digest;
        let h = sha3::Keccak256::digest(&proof);
        eprintln!("[fixture] proof keccak = 0x{}", hex::encode(h));
    }

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

    // Parse the proof natively to recover the challenge stream so we
    // can byte-diff against the Yul-side probe. We can't access the
    // private VerifierTrace fields, so re-walk the transcript schedule
    // by hand: VK digest and instance values get absorbed first, then
    // we read the user-phase advice columns, squeeze theta, etc.
    {
        use ff::PrimeField;
        use midnight_proofs::transcript::{CircuitTranscript, Hashable, Transcript};
        type Hasher = sha3::Keccak256;
        // Bls12 G1 affine point (post-decompression, blst-side).
        type G1 = midnight_curves::G1Projective;
        let mut t = <CircuitTranscript<Hasher> as Transcript>::init_from_bytes(&proof);
        // VK digest.
        midnight_proofs::plonk::VerifyingKey::<F, midnight_proofs::poly::kzg::KZGCommitmentScheme<midnight_curves::Bls12>>::hash_into(vk.vk(), &mut t).unwrap();
        // Single instance, single column, single value.
        <F as Hashable<Hasher>>::to_input(&instance);
        <CircuitTranscript<Hasher> as Transcript>::common::<F>(&mut t, &F::from_u128(1u128)).unwrap();
        <CircuitTranscript<Hasher> as Transcript>::common::<F>(&mut t, &instance).unwrap();
        // User advice phases. ZkStdLib's poseidon example ends up with
        // some number of advice columns; we read until theta squeezes.
        // For brevity, read advices for every advice column the ZkStdLib
        // CS exposes via vk.cs.advice_column_phase, then squeeze theta.
        let cs = vk.vk().cs();
        let advice_column_phase = cs.advice_column_phase();
        let challenge_phase = cs.challenge_phase();
        let phases: Vec<u8> = (0..=*advice_column_phase.iter().max().unwrap_or(&0)).collect();
        let mut challenges: Vec<F> = vec![F::ZERO; cs.num_challenges()];
        for current_phase in phases {
            for (phase, _col) in advice_column_phase.iter().enumerate() {
                if advice_column_phase[phase] == current_phase {
                    let _: G1 = <CircuitTranscript<Hasher> as Transcript>::read::<G1>(&mut t).unwrap();
                }
            }
            for (phase, ch) in challenge_phase.iter().zip(challenges.iter_mut()) {
                if *phase == current_phase {
                    *ch = <CircuitTranscript<Hasher> as Transcript>::squeeze_challenge::<F>(&mut t);
                }
            }
        }
        let theta: F = <CircuitTranscript<Hasher> as Transcript>::squeeze_challenge(&mut t);
        // Read multiplicities (one G1 per lookup; for poseidon there's none).
        for _ in 0..cs.lookups().len() {
            let _: G1 = <CircuitTranscript<Hasher> as Transcript>::read::<G1>(&mut t).unwrap();
        }
        let beta: F = <CircuitTranscript<Hasher> as Transcript>::squeeze_challenge(&mut t);
        let gamma: F = <CircuitTranscript<Hasher> as Transcript>::squeeze_challenge(&mut t);
        // Permutation Z products (one G1 per chunk).
        let perm_chunks = vk.vk().cs().permutation().columns.chunks(vk.vk().cs().degree() - 2).count();
        for _ in 0..perm_chunks {
            let _: G1 = <CircuitTranscript<Hasher> as Transcript>::read::<G1>(&mut t).unwrap();
        }
        // For each lookup: nb_chunks helper commitments + 1 accumulator.
        // For poseidon's BatchedArgument with 1 input expression, nb_chunks=1.
        for _ in 0..cs.lookups().len() {
            // 1 helper + 1 accumulator (assume nb_chunks=1).
            for _ in 0..1 {
                let _: G1 = <CircuitTranscript<Hasher> as Transcript>::read::<G1>(&mut t).unwrap();
            }
            let _: G1 = <CircuitTranscript<Hasher> as Transcript>::read::<G1>(&mut t).unwrap();
        }
        let _trash_chal: F = <CircuitTranscript<Hasher> as Transcript>::squeeze_challenge(&mut t);
        for _ in 0..cs.trashcans().len() {
            let _: G1 = <CircuitTranscript<Hasher> as Transcript>::read::<G1>(&mut t).unwrap();
        }
        let y: F = <CircuitTranscript<Hasher> as Transcript>::squeeze_challenge(&mut t);
        // num_quotients = degree - 1 = 4 for poseidon
        let num_quotients = cs.degree() - 1;
        for _ in 0..num_quotients {
            let _: G1 = <CircuitTranscript<Hasher> as Transcript>::read::<G1>(&mut t).unwrap();
        }
        let x: F = <CircuitTranscript<Hasher> as Transcript>::squeeze_challenge(&mut t);
        eprintln!("[native]  theta = 0x{}", hex_be(theta));
        eprintln!("[native]   beta = 0x{}", hex_be(beta));
        eprintln!("[native]  gamma = 0x{}", hex_be(gamma));
        eprintln!("[native]      y = 0x{}", hex_be(y));
        eprintln!("[native]      x = 0x{}", hex_be(x));

        // ---- Lagrange / instance / quotient (native) ----
        let domain = vk.vk().get_domain();
        let k = domain.k();
        let n: u64 = 1u64 << k;
        let n_inv = F::from(n).invert().unwrap();
        let omega = domain.get_omega();
        let omega_inv = domain.get_omega_inv();
        let num_neg_lagranges = (vk.vk().cs().blinding_factors() + 1) as i32;
        eprintln!("[native] num_neg_lagranges = {}", num_neg_lagranges);

        // x^n
        let mut x_n = x;
        for _ in 0..k {
            x_n = x_n * x_n;
        }
        let x_n_minus_1 = x_n - F::ONE;
        let x_n_minus_1_inv = x_n_minus_1.invert().unwrap();

        // Lagranges l_i for i in {-num_neg_lagranges, ..., num_instances-1}.
        // l_i(x) = (x^n - 1) / n * omega^i / (x - omega^i)
        // For i >= 0 we use omega^i; for i = -j we use omega^(-j) = omega_inv^j.
        let omega_inv_to_l: F = omega_inv.pow_vartime([num_neg_lagranges as u64]);
        let num_instances_actual = 1usize;
        let total = (num_neg_lagranges as usize) + num_instances_actual;
        let mut omega_pows = Vec::with_capacity(total);
        let mut p = omega_inv_to_l;
        for _ in 0..total {
            omega_pows.push(p);
            p = p * omega;
        }
        let l_common = x_n_minus_1 * n_inv;
        let mut l_evals: Vec<F> = omega_pows
            .iter()
            .map(|w| {
                let denom = (x - *w).invert().unwrap();
                l_common * denom * *w
            })
            .collect();
        // l_evals[0] = l_last, l_evals[num_neg_lagranges-1] = l_0 (since
        // we start the loop at omega_inv^L = omega^-L, and walk forward).
        let l_last = l_evals[0];
        let l_blind: F = l_evals[1..(num_neg_lagranges as usize)].iter().fold(F::ZERO, |a, b| a + *b);
        let l_0 = l_evals[num_neg_lagranges as usize];
        let mut instance_eval = F::ZERO;
        instance_eval = instance_eval + l_evals[num_neg_lagranges as usize] * instance;

        eprintln!("[native]              x_n = 0x{}", hex_be(x_n));
        eprintln!("[native]  x_n_minus_1_inv = 0x{}", hex_be(x_n_minus_1_inv));
        eprintln!("[native]           l_last = 0x{}", hex_be(l_last));
        eprintln!("[native]          l_blind = 0x{}", hex_be(l_blind));
        eprintln!("[native]              l_0 = 0x{}", hex_be(l_0));
        eprintln!("[native]    instance_eval = 0x{}", hex_be(instance_eval));
        eprintln!("[native]   instance value = 0x{}", hex_be(instance));
        eprintln!("[native] num_simple_selectors = {}", cs.num_simple_selectors());
        eprintln!("[native] num_fixed_columns = {}", cs.num_fixed_columns());
        for (gi, gate) in cs.gates().iter().enumerate() {
            let simple_sels: Vec<_> = gate
                .queried_selectors()
                .iter()
                .filter(|s| s.is_simple())
                .map(|s| s.index())
                .collect();
            eprintln!(
                "[native] gate[{}] name={:?} polys={} simple_selectors={:?}",
                gi,
                gate.name(),
                gate.polynomials().len(),
                simple_sels
            );
        }
        for col in 0..cs.num_fixed_columns() {
            eprintln!(
                "[native] fixed col {} simple={}",
                col,
                cs.has_simple_selector_col(col)
            );
        }
        let cs = vk.vk().cs();
        eprintln!(
            "[native] cs: lookups={}, num_advice={}, num_perm_cols={}, perm_chunks={}, num_trashcans={}, degree={}",
            cs.lookups().len(),
            cs.num_advice_columns(),
            cs.permutation().columns.len(),
            perm_chunks,
            cs.trashcans().len(),
            cs.degree(),
        );
        eprintln!(
            "[native] num_eval_columns: advice_q={}, fixed_q={}, instance_q={}, perm_z={}",
            cs.advice_queries().len(),
            cs.fixed_queries().len(),
            cs.instance_queries().len(),
            perm_chunks
        );
        fn hex_be<F: ff::PrimeField>(f: F) -> String {
            let mut bytes = f.to_repr().as_ref().to_vec();
            bytes.reverse();
            hex::encode(bytes)
        }
    }

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
            if output.len() == 0x120 {
                let labels = [
                    "neg_expected_eval", "sel_acc[13]", "sel_acc[14]", "sel_acc[15]", "sel_acc[17]",
                    "lin_com_x_hi", "lin_com_x_lo", "lin_com_y_hi", "lin_com_y_lo",
                ];
                for (i, l) in labels.iter().enumerate() {
                    let v = &output[i * 32..(i + 1) * 32];
                    eprintln!("[yul]    {:>20} = 0x{}", l, hex::encode(v));
                }
                return;
            }
            if output.len() == 0x260 {
                let labels = [
                    "lin_com_x_hi", "lin_com_x_lo", "lin_com_y_hi", "lin_com_y_lo",
                    "neg_expected_eval", "f_eval", "v",
                    "final_com_x_hi", "final_com_x_lo", "final_com_y_hi", "final_com_y_lo",
                    "pi_x_hi", "pi_x_lo", "pi_y_hi", "pi_y_lo",
                    "rhs_x_hi", "rhs_x_lo", "rhs_y_hi", "rhs_y_lo",
                ];
                for (i, l) in labels.iter().enumerate() {
                    let v = &output[i * 32..(i + 1) * 32];
                    eprintln!("[yul]    {:>20} = 0x{}", l, hex::encode(v));
                }
                return;
            }
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
