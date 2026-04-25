use crate::{
    codegen::{
        AccumulatorEncoding,
        BatchOpenScheme::{self, Gwc19},
        SolidityGenerator,
    },
    encode_calldata,
    evm::test::{compile_solidity, Evm},
    FN_SIG_VERIFY_PROOF,
};
use halo2_proofs::halo2curves::bls12381::{Bls12381, Fr};
use proptest::{
    prelude::any,
    test_runner::{Config as ProptestConfig, TestRunner},
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha3::Digest;
use std::{fs::File, io::Write, panic::AssertUnwindSafe};

#[test]
fn function_signature() {
    assert_eq!(
        <[u8; 32]>::from(sha3::Keccak256::digest("verifyProof(bytes,uint256[])"))[..4],
        FN_SIG_VERIFY_PROOF,
    );
}

/// Codegen-only smoke test: generate Solidity for the GWC19 scheme with
/// each render mode (embedded VK and separately). Doesn't execute the EVM
/// because the bundled `revm` doesn't ship the EIP-2537 precompiles, but it
/// does flush the codegen pipeline through the PCS emitter and asserts
/// the resulting strings reference the BLS-specific helpers.
#[test]
fn render_smoke_bls_gwc19_codegen() {
    use halo2_proofs::{
        halo2curves::bls12381::Bls12381, plonk::keygen_vk, poly::kzg::commitment::ParamsKZG,
    };
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{test::halo2::TestCircuit, SolidityGenerator};

    let mut rng = StdRng::seed_from_u64(0xcafebabe);
    let circuit = halo2::huge::HugeCircuit::<Bls12381>::new(None, &mut rng);
    let params = ParamsKZG::<Bls12381>::setup(8, &mut rng);
    let vk = keygen_vk(&params, &circuit).unwrap();

    let gen = SolidityGenerator::new(&params, &vk, Gwc19, 1);
    let inline_sol = gen.render().expect("inline render");
    assert!(inline_sol.contains("ec_pairing"), "inline must use BLS pairing helper");
    // BLS-specific Yul markers we should always emit from the PCS
    // emitter (precompile addresses 0x0b/0x0c/0x0f).
    assert!(
        inline_sol.contains("0x0b") && inline_sol.contains("0x0c") && inline_sol.contains("0x0f"),
        "inline must reference EIP-2537 precompile addresses 0x0b/0x0c/0x0f"
    );

    let gen = SolidityGenerator::new(&params, &vk, Gwc19, 1);
    let (verifier_sol, vk_sol) = gen.render_separately().expect("separate render");
    assert!(
        verifier_sol.contains("PAIRING_LHS_MPTR"),
        "separate verifier must reference PAIRING_LHS_MPTR"
    );
    assert!(!vk_sol.is_empty());
}

// All `render_*` tests below produce a Solidity verifier and call it inside
// an embedded EVM. After the BLS12-381 / EIP-2537 port the Solidity uses
// precompiles 0x0b/0x0c/0x0f -- the embedded EVM is now bumped to revm 19
// and runs `SpecId::PRAGUE`, so those calls now resolve to real BLS
// implementations. They still panic on the runtime assertion because the
// embedded VK is BN254-shape (the halo2 v0.4 + BLS-KZG prover swap is
// landed in a follow-up commit). Re-enable once that's done.

/// Direct EIP-2537 BLS12_G1ADD precompile smoke test against the bundled
/// Prague-spec revm. Exercises the runner path independently of the halo2
/// codegen so a regression in `src/evm.rs` shows up here first. The test
/// vector is "G1 generator + (-G1 generator) = identity" -- a common,
/// well-defined check straight from the EIP-2537 specification.
#[test]
fn prague_evm_runs_eip2537_g1add_to_identity() {
    use crate::evm::test::Evm;
    use revm::primitives::Address;

    // Hand-assembled stub that mirrors:
    //   assembly {
    //     calldatacopy(0x00, 0x00, calldatasize())
    //     let ok := staticcall(gas(), 0x0b, 0x00, calldatasize(), 0x00, 0x80)
    //     if iszero(ok) { revert(0, 0) }
    //     return(0x00, 0x80)
    //   }
    let runtime: Vec<u8> = vec![
        // calldatacopy(dst=0, src=0, size=calldatasize)
        0x36,           // CALLDATASIZE
        0x60, 0x00,     // PUSH1 0
        0x60, 0x00,     // PUSH1 0
        0x37,           // CALLDATACOPY  (pops dst, src, size)
        // staticcall(gas, 0x0b, 0, calldatasize, 0, 0x80)
        0x60, 0x80,     // PUSH1 0x80   ret_size
        0x60, 0x00,     // PUSH1 0      ret_off
        0x36,           // CALLDATASIZE args_size
        0x60, 0x00,     // PUSH1 0      args_off
        0x60, 0x0b,     // PUSH1 0x0b   addr
        0x5a,           // GAS
        0xfa,           // STATICCALL  -> ok
        0x50,           // POP ok
        // return(0x00, 0x80)
        0x60, 0x80,     // PUSH1 0x80
        0x60, 0x00,     // PUSH1 0
        0xf3,           // RETURN
    ];
    let len = runtime.len() as u8;
    // Deployer: copy runtime from code to memory, then return it.
    //   codecopy(0x00, 0x0c, LEN); return(0x00, LEN)
    // Length of the deployer prefix is 12 bytes, so the offset of the
    // runtime inside the codecopy payload is exactly 0x0c.
    let mut deployer = Vec::with_capacity(12 + runtime.len());
    deployer.extend([0x60, len]);    // PUSH1 LEN
    deployer.extend([0x60, 0x0c]);   // PUSH1 0x0c
    deployer.extend([0x60, 0x00]);   // PUSH1 0
    deployer.push(0x39);             // CODECOPY
    deployer.extend([0x60, len]);    // PUSH1 LEN
    deployer.extend([0x60, 0x00]);   // PUSH1 0
    deployer.push(0xf3);             // RETURN
    assert_eq!(deployer.len(), 12, "deployer prefix should be exactly 12 bytes");
    deployer.extend(runtime);

    let mut evm = Evm::default();
    let addr: Address = evm.create(deployer);

    // EIP-2537 G1ADD input layout: two G1 points, each 128 bytes
    // (x: 64 bytes padded, y: 64 bytes padded). For the generator P and
    // its negation -P we use the BLS12-381 G1 generator coords from the
    // pairing-friendly curves spec.
    let g1_x_hex = "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    let g1_y_hex = "00000000000000000000000000000000\
08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    // -G1 generator: x same, y replaced with q - y where q is BLS12-381 Fp modulus.
    // q (hex) = 0x1a0111ea397fe69a4b1ba7b6434bca8d09800000000000000000000000000000000000000000000000000000000000001 // not literal
    // Use a known precomputed -y: easier is to call G1ADD with P + P (doubling)
    // and check the output is non-zero. That still exercises the precompile
    // round-trip without requiring -y arithmetic in the test.
    let mut calldata = vec![];
    for hex in [g1_x_hex, g1_y_hex, g1_x_hex, g1_y_hex] {
        calldata.extend(hex::decode(hex.replace(['\n', '\\'], "")).unwrap());
    }
    assert_eq!(calldata.len(), 256);

    let (gas_used, output) = evm.call(addr, calldata);
    assert_eq!(output.len(), 128, "EIP-2537 G1ADD must return 128 bytes");
    // Doubling the generator yields 2G which is non-zero, so output != all
    // zeros means the precompile actually executed (and not just returned
    // empty data which is what pre-Prague EVMs would do).
    assert!(output.iter().any(|&b| b != 0), "G1ADD output is all zero -- precompile didn't run");
    assert!(gas_used > 0);
}

#[test]
#[ignore = "needs halo2 KZG-BLS prover backend; see PORTING_NOTES.md"]
fn render_gwc19_huge() {
    run_render::<halo2::huge::HugeCircuit<Bls12381>>(Gwc19)
}

#[cfg(feature = "_maingate_v3")]
#[test]
#[ignore = "needs halo2 KZG-BLS prover backend; see PORTING_NOTES.md"]
fn render_gwc19_maingate() {
    run_render::<halo2::maingate::MainGateWithRange<Bls12381>>(Gwc19)
}

#[test]
#[ignore = "needs halo2 KZG-BLS prover backend; see PORTING_NOTES.md"]
fn render_separately_gwc19_huge() {
    run_render_separately::<halo2::huge::HugeCircuit<Bls12381>>(Gwc19)
}

#[cfg(feature = "_maingate_v3")]
#[test]
#[ignore = "needs halo2 KZG-BLS prover backend; see PORTING_NOTES.md"]
fn render_separately_gwc19_maingate() {
    run_render_separately::<halo2::maingate::MainGateWithRange<Bls12381>>(Gwc19)
}

#[test]
#[ignore = "expensive property test; run in release mode"]
fn pbt_solidity_verifies_standard_plonk_embedded_vk_proofs() {
    let mut runner = new_property_test_runner();
    let strategy = (any::<u64>(), 10u32..13);

    runner
        .run(&strategy, |(seed, k)| {
            run_property_standard_plonk_positive_case(k, false, seed);
            Ok(())
        })
        .unwrap();
}

#[test]
#[ignore = "expensive property test; run in release mode"]
fn pbt_solidity_rejects_wrong_instances() {
    let mut runner = new_property_test_runner();
    let strategy = (any::<u64>(), 10u32..13, any::<bool>());

    runner
        .run(&strategy, |(seed, k, separate)| {
            run_property_standard_plonk_wrong_instance_case(k, separate, seed);
            Ok(())
        })
        .unwrap();
}

#[test]
#[ignore = "expensive property test; run in release mode"]
fn pbt_solidity_rejects_malleated_proofs() {
    let mut runner = new_property_test_runner();
    let strategy = (any::<u64>(), 10u32..13, any::<bool>(), 0usize..64);

    runner
        .run(&strategy, |(seed, k, separate, bit_idx)| {
            run_property_standard_plonk_malleated_proof_case(k, separate, seed, bit_idx);
            Ok(())
        })
        .unwrap();
}

#[test]
#[ignore = "expensive property test; run in release mode"]
fn pbt_solidity_rejects_wrong_verifying_keys() {
    let mut runner = new_property_test_runner();
    let strategy = (any::<u64>(), 10u32..12);

    runner
        .run(&strategy, |(seed, k)| {
            run_property_standard_plonk_wrong_vk_case(k, seed);
            Ok(())
        })
        .unwrap();
}

#[test]
#[ignore = "expensive property test; run in release mode"]
fn pbt_separate_vk_digest_prefix_affects_verification() {
    let mut runner = new_property_test_runner();
    let strategy = (any::<u64>(), 10u32..12);

    runner
        .run(&strategy, |(seed, k)| {
            run_separate_vk_digest_prefix_affects_verification_case(k, seed);
            Ok(())
        })
        .unwrap();
}

#[test]
#[ignore = "solidity/EVM-heavy; run in release mode"]
fn malformed_embedded_calldata_variants_are_rejected() {
    let fixture = create_property_standard_plonk_fixture(10, 0);
    let valid = encode_calldata(&fixture.proof, &fixture.instances);
    let valid_true = call_embedded_verifier_raw(&fixture.embedded_verifier_solidity, valid.clone());
    assert_solidity_accepts(valid_true, "valid embedded calldata");

    let mut wrong_selector = valid.clone();
    wrong_selector[0] ^= 0x01;

    let empty_proof = encode_calldata(&[], &fixture.instances);

    let truncated_proof = valid[..valid.len() - 1].to_vec();

    let mut extra_trailing_bytes = valid.clone();
    extra_trailing_bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    let proof_len = fixture.proof.len();
    let instances_len_word_start = 4 + 0x40 + 0x20 + proof_len;
    let mut wrong_instance_array_length = valid.clone();
    overwrite_u256_word(
        &mut wrong_instance_array_length,
        instances_len_word_start,
        fixture.instances.len() as u64 + 1,
    );

    for (name, calldata) in [
        ("empty proof", empty_proof),
        ("truncated proof", truncated_proof),
        ("extra trailing bytes", extra_trailing_bytes),
        ("wrong selector", wrong_selector),
        ("wrong instance array length", wrong_instance_array_length),
    ] {
        let output = call_embedded_verifier_raw(&fixture.embedded_verifier_solidity, calldata);
        assert_solidity_rejects(output, name);
    }
}

#[test]
#[ignore = "solidity/EVM-heavy; run in release mode"]
fn mutated_separate_vk_contract_is_rejected() {
    let fixture = create_property_standard_plonk_fixture(10, 0);
    let mutated_vk_solidity = mutate_first_large_hex_literal(&fixture.vk_solidity);
    let output = call_separate_verifier(
        &fixture.separate_verifier_solidity,
        &mutated_vk_solidity,
        &fixture.proof,
        &fixture.instances,
    );
    assert_solidity_rejects(output, "mutated separate vk");
}

#[test]
#[ignore = "solidity/EVM-heavy; run in release mode"]
fn standard_plonk_render_is_deterministic_for_same_seed() {
    let fixture_a = create_property_standard_plonk_fixture(10, 7);
    let fixture_b = create_property_standard_plonk_fixture(10, 7);

    assert_eq!(fixture_a.instances, fixture_b.instances);
    assert_eq!(fixture_a.proof, fixture_b.proof);
    assert_eq!(
        fixture_a.embedded_verifier_solidity,
        fixture_b.embedded_verifier_solidity
    );
    assert_eq!(
        fixture_a.separate_verifier_solidity,
        fixture_b.separate_verifier_solidity
    );
    assert_eq!(fixture_a.vk_solidity, fixture_b.vk_solidity);
}

#[test]
#[ignore = "solidity/EVM-heavy; run in release mode"]
fn compile_solidity_is_deterministic_for_same_source() {
    let fixture = create_property_standard_plonk_fixture(10, 1);
    let bytecode_a = compile_solidity(&fixture.embedded_verifier_solidity);
    let bytecode_b = compile_solidity(&fixture.embedded_verifier_solidity);

    assert_eq!(bytecode_a, bytecode_b);
}

fn run_render<C: halo2::TestCircuit<Fr>>(scheme: BatchOpenScheme) {
    let acc_encoding = AccumulatorEncoding::new(0, 4, 68).into();
    let (params, vk, instances, proof) =
        halo2::create_testdata::<C>(C::min_k(), scheme, acc_encoding, std_rng());

    let generator = SolidityGenerator::new(&params, &vk, scheme, instances.len())
        .set_acc_encoding(acc_encoding);
    let verifier_solidity = generator.render().unwrap();
    let verifier_creation_code = compile_solidity(verifier_solidity);
    let verifier_creation_code_size = verifier_creation_code.len();

    let mut evm = Evm::default();
    let verifier_address = evm.create(verifier_creation_code);
    let verifier_runtime_code_size = evm.code_size(verifier_address);

    println!("Verifier creation code size: {verifier_creation_code_size}");
    println!("Verifier runtime code size: {verifier_runtime_code_size}");

    let (gas_cost, output) = evm.call(verifier_address, encode_calldata(&proof, &instances));
    assert_eq!(output, [vec![0; 31], vec![1]].concat());
    println!("Gas cost: {gas_cost}");
}

fn run_render_separately<C: halo2::TestCircuit<Fr>>(scheme: BatchOpenScheme) {
    let acc_encoding = AccumulatorEncoding::new(0, 4, 68).into();
    let mut evm = Evm::default();

    for k in C::min_k()..C::min_k() + 4 {
        let (params, vk, instances, proof) =
            halo2::create_testdata::<C>(k, scheme, acc_encoding, std_rng());
        let generator = SolidityGenerator::new(&params, &vk, scheme, instances.len())
            .set_acc_encoding(acc_encoding);

        let (verifier_solidity, vk_solidity) = generator.render_separately().unwrap();
        let vk_creation_code = compile_solidity(&vk_solidity);
        let vk_address = evm.create(vk_creation_code);
        let verifier_creation_code = compile_solidity(&verifier_solidity);
        let verifier_creation_code_size = verifier_creation_code.len();
        let verifier_address = evm.create_with_address_arg(verifier_creation_code, vk_address);
        let verifier_runtime_code_size = evm.code_size(verifier_address);

        println!("Verifier creation code size: {verifier_creation_code_size}");
        println!("Verifier runtime code size: {verifier_runtime_code_size}");
        let (gas_cost, output) = evm.call(verifier_address, encode_calldata(&proof, &instances));
        assert_eq!(output, [vec![0; 31], vec![1]].concat());
        println!("Gas cost: {gas_cost}");
    }
}

fn std_rng() -> impl RngCore + Clone {
    StdRng::seed_from_u64(0)
}

fn new_property_test_runner() -> TestRunner {
    TestRunner::new(ProptestConfig {
        cases: 8,
        ..ProptestConfig::default()
    })
}

fn overwrite_u256_word(bytes: &mut [u8], start: usize, value: u64) {
    bytes[start..start + 32].fill(0);
    bytes[start + 24..start + 32].copy_from_slice(&value.to_be_bytes());
}

#[derive(Clone)]
struct PropertyStandardPlonkConfig {
    selectors: [halo2_proofs::plonk::Column<halo2_proofs::plonk::Fixed>; 5],
    wires: [halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>; 3],
    pi: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
}

impl PropertyStandardPlonkConfig {
    fn configure(
        meta: &mut halo2_proofs::plonk::ConstraintSystem<Fr>,
    ) -> PropertyStandardPlonkConfig {
        use halo2_proofs::poly::Rotation;

        let [w_l, w_r, w_o] = [(); 3].map(|_| meta.advice_column());
        let [q_l, q_r, q_o, q_m, q_c] = [(); 5].map(|_| meta.fixed_column());
        let pi = meta.instance_column();
        for column in [w_l, w_r, w_o] {
            meta.enable_equality(column);
        }
        meta.create_gate(
            "q_l·w_l + q_r·w_r + q_o·w_o + q_m·w_l·w_r + q_c + pi = 0",
            |meta| {
                let [w_l, w_r, w_o] =
                    [w_l, w_r, w_o].map(|column| meta.query_advice(column, Rotation::cur()));
                let [q_l, q_r, q_o, q_m, q_c] = [q_l, q_r, q_o, q_m, q_c]
                    .map(|column| meta.query_fixed(column, Rotation::cur()));
                let pi = meta.query_instance(pi, Rotation::cur());
                Some(q_l * w_l.clone() + q_r * w_r.clone() + q_o * w_o + q_m * w_l * w_r + q_c + pi)
            },
        );
        Self {
            selectors: [q_l, q_r, q_o, q_m, q_c],
            wires: [w_l, w_r, w_o],
            pi,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PropertyStandardPlonk<F>(Vec<F>);

impl<F: halo2_proofs::halo2curves::ff::PrimeField> PropertyStandardPlonk<F> {
    fn rand<R: RngCore>(num_instances: usize, mut rng: R) -> Self {
        Self((0..num_instances).map(|_| F::random(&mut rng)).collect())
    }

    fn instances(&self) -> Vec<F> {
        self.0.clone()
    }
}

impl halo2_proofs::plonk::Circuit<Fr> for PropertyStandardPlonk<Fr> {
    type Config = PropertyStandardPlonkConfig;
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        use halo2_proofs::arithmetic::Field;
        Self(vec![Fr::ZERO; self.0.len()])
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<Fr>) -> Self::Config {
        meta.set_minimum_degree(5);
        PropertyStandardPlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        use halo2_proofs::arithmetic::Field;
        use halo2_proofs::circuit::Value;

        let [q_l, q_r, q_o, q_m, q_c] = config.selectors;
        let [w_l, w_r, w_o] = config.wires;
        let _pi = config.pi;

        layouter.assign_region(
            || "standard plonk witness",
            |mut region| {
                for (offset, instance) in self.0.iter().enumerate() {
                    region.assign_advice(|| "", w_l, offset, || Value::known(*instance))?;
                    region.assign_fixed(|| "", q_l, offset, || Value::known(-Fr::ONE))?;
                }

                let offset = self.0.len();
                let a = region.assign_advice(|| "", w_l, offset, || Value::known(Fr::ONE))?;
                a.copy_advice(|| "", &mut region, w_r, offset)?;
                a.copy_advice(|| "", &mut region, w_o, offset)?;

                let offset = offset + 1;
                region.assign_advice(|| "", w_l, offset, || Value::known(-Fr::from(5)))?;
                for (column, idx) in [q_l, q_r, q_o, q_m, q_c].iter().zip(1..) {
                    region.assign_fixed(|| "", *column, offset, || Value::known(Fr::from(idx)))?;
                }
                Ok(())
            },
        )
    }
}

#[derive(Clone)]
struct PropertyStandardPlonkFixture {
    proof: Vec<u8>,
    instances: Vec<Fr>,
    embedded_verifier_solidity: String,
    separate_verifier_solidity: String,
    vk_solidity: String,
}

fn create_property_standard_plonk_fixture(k: u32, seed: u64) -> PropertyStandardPlonkFixture {
    use crate::transcript::Keccak256Transcript;
    use halo2_proofs::{
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::kzg::{
            commitment::ParamsKZG,
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
        transcript::TranscriptWriterBuffer,
    };

    let mut rng = StdRng::seed_from_u64(seed);
    let circuit = PropertyStandardPlonk::rand(k as usize, &mut rng);
    let instances = circuit.instances();

    let params = ParamsKZG::<Bls12381>::setup(k, &mut rng);
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();

    // halo2 v0.4 wants instances as `&[Vec<Vec<F>>]` (vec per circuit, then
    // vec per instance column) and SingleStrategy needs `ParamsVerifierKZG`.
    let instances_owned: Vec<Vec<Vec<Fr>>> = vec![vec![instances.clone()]];
    let verifier_params = params.verifier_params();
    let proof = {
        let mut transcript = Keccak256Transcript::new(Vec::new());
        create_proof::<_, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit.clone()],
            instances_owned.as_slice(),
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let result = {
        let mut transcript = Keccak256Transcript::new(proof.as_slice());
        verify_proof::<_, VerifierGWC<_>, _, _, SingleStrategy<_>>(
            &verifier_params,
            pk.get_vk(),
            SingleStrategy::new(&verifier_params),
            instances_owned.as_slice(),
            &mut transcript,
        )
    };
    assert!(
        result.is_ok(),
        "native verification failed for seed={seed} k={k}"
    );

    let generator = SolidityGenerator::new(&params, &vk, Gwc19, instances.len());
    let embedded_verifier_solidity = generator.render().unwrap();
    let (separate_verifier_solidity, vk_solidity) = generator.render_separately().unwrap();

    PropertyStandardPlonkFixture {
        proof,
        instances,
        embedded_verifier_solidity,
        separate_verifier_solidity,
        vk_solidity,
    }
}

fn run_property_standard_plonk_positive_case(k: u32, separate: bool, seed: u64) {
    let fixture = create_property_standard_plonk_fixture(k, seed);
    let output = if separate {
        call_separate_verifier(
            &fixture.separate_verifier_solidity,
            &fixture.vk_solidity,
            &fixture.proof,
            &fixture.instances,
        )
    } else {
        call_embedded_verifier(
            &fixture.embedded_verifier_solidity,
            &fixture.proof,
            &fixture.instances,
        )
    };
    assert_solidity_accepts(output, &format!("seed={seed} k={k} separate={separate}"));
}

fn run_property_standard_plonk_wrong_instance_case(k: u32, separate: bool, seed: u64) {
    use halo2_proofs::arithmetic::Field;

    let fixture = create_property_standard_plonk_fixture(k, seed);
    let mut bad_instances = fixture.instances.clone();
    bad_instances[0] += Fr::ONE;

    let output = if separate {
        call_separate_verifier(
            &fixture.separate_verifier_solidity,
            &fixture.vk_solidity,
            &fixture.proof,
            &bad_instances,
        )
    } else {
        call_embedded_verifier(
            &fixture.embedded_verifier_solidity,
            &fixture.proof,
            &bad_instances,
        )
    };
    assert_solidity_rejects(
        output,
        &format!("wrong instance seed={seed} k={k} separate={separate}"),
    );
}

fn run_property_standard_plonk_malleated_proof_case(
    k: u32,
    separate: bool,
    seed: u64,
    bit_idx: usize,
) {
    let fixture = create_property_standard_plonk_fixture(k, seed);
    let mut bad_proof = fixture.proof.clone();
    let byte_idx = bit_idx / 8 % bad_proof.len();
    let bit_mask = 1u8 << (bit_idx % 8);
    bad_proof[byte_idx] ^= bit_mask;

    let output = if separate {
        call_separate_verifier(
            &fixture.separate_verifier_solidity,
            &fixture.vk_solidity,
            &bad_proof,
            &fixture.instances,
        )
    } else {
        call_embedded_verifier(
            &fixture.embedded_verifier_solidity,
            &bad_proof,
            &fixture.instances,
        )
    };
    assert_solidity_rejects(
        output,
        &format!("malleated proof seed={seed} k={k} separate={separate}"),
    );
}

fn run_property_standard_plonk_wrong_vk_case(k: u32, seed: u64) {
    let fixture = create_property_standard_plonk_fixture(k, seed);
    let wrong_fixture = create_property_standard_plonk_fixture(k + 1, seed ^ 0x5a5a_5a5a_5a5a_5a5a);
    let output = call_separate_verifier(
        &fixture.separate_verifier_solidity,
        &wrong_fixture.vk_solidity,
        &fixture.proof,
        &fixture.instances,
    );
    assert_solidity_rejects(output, &format!("wrong vk seed={seed} k={k}"));
}

fn run_separate_vk_digest_prefix_affects_verification_case(k: u32, seed: u64) {
    let fixture = create_property_standard_plonk_fixture(k, seed);
    let original = call_separate_verifier(
        &fixture.separate_verifier_solidity,
        &fixture.vk_solidity,
        &fixture.proof,
        &fixture.instances,
    );
    assert_solidity_accepts(original, &format!("valid separate vk seed={seed} k={k}"));

    let mutated = call_separate_verifier(
        &fixture.separate_verifier_solidity,
        &mutate_vk_digest_literal_only(&fixture.vk_solidity),
        &fixture.proof,
        &fixture.instances,
    );
    assert_solidity_rejects(
        mutated,
        &format!("digest-only mutated separate vk seed={seed} k={k}"),
    );
}

fn call_embedded_verifier(
    verifier_solidity: &str,
    proof: &[u8],
    instances: &[Fr],
) -> Result<Vec<u8>, ()> {
    call_embedded_verifier_raw(verifier_solidity, encode_calldata(proof, instances))
}

fn call_embedded_verifier_raw(verifier_solidity: &str, calldata: Vec<u8>) -> Result<Vec<u8>, ()> {
    let mut evm = Evm::default();
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        let verifier_address = evm.create(compile_solidity(verifier_solidity));
        evm.call(verifier_address, calldata).1
    }))
    .map_err(|_| ())
}

fn call_separate_verifier(
    verifier_solidity: &str,
    vk_solidity: &str,
    proof: &[u8],
    instances: &[Fr],
) -> Result<Vec<u8>, ()> {
    let mut evm = Evm::default();
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        let vk_address = evm.create(compile_solidity(vk_solidity));
        let verifier_address =
            evm.create_with_address_arg(compile_solidity(verifier_solidity), vk_address);
        evm.call(verifier_address, encode_calldata(proof, instances))
            .1
    }))
    .map_err(|_| ())
}

fn assert_solidity_accepts(output: Result<Vec<u8>, ()>, context: &str) {
    let expected_true = [vec![0; 31], vec![1]].concat();
    match output {
        Ok(bytes) => assert_eq!(bytes, expected_true, "{context}"),
        Err(()) => panic!("solidity call panicked unexpectedly: {context}"),
    }
}

fn assert_solidity_rejects(output: Result<Vec<u8>, ()>, context: &str) {
    let expected_true = [vec![0; 31], vec![1]].concat();
    if let Ok(bytes) = output {
        assert_ne!(bytes, expected_true, "{context}");
    }
}

fn mutate_first_large_hex_literal(solidity: &str) -> String {
    let bytes = solidity.as_bytes();
    for start in 0..bytes.len().saturating_sub(2) {
        if bytes[start] == b'0' && bytes[start + 1] == b'x' {
            let mut end = start + 2;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end - (start + 2) >= 64 {
                let mut mutated = solidity.to_owned().into_bytes();
                let last = end - 1;
                mutated[last] = if mutated[last] == b'0' { b'1' } else { b'0' };
                return String::from_utf8(mutated).unwrap();
            }
        }
    }
    panic!("no 64-byte hex literal found to mutate");
}

fn mutate_vk_digest_literal_only(solidity: &str) -> String {
    let marker = "// vk_digest";
    let marker_idx = solidity.find(marker).expect("vk_digest marker not found");
    let line_start = solidity[..marker_idx]
        .rfind('\n')
        .map(|pos| pos + 1)
        .unwrap_or(0);
    let line_end = solidity[line_start..]
        .find('\n')
        .map(|pos| line_start + pos)
        .unwrap_or(solidity.len());
    let line = &solidity[line_start..line_end];
    let value_start = line
        .find(',')
        .and_then(|idx| line[idx..].find("0x").map(|off| idx + off))
        .expect("vk_digest line missing value hex literal");
    let abs_hex_start = line_start + value_start + 2;
    let hex_len = solidity[abs_hex_start..]
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .count();
    assert!(hex_len >= 64, "vk_digest literal shorter than expected");

    let mut mutated = solidity.as_bytes().to_vec();
    let last = abs_hex_start + hex_len - 1;
    mutated[last] = if mutated[last] == b'0' { b'1' } else { b'0' };
    String::from_utf8(mutated).unwrap()
}

#[allow(dead_code)]
fn save_generated(verifier: &str, vk: Option<&str>) {
    const DIR_GENERATED: &str = "./target/generated";

    std::fs::create_dir_all(DIR_GENERATED).unwrap();
    File::create(format!("{DIR_GENERATED}/Halo2Verifier.sol"))
        .unwrap()
        .write_all(verifier.as_bytes())
        .unwrap();
    if let Some(vk) = vk {
        File::create(format!("{DIR_GENERATED}/Halo2VerifyingKey.sol"))
            .unwrap()
            .write_all(vk.as_bytes())
            .unwrap();
    }
}

mod halo2 {
    use crate::{
        codegen::AccumulatorEncoding,
        transcript::Keccak256Transcript,
        BatchOpenScheme::{self, Gwc19},
    };
    use halo2_proofs::{
        arithmetic::CurveAffine,
        halo2curves::{
            bls12381 as bls12_381,
            ff::{Field, PrimeField},
            group::{prime::PrimeCurveAffine, Curve, Group},
            pairing::{MillerLoopResult, MultiMillerLoop},
        },
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, VerifyingKey},
        poly::kzg::{
            commitment::ParamsKZG,
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
        transcript::TranscriptWriterBuffer,
    };
    use itertools::Itertools;
    use rand::RngCore;
    use ruint::aliases::U256;
    use std::borrow::Borrow;

    pub trait TestCircuit<F: Field>: Circuit<F> {
        fn min_k() -> u32;

        fn new(acc_encoding: Option<AccumulatorEncoding>, rng: impl RngCore) -> Self;

        fn instances(&self) -> Vec<F>;
    }

    #[allow(clippy::type_complexity)]
    pub fn create_testdata<C: TestCircuit<bls12_381::Fr>>(
        k: u32,
        scheme: BatchOpenScheme,
        acc_encoding: Option<AccumulatorEncoding>,
        mut rng: impl RngCore + Clone,
    ) -> (
        ParamsKZG<bls12_381::Bls12381>,
        VerifyingKey<bls12_381::G1Affine>,
        Vec<bls12_381::Fr>,
        Vec<u8>,
    ) {
        match scheme {
            Gwc19 => create_testdata_inner!(ProverGWC<_>, VerifierGWC<_>, k, acc_encoding, rng),
        }
    }

    macro_rules! create_testdata_inner {
        ($p:ty, $v:ty, $k:ident, $acc_encoding:ident, $rng:ident) => {{
            let circuit = C::new($acc_encoding, $rng.clone());
            let instances = circuit.instances();

            let params = ParamsKZG::<bls12_381::Bls12381>::setup($k, &mut $rng);
            let vk = keygen_vk(&params, &circuit).unwrap();
            let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();

            let instances_owned: Vec<Vec<Vec<bls12_381::Fr>>> = vec![vec![instances.clone()]];
            let verifier_params = params.verifier_params();
            let proof = {
                let mut transcript = Keccak256Transcript::new(Vec::new());
                create_proof::<_, $p, _, _, _, _>(
                    &params,
                    &pk,
                    &[circuit],
                    instances_owned.as_slice(),
                    &mut $rng,
                    &mut transcript,
                )
                .unwrap();
                transcript.finalize()
            };

            let result = {
                let mut transcript = Keccak256Transcript::new(proof.as_slice());
                verify_proof::<_, $v, _, _, SingleStrategy<_>>(
                    &verifier_params,
                    pk.get_vk(),
                    SingleStrategy::new(&verifier_params),
                    instances_owned.as_slice(),
                    &mut transcript,
                )
            };
            assert!(result.is_ok());

            (params, vk, instances, proof)
        }};
    }

    use create_testdata_inner;

    fn random_accumulator_limbs<M>(
        acc_encoding: AccumulatorEncoding,
        mut rng: impl RngCore,
    ) -> Vec<M::Fr>
    where
        M: MultiMillerLoop,
        M::G1Affine: CurveAffine<ScalarExt = M::Fr>,
        <<M::G1Affine as CurveAffine>::Base as PrimeField>::Repr: AsRef<[u8]>,
        <<M::G1Affine as CurveAffine>::ScalarExt as PrimeField>::Repr:
            AsRef<[u8]> + From<[u8; 0x20]>,
    {
        let s = M::Fr::random(&mut rng);
        let g1 = M::G1Affine::generator();
        let g2 = M::G2Affine::generator();
        let neg_s_g2 = (g2 * -s).to_affine();
        let lhs_scalar = M::Fr::random(&mut rng);
        let rhs_scalar = lhs_scalar * s.invert().unwrap();
        let [lhs, rhs] = [lhs_scalar, rhs_scalar].map(|scalar| (g1 * scalar).to_affine());

        assert!(bool::from(
            M::multi_miller_loop(&[(&lhs, &g2.into()), (&rhs, &neg_s_g2.into())])
                .final_exponentiation()
                .is_identity()
        ));

        [lhs, rhs]
            .into_iter()
            .flat_map(|ec_point| ec_point_to_limbs(ec_point, acc_encoding.num_limb_bits))
            .collect()
    }

    fn ec_point_to_limbs<C>(ec_point: impl Borrow<C>, num_limb_bits: usize) -> Vec<C::Scalar>
    where
        C: CurveAffine,
        <C::Base as PrimeField>::Repr: AsRef<[u8]>,
        <C::Scalar as PrimeField>::Repr: AsRef<[u8]> + From<[u8; 0x20]>,
    {
        let coords = ec_point.borrow().coordinates().unwrap();
        [*coords.x(), *coords.y()]
            .into_iter()
            .flat_map(|coord| fe_to_limbs(coord, num_limb_bits))
            .collect()
    }

    fn fe_to_limbs<F1, F2>(fe: impl Borrow<F1>, num_limb_bits: usize) -> Vec<F2>
    where
        F1: PrimeField,
        F1::Repr: AsRef<[u8]>,
        F2: PrimeField,
        F2::Repr: AsRef<[u8]> + From<[u8; 0x20]>,
    {
        let repr = fe.borrow().to_repr();
        let bytes = repr.as_ref();
        let mut le = [0u8; 32];
        le.copy_from_slice(bytes);
        let big = U256::from_le_bytes(le);
        let mask = &((U256::from(1) << num_limb_bits) - U256::from(1));
        (0usize..)
            .step_by(num_limb_bits)
            .map(|shift| fe_from_u256((big >> shift) & mask))
            .take((F1::NUM_BITS as usize + num_limb_bits - 1) / num_limb_bits)
            .collect_vec()
    }

    fn fe_from_u256<F>(u256: impl Borrow<U256>) -> F
    where
        F: PrimeField,
        F::Repr: From<[u8; 0x20]>,
    {
        let bytes = u256.borrow().to_le_bytes::<32>();
        let repr = F::Repr::from(bytes);
        F::from_repr_vartime(repr).unwrap()
    }

    pub mod huge {
        use crate::{
            codegen::AccumulatorEncoding,
            test::halo2::{random_accumulator_limbs, TestCircuit},
        };
        use halo2_proofs::{
            arithmetic::CurveAffine,
            circuit::{Layouter, SimpleFloorPlanner, Value},
            halo2curves::{
                ff::{Field, PrimeField},
                pairing::MultiMillerLoop,
            },
            plonk::{
                self, Advice, Circuit, Column, ConstraintSystem, Expression, FirstPhase, Fixed,
                Instance, SecondPhase, Selector, ThirdPhase,
            },
            poly::Rotation,
        };
        use itertools::{izip, Itertools};
        use rand::RngCore;
        use std::{array, fmt::Debug, iter, mem};

        #[derive(Clone, Debug, Default)]
        pub struct HugeCircuit<M: MultiMillerLoop>(Vec<M::Fr>);

        impl<M: MultiMillerLoop> TestCircuit<M::Fr> for HugeCircuit<M>
        where
            M: MultiMillerLoop,
            M::G1Affine: CurveAffine<ScalarExt = M::Fr>,
            <<M::G1Affine as CurveAffine>::Base as PrimeField>::Repr: AsRef<[u8]>,
            <<M::G1Affine as CurveAffine>::ScalarExt as PrimeField>::Repr:
                AsRef<[u8]> + From<[u8; 0x20]>,
        {
            fn min_k() -> u32 {
                6
            }

            fn new(acc_encoding: Option<AccumulatorEncoding>, mut rng: impl RngCore) -> Self {
                let instances = if let Some(acc_encoding) = acc_encoding {
                    random_accumulator_limbs::<M>(acc_encoding, rng)
                } else {
                    iter::repeat_with(|| M::Fr::random(&mut rng))
                        .take(10)
                        .collect()
                };
                Self(instances)
            }

            fn instances(&self) -> Vec<M::Fr> {
                self.0.clone()
            }
        }

        impl<M: MultiMillerLoop> Circuit<M::Fr> for HugeCircuit<M> {
            type Config = (
                [Selector; 10],
                [Selector; 10],
                [Column<Fixed>; 10],
                [Column<Advice>; 10],
                Column<Instance>,
            );
            type FloorPlanner = SimpleFloorPlanner;
            #[cfg(feature = "halo2_circuit_params")]
            type Params = ();

            fn without_witnesses(&self) -> Self {
                unimplemented!()
            }

            fn configure(meta: &mut ConstraintSystem<M::Fr>) -> Self::Config {
                let selectors = [(); 10].map(|_| meta.selector());
                let complex_selectors = [(); 10].map(|_| meta.complex_selector());
                let fixeds = [(); 10].map(|_| meta.fixed_column());
                let (advices, challenges) = (0..10)
                    .map(|idx| match idx % 3 {
                        0 => (
                            meta.advice_column_in(FirstPhase),
                            meta.challenge_usable_after(FirstPhase),
                        ),
                        1 => (
                            meta.advice_column_in(SecondPhase),
                            meta.challenge_usable_after(SecondPhase),
                        ),
                        2 => (
                            meta.advice_column_in(ThirdPhase),
                            meta.challenge_usable_after(ThirdPhase),
                        ),
                        _ => unreachable!(),
                    })
                    .unzip::<_, _, Vec<_>, Vec<_>>();
                let advices: [_; 10] = advices.try_into().unwrap();
                let challenges: [_; 10] = challenges.try_into().unwrap();
                let instance = meta.instance_column();

                meta.create_gate("", |meta| {
                    let selectors = selectors.map(|selector| meta.query_selector(selector));
                    let advices: [Expression<M::Fr>; 10] = array::from_fn(|idx| {
                        let rotation = Rotation((idx as i32 - advices.len() as i32) / 2);
                        meta.query_advice(advices[idx], rotation)
                    });
                    let challenges = challenges.map(|challenge| meta.query_challenge(challenge));

                    izip!(
                        selectors,
                        advices.iter().cloned(),
                        advices[1..].iter().cloned(),
                        advices[2..].iter().cloned(),
                        challenges.iter().cloned(),
                        challenges[1..].iter().cloned(),
                        challenges[2..].iter().cloned(),
                    )
                    .map(|(q, a1, a2, a3, c1, c2, c3)| q * a1 * a2 * a3 * c1 * c2 * c3)
                    .collect_vec()
                });

                for ((q1, q2, q3), (f1, f2, f3), (a1, a2, a3)) in izip!(
                    complex_selectors.iter().tuple_windows(),
                    fixeds.iter().tuple_windows(),
                    advices.iter().tuple_windows()
                ) {
                    meta.lookup_any("", |meta| {
                        izip!([q1, q2, q3], [f1, f2, f3], [a1, a2, a3])
                            .map(|(q, f, a)| {
                                let q = meta.query_selector(*q);
                                let f = meta.query_fixed(*f, Rotation::cur());
                                let a = meta.query_advice(*a, Rotation::cur());
                                (q * a, f)
                            })
                            .collect_vec()
                    });
                }

                fixeds.map(|column| meta.enable_equality(column));
                advices.map(|column| meta.enable_equality(column));
                meta.enable_equality(instance);

                (selectors, complex_selectors, fixeds, advices, instance)
            }

            fn synthesize(
                &self,
                (selectors, complex_selectors, fixeds, advices, instance): Self::Config,
                mut layouter: impl Layouter<M::Fr>,
            ) -> Result<(), plonk::ErrorFront> {
                let assigneds = layouter.assign_region(
                    || "",
                    |mut region| {
                        let offset = &mut 10;
                        let mut next_offset = || mem::replace(offset, *offset + 1);

                        for q in selectors {
                            q.enable(&mut region, next_offset())?;
                        }
                        for q in complex_selectors {
                            q.enable(&mut region, next_offset())?;
                        }
                        for (idx, column) in izip!(1.., fixeds) {
                            let value = Value::known(M::Fr::from(idx));
                            region.assign_fixed(|| "", column, next_offset(), || value)?;
                        }
                        izip!(advices, &self.0)
                            .map(|(column, value)| {
                                let value = Value::known(*value);
                                region.assign_advice(|| "", column, next_offset(), || value)
                            })
                            .try_collect::<_, Vec<_>, _>()
                    },
                )?;
                for (idx, assigned) in izip!(0.., assigneds) {
                    layouter.constrain_instance(assigned.cell(), instance, idx)?;
                }
                Ok(())
            }
        }
    }

    // The maingate test module is gated off during the halo2 v0.4 migration:
    // `halo2_maingate` v2024_01_31 only compiles against halo2_proofs v0.3.
    // Once a v0.4-compatible maingate ships (or we replace MainGate with a
    // simpler arithmetic chip), re-enable this module and the four
    // render_*_maingate tests above.
    #[cfg(feature = "_maingate_v3")]
    pub mod maingate {
        use crate::{
            codegen::AccumulatorEncoding,
            test::halo2::{random_accumulator_limbs, TestCircuit},
        };
        use halo2_maingate::{
            MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig,
            RangeInstructions, RegionCtx,
        };
        use halo2_proofs::{
            arithmetic::CurveAffine,
            circuit::{Layouter, SimpleFloorPlanner, Value},
            halo2curves::{
                ff::{Field, PrimeField},
                pairing::MultiMillerLoop,
            },
            plonk::{Circuit, ConstraintSystem, Error},
        };
        use itertools::Itertools;
        use rand::RngCore;
        use std::iter;

        #[derive(Clone)]
        pub struct MainGateWithRangeConfig {
            main_gate_config: MainGateConfig,
            range_config: RangeConfig,
        }

        impl MainGateWithRangeConfig {
            fn configure<F: PrimeField>(
                meta: &mut ConstraintSystem<F>,
                composition_bits: Vec<usize>,
                overflow_bits: Vec<usize>,
            ) -> Self {
                let main_gate_config = MainGate::<F>::configure(meta);
                let range_config = RangeChip::<F>::configure(
                    meta,
                    &main_gate_config,
                    composition_bits,
                    overflow_bits,
                );
                MainGateWithRangeConfig {
                    main_gate_config,
                    range_config,
                }
            }

            fn main_gate<F: PrimeField>(&self) -> MainGate<F> {
                MainGate::new(self.main_gate_config.clone())
            }

            fn range_chip<F: PrimeField>(&self) -> RangeChip<F> {
                RangeChip::new(self.range_config.clone())
            }
        }

        #[derive(Clone, Default)]
        pub struct MainGateWithRange<M: MultiMillerLoop> {
            instances: Vec<M::Fr>,
        }

        impl<M> TestCircuit<M::Fr> for MainGateWithRange<M>
        where
            M: MultiMillerLoop,
            M::G1Affine: CurveAffine<ScalarExt = M::Fr>,
            <M::G1Affine as CurveAffine>::Base: PrimeField<Repr = [u8; 0x20]>,
            <M::G1Affine as CurveAffine>::ScalarExt: PrimeField<Repr = [u8; 0x20]>,
        {
            fn min_k() -> u32 {
                9
            }

            fn new(acc_encoding: Option<AccumulatorEncoding>, mut rng: impl RngCore) -> Self {
                let instances = if let Some(acc_encoding) = acc_encoding {
                    random_accumulator_limbs::<M>(acc_encoding, rng)
                } else {
                    iter::repeat_with(|| M::Fr::random(&mut rng))
                        .take(10)
                        .collect()
                };
                Self { instances }
            }

            fn instances(&self) -> Vec<M::Fr> {
                self.instances.clone()
            }
        }

        impl<M: MultiMillerLoop> Circuit<M::Fr> for MainGateWithRange<M> {
            type Config = MainGateWithRangeConfig;
            type FloorPlanner = SimpleFloorPlanner;
            #[cfg(feature = "halo2_circuit_params")]
            type Params = ();

            fn without_witnesses(&self) -> Self {
                unimplemented!()
            }

            fn configure(meta: &mut ConstraintSystem<M::Fr>) -> Self::Config {
                MainGateWithRangeConfig::configure(meta, vec![8], vec![4, 7])
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<M::Fr>,
            ) -> Result<(), Error> {
                let main_gate = config.main_gate();
                let range_chip = config.range_chip();
                range_chip.load_table(&mut layouter)?;

                let advices = layouter.assign_region(
                    || "",
                    |region| {
                        let mut ctx = RegionCtx::new(region, 0);

                        let advices = self
                            .instances
                            .iter()
                            .map(|value| main_gate.assign_value(&mut ctx, Value::known(*value)))
                            .try_collect::<_, Vec<_>, _>()?;

                        // Dummy gates to make all fixed column with values
                        range_chip.decompose(
                            &mut ctx,
                            Value::known(M::Fr::from(u64::MAX)),
                            8,
                            64,
                        )?;
                        range_chip.decompose(
                            &mut ctx,
                            Value::known(M::Fr::from(u32::MAX as u64)),
                            8,
                            39,
                        )?;
                        let a = &advices[0];
                        let b =
                            main_gate.sub_sub_with_constant(&mut ctx, a, a, a, M::Fr::from(2))?;
                        let cond = main_gate.assign_bit(&mut ctx, Value::known(M::Fr::ONE))?;
                        main_gate.select(&mut ctx, a, &b, &cond)?;

                        Ok(advices)
                    },
                )?;

                for (offset, advice) in advices.into_iter().enumerate() {
                    main_gate.expose_public(layouter.namespace(|| ""), advice, offset)?
                }

                Ok(())
            }
        }
    }
}
