use crate::{
    compile_solidity, encode_calldata, BatchOpenScheme::Gwc19, Evm, SolidityGenerator,
    FN_SIG_VERIFY_PROOF,
};
use ff::Field;
use midnight_circuits::{
    hash::poseidon::PoseidonChip,
    instructions::{hash::HashCPU, AssignmentInstructions, PublicInputInstructions},
};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error},
};
use midnight_zk_stdlib::{
    setup_vk, utils::plonk_api::srs_for_test, MidnightVK, Relation, ZkStdLib, ZkStdLibArch,
};
use proptest::{
    prelude::any,
    test_runner::{Config as ProptestConfig, TestRunner},
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha3::Digest;
use std::{
    env,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::OnceLock,
};

type F = midnight_curves::Fq;
type PoseidonParams = midnight_proofs::poly::kzg::params::ParamsKZG<midnight_curves::Bls12>;

const POSEIDON_K: u32 = 6;

#[test]
fn function_signature() {
    assert_eq!(
        <[u8; 32]>::from(sha3::Keccak256::digest("verifyProof(bytes,uint256[])"))[..4],
        FN_SIG_VERIFY_PROOF,
    );
}

/// Direct EIP-2537 BLS12_G1ADD precompile smoke test against the bundled
/// Prague-spec revm. Exercises the runner path independently of the halo2
/// codegen so a regression in `src/evm.rs` shows up here first.
#[test]
fn prague_evm_runs_eip2537_g1add_to_identity() {
    use crate::evm::test::Evm;
    use revm::primitives::Address;

    let runtime: Vec<u8> = vec![
        0x36, 0x60, 0x00, 0x60, 0x00, 0x37, // calldatacopy(0, 0, calldatasize())
        0x60, 0x80, 0x60, 0x00, 0x36, 0x60, 0x00, 0x60, 0x0b, 0x5a, 0xfa, 0x50, 0x60, 0x80, 0x60,
        0x00, 0xf3, // return(0, 0x80)
    ];
    let len = runtime.len() as u8;
    let mut deployer = Vec::with_capacity(12 + runtime.len());
    deployer.extend([0x60, len]);
    deployer.extend([0x60, 0x0c]);
    deployer.extend([0x60, 0x00]);
    deployer.push(0x39);
    deployer.extend([0x60, len]);
    deployer.extend([0x60, 0x00]);
    deployer.push(0xf3);
    assert_eq!(
        deployer.len(),
        12,
        "deployer prefix should be exactly 12 bytes"
    );
    deployer.extend(runtime);

    let mut evm = Evm::default();
    let addr: Address = evm.create(deployer);

    let g1_x_hex = "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    let g1_y_hex = "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    let mut calldata = vec![];
    for hex in [g1_x_hex, g1_y_hex, g1_x_hex, g1_y_hex] {
        calldata.extend(hex::decode(hex).unwrap());
    }
    assert_eq!(calldata.len(), 256);

    let (gas_used, output) = evm.call(addr, calldata);
    assert_eq!(output.len(), 128, "EIP-2537 G1ADD must return 128 bytes");
    assert!(
        output.iter().any(|&b| b != 0),
        "G1ADD output is all zero; precompile did not run"
    );
    assert!(gas_used > 0);
}

#[test]
#[ignore = "expensive Poseidon property test; run explicitly"]
fn pbt_solidity_verifies_standard_plonk_embedded_vk_proofs() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let mut runner = new_property_test_runner();
    runner
        .run(&any::<u64>(), |seed| {
            run_property_poseidon_positive_case(false, seed);
            Ok(())
        })
        .unwrap();
}

#[test]
#[ignore = "expensive Poseidon property test; run explicitly"]
fn pbt_solidity_rejects_wrong_instances() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let mut runner = new_property_test_runner();
    let strategy = (any::<u64>(), any::<bool>());
    runner
        .run(&strategy, |(seed, separate)| {
            run_property_poseidon_wrong_instance_case(separate, seed);
            Ok(())
        })
        .unwrap();
}

#[test]
#[ignore = "expensive Poseidon property test; run explicitly"]
fn pbt_solidity_rejects_malleated_proofs() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let mut runner = new_property_test_runner();
    let strategy = (any::<u64>(), any::<bool>(), 0usize..4096);
    runner
        .run(&strategy, |(seed, separate, bit_idx)| {
            run_property_poseidon_malleated_proof_case(separate, seed, bit_idx);
            Ok(())
        })
        .unwrap();
}

#[test]
#[ignore = "expensive Poseidon property test; run explicitly"]
fn pbt_solidity_rejects_wrong_verifying_keys() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let mut runner = new_property_test_runner();
    runner
        .run(&any::<u64>(), |seed| {
            run_property_poseidon_wrong_vk_case(seed);
            Ok(())
        })
        .unwrap();
}

#[test]
#[ignore = "expensive Poseidon property test; run explicitly"]
fn pbt_separate_vk_digest_prefix_affects_verification() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let mut runner = new_property_test_runner();
    runner
        .run(&any::<u64>(), |seed| {
            run_separate_vk_digest_prefix_affects_verification_case(seed);
            Ok(())
        })
        .unwrap();
}

#[test]
#[ignore = "solidity/EVM-heavy; run explicitly"]
fn malformed_embedded_calldata_variants_are_rejected() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
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
#[ignore = "solidity/EVM-heavy; run explicitly"]
fn mutated_separate_vk_contract_is_rejected() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let mutated_vk_solidity = mutate_first_large_hex_literal(&fixture.vk_solidity, 0);
    let output = call_separate_verifier(
        &fixture.separate_verifier_solidity,
        &mutated_vk_solidity,
        &fixture.proof,
        &fixture.instances,
    );
    assert_solidity_rejects(output, "mutated separate vk");
}

#[test]
#[ignore = "solidity/EVM-heavy; run explicitly"]
fn standard_plonk_render_is_deterministic_for_same_seed() {
    if !poseidon_srs_available() {
        return;
    }

    let fixture_a = load_property_poseidon_fixture();
    let fixture_b = load_property_poseidon_fixture();

    assert_eq!(fixture_a.instances, fixture_b.instances);
    assert_eq!(fixture_a.proof.len(), fixture_b.proof.len());
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
#[ignore = "solidity/EVM-heavy; run explicitly"]
fn compile_solidity_is_deterministic_for_same_source() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let bytecode_a = compile_solidity(&fixture.embedded_verifier_solidity);
    let bytecode_b = compile_solidity(&fixture.embedded_verifier_solidity);

    assert_eq!(bytecode_a, bytecode_b);
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
struct PropertyPoseidonFixture {
    proof: Vec<u8>,
    instances: Vec<F>,
    embedded_verifier_solidity: String,
    separate_verifier_solidity: String,
    vk_solidity: String,
}

fn create_property_poseidon_fixture() -> PropertyPoseidonFixture {
    static FIXTURE: OnceLock<PropertyPoseidonFixture> = OnceLock::new();
    FIXTURE.get_or_init(load_property_poseidon_fixture).clone()
}

fn load_property_poseidon_fixture() -> PropertyPoseidonFixture {
    let srs_dir = srs_dir();
    env::set_var("SRS_DIR", &srs_dir);

    let relation = PoseidonExample;
    let srs = srs_for_test(&relation, Some(POSEIDON_K));
    let vk = setup_vk(&srs, &relation);
    assert_eq!(vk.k() as u32, POSEIDON_K, "unexpected Poseidon VK k");

    let (compressed_proof, instance) = generate_poseidon_proof(&srs, &relation, &vk);

    let generator = SolidityGenerator::new(&srs, vk.vk(), Gwc19, 1).set_num_committed_instances(1);
    let embedded_verifier_solidity = generator.render().expect("embedded render");
    let (separate_verifier_solidity, vk_solidity) =
        generator.render_separately().expect("separate render");
    let proof = repack_proof_uncompressed(vk.vk().cs(), &compressed_proof);

    PropertyPoseidonFixture {
        proof,
        instances: vec![instance],
        embedded_verifier_solidity,
        separate_verifier_solidity,
        vk_solidity,
    }
}

fn generate_poseidon_proof(
    srs: &PoseidonParams,
    relation: &PoseidonExample,
    vk: &MidnightVK,
) -> (Vec<u8>, F) {
    let pk = midnight_zk_stdlib::setup_pk(relation, vk);
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let witness: [F; 3] = core::array::from_fn(|_| F::random(&mut rng));
    let instance = <PoseidonChip<F> as HashCPU<F, F>>::hash(&witness);
    let prover_rng = ChaCha8Rng::seed_from_u64(0xdebd);
    let proof = midnight_zk_stdlib::prove::<PoseidonExample, sha3::Keccak256>(
        srs, &pk, relation, &instance, witness, prover_rng,
    )
    .expect("proof generation should not fail");

    midnight_zk_stdlib::verify::<PoseidonExample, sha3::Keccak256>(
        &srs.verifier_params(),
        vk,
        &instance,
        None,
        &proof,
    )
    .expect("generated proof should verify natively");

    (proof, instance)
}

fn run_property_poseidon_positive_case(separate: bool, seed: u64) {
    let fixture = create_property_poseidon_fixture();
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
    assert_solidity_accepts(output, &format!("seed={seed} separate={separate}"));
}

fn run_property_poseidon_wrong_instance_case(separate: bool, seed: u64) {
    let fixture = create_property_poseidon_fixture();
    let mut bad_instances = fixture.instances.clone();
    bad_instances[0] += F::ONE;

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
        &format!("wrong instance seed={seed} separate={separate}"),
    );
}

fn run_property_poseidon_malleated_proof_case(separate: bool, seed: u64, bit_idx: usize) {
    let fixture = create_property_poseidon_fixture();
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
        &format!("malleated proof seed={seed} separate={separate}"),
    );
}

fn run_property_poseidon_wrong_vk_case(seed: u64) {
    let fixture = create_property_poseidon_fixture();
    let mutated_vk_solidity = mutate_first_large_hex_literal(&fixture.vk_solidity, seed as usize);
    let output = call_separate_verifier(
        &fixture.separate_verifier_solidity,
        &mutated_vk_solidity,
        &fixture.proof,
        &fixture.instances,
    );
    assert_solidity_rejects(output, &format!("wrong vk seed={seed}"));
}

fn run_separate_vk_digest_prefix_affects_verification_case(seed: u64) {
    let fixture = create_property_poseidon_fixture();
    let original = call_separate_verifier(
        &fixture.separate_verifier_solidity,
        &fixture.vk_solidity,
        &fixture.proof,
        &fixture.instances,
    );
    assert_solidity_accepts(original, &format!("valid separate vk seed={seed}"));

    let mutated = call_separate_verifier(
        &fixture.separate_verifier_solidity,
        &mutate_vk_digest_literal_only(&fixture.vk_solidity),
        &fixture.proof,
        &fixture.instances,
    );
    assert_solidity_rejects(
        mutated,
        &format!("digest-only mutated separate vk seed={seed}"),
    );
}

fn call_embedded_verifier(
    verifier_solidity: &str,
    proof: &[u8],
    instances: &[F],
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
    instances: &[F],
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

fn mutate_first_large_hex_literal(solidity: &str, ordinal_seed: usize) -> String {
    let bytes = solidity.as_bytes();
    let mut matches = Vec::new();
    for start in 0..bytes.len().saturating_sub(2) {
        if bytes[start] == b'0' && bytes[start + 1] == b'x' {
            let mut end = start + 2;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end - (start + 2) >= 64 {
                matches.push((start, end));
            }
        }
    }

    assert!(
        !matches.is_empty(),
        "no 64-byte hex literal found to mutate"
    );
    let (start, end) = matches[ordinal_seed % matches.len()];
    let mut mutated = solidity.to_owned().into_bytes();
    let idx = end - 1 - ordinal_seed % ((end - start - 2).min(16));
    mutated[idx] = if mutated[idx] == b'0' { b'1' } else { b'0' };
    String::from_utf8(mutated).unwrap()
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

fn new_property_test_runner() -> TestRunner {
    let cases = env::var("POSEIDON_PBT_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);
    TestRunner::new(ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    })
}

fn overwrite_u256_word(bytes: &mut [u8], start: usize, value: u64) {
    bytes[start..start + 32].fill(0);
    bytes[start + 24..start + 32].copy_from_slice(&value.to_be_bytes());
}

fn poseidon_inputs_available_for_evm() -> bool {
    if !poseidon_srs_available() {
        return false;
    }
    if !solc_available() {
        eprintln!("skipping Poseidon Solidity property test: solc not found");
        return false;
    }
    true
}

fn poseidon_srs_available() -> bool {
    let srs_path = PathBuf::from(srs_dir()).join(format!("bls_filecoin_2p{POSEIDON_K}"));
    if !srs_path.exists() {
        eprintln!(
            "skipping Poseidon Solidity property test: SRS not found at {}",
            srs_path.display()
        );
        return false;
    }
    true
}

fn solc_available() -> bool {
    std::process::Command::new("solc")
        .arg("--version")
        .output()
        .is_ok()
}

fn srs_dir() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../midfall/zk_stdlib/examples/assets")
        .to_string_lossy()
        .into_owned()
}

fn repack_proof_uncompressed(cs: &ConstraintSystem<F>, proof: &[u8]) -> Vec<u8> {
    let perm_chunks = cs.permutation().columns.chunks(cs.degree() - 2).count();
    let mut g1_groups: Vec<usize> = Vec::new();

    let advice_phase = cs.advice_column_phase();
    let max_phase = *advice_phase.iter().max().unwrap_or(&0);
    for phase in 0..=max_phase {
        let n = advice_phase.iter().filter(|p| **p == phase).count();
        if n != 0 {
            g1_groups.push(n);
        }
    }
    if !cs.lookups().is_empty() {
        g1_groups.push(cs.lookups().len());
    }
    if perm_chunks != 0 {
        g1_groups.push(perm_chunks);
    }
    for lookup in cs.lookups().iter() {
        let nb_chunks = lookup.chunk_by_degree(cs.degree()).num_chunks();
        g1_groups.push(nb_chunks);
        g1_groups.push(1);
    }
    if !cs.trashcans().is_empty() {
        g1_groups.push(cs.trashcans().len());
    }
    g1_groups.push(cs.degree() - 1);

    let nb_committed_instances = 1usize;
    let num_committed_instance_evals = cs
        .instance_queries()
        .iter()
        .filter(|(col, _)| col.index() < nb_committed_instances)
        .count();
    let num_fixed_non_simple = cs.num_fixed_columns() - cs.num_simple_selectors();
    let perm_set_count = if perm_chunks == 0 {
        0
    } else {
        3 * perm_chunks - 1
    };
    let lookup_eval_count: usize = cs
        .lookups()
        .iter()
        .map(|lookup| 1 + lookup.chunk_by_degree(cs.degree()).num_chunks() + 1 + 1)
        .sum();
    let num_evals = num_committed_instance_evals
        + cs.advice_queries().len()
        + num_fixed_non_simple
        + cs.permutation().columns.len()
        + perm_set_count
        + lookup_eval_count
        + cs.trashcans().len();

    let prefix_g1_count: usize = g1_groups.iter().sum();
    let prefix_compressed_len = prefix_g1_count * 48 + num_evals * 32;
    let trailing_compressed_len = 48 + 48;
    let q_evals_len = proof
        .len()
        .checked_sub(prefix_compressed_len + trailing_compressed_len)
        .expect("proof too short for declared groups");
    assert_eq!(
        q_evals_len % 32,
        0,
        "q_evals tail must be a multiple of 32 bytes"
    );
    let num_point_sets = q_evals_len / 32;

    let mut out: Vec<u8> = Vec::with_capacity(
        prefix_g1_count * 128 + num_evals * 32 + 128 + num_point_sets * 32 + 128,
    );
    let mut cursor = 0usize;
    for &n in &g1_groups {
        for _ in 0..n {
            push_uncompressed_g1(proof, &mut cursor, &mut out);
        }
    }
    out.extend_from_slice(&proof[cursor..cursor + num_evals * 32]);
    cursor += num_evals * 32;
    push_uncompressed_g1(proof, &mut cursor, &mut out);
    out.extend_from_slice(&proof[cursor..cursor + num_point_sets * 32]);
    cursor += num_point_sets * 32;
    push_uncompressed_g1(proof, &mut cursor, &mut out);
    assert_eq!(cursor, proof.len(), "proof not fully consumed");
    out
}

fn push_uncompressed_g1(proof: &[u8], cursor: &mut usize, out: &mut Vec<u8>) {
    use group::{prime::PrimeCurveAffine, GroupEncoding};

    let mut compressed = <midnight_curves::G1Affine as GroupEncoding>::Repr::default();
    compressed
        .as_mut()
        .copy_from_slice(&proof[*cursor..*cursor + 48]);
    let cur = *cursor;
    *cursor += 48;
    let point: midnight_curves::G1Affine = Option::from(
        <midnight_curves::G1Affine as GroupEncoding>::from_bytes(&compressed),
    )
    .unwrap_or_else(|| {
        panic!(
            "decompress failed at proof[{cur}..{}]: bytes = 0x{}",
            cur + 48,
            hex::encode(compressed.as_ref())
        )
    });

    if bool::from(point.is_identity()) {
        out.extend_from_slice(&[0u8; 128]);
        return;
    }

    let x_be = point.x().to_bytes_be();
    let y_be = point.y().to_bytes_be();
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&x_be[0..16]);
    out.extend_from_slice(&x_be[16..48]);
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&y_be[0..16]);
    out.extend_from_slice(&y_be[16..48]);
}
