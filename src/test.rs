use crate::{
    compile_solidity, encode_calldata, pinned_solc_available, CallOutcome, Evm, SolidityGenerator,
    FN_SIG_VERIFY_PROOF,
};
use ff::Field;
use group::{Curve as _, Group as _};
use midnight_circuits::{
    hash::poseidon::PoseidonChip,
    instructions::{hash::HashCPU, AssignmentInstructions, PublicInputInstructions},
};
use midnight_curves::{Bls12, Fq, G1Projective, G2Projective};
use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk_with_k, prepare, Advice, Circuit, Column,
        ConstraintSystem, Constraints, Error, Expression, Fixed, SecondPhase, Selector,
    },
    poly::{commitment::Guard as _, kzg::KZGCommitmentScheme, Rotation},
    transcript::{CircuitTranscript, Transcript},
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
#[cfg(feature = "rust-verifier-trace")]
use revm::primitives::B256;
use ruint::aliases::U256;
use sha3::Digest;
#[cfg(feature = "rust-verifier-trace")]
use std::collections::BTreeMap;
use std::{
    env,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::OnceLock,
};

type F = midnight_curves::Fq;
type PoseidonParams = midnight_proofs::poly::kzg::params::ParamsKZG<midnight_curves::Bls12>;
type PoseidonVerifierParams =
    midnight_proofs::poly::kzg::params::ParamsVerifierKZG<midnight_curves::Bls12>;

const POSEIDON_K: u32 = 6;
const RUN_EVM_TESTS_ENV: &str = "HALO2_SOLIDITY_RUN_EVM_TESTS";

#[test]
fn function_signature() {
    assert_eq!(
        <[u8; 32]>::from(sha3::Keccak256::digest("verifyProof(bytes,uint256[])"))[..4],
        FN_SIG_VERIFY_PROOF,
    );
}

/// Direct EIP-2537 precompile conformance tests against the bundled
/// Prague-spec revm. Exercises the runner path independently of the verifier
/// codegen so a regression in `src/evm.rs`, malformed-point handling, or the
/// gas path used by large verifier MSMs shows up here first.
#[test]
fn prague_evm_runs_eip2537_conformance_smoke_tests() {
    use crate::evm::test::Evm;
    use revm::primitives::Address;

    let mut evm = Evm::default();

    let g1add = Address::with_last_byte(0x0b);
    let g1msm = Address::with_last_byte(0x0c);
    let pairing = Address::with_last_byte(0x0f);
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    // G1ADD(identity, identity) -> identity.
    let (_gas_used, output) = evm.call(g1add, vec![0; 0x100]);
    assert_eq!(output, vec![0; 0x80]);

    // G1ADD(G, G) -> 2G.
    let mut g1add_input = g1_bytes(g1);
    g1add_input.extend(g1_bytes(g1));
    let (_gas_used, output) = evm.call(g1add, g1add_input);
    assert_eq!(output, g1_bytes(g1 * Fq::from(2)));

    // G1MSM([(identity, 0)]) -> identity.
    let (_gas_used, output) = evm.call(g1msm, vec![0; 0xa0]);
    assert_eq!(output, vec![0; 0x80]);

    // G1MSM([(G, 3), ([2]G, 5)]) -> [13]G.
    let mut g1msm_input = g1_msm_term(g1, 3);
    g1msm_input.extend(g1_msm_term(g1 * Fq::from(2), 5));
    let (_gas_used, output) = evm.call(g1msm, g1msm_input);
    assert_eq!(output, g1_bytes(g1 * Fq::from(13)));

    // Malformed/off-curve G1 input must be rejected by the MSM precompile.
    let mut invalid_msm = eip2537_padded_off_curve_g1_bytes().to_vec();
    invalid_msm.extend(u256_word(1));
    assert!(
        !matches!(
            evm.try_call_with_gas(g1msm, invalid_msm, 200_000),
            CallOutcome::Success { .. }
        ),
        "G1MSM accepted a canonical but off-curve G1 point"
    );

    // Full-size 78-term MSM path used by wide verifier shapes. The exact gas
    // number is fork-dependent; this asserts the local Prague runner has a
    // conforming large-input path and returns a non-identity point.
    let mut large_msm = Vec::with_capacity(78 * 0xa0);
    for _ in 0..78 {
        large_msm.extend(g1_msm_term(g1, 1));
    }
    match evm.try_call_with_gas(g1msm, large_msm, 2_000_000) {
        CallOutcome::Success { output, .. } => {
            assert_eq!(output.len(), 0x80);
            assert!(
                output.iter().any(|&b| b != 0),
                "78-term G1MSM unexpectedly returned identity"
            );
        }
        outcome => panic!("78-term G1MSM failed in Prague revm: {outcome:?}"),
    }

    // Pairing identity input should return true.
    let (_gas_used, output) = evm.call(pairing, vec![0; 0x180]);
    assert_eq!(output, [vec![0; 31], vec![1]].concat());

    // A single non-identity generator pairing is not the neutral product.
    let mut invalid_pairing = g1_bytes(g1);
    invalid_pairing.extend(g2_bytes(g2));
    let (_gas_used, output) = evm.call(pairing, invalid_pairing);
    assert_eq!(
        output,
        vec![0; 0x20],
        "PAIRING_CHECK([(G1, G2)]) should return false"
    );

    // Bilinearity: e([2]G1, G2) * e(-G1, [2]G2) == 1.
    let mut bilinear_pairing = g1_bytes(g1 * Fq::from(2));
    bilinear_pairing.extend(g2_bytes(g2));
    bilinear_pairing.extend(g1_bytes(-g1));
    bilinear_pairing.extend(g2_bytes(g2 * Fq::from(2)));
    let (_gas_used, output) = evm.call(pairing, bilinear_pairing);
    assert_eq!(output, [vec![0; 31], vec![1]].concat());
}

fn g1_bytes(point: G1Projective) -> Vec<u8> {
    words_to_bytes(crate::__test_only_g1_to_u256s(&point.to_affine()))
}

fn g2_bytes(point: G2Projective) -> Vec<u8> {
    words_to_bytes(crate::__test_only_g2_to_u256s(&point.to_affine()))
}

fn g1_msm_term(point: G1Projective, scalar: u64) -> Vec<u8> {
    let mut out = g1_bytes(point);
    out.extend(u256_word(scalar));
    out
}

fn u256_word(value: u64) -> [u8; 32] {
    U256::from(value).to_be_bytes()
}

fn words_to_bytes<const N: usize>(words: [U256; N]) -> Vec<u8> {
    words
        .into_iter()
        .flat_map(|word| word.to_be_bytes::<32>())
        .collect()
}

#[derive(Clone, Copy, Debug, Default)]
struct ShapeFuzzSpec {
    next_rotation: bool,
    second_phase: bool,
    permutation: bool,
    lookup: bool,
    additive_selector: bool,
    complex_selector: bool,
    fixed_scale: bool,
    tag: u64,
}

#[derive(Clone, Copy, Debug)]
struct ShapeFuzzCase {
    name: &'static str,
    k: u32,
    spec: ShapeFuzzSpec,
    seed: u64,
}

#[derive(Clone, Debug)]
struct ShapeFuzzConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    out: Column<Advice>,
    phase2: Option<Column<Advice>>,
    fixed_scale: Option<Column<Fixed>>,
    lookup_table: Option<Column<Fixed>>,
    selector: Selector,
}

#[derive(Clone, Debug)]
struct ShapeFuzzCircuit {
    spec: ShapeFuzzSpec,
    a: F,
    b: F,
}

impl ShapeFuzzCircuit {
    fn new(spec: ShapeFuzzSpec, seed: u64) -> Self {
        let a = F::from(seed.wrapping_mul(17).wrapping_add(5));
        let b = F::from(seed.wrapping_mul(29).wrapping_add(11));
        Self { spec, a, b }
    }

    fn out(&self) -> F {
        self.a + self.b + F::from(self.spec.tag + 19)
    }

    fn public_instance(&self) -> F {
        self.out() - self.a - self.b
    }

    fn next_a(&self) -> F {
        self.a + F::from(self.spec.tag + 7)
    }

    fn phase2_value(&self) -> F {
        self.out() + F::from(self.spec.tag + 23)
    }
}

impl Circuit<F> for ShapeFuzzCircuit {
    type Config = ShapeFuzzConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ShapeFuzzSpec;

    fn without_witnesses(&self) -> Self {
        Self {
            spec: self.spec,
            a: F::ZERO,
            b: F::ZERO,
        }
    }

    fn params(&self) -> Self::Params {
        self.spec
    }

    fn configure(_meta: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!("ShapeFuzzCircuit is always configured with explicit params")
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, spec: Self::Params) -> Self::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let out = meta.advice_column();
        let phase2 = spec
            .second_phase
            .then(|| meta.advice_column_in(SecondPhase));
        let fixed_scale = spec.fixed_scale.then(|| meta.fixed_column());
        let lookup_table = spec.lookup.then(|| meta.fixed_column());
        let committed_instance = meta.instance_column();
        let public_instance = meta.instance_column();

        if spec.permutation {
            for column in [a, b, out] {
                meta.enable_equality(column);
            }
        }

        let selector = if spec.additive_selector || spec.complex_selector || spec.lookup {
            meta.complex_selector()
        } else {
            meta.selector()
        };

        meta.create_gate("shape-fuzz arithmetic", |meta| {
            let a_cur = meta.query_advice(a, Rotation::cur());
            let b_cur = meta.query_advice(b, Rotation::cur());
            let out_cur = meta.query_advice(out, Rotation::cur());
            let committed = meta.query_instance(committed_instance, Rotation::cur());
            let public = meta.query_instance(public_instance, Rotation::cur());

            let mut balance = a_cur.clone() + b_cur + public + committed - out_cur.clone();
            if let Some(scale) = fixed_scale {
                balance = meta.query_fixed(scale, Rotation::cur()) * balance;
            }

            let mut constraints = vec![("public balance", balance)];
            if spec.next_rotation {
                constraints.push((
                    "next rotation",
                    meta.query_advice(a, Rotation::next())
                        - a_cur
                        - Expression::Constant(F::from(spec.tag + 7)),
                ));
            }
            if let Some(phase2) = phase2 {
                constraints.push((
                    "second phase",
                    meta.query_advice(phase2, Rotation::cur())
                        - out_cur
                        - Expression::Constant(F::from(spec.tag + 23)),
                ));
            }

            if spec.additive_selector {
                Constraints::with_additive_selector(selector, constraints)
            } else {
                Constraints::with_selector(selector, constraints)
            }
        });

        if let Some(table) = lookup_table {
            meta.lookup_any("shape-fuzz lookup", Some(selector), |meta| {
                vec![(
                    meta.query_advice(a, Rotation::cur()),
                    meta.query_fixed(table, Rotation::cur()),
                )]
            });
        }

        ShapeFuzzConfig {
            a,
            b,
            out,
            phase2,
            fixed_scale,
            lookup_table,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "shape-fuzz witness",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "a", config.a, 0, || Value::known(self.a))?;
                region.assign_advice(|| "b", config.b, 0, || Value::known(self.b))?;
                region.assign_advice(|| "out", config.out, 0, || Value::known(self.out()))?;

                if self.spec.next_rotation {
                    region.assign_advice(
                        || "a next",
                        config.a,
                        1,
                        || Value::known(self.next_a()),
                    )?;
                }
                if let Some(column) = config.phase2 {
                    region.assign_advice(
                        || "second phase value",
                        column,
                        0,
                        || Value::known(self.phase2_value()),
                    )?;
                }
                if let Some(column) = config.fixed_scale {
                    region.assign_fixed(|| "fixed scale", column, 0, || Value::known(F::ONE))?;
                }
                if let Some(column) = config.lookup_table {
                    region.assign_fixed(
                        || "lookup table value",
                        column,
                        0,
                        || Value::known(self.a),
                    )?;
                }

                if self.spec.permutation {
                    let copied = region.assign_advice(
                        || "permutation source",
                        config.a,
                        2,
                        || Value::known(self.b),
                    )?;
                    copied.copy_advice(|| "permutation target", &mut region, config.b, 3)?;
                }

                Ok(())
            },
        )
    }
}

#[test]
fn lookup_shape_verifier_compiles_with_native_lookup_callback() {
    if !shape_fuzz_inputs_available_for_evm() {
        return;
    }
    if env::var("HALO2_SOLIDITY_QUOTIENT_NATIVE_LOOKUP")
        .ok()
        .is_some_and(|value| value == "0")
    {
        eprintln!("skipping native lookup compile test: native lookup disabled by environment");
        return;
    }

    let case = ShapeFuzzCase {
        name: "native lookup compile",
        k: 5,
        seed: 303,
        spec: ShapeFuzzSpec {
            second_phase: true,
            lookup: true,
            fixed_scale: true,
            tag: 3,
            ..ShapeFuzzSpec::default()
        },
    };
    let circuit = ShapeFuzzCircuit::new(case.spec, case.seed);
    let mut setup_rng = ChaCha8Rng::seed_from_u64(case.seed ^ 0x5eed_5eed);
    let params = PoseidonParams::unsafe_setup(case.k, &mut setup_rng);
    let vk = keygen_vk_with_k::<F, KZGCommitmentScheme<Bls12>, _>(&params, &circuit, case.k)
        .unwrap_or_else(|err| panic!("shape fuzz `{}` vk generation failed: {err:?}", case.name));

    let generator = SolidityGenerator::new(&params, &vk, 1, 1);
    let (verifier_solidity, vk_solidity) = generator
        .render_separately()
        .unwrap_or_else(|err| panic!("shape fuzz `{}` render failed: {err:?}", case.name));

    assert!(
        verifier_solidity.contains("case 0x1f"),
        "lookup verifier should include the native lookup VM callback"
    );
    assert!(
        verifier_solidity.contains("q_lookup_f"),
        "lookup verifier should include the structured lookup callback body"
    );

    assert!(!compile_solidity(verifier_solidity).is_empty());
    assert!(!compile_solidity(vk_solidity).is_empty());
}

#[test]
fn supported_shape_circuit_fuzz_e2e() {
    if !shape_fuzz_inputs_available_for_evm() {
        return;
    }

    let cases = [
        ShapeFuzzCase {
            name: "simple-selector current-row fixed-scale",
            k: 5,
            seed: 101,
            spec: ShapeFuzzSpec {
                fixed_scale: true,
                tag: 1,
                ..ShapeFuzzSpec::default()
            },
        },
        ShapeFuzzCase {
            name: "next-rotation permutation",
            k: 5,
            seed: 202,
            spec: ShapeFuzzSpec {
                next_rotation: true,
                permutation: true,
                tag: 2,
                ..ShapeFuzzSpec::default()
            },
        },
        ShapeFuzzCase {
            name: "second-phase lookup",
            k: 5,
            seed: 303,
            spec: ShapeFuzzSpec {
                second_phase: true,
                lookup: true,
                fixed_scale: true,
                tag: 3,
                ..ShapeFuzzSpec::default()
            },
        },
        ShapeFuzzCase {
            name: "trash-additive selector with lookup",
            k: 5,
            seed: 404,
            spec: ShapeFuzzSpec {
                next_rotation: true,
                lookup: true,
                additive_selector: true,
                fixed_scale: true,
                tag: 4,
                ..ShapeFuzzSpec::default()
            },
        },
    ];

    let requested = env::var("SHAPE_FUZZ_CASES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(cases.len())
        .min(cases.len());

    #[cfg(feature = "rust-verifier-trace")]
    let mut compared_selector_folds = false;
    for case in cases.iter().take(requested) {
        let case_compared_selector_folds = run_supported_shape_fuzz_case(case);
        #[cfg(feature = "rust-verifier-trace")]
        {
            compared_selector_folds |= case_compared_selector_folds;
        }
        #[cfg(not(feature = "rust-verifier-trace"))]
        {
            let _ = case_compared_selector_folds;
        }
    }

    #[cfg(feature = "rust-verifier-trace")]
    if requested > 0 {
        assert!(
            compared_selector_folds,
            "shape fuzz trace suite should include at least one selector-fold comparison"
        );
    }
}

fn run_supported_shape_fuzz_case(case: &ShapeFuzzCase) -> bool {
    let circuit = ShapeFuzzCircuit::new(case.spec, case.seed);
    let mut setup_rng = ChaCha8Rng::seed_from_u64(case.seed ^ 0x5eed_5eed);
    let params = PoseidonParams::unsafe_setup(case.k, &mut setup_rng);
    let vk = keygen_vk_with_k::<F, KZGCommitmentScheme<Bls12>, _>(&params, &circuit, case.k)
        .unwrap_or_else(|err| panic!("shape fuzz `{}` vk generation failed: {err:?}", case.name));
    let pk = keygen_pk(vk, &circuit)
        .unwrap_or_else(|err| panic!("shape fuzz `{}` pk generation failed: {err:?}", case.name));

    let committed = [F::ZERO];
    let public = [circuit.public_instance()];
    let all_instance_columns: [&[F]; 2] = [&committed, &public];
    let mut proof_rng = ChaCha8Rng::seed_from_u64(case.seed ^ 0x0bad_f00d);
    let mut transcript = CircuitTranscript::<sha3::Keccak256>::init();
    create_proof::<F, KZGCommitmentScheme<Bls12>, _, _>(
        &params,
        &pk,
        std::slice::from_ref(&circuit),
        1,
        &[&all_instance_columns],
        &mut proof_rng,
        &mut transcript,
    )
    .unwrap_or_else(|err| {
        panic!(
            "shape fuzz `{}` proof generation failed: {err:?}",
            case.name
        )
    });
    let compressed_proof = transcript.finalize();

    let committed_pi = [G1Projective::identity()];
    let public_columns: [&[F]; 1] = [&public];
    let mut transcript = CircuitTranscript::<sha3::Keccak256>::init_from_bytes(&compressed_proof);
    let guard = prepare::<F, KZGCommitmentScheme<Bls12>, CircuitTranscript<sha3::Keccak256>>(
        pk.get_vk(),
        &[&committed_pi],
        &[&public_columns],
        &mut transcript,
    )
    .unwrap_or_else(|err| panic!("shape fuzz `{}` native prepare failed: {err:?}", case.name));
    transcript.assert_empty().unwrap_or_else(|_| {
        panic!(
            "shape fuzz `{}` native transcript had trailing bytes",
            case.name
        )
    });
    guard
        .verify(&params.verifier_params())
        .unwrap_or_else(|err| panic!("shape fuzz `{}` native verify failed: {err:?}", case.name));

    let generator = SolidityGenerator::new(&params, pk.get_vk(), public.len(), 1);
    let (verifier_solidity, vk_solidity) = generator
        .render_separately()
        .unwrap_or_else(|err| panic!("shape fuzz `{}` render failed: {err:?}", case.name));
    let repacked_proof = generator.repack_compressed_proof(&compressed_proof);
    let mut deployed = deploy_separate_verifier_from_sources(&verifier_solidity, &vk_solidity);

    assert_solidity_accepts(
        call_deployed_verifier(&mut deployed, &repacked_proof, &public),
        &format!("shape fuzz `{}` valid proof", case.name),
    );

    #[cfg(feature = "rust-verifier-trace")]
    let compared_selector_folds = assert_shape_fuzz_trace_matches_native_midfall(
        case,
        &params,
        pk.get_vk(),
        &generator,
        &compressed_proof,
        &repacked_proof,
        &public,
    );
    #[cfg(not(feature = "rust-verifier-trace"))]
    let compared_selector_folds = false;

    let mut wrong_public = public.to_vec();
    wrong_public[0] += F::ONE;
    assert_solidity_rejects(
        call_deployed_verifier(&mut deployed, &repacked_proof, &wrong_public),
        &format!("shape fuzz `{}` wrong public input", case.name),
    );

    let mut bad_proof = repacked_proof.clone();
    let mutation_idx = bad_proof.len() / 2;
    bad_proof[mutation_idx] ^= 0x01;
    assert_solidity_rejects(
        call_deployed_verifier(&mut deployed, &bad_proof, &public),
        &format!(
            "shape fuzz `{}` mutated proof byte {mutation_idx}",
            case.name
        ),
    );

    compared_selector_folds
}

fn shape_fuzz_inputs_available_for_evm() -> bool {
    if !env_flag_enabled(RUN_EVM_TESTS_ENV) {
        eprintln!("skipping supported-shape circuit fuzz: set {RUN_EVM_TESTS_ENV}=1 to run it");
        return false;
    }
    if !solc_available() {
        eprintln!("skipping supported-shape circuit fuzz: solc not found");
        return false;
    }
    true
}

#[cfg(feature = "rust-verifier-trace")]
fn assert_shape_fuzz_trace_matches_native_midfall(
    case: &ShapeFuzzCase,
    params: &PoseidonParams,
    vk: &midnight_proofs::plonk::VerifyingKey<F, KZGCommitmentScheme<Bls12>>,
    generator: &SolidityGenerator<'_>,
    compressed_proof: &[u8],
    repacked_proof: &[u8],
    public: &[F],
) -> bool {
    use midnight_proofs::plonk::solidity_trace;

    solidity_trace::start();
    let committed_pi = [G1Projective::identity()];
    let public_columns: [&[F]; 1] = [public];
    let mut transcript = CircuitTranscript::<sha3::Keccak256>::init_from_bytes(compressed_proof);
    let guard = prepare::<F, KZGCommitmentScheme<Bls12>, CircuitTranscript<sha3::Keccak256>>(
        vk,
        &[&committed_pi],
        &[&public_columns],
        &mut transcript,
    )
    .unwrap_or_else(|err| {
        panic!(
            "shape fuzz `{}` native trace prepare failed: {err:?}",
            case.name
        )
    });
    transcript.assert_empty().unwrap_or_else(|_| {
        panic!(
            "shape fuzz `{}` native trace transcript had trailing bytes",
            case.name
        )
    });
    guard
        .verify(&params.verifier_params())
        .unwrap_or_else(|err| {
            panic!(
                "shape fuzz `{}` native trace guard failed: {err:?}",
                case.name
            )
        });
    let rust_trace = solidity_trace::take();

    let (trace_verifier_solidity, trace_vk_solidity) = generator
        .render_trace_separately()
        .unwrap_or_else(|err| panic!("shape fuzz `{}` trace render failed: {err:?}", case.name));
    let mut deployed =
        deploy_separate_verifier_from_sources(&trace_verifier_solidity, &trace_vk_solidity);
    let (_gas, output, logs) = deployed.evm.call_with_logs(
        deployed.verifier_address,
        encode_calldata(repacked_proof, public),
    );
    let expected_true = [vec![0u8; 31], vec![1]].concat();
    assert_eq!(
        output, expected_true,
        "shape fuzz `{}` trace verifier should accept the proof",
        case.name
    );

    let mut rust_by_id = BTreeMap::new();
    for event in rust_trace {
        assert!(
            rust_by_id
                .insert(event.id, (event.name, event.data))
                .is_none(),
            "shape fuzz `{}` duplicate Rust trace id {}",
            case.name,
            event.id
        );
    }
    let solidity_trace = parse_solidity_trace_logs(&logs);
    let has_selector_folds = rust_by_id
        .keys()
        .chain(solidity_trace.keys())
        .any(|id| (60_000..61_000).contains(id));
    assert_trace_equivalence_and_required_coverage(
        case.name,
        &rust_by_id,
        &solidity_trace,
        has_selector_folds,
    );
    has_selector_folds
}

#[cfg(feature = "rust-verifier-trace")]
fn assert_trace_equivalence_and_required_coverage(
    context: &str,
    rust_trace: &BTreeMap<u64, (&'static str, Vec<u8>)>,
    solidity_trace: &BTreeMap<u64, Vec<u8>>,
    require_selector_folds: bool,
) {
    let missing = rust_trace
        .keys()
        .filter(|id| !solidity_trace.contains_key(id))
        .copied()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{context}: Solidity trace is missing native Rust trace ids {missing:?}"
    );

    let unexpected = solidity_trace
        .keys()
        .filter(|id| !rust_trace.contains_key(id))
        .copied()
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "{context}: Solidity trace emitted ids without a native Rust oracle {unexpected:?}"
    );

    assert_required_diff_trace_coverage_with_options(
        rust_trace,
        solidity_trace,
        require_selector_folds,
    );

    for (id, solidity_data) in solidity_trace {
        let (name, rust_data) = rust_trace
            .get(id)
            .expect("missing Solidity trace ids were checked above");
        assert_eq!(
            rust_data,
            solidity_data,
            "{context}: trace mismatch id={id} name={name}: rust=0x{} solidity=0x{}",
            hex::encode(rust_data),
            hex::encode(solidity_data),
        );
    }
}

#[cfg(not(feature = "rust-verifier-trace"))]
#[test]
fn evm_gate_requires_native_solidity_trace_feature() {
    if env_flag_enabled(RUN_EVM_TESTS_ENV) {
        panic!(
            "{RUN_EVM_TESTS_ENV}=1 now requires the `rust-verifier-trace` feature so native/Solidity trace equivalence is part of the EVM gate"
        );
    }
}

#[test]
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
fn mutated_separate_vk_contract_is_rejected() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let mut baseline = deployed_separate_verifier(&fixture);
    assert_deployed_call_accepts(
        &mut baseline,
        &fixture,
        &fixture.proof,
        "valid proof before mutated separate vk",
    );

    let mutated_vk_solidity = mutate_first_large_hex_literal(&fixture.vk_solidity, 0);
    assert_separate_verifier_rejects_vk_mutation(
        &fixture.separate_verifier_solidity,
        &mutated_vk_solidity,
        &fixture.proof,
        &fixture.instances,
        "mutated separate vk",
    );
}

#[test]
fn vk_payload_section_mutations_are_rejected() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_poseidon_vk_sources_fixture();
    let sections = [
        ("header", "vk_digest"),
        ("quotient constants", "quotient_const"),
        ("quotient program", "quotient_program"),
        ("fixed commitments", "fixed_comms[0].x_hi"),
        ("permutation commitments", "permutation_comms[0].x_hi"),
    ];

    for (section, marker) in sections {
        assert!(
            fixture.vk_solidity.contains(marker),
            "fixture VK source missing {section} marker `{marker}`"
        );
        let mutated_vk_solidity =
            mutate_value_hex_literal_on_line_containing(&fixture.vk_solidity, marker);
        assert_separate_verifier_rejects_vk_dependency(
            &fixture.separate_verifier_solidity,
            &mutated_vk_solidity,
            &format!("mutated VK payload section: {section}"),
        );
    }
}

#[test]
fn pinned_quotient_verifier_rejects_wrong_vk_and_quotient_contracts() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let wrong_vk_solidity = mutate_first_large_hex_literal(&fixture.vk_solidity, 0);
    let wrong_quotient_solidity =
        mutate_first_large_hex_literal(&fixture.quotient_evaluator_solidity, 0);

    assert_pinned_quotient_constructor_rejects(
        &fixture.quotient_verifier_solidity,
        &wrong_vk_solidity,
        &fixture.quotient_evaluator_solidity,
        "wrong VK runtime hash",
    );
    assert_pinned_quotient_constructor_rejects(
        &fixture.quotient_verifier_solidity,
        &fixture.vk_solidity,
        &wrong_quotient_solidity,
        "wrong quotient runtime hash",
    );

    let verifier_creation_code = compile_solidity(&fixture.quotient_verifier_solidity);
    let vk_creation_code = compile_solidity(&fixture.vk_solidity);
    let quotient_creation_code = compile_solidity(&fixture.quotient_evaluator_solidity);
    assert_pinned_quotient_constructor_rejects_address_args(
        &verifier_creation_code,
        &quotient_creation_code,
        &quotient_creation_code,
        "quotient evaluator supplied as VK",
    );
    assert_pinned_quotient_constructor_rejects_address_args(
        &verifier_creation_code,
        &vk_creation_code,
        &vk_creation_code,
        "VK supplied as quotient evaluator",
    );
}

#[test]
fn verifier_constructor_rejects_missing_or_mismatched_eip2537_precompiles() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    for (name, needle, replacement) in [
        (
            "missing G1ADD precompile",
            "staticcall(50000, 0x0b",
            "staticcall(50000, 0x12",
        ),
        (
            "G1MSM routed to G1ADD",
            "staticcall(60000, 0x0c",
            "staticcall(60000, 0x0b",
        ),
        (
            "pairing routed to G1MSM",
            "staticcall(120000, 0x0f",
            "staticcall(120000, 0x0c",
        ),
    ] {
        let verifier_solidity = replace_required_precompile_staticcall(
            &fixture.quotient_verifier_solidity,
            needle,
            replacement,
        );
        assert_pinned_quotient_constructor_rejects(
            &verifier_solidity,
            &fixture.vk_solidity,
            &fixture.quotient_evaluator_solidity,
            name,
        );
    }
}

#[test]
fn production_renders_do_not_emit_gas_checkpoints() {
    if crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED {
        return;
    }
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    for (name, source) in [
        ("embedded", fixture.embedded_verifier_solidity.as_str()),
        ("separate", fixture.separate_verifier_solidity.as_str()),
        (
            "quotient-separated",
            fixture.quotient_verifier_solidity.as_str(),
        ),
    ] {
        assert!(
            !source.contains("function gas_checkpoint"),
            "{name} production render unexpectedly defines gas_checkpoint"
        );
        assert!(
            !source.contains("log1("),
            "{name} production render unexpectedly emits LOG1"
        );
        assert!(
            source.contains(") external view returns (bool)"),
            "{name} production render should keep verifyProof external view"
        );
    }
}

#[test]
fn standard_plonk_render_is_deterministic_for_same_seed() {
    if !poseidon_inputs_available_for_evm() {
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
fn compile_solidity_is_deterministic_for_same_source() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let bytecode_a = compile_solidity(&fixture.embedded_verifier_solidity);
    let bytecode_b = compile_solidity(&fixture.embedded_verifier_solidity);

    assert_eq!(bytecode_a, bytecode_b);
}

#[test]
fn poseidon_verifier_variants_compile_with_pinned_solc() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let variants = [
        (
            "embedded verifier",
            fixture.embedded_verifier_solidity.as_str(),
        ),
        (
            "embedded trace verifier",
            fixture.embedded_trace_verifier_solidity.as_str(),
        ),
        (
            "embedded gas verifier",
            fixture.embedded_gas_verifier_solidity.as_str(),
        ),
        (
            "separate verifier",
            fixture.separate_verifier_solidity.as_str(),
        ),
        (
            "separate gas verifier",
            fixture.gas_separate_verifier_solidity.as_str(),
        ),
        (
            "separate trace verifier",
            fixture.trace_verifier_solidity.as_str(),
        ),
        ("separate VK", fixture.vk_solidity.as_str()),
        ("separate trace VK", fixture.trace_vk_solidity.as_str()),
        (
            "external quotient verifier",
            fixture.quotient_verifier_solidity.as_str(),
        ),
        (
            "external quotient evaluator",
            fixture.quotient_evaluator_solidity.as_str(),
        ),
        (
            "external quotient trace verifier",
            fixture.trace_quotient_verifier_solidity.as_str(),
        ),
        (
            "external quotient trace evaluator",
            fixture.trace_quotient_evaluator_solidity.as_str(),
        ),
        (
            "external quotient trace VK",
            fixture.trace_quotient_vk_solidity.as_str(),
        ),
    ];

    for (name, source) in variants {
        let bytecode = std::panic::catch_unwind(AssertUnwindSafe(|| compile_solidity(source)))
            .unwrap_or_else(|_| panic!("{name} did not compile"));
        assert!(!bytecode.is_empty(), "{name} compiled to empty bytecode");
    }
}

#[cfg(feature = "rust-verifier-trace")]
#[test]
fn native_midfall_verifier_trace_matches_solidity_trace() {
    use group::Group;
    use midnight_curves::{Bls12, G1Projective};
    use midnight_proofs::{
        plonk::{prepare, solidity_trace},
        poly::{commitment::Guard, kzg::KZGCommitmentScheme},
        transcript::{CircuitTranscript, Transcript},
    };

    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();

    solidity_trace::start();
    let mut transcript =
        CircuitTranscript::<sha3::Keccak256>::init_from_bytes(&fixture.compressed_proof);
    let committed_pi = vec![G1Projective::identity()];
    let public_columns: [&[F]; 1] = [&fixture.instances];
    let guard = prepare::<F, KZGCommitmentScheme<Bls12>, CircuitTranscript<sha3::Keccak256>>(
        fixture.vk.vk(),
        &[&committed_pi],
        &[&public_columns],
        &mut transcript,
    )
    .expect("native prepare succeeds");
    transcript
        .assert_empty()
        .expect("native transcript consumes proof");
    guard
        .verify(&fixture.params_verifier)
        .expect("native guard verifies");
    let rust_trace = solidity_trace::take();

    let mut evm = Evm::default();
    let vk_address = evm.create(compile_solidity(&fixture.trace_vk_solidity));
    let verifier_address = evm.create_with_address_arg(
        compile_solidity(&fixture.trace_verifier_solidity),
        vk_address,
    );
    let (_gas, output, logs) = evm.call_with_logs(
        verifier_address,
        encode_calldata(&fixture.proof, &fixture.instances),
    );
    let solidity_returned_success = output == [vec![0; 31], vec![1]].concat();
    let solidity_trace = parse_solidity_trace_logs(&logs);

    let mut rust_by_id = BTreeMap::new();
    for event in rust_trace {
        assert!(
            rust_by_id
                .insert(event.id, (event.name, event.data))
                .is_none(),
            "duplicate Rust trace id {}",
            event.id
        );
    }
    assert_required_diff_trace_coverage(&rust_by_id, &solidity_trace);

    assert_eq!(
        rust_by_id.keys().copied().collect::<Vec<_>>(),
        solidity_trace.keys().copied().collect::<Vec<_>>(),
        "Rust/Solidity trace ID sets differ"
    );

    for (id, solidity_data) in solidity_trace {
        let (name, rust_data) = rust_by_id.get(&id).expect("Rust trace id present");
        assert_eq!(
            rust_data,
            &solidity_data,
            "trace mismatch id={id} name={name}: rust=0x{} solidity=0x{}",
            hex::encode(rust_data),
            hex::encode(&solidity_data),
        );
    }

    assert!(
        solidity_returned_success,
        "trace verifier returned failure after matching Rust trace"
    );
}

#[test]
fn trace_verifiers_revert_on_final_pairing_failure() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let mut bad_instances = fixture.instances.clone();
    bad_instances[0] += F::ONE;

    assert_solidity_rejects(
        call_embedded_verifier(
            &fixture.embedded_trace_verifier_solidity,
            &fixture.proof,
            &bad_instances,
        ),
        "embedded trace verifier wrong instance",
    );
    assert_solidity_rejects(
        call_separate_verifier(
            &fixture.trace_verifier_solidity,
            &fixture.trace_vk_solidity,
            &fixture.proof,
            &bad_instances,
        ),
        "separate trace verifier wrong instance",
    );
}

#[cfg(feature = "rust-verifier-trace")]
fn parse_solidity_trace_logs(logs: &[revm::primitives::Log]) -> BTreeMap<u64, Vec<u8>> {
    let mut trace = BTreeMap::new();

    for log in logs {
        let topics = log.data.topics();
        assert_eq!(topics.len(), 1, "trace log must have one topic");

        let data = log.data.data.as_ref().to_vec();
        if data.is_empty() {
            continue;
        }

        let id = trace_topic_id(topics[0]);
        assert!(
            trace.insert(id, data).is_none(),
            "duplicate Solidity trace id {id}"
        );
    }

    trace
}

#[cfg(feature = "rust-verifier-trace")]
fn trace_topic_id(topic: B256) -> u64 {
    let bytes = topic.as_slice();
    u64::from_be_bytes(bytes[24..32].try_into().expect("topic is 32 bytes"))
}

#[cfg(feature = "rust-verifier-trace")]
fn assert_required_diff_trace_coverage(
    rust_trace: &BTreeMap<u64, (&'static str, Vec<u8>)>,
    solidity_trace: &BTreeMap<u64, Vec<u8>>,
) {
    assert_required_diff_trace_coverage_with_options(rust_trace, solidity_trace, true);
}

#[cfg(feature = "rust-verifier-trace")]
fn assert_required_diff_trace_coverage_with_options(
    rust_trace: &BTreeMap<u64, (&'static str, Vec<u8>)>,
    solidity_trace: &BTreeMap<u64, Vec<u8>>,
    require_selector_folds: bool,
) {
    for (name, id) in [
        ("theta challenge", 7),
        ("beta challenge", 8),
        ("gamma challenge", 9),
        ("y challenge", 10),
        ("x challenge", 11),
        ("x1 challenge", 13),
        ("x2 challenge", 14),
        ("x3 challenge", 15),
        ("x4 challenge", 16),
        ("quotient numerator", 36),
        ("f_eval", 31),
        ("final MSM commitment", 33),
        ("pairing lhs input", 27),
        ("pairing rhs input", 28),
        ("final pairing result", 35),
    ] {
        assert_trace_id_present(rust_trace, solidity_trace, id, name);
    }

    assert_trace_range_present(
        rust_trace,
        solidity_trace,
        30_000..40_000,
        "quotient identity evaluations",
    );
    assert_trace_range_present(
        rust_trace,
        solidity_trace,
        40_000..41_000,
        "PCS q_com point-set commitments",
    );
    assert_trace_range_present(
        rust_trace,
        solidity_trace,
        41_000..42_000,
        "serialized PCS point sets",
    );
    if require_selector_folds {
        assert_trace_range_present(rust_trace, solidity_trace, 60_000..61_000, "selector folds");
    }
}

#[cfg(feature = "rust-verifier-trace")]
fn assert_trace_id_present(
    rust_trace: &BTreeMap<u64, (&'static str, Vec<u8>)>,
    solidity_trace: &BTreeMap<u64, Vec<u8>>,
    id: u64,
    name: &str,
) {
    assert!(
        rust_trace.contains_key(&id),
        "Rust trace missing required {name} id {id}"
    );
    assert!(
        solidity_trace.contains_key(&id),
        "Solidity trace missing required {name} id {id}"
    );
}

#[cfg(feature = "rust-verifier-trace")]
fn assert_trace_range_present(
    rust_trace: &BTreeMap<u64, (&'static str, Vec<u8>)>,
    solidity_trace: &BTreeMap<u64, Vec<u8>>,
    range: std::ops::Range<u64>,
    name: &str,
) {
    assert!(
        rust_trace.keys().any(|id| range.contains(id)),
        "Rust trace missing required {name} in id range {range:?}"
    );
    assert!(
        solidity_trace.keys().any(|id| range.contains(id)),
        "Solidity trace missing required {name} in id range {range:?}"
    );
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
    compressed_proof: Vec<u8>,
    proof: Vec<u8>,
    scalar_layout: crate::codegen::RepackedProofScalarLayout,
    instances: Vec<F>,
    params_verifier: PoseidonVerifierParams,
    vk: MidnightVK,
    embedded_verifier_solidity: String,
    embedded_trace_verifier_solidity: String,
    embedded_gas_verifier_solidity: String,
    separate_verifier_solidity: String,
    gas_separate_verifier_solidity: String,
    vk_solidity: String,
    quotient_verifier_solidity: String,
    quotient_evaluator_solidity: String,
    trace_quotient_evaluator_solidity: String,
    trace_quotient_verifier_solidity: String,
    trace_quotient_vk_solidity: String,
    #[allow(dead_code)]
    trace_verifier_solidity: String,
    #[allow(dead_code)]
    trace_vk_solidity: String,
}

#[derive(Clone)]
struct PoseidonVkSourcesFixture {
    separate_verifier_solidity: String,
    vk_solidity: String,
}

fn create_poseidon_vk_sources_fixture() -> PoseidonVkSourcesFixture {
    static FIXTURE: OnceLock<PoseidonVkSourcesFixture> = OnceLock::new();
    FIXTURE
        .get_or_init(load_poseidon_vk_sources_fixture)
        .clone()
}

fn load_poseidon_vk_sources_fixture() -> PoseidonVkSourcesFixture {
    let srs_dir = srs_dir();
    env::set_var("SRS_DIR", &srs_dir);

    let relation = PoseidonExample;
    let srs = srs_for_test(&relation, Some(POSEIDON_K));
    let vk = setup_vk(&srs, &relation);
    assert_eq!(vk.k() as u32, POSEIDON_K, "unexpected Poseidon VK k");

    let generator = SolidityGenerator::new(&srs, vk.vk(), 1, 1);
    let (separate_verifier_solidity, vk_solidity) =
        generator.render_separately().expect("separate render");

    PoseidonVkSourcesFixture {
        separate_verifier_solidity,
        vk_solidity,
    }
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

    let generator = SolidityGenerator::new(&srs, vk.vk(), 1, 1);
    let embedded_verifier_solidity = generator.render().expect("embedded render");
    let embedded_trace_verifier_solidity = generator.render_trace().expect("embedded trace render");
    let embedded_gas_verifier_solidity = generator
        .render_with_gas_checkpoints()
        .expect("embedded gas render");
    let (separate_verifier_solidity, vk_solidity) =
        generator.render_separately().expect("separate render");
    let (gas_separate_verifier_solidity, gas_vk_solidity) = generator
        .render_with_gas_checkpoints_separately()
        .expect("separate gas render");
    assert_eq!(
        vk_solidity, gas_vk_solidity,
        "plain and gas-checkpoint render paths must share the same VK"
    );
    let quotient_evaluator_solidity = generator
        .render_quotient_evaluator()
        .expect("quotient evaluator render");
    let quotient_creation_code = compile_solidity(&quotient_evaluator_solidity);
    let mut pin_evm = Evm::default();
    let quotient_address = pin_evm.create(quotient_creation_code);
    let quotient_runtime_size = pin_evm.code_size(quotient_address);
    let quotient_codehash = pin_evm.code_hash(quotient_address);
    let trace_quotient_evaluator_solidity = generator
        .render_trace_quotient_evaluator()
        .expect("trace quotient evaluator render");
    let trace_quotient_creation_code = compile_solidity(&trace_quotient_evaluator_solidity);
    let mut trace_pin_evm = Evm::default();
    let trace_quotient_address = trace_pin_evm.create(trace_quotient_creation_code);
    let trace_quotient_runtime_size = trace_pin_evm.code_size(trace_quotient_address);
    let trace_quotient_codehash = trace_pin_evm.code_hash(trace_quotient_address);
    let (quotient_verifier_solidity, quotient_vk_solidity, pinned_quotient_solidity) = generator
        .render_separately_with_pinned_quotient(quotient_runtime_size, quotient_codehash)
        .expect("separate pinned render with quotient evaluator");
    let (trace_quotient_verifier_solidity, trace_quotient_vk_solidity, trace_pinned_quotient) =
        generator
            .render_trace_separately_with_pinned_quotient(
                trace_quotient_runtime_size,
                trace_quotient_codehash,
            )
            .expect("trace pinned render with quotient evaluator");
    assert_eq!(
        quotient_evaluator_solidity, pinned_quotient_solidity,
        "pinning the quotient evaluator must not change the evaluator source"
    );
    assert_eq!(
        trace_quotient_evaluator_solidity, trace_pinned_quotient,
        "trace pinning must not change the trace quotient evaluator source"
    );
    assert_eq!(
        vk_solidity, quotient_vk_solidity,
        "plain and quotient-separated render paths must share the same VK"
    );
    assert_eq!(
        vk_solidity, trace_quotient_vk_solidity,
        "plain and trace quotient-separated render paths must share the same VK"
    );
    let (trace_verifier_solidity, trace_vk_solidity) =
        generator.render_trace_separately().expect("trace render");
    let proof = generator.repack_compressed_proof(&compressed_proof);
    let scalar_layout = generator.repacked_proof_scalar_layout_for_test();
    let params_verifier = srs.verifier_params();

    PropertyPoseidonFixture {
        compressed_proof,
        proof,
        scalar_layout,
        instances: vec![instance],
        params_verifier,
        vk,
        embedded_verifier_solidity,
        embedded_trace_verifier_solidity,
        embedded_gas_verifier_solidity,
        separate_verifier_solidity,
        gas_separate_verifier_solidity,
        vk_solidity,
        quotient_verifier_solidity,
        quotient_evaluator_solidity,
        trace_quotient_evaluator_solidity,
        trace_quotient_verifier_solidity,
        trace_quotient_vk_solidity,
        trace_verifier_solidity,
        trace_vk_solidity,
    }
}

#[test]
fn every_proof_scalar_rejects_fr_modulus() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let r_be = fr_modulus_be_word();
    let scalar_offsets = proof_scalar_offsets(&fixture);
    assert!(
        !scalar_offsets.is_empty(),
        "fixture proof should expose scalar fields to range-check"
    );

    let mut evm = deployed_separate_verifier(&fixture);
    if !deployed_call_accepts(&mut evm, &fixture, &fixture.proof, "valid proof") {
        return;
    }

    for (name, offset) in scalar_offsets {
        let mut bad_proof = fixture.proof.clone();
        bad_proof[offset..offset + 0x20].copy_from_slice(&r_be);
        assert_deployed_call_rejects(
            &mut evm,
            &fixture,
            &bad_proof,
            &format!("{name} scalar equal to Fr modulus at proof offset {offset}"),
        );
    }
}

#[test]
fn every_proof_scalar_rejects_boundary_values() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let scalar_offsets = proof_scalar_offsets(&fixture);
    assert!(
        !scalar_offsets.is_empty(),
        "fixture proof should expose scalar fields to mutate"
    );

    let mut evm = deployed_separate_verifier(&fixture);
    if !deployed_call_accepts(&mut evm, &fixture, &fixture.proof, "valid proof") {
        return;
    }

    let r = fr_modulus_u256();
    let static_variants = [
        ("zero", U256::from(0u64).to_be_bytes::<32>()),
        ("one", U256::from(1u64).to_be_bytes::<32>()),
        ("Fr_minus_one", (r - U256::from(1u64)).to_be_bytes::<32>()),
    ];

    for (name, offset) in scalar_offsets {
        let original_word: [u8; 32] = fixture.proof[offset..offset + 0x20]
            .try_into()
            .expect("proof scalar word");
        let original = U256::from_be_bytes(original_word);
        let original_plus_r = original + r;

        for (variant, word) in static_variants
            .into_iter()
            .chain([("original_plus_Fr", original_plus_r.to_be_bytes::<32>())])
        {
            if word == original_word {
                continue;
            }
            let mut bad_proof = fixture.proof.clone();
            bad_proof[offset..offset + 0x20].copy_from_slice(&word);
            assert_deployed_call_rejects(
                &mut evm,
                &fixture,
                &bad_proof,
                &format!("{name} scalar replaced with {variant} at proof offset {offset}"),
            );
        }
    }
}

#[test]
fn representative_proof_section_mutations_are_rejected() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let sections = representative_proof_section_offsets(&fixture);
    assert!(
        !sections.is_empty(),
        "fixture should expose representative proof sections"
    );

    let mut evm = deployed_separate_verifier(&fixture);
    if !deployed_call_accepts(&mut evm, &fixture, &fixture.proof, "valid proof") {
        return;
    }

    for (section, offset) in sections {
        let mut bad_proof = fixture.proof.clone();
        bad_proof[offset] ^= 0x01;
        assert_deployed_call_rejects(
            &mut evm,
            &fixture,
            &bad_proof,
            &format!("mutated proof section `{section}` at proof offset {offset}"),
        );
    }
}

#[test]
fn separate_verifier_adversarial_calldata_variants_are_rejected() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let mut evm = deployed_separate_verifier(&fixture);
    let valid = encode_calldata(&fixture.proof, &fixture.instances);
    if !deployed_raw_call_accepts(&mut evm, valid.clone(), "valid separate-verifier calldata") {
        return;
    }

    let mut wrong_instances = fixture.instances.clone();
    wrong_instances[0] += F::ONE;
    assert_solidity_rejects(
        call_deployed_verifier(&mut evm, &fixture.proof, &wrong_instances),
        "wrong instance",
    );

    let r_be = fr_modulus_be_word();
    let mut noncanonical_instance = valid.clone();
    let instance_word_start = first_instance_word_start(&fixture.proof);
    noncanonical_instance[instance_word_start..instance_word_start + 0x20].copy_from_slice(&r_be);
    assert_solidity_rejects(
        call_deployed_verifier_raw(&mut evm, noncanonical_instance),
        "instance scalar equal to Fr modulus",
    );

    let mut endian_swapped_instance = valid.clone();
    let mut swapped_word: [u8; 32] = valid[instance_word_start..instance_word_start + 0x20]
        .try_into()
        .expect("instance word");
    swapped_word.reverse();
    if swapped_word == valid[instance_word_start..instance_word_start + 0x20] {
        swapped_word[31] ^= 0x01;
    }
    endian_swapped_instance[instance_word_start..instance_word_start + 0x20]
        .copy_from_slice(&swapped_word);
    assert_solidity_rejects(
        call_deployed_verifier_raw(&mut evm, endian_swapped_instance),
        "public input encoded with reversed endianness",
    );

    let mut trailing_bytes = valid.clone();
    trailing_bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    let mut proof_head_overlap = valid.clone();
    overwrite_u256_word(&mut proof_head_overlap, 0x04, 0x20);

    let mut proof_head_shifted_without_gap = valid.clone();
    overwrite_u256_word(&mut proof_head_shifted_without_gap, 0x04, 0x60);

    let mut instances_head_overlap = valid.clone();
    overwrite_u256_word(&mut instances_head_overlap, 0x24, 0x40);

    let mut instances_head_shifted = valid.clone();
    overwrite_u256_word(
        &mut instances_head_shifted,
        0x24,
        canonical_instances_head(&fixture.proof) as u64 + 0x20,
    );

    let shifted_valid_abi = calldata_with_shifted_dynamic_heads(&valid, &fixture.proof);

    for (name, calldata) in [
        ("trailing bytes", trailing_bytes),
        ("proof head overlaps ABI head", proof_head_overlap),
        (
            "proof head shifted without matching gap",
            proof_head_shifted_without_gap,
        ),
        ("instances head overlaps proof", instances_head_overlap),
        ("instances head shifted", instances_head_shifted),
        (
            "valid ABI with noncanonical dynamic offsets",
            shifted_valid_abi,
        ),
    ] {
        assert_solidity_rejects(call_deployed_verifier_raw(&mut evm, calldata), name);
    }
}

#[test]
fn verifier_rejects_when_x_is_forced_to_domain_root() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let forced_x_verifier =
        verifier_source_with_x_forced_to_one(&fixture.separate_verifier_solidity);
    let mut evm = deploy_separate_verifier_from_sources(&forced_x_verifier, &fixture.vk_solidity);

    assert_solidity_rejects(
        call_deployed_verifier(&mut evm, &fixture.proof, &fixture.instances),
        "verifier with x forced to domain root should hit zero Lagrange denominator",
    );
}

#[test]
fn every_proof_g1_rejects_noncanonical_coordinates() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let layout = proof_g1_layout(&fixture);

    assert_eq!(
        layout.compressed_offsets.len(),
        layout.repacked_offsets.len(),
        "native/Solidity proof G1 offset schedules must agree"
    );

    let native_bad = [0xffu8; 48];
    let mut evm = deployed_separate_verifier(&fixture);
    if !deployed_call_accepts(&mut evm, &fixture, &fixture.proof, "valid proof") {
        return;
    }

    for (idx, (&compressed_offset, &repacked_offset)) in layout
        .compressed_offsets
        .iter()
        .zip(layout.repacked_offsets.iter())
        .enumerate()
    {
        let mut bad_native = fixture.compressed_proof.clone();
        bad_native[compressed_offset..compressed_offset + 48].copy_from_slice(&native_bad);
        assert_native_poseidon_rejects(
            &fixture,
            &bad_native,
            &format!("native noncanonical G1 idx={idx} compressed_offset={compressed_offset}"),
        );

        let mut bad_solidity = fixture.proof.clone();
        // EIP-2537 padded G1 words require the top 16 bytes of x_hi/y_hi
        // to be zero. Set one padding byte so the Solidity canonicality
        // guard must reject before the point can enter the transcript.
        bad_solidity[repacked_offset] = 1;
        assert_deployed_call_rejects(
            &mut evm,
            &fixture,
            &bad_solidity,
            &format!("Solidity noncanonical G1 idx={idx} repacked_offset={repacked_offset}"),
        );
    }
}

#[test]
fn every_proof_g1_rejects_off_curve_coordinates() {
    if !poseidon_inputs_available_for_evm() {
        return;
    }

    let fixture = create_property_poseidon_fixture();
    let layout = proof_g1_layout(&fixture);
    let native_bad = compressed_off_curve_g1_bytes();
    let solidity_bad = eip2537_padded_off_curve_g1_bytes();

    let mut evm = deployed_separate_verifier(&fixture);
    if !deployed_call_accepts(&mut evm, &fixture, &fixture.proof, "valid proof") {
        return;
    }

    for (idx, (&compressed_offset, &repacked_offset)) in layout
        .compressed_offsets
        .iter()
        .zip(layout.repacked_offsets.iter())
        .enumerate()
    {
        let mut bad_native = fixture.compressed_proof.clone();
        bad_native[compressed_offset..compressed_offset + 48].copy_from_slice(&native_bad);
        assert_native_poseidon_rejects(
            &fixture,
            &bad_native,
            &format!("native off-curve G1 idx={idx} compressed_offset={compressed_offset}"),
        );

        let mut bad_solidity = fixture.proof.clone();
        bad_solidity[repacked_offset..repacked_offset + 128].copy_from_slice(&solidity_bad);
        assert_deployed_call_rejects(
            &mut evm,
            &fixture,
            &bad_solidity,
            &format!("Solidity off-curve G1 idx={idx} repacked_offset={repacked_offset}"),
        );
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
    let mut deployed = deployed_property_poseidon_verifier(&fixture, separate);
    assert_deployed_call_accepts(
        &mut deployed,
        &fixture,
        &fixture.proof,
        &format!("valid proof seed={seed} separate={separate}"),
    );
}

fn run_property_poseidon_wrong_instance_case(separate: bool, seed: u64) {
    let fixture = create_property_poseidon_fixture();
    let mut deployed = deployed_property_poseidon_verifier(&fixture, separate);
    assert_deployed_call_accepts(
        &mut deployed,
        &fixture,
        &fixture.proof,
        &format!("valid proof before wrong-instance mutation seed={seed} separate={separate}"),
    );

    let mut bad_instances = fixture.instances.clone();
    bad_instances[0] += F::ONE;

    let output = call_deployed_verifier(&mut deployed, &fixture.proof, &bad_instances);
    assert_solidity_rejects(
        output,
        &format!("wrong instance seed={seed} separate={separate}"),
    );
}

fn run_property_poseidon_malleated_proof_case(separate: bool, seed: u64, bit_idx: usize) {
    let fixture = create_property_poseidon_fixture();
    let mut deployed = deployed_property_poseidon_verifier(&fixture, separate);
    assert_deployed_call_accepts(
        &mut deployed,
        &fixture,
        &fixture.proof,
        &format!("valid proof before proof mutation seed={seed} separate={separate}"),
    );

    let mut bad_proof = fixture.proof.clone();
    let byte_idx = bit_idx / 8 % bad_proof.len();
    let bit_mask = 1u8 << (bit_idx % 8);
    bad_proof[byte_idx] ^= bit_mask;

    let output = call_deployed_verifier(&mut deployed, &bad_proof, &fixture.instances);
    assert_solidity_rejects(
        output,
        &format!("malleated proof seed={seed} separate={separate}"),
    );
}

fn run_property_poseidon_wrong_vk_case(seed: u64) {
    let fixture = create_property_poseidon_fixture();
    let mut baseline = deployed_separate_verifier(&fixture);
    assert_deployed_call_accepts(
        &mut baseline,
        &fixture,
        &fixture.proof,
        &format!("valid proof before wrong-vk mutation seed={seed}"),
    );

    let mutated_vk_solidity = mutate_first_large_hex_literal(&fixture.vk_solidity, seed as usize);
    assert_separate_verifier_rejects_vk_mutation(
        &fixture.separate_verifier_solidity,
        &mutated_vk_solidity,
        &fixture.proof,
        &fixture.instances,
        &format!("wrong vk seed={seed}"),
    );
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

    assert_separate_verifier_rejects_vk_mutation(
        &fixture.separate_verifier_solidity,
        &mutate_vk_digest_literal_only(&fixture.vk_solidity),
        &fixture.proof,
        &fixture.instances,
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
    let mut deployed = deploy_embedded_verifier_from_source(verifier_solidity);
    call_deployed_verifier_raw(&mut deployed, calldata)
}

fn call_separate_verifier(
    verifier_solidity: &str,
    vk_solidity: &str,
    proof: &[u8],
    instances: &[F],
) -> Result<Vec<u8>, ()> {
    let mut deployed = deploy_separate_verifier_from_sources(verifier_solidity, vk_solidity);
    call_deployed_verifier(&mut deployed, proof, instances)
}

fn assert_separate_verifier_rejects_vk_dependency(
    verifier_solidity: &str,
    vk_solidity: &str,
    context: &str,
) {
    let vk_creation_code = compile_solidity(vk_solidity);
    let verifier_creation_code = compile_solidity(verifier_solidity);
    let mut evm = Evm::default();
    let vk_address = evm.create(vk_creation_code);
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        evm.create_with_address_arg(verifier_creation_code, vk_address);
    }));
    assert!(
        result.is_err(),
        "separate verifier constructor accepted invalid VK dependency: {context}"
    );
}

fn assert_pinned_quotient_constructor_rejects(
    verifier_solidity: &str,
    vk_solidity: &str,
    quotient_solidity: &str,
    context: &str,
) {
    let verifier_creation_code = compile_solidity(verifier_solidity);
    let vk_creation_code = compile_solidity(vk_solidity);
    let quotient_creation_code = compile_solidity(quotient_solidity);
    assert_pinned_quotient_constructor_rejects_address_args(
        &verifier_creation_code,
        &vk_creation_code,
        &quotient_creation_code,
        context,
    );
}

fn assert_pinned_quotient_constructor_rejects_address_args(
    verifier_creation_code: &[u8],
    vk_arg_creation_code: &[u8],
    quotient_arg_creation_code: &[u8],
    context: &str,
) {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut evm = Evm::default();
        let vk_address = evm.create(vk_arg_creation_code.to_vec());
        let quotient_address = evm.create(quotient_arg_creation_code.to_vec());
        evm.create_with_two_address_args(
            verifier_creation_code.to_vec(),
            vk_address,
            quotient_address,
        );
    }));
    assert!(
        result.is_err(),
        "pinned verifier constructor accepted invalid dependency: {context}"
    );
}

struct DeployedVerifier {
    evm: Evm,
    verifier_address: revm::primitives::Address,
}

fn deployed_separate_verifier(fixture: &PropertyPoseidonFixture) -> DeployedVerifier {
    deploy_separate_verifier_from_sources(&fixture.separate_verifier_solidity, &fixture.vk_solidity)
}

fn deployed_property_poseidon_verifier(
    fixture: &PropertyPoseidonFixture,
    separate: bool,
) -> DeployedVerifier {
    if separate {
        deployed_separate_verifier(fixture)
    } else {
        deploy_embedded_verifier_from_source(&fixture.embedded_verifier_solidity)
    }
}

fn deploy_embedded_verifier_from_source(verifier_solidity: &str) -> DeployedVerifier {
    let mut evm = Evm::default();
    let verifier_address = evm.create(compile_solidity(verifier_solidity));
    DeployedVerifier {
        evm,
        verifier_address,
    }
}

fn deploy_separate_verifier_from_sources(
    verifier_solidity: &str,
    vk_solidity: &str,
) -> DeployedVerifier {
    let mut evm = Evm::default();
    let vk_address = evm.create(compile_solidity(vk_solidity));
    let verifier_address =
        evm.create_with_address_arg(compile_solidity(verifier_solidity), vk_address);
    DeployedVerifier {
        evm,
        verifier_address,
    }
}

fn call_deployed_verifier(
    deployed: &mut DeployedVerifier,
    proof: &[u8],
    instances: &[F],
) -> Result<Vec<u8>, ()> {
    call_deployed_verifier_raw(deployed, encode_calldata(proof, instances))
}

fn call_deployed_verifier_raw(
    deployed: &mut DeployedVerifier,
    calldata: Vec<u8>,
) -> Result<Vec<u8>, ()> {
    match deployed
        .evm
        .try_call_with_gas(deployed.verifier_address, calldata, 5_000_000_000)
    {
        CallOutcome::Success { output, .. } => Ok(output),
        CallOutcome::Revert { gas_used, output } => {
            eprintln!(
                "verifier reverted with gas_used = {gas_used}, output = 0x{}",
                hex::encode(output)
            );
            Err(())
        }
        CallOutcome::Halt { gas_used, reason } => {
            panic!("verifier halted with gas_used = {gas_used}, reason = {reason}");
        }
    }
}

fn deployed_call_accepts(
    deployed: &mut DeployedVerifier,
    fixture: &PropertyPoseidonFixture,
    proof: &[u8],
    context: &str,
) -> bool {
    let output = call_deployed_verifier(deployed, proof, &fixture.instances);
    solidity_output_is_true_or_skip(output, context)
}

fn assert_deployed_call_accepts(
    deployed: &mut DeployedVerifier,
    fixture: &PropertyPoseidonFixture,
    proof: &[u8],
    context: &str,
) {
    let output = call_deployed_verifier(deployed, proof, &fixture.instances);
    assert_solidity_accepts(output, context);
}

fn deployed_raw_call_accepts(
    deployed: &mut DeployedVerifier,
    calldata: Vec<u8>,
    context: &str,
) -> bool {
    let output = call_deployed_verifier_raw(deployed, calldata);
    solidity_output_is_true_or_skip(output, context)
}

fn solidity_output_is_true_or_skip(output: Result<Vec<u8>, ()>, context: &str) -> bool {
    let expected_true = [vec![0; 31], vec![1]].concat();
    match output {
        Ok(bytes) if bytes == expected_true => true,
        Ok(bytes) => {
            eprintln!(
                "skipping adversarial Solidity test: baseline `{context}` returned 0x{}",
                hex::encode(bytes)
            );
            false
        }
        Err(()) => {
            eprintln!(
                "skipping adversarial Solidity test: baseline `{context}` reverted or halted"
            );
            false
        }
    }
}

fn assert_deployed_call_rejects(
    deployed: &mut DeployedVerifier,
    fixture: &PropertyPoseidonFixture,
    proof: &[u8],
    context: &str,
) {
    let output = call_deployed_verifier(deployed, proof, &fixture.instances);
    assert_solidity_rejects(output, context);
}

fn assert_separate_verifier_rejects_vk_mutation(
    verifier_solidity: &str,
    vk_solidity: &str,
    proof: &[u8],
    instances: &[F],
    context: &str,
) {
    let vk_creation_code = compile_solidity(vk_solidity);
    let verifier_creation_code = compile_solidity(verifier_solidity);
    let mut evm = Evm::default();
    let vk_address = evm.create(vk_creation_code);
    let verifier_address = match std::panic::catch_unwind(AssertUnwindSafe(|| {
        evm.create_with_address_arg(verifier_creation_code, vk_address)
    })) {
        Ok(address) => address,
        Err(_) => return,
    };
    let mut deployed = DeployedVerifier {
        evm,
        verifier_address,
    };
    assert_solidity_rejects(
        call_deployed_verifier(&mut deployed, proof, instances),
        context,
    );
}

fn assert_native_poseidon_rejects(
    fixture: &PropertyPoseidonFixture,
    compressed_proof: &[u8],
    context: &str,
) {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        midnight_zk_stdlib::verify::<PoseidonExample, sha3::Keccak256>(
            &fixture.params_verifier,
            &fixture.vk,
            &fixture.instances[0],
            None,
            compressed_proof,
        )
    }));

    if let Ok(Ok(())) = result {
        panic!("native verifier accepted malformed proof: {context}");
    }
}

#[derive(Clone, Debug)]
struct ProofG1Layout {
    compressed_offsets: Vec<usize>,
    repacked_offsets: Vec<usize>,
}

fn proof_scalar_offsets(fixture: &PropertyPoseidonFixture) -> Vec<(String, usize)> {
    let layout = fixture.scalar_layout;
    let mut offsets = Vec::with_capacity(layout.num_evals + layout.num_point_sets);
    offsets.extend(
        (0..layout.num_evals).map(|idx| (format!("eval[{idx}]"), layout.eval_offset + idx * 0x20)),
    );
    offsets.extend(
        (0..layout.num_point_sets)
            .map(|idx| (format!("q_eval[{idx}]"), layout.q_eval_offset + idx * 0x20)),
    );
    assert!(
        offsets
            .iter()
            .all(|(_, offset)| offset + 0x20 <= fixture.proof.len()),
        "scalar offsets must be inside the Solidity proof"
    );
    offsets
}

fn proof_g1_layout(fixture: &PropertyPoseidonFixture) -> ProofG1Layout {
    let prefix_g1_count = fixture.scalar_layout.eval_offset / 0x80;
    assert_eq!(
        fixture.scalar_layout.eval_offset % 0x80,
        0,
        "G1 prefix must end on a repacked G1 boundary"
    );

    let f_com_repacked_offset =
        fixture.scalar_layout.eval_offset + fixture.scalar_layout.num_evals * 0x20;
    let pi_repacked_offset =
        fixture.scalar_layout.q_eval_offset + fixture.scalar_layout.num_point_sets * 0x20;
    assert_eq!(
        fixture.scalar_layout.q_eval_offset,
        f_com_repacked_offset + 0x80,
        "q_eval block must follow f_com"
    );

    let mut repacked_offsets = (0..prefix_g1_count)
        .map(|idx| idx * 0x80)
        .collect::<Vec<_>>();
    repacked_offsets.push(f_com_repacked_offset);
    repacked_offsets.push(pi_repacked_offset);

    let f_com_compressed_offset = prefix_g1_count * 48 + fixture.scalar_layout.num_evals * 0x20;
    let pi_compressed_offset =
        f_com_compressed_offset + 48 + fixture.scalar_layout.num_point_sets * 0x20;
    let mut compressed_offsets = (0..prefix_g1_count).map(|idx| idx * 48).collect::<Vec<_>>();
    compressed_offsets.push(f_com_compressed_offset);
    compressed_offsets.push(pi_compressed_offset);

    assert!(
        compressed_offsets
            .iter()
            .all(|offset| offset + 48 <= fixture.compressed_proof.len()),
        "compressed G1 offsets must be inside the native proof"
    );
    assert!(
        repacked_offsets
            .iter()
            .all(|offset| offset + 0x80 <= fixture.proof.len()),
        "repacked G1 offsets must be inside the Solidity proof"
    );

    ProofG1Layout {
        compressed_offsets,
        repacked_offsets,
    }
}

fn compressed_off_curve_g1_bytes() -> [u8; 48] {
    use group::GroupEncoding;
    use midnight_curves::G1Affine;

    for x in 1u64..10_000 {
        let mut candidate = [0u8; 48];
        candidate[40..48].copy_from_slice(&x.to_be_bytes());
        // BLS compressed flag, no infinity flag. The remaining high bits of
        // the x-coordinate are zero, so the coordinate is canonical.
        candidate[0] |= 0x80;

        let mut repr = <G1Affine as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(&candidate);
        if bool::from(G1Affine::from_bytes(&repr).is_none()) {
            return candidate;
        }
    }

    panic!("failed to find a canonical compressed x-coordinate with no G1 point");
}

fn eip2537_padded_off_curve_g1_bytes() -> [u8; 128] {
    let mut out = [0u8; 128];
    // EIP-2537 padded uncompressed layout is x_hi, x_lo, y_hi, y_lo.
    // (0, 1) is field-canonical but not on BLS12-381 G1, whose affine
    // equation has b = 4, so the G1 precompiles must reject it.
    out[127] = 1;
    out
}

fn assert_solidity_accepts(output: Result<Vec<u8>, ()>, context: &str) {
    let expected_true = [vec![0; 31], vec![1]].concat();
    match output {
        Ok(bytes) => assert_eq!(bytes, expected_true, "{context}"),
        Err(()) => panic!("solidity call panicked unexpectedly: {context}"),
    }
}

fn assert_solidity_rejects(output: Result<Vec<u8>, ()>, context: &str) {
    assert!(
        output.is_err(),
        "invalid proof/calldata returned instead of reverting: {context}"
    );
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
    mutate_value_hex_literal_on_line_containing(solidity, "vk_digest")
}

fn mutate_value_hex_literal_on_line_containing(solidity: &str, marker: &str) -> String {
    let (line_start, line_end, _) = solidity
        .lines()
        .scan(0usize, |offset, line| {
            let start = *offset;
            *offset += line.len() + 1;
            Some((start, start + line.len(), line))
        })
        .find(|(_, _, line)| line.contains("mstore(") && line.contains(marker))
        .unwrap_or_else(|| panic!("mstore line marker not found: {marker}"));
    let line = &solidity[line_start..line_end];
    let line_before_comment = line.split_once("//").map(|(code, _)| code).unwrap_or(line);
    let bytes = line_before_comment.as_bytes();
    let mut value_literal = None;
    for start in 0..bytes.len().saturating_sub(1) {
        if bytes[start] != b'0' || bytes[start + 1] != b'x' {
            continue;
        }
        let mut end = start + 2;
        while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
            end += 1;
        }
        if end - (start + 2) >= 64 {
            value_literal = Some((start + 2, end - (start + 2)));
        }
    }
    let (rel_hex_start, hex_len) =
        value_literal.unwrap_or_else(|| panic!("line `{marker}` missing value hex literal"));
    let abs_hex_start = line_start + rel_hex_start;

    let mut mutated = solidity.as_bytes().to_vec();
    let last = abs_hex_start + hex_len - 1;
    mutated[last] = if mutated[last] == b'0' { b'1' } else { b'0' };
    String::from_utf8(mutated).unwrap()
}

#[test]
fn vk_payload_mutator_targets_mstore_value_not_payload_offset() {
    let value = format!("0x{:064x}", 0u8);
    let old_shape = format!("mstore(0x0000, {value}) // vk_digest");
    let new_shape = format!("mstore(add(payload, 0x0000), {value}) // vk_digest");

    for source in [old_shape, new_shape] {
        let mutated = mutate_value_hex_literal_on_line_containing(&source, "vk_digest");
        assert!(
            mutated.contains("0x0000"),
            "payload offset should be left intact: {mutated}"
        );
        assert!(
            mutated.ends_with("0001) // vk_digest"),
            "mstore value should be mutated: {mutated}"
        );
    }
}

fn replace_required_precompile_staticcall(
    solidity: &str,
    needle: &str,
    replacement: &str,
) -> String {
    assert!(
        solidity.contains(needle),
        "required precompile smoke-test staticcall not found: {needle}"
    );
    solidity.replacen(needle, replacement, 1)
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

fn fr_modulus_be_word() -> [u8; 32] {
    hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
        .expect("fr modulus hex")
        .try_into()
        .expect("Fr modulus is one word")
}

fn fr_modulus_u256() -> U256 {
    U256::from_be_bytes(fr_modulus_be_word())
}

fn push_unique_section(
    sections: &mut Vec<(String, usize)>,
    name: impl Into<String>,
    offset: usize,
) {
    if sections.iter().all(|(_, existing)| *existing != offset) {
        sections.push((name.into(), offset));
    }
}

fn representative_proof_section_offsets(fixture: &PropertyPoseidonFixture) -> Vec<(String, usize)> {
    let layout = fixture.scalar_layout;
    assert!(
        layout.eval_offset >= 0x80,
        "fixture proof should contain at least one leading G1 commitment"
    );

    let mut sections = Vec::new();
    push_unique_section(&mut sections, "first transcript commitment", 0);
    push_unique_section(
        &mut sections,
        "last quotient limb commitment",
        layout.eval_offset - 0x80,
    );
    if layout.num_evals != 0 {
        push_unique_section(
            &mut sections,
            "first main evaluation scalar",
            layout.eval_offset,
        );
        push_unique_section(
            &mut sections,
            "last main evaluation scalar",
            layout.eval_offset + (layout.num_evals - 1) * 0x20,
        );
    }

    let f_com_offset = layout.eval_offset + layout.num_evals * 0x20;
    push_unique_section(&mut sections, "KZG f_com commitment", f_com_offset);

    if layout.num_point_sets != 0 {
        push_unique_section(
            &mut sections,
            "first KZG point-set evaluation scalar",
            layout.q_eval_offset,
        );
        push_unique_section(
            &mut sections,
            "last KZG point-set evaluation scalar",
            layout.q_eval_offset + (layout.num_point_sets - 1) * 0x20,
        );
    }

    push_unique_section(
        &mut sections,
        "KZG proof commitment pi",
        layout.q_eval_offset + layout.num_point_sets * 0x20,
    );

    assert!(
        sections
            .iter()
            .all(|(_, offset)| *offset < fixture.proof.len()),
        "representative proof section offsets must be inside the proof"
    );
    sections
}

fn verifier_source_with_x_forced_to_one(solidity: &str) -> String {
    let needle = "buf_len := squeeze_to(buf_len, X_MPTR)";
    assert_eq!(
        solidity.matches(needle).count(),
        1,
        "expected exactly one x challenge squeeze to patch"
    );
    solidity.replacen(
        needle,
        "buf_len := squeeze_to(buf_len, X_MPTR)\n            mstore(X_MPTR, 1)",
        1,
    )
}

fn canonical_instances_head(proof: &[u8]) -> usize {
    0x40 + 0x20 + proof.len()
}

fn first_instance_word_start(proof: &[u8]) -> usize {
    4 + canonical_instances_head(proof) + 0x20
}

fn calldata_with_shifted_dynamic_heads(valid: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut shifted = valid.to_vec();
    shifted.splice(4 + 0x40..4 + 0x40, [0u8; 0x20]);
    overwrite_u256_word(&mut shifted, 0x04, 0x60);
    overwrite_u256_word(
        &mut shifted,
        0x24,
        canonical_instances_head(proof) as u64 + 0x20,
    );
    shifted
}

fn poseidon_inputs_available_for_evm() -> bool {
    if !env_flag_enabled(RUN_EVM_TESTS_ENV) {
        eprintln!("skipping Poseidon Solidity property test: set {RUN_EVM_TESTS_ENV}=1 to run it");
        return false;
    }
    if !poseidon_srs_available() {
        return false;
    }
    if !solc_available() {
        eprintln!("skipping Poseidon Solidity property test: solc not found");
        return false;
    }
    true
}

fn env_flag_enabled(name: &str) -> bool {
    env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn poseidon_srs_available() -> bool {
    let srs_dir = PathBuf::from(srs_dir());
    let exact_srs_path = srs_dir.join(format!("bls_filecoin_2p{POSEIDON_K}"));
    let fallback_srs_path = srs_dir.join("bls_filecoin_2p19");
    if !exact_srs_path.exists() && !fallback_srs_path.exists() {
        eprintln!(
            "skipping Poseidon Solidity property test: SRS not found at {} or {}",
            exact_srs_path.display(),
            fallback_srs_path.display()
        );
        return false;
    }
    true
}

fn solc_available() -> bool {
    pinned_solc_available()
}

fn srs_dir() -> String {
    if let Ok(dir) = env::var("SRS_DIR") {
        return dir;
    }

    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../midfall/zk_stdlib/examples/assets")
        .to_string_lossy()
        .into_owned()
}
