use application::StandardPlonk;
use prelude::*;

use halo2_proofs::{
    halo2curves::{bn256::Fr, ff::PrimeField},
    transcript::{Transcript, TranscriptRead},
};
use halo2_solidity_verifier::{
    compile_solidity, encode_calldata, BatchOpenScheme::Bdfg21, Evm, Keccak256Transcript,
    SolidityGenerator,
};
use itertools::chain;
use ruint::aliases::U256;
use std::{collections::BTreeMap, io};

fn main() {
    let k = 10;
    let mut rng = seeded_std_rng();

    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let circuit = StandardPlonk::rand(k as usize, &mut rng);
    let instances = circuit.instances();

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
    let generator = SolidityGenerator::new(&params, &vk, Bdfg21, instances.len());
    let (verifier_solidity, vk_solidity) = generator.render_trace_separately().unwrap();

    let proof = create_proof_checked(&params, &pk, circuit, &instances, &mut rng);

    let mut evm = Evm::default();
    let vk_address = evm.create(compile_solidity(&vk_solidity));
    let verifier_address =
        evm.create_with_address_arg(compile_solidity(&verifier_solidity), vk_address);
    let (_, output, logs) =
        evm.call_with_logs(verifier_address, encode_calldata(&proof, &instances));
    assert_eq!(output, [vec![0; 31], vec![1]].concat());

    let solidity = decode_solidity_trace(&logs);
    let rust = compute_rust_trace(&params, &vk, &proof, &instances).unwrap();

    for name in TRACE_NAMES {
        let solidity_value = solidity.get(*name).expect("missing solidity trace entry");
        let rust_value = rust.get(*name).expect("missing rust trace entry");
        println!("{name}");
        println!("  solidity: {solidity_value}");
        println!("  rust:     {rust_value}");
        assert_eq!(solidity_value, rust_value, "trace mismatch for {name}");
    }

    println!("All comparable trace entries match.");
}

const TRACE_NAMES: &[&str] = &[
    "vk_digest",
    "num_instances",
    "k",
    "n_inv",
    "omega",
    "omega_inv",
    "theta",
    "beta",
    "gamma",
    "y",
    "x",
    "zeta",
    "nu",
    "mu",
    "x_n",
    "x_n_minus_1_inv",
    "l_last",
    "l_blind",
    "l_0",
    "instance_eval",
];

fn decode_solidity_trace(logs: &[revm::primitives::Log]) -> BTreeMap<&'static str, String> {
    let mut values = BTreeMap::new();
    for log in logs {
        let trace_id = decode_trace_id(log.topics[0]);
        if let Some(name) = trace_name(trace_id) {
            if is_point_trace(trace_id) {
                continue;
            }
            values.insert(name, decode_word(log.data.as_ref(), 0));
        }
    }
    values
}

fn compute_rust_trace(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: &[u8],
    instances: &[Fr],
) -> io::Result<BTreeMap<&'static str, String>> {
    let cs = vk.cs();
    let meta = TraceMeta::new(cs);
    let domain = vk.get_domain();
    let mut transcript = Keccak256Transcript::<G1Affine, _>::new(proof);

    transcript.common_scalar(vk.transcript_repr())?;
    for instance in instances {
        transcript.common_scalar(*instance)?;
    }

    let mut challenges = Vec::new();
    for (num_advices, num_challenges) in meta.num_advices.iter().zip(meta.num_challenges.iter()) {
        for _ in 0..*num_advices {
            let _ = transcript.read_point()?;
        }
        for _ in 0..*num_challenges {
            challenges.push(*transcript.squeeze_challenge_scalar::<()>());
        }
    }

    for _ in 0..meta.num_evals {
        let _ = transcript.read_scalar()?;
    }

    let zeta = *transcript.squeeze_challenge_scalar::<()>();
    let nu = *transcript.squeeze_challenge_scalar::<()>();
    let _ = transcript.read_point()?;
    let mu = *transcript.squeeze_challenge_scalar::<()>();
    let _ = transcript.read_point()?;

    let theta = challenges[0];
    let beta = challenges[1];
    let gamma = challenges[2];
    let y = challenges[3];
    let x = challenges[4];
    let x_n = x.pow_vartime([params.n() as u64]);
    let l_i_s = domain.l_i_range(x, x_n, meta.rotation_last..instances.len() as i32);
    let num_neg_lagranges = (-meta.rotation_last) as usize;
    let x_n_minus_1_inv = (x_n - Fr::ONE).invert().unwrap();
    let l_last = l_i_s[0];
    let l_blind = l_i_s[1..num_neg_lagranges]
        .iter()
        .fold(Fr::ZERO, |acc, value| acc + value);
    let l_0 = l_i_s[num_neg_lagranges];
    let instance_eval = instances
        .iter()
        .zip(l_i_s[num_neg_lagranges..num_neg_lagranges + instances.len()].iter())
        .fold(Fr::ZERO, |acc, (instance, l_i)| acc + (*instance * l_i));

    Ok(BTreeMap::from([
        ("vk_digest", word_hex(vk.transcript_repr())),
        ("num_instances", u64_hex(instances.len() as u64)),
        ("k", u64_hex(domain.k() as u64)),
        (
            "n_inv",
            word_hex(Fr::from(1u64 << domain.k()).invert().unwrap()),
        ),
        ("omega", word_hex(domain.get_omega())),
        ("omega_inv", word_hex(domain.get_omega_inv())),
        ("theta", word_hex(theta)),
        ("beta", word_hex(beta)),
        ("gamma", word_hex(gamma)),
        ("y", word_hex(y)),
        ("x", word_hex(x)),
        ("zeta", word_hex(zeta)),
        ("nu", word_hex(nu)),
        ("mu", word_hex(mu)),
        ("x_n", word_hex(x_n)),
        ("x_n_minus_1_inv", word_hex(x_n_minus_1_inv)),
        ("l_last", word_hex(l_last)),
        ("l_blind", word_hex(l_blind)),
        ("l_0", word_hex(l_0)),
        ("instance_eval", word_hex(instance_eval)),
    ]))
}

#[derive(Debug)]
struct TraceMeta {
    num_advices: Vec<usize>,
    num_challenges: Vec<usize>,
    num_evals: usize,
    rotation_last: i32,
}

impl TraceMeta {
    fn new(cs: &ConstraintSystem<Fr>) -> Self {
        let advice_queries = cs.advice_queries();
        let fixed_queries = cs.fixed_queries();
        let num_lookup_permuteds = 2 * cs.lookups().len();
        let num_permutation_zs = cs
            .permutation()
            .get_columns()
            .chunks(cs.degree() - 2)
            .count();
        let num_lookup_zs = cs.lookups().len();
        let num_quotients = cs.degree() - 1;
        let num_evals = advice_queries.len()
            + fixed_queries.len()
            + 1
            + cs.permutation().get_columns().len()
            + (3 * num_permutation_zs - 1)
            + 5 * cs.lookups().len();
        let num_phase = *cs.advice_column_phase().iter().max().unwrap_or(&0) as usize + 1;
        let remap_counts = |phase: Vec<u8>| {
            phase
                .into_iter()
                .fold(vec![0; num_phase], |mut counts, phase| {
                    counts[phase as usize] += 1;
                    counts
                })
        };
        let num_user_advices = remap_counts(cs.advice_column_phase());
        let mut num_user_challenges = remap_counts(cs.challenge_phase());
        if num_lookup_permuteds == 0 {
            *num_user_challenges.last_mut().unwrap() += 3;
            num_user_challenges.extend([1, 1]);
        } else {
            *num_user_challenges.last_mut().unwrap() += 1;
            num_user_challenges.extend([2, 1, 1]);
        }
        let num_advices = chain![
            num_user_advices.into_iter(),
            (num_lookup_permuteds != 0).then_some(num_lookup_permuteds),
            [num_permutation_zs + num_lookup_zs + 1, num_quotients],
        ]
        .collect();

        Self {
            num_advices,
            num_challenges: num_user_challenges,
            num_evals,
            rotation_last: -(cs.blinding_factors() as i32 + 1),
        }
    }
}

fn decode_trace_id(word: revm::primitives::B256) -> u64 {
    let bytes = word.as_slice();
    u64::from_be_bytes(bytes[24..32].try_into().unwrap())
}

fn is_point_trace(trace_id: u64) -> bool {
    matches!(trace_id, 22..=26)
}

fn trace_name(trace_id: u64) -> Option<&'static str> {
    match trace_id {
        1 => Some("vk_digest"),
        2 => Some("num_instances"),
        3 => Some("k"),
        4 => Some("n_inv"),
        5 => Some("omega"),
        6 => Some("omega_inv"),
        7 => Some("theta"),
        8 => Some("beta"),
        9 => Some("gamma"),
        10 => Some("y"),
        11 => Some("x"),
        12 => Some("zeta"),
        13 => Some("nu"),
        14 => Some("mu"),
        15 => Some("x_n"),
        16 => Some("x_n_minus_1_inv"),
        17 => Some("l_last"),
        18 => Some("l_blind"),
        19 => Some("l_0"),
        20 => Some("instance_eval"),
        21 => Some("quotient_eval"),
        22 => Some("quotient"),
        23 => Some("pairing_lhs"),
        24 => Some("pairing_rhs"),
        25 => Some("acc_lhs"),
        26 => Some("acc_rhs"),
        _ => None,
    }
}

fn decode_word(data: &[u8], idx: usize) -> String {
    format!("0x{}", hex::encode(&data[idx * 32..(idx + 1) * 32]))
}

fn word_hex(value: Fr) -> String {
    let mut bytes = value.to_repr();
    bytes.as_mut().reverse();
    format!("0x{}", hex::encode(bytes))
}

fn u64_hex(value: u64) -> String {
    format!("0x{}", hex::encode(U256::from(value).to_be_bytes::<32>()))
}

fn create_proof_checked(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: impl Circuit<Fr>,
    instances: &[Fr],
    mut rng: impl RngCore,
) -> Vec<u8> {
    use halo2_proofs::{
        poly::kzg::{
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::TranscriptWriterBuffer,
    };

    let proof = {
        let mut transcript = Keccak256Transcript::new(Vec::new());
        create_proof::<_, ProverSHPLONK<_>, _, _, _, _>(
            params,
            pk,
            &[circuit],
            &[&[instances]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let result = {
        let mut transcript = Keccak256Transcript::new(proof.as_slice());
        verify_proof::<_, VerifierSHPLONK<_>, _, _, SingleStrategy<_>>(
            params,
            pk.get_vk(),
            SingleStrategy::new(params),
            &[&[instances]],
            &mut transcript,
        )
    };
    assert!(result.is_ok());

    proof
}

mod application {
    use crate::prelude::*;

    #[derive(Clone)]
    pub struct StandardPlonkConfig {
        selectors: [Column<Fixed>; 5],
        wires: [Column<Advice>; 3],
    }

    impl StandardPlonkConfig {
        fn configure(meta: &mut ConstraintSystem<impl PrimeField>) -> Self {
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
                    Some(
                        q_l * w_l.clone()
                            + q_r * w_r.clone()
                            + q_o * w_o
                            + q_m * w_l * w_r
                            + q_c
                            + pi,
                    )
                },
            );
            StandardPlonkConfig {
                selectors: [q_l, q_r, q_o, q_m, q_c],
                wires: [w_l, w_r, w_o],
            }
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct StandardPlonk<F>(Vec<F>);

    impl<F: PrimeField> StandardPlonk<F> {
        pub fn rand<R: RngCore>(num_instances: usize, mut rng: R) -> Self {
            Self((0..num_instances).map(|_| F::random(&mut rng)).collect())
        }

        pub fn instances(&self) -> Vec<F> {
            self.0.clone()
        }
    }

    impl<F: PrimeField> Circuit<F> for StandardPlonk<F> {
        type Config = StandardPlonkConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            meta.set_minimum_degree(5);
            StandardPlonkConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let [q_l, q_r, q_o, q_m, q_c] = config.selectors;
            let [w_l, w_r, w_o] = config.wires;
            layouter.assign_region(
                || "",
                |mut region| {
                    for (offset, instance) in self.0.iter().enumerate() {
                        region.assign_advice(|| "", w_l, offset, || Value::known(*instance))?;
                        region.assign_fixed(|| "", q_l, offset, || Value::known(-F::ONE))?;
                    }
                    let offset = self.0.len();
                    let a = region.assign_advice(|| "", w_l, offset, || Value::known(F::ONE))?;
                    a.copy_advice(|| "", &mut region, w_r, offset)?;
                    a.copy_advice(|| "", &mut region, w_o, offset)?;
                    let offset = offset + 1;
                    region.assign_advice(|| "", w_l, offset, || Value::known(-F::from(5)))?;
                    for (column, idx) in [q_l, q_r, q_o, q_m, q_c].iter().zip(1..) {
                        region.assign_fixed(
                            || "",
                            *column,
                            offset,
                            || Value::known(F::from(idx)),
                        )?;
                    }
                    Ok(())
                },
            )
        }
    }
}

mod prelude {
    pub use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        halo2curves::{
            bn256::{Bn256, G1Affine},
            ff::{Field, PrimeField},
        },
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
            ConstraintSystem, Error, Fixed, ProvingKey, VerifyingKey,
        },
        poly::{commitment::Params, kzg::commitment::ParamsKZG, Rotation},
    };
    pub use rand::{rngs::StdRng, RngCore, SeedableRng};

    pub fn seeded_std_rng() -> StdRng {
        StdRng::seed_from_u64(0)
    }
}
