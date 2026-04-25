use application::StandardPlonk;
use prelude::*;

use halo2_solidity_verifier::{
    compile_solidity, encode_calldata_bls_padded, BatchOpenScheme::Bdfg21, Evm,
    Keccak256Transcript, SolidityGenerator,
};

fn main() {
    let k = 10;
    let mut rng = seeded_std_rng();

    let params = ParamsKZG::<Bls12381>::setup(k, &mut rng);
    let circuit = StandardPlonk::rand(k as usize, &mut rng);
    let instances = circuit.instances();

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
    let generator = SolidityGenerator::new(&params, &vk, Bdfg21, instances.len());
    let (verifier_solidity, vk_solidity) = generator.render_trace_separately().unwrap();

    let proof = create_proof_checked(&params, &pk, circuit, &instances, &mut rng);

    let mut evm = Evm::default();
    println!("deploy vk");
    let vk_address = evm.create(compile_solidity(&vk_solidity));
    println!("deploy traced verifier");
    let verifier_address =
        evm.create_with_address_arg(compile_solidity(&verifier_solidity), vk_address);

    println!("call traced verifier");
    let (gas_cost, output, logs) =
        evm.call_with_logs(
            verifier_address,
            encode_calldata_bls_padded(&generator, &proof, &instances),
        );
    assert_eq!(output, [vec![0; 31], vec![1]].concat());

    println!("Trace gas cost: {gas_cost}");
    println!("Trace entries:");
    print_trace_logs(&logs);
}

fn print_trace_logs(logs: &[revm::primitives::Log]) {
    for log in logs {
        let topics = log.data.topics();
        let trace_id = decode_trace_id(topics[0]);
        if is_point_trace(trace_id) {
            let name = trace_name(trace_id);
            let x = decode_word(log.data.data.as_ref(), 0);
            let y = decode_word(log.data.data.as_ref(), 1);
            println!("{name}: ({x}, {y})");
        } else {
            let name = trace_name(trace_id);
            let value = decode_word(log.data.data.as_ref(), 0);
            println!("{name}: {value}");
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

fn trace_name(trace_id: u64) -> &'static str {
    match trace_id {
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
        12 => "zeta",
        13 => "nu",
        14 => "mu",
        15 => "x_n",
        16 => "x_n_minus_1_inv",
        17 => "l_last",
        18 => "l_blind",
        19 => "l_0",
        20 => "instance_eval",
        21 => "quotient_eval",
        22 => "quotient",
        23 => "pairing_lhs",
        24 => "pairing_rhs",
        25 => "acc_lhs",
        26 => "acc_rhs",
        _ => "unknown",
    }
}

fn decode_word(data: &[u8], idx: usize) -> String {
    format!("0x{}", hex::encode(&data[idx * 32..(idx + 1) * 32]))
}

fn create_proof_checked(
    params: &ParamsKZG<Bls12381>,
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

    let instances_owned: Vec<Vec<Vec<Fr>>> = vec![vec![instances.to_vec()]];
    let verifier_params = params.verifier_params();
    let proof = {
        let mut transcript = Keccak256Transcript::new(Vec::new());
        create_proof::<_, ProverSHPLONK<_>, _, _, _, _>(
            params,
            pk,
            &[circuit],
            instances_owned.as_slice(),
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let result = {
        let mut transcript = Keccak256Transcript::new(proof.as_slice());
        verify_proof::<_, VerifierSHPLONK<_>, _, _, SingleStrategy<_>>(
            &verifier_params,
            pk.get_vk(),
            SingleStrategy::new(&verifier_params),
            instances_owned.as_slice(),
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
        ) -> Result<(), ErrorFront> {
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
            bls12381::{Bls12381, Fr, G1Affine},
            ff::{Field, PrimeField},
        },
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
            ConstraintSystem, Error, ErrorFront, Fixed, ProvingKey,
        },
        poly::{kzg::commitment::ParamsKZG, Rotation},
    };
    pub use rand::{rngs::StdRng, RngCore, SeedableRng};

    pub fn seeded_std_rng() -> StdRng {
        StdRng::seed_from_u64(0)
    }
}
