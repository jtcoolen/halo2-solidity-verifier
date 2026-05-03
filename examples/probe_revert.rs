// Hammer (k=11..16) with many seeds and report which seeds revert,
// alongside the revert payload. Run with:
//
//   cargo run --example probe_revert --features evm --release
//
// This isolates intermittent failures so we can drive a fixed-seed
// trace through `compare_trace` for a specific bad seed.

use halo2_proofs::{
    halo2curves::{
        bls12381::{Bls12381, Fr, G1Affine},
        ff::PrimeField,
    },
    plonk::*,
    poly::{kzg::commitment::ParamsKZG, Rotation},
};
use halo2_solidity_verifier::{
    compile_solidity, encode_calldata_bls_padded, CallOutcome, Evm, Keccak256Transcript,
    SolidityGenerator,
};
use rand::{rngs::StdRng, SeedableRng};

const K_RANGE: std::ops::Range<u32> = 11..14;
const NUM_SEEDS: u64 = 16;

fn main() {
    let mut totals: Vec<(u64, &'static str)> = Vec::new();
    for seed in 0..NUM_SEEDS {
        for k in K_RANGE {
            let mut rng = StdRng::seed_from_u64(seed);
            let params = ParamsKZG::<Bls12381>::setup(k, &mut rng);
            let circuit = StandardPlonk::rand(k as usize, &mut rng);
            let instances = circuit.instances();

            let vk = keygen_vk(&params, &circuit).unwrap();
            let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
            let generator = SolidityGenerator::new(&params, &vk, instances.len(), 1);
            let (verifier_solidity, vk_solidity) = generator.render_separately().unwrap();

            let mut evm = Evm::default();
            let vk_address = evm.create(compile_solidity(&vk_solidity));
            let verifier_address =
                evm.create_with_address_arg(compile_solidity(&verifier_solidity), vk_address);

            let proof = create_proof_checked(&params, &pk, circuit, &instances, &mut rng);
            let calldata = encode_calldata_bls_padded(&generator, &proof, &instances);

            match evm.try_call(verifier_address, calldata) {
                CallOutcome::Success {
                    gas_used, output, ..
                } if output == [vec![0u8; 31], vec![1]].concat() => {
                    println!("seed={seed} k={k}: ACCEPT (gas={gas_used})");
                    totals.push((gas_used, "ok"));
                }
                CallOutcome::Success {
                    gas_used, output, ..
                } => {
                    println!(
                        "seed={seed} k={k}: ran but returned {} bytes (gas={gas_used})",
                        output.len()
                    );
                }
                CallOutcome::Revert { gas_used, output } => {
                    println!(
                        "seed={seed} k={k}: REVERT (gas={gas_used}, output={} bytes = 0x{})",
                        output.len(),
                        hex::encode(&output)
                    );
                }
                CallOutcome::Halt { gas_used, reason } => {
                    println!("seed={seed} k={k}: HALT (gas={gas_used}, reason={reason})");
                }
            }
        }
    }
    println!("done; {} runs collected", totals.len());
}

fn create_proof_checked(
    params: &ParamsKZG<Bls12381>,
    pk: &ProvingKey<G1Affine>,
    circuit: impl Circuit<Fr>,
    instances: &[Fr],
    mut rng: impl rand::RngCore,
) -> Vec<u8> {
    use halo2_proofs::{
        poly::kzg::{
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
        transcript::TranscriptWriterBuffer,
    };
    let instances_owned: Vec<Vec<Vec<Fr>>> = vec![vec![instances.to_vec()]];
    let proof = {
        let mut transcript = Keccak256Transcript::new(Vec::new());
        create_proof::<_, ProverGWC<_>, _, _, _, _>(
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
    let verifier_params = params.verifier_params();
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
    assert!(result.is_ok());
    proof
}

// Same StandardPlonk as in examples/separately.rs.
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Fixed},
};

#[derive(Clone)]
struct StandardPlonkConfig {
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
        meta.create_gate("sp", |meta| {
            let [w_l, w_r, w_o] = [w_l, w_r, w_o].map(|c| meta.query_advice(c, Rotation::cur()));
            let [q_l, q_r, q_o, q_m, q_c] =
                [q_l, q_r, q_o, q_m, q_c].map(|c| meta.query_fixed(c, Rotation::cur()));
            let pi = meta.query_instance(pi, Rotation::cur());
            Some(q_l * w_l.clone() + q_r * w_r.clone() + q_o * w_o + q_m * w_l * w_r + q_c + pi)
        });
        StandardPlonkConfig {
            selectors: [q_l, q_r, q_o, q_m, q_c],
            wires: [w_l, w_r, w_o],
        }
    }
}

#[derive(Clone, Debug, Default)]
struct StandardPlonk<F>(Vec<F>);

impl<F: PrimeField> StandardPlonk<F> {
    fn rand<R: rand::RngCore>(num_instances: usize, mut rng: R) -> Self {
        Self((0..num_instances).map(|_| F::random(&mut rng)).collect())
    }
    fn instances(&self) -> Vec<F> {
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
                    region.assign_fixed(|| "", *column, offset, || Value::known(F::from(idx)))?;
                }
                Ok(())
            },
        )
    }
}
