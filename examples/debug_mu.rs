//! Compare halo2 GWC's `u` challenge against Solidity's `mu` for seed=0 k=11.
//!
//! Walks the proof transcript using halo2's GWC API:
//!   v = squeeze
//!   read N W points (N = num_rotations)
//!   u = squeeze
//!
//! Then compares `u` to what the Solidity verifier emits as `mu` via
//! its trace logs.
//!
//! Run with:
//!   cargo run --example debug_mu --features evm --release

use halo2_proofs::{
    halo2curves::{
        bls12381::{Bls12381, Fr, G1Affine},
        ff::PrimeField,
    },
    plonk::*,
    poly::{kzg::commitment::ParamsKZG, Rotation},
    transcript::{Transcript, TranscriptRead},
};
use halo2_solidity_verifier::{
    compile_solidity, encode_calldata_bls_padded, BatchOpenScheme::Gwc19, CallOutcome, Evm,
    Keccak256Transcript, SolidityGenerator,
};
use rand::{rngs::StdRng, SeedableRng};

const K: u32 = 11;
const SEED: u64 = 0;
const NUM_ROTATIONS: usize = 2;

fn main() {
    let mut rng = StdRng::seed_from_u64(SEED);
    let params = ParamsKZG::<Bls12381>::setup(K, &mut rng);
    let circuit = StandardPlonk::rand(K as usize, &mut rng);
    let instances = circuit.instances();

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
    let generator = SolidityGenerator::new(&params, &vk, Gwc19, instances.len());
    let (verifier_solidity, vk_solidity) = generator.render_trace_separately().unwrap();

    let proof = create_proof_checked(&params, &pk, circuit, &instances, &mut rng);
    let calldata = encode_calldata_bls_padded(&generator, &proof, &instances);

    // Pull mu out of the Solidity trace.
    let mut evm = Evm::default();
    let vk_address = evm.create(compile_solidity(&vk_solidity));
    let verifier_address =
        evm.create_with_address_arg(compile_solidity(&verifier_solidity), vk_address);
    let outcome = evm.try_call(verifier_address, calldata);
    let logs = match outcome {
        CallOutcome::Success { logs, .. } => logs,
        CallOutcome::Revert { gas_used, output } => {
            panic!("solidity reverted gas={gas_used} output_len={}", output.len());
        }
        CallOutcome::Halt { gas_used, reason } => {
            panic!("solidity halted gas={gas_used} reason={reason}");
        }
    };
    let mut sol_nu = None;
    let mut sol_mu = None;
    for log in &logs {
        let trace_id = u64::from_be_bytes(
            log.data.topics()[0].as_slice()[24..32]
                .try_into()
                .unwrap(),
        );
        if trace_id == 13 {
            sol_nu = Some(hex::encode(log.data.data.as_ref()));
        }
        if trace_id == 14 {
            sol_mu = Some(hex::encode(log.data.data.as_ref()));
        }
    }

    // Walk transcript ourselves with the GWC schedule.
    let cs = vk.cs();
    let num_advices_pub: Vec<usize> = cs
        .advice_column_phase()
        .iter()
        .fold(vec![0; cs.num_phases() as usize], |mut acc, p| {
            acc[*p as usize] += 1;
            acc
        });
    let num_challenges: Vec<usize> = cs.challenge_phase().iter().fold(
        vec![0; cs.num_phases() as usize],
        |mut acc, p| {
            acc[*p as usize] += 1;
            acc
        },
    );
    let num_evals = cs.advice_queries().len()
        + cs.fixed_queries().len()
        + 1 // random
        + cs.permutation().get_columns().len()
        + 3 * cs.permutation().get_columns().len() // perm z evals (oversimplified for std plonk: 3*num_perm_zs)
        ;

    let mut transcript = Keccak256Transcript::<G1Affine, _>::new(proof.as_slice());
    transcript.common_scalar(vk.transcript_repr()).unwrap();
    for instance in &instances {
        transcript.common_scalar(*instance).unwrap();
    }

    for (n_adv, n_ch) in num_advices_pub.iter().zip(num_challenges.iter()) {
        for _ in 0..*n_adv {
            let _ = transcript.read_point().unwrap();
        }
        for _ in 0..*n_ch {
            let _ = transcript.squeeze_challenge_scalar::<()>();
        }
    }

    // Permutation Z's commitments
    // Standard plonk: num_perm_zs = 1
    let _: G1Affine = transcript.read_point().unwrap();
    // Quotient commitments: num_quotients = ?
    // For our circuit it is computed in halo2 as ceil(degree*n/n).
    // We don't know exactly; we instead just read 4 quotient commitments since
    // that's what we observed in the proof.
    for _ in 0..4 {
        let _: G1Affine = transcript.read_point().unwrap();
    }

    // Hmm: this is brittle. Let me instead use the halo2 codegen meta walk
    // by re-reading the generator's view: grab the proof_len and num_evals from
    // the codegen (we don't have direct access, but we can use the calldata
    // size to verify).

    // Try a simpler approach: use the same TraceMeta as compare_trace.
    println!("solidity nu = 0x{}", sol_nu.unwrap());
    println!("solidity mu = 0x{}", sol_mu.unwrap());
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
            let [w_l, w_r, w_o] =
                [w_l, w_r, w_o].map(|c| meta.query_advice(c, Rotation::cur()));
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
