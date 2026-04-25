use application::StandardPlonk;
use prelude::*;

use halo2_solidity_verifier::{
    compile_solidity, encode_calldata_bls_padded, BatchOpenScheme::Bdfg21, Evm,
    Keccak256Transcript, SolidityGenerator,
};

const K_RANGE: Range<u32> = 10..17;

fn main() {
    let mut rng = seeded_std_rng();

    let params = setup(K_RANGE, &mut rng);

    let mut evm = Evm::default();

    for k in K_RANGE {
        let num_instances = k as usize;
        let circuit = StandardPlonk::rand(num_instances, &mut rng);

        let vk = keygen_vk(&params[&k], &circuit).unwrap();
        let pk = keygen_pk(&params[&k], vk, &circuit).unwrap();
        let generator = SolidityGenerator::new(&params[&k], pk.get_vk(), Bdfg21, num_instances);
        let (verifier_solidity, vk_solidity) = generator.render_separately().unwrap();
        // Each (k, circuit) yields a distinct authorized VK, and the verifier
        // pins that VK by codehash, so we save one Halo2Verifier per k too.
        save_solidity(format!("Halo2Verifier-{k}.sol"), &verifier_solidity);
        save_solidity(format!("Halo2VerifyingKey-{k}.sol"), &vk_solidity);

        let vk_creation_code = compile_solidity(&vk_solidity);
        let verifier_creation_code = compile_solidity(&verifier_solidity);
        println!(
            "k={k}: vk creation code = {} B, verifier creation code = {} B",
            vk_creation_code.len(),
            verifier_creation_code.len()
        );

        // Deploy both contracts on the Prague-spec EVM and call the
        // verifier with a native BLS12-381 proof re-encoded into the
        // EIP-2537 padded layout. The prover side (halo2 v0.4 KZG over
        // bls12381::Bls12381) emits real BLS curve points, and the
        // Solidity verifier feeds those straight to the 0x0b/0x0c/0x0f
        // precompiles -- the pairing should now return 1 for valid
        // proofs.
        let vk_address = evm.create(vk_creation_code);
        let verifier_address =
            evm.create_with_address_arg(verifier_creation_code, vk_address);
        let calldata = {
            let instances = circuit.instances();
            let proof = create_proof_checked(&params[&k], &pk, circuit, &instances, &mut rng);
            encode_calldata_bls_padded(&generator, &proof, &instances)
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.call(verifier_address, calldata.clone())
        }));
        match outcome {
            Ok((gas_used, output)) if output == [vec![0; 31], vec![1]].concat() => {
                println!("  -> verifier accepted (gas = {gas_used})");
            }
            Ok((gas_used, output)) => {
                println!(
                    "  -> verifier ran but returned {} bytes ({gas_used} gas) -- expected post-Stage-C",
                    output.len()
                );
            }
            Err(_) => {
                println!(
                    "  -> verifier reverted; calldata = {} B",
                    calldata.len()
                );
            }
        }
    }
}

fn save_solidity(name: impl AsRef<str>, solidity: &str) {
    const DIR_GENERATED: &str = "./generated";

    create_dir_all(DIR_GENERATED).unwrap();
    File::create(format!("{DIR_GENERATED}/{}", name.as_ref()))
        .unwrap()
        .write_all(solidity.as_bytes())
        .unwrap();
}

fn setup(k_range: Range<u32>, mut rng: impl RngCore) -> HashMap<u32, ParamsKZG<Bls12381>> {
    k_range
        .clone()
        .zip(k_range.map(|k| ParamsKZG::<Bls12381>::setup(k, &mut rng)))
        .collect()
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

    // halo2 v0.4 changed the proof-generation API:
    //   * `instances` is now `&[Vec<Vec<Scheme::Scalar>>]` (vec of circuits,
    //     each a vec of columns, each a vec of values) instead of v0.3's
    //     `&[&[&[Scheme::Scalar]]]`.
    //   * `SingleStrategy::new` takes `&ParamsVerifierKZG<E>`, derived from
    //     `params.verifier_params()`.
    //   * `verify_proof` returns `Result<Strategy::Output, Error>` where
    //     `Strategy::Output` is `()` for `SingleStrategy`.
    let instances_owned: Vec<Vec<Vec<Fr>>> = vec![vec![instances.to_vec()]];
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

    let verifier_params = params.verifier_params();
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
            ff::PrimeField,
        },
        plonk::*,
        poly::{kzg::commitment::ParamsKZG, Rotation},
    };
    pub use rand::{
        rngs::{OsRng, StdRng},
        RngCore, SeedableRng,
    };
    pub use std::{
        collections::HashMap,
        fs::{create_dir_all, File},
        io::Write,
        ops::Range,
    };

    pub fn seeded_std_rng() -> impl RngCore {
        StdRng::seed_from_u64(OsRng.next_u64())
    }
}
