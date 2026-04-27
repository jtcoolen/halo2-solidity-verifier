// Gas-attribution benchmark for the BLS12-381 / EIP-2537 verifier.
//
// Renders the verifier as a *cumulative* pipeline: each row enables one
// more stage on top of the previous one. The delta between adjacent rows
// is the gas cost of that stage. This is more reliable than flipping a
// single skip flag at a time, because skipping (say) PCS while leaving
// the pairing on means the pairing precompile reads uninitialized memory
// and burns the entire `tx.gas_limit` (u64::MAX) on a malformed-input
// failure.
//
// Pipeline rows:
//   0. baseline_skip_all    : nothing executes after the initial
//                             transcript / instance read.
//   1. + lagrange           : Lagrange & instance-evaluation block (the
//                             batch_invert via modexp + mulmod sweep).
//   2. + quotient_eval      : the Fr-only quotient-numerator computation.
//   3. + quotient_fold      : the Horner fold over the quotient
//                             commitments (G1 ops via 0x0c / 0x0b).
//   4. + pcs                : the PCS computation block that builds
//                             PAIRING_LHS / PAIRING_RHS.
//   5. + random_combine     : the keccak + 2 G1MSMs + 2 G1ADDs that
//                             fold ACC into the pairing inputs (no-op
//                             when HAS_ACCUMULATOR_MPTR == 0).
//   6. + pairing            : the final BLS12_PAIRING_CHECK at 0x0f.
//
// We also include a few "skip one at a time" rows at the end so the
// reader can sanity-check the cumulative deltas against the
// "everything except X" measurements where they're well-defined (i.e.
// where omitting the stage doesn't feed garbage into a downstream
// precompile).

use application::StandardPlonk;
use prelude::*;

use halo2_solidity_verifier::{
    compile_solidity_with, encode_calldata_bls_padded, BatchOpenScheme::Gwc19, BenchToggles, Evm,
    Keccak256Transcript, SolidityGenerator,
};

const BENCH_K: u32 = 11;

fn main() {
    let mut rng = seeded_std_rng();

    let params = ParamsKZG::<Bls12381>::setup(BENCH_K, &mut rng);
    let num_instances = BENCH_K as usize;
    let circuit = StandardPlonk::rand(num_instances, &mut rng);

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let generator = SolidityGenerator::new(&params, pk.get_vk(), Gwc19, num_instances);

    // Generate one proof up front; reuse it across every toggle combo.
    let instances = circuit.instances();
    let proof = create_proof_checked(&params, &pk, circuit, &instances, &mut rng);
    let calldata = encode_calldata_bls_padded(&generator, &proof, &instances);

    // solc's optimizer (--optimize + --via-ir) is aggressive enough that
    // it inlines whole stages into the final XOR sink and can fuse work
    // between bench variants, hiding per-stage costs. Default to
    // unoptimized so each stage shows up in gas; set BENCH_OPTIMIZE=1 to
    // reproduce production-style numbers.
    let optimize = std::env::var_os("BENCH_OPTIMIZE").is_some();
    println!("== Halo2 BLS12-381 verifier gas attribution (k={BENCH_K}) ==");
    println!(
        "circuit: standard plonk, num_instances = {num_instances}, proof bytes = {}, calldata bytes = {}",
        proof.len(),
        calldata.len(),
    );
    println!("solc optimizer: {}", if optimize { "on (--optimize --via-ir)" } else { "off (--via-ir only)" });
    println!();

    // Cumulative pipeline: each row adds one more stage. Skipping a
    // stage that downstream consumers depend on (e.g. PCS feeds the
    // pairing inputs) is only valid if everything downstream is also
    // skipped, otherwise the precompile burns the entire gas limit on
    // malformed input.
    let everything_skipped = BenchToggles {
        skip_pairing: true,
        skip_random_combine: true,
        skip_pcs: true,
        skip_quotient_fold: true,
        skip_quotient_eval: true,
        skip_lagrange: true,
        skip_g1_range_check: false,
    };
    let pipeline: Vec<(&'static str, BenchToggles)> = vec![
        ("baseline (all skipped)", everything_skipped),
        (
            "+ lagrange",
            BenchToggles {
                skip_lagrange: false,
                ..everything_skipped
            },
        ),
        (
            "+ quotient_eval",
            BenchToggles {
                skip_lagrange: false,
                skip_quotient_eval: false,
                ..everything_skipped
            },
        ),
        (
            "+ quotient_fold",
            BenchToggles {
                skip_lagrange: false,
                skip_quotient_eval: false,
                skip_quotient_fold: false,
                ..everything_skipped
            },
        ),
        (
            "+ pcs",
            BenchToggles {
                skip_lagrange: false,
                skip_quotient_eval: false,
                skip_quotient_fold: false,
                skip_pcs: false,
                ..everything_skipped
            },
        ),
        (
            "+ random_combine",
            BenchToggles {
                skip_lagrange: false,
                skip_quotient_eval: false,
                skip_quotient_fold: false,
                skip_pcs: false,
                skip_random_combine: false,
                ..everything_skipped
            },
        ),
        ("+ pairing (full verifier)", BenchToggles::default()),
    ];

    println!(
        "{:<28} {:>14} {:>14} {:>14} {:>10}",
        "stage", "verify gas", "delta", "% of full", "outcome"
    );
    println!("{}", "-".repeat(86));

    let mut prev_gas: Option<u64> = None;
    let mut full_gas: u64 = 0;
    let mut rows: Vec<(String, u64, &'static str)> = Vec::new();
    for (label, toggles) in &pipeline {
        let sol = generator.render_bench(*toggles).unwrap();
        if std::env::var_os("BENCH_DUMP_SOL").is_some() {
            let safe = label.replace([' ', '+', '(', ')'], "_");
            std::fs::write(format!("/tmp/bench_{safe}.sol"), &sol).ok();
        }
        let bytecode = compile_solidity_with(sol, optimize);
        let mut evm = Evm::default();
        let address = evm.create(bytecode);
        let outcome = evm.try_call(address, calldata.clone());
        let (gas_used, status, ret) = match outcome {
            halo2_solidity_verifier::CallOutcome::Success { gas_used, output, .. } => {
                (gas_used, "ok", output)
            }
            halo2_solidity_verifier::CallOutcome::Revert { gas_used, output } => {
                (gas_used, "revert", output)
            }
            halo2_solidity_verifier::CallOutcome::Halt { gas_used, .. } => {
                (gas_used, "halt", Vec::new())
            }
        };
        if std::env::var_os("BENCH_DUMP_SOL").is_some() {
            let ret_hex: String = ret.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("[bench] {label:<28} return = 0x{ret_hex}");
        }
        rows.push((label.to_string(), gas_used, status));
        if *label == "+ pairing (full verifier)" {
            full_gas = gas_used;
        }
    }

    for (label, gas_used, status) in &rows {
        let delta_str = match prev_gas {
            None => "—".to_string(),
            Some(prev) => format!("{:+}", *gas_used as i64 - prev as i64),
        };
        let pct = if full_gas > 0 {
            format!("{:.1}%", (*gas_used as f64 / full_gas as f64) * 100.0)
        } else {
            "—".to_string()
        };
        println!("{label:<28} {gas_used:>14} {delta_str:>14} {pct:>14} {status:>10}");
        prev_gas = Some(*gas_used);
    }

    // Sanity-check rows: only flip flags that don't break downstream
    // consumers, so the gas number is meaningful on its own.
    println!();
    println!("== Sanity checks (single-flag toggles that stay sound) ==");
    let sanity: Vec<(&'static str, BenchToggles)> = vec![
        (
            "skip_g1_range_check only",
            BenchToggles {
                skip_g1_range_check: true,
                ..Default::default()
            },
        ),
        (
            "skip_pairing only",
            BenchToggles {
                skip_pairing: true,
                ..Default::default()
            },
        ),
    ];
    println!(
        "{:<28} {:>14} {:>14} {:>10}",
        "config", "verify gas", "delta vs full", "outcome"
    );
    println!("{}", "-".repeat(70));
    for (label, toggles) in &sanity {
        let bytecode = compile_solidity_with(generator.render_bench(*toggles).unwrap(), optimize);
        let mut evm = Evm::default();
        let address = evm.create(bytecode);
        let outcome = evm.try_call(address, calldata.clone());
        let (gas_used, status) = match outcome {
            halo2_solidity_verifier::CallOutcome::Success { gas_used, .. } => (gas_used, "ok"),
            halo2_solidity_verifier::CallOutcome::Revert { gas_used, .. } => (gas_used, "revert"),
            halo2_solidity_verifier::CallOutcome::Halt { gas_used, .. } => (gas_used, "halt"),
        };
        let delta = gas_used as i64 - full_gas as i64;
        println!(
            "{label:<28} {gas_used:>14} {:>14} {status:>10}",
            format!("{delta:+}")
        );
    }

    println!();
    println!("Notes:");
    println!("- Pairing (~104 kg) and PCS (~232 kg) dominate.");
    println!("- '+ random_combine' is small here (no accumulator in this circuit).");
    println!("- 'skip_g1_range_check only' shows the audit-fix #2 cost amortized");
    println!("  across every G1 read in the proof.");
    println!("- Set BENCH_OPTIMIZE=1 to compile with solc --optimize (the");
    println!("  numbers shrink and several stages collapse into the final XOR");
    println!("  sink due to aggressive inlining).");
    println!("- Set BENCH_DUMP_SOL=1 to dump the rendered .sol for each stage");
    println!("  and the `verifyProof` return word to /tmp/bench_*.sol.");
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

    pub fn seeded_std_rng() -> impl RngCore {
        StdRng::seed_from_u64(OsRng.next_u64())
    }
}
