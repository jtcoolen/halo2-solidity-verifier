//! End-to-end on-chain verification of the IVC SHA-256 aggregation chain's
//! final Keccak-transcript proof (the EVM twin of the off-circuit
//! `IvcVerifier::verify_final` test in
//! `midfall/aggregation/tests/single_aggregation_keccak_final.rs`).
//!
//! Pipeline:
//!   1. Build the IVC circuit (k = 19, ProofAggregation transition).
//!   2. Aggregate three SHA-256 preimage proofs into a chain; the last
//!      step uses `prove_final_step` so the outer Fiat-Shamir transcript
//!      is Keccak-256 (matching the EVM verifier).
//!   3. Render `Halo2Verifier.sol` + `Halo2VerifyingKey.sol` against the
//!      IVC VK with `truncated-challenges` + `fewer-point-sets` enabled.
//!   4. Compile the Solidity, deploy on Prague-spec revm (EIP-2537
//!      precompiles routed through blst), repack the proof off-chain
//!      via `SolidityGenerator::repack_compressed_proof`, encode
//!      calldata, call `verifyProof`.
//!   5. Assert success and dump gas.
//!
//! Required features: `evm`, `truncated-challenges`, `fewer-point-sets`.
//! Midnight crates are pulled from the published midfall `keccak` branch
//! configured in `Cargo.toml`; `SRS_DIR` still needs to point at local SRS
//! assets.
//! Run:
//!
//! ```text
//! SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
//!   cargo test --release \
//!     --features evm,truncated-challenges,fewer-point-sets \
//!     --test ivc_keccak_solidity \
//!     -- --ignored --nocapture
//! ```
//!
//! Enable the detailed gas benchmark with:
//!
//! ```text
//! SRS_DIR=/Users/Julien.Coolen/midfall/zk_stdlib/examples/assets \
//!   cargo test --release \
//!     --features evm,truncated-challenges,fewer-point-sets,solidity-gas-checkpoints \
//!     --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
//!     -- --ignored --nocapture
//! ```

#![cfg(all(
    feature = "evm",
    feature = "truncated-challenges",
    feature = "fewer-point-sets",
))]

use std::{collections::BTreeMap, time::Instant};

use ff::Field;
use group::Group;
use midnight_aggregation::ivc::{self, IvcCircuit, IvcContext, IvcIO, IvcState, IvcTransition};
use midnight_circuits::{
    hash::poseidon::{PoseidonChip, PoseidonState},
    instructions::{hash::HashCPU, *},
    types::{AssignedBit, AssignedNative, Instantiable},
    verifier::{self, Accumulator, AssignedAccumulator, BlstrsEmulation, SelfEmulation},
};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::{self, ConstraintSystem, Error},
    poly::{
        kzg::{params::ParamsVerifierKZG, KZGCommitmentScheme},
        EvaluationDomain,
    },
    transcript::{CircuitTranscript, Transcript},
};
use midnight_zk_stdlib::{
    cs_degree,
    utils::plonk_api::{load_srs, SrsSource},
    MidnightPK, MidnightVK, Relation, ZkStdLib, ZkStdLibArch,
};
use rand::{rngs::OsRng, Rng};
use sha2::Digest;

use halo2_solidity_verifier::{
    compile_solidity_with_runs, encode_calldata_bls_padded, AccumulatorEncoding,
    BatchOpenScheme::Gwc19, CallOutcome, Evm, SolidityGenerator,
};

type S = BlstrsEmulation;
type F = <S as SelfEmulation>::F;
type C = <S as SelfEmulation>::C;
type E = <S as SelfEmulation>::Engine;

// ---------------------------------------------------------------------------
// Inner SHA-256 preimage circuit (mirror of
// midfall/aggregation/examples/common/sha_preimage.rs).
// ---------------------------------------------------------------------------

const SHA_K: u32 = 13;
const SHA_NB_PUBLIC_INPUTS: usize = 32;

#[derive(Clone, Debug, Default)]
struct ShaPreimageCircuit;

impl Relation for ShaPreimageCircuit {
    type Instance = [u8; 32];
    type Witness = [u8; 24];

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(instance
            .iter()
            .flat_map(midnight_circuits::types::AssignedByte::<F>::as_public_input)
            .collect())
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let witness_bytes = witness.transpose_array();
        let assigned_input = std_lib.assign_many(layouter, &witness_bytes)?;
        let output = std_lib.sha2_256(layouter, &assigned_input)?;
        output
            .iter()
            .try_for_each(|b| std_lib.constrain_as_public_input(layouter, b))
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            sha2_256: true,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(ShaPreimageCircuit)
    }
}

fn sha_random_instance() -> ([u8; 32], [u8; 24]) {
    let preimage: [u8; 24] = OsRng.gen();
    let digest: [u8; 32] = sha2::Sha256::digest(preimage).into();
    (digest, preimage)
}

fn sha_setup_vk(srs: &midnight_proofs::poly::kzg::params::ParamsKZG<E>) -> MidnightVK {
    midnight_zk_stdlib::setup_vk(srs, &ShaPreimageCircuit)
}

fn sha_setup_pk(vk: &MidnightVK) -> MidnightPK<ShaPreimageCircuit> {
    midnight_zk_stdlib::setup_pk(&ShaPreimageCircuit, vk)
}

fn sha_prove(
    srs: &midnight_proofs::poly::kzg::params::ParamsKZG<E>,
    pk: &MidnightPK<ShaPreimageCircuit>,
    instance: &[u8; 32],
    witness: [u8; 24],
) -> Vec<u8> {
    midnight_zk_stdlib::prove::<ShaPreimageCircuit, PoseidonState<F>>(
        srs,
        pk,
        &ShaPreimageCircuit,
        instance,
        witness,
        OsRng,
    )
    .expect("inner SHA proof generation should not fail")
}

// ---------------------------------------------------------------------------
// IVC ProofAggregation transition (mirror of
// midfall/aggregation/examples/single_circuit_aggregation.rs).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct InnerCircuitContext {
    cs: ConstraintSystem<F>,
    domain: EvaluationDomain<F>,
    vk: MidnightVK,
    params_verifier: ParamsVerifierKZG<E>,
}

impl InnerCircuitContext {
    fn fixed_bases(&self) -> BTreeMap<String, C> {
        verifier::fixed_bases::<S>("inner_vk", self.vk.vk())
    }
}

#[derive(Clone, Debug)]
struct State {
    statements: Vec<<ShaPreimageCircuit as Relation>::Instance>,
    statements_hash: F,
    inner_acc: Accumulator<S>,
}

#[derive(Clone, Debug)]
struct AssignedState {
    statements_hash: AssignedNative<F>,
    inner_acc: AssignedAccumulator<S>,
}

#[derive(Clone, Debug)]
struct AggregationWitness {
    inner_statement: <ShaPreimageCircuit as Relation>::Instance,
    inner_proof: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ProofAggregation {
    std_lib: ZkStdLib,
    inner_ctx: InnerCircuitContext,
}

impl IvcContext for ProofAggregation {
    type Context = InnerCircuitContext;
    fn new(std_lib: ZkStdLib, ctx: &InnerCircuitContext) -> Self {
        ProofAggregation {
            std_lib,
            inner_ctx: ctx.clone(),
        }
    }
    fn write_context<W: std::io::Write>(
        _ctx: &InnerCircuitContext,
        _writer: &mut W,
    ) -> std::io::Result<()> {
        unimplemented!()
    }
    fn read_context<R: std::io::Read>(_reader: &mut R) -> std::io::Result<InnerCircuitContext> {
        unimplemented!()
    }
}

impl IvcState for ProofAggregation {
    type State = State;
    type AssignedState = AssignedState;

    fn genesis(ctx: &InnerCircuitContext) -> Self::State {
        State {
            statements: vec![],
            statements_hash: F::ZERO,
            inner_acc: Accumulator::<S>::trivial(
                &ctx.fixed_bases().keys().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    fn is_genesis(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &Self::AssignedState,
    ) -> Result<AssignedBit<F>, Error> {
        self.std_lib.is_zero(layouter, &state.statements_hash)
    }

    fn decider(ctx: &InnerCircuitContext, state: &State) -> bool {
        let expected_hash = state.statements.iter().fold(F::ZERO, |h_acc, x| {
            let pis = ShaPreimageCircuit::format_instance(x).expect("valid instance");
            let h = <PoseidonChip<F> as HashCPU<F, F>>::hash(&pis);
            <PoseidonChip<F> as HashCPU<F, F>>::hash(&[h, h_acc])
        });
        if expected_hash != state.statements_hash {
            return false;
        }
        state
            .inner_acc
            .check(&ctx.params_verifier, &ctx.fixed_bases())
    }
}

impl IvcIO for ProofAggregation {
    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        value: Value<State>,
    ) -> Result<AssignedState, Error> {
        let statements_hash = self
            .std_lib
            .assign(layouter, value.as_ref().map(|s| s.statements_hash))?;
        let inner_acc = self.std_lib.verifier().assign_collapsed_accumulator(
            layouter,
            &self
                .inner_ctx
                .fixed_bases()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            value.as_ref().map(|s| s.inner_acc.clone()),
        )?;
        Ok(AssignedState {
            statements_hash,
            inner_acc,
        })
    }

    fn constrain_as_public_input(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &AssignedState,
    ) -> Result<(), Error> {
        self.std_lib
            .constrain_as_public_input(layouter, &state.statements_hash)?;
        self.std_lib
            .verifier()
            .constrain_as_public_input(layouter, &state.inner_acc)
    }

    fn as_public_input(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &AssignedState,
    ) -> Result<Vec<AssignedNative<F>>, Error> {
        Ok([
            self.std_lib
                .as_public_input(layouter, &state.statements_hash)?,
            self.std_lib
                .verifier()
                .as_public_input(layouter, &state.inner_acc)?,
        ]
        .concat())
    }

    fn format_public_input(state: &State) -> Vec<F> {
        [
            vec![state.statements_hash],
            AssignedAccumulator::<S>::as_public_input(&state.inner_acc),
        ]
        .concat()
    }
}

impl IvcTransition for ProofAggregation {
    type Witness = AggregationWitness;

    fn arch() -> ZkStdLibArch {
        ZkStdLibArch {
            poseidon: true,
            nr_pow2range_cols: 4,
            ..ZkStdLibArch::default()
        }
    }

    fn transition(
        ctx: &InnerCircuitContext,
        state: &Self::State,
        witness: Self::Witness,
    ) -> Self::State {
        let statement_pis =
            ShaPreimageCircuit::format_instance(&witness.inner_statement).expect("valid instance");

        let inner_proof_acc = {
            let mut transcript =
                CircuitTranscript::<PoseidonState<F>>::init_from_bytes(&witness.inner_proof);
            let dual_msm =
                plonk::prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>>(
                    ctx.vk.vk(),
                    &[&[C::identity()]],
                    &[&[&statement_pis]],
                    &mut transcript,
                )
                .expect("off-circuit prepare should succeed");
            assert!(
                dual_msm.clone().check(&ctx.params_verifier),
                "invalid inner proof"
            );
            Accumulator::from_dual_msm(dual_msm, "inner_vk", &ctx.fixed_bases())
        };

        let inner_acc = {
            let mut acc = Accumulator::accumulate(&[inner_proof_acc, state.inner_acc.clone()]);
            acc.collapse();
            acc
        };

        let statements_hash = {
            let h_statement = <PoseidonChip<F> as HashCPU<F, F>>::hash(&statement_pis);
            <PoseidonChip<F> as HashCPU<F, F>>::hash(&[h_statement, state.statements_hash])
        };

        let mut statements = state.statements.clone();
        statements.push(witness.inner_statement);

        State {
            statements,
            statements_hash,
            inner_acc,
        }
    }

    fn circuit_transition(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &Self::AssignedState,
        witness: Value<Self::Witness>,
    ) -> Result<Self::AssignedState, Error> {
        let inner_vk = self.std_lib.verifier().assign_fixed_vk(
            layouter,
            "inner_vk",
            &self.inner_ctx.domain,
            &self.inner_ctx.cs,
            self.inner_ctx.vk.vk().transcript_repr(),
        )?;

        let statement_pis = self.std_lib.assign_many(
            layouter,
            &witness
                .as_ref()
                .map(|w| ShaPreimageCircuit::format_instance(&w.inner_statement).unwrap())
                .transpose_vec(SHA_NB_PUBLIC_INPUTS),
        )?;

        let id_point = self
            .std_lib
            .bls12_381_curve()
            .assign_fixed(layouter, C::identity())?;

        let inner_proof_acc = self.std_lib.verifier().prepare(
            layouter,
            &inner_vk,
            &[id_point],
            &[&statement_pis],
            witness.map(|w| w.inner_proof),
        )?;

        let inner_acc = {
            let mut acc = self
                .std_lib
                .verifier()
                .accumulate(layouter, &[inner_proof_acc, state.inner_acc.clone()])?;
            acc.collapse(
                layouter,
                self.std_lib.bls12_381_curve(),
                self.std_lib.bls12_381_scalar(),
            )?;
            acc
        };

        let statements_hash = {
            let h_statement = self.std_lib.poseidon(layouter, &statement_pis)?;
            self.std_lib
                .poseidon(layouter, &[h_statement, state.statements_hash.clone()])?
        };

        Ok(AssignedState {
            statements_hash,
            inner_acc,
        })
    }
}

// ---------------------------------------------------------------------------
// e2e test
// ---------------------------------------------------------------------------

fn ivc_constraint_system(arch: ZkStdLibArch, k: u32) -> (ConstraintSystem<F>, EvaluationDomain<F>) {
    let mut cs = ConstraintSystem::default();
    ZkStdLib::configure(&mut cs, (arch, (k - 1) as u8));
    let domain = EvaluationDomain::new(cs.degree() as u32, k);
    (cs, domain)
}

#[test]
#[ignore = "slow IVC proving + solc + revm; ~10 min total. Run with --ignored --nocapture"]
fn ivc_final_keccak_solidity_e2e() {
    const IVC_K: u32 = 19;
    const STEPS: usize = 3;
    const SOLC_OPTIMIZE_RUNS: u32 = 1;

    // Bail out cleanly when solc isn't on PATH.
    if std::process::Command::new("solc")
        .arg("--version")
        .output()
        .is_err()
    {
        println!("[ivc-keccak-solidity] solc not found on PATH; skipping");
        return;
    }

    // ----------------------------------------------------------
    // Inner circuit: SHA-256 preimage at k = 13 (Filecoin SRS).
    // ----------------------------------------------------------
    let inner_arch = ShaPreimageCircuit.used_chips();
    let inner_srs = load_srs(SrsSource::Filecoin, SHA_K, cs_degree(inner_arch));
    let inner_vk = sha_setup_vk(&inner_srs);
    let inner_pk = sha_setup_pk(&inner_vk);
    let inner_ctx = {
        let (inner_cs, inner_domain) = ivc_constraint_system(inner_arch, SHA_K);
        InnerCircuitContext {
            cs: inner_cs,
            domain: inner_domain,
            vk: inner_vk,
            params_verifier: inner_srs.verifier_params(),
        }
    };

    let start = Instant::now();
    let inner_statements_with_witnesses: [_; STEPS] =
        std::array::from_fn(|_| sha_random_instance());
    let inner_proofs: [_; STEPS] = std::array::from_fn(|i| {
        let (digest, preimage) = &inner_statements_with_witnesses[i];
        sha_prove(&inner_srs, &inner_pk, digest, *preimage)
    });
    let inner_statements = inner_statements_with_witnesses.map(|(x, _)| x);
    println!(
        "[ivc-keccak-solidity] {STEPS} inner SHA proofs generated in {:.2?}",
        start.elapsed()
    );

    // ----------------------------------------------------------
    // IVC chain (Midnight SRS at k = 19).
    // ----------------------------------------------------------
    let ivc_srs = load_srs(
        SrsSource::Midnight,
        IVC_K,
        IvcCircuit::<ProofAggregation>::cs_degree(),
    );
    let start = Instant::now();
    let (mut prover, verifier) =
        ivc::setup::<ProofAggregation>(ivc_srs.clone(), IVC_K, inner_ctx.clone());
    println!(
        "[ivc-keccak-solidity] IVC setup completed in {:.2?}",
        start.elapsed()
    );

    for i in 0..STEPS - 1 {
        let w = AggregationWitness {
            inner_statement: inner_statements[i],
            inner_proof: inner_proofs[i].clone(),
        };
        let t0 = Instant::now();
        let p = prover.prove_step(w).unwrap();
        let dt = t0.elapsed();
        let inst = prover.instance();
        let t0 = Instant::now();
        verifier.verify(&inner_ctx, &inst, &p).unwrap();
        println!(
            "[ivc-keccak-solidity] Step {i} (Poseidon): prove {dt:.2?}, verify {:.2?}",
            t0.elapsed()
        );
    }

    let last = STEPS - 1;
    let final_witness = AggregationWitness {
        inner_statement: inner_statements[last],
        inner_proof: inner_proofs[last].clone(),
    };
    let t0 = Instant::now();
    let final_proof = prover
        .prove_final_step(final_witness)
        .expect("prove_final_step should succeed");
    println!(
        "[ivc-keccak-solidity] Step {last} (Keccak):   prove {:.2?} ({} bytes compressed)",
        t0.elapsed(),
        final_proof.len()
    );
    let final_instance = prover.instance();

    // Sanity: native verify_final must accept the proof.
    let t0 = Instant::now();
    verifier
        .verify_final::<ProofAggregation>(&inner_ctx, &final_instance, &final_proof)
        .expect("native verify_final must accept the prove_final_step output");
    println!(
        "[ivc-keccak-solidity] native verify_final: OK ({:.2?})",
        t0.elapsed()
    );

    // ----------------------------------------------------------
    // Render Halo2Verifier.sol + Halo2VerifyingKey.sol.
    // ----------------------------------------------------------
    // Public input vector exactly mirrors `IvcCircuit::format_instance`.
    let pi: Vec<F> =
        IvcCircuit::<ProofAggregation>::format_instance(&final_instance).expect("format_instance");

    // ZkStdLib creates 2 instance columns (one committed, one
    // non-committed). num_instances counts the non-committed slots.
    //
    // IvcCircuit::format_instance(instance) =
    //   [self_vk_repr, transition_state_public_inputs..., outer_acc].
    // The Solidity verifier must consume `outer_acc` for the final
    // accumulator pairing check, so pass its starting instance offset.
    let num_instances = pi.len();
    let outer_acc_offset = 1 + ProofAggregation::format_public_input(final_instance.state()).len();
    let generator = SolidityGenerator::new(&ivc_srs, verifier.vk().vk(), Gwc19, num_instances)
        .set_num_committed_instances(1)
        .set_acc_encoding(Some(AccumulatorEncoding::new(outer_acc_offset, 7, 56)));
    let gas_checkpoints_enabled = halo2_solidity_verifier::SOLIDITY_GAS_CHECKPOINTS_ENABLED;

    let t0 = Instant::now();
    let (verifier_solidity, vk_solidity) = generator
        .render_separately()
        .expect("render_separately should succeed");
    println!(
        "[ivc-keccak-solidity] rendered Halo2Verifier.sol = {} bytes, Halo2VerifyingKey.sol = {} bytes (took {:.2?})",
        verifier_solidity.len(),
        vk_solidity.len(),
        t0.elapsed()
    );

    // Persist for post-mortem inspection.
    let dump_dir = format!(
        "{}/target/ivc-keccak-solidity-dump",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::create_dir_all(&dump_dir).ok();
    std::fs::write(format!("{dump_dir}/Halo2Verifier.sol"), &verifier_solidity).ok();
    std::fs::write(format!("{dump_dir}/Halo2VerifyingKey.sol"), &vk_solidity).ok();
    std::fs::write(format!("{dump_dir}/proof.bin"), &final_proof).ok();
    let pi_bytes: Vec<u8> = pi
        .iter()
        .flat_map(|f| <F as ff::PrimeField>::to_repr(f).as_ref().to_vec())
        .collect();
    std::fs::write(format!("{dump_dir}/instance.le"), &pi_bytes).ok();
    println!("[ivc-keccak-solidity] saved generated contracts under {dump_dir}");

    // ----------------------------------------------------------
    // Compile + deploy on Prague-spec revm.
    // ----------------------------------------------------------
    let t0 = Instant::now();
    let vk_creation_code = compile_solidity_with_runs(&vk_solidity, SOLC_OPTIMIZE_RUNS);
    let verifier_creation_code = compile_solidity_with_runs(&verifier_solidity, SOLC_OPTIMIZE_RUNS);
    let vk_creation_size = vk_creation_code.len();
    let verifier_creation_size = verifier_creation_code.len();
    std::fs::write(
        format!("{dump_dir}/Halo2Verifier.creation.bin"),
        &verifier_creation_code,
    )
    .ok();
    std::fs::write(
        format!("{dump_dir}/Halo2VerifyingKey.creation.bin"),
        &vk_creation_code,
    )
    .ok();
    println!(
        "[ivc-keccak-solidity] solc compile completed in {:.2?} (optimize-runs = {SOLC_OPTIMIZE_RUNS}, no CBOR; verifier creation bytecode = {} bytes, vk creation bytecode = {} bytes)",
        t0.elapsed(),
        verifier_creation_size,
        vk_creation_size
    );

    let mut evm = Evm::default();
    let vk_address = evm.create(vk_creation_code);
    let verifier_address = evm.create_with_address_arg(verifier_creation_code, vk_address);
    let vk_runtime_size = evm.code_size(vk_address);
    let verifier_runtime_size = evm.code_size(verifier_address);
    let contract_size_summary = format!(
        "solc optimize runs: {SOLC_OPTIMIZE_RUNS}\n\
         solc CBOR metadata: omitted\n\
         Halo2Verifier.sol source bytes: {}\n\
         Halo2VerifyingKey.sol source bytes: {}\n\
         Halo2Verifier creation bytecode bytes: {verifier_creation_size}\n\
         Halo2VerifyingKey creation bytecode bytes: {vk_creation_size}\n\
         Halo2Verifier deployed runtime bytes: {verifier_runtime_size}\n\
         Halo2VerifyingKey deployed runtime bytes: {vk_runtime_size}\n\
         total deployed runtime bytes: {}\n",
        verifier_solidity.len(),
        vk_solidity.len(),
        verifier_runtime_size + vk_runtime_size
    );
    std::fs::write(
        format!("{dump_dir}/contract-sizes.txt"),
        contract_size_summary,
    )
    .ok();
    println!(
        "[ivc-keccak-solidity] deployed (vk = {vk_address:?}, verifier = {verifier_address:?})"
    );
    println!(
        "[ivc-keccak-solidity] contract sizes: verifier runtime = {verifier_runtime_size} bytes, vk runtime = {vk_runtime_size} bytes, total runtime = {} bytes",
        verifier_runtime_size + vk_runtime_size
    );

    // ----------------------------------------------------------
    // Repack the compressed proof into EIP-2537 padded form.
    // ----------------------------------------------------------
    let t0 = Instant::now();
    let repacked = generator.repack_compressed_proof(&final_proof);
    println!(
        "[ivc-keccak-solidity] repacked compressed -> padded: {} -> {} bytes ({:.2?})",
        final_proof.len(),
        repacked.len(),
        t0.elapsed()
    );

    let calldata = encode_calldata_bls_padded(&generator, &repacked, &pi);
    println!(
        "[ivc-keccak-solidity] calldata = {} bytes (pi = {} field elements)",
        calldata.len(),
        pi.len()
    );
    std::fs::write(format!("{dump_dir}/calldata.bin"), &calldata).ok();

    // ----------------------------------------------------------
    // Call verifyProof. Gas cap raised to 500M for the IVC verifier
    // (k=19, ~20+ advice columns); the Poseidon-fixture default
    // (50M) is too tight for this circuit shape.
    // ----------------------------------------------------------
    match evm.try_call_with_gas(verifier_address, calldata, 5_000_000_000) {
        CallOutcome::Success {
            gas_used,
            output,
            logs,
        } => {
            if gas_checkpoints_enabled {
                dump_gas_checkpoints(&logs, gas_used);
            }
            let expected: Vec<u8> = [vec![0u8; 31], vec![1]].concat();
            assert_eq!(
                output,
                expected,
                "verifier returned 0x{} (expected 0x...01)",
                hex::encode(&output)
            );
            println!(
                "[ivc-keccak-solidity] PASS: IVC final Keccak proof accepted on-chain in {gas_used} gas"
            );
        }
        CallOutcome::Revert { gas_used, output } => {
            panic!(
                "verifier reverted at gas_used = {gas_used}, output = 0x{}",
                hex::encode(&output)
            );
        }
        CallOutcome::Halt { gas_used, reason } => {
            panic!("verifier halted at gas_used = {gas_used}, reason = {reason}");
        }
    }
}

/// Parse LOG1 checkpoint events emitted by `--features solidity-gas-checkpoints`
/// and print a section-level gas breakdown for the final IVC verifier.
fn dump_gas_checkpoints(logs: &[halo2_solidity_verifier::revm::primitives::Log], gas_used: u64) {
    let mut events: Vec<(u8, u64)> = logs
        .iter()
        .filter_map(|log| {
            let topic = log.data.topics().first()?;
            let bytes = topic.as_slice();
            // Gas checkpoints encode `(id << 248) | gas()` so the upper byte is
            // the checkpoint id. Trace logs use small raw topics and therefore
            // have an upper byte of zero.
            let id = bytes[0];
            if id == 0 {
                return None;
            }
            let gas = u64::from_be_bytes(bytes[24..32].try_into().ok()?);
            Some((id, gas))
        })
        .collect();

    events.sort_by(|a, b| b.1.cmp(&a.1));

    if events.is_empty() {
        println!(
            "[ivc-keccak-solidity][gas] no checkpoint events found in {} LOG entries",
            logs.len()
        );
        return;
    }

    let pcs_set_count = events
        .iter()
        .filter_map(|(id, _)| (*id >= 17).then_some(*id))
        .max()
        .and_then(|max_id| max_id.checked_sub(20));

    println!();
    println!("=== IVC Keccak Solidity gas-checkpoint breakdown ===");
    if let Some(n) = pcs_set_count {
        println!("[ivc-keccak-solidity][gas] inferred PCS point sets = {n}");
    }
    println!(
        "{:>4}  {:>14}  {:>12}  {:>7}  section",
        "id", "gas_left", "delta", "%"
    );

    // LOG1 with one topic and no data costs about 750 gas. Subtract one
    // checkpoint from each pairwise delta so the table reflects verifier work
    // instead of measurement overhead.
    const CHECKPOINT_COST: u64 = 750;

    let total_billed = events[0].1.saturating_sub(events[events.len() - 1].1);
    let total_real_work = total_billed.saturating_sub(events.len() as u64 * CHECKPOINT_COST);

    let mut prev_gas = events[0].1;
    let cp1_gas = events[0].1;
    println!(
        "{:>4}  {:>14}  {:>12}  {:>7}  {}",
        events[0].0,
        format_u64(prev_gas),
        "-",
        "-",
        checkpoint_name(events[0].0, pcs_set_count),
    );

    for (id, gas) in events.iter().skip(1) {
        let raw_delta = prev_gas.saturating_sub(*gas);
        let net_delta = raw_delta.saturating_sub(CHECKPOINT_COST);
        let pct = if total_real_work > 0 {
            (net_delta as f64 / total_real_work as f64) * 100.0
        } else {
            0.0
        };
        println!(
            "{:>4}  {:>14}  {:>12}  {:>6.1}%  {}",
            id,
            format_u64(*gas),
            format_u64(net_delta),
            pct,
            checkpoint_name(*id, pcs_set_count),
        );
        prev_gas = *gas;
    }

    println!();
    println!(
        "  cp1 gas_left            = {} (verifier entry)",
        format_u64(cp1_gas)
    );
    println!(
        "  last..cp1 gas billed    = {} (work between first and last checkpoint)",
        format_u64(total_billed)
    );
    println!(
        "  - measurement overhead  = {} ({} checkpoints x {} gas)",
        format_u64(events.len() as u64 * CHECKPOINT_COST),
        events.len(),
        CHECKPOINT_COST
    );
    println!(
        "  = real section work     = {}",
        format_u64(total_real_work)
    );
    println!(
        "  total tx gas_used       = {} (incl. tx base + calldata + pre-cp1 + post-last)",
        format_u64(gas_used)
    );
}

fn checkpoint_name(id: u8, pcs_set_count: Option<u8>) -> String {
    match id {
        1 => "entry (before VK loading)".to_string(),
        2 => "VK loading".to_string(),
        3 => "VK digest + committed_pi + instance absorbs".to_string(),
        4 => "user-phase advice reads + user challenge squeezes".to_string(),
        5 => "theta squeeze + lookup multiplicities".to_string(),
        6 => "beta/gamma + permutation Z products".to_string(),
        7 => "lookup helpers + Z accumulators".to_string(),
        8 => "trash_challenge + trashcans".to_string(),
        9 => "y squeeze + quotient-limb reads".to_string(),
        10 => "evaluations + x1/x2 + f_com + x3 + q_evals + x4 + pi".to_string(),
        11 => "Lagrange + instance evaluation".to_string(),
        12 => "quotient evaluation (Fr arithmetic)".to_string(),
        13 => "linearization-commitment MSM".to_string(),
        14 => "PCS block 6 (pairing inputs LHS/RHS)".to_string(),
        15 => "public accumulator pairing check".to_string(),
        16 => "final proof ec_pairing".to_string(),
        17 => "PCS block 1 (rotation points x*omega^rot)".to_string(),
        18 => "PCS block 2 (x1 powers)".to_string(),
        id if id >= 19 => {
            if let Some(n) = pcs_set_count {
                let idx = id - 19;
                if idx < n {
                    return format!("PCS block 3 set {idx} (q_com/q_eval fold)");
                }
                if idx == n {
                    return "PCS block 4 (f_eval Lagrange interpolation)".to_string();
                }
                if idx == n + 1 {
                    return "PCS block 5 (final_com x4-power MSM + v)".to_string();
                }
            }
            format!("PCS sub-block checkpoint {id}")
        }
        _ => "<unknown>".to_string(),
    }
}

fn format_u64(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}
