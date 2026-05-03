//! End-to-end on-chain verification of a Keccak-transcript decider proof for
//! a two-leaf IVC SHA-256 aggregation tree.
//!
//! Pipeline:
//!   1. Build the IVC circuit (k = 19, ProofAggregation transition).
//!   2. Produce two independent one-step IVC proofs under the Poseidon
//!      transcript; these are the leaves of the tree.
//!   3. Build a final decider circuit (k = 20) that verifies both IVC leaves,
//!      accumulates their final proof accumulators, and fully collapses
//!      the result over the fixed IVC VK bases.
//!   4. Prove that decider circuit under Keccak-256, render
//!      `Halo2Verifier.sol` + `Halo2VerifyingKey.sol` against the decider
//!      VK with `truncated-challenges` and the fewer-point-set proof layout
//!      enabled.
//!   5. Compile the Solidity, deploy on Prague-spec revm (EIP-2537
//!      precompiles routed through blst), repack the proof off-chain
//!      via `SolidityGenerator::repack_compressed_proof`, encode
//!      calldata, call `verifyProof`.
//!   6. Assert success and dump gas.
//!
//! Required features: `evm`, `truncated-challenges`,
//! `in-circuit-fewer-point-sets`, `outer-fewer-point-sets`.
//! Midnight crates are pulled from the published midfall `keccak` branch
//! configured in `Cargo.toml`; `SRS_DIR` still needs to point at local SRS
//! assets.
//! Run:
//!
//! ```text
//! HALO2_SOLIDITY_RUN_IVC_BENCH=1 \
//!   SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
//!   cargo test --release \
//!     --features evm,truncated-challenges,in-circuit-fewer-point-sets,outer-fewer-point-sets \
//!     --test ivc_keccak_solidity \
//!     -- --nocapture
//! ```
//!
//! Enable the detailed gas benchmark with:
//!
//! ```text
//! HALO2_SOLIDITY_RUN_IVC_BENCH=1 \
//!   SRS_DIR=/path/to/midfall/zk_stdlib/examples/assets \
//!   cargo test --release \
//!     --features evm,truncated-challenges,in-circuit-fewer-point-sets,outer-fewer-point-sets,solidity-gas-checkpoints \
//!     --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
//!     -- --nocapture
//! ```
//!
//! Native Rust/Solidity trace equivalence needs a local Midfall checkout that
//! exposes `midnight_proofs::plonk::solidity_trace`.

#![cfg(all(
    feature = "evm",
    feature = "truncated-challenges",
    feature = "in-circuit-fewer-point-sets",
    feature = "outer-fewer-point-sets",
))]

use std::{collections::BTreeMap, time::Instant};

use ff::Field;
use group::Group;
use midnight_aggregation::ivc::{self, IvcCircuit, IvcContext, IvcIO, IvcState, IvcTransition};
use midnight_circuits::{
    hash::poseidon::{PoseidonChip, PoseidonState},
    instructions::{hash::HashCPU, *},
    types::{AssignedBit, AssignedNative, InnerValue, Instantiable},
    verifier::{self, Accumulator, AssignedAccumulator, BlstrsEmulation, Msm, SelfEmulation},
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
    compile_solidity_with_runs, encode_calldata_bls_padded, AccumulatorEncoding, CallOutcome, Evm,
    ProofEvaluationCounts, SolidityGenerator,
};

type S = BlstrsEmulation;
type F = <S as SelfEmulation>::F;
type C = <S as SelfEmulation>::C;
type E = <S as SelfEmulation>::Engine;

const RUN_IVC_BENCH_ENV: &str = "HALO2_SOLIDITY_RUN_IVC_BENCH";

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

fn fully_collapsed_accumulator(
    acc: &Accumulator<S>,
    fixed_bases: &BTreeMap<String, C>,
) -> Accumulator<S> {
    let (lhs, rhs) = acc.fully_collapse(fixed_bases);
    Accumulator::new(
        Msm::from_terms(&[lhs], &[F::ONE]),
        Msm::from_terms(&[rhs], &[F::ONE]),
    )
}

fn constrain_fully_collapsed_accumulator(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    acc: AssignedAccumulator<S>,
    fixed_bases: &BTreeMap<String, C>,
) -> Result<AssignedAccumulator<S>, Error> {
    let (lhs, rhs) = acc.fully_collapse(layouter, std_lib.bls12_381_curve(), fixed_bases)?;
    let collapsed_value = acc
        .value()
        .map(|acc| fully_collapsed_accumulator(&acc, fixed_bases));
    let collapsed =
        std_lib
            .verifier()
            .assign_collapsed_accumulator(layouter, &[], collapsed_value)?;

    let one: AssignedNative<F> = std_lib.assign_fixed(layouter, F::ONE)?;
    let expected = [
        std_lib.bls12_381_curve().as_public_input(layouter, &lhs)?,
        vec![one.clone()],
        std_lib.bls12_381_curve().as_public_input(layouter, &rhs)?,
        vec![one],
    ]
    .concat();
    let actual = std_lib.verifier().as_public_input(layouter, &collapsed)?;
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected.iter()) {
        std_lib.assert_equal(layouter, actual, expected)?;
    }

    Ok(collapsed)
}

fn constrain_same_accumulator_public_input(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    lhs: &AssignedAccumulator<S>,
    rhs: &AssignedAccumulator<S>,
) -> Result<(), Error> {
    let lhs = std_lib.verifier().as_public_input(layouter, lhs)?;
    let rhs = std_lib.verifier().as_public_input(layouter, rhs)?;
    assert_eq!(lhs.len(), rhs.len());
    for (lhs, rhs) in lhs.iter().zip(rhs.iter()) {
        std_lib.assert_equal(layouter, lhs, rhs)?;
    }
    Ok(())
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

    fn genesis(_ctx: &InnerCircuitContext) -> Self::State {
        State {
            statements: vec![],
            statements_hash: F::ZERO,
            inner_acc: Accumulator::<S>::trivial(&[]),
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
            &[],
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

        let inner_acc = Accumulator::accumulate(&[inner_proof_acc, state.inner_acc.clone()]);
        let inner_acc = fully_collapsed_accumulator(&inner_acc, &ctx.fixed_bases());

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

        let id_point: <S as SelfEmulation>::AssignedPoint = self
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

        let inner_acc = self
            .std_lib
            .verifier()
            .accumulate(layouter, &[inner_proof_acc, state.inner_acc.clone()])?;
        let inner_acc = constrain_fully_collapsed_accumulator(
            &self.std_lib,
            layouter,
            inner_acc,
            &self.inner_ctx.fixed_bases(),
        )?;

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
// Final two-leaf tree decider.
// ---------------------------------------------------------------------------

const TREE_LEAVES: usize = 2;

#[derive(Clone, Debug)]
struct TreeDeciderContext {
    inner_ctx: InnerCircuitContext,
    ivc_cs: ConstraintSystem<F>,
    ivc_domain: EvaluationDomain<F>,
    ivc_vk: MidnightVK,
    ivc_params_verifier: ParamsVerifierKZG<E>,
}

impl TreeDeciderContext {
    fn ivc_fixed_bases(&self) -> BTreeMap<String, C> {
        verifier::fixed_bases::<S>("ivc_vk", self.ivc_vk.vk())
    }

    fn ivc_fixed_base_names(&self) -> Vec<String> {
        self.ivc_fixed_bases().keys().cloned().collect()
    }

    fn one_step_outer_acc(&self) -> Accumulator<S> {
        Accumulator::<S>::trivial(&self.ivc_fixed_base_names())
    }

    fn leaf_public_input(&self, state: &State) -> Vec<F> {
        [
            vec![self.ivc_vk.vk().transcript_repr()],
            ProofAggregation::format_public_input(state),
            AssignedAccumulator::<S>::as_public_input(&self.one_step_outer_acc()),
        ]
        .concat()
    }

    fn leaf_final_acc(&self, state: &State, proof: &[u8]) -> Accumulator<S> {
        let leaf_pi = self.leaf_public_input(state);
        let mut transcript = CircuitTranscript::<PoseidonState<F>>::init_from_bytes(proof);
        let dual_msm =
            plonk::prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>>(
                self.ivc_vk.vk(),
                &[&[C::identity()]],
                &[&[&leaf_pi]],
                &mut transcript,
            )
            .expect("off-circuit IVC leaf prepare should succeed");
        transcript
            .assert_empty()
            .expect("IVC leaf transcript should be consumed");
        assert!(
            dual_msm.clone().check(&self.ivc_params_verifier),
            "invalid IVC leaf proof"
        );

        let proof_acc = Accumulator::from_dual_msm(dual_msm, "ivc_vk", &self.ivc_fixed_bases());
        Accumulator::accumulate(&[proof_acc, self.one_step_outer_acc()])
    }

    fn final_acc(&self, leaves: &[TreeLeafWitness; TREE_LEAVES]) -> Accumulator<S> {
        let leaf_accs = leaves
            .iter()
            .map(|leaf| self.leaf_final_acc(&leaf.state, &leaf.proof))
            .collect::<Vec<_>>();
        let acc = Accumulator::accumulate(&leaf_accs);
        fully_collapsed_accumulator(&acc, &self.ivc_fixed_bases())
    }
}

#[derive(Clone, Debug)]
struct TreeDeciderInstance {
    leaf_statement_hashes: [F; TREE_LEAVES],
    final_acc: Accumulator<S>,
}

#[derive(Clone, Debug)]
struct TreeLeafWitness {
    state: State,
    proof: Vec<u8>,
}

#[derive(Clone, Debug)]
struct TreeDeciderWitness {
    leaves: [TreeLeafWitness; TREE_LEAVES],
}

#[derive(Clone, Debug)]
struct IvcTreeDeciderCircuit {
    ctx: TreeDeciderContext,
}

impl IvcTreeDeciderCircuit {
    fn new(ctx: TreeDeciderContext) -> Self {
        Self { ctx }
    }

    fn arch() -> ZkStdLibArch {
        ZkStdLibArch {
            bls12_381: true,
            poseidon: true,
            nr_pow2range_cols: 4,
            ..ZkStdLibArch::default()
        }
    }
}

impl Relation for IvcTreeDeciderCircuit {
    type Instance = TreeDeciderInstance;
    type Witness = TreeDeciderWitness;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok([
            instance.leaf_statement_hashes.to_vec(),
            AssignedAccumulator::<S>::as_public_input(&instance.final_acc),
        ]
        .concat())
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let verifier_gadget = std_lib.verifier();
        let proof_aggregation = ProofAggregation::new(std_lib.clone(), &self.ctx.inner_ctx);

        let mut public_leaf_hashes = Vec::with_capacity(TREE_LEAVES);
        for i in 0..TREE_LEAVES {
            public_leaf_hashes.push(
                std_lib.assign(
                    layouter,
                    instance
                        .as_ref()
                        .map(|instance| instance.leaf_statement_hashes[i]),
                )?,
            );
        }
        for hash in &public_leaf_hashes {
            std_lib.constrain_as_public_input(layouter, hash)?;
        }

        let public_final_acc = verifier_gadget.assign_collapsed_accumulator(
            layouter,
            &[],
            instance.as_ref().map(|instance| instance.final_acc.clone()),
        )?;
        verifier_gadget.constrain_as_public_input(layouter, &public_final_acc)?;

        let assigned_ivc_vk = verifier_gadget.assign_fixed_vk(
            layouter,
            "ivc_vk",
            &self.ctx.ivc_domain,
            &self.ctx.ivc_cs,
            self.ctx.ivc_vk.vk().transcript_repr(),
        )?;
        let ivc_vk_pi = verifier_gadget.as_public_input(layouter, &assigned_ivc_vk)?;
        let id_point: <S as SelfEmulation>::AssignedPoint = std_lib
            .bls12_381_curve()
            .assign_fixed(layouter, C::identity())?;
        let outer_acc_value = Value::known(self.ctx.one_step_outer_acc());
        let outer_acc = verifier_gadget.assign_collapsed_accumulator(
            layouter,
            &self.ctx.ivc_fixed_base_names(),
            outer_acc_value,
        )?;
        let outer_acc_pi = verifier_gadget.as_public_input(layouter, &outer_acc)?;

        let mut leaf_accs = Vec::with_capacity(TREE_LEAVES);
        for (i, public_hash) in public_leaf_hashes.iter().enumerate() {
            let leaf_state = proof_aggregation.assign(
                layouter,
                witness
                    .as_ref()
                    .map(|witness| witness.leaves[i].state.clone()),
            )?;
            let leaf_state_pi = proof_aggregation.as_public_input(layouter, &leaf_state)?;
            std_lib.assert_equal(layouter, public_hash, &leaf_state_pi[0])?;

            let leaf_pi = [ivc_vk_pi.clone(), leaf_state_pi, outer_acc_pi.clone()].concat();
            let proof_acc = verifier_gadget.prepare(
                layouter,
                &assigned_ivc_vk,
                std::slice::from_ref(&id_point),
                &[&leaf_pi],
                witness
                    .as_ref()
                    .map(|witness| witness.leaves[i].proof.clone()),
            )?;
            let leaf_acc = verifier_gadget.accumulate(layouter, &[proof_acc, outer_acc.clone()])?;
            leaf_accs.push(leaf_acc);
        }

        let final_acc = verifier_gadget.accumulate(layouter, &leaf_accs)?;
        let final_acc = constrain_fully_collapsed_accumulator(
            std_lib,
            layouter,
            final_acc,
            &self.ctx.ivc_fixed_bases(),
        )?;
        constrain_same_accumulator_public_input(std_lib, layouter, &final_acc, &public_final_acc)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        Self::arch()
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        unimplemented!()
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

fn srs_dir() -> String {
    std::env::var("SRS_DIR").unwrap_or_else(|_| "./examples/assets".to_string())
}

fn has_required_srs_assets() -> bool {
    let srs_dir = srs_dir();
    let mut ok = true;

    let filecoin_2p13 = format!("{srs_dir}/bls_filecoin_2p13");
    let filecoin_2p19 = format!("{srs_dir}/bls_filecoin_2p19");
    if !std::path::Path::new(&filecoin_2p13).is_file()
        && !std::path::Path::new(&filecoin_2p19).is_file()
    {
        println!(
            "[ivc-keccak-solidity] missing Filecoin SRS: need {filecoin_2p13} or {filecoin_2p19}"
        );
        ok = false;
    }

    for k in [19, 20] {
        let path = format!("{srs_dir}/midnight-srs-2p{k}");
        if !std::path::Path::new(&path).is_file() {
            println!(
                "[ivc-keccak-solidity] missing Midnight SRS: {path}\n\
                 [ivc-keccak-solidity] download with: curl -L -o {path} https://srs.midnight.network/midnight-srs-2p{k}"
            );
            ok = false;
        }
    }

    ok
}

fn proof_evaluation_count_summary(counts: &ProofEvaluationCounts) -> String {
    format!(
        "proof eval scalars total: {} (main: {}, dummy PCS: {})\n\
         instances: {} proof evals from committed instance queries, {} public-input evals computed locally ({} total identity inputs)\n\
         advice evals: {}\n\
         fixed evals: {} proof evals ({} simple-selector fixed columns omitted from proof)\n\
         permutation evals: {} total ({} common/sigma, {} product/Z across {} sets)\n\
         lookup evals: {} total ({} multiplicity, {} helper, {} accumulator z/z_next)\n\
         trash evals: {}\n",
        counts.proof_total(),
        counts.proof_main_total(),
        counts.dummy,
        counts.committed_instance,
        counts.computed_instance,
        counts.instance_total_for_identities(),
        counts.advice,
        counts.fixed,
        counts.simple_selector_fixed,
        counts.permutation_total(),
        counts.permutation_common,
        counts.permutation_product,
        counts.permutation_sets,
        counts.lookup_total(),
        counts.lookup_multiplicity,
        counts.lookup_helper,
        counts.lookup_accumulator,
        counts.trash
    )
}

fn print_proof_evaluation_counts(counts: &ProofEvaluationCounts) {
    println!("\n=== IVC Keccak Solidity proof evaluation counts ===");
    for line in proof_evaluation_count_summary(counts).lines() {
        println!("[ivc-keccak-solidity][evals] {line}");
    }
}

#[test]
fn ivc_final_keccak_solidity_e2e() {
    const IVC_K: u32 = 19;
    const DECIDER_K: u32 = 20;
    const SOLC_OPTIMIZE_RUNS: u32 = 1;
    const EIP170_MAX_RUNTIME_SIZE: usize = 0x6000;

    if !env_flag_enabled(RUN_IVC_BENCH_ENV) {
        println!("[ivc-keccak-solidity] set {RUN_IVC_BENCH_ENV}=1 to run the full bench");
        return;
    }

    // Bail out cleanly when solc isn't on PATH.
    let solc = std::env::var("SOLC").unwrap_or_else(|_| "solc".to_string());
    if std::process::Command::new(&solc)
        .arg("--version")
        .output()
        .is_err()
    {
        println!("[ivc-keccak-solidity] {solc} not found on PATH; skipping");
        return;
    }
    if !has_required_srs_assets() {
        println!("[ivc-keccak-solidity] required SRS assets missing; skipping");
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
    let inner_statements_with_witnesses: [_; TREE_LEAVES] =
        std::array::from_fn(|_| sha_random_instance());
    let inner_proofs: [_; TREE_LEAVES] = std::array::from_fn(|i| {
        let (digest, preimage) = &inner_statements_with_witnesses[i];
        sha_prove(&inner_srs, &inner_pk, digest, *preimage)
    });
    let inner_statements = inner_statements_with_witnesses.map(|(x, _)| x);
    println!(
        "[ivc-keccak-solidity] {TREE_LEAVES} inner SHA proofs generated in {:.2?}",
        start.elapsed()
    );

    // ----------------------------------------------------------
    // Two independent one-step IVC leaves (Midnight SRS at k = 19).
    // ----------------------------------------------------------
    let ivc_srs = load_srs(
        SrsSource::Midnight,
        IVC_K,
        IvcCircuit::<ProofAggregation>::cs_degree(),
    );
    let start = Instant::now();
    let (leaf_prover, verifier) =
        ivc::setup::<ProofAggregation>(ivc_srs.clone(), IVC_K, inner_ctx.clone());
    println!(
        "[ivc-keccak-solidity] IVC setup completed in {:.2?}",
        start.elapsed()
    );

    let mut leaf_witnesses = Vec::with_capacity(TREE_LEAVES);
    for i in 0..TREE_LEAVES {
        let w = AggregationWitness {
            inner_statement: inner_statements[i],
            inner_proof: inner_proofs[i].clone(),
        };
        let mut prover = leaf_prover.clone();
        let t0 = Instant::now();
        let p = prover.prove_step(w).unwrap();
        let dt = t0.elapsed();
        let inst = prover.instance();
        let t0 = Instant::now();
        verifier.verify(&inner_ctx, &inst, &p).unwrap();
        println!(
            "[ivc-keccak-solidity] Leaf {i} IVC (Poseidon): prove {dt:.2?}, verify {:.2?}",
            t0.elapsed()
        );
        leaf_witnesses.push(TreeLeafWitness {
            state: inst.state().clone(),
            proof: p,
        });
    }

    let leaf_witnesses: [TreeLeafWitness; TREE_LEAVES] =
        leaf_witnesses.try_into().expect("exactly two tree leaves");

    // ----------------------------------------------------------
    // Final tree decider proof under Keccak.
    // ----------------------------------------------------------
    let (ivc_cs, ivc_domain) = ivc_constraint_system(IvcCircuit::<ProofAggregation>::arch(), IVC_K);
    let decider_ctx = TreeDeciderContext {
        inner_ctx: inner_ctx.clone(),
        ivc_cs,
        ivc_domain,
        ivc_vk: verifier.vk().clone(),
        ivc_params_verifier: ivc_srs.verifier_params(),
    };
    let decider_relation = IvcTreeDeciderCircuit::new(decider_ctx.clone());
    let decider_instance = TreeDeciderInstance {
        leaf_statement_hashes: std::array::from_fn(|i| leaf_witnesses[i].state.statements_hash),
        final_acc: decider_ctx.final_acc(&leaf_witnesses),
    };
    let no_fixed_bases = BTreeMap::new();
    assert!(
        decider_instance
            .final_acc
            .check(&ivc_srs.verifier_params(), &no_fixed_bases),
        "fully-collapsed carried IVC accumulator must satisfy the pairing invariant"
    );
    println!("[ivc-keccak-solidity] collapsed carried IVC accumulator: OK");
    let decider_witness = TreeDeciderWitness {
        leaves: leaf_witnesses,
    };

    let decider_srs = load_srs(
        SrsSource::Midnight,
        DECIDER_K,
        cs_degree(IvcTreeDeciderCircuit::arch()),
    );
    let start = Instant::now();
    let decider_vk = midnight_zk_stdlib::setup_vk(&decider_srs, &decider_relation);
    let decider_pk = midnight_zk_stdlib::setup_pk(&decider_relation, &decider_vk);
    println!(
        "[ivc-keccak-solidity] tree decider setup completed in {:.2?}",
        start.elapsed()
    );

    if cfg!(feature = "outer-fewer-point-sets") {
        println!(
            "[ivc-keccak-solidity] outer proof fewer-point-sets: enabled (dummy query evals expected)"
        );
    } else {
        println!(
            "[ivc-keccak-solidity] outer proof fewer-point-sets: disabled (published Midfall uses cargo feature state)"
        );
    }

    let t0 = Instant::now();
    let final_proof = midnight_zk_stdlib::prove::<IvcTreeDeciderCircuit, sha3::Keccak256>(
        &decider_srs,
        &decider_pk,
        &decider_relation,
        &decider_instance,
        decider_witness,
        OsRng,
    )
    .expect("tree decider proof generation should succeed");
    println!(
        "[ivc-keccak-solidity] tree decider (Keccak): prove {:.2?} ({} bytes compressed)",
        t0.elapsed(),
        final_proof.len()
    );

    // Public input vector exactly mirrors `IvcTreeDeciderCircuit::format_instance`.
    let pi: Vec<F> =
        IvcTreeDeciderCircuit::format_instance(&decider_instance).expect("format_instance");

    // Sanity: native verifier must accept the final Keccak decider proof.
    let t0 = Instant::now();
    midnight_zk_stdlib::verify::<IvcTreeDeciderCircuit, sha3::Keccak256>(
        &decider_srs.verifier_params(),
        &decider_vk,
        &decider_instance,
        None,
        &final_proof,
    )
    .expect("native decider verify must accept the Keccak proof");
    println!(
        "[ivc-keccak-solidity] native tree decider verify: OK ({:.2?})",
        t0.elapsed()
    );
    #[cfg(feature = "rust-verifier-trace")]
    let rust_trace = collect_native_midfall_trace(
        &decider_srs.verifier_params(),
        &decider_vk,
        &pi,
        &final_proof,
    );

    // ----------------------------------------------------------
    // Render Halo2Verifier.sol + Halo2VerifyingKey.sol.
    // ----------------------------------------------------------
    // ZkStdLib creates 2 instance columns (one committed, one
    // non-committed). num_instances counts the non-committed slots.
    //
    // IvcTreeDeciderCircuit::format_instance(instance) =
    //   [leaf_statement_hashes..., fully_collapsed_final_acc].
    // The Solidity verifier consumes `fully_collapsed_final_acc` for the
    // final accumulator pairing check, so pass its starting instance offset.
    let num_instances = pi.len();
    let final_acc_offset = TREE_LEAVES;
    let generator = SolidityGenerator::new(&decider_srs, decider_vk.vk(), num_instances, 1)
        .set_acc_encoding(Some(AccumulatorEncoding::new(final_acc_offset, 7, 56)));
    let proof_evaluation_counts = generator.proof_evaluation_counts();
    print_proof_evaluation_counts(&proof_evaluation_counts);
    let gas_checkpoints_enabled = halo2_solidity_verifier::SOLIDITY_GAS_CHECKPOINTS_ENABLED;

    let t0 = Instant::now();
    let quotient_solidity = generator
        .render_quotient_evaluator()
        .expect("render_quotient_evaluator should succeed");
    let quotient_creation_code = compile_solidity_with_runs(&quotient_solidity, SOLC_OPTIMIZE_RUNS);
    let quotient_creation_size = quotient_creation_code.len();
    let mut evm = Evm::default();
    let quotient_address = evm.create(quotient_creation_code.clone());
    let quotient_runtime_size = evm.code_size(quotient_address);
    let quotient_codehash = evm.code_hash(quotient_address);
    let (verifier_solidity, vk_solidity, pinned_quotient_solidity) =
        if cfg!(feature = "rust-verifier-trace") {
            generator
                .render_trace_separately_with_pinned_quotient(
                    quotient_runtime_size,
                    quotient_codehash,
                )
                .expect("render_trace_separately_with_pinned_quotient should succeed")
        } else {
            generator
                .render_separately_with_pinned_quotient(quotient_runtime_size, quotient_codehash)
                .expect("render_separately_with_pinned_quotient should succeed")
        };
    assert_eq!(
        quotient_solidity, pinned_quotient_solidity,
        "pinning the quotient evaluator must not change the evaluator source"
    );
    println!(
        "[ivc-keccak-solidity] rendered pinned Halo2Verifier.sol = {} bytes, Halo2VerifyingKey.sol = {} bytes, Halo2QuotientEvaluator.sol = {} bytes (took {:.2?})",
        verifier_solidity.len(),
        vk_solidity.len(),
        quotient_solidity.len(),
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
    std::fs::write(
        format!("{dump_dir}/Halo2QuotientEvaluator.sol"),
        &quotient_solidity,
    )
    .ok();
    std::fs::write(format!("{dump_dir}/proof.bin"), &final_proof).ok();
    std::fs::write(
        format!("{dump_dir}/proof-evaluation-counts.txt"),
        proof_evaluation_count_summary(&proof_evaluation_counts),
    )
    .ok();
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
    std::fs::write(
        format!("{dump_dir}/Halo2QuotientEvaluator.creation.bin"),
        &quotient_creation_code,
    )
    .ok();
    println!(
        "[ivc-keccak-solidity] solc compile completed in {:.2?} (optimize-runs = {SOLC_OPTIMIZE_RUNS}, no CBOR; verifier creation bytecode = {} bytes, vk creation bytecode = {} bytes, quotient creation bytecode = {} bytes)",
        t0.elapsed(),
        verifier_creation_size,
        vk_creation_size,
        quotient_creation_size
    );

    let vk_address = evm.create(vk_creation_code);
    let verifier_address =
        evm.create_with_two_address_args(verifier_creation_code, vk_address, quotient_address);
    let vk_runtime_size = evm.code_size(vk_address);
    let verifier_runtime_size = evm.code_size(verifier_address);
    for (name, runtime_size) in [
        ("Halo2Verifier", verifier_runtime_size),
        ("Halo2VerifyingKey", vk_runtime_size),
        ("Halo2QuotientEvaluator", quotient_runtime_size),
    ] {
        assert!(
            runtime_size <= EIP170_MAX_RUNTIME_SIZE,
            "{name} runtime {runtime_size} exceeds EIP-170 limit {EIP170_MAX_RUNTIME_SIZE}"
        );
    }
    let contract_size_summary = format!(
        "solc optimize runs: {SOLC_OPTIMIZE_RUNS}\n\
         solc CBOR metadata: omitted\n\
         Halo2Verifier.sol source bytes: {}\n\
         Halo2VerifyingKey.sol source bytes: {}\n\
         Halo2QuotientEvaluator.sol source bytes: {}\n\
         Halo2Verifier creation bytecode bytes: {verifier_creation_size}\n\
         Halo2VerifyingKey creation bytecode bytes: {vk_creation_size}\n\
         Halo2QuotientEvaluator creation bytecode bytes: {quotient_creation_size}\n\
         Halo2Verifier deployed runtime bytes: {verifier_runtime_size}\n\
         Halo2VerifyingKey deployed runtime bytes: {vk_runtime_size}\n\
         Halo2QuotientEvaluator deployed runtime bytes: {quotient_runtime_size}\n\
         total deployed runtime bytes: {}\n",
        verifier_solidity.len(),
        vk_solidity.len(),
        quotient_solidity.len(),
        verifier_runtime_size + vk_runtime_size + quotient_runtime_size
    );
    std::fs::write(
        format!("{dump_dir}/contract-sizes.txt"),
        contract_size_summary,
    )
    .ok();
    println!(
        "[ivc-keccak-solidity] deployed (vk = {vk_address:?}, quotient = {quotient_address:?}, verifier = {verifier_address:?})"
    );
    println!(
        "[ivc-keccak-solidity] contract sizes: verifier runtime = {verifier_runtime_size} bytes, vk runtime = {vk_runtime_size} bytes, quotient runtime = {quotient_runtime_size} bytes, total runtime = {} bytes",
        verifier_runtime_size + vk_runtime_size + quotient_runtime_size
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
    match evm.try_call_with_gas(verifier_address, calldata.clone(), 5_000_000_000) {
        CallOutcome::Success {
            gas_used,
            output,
            logs,
        } => {
            if gas_checkpoints_enabled {
                dump_gas_checkpoints(&logs, gas_used);
            }
            #[cfg(feature = "rust-verifier-trace")]
            assert_ivc_trace_matches_native_midfall(&rust_trace, &logs);
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

            let mut bad_accumulator_packing = calldata.clone();
            let first_acc_word = 4 + 0x40 + 0x20 + repacked.len() + 0x20 + final_acc_offset * 0x20;
            // Accumulator limbs are packed into 56-bit chunks. The first
            // word uses 224 bits, so byte 3 is the lowest unused high byte
            // in the big-endian ABI word. Setting it keeps the value below
            // Fr but must be rejected by the accumulator packing check.
            bad_accumulator_packing[first_acc_word + 3] ^= 0x01;
            assert_call_reverts(
                evm.try_call_with_gas(verifier_address, bad_accumulator_packing, 5_000_000_000),
                "non-canonical accumulator limb packing",
            );

            let mut bad_proof_head = calldata.clone();
            overwrite_u256_word_for_test(&mut bad_proof_head, 0x04, 0x60);
            let mut bad_instances_head = calldata.clone();
            overwrite_u256_word_for_test(&mut bad_instances_head, 0x24, 0x20);
            for (name, malformed_calldata) in [
                ("wrong proof ABI head", bad_proof_head),
                ("wrong instances ABI head", bad_instances_head),
            ] {
                assert_call_reverts(
                    evm.try_call_with_gas(verifier_address, malformed_calldata, 5_000_000_000),
                    name,
                );
            }
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

fn assert_call_reverts(outcome: CallOutcome, context: &str) {
    match outcome {
        CallOutcome::Revert { .. } => {}
        CallOutcome::Success { output, .. } => {
            panic!(
                "invalid IVC verifier call returned instead of reverting ({context}): 0x{}",
                hex::encode(output)
            );
        }
        CallOutcome::Halt { gas_used, reason } => {
            panic!("invalid IVC verifier call halted instead of reverting ({context}): gas_used = {gas_used}, reason = {reason}");
        }
    }
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn overwrite_u256_word_for_test(bytes: &mut [u8], start: usize, value: u64) {
    bytes[start..start + 32].fill(0);
    bytes[start + 24..start + 32].copy_from_slice(&value.to_be_bytes());
}

#[cfg(feature = "rust-verifier-trace")]
fn collect_native_midfall_trace(
    params_verifier: &ParamsVerifierKZG<E>,
    vk: &MidnightVK,
    pi: &[F],
    proof: &[u8],
) -> Vec<midnight_proofs::plonk::solidity_trace::SolidityTraceEvent> {
    use midnight_proofs::poly::commitment::Guard as _;

    plonk::solidity_trace::start();

    let committed_pi = [C::identity()];
    let committed_columns: [&[C]; 1] = [&committed_pi];
    let public_columns: [&[F]; 1] = [pi];
    let public_inputs: [&[&[F]]; 1] = [&public_columns];
    let mut transcript = CircuitTranscript::<sha3::Keccak256>::init_from_bytes(proof);

    let guard = plonk::prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<sha3::Keccak256>>(
        vk.vk(),
        &committed_columns,
        &public_inputs,
        &mut transcript,
    )
    .expect("native prepare succeeds while collecting trace");
    transcript
        .assert_empty()
        .expect("native transcript consumes proof while collecting trace");
    guard
        .verify(params_verifier)
        .expect("native guard verifies while collecting trace");

    plonk::solidity_trace::take()
}

#[cfg(feature = "rust-verifier-trace")]
fn assert_ivc_trace_matches_native_midfall(
    rust_trace: &[midnight_proofs::plonk::solidity_trace::SolidityTraceEvent],
    logs: &[halo2_solidity_verifier::revm::primitives::Log],
) {
    let solidity_trace = parse_solidity_trace_logs(logs);
    let external_quotient_trace_id = |id: u64| (30_000..40_000).contains(&id);
    let mut rust_by_id = BTreeMap::new();
    for event in rust_trace {
        assert!(
            rust_by_id
                .insert(event.id, (event.name, event.data.clone()))
                .is_none(),
            "duplicate Rust trace id {}",
            event.id
        );
    }

    // The IVC verifier uses a pinned external quotient evaluator in trace and
    // production builds. The evaluator is reached through STATICCALL, so it
    // cannot emit LOG records for native quotient-arithmetic trace ids.
    // Transcript, proof, PCS, and pairing trace ids are still emitted by the
    // main verifier and compared below.
    let missing = rust_by_id
        .keys()
        .filter(|&&id| !external_quotient_trace_id(id) && !solidity_trace.contains_key(&id))
        .copied()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "Solidity trace is missing native Rust trace ids: {missing:?}"
    );

    // The generator may emit accumulator-only diagnostics. Those are outside
    // the native midfall PLONK verifier, whose source-of-truth trace ends at
    // the KZG pairing inputs.
    let allowed_generator_only = [29u64, 30u64];
    let unexpected = solidity_trace
        .keys()
        .filter(|&&id| !rust_by_id.contains_key(&id) && !allowed_generator_only.contains(&id))
        .copied()
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "Solidity trace emitted ids without native Rust oracle: {unexpected:?}"
    );

    let mut matched = 0usize;
    for (id, (name, rust_data)) in rust_by_id {
        if external_quotient_trace_id(id) {
            continue;
        }
        let solidity_data = solidity_trace
            .get(&id)
            .expect("missing Solidity trace id was checked above");
        assert_eq!(
            &rust_data,
            solidity_data,
            "trace mismatch id={id} name={name}: rust=0x{} solidity=0x{}",
            hex::encode(&rust_data),
            hex::encode(solidity_data),
        );
        matched += 1;
    }

    let generator_only = allowed_generator_only
        .into_iter()
        .filter(|id| solidity_trace.contains_key(id))
        .collect::<Vec<_>>();
    println!(
        "[ivc-keccak-solidity][trace] matched {} native Rust/Solidity trace points{}",
        matched,
        if generator_only.is_empty() {
            String::new()
        } else {
            format!("; generator-only accumulator trace ids: {generator_only:?}")
        }
    );
}

#[cfg(feature = "rust-verifier-trace")]
fn parse_solidity_trace_logs(
    logs: &[halo2_solidity_verifier::revm::primitives::Log],
) -> BTreeMap<u64, Vec<u8>> {
    let mut trace = BTreeMap::new();

    for log in logs {
        let data = log.data.data.as_ref().to_vec();
        if data.is_empty() {
            continue;
        }

        let topics = log.data.topics();
        assert_eq!(topics.len(), 1, "trace log must have one topic");
        let id = trace_topic_id(topics[0]);
        assert!(
            trace.insert(id, data).is_none(),
            "duplicate Solidity trace id {id}"
        );
    }

    trace
}

#[cfg(feature = "rust-verifier-trace")]
fn trace_topic_id(topic: halo2_solidity_verifier::revm::primitives::B256) -> u64 {
    let bytes = topic.as_slice();
    u64::from_be_bytes(bytes[24..32].try_into().expect("topic is 32 bytes"))
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
        .and_then(|max_id| max_id.checked_sub(21));

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
        12 => "batched identity numerator reconstruction".to_string(),
        13 => "linearization scalar prep".to_string(),
        14 => "PCS block 6 (pairing inputs LHS/RHS)".to_string(),
        15 => "public accumulator pairing batch prep".to_string(),
        16 => "final proof ec_pairing".to_string(),
        17 => "PCS block 1 (rotation points x*omega^rot)".to_string(),
        18 => "PCS block 2 (x1 powers)".to_string(),
        id if id >= 19 => {
            if let Some(n) = pcs_set_count {
                let idx = id - 19;
                if idx < n {
                    return format!("PCS block 3 set {idx} (q_eval fold)");
                }
                if idx == n {
                    return "PCS block 3 (q_com input materialization)".to_string();
                }
                if idx == n + 1 {
                    return "PCS block 4 (f_eval Lagrange interpolation)".to_string();
                }
                if idx == n + 2 {
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
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}
