//! Step 8 end-to-end smoke test for the midnight-proofs Solidity
//! verifier on BLS12-381 / EIP-2537.
//!
//! The test rebuilds the same circuit the midfall poseidon fixture
//! (`midfall/proofs/solidity-verifier/fixtures/poseidon/`) was generated
//! from - `ZkStdLib`-backed `PoseidonExample` at `k = 6` - generates a
//! fresh proof against the local Filecoin SRS, renders the
//! `Halo2Verifier.sol` + `Halo2VerifyingKey.sol` pair through
//! `SolidityGenerator::render_separately`, compiles them with `solc`,
//! deploys both to a Prague-spec revm (so EIP-2537 BLS12-381
//! precompiles `0x0b` / `0x0c` / `0x0f` are routed to revm's bundled
//! implementations), encodes the calldata via `encode_calldata_bls_padded`
//! and finally calls `verifyProof`. Pass condition is `output ==
//! 0x...01` (the verifier accepted the proof) AND a successful native
//! `midnight_zk_stdlib::verify` against the same proof.
//!
//! Gated behind `feature = "evm"`. Skipped automatically when the host
//! lacks the local SRS / `solc` binary; otherwise it asserts both the
//! Yul renders cleanly and the Prague-spec EVM accepts the proof.
//!
//! NOTE: this test depends on `midnight-zk-stdlib` + `midnight-circuits`
//! (path deps under `../midfall/`) which carry the full poseidon chip
//! configuration. The crate's `Cargo.toml` `[patch.crates-io]` block
//! redirects every `midnight-*` reference to the local midfall checkout
//! so cargo resolves a single canonical crate copy across the whole
//! dep graph.

#![cfg(feature = "evm")]

use std::env;
use std::path::Path;

use ff::Field;
use midnight_circuits::{
    hash::poseidon::PoseidonChip,
    instructions::{hash::HashCPU, AssignmentInstructions, PublicInputInstructions},
};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::{
    utils::plonk_api::srs_for_test, Relation, ZkStdLib, ZkStdLibArch,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha3::Keccak256;

use halo2_solidity_verifier::{
    compile_solidity, encode_calldata_bls_padded, BatchOpenScheme::Gwc19, Evm, SolidityGenerator,
};

type F = midnight_curves::Fq;

#[derive(Clone, Default)]
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

fn srs_dir() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../midfall/zk_stdlib/examples/assets").to_string()
}

/// Step 8 end-to-end smoke. Marked `#[ignore]` because it depends on
/// the local midfall checkout, Filecoin SRS asset, solc, and Prague
/// EIP-2537 precompile support. Run explicitly via
///   cargo test --features evm --test poseidon_fixture -- --ignored --nocapture
#[test]
#[ignore = "requires local midfall assets and Prague EIP-2537 precompiles"]
fn poseidon_renders_compiles_and_verifies() {
    const K: u32 = 6;

    // The Filecoin SRS file is loaded by `srs_for_test` via the
    // `SRS_DIR` env var. Skip the test cleanly if the asset is
    // unavailable on the host (e.g. fresh checkout where the SRS
    // hasn't been downloaded yet).
    let srs_dir = srs_dir();
    let srs_path = format!("{srs_dir}/bls_filecoin_2p{K}");
    if !Path::new(&srs_path).exists() {
        eprintln!(
            "skipping poseidon end-to-end smoke: SRS not found at {srs_path}. \
             Set SRS_DIR or fetch the asset under midfall/zk_stdlib."
        );
        return;
    }
    env::set_var("SRS_DIR", &srs_dir);

    let relation = PoseidonExample;
    let srs = srs_for_test(&relation, Some(K));
    let vk = midnight_zk_stdlib::setup_vk(&srs, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let witness: [F; 3] = core::array::from_fn(|_| F::random(&mut rng));
    let instance = <PoseidonChip<F> as HashCPU<F, F>>::hash(&witness);

    let prover_rng = ChaCha8Rng::seed_from_u64(0xdebd);
    let proof = midnight_zk_stdlib::prove::<PoseidonExample, Keccak256>(
        &srs, &pk, &relation, &instance, witness, prover_rng,
    )
    .expect("Proof generation should not fail");

    // Sanity-check via the native verifier first. If this fails, the
    // proof itself is broken so any Solidity-side mismatch downstream
    // is meaningless.
    midnight_zk_stdlib::verify::<PoseidonExample, Keccak256>(
        &srs.verifier_params(),
        &vk,
        &instance,
        None,
        &proof,
    )
    .expect("native verify should accept the proof");

    // Render Halo2Verifier.sol + Halo2VerifyingKey.sol against the
    // same VK. ZkStdLib creates two instance columns (one committed,
    // one non-committed); set num_committed_instances accordingly.
    let num_instances = 1;
    let generator = SolidityGenerator::new(&srs, vk.vk(), Gwc19, num_instances)
        .set_num_committed_instances(1);
    let trace_solidity = env::var_os("DROID_TRACE_SOLIDITY").is_some();
    let (verifier_solidity, vk_solidity) = if trace_solidity {
        generator
            .render_trace_separately()
            .expect("render_trace_separately should succeed")
    } else {
        generator
            .render_separately()
            .expect("render_separately should succeed")
    };

    // Persist for post-mortem inspection.
    let dump_dir = format!(
        "{}/target/poseidon-fixture-dump",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::create_dir_all(&dump_dir).ok();
    std::fs::write(format!("{dump_dir}/Halo2Verifier.sol"), &verifier_solidity).ok();
    std::fs::write(format!("{dump_dir}/Halo2VerifyingKey.sol"), &vk_solidity).ok();
    std::fs::write(format!("{dump_dir}/proof.bin"), &proof).ok();
    std::fs::write(
        format!("{dump_dir}/instance.be"),
        &<F as ff::PrimeField>::to_repr(&instance).as_ref(),
    )
    .ok();
    eprintln!(
        "[poseidon_fixture] proof = {} bytes, vk_solidity = {} bytes, verifier_solidity = {} bytes; \
         dumps under {dump_dir}",
        proof.len(),
        vk_solidity.len(),
        verifier_solidity.len()
    );

    // Skip the EVM portion if `solc` is not on PATH.
    if std::process::Command::new("solc")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipping poseidon end-to-end smoke: solc not found");
        return;
    }

    let vk_creation_code = compile_solidity(&vk_solidity);
    let verifier_creation_code = compile_solidity(&verifier_solidity);

    // Deploy on Prague-spec revm (EIP-2537 routed via blst).
    let mut evm = Evm::default();
    let vk_address = evm.create(vk_creation_code);
    let verifier_address = evm.create_with_address_arg(verifier_creation_code, vk_address);

    // The midnight-proofs prover writes G1 commitments in the
    // 48-byte zcash-compressed encoding. The Solidity verifier
    // expects them in 128-byte uncompressed EIP-2537 padded form
    // (4 words: x_hi, x_lo, y_hi, y_lo). Re-pack the proof off
    // chain so the on-chain side never has to run the modexp-based
    // sqrt; the verifier reconstructs the compressed encoding on
    // the fly inside `common_uncompressed_g1` for transcript
    // hashing only.
    let repacked = {
        let cs = vk.vk().cs();
        let perm_chunks = cs.permutation().columns.chunks(cs.degree() - 2).count();
        // Group counts in transcript order:
        let mut g1_groups: Vec<usize> = Vec::new();
        // user phases: each phase contributes its advice columns. We
        // simplify and emit a single block per phase (the `verify` loop
        // reads all of them sequentially anyway).
        let advice_phase = cs.advice_column_phase();
        let max_phase = *advice_phase.iter().max().unwrap_or(&0);
        for phase in 0..=max_phase {
            let n = advice_phase.iter().filter(|p| **p == phase).count();
            if n != 0 {
                g1_groups.push(n);
            }
        }
        // multiplicities (one per lookup)
        if cs.lookups().len() != 0 {
            g1_groups.push(cs.lookups().len());
        }
        // perm Z products
        if perm_chunks != 0 {
            g1_groups.push(perm_chunks);
        }
        // per-lookup helpers + acc; nb_chunks per lookup
        for l in cs.lookups().iter() {
            let nb_chunks = l.chunk_by_degree(cs.degree()).num_chunks();
            g1_groups.push(nb_chunks); // helpers
            g1_groups.push(1); // acc
        }
        // trashcans
        if cs.trashcans().len() != 0 {
            g1_groups.push(cs.trashcans().len());
        }
        // quotient limbs
        let num_quotients = cs.degree() - 1;
        g1_groups.push(num_quotients);

        // num_evals = committed_instance + advice + fixed_non_simple +
        //             permutation_columns + perm_set_evals +
        //             per_lookup(1 + chunks + 1 + 1) + trashcans
        // ZkStdLib's prover always passes NB_COMMITTED_INSTANCES = 1.
        // The committed-instance commitment is NOT in the proof bytes
        // (it's `committed_pi = G1::identity()` passed as a separate
        // verifier argument), but each instance_query whose
        // column_idx < NB_COMMITTED_INSTANCES contributes ONE eval
        // slot to the proof byte stream (read from transcript at
        // x in `verify_algebraic_constraints`).
        let nb_committed_instances = 1usize;
        let num_committed_instance_evals = cs
            .instance_queries()
            .iter()
            .filter(|(col, _)| col.index() < nb_committed_instances)
            .count();
        let num_fixed_non_simple = cs.num_fixed_columns() - cs.num_simple_selectors();
        let perm_set_count = if perm_chunks == 0 { 0 } else { 3 * perm_chunks - 1 };
        let lookup_eval_count: usize = cs
            .lookups()
            .iter()
            .map(|l| 1 + l.chunk_by_degree(cs.degree()).num_chunks() + 1 + 1)
            .sum();
        let num_evals = num_committed_instance_evals
            + cs.advice_queries().len()
            + num_fixed_non_simple
            + cs.permutation().columns.len()
            + perm_set_count
            + lookup_eval_count
            + cs.trashcans().len();

        // Multi-prepare tail: f_com (1 G1) + q_evals (one per point set
        // - derived from the codegen-side intermediate-set construction).
        // For Gwc19 the number of point sets equals the number of
        // distinct (commitment-set, point-set) groupings; we recover it
        // by counting distinct rotations across all queries (advice +
        // fixed-non-simple + perm + lookup + trash + quotient + f_com
        // queries). The queries this codegen emits use the rotation set
        // that the prover/verifier emit q_evals for, which is computed
        // by the codegen-side `intermediate_sets`. To avoid duplicating
        // the codegen logic here, we read the proof tail by *length*:
        // the proof's last 32 + 0x80 bytes (q_eval x 1 + pi x 1) follows
        // an unknown number of q_evals + f_com. We compute it as
        // (proof_len - prefix_len - num_evals * 32 - 1 G1 - 1 G1) / 32.
        let prefix_g1_count: usize = g1_groups.iter().sum();
        let prefix_compressed_len = prefix_g1_count * 48 + num_evals * 32;
        let trailing_compressed_len = 48 + 48; // f_com + pi
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
        eprintln!(
            "[repack] g1_groups = {:?}, prefix_g1 = {}, num_evals = {}, num_point_sets = {}, proof_len = {}",
            g1_groups, prefix_g1_count, num_evals, num_point_sets, proof.len()
        );

        // Now walk and repack.
        let mut out: Vec<u8> = Vec::with_capacity(
            prefix_g1_count * 128 + num_evals * 32 + 128 + num_point_sets * 32 + 128,
        );
        let mut cursor = 0usize;
        use group::prime::PrimeCurveAffine;
        use group::GroupEncoding;
        let push_g1 = |cursor: &mut usize, out: &mut Vec<u8>| {
            let mut comp = <midnight_curves::G1Affine as GroupEncoding>::Repr::default();
            comp.as_mut()
                .copy_from_slice(&proof[*cursor..*cursor + 48]);
            let cur = *cursor;
            *cursor += 48;
            let pt: midnight_curves::G1Affine =
                Option::from(<midnight_curves::G1Affine as GroupEncoding>::from_bytes(&comp))
                    .unwrap_or_else(|| {
                        panic!(
                            "decompress failed at proof[{cur}..{}]: bytes = 0x{}",
                            cur + 48,
                            hex::encode(comp.as_ref())
                        )
                    });
            // For identity, write all zeros (EIP-2537 identity).
            if bool::from(pt.is_identity()) {
                out.extend_from_slice(&[0u8; 128]);
                return;
            }
            let x_be = pt.x().to_bytes_be();
            let y_be = pt.y().to_bytes_be();
            // Encode EIP-2537 padded (4x32 BE words):
            //   word0 = 16 zero || x[0..16]
            //   word1 = x[16..48]  (32 bytes)
            //   word2 = 16 zero || y[0..16]
            //   word3 = y[16..48]
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&x_be[0..16]);
            out.extend_from_slice(&x_be[16..48]);
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&y_be[0..16]);
            out.extend_from_slice(&y_be[16..48]);
        };
        for &n in &g1_groups {
            for _ in 0..n {
                push_g1(&mut cursor, &mut out);
            }
        }
        // evals (Fr 32-byte LE) - pass through.
        out.extend_from_slice(&proof[cursor..cursor + num_evals * 32]);
        cursor += num_evals * 32;
        // f_com
        push_g1(&mut cursor, &mut out);
        // q_evals
        out.extend_from_slice(&proof[cursor..cursor + num_point_sets * 32]);
        cursor += num_point_sets * 32;
        // pi
        push_g1(&mut cursor, &mut out);
        assert_eq!(cursor, proof.len(), "proof not fully consumed");
        out
    };

    let calldata = encode_calldata_bls_padded(&generator, &repacked, &[instance]);
    eprintln!(
        "[poseidon_fixture] calldata = {} bytes (compressed_proof={}, repacked={}, instances={})",
        calldata.len(),
        proof.len(),
        repacked.len(),
        1
    );

    use halo2_solidity_verifier::CallOutcome;
    match evm.try_call(verifier_address, calldata) {
        CallOutcome::Success {
            logs,
            gas_used,
            output,
        } => {
            if trace_solidity {
                dump_trace_logs(&logs);
            }
            let expected: Vec<u8> = [vec![0u8; 31], vec![1]].concat();
            assert_eq!(
                output, expected,
                "verifier should accept the proof; gas_used = {gas_used}, output = 0x{}",
                hex::encode(&output)
            );
            println!("Poseidon proof verified on-chain in {gas_used} gas");
        }
        CallOutcome::Revert { gas_used, output } => {
            panic!(
                "verifier reverted with gas_used = {gas_used}, output = 0x{}",
                hex::encode(&output)
            );
        }
        CallOutcome::Halt { gas_used, reason } => {
            panic!("verifier halted with gas_used = {gas_used}, reason = {reason}");
        }
    }
}

fn dump_trace_logs(logs: &[halo2_solidity_verifier::revm::primitives::Log]) {
    for log in logs {
        let topic = log.data.topics()[0];
        let id = u64::from_be_bytes(topic.as_slice()[24..32].try_into().unwrap());
        let data = log.data.data.as_ref();
        let name = match id {
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
            13 => "x1",
            14 => "x2",
            15 => "x3",
            16 => "x4",
            17 => "x_n",
            18 => "x_n_minus_1_inv",
            19 => "l_last",
            20 => "l_blind",
            21 => "l_0",
            22 => "instance_eval",
            23 => "quotient_eval",
            24 => "quotient",
            25 => "f_com",
            26 => "pi",
            27 => "pairing_lhs",
            28 => "pairing_rhs",
            29 => "acc_lhs",
            30 => "acc_rhs",
            31 => "f_eval",
            32 => "v",
            33 => "final_com",
            _ => "unknown",
        };
        if matches!(id, 24..=30 | 33) {
            eprintln!("[yul-trace] {name}");
            for (slot, word) in ["x_hi", "x_lo", "y_hi", "y_lo"]
                .iter()
                .zip(data.chunks_exact(32))
            {
                eprintln!("[yul-trace]   {slot} = 0x{}", hex::encode(word));
            }
        } else {
            eprintln!("[yul-trace] {name}[{id}] = 0x{}", hex::encode(&data[0..32]));
        }
    }
}
