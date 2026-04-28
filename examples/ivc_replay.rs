//! Replay harness for the IVC Keccak Solidity verifier.
//!
//! Loads the cached
//!   target/ivc-keccak-solidity-dump/{Halo2Verifier.sol,
//!                                    Halo2VerifyingKey.sol,
//!                                    calldata.bin}
//! produced by the `ivc_keccak_solidity` test, recompiles via solc,
//! deploys on Prague-spec revm, and calls `verifyProof` with the
//! cached calldata. Skips the multi-minute prove step entirely so
//! we can iterate on the rendered Yul (manual edits or codegen
//! changes) in seconds.
//!
//! Usage:
//!
//! ```text
//! GAS_CAP=500000000 cargo run --release \
//!     --features evm,truncated-challenges,fewer-point-sets \
//!     --example ivc_replay
//! ```
//!
//! `GAS_CAP` defaults to 5_000_000_000 (5 B) so we always see a
//! genuine OutOfGas vs Revert distinction even for the pathological
//! case the original e2e test hits.

#[cfg(not(all(
    feature = "evm",
    feature = "truncated-challenges",
    feature = "fewer-point-sets",
)))]
fn main() {
    eprintln!("ivc_replay requires --features evm,truncated-challenges,fewer-point-sets");
    std::process::exit(1);
}

#[cfg(all(
    feature = "evm",
    feature = "truncated-challenges",
    feature = "fewer-point-sets",
))]
use halo2_solidity_verifier::{compile_solidity, CallOutcome, Evm};

#[cfg(all(
    feature = "evm",
    feature = "truncated-challenges",
    feature = "fewer-point-sets",
))]
fn main() {
    let dump_dir = format!(
        "{}/target/ivc-keccak-solidity-dump",
        env!("CARGO_MANIFEST_DIR")
    );

    let verifier_solidity = std::fs::read_to_string(format!("{dump_dir}/Halo2Verifier.sol"))
        .expect("Halo2Verifier.sol not found in dump dir; run the test first");
    let vk_solidity = std::fs::read_to_string(format!("{dump_dir}/Halo2VerifyingKey.sol"))
        .expect("Halo2VerifyingKey.sol not found in dump dir; run the test first");
    let calldata =
        std::fs::read(format!("{dump_dir}/calldata.bin")).expect("calldata.bin not found");

    let gas_cap: u64 = std::env::var("GAS_CAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000_000_000);

    let t0 = std::time::Instant::now();
    let vk_creation_code = compile_solidity(&vk_solidity);
    let verifier_creation_code = compile_solidity(&verifier_solidity);
    println!(
        "[ivc-replay] solc compile completed in {:.2?} (verifier bytecode = {} bytes, vk bytecode = {} bytes)",
        t0.elapsed(),
        verifier_creation_code.len(),
        vk_creation_code.len()
    );

    let mut evm = Evm::default();
    let vk_address = evm.create(vk_creation_code);
    let verifier_address = evm.create_with_address_arg(verifier_creation_code, vk_address);
    println!("[ivc-replay] deployed (vk = {vk_address:?}, verifier = {verifier_address:?})");
    println!(
        "[ivc-replay] calldata = {} bytes, gas_cap = {gas_cap}",
        calldata.len()
    );

    let t0 = std::time::Instant::now();
    match evm.try_call_with_gas(verifier_address, calldata, gas_cap) {
        CallOutcome::Success {
            gas_used,
            output,
            logs,
        } => {
            let expected: Vec<u8> = [vec![0u8; 31], vec![1]].concat();
            let ok = output == expected;
            println!(
                "[ivc-replay] {} (gas_used = {gas_used}, output = 0x{}, {} log(s)) in {:.2?}",
                if ok { "PASS" } else { "BAD-OUTPUT" },
                hex::encode(&output),
                logs.len(),
                t0.elapsed()
            );
            for (i, log) in logs.iter().enumerate() {
                let topics: Vec<String> =
                    log.data.topics().iter().map(|t| hex::encode(t.0)).collect();
                println!("  log[{i}] addr={:?} topics={:?}", log.address, topics);
            }
        }
        CallOutcome::Revert { gas_used, output } => {
            println!(
                "[ivc-replay] REVERT (gas_used = {gas_used}, output = 0x{}) in {:.2?}",
                hex::encode(&output),
                t0.elapsed()
            );
        }
        CallOutcome::Halt { gas_used, reason } => {
            println!(
                "[ivc-replay] HALT (gas_used = {gas_used}, reason = {reason}) in {:.2?}",
                t0.elapsed()
            );
        }
    }
}
