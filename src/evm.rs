use crate::codegen::util::{fr_to_u256, to_u256_be_bytes};
use halo2_proofs::halo2curves::bn256;
use itertools::chain;

/// Function signature of `verifyProof(bytes,uint256[])`.
pub const FN_SIG_VERIFY_PROOF: [u8; 4] = [0x1e, 0x8e, 0x1e, 0x13];

/// Encode proof into calldata to invoke `Halo2Verifier.verifyProof`.
pub fn encode_calldata(proof: &[u8], instances: &[bn256::Fr]) -> Vec<u8> {
    let offset = 0x40;
    let num_instances = instances.len();
    chain![
        FN_SIG_VERIFY_PROOF,                                         // function signature
        to_u256_be_bytes(offset),                                    // offset of proof
        to_u256_be_bytes(offset + 0x20 + proof.len()),               // offset of instances
        to_u256_be_bytes(proof.len()),                               // length of proof
        proof.iter().cloned(),                                       // proof
        to_u256_be_bytes(num_instances),                             // length of instances
        instances.iter().map(fr_to_u256).flat_map(to_u256_be_bytes), // instances
    ]
    .collect()
}

#[cfg(any(test, feature = "evm"))]
pub(crate) mod test {
    pub use revm;
    use revm::{
        db::InMemoryDB,
        primitives::{Address, ExecutionResult, Log, Output, SpecId, TxKind},
        Evm as RevmEvm,
    };
    use ruint::aliases::U256;
    use std::{
        fmt::{self, Debug, Formatter},
        io::{self, Write},
        process::{Command, Stdio},
        str,
    };

    /// Compile solidity with `--via-ir`, targeting Cancun bytecode (the
    /// embedded revm runner is set up for the Prague hard fork which
    /// supersedes Cancun + adds EIP-2537), then return creation bytecode.
    ///
    /// # Panics
    /// Panics if executable `solc` can not be found, or compilation fails.
    pub fn compile_solidity(solidity: impl AsRef<[u8]>) -> Vec<u8> {
        let mut process = match Command::new("solc")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("--bin")
            .arg("--optimize")
            .arg("--via-ir")
            .arg("--evm-version")
            .arg("cancun")
            .arg("-")
            .spawn()
        {
            Ok(process) => process,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                panic!("Command 'solc' not found");
            }
            Err(err) => {
                panic!("Failed to spwan process with command 'solc':\n{err}");
            }
        };
        process
            .stdin
            .take()
            .unwrap()
            .write_all(solidity.as_ref())
            .unwrap();
        let output = process.wait_with_output().unwrap();
        let stdout = str::from_utf8(&output.stdout).unwrap();
        if let Some(binary) = find_binary(stdout) {
            binary
        } else {
            panic!(
                "Compilation fails:\n{}",
                str::from_utf8(&output.stderr).unwrap()
            )
        }
    }

    fn find_binary(stdout: &str) -> Option<Vec<u8>> {
        let start = stdout.find("Binary:")? + 8;
        Some(hex::decode(&stdout[start..stdout.len() - 1]).unwrap())
    }

    /// In-process EVM runner pinned to `SpecId::PRAGUE` so that the
    /// EIP-2537 BLS12-381 precompiles (`0x0b`/`0x0c`/`0x0d`/`0x0e`/`0x0f`)
    /// are routed to revm's bundled implementations. The runner keeps an
    /// `InMemoryDB` across calls so tests can deploy once and call many
    /// times.
    pub struct Evm {
        db: InMemoryDB,
    }

    impl Debug for Evm {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("Evm").finish_non_exhaustive()
        }
    }

    impl Default for Evm {
        fn default() -> Self {
            Self {
                db: InMemoryDB::default(),
            }
        }
    }

    impl Evm {
        /// Return code_size of given address.
        ///
        /// # Panics
        /// Panics if given address doesn't have bytecode.
        pub fn code_size(&mut self, address: Address) -> usize {
            self.db.accounts[&address]
                .info
                .code
                .as_ref()
                .map(|c| c.len())
                .unwrap_or(0)
        }

        /// Apply create transaction with given `bytecode` as creation bytecode.
        /// Return created `address`.
        ///
        /// # Panics
        /// Panics if execution reverts or halts unexpectedly.
        pub fn create(&mut self, bytecode: Vec<u8>) -> Address {
            let (_, output, _) = self.run_tx(TxKind::Create, bytecode);
            match output {
                Output::Create(_, Some(address)) => address,
                _ => unreachable!("expected create output, got {output:?}"),
            }
        }

        /// Apply create transaction with an address constructor argument appended to creation
        /// bytecode and return created `address`.
        pub fn create_with_address_arg(
            &mut self,
            mut bytecode: Vec<u8>,
            address_arg: Address,
        ) -> Address {
            bytecode.extend_from_slice(
                &U256::try_from_be_slice(address_arg.as_slice())
                    .unwrap()
                    .to_be_bytes::<0x20>(),
            );
            self.create(bytecode)
        }

        /// Apply call transaction to given `address` with `calldata`.
        /// Returns `gas_used` and `return_data`.
        ///
        /// # Panics
        /// Panics if execution reverts or halts unexpectedly.
        pub fn call(&mut self, address: Address, calldata: Vec<u8>) -> (u64, Vec<u8>) {
            let (gas_used, output, _) = self.run_tx(TxKind::Call(address), calldata);
            match output {
                Output::Call(output) => (gas_used, output.into()),
                _ => unreachable!("expected call output, got {output:?}"),
            }
        }

        /// Apply call transaction and return gas, return data, and emitted logs.
        pub fn call_with_logs(
            &mut self,
            address: Address,
            calldata: Vec<u8>,
        ) -> (u64, Vec<u8>, Vec<Log>) {
            let (gas_used, output, logs) = self.run_tx(TxKind::Call(address), calldata);
            match output {
                Output::Call(output) => (gas_used, output.into(), logs),
                _ => unreachable!("expected call output, got {output:?}"),
            }
        }

        /// Build a Prague-spec EVM around the in-memory db, run the
        /// configured transaction, commit, then unwrap the success result.
        fn run_tx(&mut self, transact_to: TxKind, data: Vec<u8>) -> (u64, Output, Vec<Log>) {
            // Take the db out so we can hand it to the builder, then put it
            // back after the call.
            let db = std::mem::take(&mut self.db);
            let mut evm = RevmEvm::builder()
                .with_db(db)
                .with_spec_id(SpecId::PRAGUE)
                .modify_tx_env(|tx| {
                    tx.gas_limit = u64::MAX;
                    tx.transact_to = transact_to;
                    tx.data = data.into();
                })
                .build();
            let result = evm.transact_commit().unwrap();
            // Recover the database for the next call. revm 19 stores the
            // db deep inside `evm.context.evm.db`; the simplest way to get
            // it back without moving fields out of `EvmContext` (which
            // holds non-Copy state) is to swap with a dummy default.
            self.db = std::mem::take(&mut evm.context.evm.db);
            match result {
                ExecutionResult::Success {
                    gas_used,
                    output,
                    logs,
                    ..
                } => {
                    if !logs.is_empty() {
                        println!("--- logs from {} ---", logs[0].address);
                        for (log_idx, log) in logs.iter().enumerate() {
                            println!("log#{log_idx}");
                            for (topic_idx, topic) in log.data.topics().iter().enumerate() {
                                println!("  topic{topic_idx}: {topic:?}");
                            }
                        }
                        println!("--- end ---");
                    }
                    (gas_used, output, logs)
                }
                ExecutionResult::Revert { gas_used, output } => {
                    panic!("Transaction reverts with gas_used {gas_used} and output 0x{output:x}")
                }
                ExecutionResult::Halt { reason, gas_used } => panic!(
                    "Transaction halts unexpectedly with gas_used {gas_used} and reason {reason:?}"
                ),
            }
        }
    }
}
