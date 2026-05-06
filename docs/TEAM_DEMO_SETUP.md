# Team Demo Setup: Halo2 Solidity IVC Verifier

Use this guide to prepare a fresh laptop before the demo session and to replay
the same commands during the meeting.

The demo shows the optimized IVC Solidity verifier path where the quotient
numerator body is small enough to live inside `Halo2Verifier` instead of being
deployed as a separate `Halo2QuotientEvaluator` contract. For background, read
`docs/QUOTIENT_EVALUATOR_9KB_BYTECODE.md`.

## Assumptions

- macOS, Linux, or Windows with WSL2 Ubuntu.
- A stable internet connection.
- At least 20 GB free disk space.
- A terminal.
- GitHub access to the repository.
- Git, Rust/Cargo, and a normal native build toolchain are already installed.

The full proof bench is CPU-heavy. Please do the preparation before the meeting
so the session can focus on reading the generated contracts and comparing gas
numbers.

## 1. Clone the Repo

Use SSH if your GitHub account is set up for it:

```bash
git clone git@github.com:privacy-ethereum/halo2-solidity-verifier.git
cd halo2-solidity-verifier
```

Or use HTTPS:

```bash
git clone https://github.com/privacy-ethereum/halo2-solidity-verifier.git
cd halo2-solidity-verifier
```

Switch to the demo branch once it has been pushed:

```bash
git fetch origin
git switch next2
```

Check that you are in the right place:

```bash
git status
```

## 2. Install the Pinned Solidity Compiler

The benchmark is reproducible only with `solc 0.8.30+commit.73712a01`.
Use the repo helper:

```bash
scripts/install_pinned_solc.sh .solc
export SOLC="$PWD/.solc/solc"
```

Check:

```bash
"$SOLC" --version
```

Expected version prefix:

```text
Version: 0.8.30+commit.73712a01
```

If you open a new terminal later, run this again from the repo root:

```bash
export SOLC="$PWD/.solc/solc"
```

## One-Command Demo Runner

The scripted path performs the setup checks, installs pinned `solc` when needed,
checks/downloads SRS assets, checks the sibling Moonlight checkout, prints
colored progress logs, and writes full command logs under
`target/team-demo-logs`.

Run setup and compile preflights only:

```bash
scripts/run_team_demo.sh --check-only
```

Run the full demo path:

```bash
scripts/run_team_demo.sh
```

The full path runs the IVC Rust/Solidity trace equivalence test plus the
Moonlight wrap decider Solidity bench and trace equivalence check. Use `--help`
to see options for custom SRS directories, HTTPS Moonlight cloning, or skipping
one of the heavy runs.

## 3. Download SRS Assets

For the demo, we will use the multi-limb outer proof shape so everyone can
replicate the same numbers from the session:

```bash
scripts/run_ivc_bench.sh --check-only --no-outer-single-h-commitment
```

This command downloads the required Midnight SRS files into `.srs/` and compiles
the IVC bench without running the expensive proof. It may take a while on a
fresh laptop because Cargo has to build the dependency graph.

If the command succeeds, your laptop is ready for the session.

## 4. Quick Sanity Check

Run the focused codegen tests:

```bash
cargo test --features evm,truncated-challenges,in-circuit-fewer-point-sets --lib codegen
```

Expected ending:

```text
test result: ok.
```

## Commands We Will Run During the Demo

Start from the repo root:

```bash
cd halo2-solidity-verifier
export SOLC="$PWD/.solc/solc"
git pull
```

Run the full IVC Solidity verifier bench:

```bash
scripts/run_ivc_bench.sh --skip-srs-download --no-outer-single-h-commitment
```

This proves, renders Solidity, compiles with pinned `solc`, deploys into local
Prague `revm`, verifies the proof, and prints gas checkpoints.

On a machine similar to the demo laptop, this run took around 3-5 minutes after
the prep build. Slower laptops can take longer.

## Moonlight Wrap Proof Solidity Verifier

The Moonlight demo proves the final wrap recursion proof from
`wrap_circuit_composes_two_fold_children_from_four_dummy_fold_proofs`, renders a
Solidity verifier with this repository, deploys it into local Prague `revm`, and
verifies the Moonlight proof on-chain.

Clone Moonlight next to this verifier repo:

```bash
cd ..
git clone git@github.com:EYBlockchain/Moonlight.git
cd Moonlight
git fetch origin
git switch codex/wrap-bench-cherry-picks
```

If you need HTTPS instead:

```bash
cd ..
git clone https://github.com/EYBlockchain/Moonlight.git
cd Moonlight
git fetch origin
git switch codex/wrap-bench-cherry-picks
```

The Moonlight branch pins its Midnight dependencies to the same Midfall commit
as this verifier repository and uses this local checkout through:

```text
halo2_solidity_verifier = { path = "../../halo2-solidity-verifier-exp", ... }
```

That path assumes the two repositories are siblings:

```text
parent/
  halo2-solidity-verifier-exp/
  Moonlight/
```

If your checkout names or locations differ, the one-command runner checks this
path and creates a local symlink from Moonlight's expected verifier dependency
path to the current checkout when the target is missing. Pass
`--no-fix-moonlight-dep` if you prefer the script to fail instead. If you run
the Cargo command directly, either keep the sibling checkout name above or
update/create the dependency path yourself before running the bench.

From this verifier repo, run the Moonlight Solidity path with the sibling
Moonlight manifest path:

```bash
export SOLC="$PWD/.solc/solc"

MOONLIGHT_RUN_WRAP_SOLIDITY_BENCH=1 \
cargo test --manifest-path ../Moonlight/aggregation/Cargo.toml \
  wrap_circuit_composes_two_fold_children_from_four_dummy_fold_proofs --release \
  --lib -- --ignored --nocapture
```

The important part is that Cargo targets Moonlight's `aggregation/Cargo.toml`
while Moonlight's dev dependency points back to this local Solidity verifier
checkout.

The run is much heavier than the IVC bench. On the demo machine it took about
23 minutes. The final proof is produced with Midfall's
`CircuitTranscript<sha3::Keccak256>` and with the final outer proof layout set
to no fewer-point-sets so it matches the generated Solidity verifier.
The Solidity path also enables the public accumulator check. Moonlight exposes
its final wrap accumulator as an already-collapsed `(lhs, rhs)` point pair at
instance offset `11`, so the verifier uses
`AccumulatorEncoding::point_pair(offset, 7, 56)` rather than the Midfall IVC
`point, scalar, point, scalar` layout.

Expected success line:

```text
[moonlight-wrap-solidity] PASS: final wrap decider proof accepted on-chain
```

The run also prints an IVC-style gas checkpoint table with section names, gas
deltas, percentages, measurement overhead, and total transaction gas. With the
public accumulator check enabled, the local demo run was:

```text
[moonlight-wrap-solidity][gas] inferred PCS point sets = 4
  15   4,998,802,662        64,564     5.6%  public accumulator pairing batch prep
  total tx gas_used       = 1,302,138 (incl. tx base + calldata + pre-cp1 + post-last)
[moonlight-wrap-solidity] PASS: final wrap decider proof accepted on-chain in 1302138 gas
[moonlight-wrap-solidity][trace] matched 244 native Rust/Solidity trace points; generator-only accumulator trace ids: [29, 30]
[moonlight-wrap-solidity][trace] PASS: final wrap decider trace matched native Midfall and accepted on-chain
```

By default, generated Moonlight verifier artifacts are written under:

```text
../Moonlight/aggregation/target/moonlight-wrap-solidity-dump
```

To keep the artifacts under this verifier repo instead:

```bash
MOONLIGHT_RUN_WRAP_SOLIDITY_BENCH=1 \
MOONLIGHT_WRAP_SOLIDITY_DUMP_DIR=target/moonlight-wrap-solidity-dump \
cargo test --manifest-path ../Moonlight/aggregation/Cargo.toml \
  wrap_circuit_composes_two_fold_children_from_four_dummy_fold_proofs --release \
  --lib -- --ignored --nocapture
```

The dump includes both the production gas-bench verifier and the trace verifier:

```text
Halo2Verifier.sol
Halo2VerifyingKey.sol
Halo2Verifier.trace.sol
Halo2VerifyingKey.trace.sol
proof.bin
instance.le
calldata.bin
```

## Expected Demo Output

Look for:

```text
[ivc-keccak-solidity] PASS: IVC final Keccak proof accepted on-chain
```

Then inspect the generated contract-size summary:

```bash
cat target/ivc-keccak-solidity-dump/contract-sizes.txt
```

For the merged verifier with the multi-limb outer proof shape, the demo run
should be close to:

```text
Halo2Verifier deployed runtime bytes: 21374
Halo2VerifyingKey deployed runtime bytes: 17024
total deployed runtime bytes: 38398
```

Small differences can happen if the branch changes before the session. The
important checks are:

- `Halo2Verifier` stays below the EIP-170 limit of `24576` bytes.
- The proof is accepted on-chain in the local EVM.
- The generated dump does not contain `Halo2QuotientEvaluator.sol`; the quotient
  numerator body is merged into `Halo2Verifier.sol`.

Check the generated files:

```bash
ls target/ivc-keccak-solidity-dump
```

Expected key files:

```text
Halo2Verifier.sol
Halo2VerifyingKey.sol
Halo2Verifier.creation.bin
Halo2VerifyingKey.creation.bin
contract-sizes.txt
calldata.bin
proof.bin
```

## Inspect the Optimized Quotient Body

Search for the compact quotient VM section inside the generated verifier:

```bash
grep -nE "Compact quotient-program mode|native gate|Q_OP_NATIVE|q_program" \
  target/ivc-keccak-solidity-dump/Halo2Verifier.sol
```

Read the implementation notes:

```bash
sed -n '1,220p' docs/QUOTIENT_EVALUATOR_9KB_BYTECODE.md
```

## Replay Without Proving Again

After one full bench run, you can replay the generated calldata and contracts
without regenerating the proof:

```bash
cargo run --release \
  --features evm,truncated-challenges,fewer-point-sets \
  --example ivc_replay
```

This is useful during the session if we want to tweak generated Solidity and
quickly test deployment or verification behavior.

## Optional Experiments

Try the compact VM shape profile:

```bash
HALO2_SOLIDITY_QUOTIENT_SHAPE_PROFILE=1 \
scripts/run_ivc_bench.sh --skip-srs-download --no-outer-single-h-commitment
```

Try disabling native gate callbacks:

```bash
HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=0 \
scripts/run_ivc_bench.sh --skip-srs-download --no-outer-single-h-commitment
```

Try changing the native-gate count:

```bash
HALO2_SOLIDITY_QUOTIENT_NATIVE_GATES=5 \
scripts/run_ivc_bench.sh --skip-srs-download --no-outer-single-h-commitment
```

The native-gate selector is byte-budgeted, so increasing the count does not
automatically mean the verifier spends more runtime bytecode.

## Troubleshooting

### `solc version ... does not match pinned`

Run:

```bash
scripts/install_pinned_solc.sh .solc
export SOLC="$PWD/.solc/solc"
"$SOLC" --version
```

### Missing SRS asset

Run prep again without `--skip-srs-download`:

```bash
scripts/run_ivc_bench.sh --check-only --no-outer-single-h-commitment
```

### Cargo cannot find Rust `1.90.0`

```bash
rustup toolchain install 1.90.0
```

### Build is slow

The first build is the expensive one. Let the prep command finish before the
meeting. The full bench is faster once dependencies are compiled.

### `manifest path aggregation/Cargo.toml does not exist`

You are running the Moonlight command from this verifier repo while using a
Moonlight manifest path relative to Moonlight itself. From this verifier repo,
use the sibling repo path:

```bash
cargo test --manifest-path ../Moonlight/aggregation/Cargo.toml \
  wrap_circuit_composes_two_fold_children_from_four_dummy_fold_proofs --release \
  --lib -- --ignored --nocapture
```

Or `cd ../Moonlight` and use `--manifest-path aggregation/Cargo.toml`.

### Moonlight cannot find `halo2_solidity_verifier`

Check the path dependency in `Moonlight/aggregation/Cargo.toml`. It should point
to this local verifier checkout. For sibling checkouts named as above, use:

```text
halo2_solidity_verifier = { path = "../../halo2-solidity-verifier-exp", features = ["evm", "truncated-challenges", "solidity-gas-checkpoints"] }
```

### Apple Silicon `solc` will not run

Install Rosetta:

```bash
softwareupdate --install-rosetta --agree-to-license
```

Then reinstall pinned `solc`:

```bash
rm -rf .solc
scripts/install_pinned_solc.sh .solc
export SOLC="$PWD/.solc/solc"
```
