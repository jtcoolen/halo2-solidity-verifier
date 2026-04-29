#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CHECK_ONLY=0
GAS_CHECKPOINTS=1
RUN_NATIVE_MIDFALL=0
RUN_SOLIDITY_BENCH=1
SKIP_SRS_DOWNLOAD=0

SRS_DIR="${SRS_DIR:-"$ROOT_DIR/.srs"}"
MIDFALL_DIR="${MIDFALL_DIR:-"$ROOT_DIR/../midfall"}"

FILECOIN_SRS_URL="https://midnight-s3-fileshare-dev-eu-west-1.s3.eu-west-1.amazonaws.com/bls_filecoin_2p19"
MIDNIGHT_SRS_URL="https://srs.midnight.network/midnight-srs-2p19"

usage() {
  cat <<'USAGE'
Run the IVC Keccak Solidity verifier bench.

Usage:
  scripts/run_ivc_bench.sh [options]

Options:
  --check-only          Download/check SRS assets and compile the ignored tests
                        without running the slow proving/verifier bench.
  --skip-srs-download  Fail if a required SRS asset is missing.
  --srs-dir DIR        Directory for SRS assets. Defaults to $SRS_DIR or ./.srs.
  --no-gas-checkpoints Run the Solidity verifier bench without section logs.
  --native-midfall     Also run Midfall's native Keccak final IVC test from
                        $MIDFALL_DIR/aggregation.
  --native-only        Run only the Midfall native Keccak final IVC test.
  --midfall-dir DIR    Local Midfall checkout for --native-midfall.
                        Defaults to ../midfall.
  -h, --help           Show this help.

Default behavior:
  1. Ensure SRS_DIR has Midnight's midnight-srs-2p19 and either Filecoin's
     bls_filecoin_2p13 or bls_filecoin_2p19. If bls_filecoin_2p13 is absent,
     Midfall's loader downsizes bls_filecoin_2p19 on the first full run.
  2. Compile the ignored Solidity verifier bench.
  3. Run tests/ivc_keccak_solidity.rs::ivc_final_keccak_solidity_e2e with
     evm,truncated-challenges,fewer-point-sets,solidity-gas-checkpoints.

Examples:
  scripts/run_ivc_bench.sh --check-only
  scripts/run_ivc_bench.sh
  SRS_DIR=/path/to/srs scripts/run_ivc_bench.sh --native-midfall
USAGE
}

die() {
  echo "[ivc-bench] error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found on PATH: $1"
}

abs_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "$PWD/${1#./}" ;;
  esac
}

while (($#)); do
  case "$1" in
    --check-only)
      CHECK_ONLY=1
      ;;
    --skip-srs-download)
      SKIP_SRS_DOWNLOAD=1
      ;;
    --srs-dir)
      [[ $# -ge 2 ]] || die "--srs-dir requires a value"
      SRS_DIR="$2"
      shift
      ;;
    --no-gas-checkpoints)
      GAS_CHECKPOINTS=0
      ;;
    --native-midfall)
      RUN_NATIVE_MIDFALL=1
      ;;
    --native-only)
      RUN_NATIVE_MIDFALL=1
      RUN_SOLIDITY_BENCH=0
      ;;
    --midfall-dir)
      [[ $# -ge 2 ]] || die "--midfall-dir requires a value"
      MIDFALL_DIR="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
  shift
done

SRS_DIR="$(abs_path "$SRS_DIR")"
MIDFALL_DIR="$(abs_path "$MIDFALL_DIR")"

download_if_missing() {
  local path="$1"
  local url="$2"

  if [[ -s "$path" ]]; then
    echo "[ivc-bench] using $(basename "$path")"
    return
  fi

  [[ "$SKIP_SRS_DOWNLOAD" -eq 0 ]] || die "missing SRS asset: $path"
  require_cmd curl

  mkdir -p "$(dirname "$path")"
  local tmp="$path.partial"
  echo "[ivc-bench] downloading $(basename "$path")"
  echo "[ivc-bench]   from $url"
  curl -fL --retry 3 --retry-delay 2 -o "$tmp" "$url"
  mv "$tmp" "$path"
}

ensure_srs_assets() {
  mkdir -p "$SRS_DIR"

  if [[ -s "$SRS_DIR/bls_filecoin_2p13" ]]; then
    echo "[ivc-bench] using bls_filecoin_2p13"
  elif [[ -s "$SRS_DIR/bls_filecoin_2p19" ]]; then
    echo "[ivc-bench] using bls_filecoin_2p19; Midfall will downsize to bls_filecoin_2p13 if needed"
  else
    download_if_missing "$SRS_DIR/bls_filecoin_2p19" "$FILECOIN_SRS_URL"
  fi

  download_if_missing "$SRS_DIR/midnight-srs-2p19" "$MIDNIGHT_SRS_URL"
}

cargo_features() {
  local features="evm,truncated-challenges,fewer-point-sets"
  if [[ "$GAS_CHECKPOINTS" -eq 1 ]]; then
    features="$features,solidity-gas-checkpoints"
  fi
  printf '%s\n' "$features"
}

run_native_midfall() {
  [[ -f "$MIDFALL_DIR/aggregation/Cargo.toml" ]] || die "Midfall aggregation Cargo.toml not found under $MIDFALL_DIR"

  echo "[ivc-bench] compiling Midfall native Keccak final IVC test"
  echo "+ SRS_DIR=$SRS_DIR cargo test --release --manifest-path $MIDFALL_DIR/aggregation/Cargo.toml --test single_aggregation_keccak_final --features keccak-transcript,truncated-challenges,fewer-point-sets --no-run"
  SRS_DIR="$SRS_DIR" cargo test --release \
    --manifest-path "$MIDFALL_DIR/aggregation/Cargo.toml" \
    --test single_aggregation_keccak_final \
    --features keccak-transcript,truncated-challenges,fewer-point-sets \
    --no-run

  if [[ "$CHECK_ONLY" -eq 0 ]]; then
    echo "[ivc-bench] running Midfall native Keccak final IVC test"
    echo "+ SRS_DIR=$SRS_DIR cargo test --release --manifest-path $MIDFALL_DIR/aggregation/Cargo.toml --test single_aggregation_keccak_final --features keccak-transcript,truncated-challenges,fewer-point-sets -- --ignored --nocapture"
    SRS_DIR="$SRS_DIR" cargo test --release \
      --manifest-path "$MIDFALL_DIR/aggregation/Cargo.toml" \
      --test single_aggregation_keccak_final \
      --features keccak-transcript,truncated-challenges,fewer-point-sets \
      -- --ignored --nocapture
  fi
}

run_solidity_bench() {
  local features
  features="$(cargo_features)"

  if [[ "$CHECK_ONLY" -eq 0 ]]; then
    require_cmd solc
  fi

  echo "[ivc-bench] compiling IVC Keccak Solidity verifier bench"
  echo "+ SRS_DIR=$SRS_DIR cargo test --release --features $features --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e --no-run"
  (
    cd "$ROOT_DIR"
    SRS_DIR="$SRS_DIR" cargo test --release \
      --features "$features" \
      --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
      --no-run
  )

  if [[ "$CHECK_ONLY" -eq 0 ]]; then
    echo "[ivc-bench] running IVC Keccak Solidity verifier bench"
    echo "+ SRS_DIR=$SRS_DIR cargo test --release --features $features --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e -- --ignored --nocapture"
    (
      cd "$ROOT_DIR"
      SRS_DIR="$SRS_DIR" cargo test --release \
        --features "$features" \
        --test ivc_keccak_solidity ivc_final_keccak_solidity_e2e \
        -- --ignored --nocapture
    )

    local dump_dir="$ROOT_DIR/target/ivc-keccak-solidity-dump"
    if [[ -d "$dump_dir" ]]; then
      echo "[ivc-bench] generated Solidity artifacts: $dump_dir"
      if [[ -f "$dump_dir/contract-sizes.txt" ]]; then
        echo "[ivc-bench] contract sizes:"
        cat "$dump_dir/contract-sizes.txt"
      fi
    fi
  fi
}

require_cmd cargo
ensure_srs_assets

echo "[ivc-bench] SRS_DIR=$SRS_DIR"

if [[ "$RUN_NATIVE_MIDFALL" -eq 1 ]]; then
  run_native_midfall
fi

if [[ "$RUN_SOLIDITY_BENCH" -eq 1 ]]; then
  run_solidity_bench
fi

echo "[ivc-bench] done"
