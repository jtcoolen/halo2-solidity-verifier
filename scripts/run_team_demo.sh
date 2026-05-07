#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_NAME="$(basename "$ROOT_DIR")"
cd "$ROOT_DIR"

PINNED_SOLC_VERSION="${PINNED_SOLC_VERSION:-0.8.30+commit.73712a01}"
SOLC_INSTALL_DIR="${SOLC_INSTALL_DIR:-"$ROOT_DIR/.solc"}"
SRS_DIR="${SRS_DIR:-"$ROOT_DIR/.srs"}"
LOG_DIR="${LOG_DIR:-"$ROOT_DIR/target/team-demo-logs"}"

MOONLIGHT_DIR="${MOONLIGHT_DIR:-../Moonlight}"
MOONLIGHT_BRANCH="${MOONLIGHT_BRANCH:-codex/wrap-bench-cherry-picks}"
MOONLIGHT_URL="${MOONLIGHT_URL:-git@github.com:EYBlockchain/Moonlight.git}"
MOONLIGHT_HTTPS_URL="${MOONLIGHT_HTTPS_URL:-https://github.com/EYBlockchain/Moonlight.git}"
MOONLIGHT_WRAP_TEST="wrap_circuit_composes_two_fold_children_from_four_dummy_fold_proofs"
MOONLIGHT_DUMP_DIR="${MOONLIGHT_WRAP_SOLIDITY_DUMP_DIR:-"$ROOT_DIR/target/moonlight-wrap-solidity-dump"}"

CHECK_ONLY=0
SKIP_SRS_DOWNLOAD=0
RUN_TRACE=1
RUN_MOONLIGHT=1
CLONE_MOONLIGHT=1
UPDATE_MOONLIGHT=0
USE_HTTPS=0
INSTALL_SOLC=1
PRECHECK_BUILDS=1
FIX_MOONLIGHT_DEP=1

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RED=$'\033[31m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  BLUE=$'\033[34m'
  MAGENTA=$'\033[35m'
  CYAN=$'\033[36m'
  RESET=$'\033[0m'
else
  BOLD=""
  DIM=""
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  MAGENTA=""
  CYAN=""
  RESET=""
fi

usage() {
  cat <<USAGE
Run the full team demo setup, trace equivalence tests, and Moonlight wrap bench.

Usage:
  scripts/run_team_demo.sh [options]

Default flow:
  1. Check local tools and install the pinned solc under .solc when needed.
  2. Check/download Midnight SRS assets through scripts/run_ivc_bench.sh.
  3. Check or clone Moonlight next to this repo.
  4. Compile the trace and Moonlight bench paths as a preflight.
  5. Run the IVC Rust/Solidity trace equivalence test.
  6. Run the Moonlight wrap decider Solidity bench and trace equivalence check.

Options:
  --check-only              Run setup checks and compile preflights only.
  --skip-srs-download      Fail when required SRS assets are missing.
  --srs-dir DIR            SRS directory. Defaults to \$SRS_DIR or .srs.
  --log-dir DIR            Command log directory. Defaults to target/team-demo-logs.
  --moonlight-dir DIR      Moonlight checkout, relative to this repo unless absolute. Defaults to ../Moonlight.
  --moonlight-branch NAME  Moonlight branch. Defaults to codex/wrap-bench-cherry-picks.
  --moonlight-url URL      SSH clone URL for Moonlight.
  --https                  Clone Moonlight with the HTTPS URL.
  --update-moonlight       Fetch and switch Moonlight to the requested branch.
  --no-clone-moonlight     Do not clone Moonlight if it is missing.
  --skip-trace             Skip the IVC Rust/Solidity trace equivalence run.
  --skip-moonlight         Skip the Moonlight wrap decider bench and trace check.
  --no-solc-install        Do not install .solc/solc automatically.
  --no-precheck-builds     Skip compile-only preflight commands.
  --no-fix-moonlight-dep   Do not create a local symlink for Moonlight's verifier path dependency.
  -h, --help               Show this help.

Examples:
  scripts/run_team_demo.sh --check-only
  scripts/run_team_demo.sh
  scripts/run_team_demo.sh --https --update-moonlight

Standalone Moonlight gas bench command:
  MOONLIGHT_RUN_WRAP_SOLIDITY_BENCH=1 \\
  cargo test --manifest-path ../Moonlight/aggregation/Cargo.toml \\
    wrap_circuit_composes_two_fold_children_from_four_dummy_fold_proofs --release \\
    --lib -- --ignored --nocapture
USAGE
}

die() {
  printf '%s[demo:error]%s %s\n' "$RED" "$RESET" "$*" >&2
  exit 1
}

warn() {
  printf '%s[demo:warn]%s %s\n' "$YELLOW" "$RESET" "$*"
}

info() {
  printf '%s[demo]%s %s\n' "$BLUE" "$RESET" "$*"
}

ok() {
  printf '%s[demo:ok]%s %s\n' "$GREEN" "$RESET" "$*"
}

section() {
  printf '\n%s%s%s\n' "$BOLD$CYAN" "$*" "$RESET"
}

explain() {
  printf '%s%s%s\n' "$DIM" "$*" "$RESET"
}

quote_cmd() {
  local quoted=()
  local arg
  for arg in "$@"; do
    printf -v arg '%q' "$arg"
    quoted+=("$arg")
  done
  printf '%s' "${quoted[*]}"
}

slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-//; s/-$//'
}

moonlight_manifest_path() {
  printf '%s/aggregation/Cargo.toml' "$MOONLIGHT_DIR"
}

print_moonlight_gas_command() {
  [[ "$RUN_MOONLIGHT" -eq 1 ]] || return 0

  printf '%s\n' "Moonlight gas bench command:"
  printf '%s\n' "  MOONLIGHT_RUN_WRAP_SOLIDITY_BENCH=1 \\"
  printf '%s\n' "  cargo test --manifest-path $(moonlight_manifest_path) \\"
  printf '%s\n' "    $MOONLIGHT_WRAP_TEST --release \\"
  printf '%s\n' "    --lib -- --ignored --nocapture"
}

run_logged() {
  local label="$1"
  shift

  mkdir -p "$LOG_DIR"
  local slug
  slug="$(slugify "$label")"
  local stamp
  stamp="$(date +"%Y%m%d-%H%M%S")"
  local log_file="$LOG_DIR/${stamp}-${slug}.log"

  section "$label"
  explain "Log: $log_file"
  printf '%s+ %s%s\n' "$MAGENTA" "$(quote_cmd "$@")" "$RESET"

  local start
  start="$(date +%s)"
  if "$@" 2>&1 | tee "$log_file"; then
    local end
    end="$(date +%s)"
    ok "$label completed in $((end - start))s"
  else
    local status=$?
    warn "$label failed. Full log: $log_file"
    return "$status"
  fi
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

dependency_abs_path() {
  local base_dir="$1"
  local dep_path="$2"
  local parent
  local leaf

  case "$dep_path" in
    /*)
      parent="$(dirname "$dep_path")"
      leaf="$(basename "$dep_path")"
      ;;
    *)
      parent="$base_dir/$(dirname "$dep_path")"
      leaf="$(basename "$dep_path")"
      ;;
  esac

  local parent_abs
  parent_abs="$(cd "$parent" 2>/dev/null && pwd -P)" || return 1
  printf '%s/%s\n' "$parent_abs" "$leaf"
}

solc_version() {
  local solc_bin="$1"
  "$solc_bin" --version 2>/dev/null | awk '/^Version: / { print $2; exit }'
}

ensure_solc() {
  section "Pinned Solidity Compiler"
  explain "The generated bytecode is reproducible only with solc $PINNED_SOLC_VERSION."

  local preferred="${SOLC:-"$SOLC_INSTALL_DIR/solc"}"
  if [[ -x "$preferred" && "$(solc_version "$preferred")" == "$PINNED_SOLC_VERSION"* ]]; then
    export SOLC="$preferred"
    ok "Using pinned solc: $SOLC"
    "$SOLC" --version
    return
  fi

  if [[ "$INSTALL_SOLC" -eq 0 ]]; then
    die "pinned solc not found. Set SOLC or rerun without --no-solc-install."
  fi

  require_cmd curl
  run_logged "Install pinned solc" "$ROOT_DIR/scripts/install_pinned_solc.sh" "$SOLC_INSTALL_DIR"
  export SOLC="$SOLC_INSTALL_DIR/solc"
  [[ -x "$SOLC" ]] || die "solc install did not create $SOLC"
  [[ "$(solc_version "$SOLC")" == "$PINNED_SOLC_VERSION"* ]] || die "installed solc is not pinned $PINNED_SOLC_VERSION"
  ok "SOLC=$SOLC"
}

check_disk_space() {
  local available_kb
  available_kb="$(df -Pk "$ROOT_DIR" | awk 'NR == 2 { print $4 }')"
  local available_gb=$((available_kb / 1024 / 1024))
  if (( available_gb < 20 )); then
    warn "Only ${available_gb}GB free under $ROOT_DIR. The full demo is happier with 20GB+."
  else
    ok "Disk space: ${available_gb}GB free near repo"
  fi
}

check_tools() {
  section "Toolchain Checks"
  explain "These checks catch the boring setup problems before we start proving."

  require_cmd git
  require_cmd cargo
  require_cmd rustc
  require_cmd sed
  require_cmd awk
  require_cmd tee

  ok "git: $(git --version)"
  ok "cargo: $(cargo --version)"
  ok "rustc: $(rustc --version)"
  if command -v rustup >/dev/null 2>&1; then
    ok "rustup active toolchain: $(rustup show active-toolchain 2>/dev/null || true)"
  else
    warn "rustup is not on PATH. Cargo may still work if the pinned toolchain is already active."
  fi
  check_disk_space
}

setup_moonlight() {
  section "Moonlight Checkout"
  explain "The wrap bench lives in Moonlight, while its dev dependency points back to this verifier checkout."

  local clone_url="$MOONLIGHT_URL"
  if [[ "$USE_HTTPS" -eq 1 ]]; then
    clone_url="$MOONLIGHT_HTTPS_URL"
  fi

  if [[ ! -d "$MOONLIGHT_DIR/.git" ]]; then
    [[ "$CLONE_MOONLIGHT" -eq 1 ]] || die "Moonlight checkout missing at $MOONLIGHT_DIR"
    mkdir -p "$(dirname "$MOONLIGHT_DIR")"
    run_logged "Clone Moonlight" git clone "$clone_url" "$MOONLIGHT_DIR"
    UPDATE_MOONLIGHT=1
  else
    ok "Moonlight checkout: $MOONLIGHT_DIR"
  fi

  local current_branch
  current_branch="$(git -C "$MOONLIGHT_DIR" branch --show-current || true)"
  if [[ "$UPDATE_MOONLIGHT" -eq 1 || "$current_branch" != "$MOONLIGHT_BRANCH" ]]; then
    local tracked_changes
    tracked_changes="$(git -C "$MOONLIGHT_DIR" status --porcelain --untracked-files=no)"
    [[ -z "$tracked_changes" ]] || die "Moonlight has tracked local changes. Commit/stash them before switching branches."

    run_logged "Fetch Moonlight branch" git -C "$MOONLIGHT_DIR" fetch origin "$MOONLIGHT_BRANCH"
    if git -C "$MOONLIGHT_DIR" show-ref --verify --quiet "refs/heads/$MOONLIGHT_BRANCH"; then
      run_logged "Switch Moonlight branch" git -C "$MOONLIGHT_DIR" switch "$MOONLIGHT_BRANCH"
    else
      run_logged "Create Moonlight branch" git -C "$MOONLIGHT_DIR" switch -c "$MOONLIGHT_BRANCH" --track "origin/$MOONLIGHT_BRANCH"
    fi
  fi

  current_branch="$(git -C "$MOONLIGHT_DIR" branch --show-current || true)"
  ok "Moonlight branch: $current_branch"

  local manifest
  manifest="$(moonlight_manifest_path)"
  [[ -f "$manifest" ]] || die "Moonlight manifest not found: $manifest"

  local manifest_dir
  manifest_dir="$(dirname "$manifest")"
  local dep_path
  dep_path="$(
    sed -nE '/halo2_solidity_verifier[[:space:]]*=/ {
      s/.*path[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p
      q
    }' "$manifest"
  )"
  [[ -n "$dep_path" ]] || die "Moonlight manifest has no halo2_solidity_verifier path dependency: $manifest"

  local dep_abs
  dep_abs="$(dependency_abs_path "$manifest_dir" "$dep_path")" || die "Could not resolve Moonlight verifier dependency path \"$dep_path\" from $manifest_dir"

  if [[ ! -f "$dep_abs/Cargo.toml" ]]; then
    if [[ -e "$dep_abs" || -L "$dep_abs" ]]; then
      die "Moonlight verifier dependency exists but has no Cargo.toml: $dep_abs"
    fi
    if [[ "$FIX_MOONLIGHT_DEP" -eq 0 ]]; then
      die "Moonlight verifier dependency is missing: $dep_abs. Rerun without --no-fix-moonlight-dep or update $manifest."
    fi

    warn "Moonlight expects halo2_solidity_verifier at $dep_abs, but that path is missing."
    warn "Creating a local symlink so Moonlight resolves to this checkout: $ROOT_DIR"
    ln -s "$ROOT_DIR" "$dep_abs"
  fi

  local root_physical
  local dep_physical
  root_physical="$(cd "$ROOT_DIR" && pwd -P)"
  dep_physical="$(cd "$dep_abs" && pwd -P)"
  if [[ "$dep_physical" == "$root_physical" ]]; then
    ok "Moonlight dev dependency path \"$dep_path\" resolves to this checkout"
  else
    die "Moonlight halo2_solidity_verifier path \"$dep_path\" resolves to $dep_physical, not this checkout ($root_physical)"
  fi
}

preflight_ivc_trace() {
  [[ "$RUN_TRACE" -eq 1 ]] || return 0
  [[ "$PRECHECK_BUILDS" -eq 1 ]] || return 0

  local args=(--check-only --trace --no-outer-single-h-commitment --srs-dir "$SRS_DIR")
  if [[ "$SKIP_SRS_DOWNLOAD" -eq 1 ]]; then
    args+=(--skip-srs-download)
  fi

  run_logged \
    "Preflight IVC trace bench and SRS assets" \
    env SOLC="$SOLC" "$ROOT_DIR/scripts/run_ivc_bench.sh" "${args[@]}"
}

preflight_moonlight() {
  [[ "$RUN_MOONLIGHT" -eq 1 ]] || return 0
  [[ "$PRECHECK_BUILDS" -eq 1 ]] || return 0

  run_logged \
    "Preflight Moonlight wrap bench compile" \
    env SOLC="$SOLC" cargo test \
      --manifest-path "$(moonlight_manifest_path)" \
      "$MOONLIGHT_WRAP_TEST" \
      --release \
      --lib \
      --no-run
}

run_trace_equivalence() {
  [[ "$RUN_TRACE" -eq 1 ]] || return 0

  local args=(--trace --no-outer-single-h-commitment --srs-dir "$SRS_DIR")
  if [[ "$SKIP_SRS_DOWNLOAD" -eq 1 ]]; then
    args+=(--skip-srs-download)
  fi

  run_logged \
    "IVC Rust/Solidity trace equivalence" \
    env SOLC="$SOLC" "$ROOT_DIR/scripts/run_ivc_bench.sh" "${args[@]}"
}

run_moonlight_bench() {
  [[ "$RUN_MOONLIGHT" -eq 1 ]] || return 0

  run_logged \
    "Moonlight wrap decider Solidity bench and trace equivalence" \
    env \
      SOLC="$SOLC" \
      MOONLIGHT_RUN_WRAP_SOLIDITY_BENCH=1 \
      MOONLIGHT_RUN_WRAP_SOLIDITY_TRACE=1 \
      MOONLIGHT_WRAP_SOLIDITY_DUMP_DIR="$MOONLIGHT_DUMP_DIR" \
      cargo test \
        --manifest-path "$(moonlight_manifest_path)" \
        "$MOONLIGHT_WRAP_TEST" \
        --release \
        --lib \
        -- \
        --ignored \
        --nocapture
}

print_intro() {
  printf '%s\n' "${BOLD}${BLUE}Halo2 Solidity team demo runner${RESET}"
  printf '%s\n' "Repo:       $ROOT_DIR"
  printf '%s\n' "SRS_DIR:    $SRS_DIR"
  printf '%s\n' "Logs:       $LOG_DIR"
  printf '%s\n' "Moonlight:  $MOONLIGHT_DIR"
  printf '%s\n' "Branch:     $MOONLIGHT_BRANCH"
  printf '\n'
  printf '%s\n' "${YELLOW}This can take a while.${RESET} The trace run and Moonlight wrap bench both generate real proofs."
  printf '%s\n' "Use --check-only for setup and compile checks without the slow proof runs."
  printf '\n'
  print_moonlight_gas_command
}

print_done() {
  section "Done"
  ok "Logs are under $LOG_DIR"
  if [[ "$RUN_TRACE" -eq 1 && "$CHECK_ONLY" -eq 0 ]]; then
    ok "Trace equivalence artifacts: $ROOT_DIR/target/ivc-keccak-solidity-dump"
  fi
  if [[ "$RUN_MOONLIGHT" -eq 1 && "$CHECK_ONLY" -eq 0 ]]; then
    ok "Moonlight Solidity artifacts: $MOONLIGHT_DUMP_DIR"
  fi
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
      [[ $# -ge 2 ]] || die "--srs-dir requires DIR"
      SRS_DIR="$2"
      shift
      ;;
    --log-dir)
      [[ $# -ge 2 ]] || die "--log-dir requires DIR"
      LOG_DIR="$2"
      shift
      ;;
    --moonlight-dir)
      [[ $# -ge 2 ]] || die "--moonlight-dir requires DIR"
      MOONLIGHT_DIR="$2"
      shift
      ;;
    --moonlight-branch)
      [[ $# -ge 2 ]] || die "--moonlight-branch requires NAME"
      MOONLIGHT_BRANCH="$2"
      shift
      ;;
    --moonlight-url)
      [[ $# -ge 2 ]] || die "--moonlight-url requires URL"
      MOONLIGHT_URL="$2"
      shift
      ;;
    --https)
      USE_HTTPS=1
      ;;
    --update-moonlight)
      UPDATE_MOONLIGHT=1
      ;;
    --no-clone-moonlight)
      CLONE_MOONLIGHT=0
      ;;
    --skip-trace)
      RUN_TRACE=0
      ;;
    --skip-moonlight)
      RUN_MOONLIGHT=0
      ;;
    --no-solc-install)
      INSTALL_SOLC=0
      ;;
    --no-precheck-builds)
      PRECHECK_BUILDS=0
      ;;
    --no-fix-moonlight-dep)
      FIX_MOONLIGHT_DEP=0
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
LOG_DIR="$(abs_path "$LOG_DIR")"
MOONLIGHT_DUMP_DIR="$(abs_path "$MOONLIGHT_DUMP_DIR")"

print_intro
check_tools
ensure_solc
if [[ "$RUN_MOONLIGHT" -eq 1 ]]; then
  setup_moonlight
fi
preflight_ivc_trace
preflight_moonlight

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  section "Check-only complete"
  ok "Setup and compile preflights completed. Re-run without --check-only for the slow proof benches."
  exit 0
fi

run_trace_equivalence
run_moonlight_bench
print_done
