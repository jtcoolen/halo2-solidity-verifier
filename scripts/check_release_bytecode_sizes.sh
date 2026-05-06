#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUMMARY="${1:-"$ROOT_DIR/target/ivc-keccak-solidity-dump/contract-sizes.txt"}"
EIP170_MAX_RUNTIME_SIZE="${EIP170_MAX_RUNTIME_SIZE:-24576}"

[[ -f "$SUMMARY" ]] || {
  echo "contract size summary not found: $SUMMARY" >&2
  exit 1
}

extract_number() {
  local label="$1"
  awk -F': ' -v label="$label" '$1 == label { gsub(",", "", $2); print $2; found=1 } END { if (!found) exit 1 }' "$SUMMARY"
}

extract_hash() {
  local label="$1"
  awk -F': ' -v label="$label" '$1 == label { print $2; found=1 } END { if (!found) exit 1 }' "$SUMMARY"
}

check_size() {
  local label="$1"
  local size
  size="$(extract_number "$label")"
  if (( size > EIP170_MAX_RUNTIME_SIZE )); then
    echo "$label = $size exceeds EIP-170 max $EIP170_MAX_RUNTIME_SIZE" >&2
    exit 1
  fi
  echo "[bytecode-size] $label = $size"
}

check_hash() {
  local label="$1"
  local expected="$2"
  local actual
  actual="$(extract_hash "$label")"
  if [[ "$actual" != "$expected" ]]; then
    echo "$label mismatch: expected $expected, got $actual" >&2
    exit 1
  fi
  echo "[bytecode-hash] $label = $actual"
}

check_size "Halo2Verifier deployed runtime bytes"
check_size "Halo2VerifyingKey deployed runtime bytes"

check_hash "Halo2Verifier deployed runtime keccak256" "0x37fca91bd3fe16ac462da8ab79b9891b70d8d7a33af62df713f80a76436fa0b0"
check_hash "Halo2VerifyingKey deployed runtime keccak256" "0x92dc96f0c5182608e61ac3b9a257294749f67c1306b516b898f6e2456ccfdfc9"

echo "[bytecode-size] release bytecode size and hash checks passed"
