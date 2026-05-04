#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRS_DIR="${SRS_DIR:-"$ROOT_DIR/.srs"}"
SKIP_DOWNLOAD=0

while (($#)); do
  case "$1" in
    --skip-download)
      SKIP_DOWNLOAD=1
      shift
      ;;
    --srs-dir)
      [[ $# -ge 2 ]] || { echo "--srs-dir requires DIR" >&2; exit 1; }
      SRS_DIR="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

mkdir -p "$SRS_DIR"

ensure_asset() {
  local name="$1"
  local url="$2"
  local path="$SRS_DIR/$name"
  if [[ -s "$path" ]]; then
    echo "[srs] using $name"
    return
  fi
  if [[ "$SKIP_DOWNLOAD" -eq 1 ]]; then
    echo "[srs] missing $path" >&2
    exit 1
  fi
  echo "[srs] downloading $name"
  curl -fL --retry 3 --retry-delay 5 -o "$path" "$url"
}

ensure_asset "bls_filecoin_2p19" "https://midnight-s3-fileshare-dev-eu-west-1.s3.eu-west-1.amazonaws.com/bls_filecoin_2p19"
ensure_asset "midnight-srs-2p19" "https://srs.midnight.network/midnight-srs-2p19"
ensure_asset "midnight-srs-2p20" "https://srs.midnight.network/midnight-srs-2p20"
ensure_asset "midnight-srs-2p22" "https://srs.midnight.network/midnight-srs-2p22"

echo "[srs] SRS_DIR=$SRS_DIR"
