#!/usr/bin/env bash
set -euo pipefail

PINNED_SOLC_VERSION="${PINNED_SOLC_VERSION:-0.8.30+commit.73712a01}"
INSTALL_DIR="${1:-${SOLC_INSTALL_DIR:-$PWD/.solc}}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    platform="linux-amd64"
    binary="solc-linux-amd64-v${PINNED_SOLC_VERSION}"
    ;;
  Darwin-x86_64)
    platform="macosx-amd64"
    binary="solc-macosx-amd64-v${PINNED_SOLC_VERSION}"
    ;;
  Darwin-arm64)
    platform="macosx-amd64"
    binary="solc-macosx-amd64-v${PINNED_SOLC_VERSION}"
    ;;
  *)
    echo "unsupported platform for pinned solc install: $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "$INSTALL_DIR"
solc_path="$INSTALL_DIR/solc"

if [[ ! -x "$solc_path" ]] || ! "$solc_path" --version | grep -q "Version: ${PINNED_SOLC_VERSION}"; then
  url="https://binaries.soliditylang.org/${platform}/${binary}"
  echo "[install-solc] downloading $url"
  curl -fsSL "$url" -o "$solc_path"
  chmod +x "$solc_path"
fi

"$solc_path" --version
echo "$solc_path"
