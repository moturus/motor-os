#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: rust-analyzer-contract.sh LORRY" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
if [ -z "${LORRY_TEST_CARGO:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}" RUSTC="$LORRY_TEST_RUSTC" \
    "$LORRY_TEST_CARGO" run --quiet --locked --offline \
    --manifest-path "$ROOT_DIR/src/tests/rust-analyzer-smoke/Cargo.toml" -- \
    --lorry "$(realpath "$1")"
