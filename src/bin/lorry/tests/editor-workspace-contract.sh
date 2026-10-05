#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
LORRY="$(realpath "${1:?usage: editor-workspace-contract.sh LORRY}")"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
WORK="$(mktemp -d /tmp/lorry-editor-workspace-XXXXXX)"
trap 'status=$?; if [ "$status" = 0 ]; then rm -rf "$WORK"; else echo "Retained editor fixture: $WORK" >&2; fi' EXIT
RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" run --quiet --locked --offline \
    --manifest-path "$SCRIPT_DIR/editor-workspace/Cargo.toml" -- "$LORRY" "$ROOT_DIR" "$WORK"
