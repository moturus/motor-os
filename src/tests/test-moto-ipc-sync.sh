#!/bin/bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_DIR="$(mktemp -d /tmp/moto-ipc-sync.XXXXXX)"
trap 'rm -r "$TEST_DIR"' EXIT
RUST_ARGS=()
if [ "${1:-}" = --release ] && [ "$#" -eq 1 ]; then
  RUST_ARGS+=(-O)
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--release]" >&2
  exit 2
fi
cd "$ROOT_DIR"
rustc --edition=2021 --test -D warnings src/tests/moto-ipc-sync.rs \
  "${RUST_ARGS[@]}" -o "$TEST_DIR/tests"
"$TEST_DIR/tests"
