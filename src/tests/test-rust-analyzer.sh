#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
MANIFEST="$ROOT_DIR/src/tests/rust-analyzer-smoke/Cargo.toml"
profile_args=()

if [ "${1:-}" = "--release" ]; then
  profile_args+=(--release)
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--release]" >&2
  exit 2
fi

cargo test --quiet --manifest-path "$MANIFEST" --locked --offline "${profile_args[@]}"
cargo run --quiet --manifest-path "$MANIFEST" --locked --offline "${profile_args[@]}"

echo "test-rust-analyzer PASS"
