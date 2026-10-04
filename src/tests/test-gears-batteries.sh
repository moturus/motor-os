#!/bin/bash
# Hermetic host gate for optional Gears workflows.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PROFILE_ARGS=()
case "${1:-}" in
  "") ;;
  --release) PROFILE_ARGS=(--release) ;;
  *) echo "usage: test-gears-batteries.sh [--release]" >&2; exit 2 ;;
esac
cargo test --quiet --locked --manifest-path "$ROOT_DIR/src/bin/gears-batteries/Cargo.toml" "${PROFILE_ARGS[@]}"
echo "test-gears-batteries.sh ALL PASS"
