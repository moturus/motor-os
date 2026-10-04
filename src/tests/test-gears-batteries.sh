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
WORKFLOW_PROFILE=debug
if [ "${1:-}" = --release ]; then WORKFLOW_PROFILE=release; fi
WORKFLOW_TARGET="$(cargo metadata --no-deps --format-version 1 --manifest-path "$ROOT_DIR/src/bin/gears-batteries/Cargo.toml" | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
cargo run --quiet --locked --manifest-path "$ROOT_DIR/src/bin/gears-batteries/Cargo.toml" --example workflow-smoke "${PROFILE_ARGS[@]}" -- "$WORKFLOW_TARGET/$WORKFLOW_PROFILE/gears-batteries" "$(rustup which rustc)"
echo "test-gears-batteries.sh ALL PASS"
