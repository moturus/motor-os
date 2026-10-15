#!/bin/bash
# Hermetic host gate for optional Gears workflows.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PROFILE_ARGS=()
WORKFLOW_PROFILE=debug
PREPARE=0
for arg in "$@"; do
  case "$arg" in
    --release) PROFILE_ARGS=(--release); WORKFLOW_PROFILE=release ;;
    --prepare) PREPARE=1 ;;
    *) echo "usage: test-gears-batteries.sh [--release] [--prepare]" >&2; exit 2 ;;
  esac
done

# The ordinary host need not have rg installed. Use the same source checkout
# as the Motor add-on, with Linux artifacts kept inside this repository.
RG_MANIFEST="$ROOT_DIR/../ripgrep/Cargo.toml"
if [ ! -f "$RG_MANIFEST" ]; then
  echo "batteries host gate requires the ripgrep checkout at $RG_MANIFEST" >&2
  exit 1
fi
RG_TARGET="$ROOT_DIR/build/gears-batteries-host-rg"
cargo build --quiet --locked --offline --manifest-path "$RG_MANIFEST" \
  --target x86_64-unknown-linux-gnu --target-dir "$RG_TARGET" --bin rg \
  "${PROFILE_ARGS[@]}"
RG_DIRECTORY="$RG_TARGET/x86_64-unknown-linux-gnu/$WORKFLOW_PROFILE"
test -x "$RG_DIRECTORY/rg"
export PATH="$RG_DIRECTORY:$PATH"
if [ "$PREPARE" = 1 ]; then
  echo "test-gears-batteries.sh host rg prepared"
  exit 0
fi

# test-gears-http.sh runs the package's tests; this gate runs the workflow.
MANIFEST="$ROOT_DIR/src/bin/gears/Cargo.toml"
TARGET="$ROOT_DIR/src/bin/gears/target"
cargo build --quiet --locked --offline --manifest-path "$MANIFEST" --target-dir "$TARGET" \
  --bins "${PROFILE_ARGS[@]}"
cargo run --quiet --locked --offline --manifest-path "$MANIFEST" --target-dir "$TARGET" \
  --example workflow-smoke "${PROFILE_ARGS[@]}" -- \
  "$TARGET/$WORKFLOW_PROFILE/gears-batteries" "$(rustup which rustc)" "$TARGET/$WORKFLOW_PROFILE/gears"
echo "test-gears-batteries.sh ALL PASS"
