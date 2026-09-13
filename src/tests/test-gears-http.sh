#!/bin/bash
# Hermetic host gate, including Gears through the in-tree curl executable.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PROFILE=debug
PROFILE_ARGS=()
case "${1:-}" in
  "") ;;
  --release) PROFILE=release; PROFILE_ARGS=(--release) ;;
  *) echo "usage: test-gears-http.sh [--release]" >&2; exit 2 ;;
esac

cargo_in() {
  local crate="$1"
  shift
  cargo "$@" --quiet --locked --manifest-path "$ROOT_DIR/src/bin/$crate/Cargo.toml" "${PROFILE_ARGS[@]}"
}

# curl's integration tests build the host binary that the Gears provider
# regression then runs in place of upstream curl.
cargo_in curl test
export MOTOR_CURL_TEST_PROGRAM="$ROOT_DIR/src/bin/curl/target/$PROFILE/curl"
test -x "$MOTOR_CURL_TEST_PROGRAM"
cargo_in gears test
# test-gears-http-vm.sh runs this binary on the host.
cargo_in gears-mock-provider build
cargo_in gears-mock-provider test
echo "test-gears-http.sh ALL PASS"
