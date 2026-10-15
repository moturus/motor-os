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
  cargo "$@" --quiet --locked --offline --manifest-path "$ROOT_DIR/src/bin/$crate/Cargo.toml" "${PROFILE_ARGS[@]}"
}

# curl's integration tests build the host binary that the Gears provider
# regression then runs in place of upstream curl.
cargo_in curl test
export MOTOR_CURL_TEST_PROGRAM="$ROOT_DIR/src/bin/curl/target/$PROFILE/curl"
test -x "$MOTOR_CURL_TEST_PROGRAM"
# The batteries' search tests run the rg that the batteries gate prepares.
bash "$ROOT_DIR/src/tests/test-gears-batteries.sh" --prepare "${PROFILE_ARGS[@]}"
export PATH="$ROOT_DIR/build/gears-batteries-host-rg/x86_64-unknown-linux-gnu/$PROFILE:$PATH"
cargo_in gears test
# test-gears-http-vm.sh runs the mock provider example on the host.
cargo_in gears test --example mock-provider
cargo_in gears build --example mock-provider
echo "test-gears-http.sh ALL PASS"
