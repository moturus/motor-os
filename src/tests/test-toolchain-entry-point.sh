#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

fail() {
  echo "test-toolchain-entry-point: $*" >&2
  exit 1
}

if output="$($ROOT_DIR/src/build-base.sh 2>&1)"; then
  fail "private build-base.sh accepted direct execution"
fi
case "$output" in
  *"build-base.sh is private"*"src/build-motor-os.sh"*) ;;
  *) fail "private entry-point diagnostic is missing: $output" ;;
esac

help="$($ROOT_DIR/src/build-motor-os.sh --help)"
case "$help" in
  *"Usage: src/build-motor-os.sh"*) ;;
  *) fail "public entry point did not provide usage" ;;
esac

# Sourcing the private helper remains valid for its function-level offline
# tests and must not execute provisioning.
. "$ROOT_DIR/src/build-base.sh"
declare -F host_networking_ready >/dev/null || fail "private helper was not sourceable"
declare -F build_rust_toolchain >/dev/null && fail "private helper still builds Rust"
case "$(declare -f install_rust)" in
  *'rustup default'*|*'rustup component add'*) fail "host helper changes the Rust selection" ;;
esac
. "$ROOT_DIR/src/build-motor-os.sh"
declare -F prepare_exact_sources >/dev/null || fail "exact source orchestrator is missing"

echo "test-toolchain-entry-point PASS"
