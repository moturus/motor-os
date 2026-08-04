#!/usr/bin/env bash

if [ "${LORRY_INTEGRATION_TIMEOUT_ACTIVE:-0}" != "1" ]; then
    export LORRY_INTEGRATION_TIMEOUT_ACTIVE=1
    timeout 3600s "$0" "$@" < /dev/null
    status=$?
    if [ "$status" -eq 124 ]; then
        echo "lorry-integration-test: timed out after 3600 seconds" >&2
    fi
    exit "$status"
fi

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LORRY_DIR="$ROOT_DIR/src/bin/lorry"

[ "$#" -eq 0 ] || {
    echo "usage: lorry-integration-test.sh" >&2
    exit 1
}

run_host() {
    # This includes the unit suite plus the Linux-native, Linux-to-Motor,
    # Cargo-identity, and self-build gates.
    "$LORRY_DIR/tests/stage1-linux.sh"
    "$LORRY_DIR/tests/curl-contract-linux.sh"
    "$LORRY_DIR/tests/public-crates-io.sh"
    "$LORRY_DIR/tests/motor-crates-io.sh"
}

run_native() {
    "$LORRY_DIR/test-native.sh"
}

run_host
run_native
