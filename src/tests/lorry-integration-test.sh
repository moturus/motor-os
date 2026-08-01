#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LORRY_DIR="$ROOT_DIR/src/bin/lorry"

BUILD="debug"
MODE="all"
REUSE_VM=0

usage() {
    echo "usage: lorry-integration-test.sh [--release] [--host-only|--native-only] [--reuse-running-vm]"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --release) BUILD="release" ;;
        --host-only) MODE="host" ;;
        --native-only) MODE="native" ;;
        --reuse-running-vm) REUSE_VM=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "lorry-integration-test: unknown option '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

run_host() {
    local -a cargo_arguments=(
        test
        --manifest-path "$LORRY_DIR/Cargo.toml"
        --locked
        --offline
    )
    local -a contract_arguments=()
    local -a motor_arguments=()
    if [ "$BUILD" = "release" ]; then
        cargo_arguments+=(--release)
        contract_arguments+=(--release)
        motor_arguments+=(--release)
    fi

    if [ "$BUILD" = "release" ]; then
        cargo "${cargo_arguments[@]}"
    else
        # This includes the debug unit suite plus the Stage-1 Cargo identity,
        # cross-Motor, and self-build gates.
        "$LORRY_DIR/tests/stage1-linux.sh"
    fi
    "$LORRY_DIR/tests/curl-contract-linux.sh" "${contract_arguments[@]}"
    "$LORRY_DIR/tests/public-crates-io.sh"
    "$LORRY_DIR/tests/motor-crates-io.sh" "${motor_arguments[@]}"
}

run_native() {
    local -a arguments=()
    [ "$BUILD" = "debug" ] || arguments+=(--release)
    [ "$REUSE_VM" -eq 0 ] || arguments+=(--reuse-running-vm)
    "$LORRY_DIR/test-native.sh" "${arguments[@]}"
}

case "$MODE" in
    all)
        run_host
        run_native
        ;;
    host) run_host ;;
    native) run_native ;;
esac
