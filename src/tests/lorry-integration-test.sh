#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LORRY_DIR="$ROOT_DIR/src/bin/lorry"

BUILD="debug"
MODE="all"
REUSE_VM=0
GATE="exhaustive"

usage() {
    echo "usage: lorry-integration-test.sh [--release] [--acceptance|--exhaustive] [--host-only|--native-only] [--reuse-running-vm]"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --release) BUILD="release" ;;
        --acceptance) GATE="acceptance" ;;
        --exhaustive) GATE="exhaustive" ;;
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
    "$SCRIPT_DIR/lorry-integration-policy-contract.sh"
    if [ "$BUILD" = "release" ]; then
        cargo_arguments+=(--release)
        contract_arguments+=(--release)
    fi

    if [ "$BUILD" = "release" ]; then
        cargo "${cargo_arguments[@]}"
    else
        # This includes the debug unit suite plus the Stage-1 Cargo identity,
        # cross-Motor, and self-build gates.
        "$SCRIPT_DIR/lorry-stage1-integration.sh"
    fi
    "$SCRIPT_DIR/lorry-curl-contract-linux.sh" "${contract_arguments[@]}"
    "$SCRIPT_DIR/lorry-registry-cache.sh"
}

run_native() {
    local -a arguments=()
    local -a motor_arguments=()
    [ "$GATE" = "acceptance" ] || arguments+=(--full)
    if [ "$BUILD" = "release" ]; then
        arguments+=(--release)
        motor_arguments+=(--release)
    fi
    [ "$REUSE_VM" -eq 0 ] || arguments+=(--reuse-running-vm)
    "$SCRIPT_DIR/lorry-native-integration.sh" "${arguments[@]}"
    if [ "$GATE" = "exhaustive" ]; then
        "$SCRIPT_DIR/lorry-motor-registry-cache.sh" "${motor_arguments[@]}"
    fi
}

case "$MODE" in
    all)
        run_host
        run_native
        ;;
    host) run_host ;;
    native) run_native ;;
esac
