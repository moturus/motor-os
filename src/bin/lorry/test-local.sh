#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="debug"
REPEAT=1
KEEP=0

# shellcheck source=tests/timing.sh
source "$SCRIPT_DIR/tests/timing.sh"

usage() {
    cat <<'EOF'
usage: test-local.sh [--release] [--repeat COUNT] [--keep]

Runs the Lorry-local Linux-to-Linux, Linux-to-Motor, and Motor-to-Motor
verification matrix. Use --repeat 3 for the pre-review gate.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --release) PROFILE="release" ;;
        --repeat)
            [ "$#" -ge 2 ] || { usage >&2; exit 1; }
            REPEAT="$2"
            shift
            ;;
        --keep) KEEP=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "test-local: unknown option '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

case "$REPEAT" in
    '' | *[!0-9]* | 0)
        echo "test-local: repeat count must be a positive integer" >&2
        exit 1
        ;;
esac

timing_init
for pass in $(seq 1 "$REPEAT"); do
    echo "== Lorry $PROFILE local matrix pass $pass/$REPEAT =="
    cargo_args=(
        test
        --manifest-path "$SCRIPT_DIR/Cargo.toml"
        --locked
        --offline
    )
    build_args=(
        build
        --manifest-path "$SCRIPT_DIR/Cargo.toml"
        --locked
        --offline
    )
    native_args=()
    lorry_args=(build)
    target_profile="debug"
    if [ "$PROFILE" = "release" ]; then
        cargo_args+=(--release)
        build_args+=(--release)
        native_args+=(--release)
        lorry_args+=(--release)
        target_profile="release"
    fi
    [ "$KEEP" -eq 0 ] || native_args+=(--keep)

    timing_run "pass-$pass/timing-contract" \
        "$SCRIPT_DIR/tests/timing-contract.sh"
    timing_run "pass-$pass/stage2-resolution-oracles" \
        "$SCRIPT_DIR/tests/verify-stage2-resolution-oracle.sh"
    timing_run "pass-$pass/rust-tests" cargo "${cargo_args[@]}"
    timing_run "pass-$pass/linux-lorry-build" cargo "${build_args[@]}"
    (
        cd "$SCRIPT_DIR"
        timing_run "pass-$pass/linux-to-linux-build" \
            "$SCRIPT_DIR/target/$target_profile/lorry" "${lorry_args[@]}"
    )
    timing_run "pass-$pass/native-matrix" \
        "$SCRIPT_DIR/test-native.sh" "${native_args[@]}"
done

echo "PASS: $REPEAT Lorry $PROFILE local matrix pass(es) completed"
