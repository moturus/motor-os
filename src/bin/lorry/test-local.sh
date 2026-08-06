#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="debug"
REPEAT=1
KEEP=0
WARM=0
DEBUG_CROSS_ONLY=0

# shellcheck source=tests/timing.sh
source "$SCRIPT_DIR/tests/timing.sh"

usage() {
    cat <<'EOF'
usage: test-local.sh [--release|--both] [--repeat COUNT] [--debug-cross-only] [--warm] [--keep]

Runs the Lorry-local Linux-to-Linux, Linux-to-Motor, and Motor-to-Motor
verification matrix. Use --repeat 3 for the pre-review gate.
--both orders both artifact profiles' host checks before their native checks.
--debug-cross-only executes but does not natively rebuild the debug artifact.
--warm preserves native target directories for the next iteration.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --release) PROFILE="release" ;;
        --both) PROFILE="both" ;;
        --repeat)
            [ "$#" -ge 2 ] || { usage >&2; exit 1; }
            REPEAT="$2"
            shift
            ;;
        --keep) KEEP=1 ;;
        --warm) WARM=1 ;;
        --debug-cross-only) DEBUG_CROSS_ONLY=1 ;;
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
    timing_run "pass-$pass/timing-contract" \
        "$SCRIPT_DIR/tests/timing-contract.sh"
    timing_run "pass-$pass/gate-routing-contract" \
        "$SCRIPT_DIR/tests/gate-routing-contract.sh"
    timing_run "pass-$pass/stage2-resolution-oracles" \
        "$SCRIPT_DIR/tests/verify-stage2-resolution-oracle.sh"

    profiles=("$PROFILE")
    [ "$PROFILE" != "both" ] || profiles=(debug release)
    for artifact_profile in "${profiles[@]}"; do
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
        lorry_args=(build)
        if [ "$artifact_profile" = "release" ]; then
            cargo_args+=(--release)
            build_args+=(--release)
            lorry_args+=(--release)
        fi
        timing_run "pass-$pass/$artifact_profile-rust-tests" \
            cargo "${cargo_args[@]}"
        timing_run "pass-$pass/$artifact_profile-linux-lorry-build" \
            cargo "${build_args[@]}"
        (
            cd "$SCRIPT_DIR"
            timing_run "pass-$pass/$artifact_profile-linux-to-linux-build" \
                "$SCRIPT_DIR/target/$artifact_profile/lorry" "${lorry_args[@]}"
        )
    done

    for artifact_profile in "${profiles[@]}"; do
        native_args=()
        [ "$artifact_profile" = "debug" ] || native_args+=(--release)
        [ "$artifact_profile" != "debug" ] || [ "$DEBUG_CROSS_ONLY" -eq 0 ] ||
            native_args+=(--cross-only)
        [ "$KEEP" -eq 0 ] || native_args+=(--keep)
        [ "$WARM" -eq 0 ] || native_args+=(--warm)
        timing_run "pass-$pass/$artifact_profile-native-matrix" \
            "$SCRIPT_DIR/test-native.sh" "${native_args[@]}"
    done
done

echo "PASS: $REPEAT Lorry $PROFILE local matrix pass(es) completed"
