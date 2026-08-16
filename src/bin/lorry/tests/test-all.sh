#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUDGET_SECONDS="${LORRY_TEST_BUDGET_SECONDS:-1800}"
NATIVE_ARGUMENTS=()

usage() {
    cat <<'EOF'
usage: test-all.sh [--warm] [--keep] [--reuse-running-vm]

Runs the complete Lorry product suite once. The default invocation is bounded
to 30 minutes; exceeding the budget is a test failure. --warm only preserves
the native fixture's host and guest target directories for local iteration.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --warm | --keep | --reuse-running-vm) NATIVE_ARGUMENTS+=("$1") ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "test-all: unknown option '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

case "$BUDGET_SECONDS" in
    '' | *[!0-9]* | 0)
        echo "test-all: LORRY_TEST_BUDGET_SECONDS must be a positive integer" >&2
        exit 1
        ;;
esac

if [ "${LORRY_TEST_BUDGET_ACTIVE:-0}" -eq 0 ]; then
    start="$SECONDS"
    set +e
    LORRY_TEST_BUDGET_ACTIVE=1 timeout --foreground "$BUDGET_SECONDS" \
        "$0" "${NATIVE_ARGUMENTS[@]}"
    status="$?"
    set -e
    elapsed=$((SECONDS - start))
    if [ "$status" -eq 124 ]; then
        echo "test-all: exceeded the ${BUDGET_SECONDS}s wall-clock budget" >&2
    fi
    echo "Lorry complete-suite wall time: ${elapsed}s"
    exit "$status"
fi

TOOLCHAIN="nightly-2026-06-19"
CARGO="$(rustup which cargo --toolchain "$TOOLCHAIN")"
RUSTC="$(rustup which rustc --toolchain "$TOOLCHAIN")"

echo "== Lorry unit and integration-style Rust tests =="
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTC="$RUSTC" "$CARGO" test \
    --manifest-path "$LORRY_DIR/Cargo.toml" --locked --offline

echo "== Paired Cargo resolution oracle =="
"$SCRIPT_DIR/verify-stage2-resolution-oracle.sh"

echo "== Release Lorry and offline review contract =="
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTC="$RUSTC" "$CARGO" build \
    --manifest-path "$LORRY_DIR/Cargo.toml" --locked --offline --release
LORRY="$LORRY_DIR/target/release/lorry"
"$SCRIPT_DIR/review-contract.sh" "$LORRY"

"$SCRIPT_DIR/cargo-identity.sh" "$LORRY"
"$SCRIPT_DIR/workspace-contract.sh" "$LORRY"
"$SCRIPT_DIR/registry-contract.sh" "$LORRY"
"$SCRIPT_DIR/curl-contract.sh" "$LORRY"
"$SCRIPT_DIR/test-native.sh" "${NATIVE_ARGUMENTS[@]}"

echo "PASS: complete Lorry product suite"
