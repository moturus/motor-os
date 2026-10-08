#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [ -z "${LORRY_TEST_CARGO:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/lorry-resolution-oracles.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT

# Regenerates an oracle's frozen Cargo.lock and requires identical bytes.
verify() {
    local family=$1
    local cargo=$2
    local oracle=$3
    local version
    local copy="$WORK/$oracle/fixture"
    version=$("$cargo" --version)
    mkdir -p -- "$copy"
    cp -R -- "$SCRIPT_DIR/oracles/$oracle/." "$copy"
    rm -f -- "$copy/root/Cargo.lock"
    (
        cd -- "$copy/root"
        CARGO_HOME="$WORK/$oracle/cargo-home" RUSTC="$LORRY_TEST_RUSTC" \
            "$cargo" generate-lockfile --offline --quiet
    )
    if ! cmp -s -- "$SCRIPT_DIR/oracles/$oracle/root/Cargo.lock" "$copy/root/Cargo.lock"; then
        case "$version" in
            "cargo $family."*)
                echo "error: $version generated a result different from its frozen $oracle oracle" >&2
                ;;
            *)
                echo "error: $version is not the expected Cargo $family oracle and generated a different $oracle result" >&2
                ;;
        esac
        diff -u --label "Cargo $family $oracle oracle/Cargo.lock" \
            --label "$version/Cargo.lock" \
            "$SCRIPT_DIR/oracles/$oracle/root/Cargo.lock" "$copy/root/Cargo.lock" >&2 || true
        return 1
    fi
}

verify "1.99" "$LORRY_TEST_CARGO" stage2-resolution
verify "1.99" "$LORRY_TEST_CARGO" candidate-order
echo "PASS: the current Motor Cargo matches the frozen resolution oracles"
