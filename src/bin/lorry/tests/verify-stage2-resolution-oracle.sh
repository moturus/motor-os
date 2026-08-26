#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FIXTURE="$SCRIPT_DIR/oracles/stage2-resolution"
if [ -z "${LORRY_TEST_CARGO:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/lorry-stage2-resolution-oracle.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT

verify() {
    local family=$1
    local cargo=$2
    local version
    local copy="$WORK/$family/fixture"
    version=$("$cargo" --version)
    mkdir -p -- "$copy"
    cp -R -- "$FIXTURE/." "$copy"
    rm -f -- "$copy/root/Cargo.lock"
    (
        cd -- "$copy/root"
        CARGO_HOME="$WORK/$family/cargo-home" "$cargo" generate-lockfile --offline
    )
    if ! cmp -s -- "$FIXTURE/root/Cargo.lock" "$copy/root/Cargo.lock"; then
        case "$version" in
            "cargo $family."*)
                echo "error: $version generated a result different from its frozen oracle" >&2
                ;;
            *)
                echo "error: $version is not the expected Cargo $family oracle and generated a different result" >&2
                ;;
        esac
        diff -u --label "Cargo $family oracle/Cargo.lock" \
            --label "$version/Cargo.lock" \
            "$FIXTURE/root/Cargo.lock" "$copy/root/Cargo.lock" >&2 || true
        return 1
    fi
}

verify "1.99" "$LORRY_TEST_CARGO"
echo "PASS: the current Motor Cargo matches the frozen Stage 2 resolution oracle"
