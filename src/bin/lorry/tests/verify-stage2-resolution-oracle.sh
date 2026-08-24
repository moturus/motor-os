#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FIXTURE="$SCRIPT_DIR/oracles/stage2-resolution"
CARGO_197=${CARGO_197:-"$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo"}
CARGO_198=${CARGO_198:-"$HOME/.rustup/toolchains/nightly-2026-06-19-x86_64-unknown-linux-gnu/bin/cargo"}
CARGO_199=${CARGO_199:-"$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/cargo"}
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

verify "1.97" "$CARGO_197"
verify "1.98" "$CARGO_198"
verify "1.99" "$CARGO_199"
echo "PASS: configured Cargo versions match the frozen Cargo 1.97, 1.98, and 1.99 Stage 2 resolution oracles"
