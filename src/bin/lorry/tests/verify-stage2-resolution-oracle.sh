#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
FIXTURE="$SCRIPT_DIR/oracles/stage2-resolution"
CARGO_197=${CARGO_197:-"$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo"}
CARGO_198=${CARGO_198:-"$HOME/.rustup/toolchains/nightly-2026-06-19-x86_64-unknown-linux-gnu/bin/cargo"}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/lorry-stage2-resolution-oracle.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT

verify() {
    local family=$1
    local cargo=$2
    local version
    local copy="$WORK/$family/fixture"
    version=$("$cargo" --version)
    case "$version" in
        "cargo $family."*) ;;
        *)
            echo "error: expected Cargo $family, got: $version" >&2
            return 1
            ;;
    esac
    mkdir -p -- "$copy"
    cp -R -- "$FIXTURE/." "$copy"
    rm -f -- "$copy/root/Cargo.lock"
    (
        cd -- "$copy/root"
        CARGO_HOME="$WORK/$family/cargo-home" "$cargo" generate-lockfile --offline
    )
    cmp -- "$FIXTURE/root/Cargo.lock" "$copy/root/Cargo.lock"
}

verify "1.97" "$CARGO_197"
verify "1.98" "$CARGO_198"
echo "PASS: Cargo 1.97 and 1.98 match the frozen Stage 2 resolution oracle"
