#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: selected-cache-contract.sh LORRY" >&2
    exit 2
fi
LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
export RUSTC="$LORRY_TEST_RUSTC"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
WORK="$(mktemp -d /tmp/lorry-selected-cache-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/src"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
export HOME="$WORK/home"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[package]
name = "selected-cache"
version = "0.1.0"
edition = "2024"
EOF
cat >"$WORK/project/Cargo.lock" <<'EOF'
version = 4
[[package]]
name = "selected-cache"
version = "0.1.0"
EOF
printf 'fn unused_cache_warning() {}\npub fn value() -> u8 { 42 }\n' >"$WORK/project/src/lib.rs"
printf 'fn main() { assert_eq!(selected_cache::value(), 42); }\n' \
    >"$WORK/project/src/main.rs"

(
    cd "$WORK/project"
    "$LORRY" --verbose build >"$WORK/first.log" 2>&1
    rg -Fq 'function `unused_cache_warning` is never used' "$WORK/first.log"
    test -f target/lorry/debug/selected-cache
    test -d target/lorry/.cache/v1/units/sha256
    rm -rf target/lorry/debug
    "$LORRY" --verbose build >"$WORK/second.log" 2>&1
    rg -Fq 'Fresh selected-cache v0.1.0 (verified Lorry cache)' "$WORK/second.log"
    rg -Fq 'function `unused_cache_warning` is never used' "$WORK/second.log"
    "$LORRY" --quiet build >"$WORK/profile-human.log" 2>&1
    rg -Fq 'function `unused_cache_warning` is never used' "$WORK/profile-human.log"
    for format in json json-diagnostic-rendered-ansi; do
        "$LORRY" --quiet build --message-format="$format" >"$WORK/profile-$format.json"
        rg -F '"reason":"compiler-message"' "$WORK/profile-$format.json" | \
            rg -Fq 'function `unused_cache_warning` is never used'
        if rg -F '"reason":"compiler-artifact"' "$WORK/profile-$format.json" | rg -Fq '"fresh":false'; then
            echo 'selected-cache-contract: cached profile rebuilt a compiler unit' >&2
            exit 1
        fi
    done
    "$LORRY" --quiet test --no-run --message-format=json >"$WORK/tests-cold.json"
    "$LORRY" --quiet test --no-run --message-format=json >"$WORK/tests-fresh.json"
    for transcript in "$WORK/tests-cold.json" "$WORK/tests-fresh.json"; do
        rg -F '"reason":"compiler-message"' "$transcript" | \
            rg -Fq 'function `unused_cache_warning` is never used'
    done
    if rg -F '"reason":"compiler-artifact"' "$WORK/tests-fresh.json" | rg -Fq '"fresh":false'; then
        echo 'selected-cache-contract: repeated test rebuilt a fresh compiler unit' >&2
        exit 1
    fi
    target/lorry/debug/selected-cache
)
echo "PASS: selected library is restored from its verified local unit cache"
