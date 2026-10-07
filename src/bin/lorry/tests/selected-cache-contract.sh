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
    grep -Fq 'function `unused_cache_warning` is never used' "$WORK/first.log"
    test -f target/lorry/debug/selected-cache
    test -d target/lorry/.cache/v1/units/sha256
    rm -rf target/lorry/debug
    "$LORRY" --verbose build >"$WORK/second.log" 2>&1
    grep -Fq 'Fresh selected-cache v0.1.0 (verified Lorry cache)' "$WORK/second.log"
    grep -Fq 'function `unused_cache_warning` is never used' "$WORK/second.log"
    "$LORRY" --quiet build >"$WORK/profile-human.log" 2>&1
    grep -Fq 'function `unused_cache_warning` is never used' "$WORK/profile-human.log"
    for format in json json-diagnostic-rendered-ansi; do
        "$LORRY" --quiet build --message-format="$format" >"$WORK/profile-$format.json"
        grep -F '"reason":"compiler-message"' "$WORK/profile-$format.json" | \
            grep -F 'function `unused_cache_warning` is never used' >/dev/null
        if grep -F '"reason":"compiler-artifact"' "$WORK/profile-$format.json" | grep -F '"fresh":false' >/dev/null; then
            echo 'selected-cache-contract: cached profile rebuilt a compiler unit' >&2
            exit 1
        fi
    done
    "$LORRY" --quiet test --no-run --message-format=json >"$WORK/tests-cold.json"
    "$LORRY" --quiet test --no-run --message-format=json >"$WORK/tests-fresh.json"
    for transcript in "$WORK/tests-cold.json" "$WORK/tests-fresh.json"; do
        grep -F '"reason":"compiler-message"' "$transcript" | \
            grep -F 'function `unused_cache_warning` is never used' >/dev/null
    done
    if grep -F '"reason":"compiler-artifact"' "$WORK/tests-fresh.json" | grep -F '"fresh":false' >/dev/null; then
        echo 'selected-cache-contract: repeated test rebuilt a fresh compiler unit' >&2
        exit 1
    fi
    target/lorry/debug/selected-cache
)
echo "PASS: selected library is restored from its verified local unit cache"

echo "== Reusing workspace admission without starting build-time code =="
mkdir -p "$WORK/helper/src"
cat >"$WORK/helper/Cargo.toml" <<'EOF'
[package]
name = "cache-helper"
version = "0.1.0"
edition = "2024"
EOF
printf 'pub fn value() {}\n' >"$WORK/helper/src/lib.rs"
cat >"$WORK/helper/build.rs" <<'EOF'
use std::io::Write;
fn main() {
    std::fs::OpenOptions::new().create(true).append(true)
        .open(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("script-runs"))
        .unwrap().write_all(b"x").unwrap();
}
EOF
cat >>"$WORK/project/Cargo.toml" <<'EOF'
[dependencies]
cache-helper = { path = "../helper" }
EOF
cat >>"$HOME/.config/lorry/lorry.toml" <<'EOF'
[policy.rules.allow-helper-script]
action = "allow"
name = "cache-helper"
version = "=0.1.0"
source = "path"
allow-build-script = true
EOF
(
    cd "$WORK/project"
    RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" generate-lockfile --offline
    "$LORRY" vendor --accept-all >"$WORK/vendor.out" 2>"$WORK/vendor.err"
    test -z "$(find target/lorry -name script-runs -print)"
    "$LORRY" --quiet build
    counter="$(find target/lorry/debug/build/cache-helper -name script-runs -print)"
    test "$(cat "$counter")" = x
    "$LORRY" --quiet build --message-format=json >"$WORK/admitted-fresh.json"
    test "$(cat "$counter")" = x
    if grep -F '"reason":"compiler-artifact"' "$WORK/admitted-fresh.json" | grep -F '"fresh":false' >/dev/null; then
        echo 'selected-cache-contract: admitted profile rebuilt a compiler unit' >&2
        exit 1
    fi
    "$LORRY" --quiet run >"$WORK/admitted-run.out"
    test "$(cat "$counter")" = x
    "$LORRY" --quiet run >"$WORK/admitted-fresh-run.out"
    test "$(cat "$counter")" = x
    cmp "$WORK/admitted-run.out" "$WORK/admitted-fresh-run.out"
    sed -i 's/^review-sha256 = ".*"/review-sha256 = "0000000000000000000000000000000000000000000000000000000000000000"/' \
        .lorry/dependencies-v2.toml
    if "$LORRY" --quiet build >"$WORK/stale.out" 2>"$WORK/stale.err"; then
        echo 'selected-cache-contract: cached profile bypassed admission verification' >&2
        exit 1
    fi
    grep -Fq 'workspace admission commitment does not match' "$WORK/stale.err"
    test "$(cat "$counter")" = x
)
echo "PASS: admitted profiles preserve validation and skip build scripts"
