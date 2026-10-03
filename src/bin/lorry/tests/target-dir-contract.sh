#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: target-dir-contract.sh LORRY" >&2
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
WORK="$(mktemp -d /tmp/lorry-target-dir-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/.cargo" "$WORK/project/app/src"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
export HOME="$WORK/home"
cat >"$WORK/project/Cargo.toml" <<'EOF'
[workspace]
members = ["app"]
resolver = "2"
EOF
cat >"$WORK/project/Cargo.lock" <<'EOF'
version = 4
[[package]]
name = "app"
version = "0.1.0"
EOF
cat >"$WORK/project/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version = "0.1.0"
edition = "2024"
EOF
printf 'fn main() { println!("target-dir-ok"); }\n' \
    >"$WORK/project/app/src/main.rs"
printf '[build]\ntarget-dir = "configured"\n' \
    >"$WORK/project/.cargo/config.toml"

(
    cd "$WORK/project/app"
    "$LORRY" build
    test -f "$WORK/project/configured/lorry/packages/app/debug/app"
    CARGO_TARGET_DIR=env-output "$LORRY" build
    test -f "$WORK/project/app/env-output/lorry/packages/app/debug/app"
    CARGO_TARGET_DIR=env-output "$LORRY" build --target-dir cli-output
    test -f "$WORK/project/app/cli-output/lorry/packages/app/debug/app"
    CARGO_TARGET_DIR=env-output "$LORRY" run --target-dir cli-output \
        >"$WORK/run.out"
    test "$(cat "$WORK/run.out")" = target-dir-ok
    CARGO_TARGET_DIR=env-output "$LORRY" test --target-dir cli-output --no-run \
        >"$WORK/test.out"
    test -s "$WORK/test.out"
    CARGO_TARGET_DIR=env-output "$LORRY" check --target-dir check-output
    test -d "$WORK/project/app/check-output/lorry/packages/app/check"
    CARGO_TARGET_DIR=env-output "$LORRY" clean --target-dir cli-output
    test ! -e "$WORK/project/app/cli-output/lorry/packages/app"
    test -f "$WORK/project/app/cli-output/.lorry-artifacts.lock"
    test -f "$WORK/project/app/env-output/lorry/packages/app/debug/app"
)
echo "PASS: CLI, environment, and Cargo config choose target directories like Cargo"
