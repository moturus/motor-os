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
export CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
WORK="$(mktemp -d /tmp/lorry-target-dir-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/.cargo" "$WORK/project/app/src"
printf 'config-version = 1\nuse-cargo-registry = false\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
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
    test -f "$WORK/project/configured/lorry/debug/app"
    CARGO_TARGET_DIR=env-output "$LORRY" build
    test -f "$WORK/project/app/env-output/lorry/debug/app"
    CARGO_TARGET_DIR=env-output "$LORRY" build --target-dir cli-output
    test -f "$WORK/project/app/cli-output/lorry/debug/app"
    CARGO_TARGET_DIR=env-output "$LORRY" run --target-dir cli-output \
        >"$WORK/run.out"
    test "$(cat "$WORK/run.out")" = target-dir-ok
    CARGO_TARGET_DIR=env-output "$LORRY" test --target-dir cli-output --no-run \
        >"$WORK/test.out"
    test -s "$WORK/test.out"
    CARGO_TARGET_DIR=env-output "$LORRY" check --target-dir check-output
    test -d "$WORK/project/app/check-output/lorry/check"
    CARGO_TARGET_DIR=env-output "$LORRY" clean --target-dir cli-output
    test ! -e "$WORK/project/app/cli-output/lorry"
    test -f "$WORK/project/app/cli-output/.lorry-artifacts.lock"
    test -f "$WORK/project/app/env-output/lorry/debug/app"
)
mkdir "$WORK/project/app/.cargo"
printf '[build]\ntarget-dir = "member-configured"\n[alias]\nagent-build = ["build", "-p", "app"]\n' \
    >"$WORK/project/app/.cargo/config.toml"
(
    cd "$WORK/project"
    "$LORRY" build -p app
    "$LORRY_TEST_CARGO" build --offline -p app
    test -f configured/lorry/debug/app
    test -f configured/debug/app
    test ! -e app/member-configured
    "$LORRY" check --manifest-path app/Cargo.toml --bin app
    "$LORRY_TEST_CARGO" check --offline --manifest-path app/Cargo.toml --bin app
    test -d configured/lorry/check
    test ! -e app/member-configured
)
(
    cd "$WORK/project/app"
    "$LORRY" build
    "$LORRY_TEST_CARGO" build --offline
    test -f member-configured/lorry/debug/app
    test -f member-configured/debug/app
    if "$LORRY" agent-build >"$WORK/alias.out" 2>"$WORK/alias.err"; then
        echo "target-dir-contract: executed a Cargo alias" >&2
        exit 1
    fi
)
printf 'config-version = 1\nuse-cargo-registry = false\n' >"$WORK/project/app/lorry.toml"
if (cd "$WORK/project" && "$LORRY" build -p app) 2>"$WORK/member-config.err"; then
    echo "target-dir-contract: accepted member-local project configuration" >&2
    exit 1
fi
grep -F "$WORK/project/app/lorry.toml" "$WORK/member-config.err" >/dev/null
grep -F "move project settings to \`$WORK/project/lorry.toml\`" "$WORK/member-config.err" >/dev/null
mv "$WORK/project/app/lorry.toml" "$WORK/project/lorry.toml"
(cd "$WORK/project" && "$LORRY" build -p app)
echo "PASS: CLI, environment, and Cargo config choose target directories like Cargo"
