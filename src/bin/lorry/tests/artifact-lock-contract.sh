#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: artifact-lock-contract.sh LORRY" >&2
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
WORK="$(mktemp -d /tmp/lorry-artifact-lock-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home/.config/lorry" "$WORK/src" "$WORK/tests"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
export HOME="$WORK/home"
cat >"$WORK/Cargo.toml" <<'EOF'
[package]
name = "artifact-lock-fixture"
version = "0.1.0"
edition = "2024"
EOF
cat >"$WORK/Cargo.lock" <<'EOF'
version = 4
[[package]]
name = "artifact-lock-fixture"
version = "0.1.0"
EOF
cat >"$WORK/src/main.rs" <<'EOF'
fn main() {
    let lorry = std::env::var_os("LORRY_NESTED").unwrap();
    assert!(std::process::Command::new(lorry).arg("build").status().unwrap().success());
}
EOF
cat >"$WORK/tests/integration.rs" <<'EOF'
#[test]
fn starts_another_build() {
    let lorry = std::env::var_os("LORRY_NESTED").unwrap();
    assert!(std::process::Command::new(lorry).arg("build").status().unwrap().success());
}
EOF

(
    cd "$WORK"
    LORRY_NESTED="$LORRY" timeout 90 "$LORRY" run
    LORRY_NESTED="$LORRY" timeout 90 "$LORRY" test --test integration
    test -f target/.lorry-artifacts.lock
    "$LORRY" clean
    test -f target/.lorry-artifacts.lock
    test ! -e target/lorry
)
echo "PASS: artifact lock is released before programs and tests and survives clean"
