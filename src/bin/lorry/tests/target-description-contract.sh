#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: target-description-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
WORK="$(mktemp -d /tmp/lorry-target-description-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
mkdir -p "$WORK/home/.config/lorry" "$WORK/app/src" "$WORK/dep/src" "$WORK/dep/tests"
printf 'config-version = 1\nuse-cargo-registry = false\n[cache]\ndirectory = "%s"\n' "$WORK/cache" \
    >"$WORK/home/.config/lorry/lorry.toml"
export HOME="$WORK/home"
cat >"$WORK/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version = "0.1.0"
edition = "2024"
[dependencies]
dep = { path = "../dep" }
EOF
cat >"$WORK/dep/Cargo.toml" <<'EOF'
[package]
name = "dep"
version = "0.1.0"
edition = "2024"
EOF
cat >"$WORK/app/Cargo.lock" <<'EOF'
version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["dep"]
[[package]]
name = "dep"
version = "0.1.0"
EOF
printf 'fn main() {}\n' >"$WORK/app/src/main.rs"
printf 'pub fn answer() -> u32 { 42 }\n' >"$WORK/dep/src/lib.rs"

for number in $(seq -w 1 1024); do
    printf '#[test] fn sample() {}\n' >"$WORK/dep/tests/case$number.rs"
done
"$LORRY" metadata --format-version 1 --locked \
    --manifest-path "$WORK/app/Cargo.toml" >"$WORK/metadata.json"

printf '#[test] fn sample() {}\n' >"$WORK/dep/tests/overflow.rs"
if "$LORRY" metadata --format-version 1 --locked \
    --manifest-path "$WORK/app/Cargo.toml" >"$WORK/overflow.json" \
    2>"$WORK/overflow.err"; then
    echo "target-description-contract: accepted 1,025 dependency tests" >&2
    exit 1
fi
grep -F 'more than 1024 integration-test targets' "$WORK/overflow.err" >/dev/null
echo 'PASS: dependency target descriptions allow 1,024 tests'
