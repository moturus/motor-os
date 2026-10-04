#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY="$(realpath "${1:?usage: fetch-contract.sh LORRY}")"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
WORK="$(mktemp -d /tmp/lorry-fetch-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
HOST_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="$HOST_CARGO_HOME"
export RUSTC="$LORRY_TEST_RUSTC"
mkdir -p "$WORK/home/.config/lorry" "$WORK/project/app/src"
export HOME="$WORK/home"
PROJECT="$WORK/project"
cat >"$PROJECT/Cargo.toml" <<'EOF'
[workspace]
members = ["app"]
resolver = "2"
EOF
cat >"$PROJECT/app/Cargo.toml" <<'EOF'
[package]
name = "app"
version = "1.0.0"
edition = "2021"
[dependencies]
cfg-if = { version = "=1.0.4", optional = true }
[target.'cfg(windows)'.dependencies]
equivalent = "=1.0.2"
EOF
echo 'compile_error!("fetch must never compile this package");' >"$PROJECT/app/src/lib.rs"
"$LORRY_TEST_CARGO" generate-lockfile --manifest-path "$PROJECT/Cargo.toml" --offline
cp "$PROJECT/Cargo.lock" "$WORK/original.lock"
"$RUSTC" --edition=2024 -D warnings -O "$SCRIPT_DIR/helpers/cache-curl.rs" -o "$WORK/cache-curl"
"$WORK/cache-curl" prepare "$HOST_CARGO_HOME" "$WORK/crates-io" "$PROJECT/Cargo.lock"
cat >"$WORK/curl" <<EOF
#!/bin/sh
printf '%s\n' "\$@" >> "$WORK/requests"
exec "$WORK/crates-io/curl" "\$@"
EOF
chmod 0700 "$WORK/curl"
cat >"$HOME/.config/lorry/lorry.toml" <<EOF
config-version = 1
[repositories]
user = "$WORK/repository"
[network]
curl = "$WORK/curl"
[cache]
directory = "$WORK/cache"
[policy]
default = "deny"
EOF
mkdir "$PROJECT/.lorry"
echo 'existing admission bytes' >"$PROJECT/.lorry/dependencies-v2.toml"
cp "$PROJECT/.lorry/dependencies-v2.toml" "$WORK/original.admission"
cd "$PROJECT"
"$LORRY" fetch --locked --target x86_64-unknown-linux-gnu >"$WORK/targeted.out" 2>"$WORK/targeted.err"
grep -F 'Downloading cfg-if v1.0.4' "$WORK/targeted.err"
if grep -F 'https://static.crates.io/crates/equivalent/' "$WORK/requests"; then
    echo 'targeted fetch downloaded an inactive platform archive' >&2
    exit 1
fi
cmp Cargo.lock "$WORK/original.lock"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
"$LORRY" fetch --locked >"$WORK/full.out" 2>"$WORK/full.err"
grep -F 'Downloading equivalent v1.0.2' "$WORK/full.err"
test "$(find "$WORK/repository/objects/crates-io/sha256" -name package.toml | wc -l)" -eq 2
cp "$WORK/requests" "$WORK/requests.before"
"$LORRY" -q fetch --offline --target x86_64-unknown-linux-gnu --target x86_64-pc-windows-gnu >"$WORK/offline.out" 2>"$WORK/offline.err"
test ! -s "$WORK/offline.out"
test ! -s "$WORK/offline.err"
cmp "$WORK/requests" "$WORK/requests.before"
cmp Cargo.lock "$WORK/original.lock"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
cat >>app/Cargo.toml <<'EOF'
[dependencies.semver]
version = "=1.0.27"
EOF
if "$LORRY" --lorry-messages fetch --offline >"$WORK/stale.out" 2>"$WORK/stale.err"; then
    echo 'fetch accepted a stale workspace lock' >&2
    exit 1
fi
grep -F 'Cargo.lock has no crates.io package' "$WORK/stale.err"
cmp Cargo.lock "$WORK/original.lock"
cmp .lorry/dependencies-v2.toml "$WORK/original.admission"
cmp "$WORK/requests" "$WORK/requests.before"
echo 'PASS: hermetic workspace fetch preserves lock and admission without executing code'
