#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: registry-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CACHE_CURL_SOURCE="$SCRIPT_DIR/helpers/cache-curl.rs"
WORK="$(mktemp -d /tmp/lorry-registry-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "registry-contract: $*" >&2
    exit 1
}

RUSTC="$(rustup which rustc --toolchain nightly-2026-06-19)"
HOST_CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
PROJECT="$WORK/project"
HOME_DIR="$WORK/home"
REPOSITORY="$HOME_DIR/.config/lorry/vendor"
CONFIG="$HOME_DIR/.config/lorry/lorry.toml"
mkdir -p "$PROJECT/src" "$HOME_DIR/.config/lorry" \
    "$REPOSITORY/objects/crates-io/sha256" \
    "$REPOSITORY/objects/seeded-git/sha256" "$REPOSITORY/.staging"

cat >"$PROJECT/Cargo.toml" <<'EOF'
[package]
name = "registry-fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
cfg-if = "=1.0.4"
EOF
cat >"$PROJECT/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "cfg-if"
version = "1.0.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801"

[[package]]
name = "registry-fixture"
version = "0.1.0"
dependencies = ["cfg-if"]
EOF
cat >"$PROJECT/src/main.rs" <<'EOF'
fn main() { cfg_if::cfg_if! { if #[cfg(unix)] {} else {} } }
EOF

echo "== Preparing the fail-closed Cargo-cache crates.io fixture =="
"$RUSTC" --edition=2024 -D warnings -O "$CACHE_CURL_SOURCE" \
    -o "$WORK/cache-curl"
"$WORK/cache-curl" prepare "$HOST_CARGO_HOME" \
    "$WORK/archive-cache" "$WORK/crates-io" "$PROJECT/Cargo.lock"
cat >"$CONFIG" <<EOF
config-version = 1

[repositories]
user = "$REPOSITORY"

[network]
curl = "$WORK/crates-io/curl"

[policy]
default = "allow"
EOF
cat >"$REPOSITORY/repository.toml" <<'EOF'
format-version = 1
object-hash = "sha256"
EOF

echo "== Vendoring one exact crates.io package =="
(cd "$PROJECT" && HOME="$HOME_DIR" RUSTC="$RUSTC" \
    "$LORRY" vendor --accept-all) >"$WORK/fresh.log" 2>&1
grep -F "New crates.io packages (1):" "$WORK/fresh.log" >/dev/null || {
    cat "$WORK/fresh.log" >&2
    fail "fresh acquisition did not publish one package"
}
grep -F 'Updating crates.io index for `cfg-if`' "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not report its sparse-index request"
grep -F 'Downloading cfg-if v1.0.4' "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not report its archive request"
grep -F 'Resolving dependency graph' "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not report graph resolution"
grep -F 'Checking dependency repository state' "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not report repository verification"
grep -F 'Verifying selected dependency sources' "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not report source verification"
OBJECT_ROOT="$REPOSITORY/objects/crates-io/sha256"
[ "$(find "$OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l)" -eq 1 ] ||
    fail "fresh acquisition published an unexpected object count"

echo "== Proving warm reuse performs no archive download =="
ARGS="$WORK/warm-curl-arguments"
cat >"$WORK/warm-curl" <<EOF
#!/bin/sh
printf '%s\n' "\$@" >> "$ARGS"
exec "$WORK/crates-io/curl" "\$@"
EOF
chmod 0700 "$WORK/warm-curl"
sed -i "s|$WORK/crates-io/curl|$WORK/warm-curl|" "$CONFIG"
(cd "$PROJECT" && HOME="$HOME_DIR" RUSTC="$RUSTC" \
    "$LORRY" vendor --accept-all) >"$WORK/warm.log" 2>&1
grep -F "Verified Cargo.lock" "$WORK/warm.log" >/dev/null ||
    fail "warm acquisition did not verify Cargo.lock"
if [ -f "$ARGS" ] && grep -F "https://static.crates.io/" "$ARGS" >/dev/null; then
    fail "warm acquisition attempted to download the selected archive"
fi

echo "PASS: cached crates.io acquisition published and reused a verified object"
