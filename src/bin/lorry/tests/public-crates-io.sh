#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$LORRY_DIR/../../.." && pwd)"
BOOTSTRAP="$LORRY_DIR/bootstrap"
CURL_DIR="$ROOT_DIR/src/bin/curl"
MOTO_RT_DIR="$ROOT_DIR/src/sys/lib/moto-rt"

if [ "${LORRY_TEST_PUBLIC_CRATES_IO:-0}" != "1" ]; then
    echo "SKIP: set LORRY_TEST_PUBLIC_CRATES_IO=1 to run public crates.io acquisition"
    exit 0
fi

WORK="$(mktemp -d /tmp/lorry-public-crates-io-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "public-crates-io: $*" >&2
    exit 1
}

require_program() {
    type -P "$1" || fail "required program '$1' was not found"
}

PYTHON="$(require_program python3)"
CLANG="$(require_program clang)"
AR="$(require_program ar)"
CURL="$(require_program curl)"
CARGO="$(rustup which cargo --toolchain nightly-2026-06-19)"
RUSTC="$(rustup which rustc --toolchain nightly-2026-06-19)"
HOST_CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"

echo "== Building the Lorry executable offline =="
CARGO_HOME="$HOST_CARGO_HOME" RUSTC="$RUSTC" "$CARGO" build \
    --manifest-path "$LORRY_DIR/Cargo.toml" \
    --locked --offline --release --target-dir "$WORK/lorry-target"
LORRY="$WORK/lorry-target/release/lorry"

HOME_DIR="$WORK/home"
CONFIG="$HOME_DIR/.config/lorry/lorry.toml"
SYSTEM_REPOSITORY="$HOME_DIR/.config/lorry/system/vendor"
USER_REPOSITORY="$HOME_DIR/.config/lorry/vendor"
mkdir -p "$WORK/seed" "$WORK/image" "$HOME_DIR"

echo "== Creating the reviewed ring-only system seed =="
"$PYTHON" "$BOOTSTRAP/install_stage2_seed.py" \
    --manifest "$BOOTSTRAP/stage2-seed.toml" \
    --build-repository "$WORK/seed/vendor" \
    --host-repository "$SYSTEM_REPOSITORY" \
    --host-user-repository "$USER_REPOSITORY" \
    --host-config "$CONFIG" \
    --image-repository "$WORK/image/vendor" \
    --motor-config "$WORK/image/lorry.toml" \
    --cache "$WORK/download-cache" \
    --mode minimal \
    --host-c-compiler "$CLANG" \
    --host-archiver "$AR"

PROJECT="$WORK/source/src/bin/curl"
mkdir -p "$PROJECT" "$WORK/source/src/sys/lib/moto-rt"
cp "$CURL_DIR/Cargo.toml" "$CURL_DIR/Cargo.lock" "$PROJECT/"
cp -R "$CURL_DIR/src" "$PROJECT/src"
cp "$MOTO_RT_DIR/Cargo.toml" "$MOTO_RT_DIR/LICENSE-APACHE" \
    "$MOTO_RT_DIR/LICENSE-MIT" "$MOTO_RT_DIR/README.md" \
    "$WORK/source/src/sys/lib/moto-rt/"
cp -R "$MOTO_RT_DIR/src" "$WORK/source/src/sys/lib/moto-rt/src"
cp "$PROJECT/Cargo.lock" "$WORK/expected-Cargo.lock"

echo "== Vendoring the curl graph from public crates.io =="
(
    cd "$PROJECT"
    HOME="$HOME_DIR" CARGO_HOME="$WORK/cargo-home" RUSTC="$RUSTC" \
        "$LORRY" vendor --accept-all
) >"$WORK/fresh.log" 2>&1
cat "$WORK/fresh.log"
grep -F "New crates.io packages (14):" "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not approve the expected 14-package graph"
cmp "$WORK/expected-Cargo.lock" "$PROJECT/Cargo.lock" ||
    fail "fresh acquisition changed the reviewed curl lockfile"

OBJECT_ROOT="$USER_REPOSITORY/objects/crates-io/sha256"
object_count="$(
    find "$OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l
)"
[ "$object_count" -eq 14 ] ||
    fail "fresh acquisition published $object_count registry objects instead of 14"
[ ! -d "$SYSTEM_REPOSITORY/objects/crates-io" ] ||
    [ -z "$(find "$SYSTEM_REPOSITORY/objects/crates-io" -type f -print -quit)" ] ||
    fail "minimal system seed unexpectedly contains a registry object"
[ ! -d "$USER_REPOSITORY/.staging" ] ||
    [ -z "$(find "$USER_REPOSITORY/.staging" -mindepth 1 -print -quit)" ] ||
    fail "fresh acquisition left private transaction staging behind"

WARM_ARGUMENTS="$WORK/warm-curl-arguments"
WARM_CURL="$WORK/warm-curl"
printf '%s\n' \
    '#!/bin/sh' \
    "printf '%s\\n' \"\$@\" >> \"$WARM_ARGUMENTS\"" \
    "exec \"$CURL\" \"\$@\"" >"$WARM_CURL"
chmod 700 "$WARM_CURL"
printf '\n[network]\ncurl = "%s"\n' "$WARM_CURL" >>"$CONFIG"
echo "== Proving warm reuse without archive downloads =="
(
    cd "$PROJECT"
    HOME="$HOME_DIR" CARGO_HOME="$WORK/cargo-home" RUSTC="$RUSTC" \
        "$LORRY" vendor --accept-all
) >"$WORK/warm.log" 2>&1
cat "$WORK/warm.log"
grep -F "Verified Cargo.lock" "$WORK/warm.log" >/dev/null ||
    fail "warm acquisition did not verify the existing lockfile"
if grep -F "https://static.crates.io/" "$WARM_ARGUMENTS" >/dev/null; then
    fail "warm acquisition attempted to download a selected archive"
fi
[ "$(
    find "$OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l
)" -eq 14 ] || fail "warm acquisition changed the registry object set"

echo
echo "PASS: fresh public crates.io acquisition and warm archive reuse passed"
