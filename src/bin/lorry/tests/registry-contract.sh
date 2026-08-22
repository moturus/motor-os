#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$LORRY_DIR/../../.." && pwd)"
BOOTSTRAP="$LORRY_DIR/bootstrap"
CURL_DIR="$ROOT_DIR/src/bin/curl"
MOTO_RT_DIR="$ROOT_DIR/src/sys/lib/moto-rt"
CACHE_CURL_SOURCE="$SCRIPT_DIR/helpers/cache-curl.rs"
BUILD_REPOSITORY="$ROOT_DIR/build/lorry/stage2/system-seed"
DOWNLOAD_CACHE="$ROOT_DIR/build/lorry/stage2/download-cache"

WORK="$(mktemp -d /tmp/lorry-registry-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "registry-contract: $*" >&2
    exit 1
}

require_program() {
    type -P "$1" || fail "required program '$1' was not found"
}

if [ "$#" -ne 1 ]; then
    echo "usage: registry-contract.sh LORRY" >&2
    exit 1
fi
LORRY="$(realpath "$1")"

PYTHON="$(require_program python3)"
CLANG="$(require_program clang)"
AR="$(require_program ar)"
RUSTC="$(rustup which rustc --toolchain nightly-2026-06-19)"
HOST_CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"

echo "== Preparing the fail-closed Cargo-cache crates.io fixture =="
"$RUSTC" --edition=2024 -D warnings -O "$CACHE_CURL_SOURCE" \
    -o "$WORK/lorry-cache-curl"
"$WORK/lorry-cache-curl" prepare "$HOST_CARGO_HOME" \
    "$DOWNLOAD_CACHE/archives" "$WORK/crates-io" "$CURL_DIR/Cargo.lock"
set +e
"$WORK/crates-io/curl" --url https://example.com/denied \
    --write-out 'LORRY-CURL-1 00000000000000000000000000000000' \
    --output - >"$WORK/denied.out" 2>"$WORK/denied.err"
denied_status="$?"
set -e
[ "$denied_status" -eq 22 ] ||
    fail "cache fixture did not reject a non-crates.io URL with status 22"
grep -F 'request for non-crates.io URL' "$WORK/denied.err" >/dev/null ||
    fail "cache fixture did not diagnose the rejected external URL"

install_minimal_seed() {
    local prefix="$1"
    local home_dir="$WORK/$prefix/home"
    mkdir -p "$WORK/$prefix/image" "$home_dir"
    shift
    "$PYTHON" "$BOOTSTRAP/install_stage2_seed.py" \
        --manifest "$BOOTSTRAP/stage2-seed.toml" \
        --build-repository "$BUILD_REPOSITORY" \
        --host-repository "$home_dir/.config/lorry/system/vendor" \
        --host-user-repository "$home_dir/.config/lorry/vendor" \
        --host-config "$home_dir/.config/lorry/lorry.toml" \
        --image-repository "$WORK/$prefix/image/vendor" \
        --motor-config "$WORK/$prefix/image/lorry.toml" \
        --cache "$DOWNLOAD_CACHE" \
        --mode minimal \
        --host-c-compiler "$CLANG" \
        --host-archiver "$AR" --offline "$@"
}

stage_project() {
    local source_root="$1"
    local project="$source_root/src/bin/curl"
    mkdir -p "$project" "$source_root/src/sys/lib/moto-rt"
    cp "$CURL_DIR/Cargo.toml" "$CURL_DIR/Cargo.lock" "$project/"
    cp -R "$CURL_DIR/src" "$project/src"
    cp "$MOTO_RT_DIR/Cargo.toml" "$MOTO_RT_DIR/LICENSE-APACHE" \
        "$MOTO_RT_DIR/LICENSE-MIT" "$MOTO_RT_DIR/README.md" \
        "$source_root/src/sys/lib/moto-rt/"
    cp -R "$MOTO_RT_DIR/src" "$source_root/src/sys/lib/moto-rt/src"
}

FIRST_HOME="$WORK/first/home"
FIRST_CONFIG="$FIRST_HOME/.config/lorry/lorry.toml"
FIRST_SYSTEM_REPOSITORY="$FIRST_HOME/.config/lorry/system/vendor"
FIRST_USER_REPOSITORY="$FIRST_HOME/.config/lorry/vendor"

echo "== Creating the first reviewed patched-source system seed =="
install_minimal_seed first
stage_project "$WORK/first/source"
FIRST_PROJECT="$WORK/first/source/src/bin/curl"
cp "$FIRST_PROJECT/Cargo.lock" "$WORK/expected-Cargo.lock"

printf '\n[network]\ncurl = "%s"\n' "$WORK/crates-io/curl" >>"$FIRST_CONFIG"
echo "== Vendoring the curl graph from the Cargo-cache crates.io fixture =="
if ! (
    cd "$FIRST_PROJECT"
    HOME="$FIRST_HOME" CARGO_HOME="$WORK/cargo-home" RUSTC="$RUSTC" \
        "$LORRY" vendor --accept-all
) >"$WORK/fresh.log" 2>&1; then
    cat "$WORK/fresh.log" >&2
    fail "fresh acquisition failed"
fi
mapfile -t approved_counts < <(
    sed -n 's/^New crates\.io packages (\([1-9][0-9]*\)):$/\1/p' \
        "$WORK/fresh.log"
)
[ "${#approved_counts[@]}" -eq 1 ] ||
    fail "fresh acquisition did not approve one nonempty registry package set"
expected_objects="${approved_counts[0]}"
cmp "$WORK/expected-Cargo.lock" "$FIRST_PROJECT/Cargo.lock" ||
    fail "fresh acquisition changed the reviewed curl lockfile"

FIRST_OBJECT_ROOT="$FIRST_USER_REPOSITORY/objects/crates-io/sha256"
object_count="$(
    find "$FIRST_OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l
)"
[ "$object_count" -eq "$expected_objects" ] ||
    fail "fresh acquisition approved $expected_objects packages but published $object_count objects"
[ ! -d "$FIRST_SYSTEM_REPOSITORY/objects/crates-io" ] ||
    [ -z "$(find "$FIRST_SYSTEM_REPOSITORY/objects/crates-io" -type f -print -quit)" ] ||
    fail "minimal system seed unexpectedly contains a registry object"
[ ! -d "$FIRST_USER_REPOSITORY/.staging" ] ||
    [ -z "$(find "$FIRST_USER_REPOSITORY/.staging" -mindepth 1 -print -quit)" ] ||
    fail "fresh acquisition left private transaction staging behind"
WARM_ARGUMENTS="$WORK/warm-curl-arguments"
WARM_CURL="$WORK/warm-curl"
printf '%s\n' \
    '#!/bin/sh' \
    "printf '%s\\n' \"\$@\" >> \"$WARM_ARGUMENTS\"" \
    "exec \"$WORK/crates-io/curl\" \"\$@\"" >"$WARM_CURL"
chmod 700 "$WARM_CURL"
sed -i "s|curl = \"$WORK/crates-io/curl\"|curl = \"$WARM_CURL\"|" \
    "$FIRST_CONFIG"
echo "== Proving warm reuse without archive downloads =="
if ! (
    cd "$FIRST_PROJECT"
    HOME="$FIRST_HOME" CARGO_HOME="$WORK/cargo-home" RUSTC="$RUSTC" \
        "$LORRY" vendor --accept-all
) >"$WORK/warm.log" 2>&1; then
    cat "$WORK/warm.log" >&2
    fail "warm acquisition failed"
fi
grep -F "Verified Cargo.lock" "$WORK/warm.log" >/dev/null ||
    fail "warm acquisition did not verify the existing lockfile"
if grep -F "https://static.crates.io/" "$WARM_ARGUMENTS" >/dev/null; then
    fail "warm acquisition attempted to download a selected archive"
fi
[ "$(
    find "$FIRST_OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l
)" -eq "$expected_objects" ] || fail "warm acquisition changed the registry object set"

echo
echo "PASS: cached crates.io acquisition published and reused verified objects"
