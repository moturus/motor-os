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

install_minimal_seed() {
    local prefix="$1"
    local home_dir="$WORK/$prefix/home"
    mkdir -p "$WORK/seed" "$WORK/$prefix/image" "$home_dir"
    shift
    "$PYTHON" "$BOOTSTRAP/install_stage2_seed.py" \
        --manifest "$BOOTSTRAP/stage2-seed.toml" \
        --build-repository "$WORK/seed/vendor" \
        --host-repository "$home_dir/.config/lorry/system/vendor" \
        --host-user-repository "$home_dir/.config/lorry/vendor" \
        --host-config "$home_dir/.config/lorry/lorry.toml" \
        --image-repository "$WORK/$prefix/image/vendor" \
        --motor-config "$WORK/$prefix/image/lorry.toml" \
        --cache "$WORK/download-cache" \
        --mode minimal \
        --host-c-compiler "$CLANG" \
        --host-archiver "$AR" "$@"
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

echo "== Creating the first reviewed ring-only system seed =="
install_minimal_seed first
stage_project "$WORK/first/source"
FIRST_PROJECT="$WORK/first/source/src/bin/curl"
cp "$FIRST_PROJECT/Cargo.lock" "$WORK/expected-Cargo.lock"

echo "== Vendoring the curl graph from public crates.io =="
(
    cd "$FIRST_PROJECT"
    HOME="$FIRST_HOME" CARGO_HOME="$WORK/cargo-home" RUSTC="$RUSTC" \
        "$LORRY" vendor --accept-all
) >"$WORK/fresh.log" 2>&1
cat "$WORK/fresh.log"
grep -F "New crates.io packages (14):" "$WORK/fresh.log" >/dev/null ||
    fail "fresh acquisition did not approve the expected 14-package graph"
cmp "$WORK/expected-Cargo.lock" "$FIRST_PROJECT/Cargo.lock" ||
    fail "fresh acquisition changed the reviewed curl lockfile"

FIRST_OBJECT_ROOT="$FIRST_USER_REPOSITORY/objects/crates-io/sha256"
object_count="$(
    find "$FIRST_OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l
)"
[ "$object_count" -eq 14 ] ||
    fail "fresh acquisition published $object_count registry objects instead of 14"
[ ! -d "$FIRST_SYSTEM_REPOSITORY/objects/crates-io" ] ||
    [ -z "$(find "$FIRST_SYSTEM_REPOSITORY/objects/crates-io" -type f -print -quit)" ] ||
    fail "minimal system seed unexpectedly contains a registry object"
[ ! -d "$FIRST_USER_REPOSITORY/.staging" ] ||
    [ -z "$(find "$FIRST_USER_REPOSITORY/.staging" -mindepth 1 -print -quit)" ] ||
    fail "fresh acquisition left private transaction staging behind"
find "$FIRST_OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d -printf '%P\n' |
    sort >"$WORK/first-objects"

WARM_ARGUMENTS="$WORK/warm-curl-arguments"
WARM_CURL="$WORK/warm-curl"
printf '%s\n' \
    '#!/bin/sh' \
    "printf '%s\\n' \"\$@\" >> \"$WARM_ARGUMENTS\"" \
    "exec \"$CURL\" \"\$@\"" >"$WARM_CURL"
chmod 700 "$WARM_CURL"
printf '\n[network]\ncurl = "%s"\n' "$WARM_CURL" >>"$FIRST_CONFIG"
echo "== Proving warm reuse without archive downloads =="
(
    cd "$FIRST_PROJECT"
    HOME="$FIRST_HOME" CARGO_HOME="$WORK/cargo-home" RUSTC="$RUSTC" \
        "$LORRY" vendor --accept-all
) >"$WORK/warm.log" 2>&1
cat "$WORK/warm.log"
grep -F "Verified Cargo.lock" "$WORK/warm.log" >/dev/null ||
    fail "warm acquisition did not verify the existing lockfile"
if grep -F "https://static.crates.io/" "$WARM_ARGUMENTS" >/dev/null; then
    fail "warm acquisition attempted to download a selected archive"
fi
[ "$(
    find "$FIRST_OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l
)" -eq 14 ] || fail "warm acquisition changed the registry object set"

echo "== Building curl from the first writable repository =="
(
    cd "$FIRST_PROJECT"
    HOME="$FIRST_HOME" CARGO_HOME="$WORK/cargo-home" RUSTC="$RUSTC" \
        "$LORRY" build --release
)
FIRST_CURL="$FIRST_PROJECT/target/lorry/release/curl"
[ -x "$FIRST_CURL" ] || fail "first Lorry build did not produce curl"
"$FIRST_CURL" --version | grep -F "curl 0.1.0 (Motor OS) rustls" >/dev/null ||
    fail "first Lorry build did not identify as Motor curl"

SECOND_HOME="$WORK/second/home"
SECOND_CONFIG="$SECOND_HOME/.config/lorry/lorry.toml"
SECOND_SYSTEM_REPOSITORY="$SECOND_HOME/.config/lorry/system/vendor"
SECOND_USER_REPOSITORY="$SECOND_HOME/.config/lorry/vendor"

echo "== Creating a second fresh ring-only seed and writable repository =="
install_minimal_seed second --offline
printf '\n[network]\ncurl = "%s"\n' "$FIRST_CURL" >>"$SECOND_CONFIG"
stage_project "$WORK/second/source"
SECOND_PROJECT="$WORK/second/source/src/bin/curl"

echo "== Vendoring the second curl graph through the Lorry-built curl =="
(
    cd "$SECOND_PROJECT"
    HOME="$SECOND_HOME" CARGO_HOME="$WORK/cargo-home" RUSTC="$RUSTC" \
        "$LORRY" vendor --accept-all
) >"$WORK/second-fresh.log" 2>&1
cat "$WORK/second-fresh.log"
grep -F "New crates.io packages (14):" "$WORK/second-fresh.log" >/dev/null ||
    fail "second fresh acquisition did not approve the expected 14-package graph"
cmp "$WORK/expected-Cargo.lock" "$SECOND_PROJECT/Cargo.lock" ||
    fail "second fresh acquisition changed the reviewed curl lockfile"

SECOND_OBJECT_ROOT="$SECOND_USER_REPOSITORY/objects/crates-io/sha256"
[ "$(
    find "$SECOND_OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l
)" -eq 14 ] || fail "second fresh acquisition did not publish 14 registry objects"
[ ! -d "$SECOND_SYSTEM_REPOSITORY/objects/crates-io" ] ||
    [ -z "$(find "$SECOND_SYSTEM_REPOSITORY/objects/crates-io" -type f -print -quit)" ] ||
    fail "second minimal system seed unexpectedly contains a registry object"
[ ! -d "$SECOND_USER_REPOSITORY/.staging" ] ||
    [ -z "$(find "$SECOND_USER_REPOSITORY/.staging" -mindepth 1 -print -quit)" ] ||
    fail "second fresh acquisition left private transaction staging behind"
find "$SECOND_OBJECT_ROOT" -mindepth 2 -maxdepth 2 -type d -printf '%P\n' |
    sort >"$WORK/second-objects"
cmp "$WORK/first-objects" "$WORK/second-objects" ||
    fail "the two writable repositories contain different registry objects"

echo "== Rebuilding curl solely from the second writable repository =="
(
    cd "$SECOND_PROJECT"
    HOME="$SECOND_HOME" CARGO_HOME="$WORK/cargo-home" RUSTC="$RUSTC" \
        "$LORRY" build --release
)
SECOND_CURL="$SECOND_PROJECT/target/lorry/release/curl"
[ -x "$SECOND_CURL" ] || fail "second Lorry build did not produce curl"
cmp "$FIRST_CURL" "$SECOND_CURL" ||
    fail "first- and second-repository curl executables differ"

echo
echo "PASS: Lorry-built curl populated a second repository and rebuilt identically"
