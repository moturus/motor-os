#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$LORRY_DIR/../../.." && pwd)"
BOOTSTRAP="$LORRY_DIR/bootstrap"
CURL_DIR="$ROOT_DIR/src/bin/curl"
MOTO_RT_DIR="$ROOT_DIR/src/sys/lib/moto-rt"
BUILD_REPOSITORY="$ROOT_DIR/build/lorry/stage2/system-seed"
DOWNLOAD_CACHE="$ROOT_DIR/build/lorry/stage2/download-cache"

TEST_PROFILE=()
case "${1:-}" in
    "") ;;
    --release) TEST_PROFILE=(--release) ;;
    *)
        echo "usage: curl-contract-linux.sh [--release]" >&2
        exit 1
        ;;
esac

WORK="$(mktemp -d /tmp/lorry-curl-contract-linux-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "curl-contract-linux: $*" >&2
    exit 1
}

require_program() {
    type -P "$1" || fail "required program '$1' was not found"
}

[ -d "$BUILD_REPOSITORY/objects" ] ||
    fail "Stage 2 system seed is missing; run the repository build first"
[ -d "$DOWNLOAD_CACHE" ] ||
    fail "Stage 2 download cache is missing; run the repository build first"

PYTHON="$(require_program python3)"
CLANG="$(require_program clang)"
AR="$(require_program ar)"
CARGO="$(rustup which cargo --toolchain nightly-2026-06-19)"
RUSTC="$(rustup which rustc --toolchain nightly-2026-06-19)"
HOST_CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"

echo "== Building the Lorry acceptance executable offline =="
CARGO_HOME="$HOST_CARGO_HOME" RUSTC="$RUSTC" "$CARGO" build \
    --manifest-path "$LORRY_DIR/Cargo.toml" \
    --locked --offline --release
LORRY="$LORRY_DIR/target/release/lorry"

HOME_DIR="$WORK/home"
CONFIG="$HOME_DIR/.config/lorry/lorry.toml"
SYSTEM_REPOSITORY="$HOME_DIR/.config/lorry/system/vendor"
USER_REPOSITORY="$HOME_DIR/.config/lorry/vendor"
mkdir -p "$WORK/image" "$HOME_DIR"

echo "== Installing an isolated copy of the reviewed full seed =="
"$PYTHON" "$BOOTSTRAP/install_stage2_seed.py" \
    --manifest "$BOOTSTRAP/stage2-seed.toml" \
    --build-repository "$BUILD_REPOSITORY" \
    --host-repository "$SYSTEM_REPOSITORY" \
    --host-user-repository "$USER_REPOSITORY" \
    --host-config "$CONFIG" \
    --image-repository "$WORK/image/vendor" \
    --motor-config "$WORK/image/lorry.toml" \
    --cache "$DOWNLOAD_CACHE" \
    --mode full --offline \
    --host-c-compiler "$CLANG" \
    --host-archiver "$AR"

PROJECT="$WORK/source/src/bin/curl"
mkdir -p "$PROJECT" "$WORK/source/src/sys/lib/moto-rt" \
    "$WORK/source/img_files/motor-os/sys/cfg/ssl"
cp "$CURL_DIR/Cargo.toml" "$CURL_DIR/Cargo.lock" "$PROJECT/"
cp -R "$CURL_DIR/src" "$PROJECT/src"
cp -R "$CURL_DIR/tests" "$PROJECT/tests"
cp "$MOTO_RT_DIR/Cargo.toml" "$MOTO_RT_DIR/LICENSE-APACHE" \
    "$MOTO_RT_DIR/LICENSE-MIT" "$MOTO_RT_DIR/README.md" \
    "$WORK/source/src/sys/lib/moto-rt/"
cp -R "$MOTO_RT_DIR/src" "$WORK/source/src/sys/lib/moto-rt/src"
cp "$ROOT_DIR/img_files/motor-os/sys/cfg/ssl/ssl-cert.pem" \
    "$WORK/source/img_files/motor-os/sys/cfg/ssl/ssl-cert.pem"
cp "$PROJECT/Cargo.lock" "$WORK/expected-Cargo.lock"

echo "== Building Motor curl with Lorry =="
(
    cd "$PROJECT"
    HOME="$HOME_DIR" CARGO_HOME="$WORK/cargo-home" RUSTC="$RUSTC" \
        "$LORRY" test --release --no-run
)
cmp "$WORK/expected-Cargo.lock" "$PROJECT/Cargo.lock" ||
    fail "building curl changed the reviewed lockfile"
BUILT_CURL="$PROJECT/target/lorry/release/curl"
[ -x "$BUILT_CURL" ] || fail "Lorry did not produce an executable curl"
"$BUILT_CURL" --version | grep -F "curl 0.1.0 (Motor OS) rustls" >/dev/null ||
    fail "Lorry-built executable did not identify as Motor curl"
TLS_SERVER=""
for candidate in "$PROJECT"/target/lorry/release/deps/https-*; do
    [ -f "$candidate" ] && [ -x "$candidate" ] || continue
    [ -z "$TLS_SERVER" ] || fail "Lorry produced multiple HTTPS test executables"
    TLS_SERVER="$candidate"
done
[ -n "$TLS_SERVER" ] || fail "Lorry did not produce the HTTPS test executable"

echo "== Running Lorry's production request boundary through that curl =="
LORRY_TEST_CURL="$BUILT_CURL" \
    LORRY_TEST_CA="$PROJECT/tests/test-ca.pem" \
    LORRY_TEST_UNTRUSTED_CA="$WORK/source/img_files/motor-os/sys/cfg/ssl/ssl-cert.pem" \
    LORRY_TEST_TLS_SERVER="$TLS_SERVER" \
    HOME="$HOME_DIR" CARGO_HOME="$HOST_CARGO_HOME" RUSTC="$RUSTC" \
    "$CARGO" test --manifest-path "$LORRY_DIR/Cargo.toml" \
    --locked --offline "${TEST_PROFILE[@]}" 'curl::tests::'

echo
echo "PASS: Lorry-built Linux curl passed the production request contract"
