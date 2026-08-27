#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$LORRY_DIR/../../.." && pwd)"
CURL_DIR="$ROOT_DIR/src/bin/curl"

if [ "$#" -ne 1 ]; then
    echo "usage: curl-contract.sh LORRY" >&2
    exit 1
fi
LORRY="$(realpath "$1")"

WORK="$(mktemp -d /tmp/lorry-curl-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "curl-contract: $*" >&2
    exit 1
}

if [ -z "${LORRY_TEST_CARGO:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
CARGO="$LORRY_TEST_CARGO"
RUSTC="$LORRY_TEST_RUSTC"
HOST_CARGO_HOME="${CARGO_HOME:-${HOME:?}/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"

echo "== Building the Linux curl integration fixture with Cargo =="
if ! CARGO_HOME="$HOST_CARGO_HOME" RUSTC="$RUSTC" "$CARGO" test \
    --manifest-path "$CURL_DIR/Cargo.toml" --locked --offline --no-run \
    --target-dir "$WORK/curl-target" >"$WORK/curl-build.log" 2>&1; then
    cat "$WORK/curl-build.log" >&2
    fail "offline curl fixture build failed; run 'make curl' to acquire its pinned Git sources"
fi
cat "$WORK/curl-build.log"
BUILT_CURL="$WORK/curl-target/debug/curl"
[ -x "$BUILT_CURL" ] || fail "Cargo did not produce an executable curl"
"$BUILT_CURL" --version | grep -F "curl 0.2.0 (Motor OS) rustls" >/dev/null ||
    fail "Cargo-built executable did not identify as Motor curl"
TLS_SERVER=""
while IFS= read -r candidate; do
    [ -z "$TLS_SERVER" ] || fail "Cargo produced multiple HTTPS test executables"
    TLS_SERVER="$candidate"
done < <(find "$WORK/curl-target/debug/build/curl" -type f -perm -111 \
    -name 'https-*' -print)
[ -n "$TLS_SERVER" ] || fail "Cargo did not produce the HTTPS test executable"

echo "== Running Lorry's production request boundary through that curl =="
LORRY_TEST_CURL="$BUILT_CURL" \
    LORRY_TEST_CA="$CURL_DIR/tests/test-ca.pem" \
    LORRY_TEST_HOSTNAME_CA="$CURL_DIR/tests/hostname-ca.pem" \
    LORRY_TEST_UNTRUSTED_CA="$ROOT_DIR/img_files/motor-os-base/system/cfg/ssl/ssl-cert.pem" \
    LORRY_TEST_TLS_SERVER="$TLS_SERVER" \
    CARGO_HOME="$HOST_CARGO_HOME" RUSTC="$RUSTC" \
    "$CARGO" test --manifest-path "$LORRY_DIR/Cargo.toml" \
    --locked --offline 'curl::tests::' -- --ignored

echo
echo "PASS: Cargo-built Linux curl passed Lorry's production request contract"
