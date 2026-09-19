#!/bin/bash
# Hermetic checks of host provisioning's vsock backend step: a stub cargo and
# fake backends stand in for the network install.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/build-base.sh"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/test-build-base-vsock-backend.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin"

fail_test() {
  echo "test-build-base-vsock-backend: $*" >&2
  exit 1
}

log() { :; }
skip() { :; }
warn() { printf '%s\n' "$*" >> "$TMP/warnings"; }

# Write a fake backend that reports VERSION, as the installed one.
fake_backend() {
  printf '#!/bin/sh\necho "vhost-device-vsock %s"\n' "$1" > "$BIN/vhost-device-vsock"
  command -p chmod +x "$BIN/vhost-device-vsock"
}

cargo_usable=1
install_produces_backend=1
cargo() {
  printf '%s | %s\n' "$PWD" "$*" >> "$TMP/cargo.log"
  case "$*" in
    --version) [ "$cargo_usable" -eq 1 ] ;;
    "install --locked --version $VSOCK_BACKEND_VERSION vhost-device-vsock")
      [ "$install_produces_backend" -eq 0 ] || fake_backend "$VSOCK_BACKEND_VERSION"
      ;;
    *) fail_test "unexpected cargo command: $*" ;;
  esac
}

# Run the step on a host whose only PATH entry is BIN, which hides any backend
# really installed here, starting from the INITIAL backend version or none.
# It starts outside the checkout: cargo must run inside it to get its toolchain.
run_step() (
  rm -rf "$BIN" "$TMP/cargo.log" "$TMP/warnings"
  mkdir -p "$BIN"
  : > "$TMP/cargo.log"
  : > "$TMP/warnings"
  [ "$1" = none ] || fake_backend "$1"
  cd "$TMP"
  PATH="$BIN"
  unset VHOST_DEVICE_VSOCK
  install_vsock_backend
)

probe="$MOTOR | --version"
install="$MOTOR | install --locked --version $VSOCK_BACKEND_VERSION vhost-device-vsock"
expect_cargo_log() {
  [ "$(< "$TMP/cargo.log")" = "$1" ] ||
    fail_test "$2: unexpected cargo calls: $(< "$TMP/cargo.log")"
}

run_step "$VSOCK_BACKEND_VERSION" || fail_test "an installed backend was rejected"
expect_cargo_log "" "installed backend"

run_step none || fail_test "a missing backend was not installed"
expect_cargo_log "$probe"$'\n'"$install" "missing backend"
[ -x "$BIN/vhost-device-vsock" ] || fail_test "the install left no backend"

run_step 0.2.0 || fail_test "a backend of another version was not replaced"
expect_cargo_log "$probe"$'\n'"$install" "stale backend"

# A new host has no Motor toolchain during provisioning: warn, do not fail.
cargo_usable=0
run_step none || fail_test "a host without a toolchain failed provisioning"
expect_cargo_log "$probe" "unusable cargo"
grep -Fq -- "${VSOCK_BACKEND_INSTALL[*]}" "$TMP/warnings" ||
  fail_test "the warning does not give the install command"
cargo_usable=1

install_produces_backend=0
if run_step none 2>/dev/null; then
  fail_test "an install that produced no usable backend was accepted"
fi
expect_cargo_log "$probe"$'\n'"$install" "fruitless install"

echo "test-build-base-vsock-backend PASS"
