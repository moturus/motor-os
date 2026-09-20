#!/bin/bash
# Hermetic checks of the vsock backend lookup and its one-time install: fake
# backends and a stub cargo stand in for the network install.

set -euo pipefail

WD="$(dirname "$0")"
. "$WD/vm-vsock-backend.sh"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/test-vm-vsock-backend.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "test-vm-vsock-backend: $*" >&2
  [ ! -s "$TMP/stderr" ] || cat "$TMP/stderr" >&2
  exit 1
}

# Create DIR/vhost-device-vsock, a fake backend that reports VERSION. The stub
# cargo calls this under a PATH that holds nothing else, hence `command -p`.
fake_backend() {
  command -p mkdir -p "$1"
  printf '#!/bin/sh\necho "vhost-device-vsock %s"\n' "$2" > "$1/vhost-device-vsock"
  command -p chmod +x "$1/vhost-device-vsock"
}
fake_backend "$TMP/pinned" "$VSOCK_BACKEND_VERSION"
fake_backend "$TMP/explicit" "$VSOCK_BACKEND_VERSION"
fake_backend "$TMP/stale" 0.2.0
mkdir "$TMP/empty"

# Look up with only SEARCH_PATH and EXPLICIT visible, so that a backend really
# installed on this host cannot affect the result. Prints the selected backend.
lookup() (
  PATH="$1"
  VHOST_DEVICE_VSOCK="$2"
  resolve_vsock_backend 2> "$TMP/stderr" && printf '%s\n' "$VHOST_DEVICE_VSOCK"
)

# A rejected lookup must name the remedy.
expect_hint() {
  grep -Fq -- "${VSOCK_BACKEND_INSTALL[*]}" "$TMP/stderr" ||
    fail "$1: the diagnostic does not give the install command"
}

[ "$(lookup "$TMP/pinned" "")" = "$TMP/pinned/vhost-device-vsock" ] ||
  fail "the pinned backend on PATH was not selected"
[ "$(lookup "$TMP/pinned" "$TMP/explicit/vhost-device-vsock")" = "$TMP/explicit/vhost-device-vsock" ] ||
  fail "an explicit VHOST_DEVICE_VSOCK did not take precedence over PATH"

if lookup "$TMP/empty" "" >/dev/null; then
  fail "a missing backend was accepted"
fi
grep -Fq 'is not installed' "$TMP/stderr" || fail "a missing backend was not reported as such"
expect_hint "missing backend"

if lookup "$TMP/stale" "" >/dev/null; then
  fail "a backend of another version was accepted"
fi
grep -Fq "expected vhost-device-vsock $VSOCK_BACKEND_VERSION, got 'vhost-device-vsock 0.2.0'" \
  "$TMP/stderr" || fail "a version mismatch was not reported as such"
expect_hint "version mismatch"

# A broken explicit choice is an error; it must not silently fall back to PATH.
if lookup "$TMP/pinned" "$TMP/empty/vhost-device-vsock" >/dev/null; then
  fail "a broken explicit VHOST_DEVICE_VSOCK fell back to PATH"
fi
expect_hint "broken explicit backend"

# The harness entry point installs the pinned backend once, from the checkout.
install_produces_backend=1
cargo() {
  printf '%s | %s\n' "$PWD" "$*" >> "$TMP/cargo.log"
  [ "$*" = "install --locked --version $VSOCK_BACKEND_VERSION vhost-device-vsock" ] ||
    fail "unexpected cargo command: $*"
  [ "$install_produces_backend" -eq 0 ] || fake_backend "$TMP/bin" "$VSOCK_BACKEND_VERSION"
}
# Run with BIN as the only PATH entry, holding the INITIAL backend version or none.
ensure() (
  rm -rf "$TMP/bin" "$TMP/cargo.log"
  mkdir -p "$TMP/bin"
  : > "$TMP/cargo.log"
  [ "$1" = none ] || fake_backend "$TMP/bin" "$1"
  cd "$TMP"
  PATH="$TMP/bin"
  VHOST_DEVICE_VSOCK="${2:-}"
  ensure_vsock_backend 2> "$TMP/stderr"
)
install="$VSOCK_BACKEND_CHECKOUT | install --locked --version $VSOCK_BACKEND_VERSION vhost-device-vsock"
expect_cargo_log() {
  [ "$(< "$TMP/cargo.log")" = "$1" ] || fail "$2: unexpected cargo calls: $(< "$TMP/cargo.log")"
}
ensure "$VSOCK_BACKEND_VERSION" || fail "an installed backend was rejected"
expect_cargo_log "" "installed backend"
ensure none || fail "a missing backend was not installed"
expect_cargo_log "$install" "missing backend"
ensure 0.2.0 || fail "a backend of another version was not replaced"
expect_cargo_log "$install" "stale backend"
if ensure none "$TMP/empty/vhost-device-vsock"; then
  fail "a broken explicit VHOST_DEVICE_VSOCK was accepted"
fi
expect_cargo_log "" "explicit backend"
install_produces_backend=0
if ensure none; then fail "an install that produced no usable backend was accepted"; fi
expect_cargo_log "$install" "fruitless install"

echo "test-vm-vsock-backend PASS"
