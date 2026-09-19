#!/bin/bash
# Hermetic checks of the vsock backend lookup, using fake backends.

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

# Create DIR/vhost-device-vsock, a fake backend that reports VERSION.
fake_backend() {
  mkdir -p "$1"
  printf '#!/bin/sh\necho "vhost-device-vsock %s"\n' "$2" > "$1/vhost-device-vsock"
  chmod +x "$1/vhost-device-vsock"
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

# A rejected lookup must name both remedies.
expect_hint() {
  grep -Fq 'src/build-motor-os.sh' "$TMP/stderr" ||
    fail "$1: the diagnostic does not name src/build-motor-os.sh"
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

echo "test-vm-vsock-backend PASS"
