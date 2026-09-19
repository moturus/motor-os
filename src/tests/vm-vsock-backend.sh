# Locate the vhost-device-vsock backend that QEMU's vsock device needs. Sourced
# by the vsock harnesses and by host provisioning. Not executable.

VSOCK_BACKEND_VERSION=0.3.0
# Host provisioning runs this once, with network access; tests only print it.
VSOCK_BACKEND_INSTALL=(cargo install --locked --version "$VSOCK_BACKEND_VERSION" vhost-device-vsock)

# Tell the user how to obtain the backend after a failed lookup.
vsock_backend_hint() {
  echo "vsock-backend: run src/build-motor-os.sh, or install it once (needs network access):" >&2
  echo "  ${VSOCK_BACKEND_INSTALL[*]}" >&2
}

# Set VHOST_DEVICE_VSOCK to an installed backend of the pinned version. The
# caller's own VHOST_DEVICE_VSOCK wins, and is never replaced by one on PATH.
resolve_vsock_backend() {
  local version
  if [ -z "${VHOST_DEVICE_VSOCK:-}" ]; then
    VHOST_DEVICE_VSOCK="$(command -v vhost-device-vsock || true)"
    [ -n "$VHOST_DEVICE_VSOCK" ] || {
      echo "vsock-backend: vhost-device-vsock is not installed (it is not on PATH)" >&2
      vsock_backend_hint
      return 1
    }
  fi
  command -v "$VHOST_DEVICE_VSOCK" >/dev/null 2>&1 || {
    echo "vsock-backend: VHOST_DEVICE_VSOCK is not an executable: $VHOST_DEVICE_VSOCK" >&2
    vsock_backend_hint
    return 1
  }
  version="$("$VHOST_DEVICE_VSOCK" --version)"
  [ "$version" = "vhost-device-vsock $VSOCK_BACKEND_VERSION" ] || {
    echo "vsock-backend: expected vhost-device-vsock $VSOCK_BACKEND_VERSION, got '$version' from $VHOST_DEVICE_VSOCK" >&2
    vsock_backend_hint
    return 1
  }
}
