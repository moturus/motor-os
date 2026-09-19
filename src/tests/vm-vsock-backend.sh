# Resolve the vhost-device-vsock backend that QEMU's vsock device needs. Sourced
# by the vsock harnesses, which need no environment setup for it. Not executable.

VSOCK_BACKEND_VERSION=0.3.0

# Set VHOST_DEVICE_VSOCK to a backend of the pinned version. The caller's own
# VHOST_DEVICE_VSOCK wins, then one installed on PATH; otherwise the pinned
# release is built once into ROOT's build directory.
resolve_vsock_backend() {
  local root tools version
  root="$(cd "$1" && pwd)" || return 1 # Callers may pass a relative ROOT.
  tools="$root/build/host-tools"
  if [ -z "${VHOST_DEVICE_VSOCK:-}" ]; then
    VHOST_DEVICE_VSOCK="$(command -v vhost-device-vsock || true)"
  fi
  if [ -z "$VHOST_DEVICE_VSOCK" ]; then
    VHOST_DEVICE_VSOCK="$tools/bin/vhost-device-vsock"
    if [ ! -x "$VHOST_DEVICE_VSOCK" ]; then
      # Tests stay off the network, so the build takes the crate and its
      # dependencies from Cargo's local cache. Run from ROOT for its toolchain.
      echo "vsock-backend: building vhost-device-vsock $VSOCK_BACKEND_VERSION into $tools"
      (cd "$root" && cargo install --locked --offline --root "$tools" \
        --version "$VSOCK_BACKEND_VERSION" vhost-device-vsock) || {
        echo "vsock-backend: the offline build failed. Fill Cargo's cache once, with network access:" >&2
        echo "  cargo install --locked --root '$tools' --version $VSOCK_BACKEND_VERSION vhost-device-vsock" >&2
        return 1
      }
    fi
  fi
  command -v "$VHOST_DEVICE_VSOCK" >/dev/null 2>&1 || {
    echo "vsock-backend: required host tool is missing: $VHOST_DEVICE_VSOCK" >&2
    return 1
  }
  version="$("$VHOST_DEVICE_VSOCK" --version)"
  [ "$version" = "vhost-device-vsock $VSOCK_BACKEND_VERSION" ] || {
    echo "vsock-backend: expected vhost-device-vsock $VSOCK_BACKEND_VERSION, got '$version'" >&2
    return 1
  }
}
