#!/bin/sh

WD="$(dirname "$0")"
IMAGE="${MOTO_IMAGE:-motor-os-base.img}"
SMP="${MOTO_SMP:-2}"
MEMORY_MIB="${MOTO_MEMORY_MIB:-64}"
RUNTIME_DIR="${MOTO_FC_RUNTIME_DIR:-/tmp}"
case "$IMAGE" in
  "" | *[!A-Za-z0-9._-]*)
    echo "run-fc: invalid image filename '$IMAGE'" >&2
    exit 2
    ;;
esac
case "$IMAGE" in
  *.img | *.raw) ;;
  *.qcow2)
    echo "run-fc: Firecracker requires a raw image, not '$IMAGE'" >&2
    exit 2
    ;;
  *)
    echo "run-fc: unsupported image filename '$IMAGE'" >&2
    exit 2
    ;;
esac
case "$SMP" in
  "" | *[!0-9]* | 0 | 0[0-9]*)
    echo "run-fc: MOTO_SMP must be a positive integer" >&2
    exit 2
    ;;
esac
case "$MEMORY_MIB" in
  "" | *[!0-9]* | 0 | 0[0-9]*)
    echo "run-fc: MOTO_MEMORY_MIB must be a positive integer" >&2
    exit 2
    ;;
esac
case "$RUNTIME_DIR" in
  /*) ;;
  *)
    echo "run-fc: MOTO_FC_RUNTIME_DIR must be an absolute path" >&2
    exit 2
    ;;
esac
case "$RUNTIME_DIR" in
  *[!A-Za-z0-9_./-]*)
    echo "run-fc: invalid MOTO_FC_RUNTIME_DIR '$RUNTIME_DIR'" >&2
    exit 2
    ;;
esac

SOCKET="$RUNTIME_DIR/firecracker.socket"
LOG="$RUNTIME_DIR/firecracker.log"
CONFIG="$RUNTIME_DIR/fc-config.json"
mkdir -p "$RUNTIME_DIR"
rm -f "$SOCKET" "$LOG"
touch "$LOG"
# Firecracker strictly requires absolute paths in its JSON configuration
ABS_WD="$(cd "$WD" && pwd)"

cat <<EOF > "$CONFIG"
{
  "boot-source": {
    "kernel_image_path": "${ABS_WD}/kloader",
    "initrd_path": "${ABS_WD}/initrd",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ip=192.168.4.2:::255.255.255.0::eth0:off"
  },
  "drives": [
    {
      "drive_id": "disk0",
      "path_on_host": "${ABS_WD}/${IMAGE}",
      "is_root_device": false,
      "is_read_only": false
    }
  ],
  "network-interfaces": [
    {
      "iface_id": "eth0",
      "guest_mac": "a4:a1:c2:00:00:01",
      "host_dev_name": "moto-tap"
    }
  ],
  "machine-config": {
    "vcpu_count": ${SMP},
    "mem_size_mib": ${MEMORY_MIB}
  },
  "logger": {
    "log_path": "${LOG}",
    "level": "Debug",
    "show_level": true,
    "show_log_origin": true
  }
}
EOF

exec firecracker --enable-pci --api-sock "$SOCKET" \
  --config-file "$CONFIG" "$@"
