#!/bin/sh

WD="$(dirname "$0")"
IMAGE="${MOTO_IMAGE:-motor-os.qcow2}"
SMP="${MOTO_SMP:-4}"
MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}"
RUNTIME_DIR="${MOTO_CHV_RUNTIME_DIR:-/tmp}"
case "$IMAGE" in
  "" | *[!A-Za-z0-9._-]*)
    echo "run-chv: invalid image filename '$IMAGE'" >&2
    exit 2
    ;;
esac
case "$IMAGE" in
  *.qcow2) IMAGE_FORMAT=qcow2 ;;
  *.img | *.raw) IMAGE_FORMAT=raw ;;
  *)
    echo "run-chv: unsupported image filename '$IMAGE'" >&2
    exit 2
    ;;
esac

mkdir -p "$RUNTIME_DIR"
rm -f "$RUNTIME_DIR/chv"

exec cloud-hypervisor-static --cpus "boot=$SMP" --memory "size=${MEMORY_MIB}M" \
    --api-socket "$RUNTIME_DIR/chv" \
    --console off --serial tty \
    --log-file "$RUNTIME_DIR/cloud-hypervisor.log" -v \
    --kernel "$WD/kloader" \
    --initramfs "$WD/initrd" \
    --net "tap=moto-tap,mac=a4:a1:c2:00:00:01,ip=192.168.4.2,mask=255.255.255.0" \
    --disk "path=$WD/$IMAGE,image_type=$IMAGE_FORMAT" "$@"

#           "tap=moto-tap-2,mac=a4:a1:c2:00:00:02,ip=192.168.6.2,mask=255.255.255.0" \
