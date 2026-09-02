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

# Guest RAM backing. With enough free pages in the host's hugetlbfs pool
# (vm.nr_hugepages), the RAM comes from there, prefaulted. Otherwise it is a
# memfd with the transparent-hugepage hint, which only works when the host
# has /sys/kernel/mm/transparent_hugepage/shmem_enabled set to advise.
# MOTO_HUGEPAGES=0 asks for neither. See docs/plans/boot-time.md.
MEMORY="size=${MEMORY_MIB}M"
if [ "${MOTO_HUGEPAGES:-1}" != "0" ]; then
  HP_KB="$(awk '/^Hugepagesize/ {print $2}' /proc/meminfo)"
  HP_FREE="$(awk '/^HugePages_Free/ {print $2}' /proc/meminfo)"
  if [ "${HP_FREE:-0}" -ge $(( (MEMORY_MIB * 1024 + HP_KB - 1) / HP_KB )) ]; then
    MEMORY="$MEMORY,hugepages=on,prefault=on"
    echo "run-chv: guest RAM from the hugetlbfs pool ($((HP_KB / 1024)) MiB pages)" >&2
  else
    MEMORY="$MEMORY,thp=on"
    echo "run-chv: guest RAM with the transparent-hugepage hint (no hugetlbfs pool)" >&2
  fi
fi

exec cloud-hypervisor-static --cpus "boot=$SMP" --memory "$MEMORY" \
    --api-socket "$RUNTIME_DIR/chv" \
    --console off --serial tty \
    --log-file "$RUNTIME_DIR/cloud-hypervisor.log" -v \
    --kernel "$WD/kloader" \
    --initramfs "$WD/initrd" \
    --net "tap=moto-tap,mac=a4:a1:c2:00:00:01,ip=192.168.4.2,mask=255.255.255.0" \
    --disk "path=$WD/$IMAGE,image_type=$IMAGE_FORMAT" "$@"

#           "tap=moto-tap-2,mac=a4:a1:c2:00:00:02,ip=192.168.6.2,mask=255.255.255.0" \
