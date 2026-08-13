#!/bin/sh

rm -f /tmp/chv

WD="$(dirname "$0")"
IMAGE="${MOTO_IMAGE:-motor-os.img}"
SMP="${MOTO_SMP:-4}"
MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}"

exec cloud-hypervisor-static --cpus "boot=$SMP" --memory "size=${MEMORY_MIB}M" \
    --api-socket /tmp/chv \
    --console off --serial tty \
    --log-file /tmp/cloud-hypervisor.log -v \
    --kernel "$WD/kloader" \
    --initramfs "$WD/initrd" \
    --net "tap=moto-tap,mac=a4:a1:c2:00:00:01,ip=192.168.4.2,mask=255.255.255.0" \
    --disk "path=$WD/$IMAGE" "$@"

#           "tap=moto-tap-2,mac=a4:a1:c2:00:00:02,ip=192.168.6.2,mask=255.255.255.0" \
