#!/bin/sh

rm -f /tmp/chv

WD="$(dirname $0)"

cloud-hypervisor-static --cpus boot=2 --memory size=256M \
    --api-socket /tmp/chv \
    --console off --serial tty \
    --log-file /tmp/cloud-hypervisor.log -v \
    --kernel "$WD/kloader" \
    --initramfs "$WD/initrd" \
    --net "tap=moto-tap,mac=a4:a1:c2:00:00:01,ip=192.168.4.2,mask=255.255.255.0" \
    --disk path="$WD/motor.motor-fs.img"

#           "tap=moto-tap-2,mac=a4:a1:c2:00:00:02,ip=192.168.6.2,mask=255.255.255.0" \
