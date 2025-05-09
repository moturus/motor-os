#!/bin/sh

rm -f /tmp/chv

cloud-hypervisor-static --cpus boot=2 --memory size=256M \
    --api-socket /tmp/chv \
    --console off --serial tty \
    --log-file /tmp/cloud-hypervisor.log -v \
    --kernel kloader \
    --initramfs initrd \
    --net "tap=moto-tap,mac=a4:a1:c2:00:00:01,ip=192.168.4.2,mask=255.255.255.0" \
    --disk path=moturus.full.img

#           "tap=moto-tap-2,mac=a4:a1:c2:00:00:02,ip=192.168.6.2,mask=255.255.255.0" \
