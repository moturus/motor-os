#!/bin/sh

cloud-hypervisor-static --cpus boot=4 --memory size=256M \
    --api-socket /tmp/chv \
    --console off --serial tty \
    --log-file /tmp/cloud-hypervisor.log -v \
    --kernel kloader \
    --initramfs initrd \
    --disk path=moturus.full.img
