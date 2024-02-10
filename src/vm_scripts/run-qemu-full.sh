#!/bin/sh

qemu-system-x86_64 -m 256M -enable-kvm -cpu host -smp 4 \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -device virtio-blk-pci,drive=drive0,id=virtblk0,num-queues=1,disable-legacy=on \
  -drive file=moturus.full.img,if=none,id=drive0,format=raw \
  -netdev tap,ifname=moto-tap,script=no,downscript=no,id=nic0 \
  -device virtio-net-pci,disable-legacy=on,netdev=nic0 \
  -no-reboot -nographic

#  -netdev user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10023-:5542,id=nic0 \

