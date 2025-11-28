#!/bin/sh

WD="$(dirname $0)"
# the script allows for --img=<image-file> to be passed as first argument
# if this exists, should be stripped from "$@" before passing to qemu
IMG="motor.full.img"
if [ "${1#--img=}" != "$1" ]; then
  IMG="${1#--img=}"
  shift
fi

qemu-system-x86_64 -m 256M -enable-kvm -cpu host -smp 4 \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -device virtio-blk-pci,drive=drive0,id=virtblk0,num-queues=1,disable-legacy=on \
  -drive "file=$WD/$IMG,if=none,id=drive0,format=raw" \
  -netdev tap,ifname=moto-tap,script=no,downscript=no,id=nic0 \
  -device virtio-net-pci,disable-legacy=on,mac=a4:a1:c2:00:00:01,netdev=nic0 \
  -no-reboot -nographic "$@"

#  -netdev user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10023-:5542,id=nic0 \

#  -netdev tap,ifname=moto-tap-2,script=no,downscript=no,id=nic1 \
#  -device virtio-net-pci,disable-legacy=on,mac=a4:a1:c2:00:00:02,netdev=nic1 \
