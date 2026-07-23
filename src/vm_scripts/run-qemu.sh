#!/bin/sh

WD="$(dirname $0)"

# Oversubscribe knob (harness): MOTO_SMP overrides the vCPU count (default 4);
# MOTO_CPU_AFFINITY, when set, pins the whole qemu process to that host cpuset
# via taskset. Setting MOTO_SMP above the pinned set's size forces the host to
# multiplex vCPUs -- widening the scheduling windows that lost-wake and
# io_channel client/server races depend on. Unset == today's behavior (4
# vCPUs, no pinning).
SMP="${MOTO_SMP:-4}"
if [ -n "${MOTO_CPU_AFFINITY:-}" ]; then
  TASKSET="taskset -c ${MOTO_CPU_AFFINITY}"
else
  TASKSET=""
fi
echo "run-qemu: -smp ${SMP}${MOTO_CPU_AFFINITY:+ (pinned to host cpus ${MOTO_CPU_AFFINITY})}" 1>&2

$TASKSET qemu-system-x86_64 -m 1024M -enable-kvm -cpu host -smp "${SMP}" \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -device virtio-blk-pci,drive=drive0,id=virtblk0,num-queues=1,disable-legacy=on \
  -drive file="$WD/motor-os.img",if=none,id=drive0,format=raw \
  -netdev tap,ifname=moto-tap,script=no,downscript=no,id=nic0 \
  -device virtio-net-pci,disable-legacy=on,mac=a4:a1:c2:00:00:01,netdev=nic0 \
  -no-reboot -nographic "$@"

#  -netdev user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10023-:5542,id=nic0 \

#  -netdev tap,ifname=moto-tap-2,script=no,downscript=no,id=nic1 \
#  -device virtio-net-pci,disable-legacy=on,mac=a4:a1:c2:00:00:02,netdev=nic1 \
