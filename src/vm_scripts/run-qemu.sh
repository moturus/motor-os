#!/bin/sh

WD="$(dirname "$0")"

# Every standard harness uses the same tap, guest address, MAC, and SSH port.
# Without host-side exclusion, SSH can reach another run's already-booted guest
# while this run's QEMU is still starting, silently mixing two test suites.
VM_LOCK="${MOTO_QEMU_LOCK:-/tmp/motor-os-qemu.$(id -u).lock}"
exec 9>"$VM_LOCK"
if ! flock -n 9; then
  echo "run-qemu: another Motor OS VM owns $VM_LOCK" >&2
  exit 1
fi

# MOTO_IMAGE selects the disk image (e.g. motor-os-dev.img); default: the main one.
IMAGE="${MOTO_IMAGE:-motor-os.img}"

# Harness knobs: MOTO_SMP overrides the vCPU count (default 4), and
# MOTO_MEMORY_MIB overrides RAM in MiB (default 1024). MOTO_CPU_AFFINITY, when
# set, pins the whole qemu process to that host cpuset via taskset. Setting
# MOTO_SMP above the pinned set's size forces the host to multiplex vCPUs --
# widening the scheduling windows that lost-wake and io_channel client/server
# races depend on.
SMP="${MOTO_SMP:-4}"
MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}"
if [ -n "${MOTO_CPU_AFFINITY:-}" ]; then
  TASKSET="taskset -c ${MOTO_CPU_AFFINITY}"
else
  TASKSET=""
fi
echo "run-qemu: -smp ${SMP}, memory ${MEMORY_MIB} MiB${MOTO_CPU_AFFINITY:+ (pinned to host cpus ${MOTO_CPU_AFFINITY})}" 1>&2

if [ "${MOTO_QEMU_USER_NET:-0}" = "1" ]; then
  NETDEV="user,net=192.168.4.0/24,host=192.168.4.1,hostfwd=tcp:127.0.0.1:10023-192.168.4.2:2222,id=nic0"
else
  NETDEV="tap,ifname=moto-tap,script=no,downscript=no,id=nic0"
fi

# exec, so that this script's pid *is* qemu's pid. Without it /bin/sh forks
# qemu as a child, and a harness that backgrounds this script and kills "$!"
# kills only the wrapper: qemu is orphaned to init and keeps holding moto-tap
# and the image, so the next run's ssh silently reaches the stale guest.
exec $TASKSET qemu-system-x86_64 -m "${MEMORY_MIB}M" -enable-kvm -cpu host -smp "${SMP}" \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -device virtio-blk-pci,drive=drive0,id=virtblk0,num-queues=1,disable-legacy=on \
  -drive file="$WD/$IMAGE",if=none,id=drive0,format=raw \
  -netdev "$NETDEV" \
  -device virtio-net-pci,disable-legacy=on,mac=a4:a1:c2:00:00:01,netdev=nic0 \
  -no-reboot -nographic "$@"

#  -netdev tap,ifname=moto-tap-2,script=no,downscript=no,id=nic1 \
#  -device virtio-net-pci,disable-legacy=on,mac=a4:a1:c2:00:00:02,netdev=nic1 \
