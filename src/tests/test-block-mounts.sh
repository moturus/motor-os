#!/bin/bash
if [ "${TEST_BLOCK_MOUNTS_TIMEOUT_ACTIVE:-0}" != 1 ]; then
  export TEST_BLOCK_MOUNTS_TIMEOUT_ACTIVE=1
  set -m
  timeout 300s "$0" "$@" < /dev/null
  status=$?
  set +m
  [ "$status" -ne 124 ] || echo "test-block-mounts: timed out after 300 seconds" >&2
  exit "$status"
fi
set -euo pipefail
WD="$(dirname "$0")"
ROOT_DIR="$(realpath "$WD/../..")"
BUILD=debug
VMM=qemu
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      [ "$BUILD" = debug ] || { echo "duplicate --release" >&2; exit 2; }
      BUILD=release; shift ;;
    --vmm)
      [ "$#" -ge 2 ] || { echo "--vmm requires qemu, chv, or fc" >&2; exit 2; }
      VMM="$2"; shift 2 ;;
    *) echo "usage: $0 [--release] [--vmm qemu|chv|fc]" >&2; exit 2 ;;
  esac
done
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}"
export MOTO_SMP="${MOTO_SMP:-4}"
. "$WD/vm-test-selection.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-serial.sh"
test_vm_configure_ssh
fail() { echo "test-block-mounts: $* (log: $CONSOLE_LOG)" >&2; exit 1; }
SCRATCH="$(mktemp -d)"
CONSOLE_LOG=/tmp/test-block-mounts.log
export MOTO_CHV_RUNTIME_DIR="$SCRATCH/chv"
export MOTO_FC_RUNTIME_DIR="$SCRATCH/fc"
export MOTO_FC_VSOCK_UDS=''
VMM_PID=""
VM_CHILD_PID=""
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  exec 3>&-
  stop_serial_test_vm || status=1
  rm -rf "$SCRATCH" || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
select_test_vm "$SCRATCH" "$BUILD" system-console "$VMM"
export MOTO_IMAGE=motor-os-ro-root.img
make -C "$ROOT_DIR" ro-root.img BUILD="$BUILD" TEST_IMAGE_ROOT="$SCRATCH" -j"$(nproc)"
image="$TEST_VM_IMG_DIR/$MOTO_IMAGE"
baseline="$(sha256sum "$image")"
mkfifo "$SCRATCH/console-in"
exec 3<> "$SCRATCH/console-in"
for boot in 1 2; do
  CONSOLE_LOG="/tmp/test-block-mounts-$BUILD-$VMM-$boot.log"
  start_serial_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG" "$SCRATCH/console-in"
  until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
      motor@192.168.4.2 /system/bin/rush -c true >/dev/null 2>&1; do
    serial_test_vm_alive || fail "guest exited before SSH was ready"
    sleep 1
  done
  if [ "$boot" = 1 ]; then
    vm_ssh '/system/services/strobe --self-test'
  fi
  vm_ssh 'MOTOR_OS_CAPS=0x244 /user/bin/systest block-ro-root'
  vm_ssh 'MOTOR_OS_CAPS=0x204 /user/bin/systest block-ro-root'
  printf '%s\r' 'MOTOR_OS_CAPS=0x20d /user/bin/systest block-ro-root > /user/tmp/ro-system.log; echo $? > /user/tmp/ro-system.status' >&3
  until vm_ssh '[ -e /user/tmp/ro-system.status ]' >/dev/null 2>&1; do
    serial_test_vm_alive || fail "guest exited during System tests"
    sleep 0.5
  done
  vm_ssh 'cat /user/tmp/ro-system.log'
  [ "$(vm_ssh 'cat /user/tmp/ro-system.status')" = 0 ] || fail "System checks failed"
  vm_ssh 'findmnt'
  # Require a guest-requested exit; forced cleanup is not a successful reboot.
  vm_ssh shutdown
  serial_test_wait_exit "$VMM_PID" 20 || fail "shutdown did not finish"
  status=0
  wait "$VMM_PID" || status=$?
  if [ -n "$VM_CHILD_PID" ] && kill -0 "$VM_CHILD_PID" 2>/dev/null; then
    fail "VMM child survived shutdown"
  fi
  VMM_PID=""
  VM_CHILD_PID=""
  case "$VMM:$status" in qemu:33|chv:0|fc:0) ;; *) fail "shutdown status $status" ;; esac
  [ "$(sha256sum "$image")" = "$baseline" ] || fail "read-only root changed its backing image"
done
echo "-------- TEST-BLOCK-MOUNTS PASS ---------"
