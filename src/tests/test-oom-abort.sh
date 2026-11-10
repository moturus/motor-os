#!/bin/bash
# A fresh System-console guest must report victimless OOM before terminating.
if [ "${TEST_OOM_ABORT_TIMEOUT_ACTIVE:-0}" != 1 ]; then
  export TEST_OOM_ABORT_TIMEOUT_ACTIVE=1
  set -m
  timeout 180s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "test-oom-abort: timed out after 180 seconds" >&2
  fi
  exit "$status"
fi
set -euo pipefail
WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."
BUILD=debug
VMM=qemu
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      [ "$BUILD" = debug ] || { echo "test-oom-abort: duplicate --release" >&2; exit 2; }
      BUILD=release; shift ;;
    --vmm)
      [ "$#" -ge 2 ] || { echo "test-oom-abort: --vmm requires qemu, chv, or fc" >&2; exit 2; }
      VMM="$2"; shift 2 ;;
    *) echo "usage: $0 [--release] [--vmm qemu|chv|fc]" >&2; exit 2 ;;
  esac
done
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-256}"
export MOTO_SMP="${MOTO_SMP:-4}"
. "$WD/vm-test-selection.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-serial.sh"
test_vm_configure_ssh
fail() { echo "test-oom-abort: $* (log: $CONSOLE_LOG)" >&2; exit 1; }
CONSOLE_LOG=/tmp/test-oom-abort.log
SCRATCH="$(mktemp -d)"
export MOTO_CHV_RUNTIME_DIR="$SCRATCH/chv"
export MOTO_FC_RUNTIME_DIR="$SCRATCH/fc"
export MOTO_FC_VSOCK_UDS=''
VMM_PID=""
VM_CHILD_PID=""
# Once pressure starts, SSH may be unavailable. Teardown owns only this VM.
SERIAL_VM_HAS_SSH=0
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
export MOTO_IMAGE="$TEST_VM_IMAGE"
make -C "$ROOT_DIR" "$TEST_VM_IMG_TARGET" systest BUILD="$BUILD" \
  TEST_IMAGE_ROOT="$SCRATCH" -j"$(nproc)"
# Raw OOM reports bypass sys-tty's writer. Keep routine debug logs in the
# standard file sink so the console-flood fixture cannot interleave with them.
"$ROOT_DIR/build/obj/$BUILD/imager/$BUILD/imager" put --mode r--r--r-- \
  "$TEST_VM_IMG_DIR/$TEST_VM_IMAGE" \
  "$ROOT_DIR/img_files/motor-os-base/system/cfg/sys-tty.cfg" /system/cfg/sys-tty.cfg
mkfifo "$SCRATCH/console-in"
exec 3<> "$SCRATCH/console-in"
start_serial_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG" \
  "$SCRATCH/console-in"
until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /system/bin/rush -c true >/dev/null 2>&1; do
  serial_test_vm_alive || fail "guest exited before SSH was ready"
  sleep 1
done
scp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
  -i "$WD/test.key" "$ROOT_DIR/build/bin/$BUILD/systest" \
  motor@192.168.4.2:/none/tmp/oom-abort
printf 'chmod r-xr-xr-x /none/tmp/oom-abort; /none/tmp/oom-abort system-oom-abort\r' >&3
# Observe only the console and the owned VMM; no new guest processes under pressure.
serial_test_wait_exit "$VMM_PID" 30 || fail "guest did not abort"
vm_status=0
wait "$VMM_PID" || vm_status=$?
if [ -n "$VM_CHILD_PID" ] && kill -0 "$VM_CHILD_PID" 2>/dev/null; then
  fail "VMM child survived its wrapper"
fi
VMM_PID=""
VM_CHILD_PID=""
case "$VMM:$vm_status" in
  qemu:33|chv:0|fc:0) ;;
  *) fail "unexpected VMM exit status $vm_status" ;;
esac
tr -d '\r' < "$CONSOLE_LOG" | awk '
  /^oom-abort: READY pid=[0-9]+$/ { split($3, field, "="); pid = field[2] }
  /^OOM: remaining processes, [0-9]+ free physical pages$/ {
    if (!pid || $4 >= 512) bad = 1
    report = 1
  }
  /^OOM: .* pid=[0-9]+ kernel_pid=[0-9]+ user_bytes=[0-9]+ kernel_bytes=[0-9]+$/ {
    if (report && index($0, " pid=" pid " ")) own_memory = 1
  }
  /^OOM: .* free pages, kill / { bad = 1 }
  /KERNEL PANIC/ { panics++; if (!own_memory) bad = 1 }
  /^OOM: no eligible victims or pending reclamation below 512 free pages$/ {
    if (panics == 1) expected = 1
  }
  /vm_exit: bye\./ { exited = 1 }
  END { exit !(pid && report && own_memory && panics == 1 && expected && exited && !bad) }
' || fail "missing or incorrect victimless OOM report/panic"
echo "-------- TEST-OOM-ABORT PASS ---------"
