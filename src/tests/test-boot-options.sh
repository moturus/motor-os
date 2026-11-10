#!/bin/bash
set -euo pipefail

if [ "${TEST_BOOT_OPTIONS_TIMED:-0}" != 1 ]; then
  exec timeout 180s env TEST_BOOT_OPTIONS_TIMED=1 "$0" "$@"
fi
WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
BUILD=debug
VMM=chv
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release) BUILD=release; shift ;;
    --vmm) VMM="${2:?missing VMM}"; shift 2 ;;
    *) echo "usage: $0 [--release] [--vmm qemu|chv|fc]" >&2; exit 2 ;;
  esac
done
. "$WD/vm-test-selection.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-serial.sh"
. "$WD/vm-console-filter.sh"
select_test_vm "$ROOT_DIR" "$BUILD" standard "$VMM"
test_vm_configure_ssh
make -C "$ROOT_DIR" "$TEST_VM_IMG_TARGET" systest BUILD="$BUILD" -j"$(nproc)"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
mkdir -p "$ROOT_DIR/build/test-boot-options"
LOG_DIR="$(mktemp -d "$ROOT_DIR/build/test-boot-options/$BUILD-$VMM.XXXXXX")"
cp "$ROOT_DIR/src/vm_scripts/"*.sh "$SCRATCH/"
cp "$TEST_VM_IMG_DIR/kloader" "$TEST_VM_IMG_DIR/initrd" "$SCRATCH/"
cp --reflink=auto --sparse=always "$TEST_VM_IMG_DIR/$TEST_VM_IMAGE" "$SCRATCH/"
"$TEST_VM_IMG_DIR/tools/imager" put --mode r-xr-xr-x \
  "$SCRATCH/$TEST_VM_IMAGE" "$ROOT_DIR/build/bin/$BUILD/systest" /user/bin/boot-options-test
export MOTO_IMAGE="$TEST_VM_IMAGE" MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}" MOTO_SMP="${MOTO_SMP:-4}"
export MOTO_CHV_RUNTIME_DIR="$SCRATCH/chv" MOTO_FC_RUNTIME_DIR="$SCRATCH/fc" MOTO_FC_VSOCK_UDS=''
VMM_PID=''
VM_CHILD_PID=''
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  exec 3>&-
  stop_serial_test_vm || status=1
  rm -rf "$SCRATCH"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { echo "test-boot-options: $VMM $BUILD: $* (logs: $LOG_DIR)" >&2; exit 1; }
mkfifo "$SCRATCH/input"
exec 3<> "$SCRATCH/input"

wait_line() {
  for _ in $(seq 1 120); do
    if filter_vm_console < "$CONSOLE_LOG" | tr -d '\r' | grep -aE "$1" >/dev/null; then return; fi
    serial_test_vm_alive || fail "VM exited waiting for $1"
    sleep 0.5
  done
  fail "console did not emit $1"
}

boot_console() {
  local name="$1" system_tty="$2" cmdline="$3"
  shift 3
  export SERIAL_VM_HAS_SSH=1
  CONSOLE_LOG="$LOG_DIR/$name.log"
  start_serial_test_vm "$SCRATCH/run-$VMM.sh" "$TEST_VM_LABEL" "$CONSOLE_LOG" "$SCRATCH/input" "$@"
  until vm_ssh /system/bin/rush -c true >/dev/null 2>&1; do
    serial_test_vm_alive || fail 'VM exited before SSH'
    sleep 0.5
  done
  # Wait for the console shell too: it is independently scheduled from SSH.
  wait_line '/user\$'
  vm_ssh /user/bin/boot-options-test boot-console "$system_tty"
  if [ "$system_tty" = true ]; then
    # The System console can query the bytes; SSH and its None child cannot.
    printf "/user/bin/boot-options-test boot-cmdline '%s'; echo BOOT_CMDLINE_STATUS=\$?\r" "$cmdline" >&3
    wait_line '^BOOT_CMDLINE_STATUS=-?[0-9]+$'
    filter_vm_console < "$CONSOLE_LOG" | tr -d '\r' | grep -aFx 'BOOT_CMDLINE_STATUS=0' >/dev/null ||
      fail 'command-line query guest test failed'
    wait_line '^kernel command-line query PASS$'
  fi
  if [ "$BUILD" = debug ]; then
    grep -Fq 'kernel command-line tests PASS' "$CONSOLE_LOG" || fail 'kernel command-line reader tests did not run'
  fi
  stop_serial_test_vm
}

boot_console default false ''
case "$VMM" in
  chv)
    boot_console empty false '' -- --cmdline ''
    boot_console lookalikes false '' -- --cmdline 'system-tty=1 no-system-tty system-tty-extra --system-tty'
    # CHV trims outer whitespace before passing the line to the kernel.
    boot_console system true 'unrelated=1  system-tty=1   system-tty' \
      --system-tty -- --cmdline 'unrelated=1  system-tty=1  '
    ;;
  fc)
    boot_console system true \
      'console=ttyS0 reboot=k panic=1 pci=off ip=192.168.4.2:::255.255.255.0::eth0:off system-tty' --system-tty
    ;;
esac

export SERIAL_VM_HAS_SSH=0
CONSOLE_LOG="$LOG_DIR/no-network.log"
start_serial_test_vm "$SCRATCH/run-$VMM.sh" "$TEST_VM_LABEL" "$CONSOLE_LOG" "$SCRATCH/input" --no-network
wait_line '/user\$'
printf '/user/bin/boot-options-test boot-no-network; echo BOOT_NETWORK_STATUS=$?\r' >&3
wait_line '^BOOT_NETWORK_STATUS=-?[0-9]+$'
filter_vm_console < "$CONSOLE_LOG" | tr -d '\r' | grep -aFx 'BOOT_NETWORK_STATUS=0' >/dev/null ||
  fail 'no-network guest test failed'
wait_line '^boot without network device PASS$'
stop_serial_test_vm
echo "test-boot-options: $VMM $BUILD PASS"
