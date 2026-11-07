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
start_guest() {
  CONSOLE_LOG="/tmp/test-block-mounts-$BUILD-$VMM-$1.log"
  shift
  start_serial_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG" "$SCRATCH/console-in" "$@"
  until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
      motor@192.168.4.2 /system/bin/rush -c true >/dev/null 2>&1; do
    serial_test_vm_alive || fail "guest exited before SSH was ready"
    sleep 1
  done
}
stop_guest() {
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
}
for boot in 1 2; do
  start_guest "ro-root-$boot"
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
  stop_guest
  [ "$(sha256sum "$image")" = "$baseline" ] || fail "read-only root changed its backing image"
done
imager="$ROOT_DIR/build/obj/$BUILD/imager/$BUILD/imager"
"$imager" block-mount-fixture create "$image" "$SCRATCH/partitions"
cp --sparse=always "$SCRATCH/partitions/root.img" "$TEST_VM_IMG_DIR/partitions.img"
export MOTO_IMAGE=partitions.img
start_guest unconfigured
vm_ssh '/user/bin/systest block-partition unconfigured'
stop_guest
sed 's/read_only = true/read_only = false/' \
  "$ROOT_DIR/img_files/test-ro-root/system/cfg/sys-fs.toml" > "$SCRATCH/partitions.toml"
cat >> "$SCRATCH/partitions.toml" <<'TOML'

[[mount]]
path = "/user/data"
type = "motor-fs"
device = 0
partition = 4
TOML
"$imager" block-mount-fixture config "$TEST_VM_IMG_DIR/$MOTO_IMAGE" "$SCRATCH/partitions.toml"
start_guest partition-write
vm_ssh '/user/bin/systest block-partition write'
stop_guest
echo 'read_only = true' >> "$SCRATCH/partitions.toml"
"$imager" block-mount-fixture config "$TEST_VM_IMG_DIR/$MOTO_IMAGE" "$SCRATCH/partitions.toml"
start_guest partition-read
vm_ssh '/user/bin/systest block-partition read-only'
stop_guest

for disk in parted bare unused; do
  cp --sparse=always "$SCRATCH/partitions/$disk.img" "$TEST_VM_IMG_DIR/$disk.img"
done
sed 's/read_only = true/read_only = false/' "$SCRATCH/partitions.toml" > "$SCRATCH/devices.toml"
cat >> "$SCRATCH/devices.toml" <<'TOML'

[[mount]]
path = "/user/data/nested"
type = "motor-fs"
device = 1
partition = 1
cache_mb = 2

[[mount]]
path = "/user/bare"
type = "motor-fs"
device = 2
TOML
"$imager" block-mount-fixture config "$TEST_VM_IMG_DIR/$MOTO_IMAGE" "$SCRATCH/devices.toml"
start_guest devices-write --extra-disk parted.img --extra-disk bare.img --extra-disk unused.img
vm_ssh '/user/bin/systest block-devices write'
stop_guest
echo 'read_only = true' >> "$SCRATCH/devices.toml"
"$imager" block-mount-fixture config "$TEST_VM_IMG_DIR/$MOTO_IMAGE" "$SCRATCH/devices.toml"
bare_before="$(sha256sum "$TEST_VM_IMG_DIR/bare.img")"
start_guest devices-read --extra-disk parted.img --extra-disk-ro bare.img --extra-disk unused.img
vm_ssh '/user/bin/systest block-devices read-only'
vm_ssh findmnt
stop_guest
[ "$(sha256sum "$TEST_VM_IMG_DIR/bare.img")" = "$bare_before" ] || fail 'read-only bare device changed'

reject_guest() {
  local name="$1" diagnostic="$2"
  shift 2
  CONSOLE_LOG="/tmp/test-block-mounts-$BUILD-$VMM-$name.log"
  SERIAL_VM_HAS_SSH=0
  start_serial_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG" "$SCRATCH/console-in" "$@"
  local deadline=$((SECONDS + 30))
  until grep -Fq "$diagnostic" "$CONSOLE_LOG"; do
    if ! serial_test_vm_alive; then
      grep -Fq "$diagnostic" "$CONSOLE_LOG" || fail "guest exited without expected diagnostic: $diagnostic"
      break
    fi
    [ "$SECONDS" -lt "$deadline" ] || fail "missing rejection: $diagnostic"
    sleep 0.1
  done
  ! grep -Fq 'most services up' "$CONSOLE_LOG" || fail 'failed configuration published services'
  if ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=2 -o ConnectionAttempts=1 \
      motor@192.168.4.2 /system/bin/rush -c true >/dev/null 2>&1; then
    fail 'rejected configuration accepted a filesystem client'
  fi
  # Signal only the owned VMM; CHV's PTY wrapper reaps its child normally.
  local signal_pid="$VMM_PID" status=0
  [ "$VMM" != chv ] || signal_pid="$VM_CHILD_PID"
  if kill -0 "$signal_pid" 2>/dev/null; then
    kill "$signal_pid" 2>/dev/null || ! kill -0 "$signal_pid" 2>/dev/null ||
      fail 'could not terminate rejected guest'
  fi
  serial_test_wait_exit "$VMM_PID" 10 || fail 'rejected guest did not terminate'
  wait "$VMM_PID" || status=$?
  if [ -n "$VM_CHILD_PID" ] && kill -0 "$VM_CHILD_PID" 2>/dev/null; then
    fail 'VMM child survived rejected boot'
  fi
  VMM_PID=''
  VM_CHILD_PID=''
  case "$VMM:$status" in
    qemu:0|qemu:33|qemu:143|chv:0|chv:143|fc:0|fc:143) ;;
    *) fail "rejected boot exit status $status" ;;
  esac
  SERIAL_VM_HAS_SSH=1
}

# Both data-only MBR disks and whole-device files must obey the backing flag.
for format in parted bare; do
  cp --sparse=always "$SCRATCH/partitions/root.img" "$TEST_VM_IMG_DIR/recovery-root.img"
  cp --sparse=always "$SCRATCH/partitions/$format.img" "$TEST_VM_IMG_DIR/recovery-data.img"
  cp "$ROOT_DIR/img_files/test-ro-root/system/cfg/sys-fs.toml" "$SCRATCH/recovery.toml"
  cat >> "$SCRATCH/recovery.toml" <<'TOML'

[[mount]]
path = "/user/data"
type = "motor-fs"
device = 1
TOML
  [ "$format" != parted ] || echo 'partition = 1' >> "$SCRATCH/recovery.toml"
  cp "$SCRATCH/recovery.toml" "$SCRATCH/recovery-writable.toml"
  echo 'read_only = true' >> "$SCRATCH/recovery.toml"
  export MOTO_IMAGE=recovery-root.img
  "$imager" block-mount-fixture config "$TEST_VM_IMG_DIR/$MOTO_IMAGE" "$SCRATCH/recovery.toml"
  data_before="$(sha256sum "$TEST_VM_IMG_DIR/recovery-data.img")"
  start_guest "$format-clean-ro" --extra-disk-ro recovery-data.img
  vm_ssh 'cat /user/data/label'
  stop_guest
  [ "$(sha256sum "$TEST_VM_IMG_DIR/recovery-data.img")" = "$data_before" ] || fail 'clean read-only data changed'
  "$imager" block-mount-fixture config "$TEST_VM_IMG_DIR/$MOTO_IMAGE" "$SCRATCH/recovery-writable.toml"
  reject_guest "$format-writable-on-ro" 'writable mount on read-only device' --extra-disk-ro recovery-data.img
  [ "$(sha256sum "$TEST_VM_IMG_DIR/recovery-data.img")" = "$data_before" ] || fail 'rejected writable data changed'
  "$imager" block-mount-fixture config "$TEST_VM_IMG_DIR/$MOTO_IMAGE" "$SCRATCH/recovery.toml"
  "$imager" block-mount-fixture dirty "$TEST_VM_IMG_DIR/recovery-data.img"
  dirty_before="$(sha256sum "$TEST_VM_IMG_DIR/recovery-data.img")"
  reject_guest "$format-dirty-ro" 'Motor FS journal recovery required on read-only backing' --extra-disk-ro recovery-data.img
  [ "$(sha256sum "$TEST_VM_IMG_DIR/recovery-data.img")" = "$dirty_before" ] || fail 'dirty read-only data changed'
  start_guest "$format-recover-ro-mount" --extra-disk recovery-data.img
  vm_ssh '[ -d /user/data/recovery-probe ] && cat /user/data/label'
  stop_guest
  "$imager" block-mount-fixture check-recovery "$TEST_VM_IMG_DIR/recovery-data.img"
done

root_formats=(mbr)
[ "$VMM" = qemu ] || root_formats+=(bare)
for format in "${root_formats[@]}"; do
  root="$TEST_VM_IMG_DIR/recovery-root-$format.img"
  if [ "$format" = mbr ]; then
    cp --sparse=always "$image" "$root"
  else
    "$imager" block-mount-fixture extract-root "$image" "$root"
  fi
  export MOTO_IMAGE="${root##*/}"
  root_before="$(sha256sum "$root")"
  start_guest "root-$format-clean-ro" --root-read-only
  vm_ssh '/user/bin/systest block-ro-root'
  stop_guest
  [ "$(sha256sum "$root")" = "$root_before" ] || fail 'clean read-only root changed'
  sed 's/read_only = true/read_only = false/' \
    "$ROOT_DIR/img_files/test-ro-root/system/cfg/sys-fs.toml" > "$SCRATCH/root-writable.toml"
  "$imager" block-mount-fixture config "$root" "$SCRATCH/root-writable.toml"
  root_before="$(sha256sum "$root")"
  reject_guest "root-$format-writable-on-ro" 'writable mount on read-only device' --root-read-only
  [ "$(sha256sum "$root")" = "$root_before" ] || fail 'rejected writable root changed'
  "$imager" block-mount-fixture config "$root" "$ROOT_DIR/img_files/test-ro-root/system/cfg/sys-fs.toml"
  "$imager" block-mount-fixture dirty "$root"
  root_before="$(sha256sum "$root")"
  reject_guest "root-$format-dirty-ro" 'Motor FS journal recovery required on read-only backing' --root-read-only
  [ "$(sha256sum "$root")" = "$root_before" ] || fail 'dirty read-only root changed'
  start_guest "root-$format-recover-ro-mount"
  vm_ssh '[ -d /recovery-probe ] && /user/bin/systest block-ro-root'
  stop_guest
  "$imager" block-mount-fixture check-recovery "$root"
done
"$imager" resize -i "$image" -o "$TEST_VM_IMG_DIR/resized-root.img" --size 256M
export MOTO_IMAGE=resized-root.img
resized_before="$(sha256sum "$TEST_VM_IMG_DIR/$MOTO_IMAGE")"
start_guest resized-root
vm_ssh '/user/bin/systest block-ro-root'
stop_guest
[ "$(sha256sum "$TEST_VM_IMG_DIR/$MOTO_IMAGE")" = "$resized_before" ] || fail 'resized read-only root changed'
echo "-------- TEST-BLOCK-MOUNTS PASS ---------"
