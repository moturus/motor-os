#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
VM_DIR="$ROOT_DIR/src/vm_scripts"
TEST_ROOT="$(mktemp -d /tmp/motor-image-format-test-XXXXXX)"
FAKE_BIN="$TEST_ROOT/bin"
ARG_LOG="$TEST_ROOT/args"
ERROR_LOG="$TEST_ROOT/error"

cleanup() {
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

fail() {
  echo "test-vm-image-format: $*" >&2
  exit 1
}

assert_arg() {
  local expected="$1"
  grep -Fxq -- "$expected" "$ARG_LOG" ||
    fail "missing VMM argument '$expected'"
}

assert_no_arg() {
  local unexpected="$1"
  if grep -Fxq -- "$unexpected" "$ARG_LOG"; then
    fail "unexpected VMM argument '$unexpected'"
  fi
}

mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/fake-vmm" <<'EOF'
#!/bin/sh
: "${MOTOR_VM_ARG_LOG:?}"
if [ -n "${MOTOR_VM_EXPECT_LOCK:-}" ]; then
  exec 7> "$MOTOR_VM_EXPECT_LOCK"
  if flock -n 7; then
    echo "fake-vmm: runner lock was not held across exec" >&2
    exit 1
  fi
fi
printf '%s\n' "$@" > "$MOTOR_VM_ARG_LOG"
EOF
chmod +x "$FAKE_BIN/fake-vmm"
ln -s fake-vmm "$FAKE_BIN/qemu-system-x86_64"
ln -s fake-vmm "$FAKE_BIN/cloud-hypervisor-static"
ln -s fake-vmm "$FAKE_BIN/firecracker"

# The raw standard image is opt-in. Exercise the inner make graph directly so
# this remains independent of the top-level logging wrapper.
make -n -C "$ROOT_DIR" MAKELEVEL=1 > "$TEST_ROOT/make-default"
for target in all images; do
  make -n -C "$ROOT_DIR" MAKELEVEL=1 "$target" > "$TEST_ROOT/make-$target"
done
for graph in default all images; do
  if grep -Fq -- '--raw-output' "$TEST_ROOT/make-$graph"; then
    fail "$graph make graph unexpectedly builds the raw standard image"
  fi
done
make -n -C "$ROOT_DIR" MAKELEVEL=1 raw.img > "$TEST_ROOT/make-raw"
grep -Fq -- 'motor-os.yaml --raw-output motor-os.img' "$TEST_ROOT/make-raw" ||
  fail "raw.img make graph does not request the raw standard image"

run_qemu() {
  PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG" \
    MOTO_QEMU_LOCK="$TEST_ROOT/qemu.lock" "$VM_DIR/run-qemu.sh" "$@" \
    >/dev/null 2>&1
}

run_chv() {
  PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG" \
    MOTO_CHV_RUNTIME_DIR="$TEST_ROOT/chv" "$VM_DIR/run-chv.sh" "$@" \
    >/dev/null 2>&1
}

run_fc() {
  PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG" \
    MOTO_QEMU_LOCK="${MOTO_QEMU_LOCK:-$TEST_ROOT/qemu.lock}" \
    MOTOR_VM_EXPECT_LOCK="${MOTO_QEMU_LOCK:-$TEST_ROOT/qemu.lock}" \
    MOTO_FC_RUNTIME_DIR="$TEST_ROOT/fc" "$VM_DIR/run-fc.sh" "$@"
}

MOTO_SHARED_MEM='' run_qemu
assert_arg "file=$VM_DIR/motor-os.qcow2,if=none,id=drive0,format=qcow2"
assert_no_arg "memory-backend-memfd,id=mem0,size=1024M,share=on"
assert_no_arg "memory-backend=mem0"

MOTO_MEMORY_MIB=1024 MOTO_HUGEPAGES=0 MOTO_SHARED_MEM=1 run_qemu
assert_arg "-object"
assert_arg "memory-backend-memfd,id=mem0,size=1024M,share=on"
assert_arg "-machine"
assert_arg "memory-backend=mem0"
assert_no_arg "-mem-path"

MOTO_IMAGE=motor-os-base.img run_qemu
assert_arg "file=$VM_DIR/motor-os-base.img,if=none,id=drive0,format=raw"

if MOTO_IMAGE=motor-os.bad run_qemu 2> "$ERROR_LOG"; then
  fail "QEMU accepted an unsupported image suffix"
fi

run_chv
assert_arg "path=$VM_DIR/motor-os.qcow2,image_type=qcow2"

MOTO_IMAGE=motor-os-base.img run_chv
assert_arg "path=$VM_DIR/motor-os-base.img,image_type=raw"

PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG" \
  MOTO_QEMU_LOCK="$TEST_ROOT/qemu.lock" "$VM_DIR/run-dev.sh" --vmm qemu \
  >/dev/null 2>&1
assert_arg "file=$VM_DIR/motor-os-dev.qcow2,if=none,id=drive0,format=qcow2"

MOTO_FC_VSOCK_UDS='' run_fc >/dev/null 2>&1
grep -Fq '"path_on_host": "'"$VM_DIR"'/motor-os-base.img"' \
  "$TEST_ROOT/fc/fc-config.json" || fail "Firecracker did not select the raw base image"
if grep -Fq '"vsock"' "$TEST_ROOT/fc/fc-config.json"; then
  fail "Firecracker enabled vsock without MOTO_FC_VSOCK_UDS"
fi

MOTO_IMAGE=motor-os.img MOTO_FC_VSOCK_UDS='' run_fc >/dev/null 2>&1
grep -Fq '"path_on_host": "'"$VM_DIR"'/motor-os.img"' \
  "$TEST_ROOT/fc/fc-config.json" || fail "Firecracker did not select the raw standard image"

MOTO_FC_VSOCK_UDS="$TEST_ROOT/fc/vsock" run_fc >/dev/null 2>&1
grep -Fq '"guest_cid": 3' "$TEST_ROOT/fc/fc-config.json" ||
  fail "Firecracker vsock config lacks guest CID 3"
grep -Fq '"uds_path": "'"$TEST_ROOT"'/fc/vsock"' \
  "$TEST_ROOT/fc/fc-config.json" || fail "Firecracker vsock config lacks its UDS path"

rm -f "$ARG_LOG"
if MOTO_FC_VSOCK_UDS=relative/path run_fc 2> "$ERROR_LOG"; then
  fail "Firecracker accepted a relative vsock UDS path"
fi
grep -Fq "MOTO_FC_VSOCK_UDS must be an absolute path" "$ERROR_LOG" ||
  fail "Firecracker did not explain its invalid vsock UDS path"
[ ! -e "$ARG_LOG" ] || fail "Firecracker launched with an invalid vsock UDS path"

rm -f "$ARG_LOG"
if MOTO_FC_VSOCK_UDS="$TEST_ROOT/fc/vsock bad" run_fc 2> "$ERROR_LOG"; then
  fail "Firecracker accepted an unsafe vsock UDS path"
fi
grep -Fq "invalid MOTO_FC_VSOCK_UDS" "$ERROR_LOG" ||
  fail "Firecracker did not explain its unsafe vsock UDS path"
[ ! -e "$ARG_LOG" ] || fail "Firecracker launched with an unsafe vsock UDS path"

exec 8> "$TEST_ROOT/common-vm.lock"
flock -n 8
rm -f "$ARG_LOG"
if MOTO_QEMU_LOCK="$TEST_ROOT/common-vm.lock" run_fc 2> "$ERROR_LOG"; then
  fail "Firecracker ignored the common Motor OS VM lock"
fi
grep -Fq "another Motor OS VM owns $TEST_ROOT/common-vm.lock" "$ERROR_LOG" ||
  fail "Firecracker did not explain the common VM lock conflict"
[ ! -e "$ARG_LOG" ] || fail "Firecracker launched while the common VM lock was held"
exec 8>&-

if MOTO_IMAGE=motor-os.qcow2 run_fc > /dev/null 2> "$ERROR_LOG"; then
  fail "Firecracker accepted a qcow2 image"
fi
grep -Fq "Firecracker requires a raw image" "$ERROR_LOG" ||
  fail "Firecracker did not explain its raw-image requirement"

if "$VM_DIR/run-dev.sh" --vmm fc > /dev/null 2> "$ERROR_LOG"; then
  fail "run-dev accepted Firecracker"
fi
grep -Fq "expected qemu or chv" "$ERROR_LOG" ||
  fail "run-dev did not report its supported VMMs"

echo "test-vm-image-format: PASS"
