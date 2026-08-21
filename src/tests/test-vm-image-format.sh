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

mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/fake-vmm" <<'EOF'
#!/bin/sh
: "${MOTOR_VM_ARG_LOG:?}"
printf '%s\n' "$@" > "$MOTOR_VM_ARG_LOG"
EOF
chmod +x "$FAKE_BIN/fake-vmm"
ln -s fake-vmm "$FAKE_BIN/qemu-system-x86_64"
ln -s fake-vmm "$FAKE_BIN/cloud-hypervisor-static"
ln -s fake-vmm "$FAKE_BIN/firecracker"

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

run_qemu
assert_arg "file=$VM_DIR/motor-os.qcow2,if=none,id=drive0,format=qcow2"

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

PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG" \
  MOTO_FC_RUNTIME_DIR="$TEST_ROOT/fc" "$VM_DIR/run-fc.sh" >/dev/null 2>&1
grep -Fq '"path_on_host": "'"$VM_DIR"'/motor-os-base.img"' \
  "$TEST_ROOT/fc/fc-config.json" || fail "Firecracker did not select the raw base image"

if MOTO_IMAGE=motor-os.qcow2 MOTO_FC_RUNTIME_DIR="$TEST_ROOT/fc" \
  "$VM_DIR/run-fc.sh" > /dev/null 2> "$ERROR_LOG"; then
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
