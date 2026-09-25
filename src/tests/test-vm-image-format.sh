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

. "$SCRIPT_DIR/vm-test-selection.sh"

assert_selection() {
  local build="$1" phase="$2" vmm="$3" target="$4" image="$5" label="$6"
  select_test_vm "$ROOT_DIR" "$build" "$phase" "$vmm"
  [ "$TEST_VM_PROFILE" = "$build" ] || fail "wrong profile for $phase/$vmm"
  [ "$TEST_VM_IMG_TARGET" = "$target" ] || fail "wrong target for $phase/$vmm"
  [ "$TEST_VM_IMAGE" = "$image" ] || fail "wrong image for $phase/$vmm"
  [ "$TEST_VM_LABEL" = "$label" ] || fail "wrong label for $phase/$vmm"
  [ "$TEST_VM_RUNNER" = "$ROOT_DIR/vm_images/$build/run-$vmm.sh" ] ||
    fail "wrong runner for $phase/$vmm"
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

assert_selection debug standard qemu main.img motor-os.qcow2 QEMU
assert_selection release standard chv main.img motor-os.qcow2 "Cloud Hypervisor"
assert_selection debug standard fc raw.img motor-os.img Firecracker
assert_selection debug boot-check qemu main.img motor-os.qcow2 QEMU
assert_selection debug boot-check chv main.img motor-os.qcow2 "Cloud Hypervisor"
assert_selection debug boot-check fc base.img motor-os-base.img Firecracker
assert_selection debug system-console qemu system-tty.img motor-os-system-tty.img QEMU
assert_selection debug system-console chv system-tty.img motor-os-system-tty.img "Cloud Hypervisor"
assert_selection debug system-console fc system-tty.img motor-os-system-tty.img Firecracker
assert_selection debug developer qemu dev.img motor-os-dev.qcow2 QEMU
assert_selection debug developer chv dev.img motor-os-dev.qcow2 "Cloud Hypervisor"
if select_test_vm "$ROOT_DIR" debug developer fc 2> "$ERROR_LOG"; then
  fail "VM selection accepted a Firecracker developer image"
fi
if select_test_vm "$ROOT_DIR" optimized standard qemu 2> "$ERROR_LOG"; then
  fail "VM selection accepted an invalid build profile"
fi
if select_test_vm "$ROOT_DIR" debug unknown qemu 2> "$ERROR_LOG"; then
  fail "VM selection accepted an invalid test phase"
fi
if select_test_vm "$ROOT_DIR" debug standard unknown 2> "$ERROR_LOG"; then
  fail "VM selection accepted an invalid VMM"
fi
if select_test_vm "$ROOT_DIR" debug standard 2> "$ERROR_LOG"; then
  fail "VM selection accepted an incomplete matrix request"
fi

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

# Exercise all public launchers with fake VMMs, isolated from host resources.
(
  export PATH="$FAKE_BIN:$PATH" MOTOR_VM_ARG_LOG="$ARG_LOG"
  export MOTO_QEMU_LOCK="$TEST_ROOT/options.lock" MOTO_HUGEPAGES=0
  export MOTO_CHV_RUNTIME_DIR="$TEST_ROOT/chv" MOTO_FC_RUNTIME_DIR="$TEST_ROOT/fc"
  unset MOTO_IMAGE MOTO_CPU_AFFINITY MOTO_SHARED_MEM MOTO_FC_VSOCK_UDS

  run_options() {
    local script="$runner"
    if [ "$runner" = dev-chv ]; then
      script=dev
      set -- --vmm chv "$@"
    fi
    "$VM_DIR/run-$script.sh" "$@" > /dev/null 2> "$ERROR_LOG"
  }

  assert_resources() {
    local cpus="$1" memory="$2"
    case "$runner" in
      fc)
        grep -Fxq "    \"vcpu_count\": $cpus," "$TEST_ROOT/fc/fc-config.json" ||
          fail "wrong Firecracker CPU count"
        grep -Fxq "    \"mem_size_mib\": $memory" "$TEST_ROOT/fc/fc-config.json" ||
          fail "wrong Firecracker memory size"
        ;;
      chv | dev-chv) assert_arg "boot=$cpus"; assert_arg "size=${memory}M" ;;
      *) assert_arg "-smp"; assert_arg "$cpus"; assert_arg "${memory}M" ;;
    esac
  }

  for runner in qemu qemu-echr chv fc dev dev-chv; do
    unset MOTO_SMP MOTO_MEMORY_MIB
    run_options
    case "$runner" in
      fc) assert_resources 2 64 ;;
      dev*) assert_resources 8 8192 ;;
      *) assert_resources 4 1024 ;;
    esac
    export MOTO_SMP=6 MOTO_MEMORY_MIB=768
    run_options
    assert_resources 6 768
    run_options --cpus 3 --memory 512M
    assert_resources 3 512
    run_options --memory=2G --cpus=5 -- 'argument with spaces' --cpus=passthrough
    assert_resources 5 2048
    assert_arg 'argument with spaces'
    assert_arg --cpus=passthrough
    assert_no_arg --cpus=5
    assert_no_arg --memory=2G
    if [ "$runner" = qemu-echr ]; then
      assert_arg -echr
      assert_arg 0x14
    fi

    for option in --cpus --memory; do
      for value in '' 0 -1 1.5 01 invalid; do
        rm -f "$ARG_LOG"
        if run_options "$option=$value"; then
          fail "$runner accepted $option=$value"
        fi
        [ ! -e "$ARG_LOG" ] || fail "$runner launched with invalid options"
      done
      if run_options "$option"; then
        fail "$runner accepted a missing $option value"
      fi
    done
    for value in 512 0M 01G 1m 1g 1MB 1.5G 9000000000G 99999999999999999999M; do
      if run_options --memory "$value"; then
        fail "$runner accepted --memory $value"
      fi
    done
    rm -f "$ARG_LOG"
    run_options --help
    [ ! -e "$ARG_LOG" ] || fail "$runner launched for --help"
  done

  runner=dev
  run_options --cpus 3 --vmm chv --memory 1G
  assert_arg boot=3
  assert_arg size=1024M
  run_options --vmm chv -- --cpus boot=7 --memory size=3G
  assert_arg boot=7
  assert_arg size=3G

  runner=qemu
  MOTO_SHARED_MEM=1 run_options --memory 2G -monitor 'unix:monitor path,server'
  assert_arg 'memory-backend-memfd,id=mem0,size=2048M,share=on'
  assert_arg -monitor
  assert_arg 'unix:monitor path,server'
)

echo "test-vm-image-format: PASS"
