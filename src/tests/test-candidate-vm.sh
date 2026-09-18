#!/usr/bin/env bash
# Run candidate-only acceptance against an already built developer image.
set -euo pipefail

WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$WD/../.."
BUILD=debug
VMM=qemu
SEEN_RELEASE=0
SEEN_VMM=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      [ "$SEEN_RELEASE" = 0 ] || { echo "test-candidate-vm: duplicate --release" >&2; exit 2; }
      BUILD=release
      SEEN_RELEASE=1
      shift
      ;;
    --vmm)
      [ "$SEEN_VMM" = 0 ] || { echo "test-candidate-vm: duplicate --vmm" >&2; exit 2; }
      [ "$#" -ge 2 ] || { echo "test-candidate-vm: --vmm requires qemu or chv" >&2; exit 2; }
      VMM="$2"
      SEEN_VMM=1
      shift 2
      ;;
    --vmm=*)
      [ "$SEEN_VMM" = 0 ] || { echo "test-candidate-vm: duplicate --vmm" >&2; exit 2; }
      VMM="${1#--vmm=}"
      SEEN_VMM=1
      shift
      ;;
    *) echo "usage: $0 [--release] [--vmm qemu|chv]" >&2; exit 2 ;;
  esac
done
case "$VMM" in
  qemu|chv) ;;
  fc) echo "test-candidate-vm: Firecracker does not support developer images" >&2; exit 2 ;;
  *) echo "test-candidate-vm: unsupported VMM '$VMM'" >&2; exit 2 ;;
esac

export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-8192}"
export FULL_TEST_VERIFY_DEV_SOURCES=1
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-boot-check.sh"
. "$WD/vm-test-selection.sh"

select_test_vm "$ROOT_DIR" "$BUILD" developer "$VMM"
export MOTO_IMAGE="${FULL_TEST_IMAGE:-$TEST_VM_IMAGE}"
VM_RUNTIME_DIR="$(mktemp -d "${TMPDIR:-/tmp}/candidate-vm-runtime.XXXXXX")"
export MOTO_CHV_RUNTIME_DIR="$VM_RUNTIME_DIR/chv"

fail() {
  echo "test-candidate-vm: $*" >&2
  exit 1
}

test_vm_configure_ssh
VMM_PID=""
stop_candidate_vm() {
  local status=$?
  set +e
  trap - EXIT
  if [ -n "$VMM_PID" ]; then
    stop_test_vm_owned "$VMM" "$TEST_VM_LABEL" || {
      [ "$status" -ne 0 ] || status=1
    }
  fi
  exit "$status"
}
trap stop_candidate_vm EXIT

runner_args=()
if [ "$VMM" = qemu ] && [ -n "${FULL_TEST_QEMU_ARGS:-}" ]; then
  # Keep the existing candidate QEMU argument splitting.
  runner_args+=(${FULL_TEST_QEMU_ARGS})
fi
echo "test-candidate-vm: runner=$TEST_VM_RUNNER profile=$TEST_VM_PROFILE image=$MOTO_IMAGE"
echo "test-candidate-vm: console=/tmp/test-candidate-vm.log runtime=$VM_RUNTIME_DIR"
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" /tmp/test-candidate-vm.log \
  "${runner_args[@]}"
"$WD/test-rust-analyzer-native.sh"
"$WD/test-rust-analyzer-crates.sh"
"$WD/test-unwind.sh"
"$WD/test-rustfmt-native.sh"
kill -0 "$VMM_PID" 2>/dev/null ||
  fail "owned $TEST_VM_LABEL exited before final teardown"
stop_test_vm_owned "$VMM" "$TEST_VM_LABEL" ||
  fail "owned $TEST_VM_LABEL teardown failed"
echo "test-candidate-vm PASS"
