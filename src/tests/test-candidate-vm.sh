#!/usr/bin/env bash
# Run candidate-only acceptance against an already built developer image.
set -euo pipefail

WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$WD/../.."
BUILD=debug
if [ "${1:-}" = --release ]; then
  BUILD=release
  shift
fi
[ "$#" = 0 ] || { echo "usage: $0 [--release]" >&2; exit 2; }

export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-8192}"
export FULL_TEST_VERIFY_DEV_SOURCES=1
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-cleanup.sh"
. "$WD/vm-test-selection.sh"

# Candidate selection remains QEMU-only until the suite-wide selector lands.
select_test_vm "$ROOT_DIR" "$BUILD" developer qemu
export MOTO_IMAGE="${FULL_TEST_IMAGE:-$TEST_VM_IMAGE}"

fail() {
  echo "test-candidate-vm: $*" >&2
  exit 1
}

test_vm_configure_ssh
VMM_PID=""
stop_candidate_vm() {
  set +e
  stop_vm "$VMM_PID"
  VMM_PID=""
}
trap stop_candidate_vm EXIT

echo "Starting candidate developer VM; console log: /tmp/test-candidate-vm.log"
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" /tmp/test-candidate-vm.log \
  ${FULL_TEST_QEMU_ARGS:-}
"$WD/test-rust-analyzer-native.sh"
"$WD/test-rust-analyzer-crates.sh"
"$WD/test-unwind.sh"
"$WD/test-rustfmt-native.sh"
echo "test-candidate-vm PASS"
