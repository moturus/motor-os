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

IMG_DIR="$ROOT_DIR/vm_images/$BUILD"
export MOTO_IMAGE="${FULL_TEST_IMAGE:-motor-os-dev.qcow2}"
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-8192}"
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-cleanup.sh"

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
start_test_vm "$IMG_DIR" /tmp/test-candidate-vm.log
"$WD/test-rust-analyzer-native.sh"
"$WD/test-rust-analyzer-crates.sh"
echo "test-candidate-vm PASS"
