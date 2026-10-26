#!/usr/bin/env bash
#
# prepare-dev-image.sh -- the last step of `make dev.img`.
#
# The developer image stages Motor OS library sources in
# /devtools/src/motor-os/sys/lib for native `lorry test` runs. Lorry admits a
# workspace and compiles its dependencies for Motor OS only on Motor OS, so the
# image build boots the new image once to do both, and the native test step
# needs neither. It leaves on the image the workspace's Cargo.lock, its
# admission record, the motor user's approval, and the dependencies compiled
# into the Interactive Lorry cache.

usage() {
  echo "usage: $0 debug|release" >&2
  exit 2
}

[ "$#" -eq 1 ] || usage
case "$1" in debug|release) BUILD="$1" ;; *) usage ;; esac
ROOT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)"

# Preparation takes about 10 seconds on a release image and 4 minutes on a
# debug one. A stalled boot or guest command must not hold the build, so the
# run has a deadline; timeout stops its whole process group, the VM included.
# stdin is never a terminal, as for the tests.
if [ "${PREPARE_DEV_IMAGE_TIMEOUT_ACTIVE:-0}" != 1 ]; then
  export PREPARE_DEV_IMAGE_TIMEOUT_ACTIVE=1
  deadline=300
  [ "$BUILD" = release ] || deadline=1200
  set -m
  timeout --kill-after=30s "${deadline}s" "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -ne 0 ]; then
    [ "$status" -ne 124 ] || echo "prepare-dev-image: timed out after $deadline seconds" >&2
    # A half-prepared image must not pass for a prepared one.
    rm -f "$ROOT_DIR/vm_images/$BUILD/motor-os-dev.qcow2"
    echo "prepare-dev-image: removed vm_images/$BUILD/motor-os-dev.qcow2" >&2
  fi
  exit "$status"
fi

set -euo pipefail

WD="$ROOT_DIR/src/tests"
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-boot-check.sh"
. "$WD/vm-test-selection.sh"
select_test_vm "$ROOT_DIR" "$BUILD" developer qemu
export MOTO_IMAGE="$TEST_VM_IMAGE"
# The cache keys of dependencies with build scripts cover NUM_JOBS, so this
# compile and the test in test-dev-sources.sh both use four jobs. The VM size
# changes only how long this takes.
export MOTO_SMP=4 MOTO_MEMORY_MIB=4096
STAGED=/devtools/src/motor-os/sys/lib
work="$(mktemp -d "$ROOT_DIR/build/prepare-dev-image.XXXXXX")"
VMM_PID=""

fail() {
  echo "prepare-dev-image: $*" >&2
  exit 1
}

# Forced teardown is for failures only: the caller then removes the image.
cleanup() {
  local status=$?
  set +e
  trap - EXIT
  if [ -n "$VMM_PID" ]; then
    stop_test_vm_owned qemu "$TEST_VM_LABEL"
    [ "$status" -ne 0 ] || status=1
  fi
  if [ "$status" -eq 0 ]; then
    rm -rf "$work"
  elif [ -f "$work/console.log" ]; then
    echo "prepare-dev-image: the VM console is in $work/console.log" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM

# A forced stop can lose what the guest has not flushed to its disk, so the
# image is prepared only when the guest shuts down by itself.
shut_down_vm() {
  local waited=0 status=0
  # The session may end with an error as the guest goes down; the VM's own
  # exit decides.
  timeout 30s ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 \
    motor@192.168.4.2 shutdown > /dev/null 2>&1 || true
  while kill -0 "$VMM_PID" 2>/dev/null && [ "$waited" -lt 60 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$VMM_PID" 2>/dev/null; then
    fail "$TEST_VM_LABEL did not shut down within 60 seconds"
  fi
  wait "$VMM_PID" || status=$?
  VMM_PID=""
  # Motor writes 0x10 to isa-debug-exit: QEMU returns (0x10 << 1) | 1.
  [ "$status" -eq 33 ] || fail "$TEST_VM_LABEL exited with status $status, not by shutting down"
}

"$ROOT_DIR/src/build-scripts/sys-lib-workspace.sh" --offline "$work/lib"
test_vm_configure_ssh
# The console goes to its log only; failures print it.
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$work/console.log" > /dev/null
vm_ssh "/system/bin/rush -c 'cat > $STAGED/Cargo.lock'" < "$work/lib/Cargo.lock" ||
  fail "cannot install $STAGED/Cargo.lock"
vm_ssh "cd $STAGED && /devtools/bin/lorry -q vendor --locked --offline --accept-all" ||
  fail "cannot admit $STAGED offline; if its dependencies changed, run" \
    "src/build-motor-os.sh --sys-lib-deps-only and build the image again"
vm_ssh "cd $STAGED && /devtools/bin/lorry -q test --no-run -j 4" > /dev/null ||
  fail "cannot compile the tests of $STAGED"
vm_ssh "/system/bin/rm -r $STAGED/target" || fail "cannot remove $STAGED/target"
shut_down_vm
echo "prepare-dev-image: admitted $STAGED and compiled its dependencies in ${SECONDS}s"
