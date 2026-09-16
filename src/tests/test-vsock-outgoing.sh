#!/bin/bash
# Selected-VMM outgoing-peer phase. The existing IP-disabled
# serial discovery cases remain separate until their D16 conversion lands.

if [ "${TEST_VSOCK_TIMEOUT_ACTIVE:-0}" != 1 ]; then
  export TEST_VSOCK_TIMEOUT_ACTIVE=1
  timeout 300s "$0" "$@" < /dev/null
  status=$?
  if [ "$status" -eq 124 ]; then
    echo "test-vsock: timed out after 300 seconds" >&2
  fi
  exit "$status"
fi

set -euo pipefail

BUILD=debug
VMM=qemu
SEEN_RELEASE=0
SEEN_VMM=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      [ "$SEEN_RELEASE" = 0 ] || { echo "test-vsock: duplicate --release" >&2; exit 2; }
      BUILD=release
      SEEN_RELEASE=1
      shift
      ;;
    --vmm)
      [ "$SEEN_VMM" = 0 ] || { echo "test-vsock: duplicate --vmm" >&2; exit 2; }
      [ "$#" -ge 2 ] || { echo "test-vsock: --vmm requires qemu, chv, or fc" >&2; exit 2; }
      VMM="$2"
      SEEN_VMM=1
      shift 2
      ;;
    --vmm=*)
      [ "$SEEN_VMM" = 0 ] || { echo "test-vsock: duplicate --vmm" >&2; exit 2; }
      VMM="${1#--vmm=}"
      SEEN_VMM=1
      shift
      ;;
    *)
      echo "usage: $0 [--release] [--vmm qemu|chv|fc]" >&2
      exit 2
      ;;
  esac
done

case "$VMM" in qemu|chv|fc) ;; *) echo "test-vsock: unsupported VMM '$VMM'" >&2; exit 2 ;; esac

WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-selection.sh"

TEST_VM_PHASE=standard
if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = 1 ]; then
  TEST_VM_PHASE=developer
fi
select_test_vm "$ROOT_DIR" "$BUILD" "$TEST_VM_PHASE" "$VMM"
IMG_TARGET="${FULL_TEST_IMG_TARGET:-$TEST_VM_IMG_TARGET}"
IMAGE="${FULL_TEST_IMAGE:-${MOTO_IMAGE:-$TEST_VM_IMAGE}}"
case "$VMM:$IMAGE" in
  fc:*.img | fc:*.raw | qemu:*.qcow2 | qemu:*.img | qemu:*.raw | chv:*.qcow2 | chv:*.img | chv:*.raw) ;;
  fc:*) echo "test-vsock: Firecracker requires a raw image, not '$IMAGE'" >&2; exit 2 ;;
  *) echo "test-vsock: unsupported image filename '$IMAGE'" >&2; exit 2 ;;
esac
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/test-vsock.XXXXXX")"
RUNTIME_DIR="$(mktemp -d "$LOG_DIR/runtime.XXXXXX")"
CONSOLE_LOG="$LOG_DIR/console.log"
PEER_BIN="$LOG_DIR/vsock-peer"
GUEST_BIN="/user/tmp/$(basename "$LOG_DIR")-systest"
VSOCK_BASE="$RUNTIME_DIR/vsock"
VMM_PID=""
BACKEND_PID=""
PEER_PID=""
echo "test-vsock: logs preserved in $LOG_DIR"
echo "test-vsock: runner=$TEST_VM_RUNNER profile=$TEST_VM_PROFILE target=$IMG_TARGET image=$IMAGE"

fail() {
  echo "test-vsock: $BUILD $VMM: $*" >&2
  exit 1
}

for tool in flock make mktemp nproc rg rustc sed seq sftp ssh tee; do
  command -v "$tool" >/dev/null 2>&1 || fail "required host tool is missing: $tool"
done
case "$VMM" in
  qemu)
    command -v qemu-system-x86_64 >/dev/null 2>&1 || fail "required host tool is missing: qemu-system-x86_64"
    VHOST_DEVICE_VSOCK="${VHOST_DEVICE_VSOCK:-vhost-device-vsock}"
    command -v "$VHOST_DEVICE_VSOCK" >/dev/null 2>&1 || fail "required host tool is missing: $VHOST_DEVICE_VSOCK"
    backend_version="$("$VHOST_DEVICE_VSOCK" --version)"
    [ "$backend_version" = "vhost-device-vsock 0.3.0" ] ||
      fail "expected vhost-device-vsock 0.3.0, got '$backend_version'"
    ;;
  chv)
    command -v cloud-hypervisor-static >/dev/null 2>&1 ||
      fail "required host tool is missing: cloud-hypervisor-static"
    ;;
  fc)
    command -v firecracker >/dev/null 2>&1 || fail "required host tool is missing: firecracker"
    ;;
esac

stop_owned() {
  local pid="$1" name="$2" process_status=0
  [ -n "$pid" ] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || return 1
  fi
  wait "$pid" || process_status=$?
  case "$process_status" in 0|143) ;; *) echo "test-vsock: $name exited $process_status" >&2; return 1 ;; esac
  ! kill -0 "$pid" 2>/dev/null || { echo "test-vsock: $name pid $pid survived wait" >&2; return 1; }
}

stop_vmm_owned() {
  local pid="$1" process_status=0 waited=0 requested_shutdown=0
  [ -n "$pid" ] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    requested_shutdown=1
    timeout 30s ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 \
      motor@192.168.4.2 shutdown >/dev/null 2>&1 || true
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 20 ]; do
      sleep 1
      waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || return 1
      waited=0
      while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 10 ]; do
        sleep 1
        waited=$((waited + 1))
      done
    fi
    if kill -0 "$pid" 2>/dev/null; then
      echo "test-vsock: owned $TEST_VM_LABEL pid $pid outlived SIGTERM" >&2
      kill -KILL "$pid" 2>/dev/null || return 1
    fi
  fi
  wait "$pid" || process_status=$?
  case "$VMM:$process_status" in
    *:0|*:143) ;;
    qemu:33)
      # Motor writes 0x10 to isa-debug-exit: QEMU returns (0x10 << 1) | 1.
      [ "$requested_shutdown" = 1 ] || return 1
      ;;
    *) echo "test-vsock: owned $TEST_VM_LABEL exited $process_status" >&2; return 1 ;;
  esac
  ! kill -0 "$pid" 2>/dev/null || {
    echo "test-vsock: owned $TEST_VM_LABEL pid $pid survived wait" >&2
    return 1
  }
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [ -n "$PEER_PID" ]; then
    stop_owned "$PEER_PID" "host peer" || status=1
    PEER_PID=""
  fi
  if [ -n "$VMM_PID" ]; then
    stop_vmm_owned "$VMM_PID" || status=1
    VMM_PID=""
  fi
  if [ -n "$BACKEND_PID" ]; then
    stop_owned "$BACKEND_PID" "vhost-device-vsock" || status=1
    BACKEND_PID=""
  fi
  exit "$status"
}
trap cleanup EXIT

# Build only the selected suite image. Firecracker's standard suite needs the
# explicit raw image; developer selection supports QEMU and CHV only.
make -C "$ROOT_DIR" "$IMG_TARGET" systest BUILD="$BUILD" -j"$(nproc)"
rustc --edition 2024 -D warnings "$WD/vsock-peer.rs" -o "$PEER_BIN"

export MOTO_IMAGE="$IMAGE"
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}"
export MOTO_SMP="${MOTO_SMP:-4}"
export MOTO_CHV_RUNTIME_DIR="$RUNTIME_DIR/chv"
export MOTO_FC_RUNTIME_DIR="$RUNTIME_DIR/fc"

runner_args=()
case "$VMM" in
  qemu)
    export MOTO_SHARED_MEM=1
    "$VHOST_DEVICE_VSOCK" \
      --guest-cid 3 --socket "$RUNTIME_DIR/vhost" --uds-path "$VSOCK_BASE" \
      --queue-size 256 > "$LOG_DIR/backend.log" 2>&1 &
    BACKEND_PID="$!"
    for _ in $(seq 1 100); do
      [ -S "$RUNTIME_DIR/vhost" ] && break
      kill -0 "$BACKEND_PID" 2>/dev/null || fail "owned backend exited before readiness"
      sleep 0.1
    done
    [ -S "$RUNTIME_DIR/vhost" ] || fail "backend control socket did not become ready"
    kill -0 "$BACKEND_PID" 2>/dev/null || fail "owned backend exited at readiness"
    if [ -n "${FULL_TEST_QEMU_ARGS:-}" ]; then
      # Preserve the existing full-test knob's intentional shell splitting.
      runner_args+=(${FULL_TEST_QEMU_ARGS})
    fi
    runner_args+=(-chardev "socket,id=vsock,path=$RUNTIME_DIR/vhost" \
      -device vhost-user-vsock-pci,chardev=vsock)
    ;;
  chv)
    runner_args=(--vsock "cid=3,socket=$VSOCK_BASE")
    ;;
  fc)
    export MOTO_FC_VSOCK_UDS="$VSOCK_BASE"
    ;;
esac

test_vm_configure_ssh
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG" "${runner_args[@]}"

printf 'put %s %s\n' "$ROOT_DIR/build/bin/$BUILD/systest" "$GUEST_BIN" |
  sftp -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
    -i "$WD/test.key" motor@192.168.4.2

run_outgoing_case() {
  local action="$1"
  shift
  local case_name="$action"
  local verdict="$action"
  if [ "$#" -gt 0 ]; then
    case_name="$action-$(printf '%s-' "$@" | sed 's/-$//')"
    verdict="$action $*"
  fi
  local peer_log="$LOG_DIR/peer-$case_name.log"
  local guest_log="$LOG_DIR/guest-$case_name.log"
  local peer_status=0

  "$PEER_BIN" "$VSOCK_BASE" "$action" "$@" > "$peer_log" 2>&1 &
  PEER_PID="$!"
  for _ in $(seq 1 100); do
    rg -Fx "READY ${VSOCK_BASE}_70000" "$peer_log" >/dev/null && break
    kill -0 "$PEER_PID" 2>/dev/null || fail "owned host peer exited before readiness"
    sleep 0.1
  done
  rg -Fx "READY ${VSOCK_BASE}_70000" "$peer_log" >/dev/null ||
    fail "host peer did not become ready"

  vm_ssh "MOTOR_OS_CAPS=0xcc $GUEST_BIN test-vsock-outgoing 2 70000 $action $*" |
    tee "$guest_log"
  rg -Fx "vsock outgoing: $verdict PASS" "$guest_log" >/dev/null ||
    fail "guest PASS marker missing for $verdict"

  wait "$PEER_PID" || peer_status=$?
  PEER_PID=""
  [ "$peer_status" -eq 0 ] || fail "host peer failed for $action (status $peer_status)"
  rg -Fx "DONE $verdict" "$peer_log" >/dev/null || fail "host peer DONE marker missing for $verdict"
  kill -0 "$VMM_PID" 2>/dev/null || fail "owned $TEST_VM_LABEL exited after $action"
  if [ -n "$BACKEND_PID" ]; then
    kill -0 "$BACKEND_PID" 2>/dev/null || fail "owned backend exited after $action"
  fi
}

# Validate the functional first vertical on CHV before the other VMMs:
#   src/tests/test-vsock.sh --vmm chv
run_outgoing_case echo 0
run_outgoing_case echo 1
run_outgoing_case echo 4095
run_outgoing_case echo 4096
run_outgoing_case echo 4097
run_outgoing_case echo 65536
run_outgoing_case duplex 1048576 1048576
run_outgoing_case local-send-shutdown 4096 4096
run_outgoing_case local-receive-shutdown 4096 4096
run_outgoing_case unix-peer-close 4096
run_outgoing_case cancel-read 257
run_outgoing_case cancel-write 16384
run_outgoing_case cancel-before-poll-drop
run_outgoing_case cancel-queued-connect

stop_vmm_owned "$VMM_PID"
VMM_PID=""
stop_owned "$BACKEND_PID" "vhost-device-vsock"
BACKEND_PID=""
echo "test-vsock: $BUILD $VMM outgoing PASS"
