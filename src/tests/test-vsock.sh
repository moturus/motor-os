#!/bin/bash

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
if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = 1 ] && [ "$VMM" = fc ]; then
  echo "test-vsock: Firecracker does not support developer images" >&2
  exit 2
fi

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."
. "$WD/vm-console-filter.sh"
. "$WD/vm-cleanup.sh"
. "$WD/vm-test-selection.sh"
. "$WD/vm-test-serial.sh"
. "$WD/vm-vsock-backend.sh"
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/test-vsock.XXXXXX")"
echo "test-vsock: logs preserved in $LOG_DIR"

for tool in flock; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "test-vsock: required host tool is missing: $tool" >&2
    exit 1
  }
done
case "$VMM" in
  qemu)
    resolve_vsock_backend "$ROOT_DIR" || exit 1
    discovery_tools=(qemu-system-x86_64)
    ;;
  chv) discovery_tools=(cloud-hypervisor-static pgrep script) ;;
  fc) discovery_tools=(firecracker) ;;
esac
for tool in "${discovery_tools[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "test-vsock: required host tool is missing: $tool" >&2
    exit 1
  }
done
# Both the peer and IP-disabled serial discovery phases use the selected VMM.
outgoing_args=(--vmm "$VMM")
[ "$BUILD" = release ] && outgoing_args=(--release "${outgoing_args[@]}")
"$WD/test-vsock-outgoing.sh" "${outgoing_args[@]}"

select_test_vm "$ROOT_DIR" "$BUILD" system-console "$VMM"
make -C "$ROOT_DIR" vsock-test.img BUILD="$BUILD" -j"$(nproc)"

run_discovery() (
  local mode="$1"
  local runtime_dir console_log first_byte backend_status=0 cleanup_status=0
  local -a runner_args=()
  runtime_dir="$(mktemp -d "$LOG_DIR/$mode-runtime.XXXXXX")"
  console_log="$LOG_DIR/$mode-console.log"
  mkfifo "$runtime_dir/console-in"

  export MOTO_IMAGE=motor-os-vsock-test.img
  export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}"
  export MOTO_SMP="${MOTO_SMP:-4}"
  export MOTO_CHV_RUNTIME_DIR="$runtime_dir/chv"
  export MOTO_FC_RUNTIME_DIR="$runtime_dir/fc"
  export MOTO_FC_VSOCK_UDS=''
  export SERIAL_VM_HAS_SSH=0
  VMM_PID=""
  VM_CHILD_PID=""
  BACKEND_PID=""

  fail() {
    echo "test-vsock: $TEST_VM_LABEL $BUILD $mode: $*" >&2
    tail -100 "$console_log" >&2 || true
    exit 1
  }

  stop_backend() {
    local owned_pid
    [ -n "$BACKEND_PID" ] || return 0
    owned_pid="$BACKEND_PID"
    if kill -0 "$owned_pid" 2>/dev/null; then
      kill "$owned_pid" 2>/dev/null || return 1
    fi
    wait "$owned_pid" || backend_status=$?
    # The sole wait released ownership; clear before status validation can
    # return through cleanup with a stale, already-reaped pid.
    BACKEND_PID=""
    case "$backend_status" in 0|143) ;; *) return 1 ;; esac
    ! kill -0 "$owned_pid" 2>/dev/null || return 1
  }

  cleanup() {
    local status=$?
    trap - EXIT
    set +e
    exec 3>&-
    stop_serial_test_vm || cleanup_status=1
    stop_backend || cleanup_status=1
    [ "$status" -ne 0 ] || status="$cleanup_status"
    exit "$status"
  }
  trap cleanup EXIT

  if [ "$VMM" = qemu ] && [ -n "${FULL_TEST_QEMU_ARGS:-}" ]; then
    # Preserve the existing full-test knob's intentional shell splitting.
    runner_args+=(${FULL_TEST_QEMU_ARGS})
  fi
  if [ "$mode" = present ]; then
    case "$VMM" in
      qemu)
        export MOTO_SHARED_MEM=1
        "$VHOST_DEVICE_VSOCK" --guest-cid 3 --socket "$runtime_dir/vhost" \
          --uds-path "$runtime_dir/vsock" --queue-size 256 \
          > "$runtime_dir/backend.log" 2>&1 &
        BACKEND_PID="$!"
        for _ in $(seq 1 100); do
          [ -S "$runtime_dir/vhost" ] && break
          kill -0 "$BACKEND_PID" 2>/dev/null || fail "vsock backend exited before readiness"
          sleep 0.1
        done
        [ -S "$runtime_dir/vhost" ] || fail "vsock backend did not become ready"
        kill -0 "$BACKEND_PID" 2>/dev/null || fail "vsock backend exited at readiness"
        runner_args+=(-chardev "socket,id=vsock,path=$runtime_dir/vhost" \
          -device vhost-user-vsock-pci,chardev=vsock)
        ;;
      chv) runner_args+=(--vsock "cid=3,socket=$runtime_dir/vsock") ;;
      fc) export MOTO_FC_VSOCK_UDS="$runtime_dir/vsock" ;;
    esac
  fi

  exec 3<> "$runtime_dir/console-in"
  start_serial_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$console_log" \
    "$runtime_dir/console-in" "${runner_args[@]}"

  wait_line() {
    local offset="$1" pattern="$2" description="$3"
    for _ in $(seq 1 120); do
      if tail -c "+$offset" "$console_log" | filter_vm_console | tr -d '\r' |
          grep -aE "$pattern" >/dev/null; then
        return
      fi
      serial_test_vm_alive || fail "owned $TEST_VM_LABEL exited while waiting for $description"
      sleep 0.5
    done
    fail "console did not emit $description"
  }

  wait_line 1 '/user\$' 'the System console prompt'
  first_byte=$(( $(wc -c < "$console_log") + 1 ))
  printf 'MOTOR_OS_CAPS=0xcc /user/bin/systest test-vsock-discovery %s; echo VSOCK_DISCOVERY_STATUS=$?' \
    "$mode" >&3
  printf '\r' >&3
  wait_line "$first_byte" '^VSOCK_DISCOVERY_STATUS=[0-9]+$' 'the guest status marker'

  tail -c "+$first_byte" "$console_log" | filter_vm_console | tr -d '\r' |
    grep -aE '^VSOCK_DISCOVERY_STATUS=0$' >/dev/null || fail "guest test returned failure"
  tail -c "+$first_byte" "$console_log" | filter_vm_console | tr -d '\r' |
    grep -aE "^vsock discovery: $mode PASS$" >/dev/null || fail "guest PASS marker missing"
  serial_test_vm_alive || fail "owned $TEST_VM_LABEL exited before the final liveness check"
  if [ "$VMM" = qemu ] && [ "$mode" = present ]; then
    kill -0 "$BACKEND_PID" 2>/dev/null || fail "owned backend exited before the final liveness check"
  fi
  echo "test-vsock: $TEST_VM_LABEL $BUILD $mode guest status=0 PASS"
)

run_discovery present
run_discovery disabled
echo "test-vsock: ALL PASS"
