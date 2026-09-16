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
case "$#:${1:-}" in
  0:) ;;
  1:--release) BUILD=release ;;
  *)
    echo "usage: $0 [--release]" >&2
    exit 2
    ;;
esac

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."
IMG_DIR="$ROOT_DIR/vm_images/$BUILD"
. "$WD/vm-console-filter.sh"
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/test-vsock.XXXXXX")"
echo "test-vsock: logs preserved in $LOG_DIR"

for tool in cloud-hypervisor-static flock pgrep rg script; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "test-vsock: required host tool is missing: $tool" >&2
    exit 1
  }
done

make -C "$ROOT_DIR" vsock-test.img BUILD="$BUILD" -j"$(nproc)"

run_discovery() (
  local mode="$1"
  local runtime_dir console_log first_byte chv_command
  local wrapper_pid="" chv_pid="" wrapper_status=0 cleanup_status=0
  runtime_dir="$(mktemp -d "$LOG_DIR/$mode-runtime.XXXXXX")"
  console_log="$LOG_DIR/$mode-console.log"
  mkfifo "$runtime_dir/console-in"

  export MOTO_IMAGE=motor-os-vsock-test.img
  export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}"
  export MOTO_SMP="${MOTO_SMP:-4}"
  export MOTO_CHV_RUNTIME_DIR="$runtime_dir"

  fail() {
    echo "test-vsock: CHV $BUILD $mode: $*" >&2
    tail -100 "$console_log" >&2 || true
    exit 1
  }

  vm_alive() {
    local children
    kill -0 "$wrapper_pid" 2>/dev/null || return 1
    children="$(pgrep -P "$wrapper_pid" || true)"
    [ "$(printf '%s\n' "$children" | sed '/^$/d' | wc -l)" -eq 1 ] || return 1
    chv_pid="$children"
    kill -0 "$chv_pid" 2>/dev/null
  }

  cleanup() {
    local status=$?
    trap - EXIT
    exec 3>&-
    if [ -n "$chv_pid" ] && kill -0 "$chv_pid" 2>/dev/null; then
      # Leave script alive: its normal SIGCHLD path reaps this direct child.
      kill "$chv_pid" 2>/dev/null || cleanup_status=1
    elif [ -z "$chv_pid" ] && [ -n "$wrapper_pid" ] &&
        kill -0 "$wrapper_pid" 2>/dev/null; then
      # Launch failed before ownership of a direct child could be established.
      kill "$wrapper_pid" 2>/dev/null || cleanup_status=1
    fi
    if [ -n "$wrapper_pid" ]; then
      wait "$wrapper_pid" || wrapper_status=$?
      case "$wrapper_status" in
        0|143) ;;
        *) cleanup_status=1 ;;
      esac
    fi
    if [ -n "$chv_pid" ] && kill -0 "$chv_pid" 2>/dev/null; then
      echo "test-vsock: owned CHV pid $chv_pid survived wrapper teardown" >&2
      cleanup_status=1
    fi
    echo "test-vsock: CHV $BUILD $mode wrapper exit $wrapper_status after owned teardown"
    if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
      status=1
    fi
    exit "$status"
  }
  trap cleanup EXIT

  local -a runner=("$IMG_DIR/run-chv.sh")
  if [ "$mode" = present ]; then
    runner+=(--vsock "cid=3,socket=$runtime_dir/vsock")
  fi
  printf -v chv_command '%q ' "${runner[@]}"
  chv_command="exec $chv_command"

  # CHV only accepts serial input from a TTY. script supplies the PTY, forwards
  # termination to its direct exec'ed child, and suppresses host-side echo.
  exec 3<> "$runtime_dir/console-in"
  script -qef -E never -c "$chv_command" /dev/null \
    < "$runtime_dir/console-in" > "$console_log" 2>&1 &
  wrapper_pid=$!

  for _ in $(seq 1 100); do
    vm_alive && break
    kill -0 "$wrapper_pid" 2>/dev/null || fail "CHV wrapper exited during launch"
    sleep 0.1
  done
  vm_alive || fail "CHV child did not start"
  echo "test-vsock: CHV $BUILD $mode wrapper=$wrapper_pid child=$chv_pid"

  wait_line() {
    local offset="$1" pattern="$2" description="$3"
    for _ in $(seq 1 120); do
      if tail -c "+$offset" "$console_log" | filter_vm_console | tr -d '\r' |
          rg -a "$pattern" >/dev/null; then
        return
      fi
      vm_alive || fail "owned CHV exited while waiting for $description"
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
    rg -a '^VSOCK_DISCOVERY_STATUS=0$' >/dev/null || fail "guest test returned failure"
  tail -c "+$first_byte" "$console_log" | filter_vm_console | tr -d '\r' |
    rg -a "^vsock discovery: $mode PASS$" >/dev/null || fail "guest PASS marker missing"
  vm_alive || fail "owned CHV exited before the final liveness check"
  echo "test-vsock: CHV $BUILD $mode guest status=0 PASS"
)

run_discovery present
run_discovery disabled
echo "test-vsock: ALL PASS"
