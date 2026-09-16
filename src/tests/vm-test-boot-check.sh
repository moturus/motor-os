# Strictly stop and reap the VMM in VMM_PID. The caller supplies SSH_OPTIONS;
# vmm and label identify the runner for exact exit-status diagnostics.
stop_test_vm_owned() {
  local vmm="$1" vmm_label="$2"
  local pid="$VMM_PID" process_status=0 requested_shutdown=0 waited=0
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
      if ! kill "$pid" 2>/dev/null; then
        # It may have exited between the liveness check and the signal.
        # A still-live child is a real teardown failure; an exited one must
        # continue to the sole wait below so ownership is released.
        if kill -0 "$pid" 2>/dev/null; then
          echo "vm-test: failed to SIGTERM owned $vmm_label pid $pid" >&2
          return 1
        fi
      fi
      waited=0
      while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 10 ]; do
        sleep 1
        waited=$((waited + 1))
      done
    fi
    if kill -0 "$pid" 2>/dev/null; then
      echo "vm-test: owned $vmm_label pid $pid outlived SIGTERM" >&2
      if ! kill -KILL "$pid" 2>/dev/null; then
        if kill -0 "$pid" 2>/dev/null; then
          echo "vm-test: failed to SIGKILL owned $vmm_label pid $pid" >&2
          return 1
        fi
      fi
    fi
  fi
  wait "$pid" || process_status=$?
  # The sole wait has released ownership. Clear before any validation can
  # fail and re-enter cleanup with an already-reaped pid.
  VMM_PID=""
  ! kill -0 "$pid" 2>/dev/null || {
    echo "vm-test: owned $vmm_label pid $pid survived wait" >&2
    return 1
  }
  case "$vmm:$process_status" in
    *:0|*:143) ;;
    qemu:33)
      # Motor writes 0x10 to isa-debug-exit: QEMU returns (0x10 << 1) | 1.
      [ "$requested_shutdown" = 1 ] || return 1
      ;;
    *) echo "vm-test: owned $vmm_label exited $process_status" >&2; return 1 ;;
  esac
}

# Boot one non-selected VMM through the shared SSH path. The caller sources
# vm-test-boot.sh and vm-test-selection.sh and supplies its standard fail().
run_test_vm_boot_check() (
  if [ "$#" -ne 3 ]; then
    echo "run_test_vm_boot_check: expected ROOT BUILD VMM" >&2
    exit 2
  fi
  local root="$1" build="$2" vmm="$3"
  local log_dir console_log
  local -a runner_args=()

  select_test_vm "$root" "$build" boot-check "$vmm"
  log_dir="$(mktemp -d "${TMPDIR:-/tmp}/motor-boot-$vmm.XXXXXX")"
  console_log="$log_dir/console.log"
  export MOTO_IMAGE="$TEST_VM_IMAGE"
  export MOTO_CHV_RUNTIME_DIR="$log_dir/chv"
  export MOTO_FC_RUNTIME_DIR="$log_dir/fc"
  export MOTO_FC_VSOCK_UDS=''
  VMM_PID=""

  fail() {
    echo "boot-check: $build $TEST_VM_LABEL: $* (logs: $log_dir)" >&2
    exit 1
  }

  cleanup_boot_check() {
    local status=$?
    trap - EXIT
    set +e
    if [ -n "$VMM_PID" ]; then
      stop_test_vm_owned "$vmm" "$TEST_VM_LABEL" || status=1
    fi
    exit "$status"
  }
  trap cleanup_boot_check EXIT

  if [ "$vmm" = qemu ] && [ -n "${FULL_TEST_QEMU_ARGS:-}" ]; then
    # Keep the suite's existing QEMU-only argument splitting.
    runner_args+=(${FULL_TEST_QEMU_ARGS})
  fi

  echo "boot-check: runner=$TEST_VM_RUNNER profile=$TEST_VM_PROFILE image=$MOTO_IMAGE logs=$log_dir"
  test_vm_configure_ssh
  start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$console_log" \
    "${runner_args[@]}"
  vm_ssh /system/bin/rush -c true
  kill -0 "$VMM_PID" 2>/dev/null ||
    fail "owned VMM exited after the SSH command"
  stop_test_vm_owned "$vmm" "$TEST_VM_LABEL" || fail "owned VMM teardown failed"
  echo "boot-check: $build $TEST_VM_LABEL PASS"
)
