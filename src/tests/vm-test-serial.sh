# Selected-runner serial launch for tests that own a console-input FIFO.
# Callers provide fail(), SSH_OPTIONS, VMM, and initialize VMM_PID/VM_CHILD_PID.
start_serial_test_vm() {
  local runner="$1" label="$2" console_log="$3" input_fifo="$4"
  local command children required_tool
  local -a required_tools
  shift 4

  [ -x "$runner" ] || fail "VM launcher is missing: $runner"
  case "$VMM" in
    qemu) required_tools=(flock qemu-system-x86_64) ;;
    chv) required_tools=(flock cloud-hypervisor-static pgrep script) ;;
    fc) required_tools=(firecracker flock) ;;
    *) fail "unsupported serial VMM '$VMM'" ;;
  esac
  for required_tool in "${required_tools[@]}"; do
    command -v "$required_tool" >/dev/null 2>&1 ||
      fail "required host tool is missing: $required_tool"
  done
  echo "serial VM: runner=$runner label=$label profile=$TEST_VM_PROFILE image=$MOTO_IMAGE log=$console_log"
  if [ "$VMM" = chv ]; then
    printf -v command '%q ' "$runner" "$@"
    command="exec $command"
    script -qef -E never -c "$command" /dev/null \
      < "$input_fifo" > "$console_log" 2>&1 &
    VMM_PID="$!"
    for _ in $(seq 1 100); do
      children="$(pgrep -P "$VMM_PID" || true)"
      if [ "$(printf '%s\n' "$children" | sed '/^$/d' | wc -l)" -eq 1 ]; then
        VM_CHILD_PID="$children"
        kill -0 "$VM_CHILD_PID" 2>/dev/null && return
      fi
      kill -0 "$VMM_PID" 2>/dev/null ||
        fail "$label PTY wrapper exited during launch"
      sleep 0.1
    done
    fail "$label child did not start behind its PTY wrapper"
  fi

  "$runner" "$@" < "$input_fifo" > "$console_log" 2>&1 &
  VMM_PID="$!"
}

serial_test_vm_alive() {
  kill -0 "$VMM_PID" 2>/dev/null || return 1
  if [ "$VMM" = chv ]; then
    [ -n "$VM_CHILD_PID" ] && kill -0 "$VM_CHILD_PID" 2>/dev/null
  fi
}

serial_test_wait_exit() {
  local pid="$1" limit="$2" waited=0
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$limit" ]; do
    sleep 1
    waited=$((waited + 1))
  done
  ! kill -0 "$pid" 2>/dev/null
}

stop_serial_test_vm() {
  local process_status=0 owned_child owned_pid requested_shutdown=0

  [ -n "$VMM_PID" ] || return 0
  owned_pid="$VMM_PID"
  owned_child="$VM_CHILD_PID"
  if [ "$VMM" != chv ]; then
    if kill -0 "$owned_pid" 2>/dev/null; then
      if [ "${SERIAL_VM_HAS_SSH:-1}" = 1 ]; then
        requested_shutdown=1
        timeout 30s ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 \
          motor@192.168.4.2 shutdown >/dev/null 2>&1 || true
        if ! serial_test_wait_exit "$owned_pid" 20; then
          kill "$owned_pid" 2>/dev/null || return 1
          serial_test_wait_exit "$owned_pid" 10 ||
            kill -KILL "$owned_pid" 2>/dev/null || return 1
        fi
      else
        kill "$owned_pid" 2>/dev/null || return 1
        serial_test_wait_exit "$owned_pid" 10 ||
          kill -KILL "$owned_pid" 2>/dev/null || return 1
      fi
    fi
    wait "$owned_pid" || process_status=$?
    VMM_PID=""
    VM_CHILD_PID=""
    if kill -0 "$owned_pid" 2>/dev/null; then
      echo "serial VM: owned $TEST_VM_LABEL pid $owned_pid survived teardown" >&2
      return 1
    fi
    case "$VMM:$process_status" in
      *:0|*:143) ;;
      qemu:33)
        # Motor writes 0x10 to isa-debug-exit: QEMU returns (0x10 << 1) | 1.
        [ "$requested_shutdown" = 1 ] || return 1
        ;;
      *) echo "serial VM: owned $TEST_VM_LABEL exited $process_status" >&2; return 1 ;;
    esac
    echo "serial VM: $TEST_VM_LABEL pid=$owned_pid exit=$process_status"
    return 0
  fi

  if [ "${SERIAL_VM_HAS_SSH:-1}" = 1 ] && serial_test_vm_alive; then
    requested_shutdown=1
    timeout 30s ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 \
      motor@192.168.4.2 shutdown >/dev/null 2>&1 || true
    if ! serial_test_wait_exit "$owned_pid" 20; then
      echo "serial VM: $TEST_VM_LABEL did not exit after guest shutdown" >&2
    fi
  fi

  if kill -0 "$owned_pid" 2>/dev/null; then
    if [ -n "$owned_child" ]; then
      # Keep script alive while its normal SIGCHLD path reaps the direct CHV
      # child. Signalling script first can orphan a transient zombie.
      if kill -0 "$owned_child" 2>/dev/null; then
        kill "$owned_child" 2>/dev/null || return 1
      fi
      if ! serial_test_wait_exit "$owned_pid" 10; then
        if kill -0 "$owned_child" 2>/dev/null; then
          kill -KILL "$owned_child" 2>/dev/null || return 1
        else
          kill "$owned_pid" 2>/dev/null || return 1
        fi
      fi
    else
      # Launch failed before ownership of a unique direct child was recorded.
      kill "$owned_pid" 2>/dev/null || return 1
      serial_test_wait_exit "$owned_pid" 10 ||
        kill -KILL "$owned_pid" 2>/dev/null || return 1
    fi
  fi
  wait "$owned_pid" || process_status=$?
  VMM_PID=""
  VM_CHILD_PID=""
  if [ -n "$owned_child" ] && kill -0 "$owned_child" 2>/dev/null; then
    echo "serial VM: owned CHV child $owned_child survived wrapper teardown" >&2
    return 1
  fi
  kill -0 "$owned_pid" 2>/dev/null && {
    echo "serial VM: owned CHV wrapper $owned_pid survived wait" >&2
    return 1
  }
  case "$process_status" in
    0|143) ;;
    *) echo "serial VM: owned $TEST_VM_LABEL wrapper exited $process_status" >&2; return 1 ;;
  esac
  echo "serial VM: $TEST_VM_LABEL wrapper=$owned_pid child=$owned_child exit=$process_status request=$requested_shutdown"
}
