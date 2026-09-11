# Shared SSH setup and VM startup for noninteractive test harnesses. Sourced by
# callers, which provide WD, filter_vm_console, fail, and the image selection.

test_vm_configure_ssh() {
  chmod 600 "$WD/test.key"
  SSH_OPTIONS=(
    -F /dev/null
    -p 2222
    -o IdentitiesOnly=yes
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$WD/test-known-hosts"
    -i "$WD/test.key"
  )
  SSH=(ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2)
}

vm_ssh() {
  "${SSH[@]}" "$@"
}

start_test_vm() {
  local img_dir="$1"
  local console_log="$2"
  local vmm_status=0

  [ -x "$img_dir/run-qemu.sh" ] || fail "VM launcher is missing: $img_dir/run-qemu.sh"

  # Do not forward the guest's terminal queries: a host terminal may answer
  # them or leave responses queued for the shell after this run.
  "$img_dir/run-qemu.sh" ${FULL_TEST_QEMU_ARGS:-} \
    > >(filter_vm_console | tee "$console_log") 2>&1 &
  VMM_PID="$!"

  # A refused connection returns immediately, so OpenSSH's
  # ConnectionAttempts does not reliably cover a slow debug boot. The caller's
  # whole-suite deadline bounds this loop.
  until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
    motor@192.168.4.2 /system/bin/rush -c true; do
    if ! kill -0 "$VMM_PID" 2>/dev/null; then
      wait "$VMM_PID" || vmm_status="$?"
      VMM_PID=""
      cat "$console_log" >&2
      fail "QEMU exited before SSH became ready (status $vmm_status)"
    fi
    sleep 1
  done
  if ! kill -0 "$VMM_PID" 2>/dev/null; then
    wait "$VMM_PID" || vmm_status="$?"
    VMM_PID=""
    cat "$console_log" >&2
    fail "SSH reached a VM after this run's QEMU exited (status $vmm_status)"
  fi
}
