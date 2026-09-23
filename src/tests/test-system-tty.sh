#!/bin/bash

if [ "${TEST_SYSTEM_TTY_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export TEST_SYSTEM_TTY_TIMEOUT_ACTIVE=1
  set -m
  timeout 300s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "test-system-tty: timed out after 300 seconds" >&2
  fi
  exit "$status"
fi

set -e

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."
BUILD=debug
VMM=qemu
SEEN_RELEASE=0
SEEN_VMM=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      [ "$SEEN_RELEASE" = 0 ] || { echo "test-system-tty: duplicate --release" >&2; exit 2; }
      BUILD=release; SEEN_RELEASE=1; shift ;;
    --vmm)
      [ "$SEEN_VMM" = 0 ] || { echo "test-system-tty: duplicate --vmm" >&2; exit 2; }
      [ "$#" -ge 2 ] || { echo "test-system-tty: --vmm requires qemu, chv, or fc" >&2; exit 2; }
      VMM="$2"; SEEN_VMM=1; shift 2 ;;
    --vmm=*)
      [ "$SEEN_VMM" = 0 ] || { echo "test-system-tty: duplicate --vmm" >&2; exit 2; }
      VMM="${1#--vmm=}"; SEEN_VMM=1; shift ;;
    *) echo "usage: $0 [--release] [--vmm qemu|chv|fc]" >&2; exit 2 ;;
  esac
done
case "$VMM" in qemu|chv|fc) ;; *) echo "test-system-tty: unsupported VMM '$VMM'" >&2; exit 2 ;; esac
if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = 1 ] && [ "$VMM" = fc ]; then
  echo "test-system-tty: Firecracker does not support developer-image runs" >&2
  exit 2
fi
. "$WD/vm-test-selection.sh"
select_test_vm "$ROOT_DIR" "$BUILD" system-console "$VMM"
export MOTO_IMAGE="$TEST_VM_IMAGE"
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}"
export MOTO_SMP="${MOTO_SMP:-4}"

if [ "$BUILD" = release ]; then
  make -C "$ROOT_DIR" system-tty.img systest BUILD=release -j"$(nproc)"
else
  make -C "$ROOT_DIR" system-tty.img systest -j"$(nproc)"
fi

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

. "$WD/vm-cleanup.sh"
. "$WD/vm-test-serial.sh"

fail() {
  echo "test-system-tty: $*" >&2
  exit 1
}

CONSOLE_LOG=/tmp/test-system-tty.log
SCRATCH="$(mktemp -d)"
export MOTO_CHV_RUNTIME_DIR="$SCRATCH/chv"
export MOTO_FC_RUNTIME_DIR="$SCRATCH/fc"
export MOTO_FC_VSOCK_UDS=''
VMM_PID=""
VM_CHILD_PID=""

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  exec 3>&-
  stop_serial_test_vm || status=1
  rm -rf "$SCRATCH"
  exit "$status"
}
trap cleanup EXIT

CHECK_STDERR="$SCRATCH/check-console-stderr"
rustc --edition=2024 -D warnings "$WD/check-console-stderr.rs" -o "$CHECK_STDERR"
"$CHECK_STDERR" --self-test

vm_ssh() {
  ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 "$@"
}

wait_guest_file() {
  local path="$1"
  for _ in $(seq 1 120); do
    if vm_ssh "[ -e $path ]" >/dev/null 2>&1; then
      return
    fi
    if ! serial_test_vm_alive; then
      cat "$CONSOLE_LOG" >&2
      fail "$TEST_VM_LABEL exited while waiting for '$path'"
    fi
    sleep 0.5
  done
  fail "console did not create '$path' (log: $CONSOLE_LOG)"
}

run_console() {
  local marker="$1"
  local command="$2"
  printf '%s; echo done > %s\r' "$command" "$marker" >&3
  wait_guest_file "$marker"
}

has_system_process() {
  local process="$1"
  awk -v process="$process" '
    $1 ~ /\*$/ {
      for (i = 1; i <= NF; i++) {
        if ($i == process) {
          found = 1
        }
      }
    }
    END { exit !found }
  '
}

mkfifo "$SCRATCH/console-in"
exec 3<> "$SCRATCH/console-in"
start_serial_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG" \
  "$SCRATCH/console-in"

until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /system/bin/rush -c true >/dev/null; do
  if ! serial_test_vm_alive; then
    cat "$CONSOLE_LOG" >&2
    fail "$TEST_VM_LABEL exited before SSH became ready"
  fi
  sleep 1
done

run_console /user/tmp/system-tty-ps-done \
  '/system/bin/sysbox ps > /user/tmp/system-tty-ps'
run_console /user/tmp/system-tty-shim-done \
  'echo shim > /user/tmp/system-tty-shim; chmod r-xr-xr-- /user/tmp/system-tty-shim'
run_console /user/tmp/system-tty-direct-done \
  'echo direct > /user/tmp/system-tty-direct; /system/bin/sysbox chmod r-xr--r-- /user/tmp/system-tty-direct'
run_console /user/tmp/system-tty-defaults-done \
  'echo default > /user/tmp/system-tty-default-file; /system/bin/mkdir /user/tmp/system-tty-default-dir'
run_console /user/tmp/system-tty-script-v1-done \
  "echo '#!/system/bin/rush' > /user/tmp/system-tty-script; echo 'echo V1 > /user/tmp/system-tty-script-v1' >> /user/tmp/system-tty-script; chmod r-xr--r-- /user/tmp/system-tty-script; /user/tmp/system-tty-script"
run_console /user/tmp/system-tty-script-edit-done \
  "echo 'echo EDITED > /user/tmp/system-tty-edit-succeeded' >> /user/tmp/system-tty-script; chmod rw-r--r-- /user/tmp/system-tty-script; /user/tmp/system-tty-script; /system/bin/rm /user/tmp/system-tty-script"
run_console /user/tmp/system-tty-script-done \
  "echo '#!/system/bin/rush' > /user/tmp/system-tty-script; echo 'echo V2 > /user/tmp/system-tty-script-v2' >> /user/tmp/system-tty-script; chmod r-xr--r-- /user/tmp/system-tty-script; /user/tmp/system-tty-script"

# The System console can grant both reserve capabilities and can launch
# unprivileged children. The ordinary SSH shell cannot grant System authority.
make -C "$ROOT_DIR" systest BUILD="$BUILD" -j"$(nproc)"
scp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
  -i "$WD/test.key" "$ROOT_DIR/build/bin/$BUILD/systest" \
  motor@192.168.4.2:/user/tmp/admission-systest
run_console /user/tmp/admission-mode-done \
  'chmod r-xr-xr-x /user/tmp/admission-systest'
run_console /user/tmp/admission-class-done \
  'MOTOR_OS_CAPS=0x20d /user/tmp/admission-systest admission-class-tests > /user/tmp/admission-class.log 2>&1; echo $? > /user/tmp/admission-class.status'
admission_status="$(vm_ssh /system/bin/cat /user/tmp/admission-class.status)"
admission_output="$(vm_ssh /system/bin/cat /user/tmp/admission-class.log)"
[ "$admission_status" = "0" ] || fail "admission classes exited $admission_status: '$admission_output'"
[ "$admission_output" = "admission::test_process_classes PASS" ] ||
  fail "admission classes did not finish: '$admission_output'"
printf '%s\n' "$admission_output"

# CAP_SYS does not substitute for the sys-io bits: a System parent without
# CAP_NET cannot grant it, and a System child without CAP_FS_WRITE is refused
# writes.
run_console /user/tmp/system-caps-done \
  'MOTOR_OS_CAPS=0x20d /user/tmp/admission-systest system-caps-tests > /user/tmp/system-caps.log 2>&1; echo $? > /user/tmp/system-caps.status'
system_caps_status="$(vm_ssh /system/bin/cat /user/tmp/system-caps.status)"
system_caps_output="$(vm_ssh /system/bin/cat /user/tmp/system-caps.log)"
[ "$system_caps_status" = "0" ] ||
  fail "System capability tests exited $system_caps_status: '$system_caps_output'"
[ "$system_caps_output" = $'spawn_wait_kill::test_system_parent_cannot_grant_unheld PASS\nfs_permissions::test_write_capability(System) PASS' ] ||
  fail "System capability tests did not finish: '$system_caps_output'"
printf '%s\n' "$system_caps_output"

# An exported mask wins over Rush's ordinary System grant, even when it omits
# CAP_NET; without one, the grant keeps the console's own bits.
run_console /user/tmp/rush-caps-done \
  'export MOTOR_OS_CAPS=0x205; /user/tmp/admission-systest print-caps exported > /user/tmp/rush-caps.log; unset MOTOR_OS_CAPS; /user/tmp/admission-systest print-caps ordinary >> /user/tmp/rush-caps.log'
rush_caps="$(vm_ssh /system/bin/cat /user/tmp/rush-caps.log)"
[ "$rush_caps" = $'exported=0x205\nordinary=0x38d' ] ||
  fail "System Rush capability precedence: '$rush_caps'"
printf 'System Rush capability precedence: %s\n' "${rush_caps//$'\n'/ }"

# The checker distinguishes an unfinished live log from an ordering failure.
# A complete prompt before the expected tail fails immediately.
wait_console_burst() {
  local offset="$1" burst="$2" phase="$3" status
  for _ in $(seq 1 100); do
    if "$CHECK_STDERR" "$CONSOLE_LOG" "$offset" "$burst" "$phase"; then
      return
    else
      status=$?
      [ "$status" -eq 2 ] || fail "stderr burst $burst failed (log: $CONSOLE_LOG)"
    fi
    serial_test_vm_alive || fail "$TEST_VM_LABEL exited during stderr burst $burst"
    sleep 0.1
  done
  fail "stderr burst $burst did not reach $phase (log: $CONSOLE_LOG)"
}

run_console /user/tmp/stderr-burst-save-prompt 'tty_saved_ps1="$PS1"'
for burst in $(seq 1 11); do
  lines=24
  [ "$burst" -ne 11 ] || lines=512 # Exceeds the old 16 KiB backlog.
  offset="$(wc -c < "$CONSOLE_LOG")"
  # Adjacent quoted words keep the full prompt token out of the command echo.
  printf "PS1='[TTY-BURST-''%s] '; /user/tmp/admission-systest stderr-burst %s %s\r" \
    "$burst" "$burst" "$lines" >&3
  wait_console_burst "$offset" "$burst" ready
  printf '!' >&3
  wait_console_burst "$offset" "$burst" "$lines"
  echo "console stderr burst $burst: $lines intact lines before the prompt"
done
run_console /user/tmp/stderr-burst-restore-prompt 'PS1="$tty_saved_ps1"'

ps_output="$(vm_ssh /system/bin/cat /user/tmp/system-tty-ps)"
listing="$(vm_ssh /system/bin/ls -l /user/tmp)"
printf '%s\n' "$ps_output" | has_system_process /system/services/sys-tty ||
  fail "sys-tty is not System: '$ps_output'"
printf '%s\n' "$ps_output" | has_system_process /system/bin/rush ||
  fail "the console shell is not System: '$ps_output'"
printf '%s\n' "$ps_output" | has_system_process /system/bin/sysbox ||
  fail "an ordinary external command did not retain System: '$ps_output'"

# Only a System parent may grant CAP_IO_MANAGER. The ordinary SSH shell
# deliberately cannot launch this test with its required 0x24e mask.
scp -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
  -i "$WD/test.key" "$ROOT_DIR/build/bin/$BUILD/systest" \
  motor@192.168.4.2:/user/tmp/mmio-systest
# The child is Interactive, so its redirected output must be writable by
# that role, not just by the System shell creating the redirection.
vm_ssh 'echo -n > /user/tmp/mmio-validation.log'
run_console /user/tmp/mmio-validation-done \
  'MOTOR_OS_CAPS=0x24e /user/tmp/mmio-systest mmio-validation-tests > /user/tmp/mmio-validation.log 2>&1; echo $? > /user/tmp/mmio-validation.status'
mmio_status="$(vm_ssh /system/bin/cat /user/tmp/mmio-validation.status)"
mmio_output="$(vm_ssh /system/bin/cat /user/tmp/mmio-validation.log)"
[ "$mmio_status" = "0" ] || fail "MMIO validation exited $mmio_status: '$mmio_output'"
[ "$mmio_output" = "mmio::validation_tests PASS" ] ||
  fail "MMIO validation did not finish: '$mmio_output'"
printf '%s\n' "$mmio_output"

for mmio_case in mmio-unmap-suite mmio-unmap-fault; do
  vm_ssh "echo -n > /user/tmp/$mmio_case.log"
  run_console "/user/tmp/$mmio_case-done" \
    "MOTOR_OS_CAPS=0x24e /user/tmp/mmio-systest $mmio_case > /user/tmp/$mmio_case.log 2>&1; echo \$? > /user/tmp/$mmio_case.status"
  mmio_status="$(vm_ssh /system/bin/cat /user/tmp/$mmio_case.status)"
  mmio_output="$(vm_ssh /system/bin/cat /user/tmp/$mmio_case.log)"
  if [ "$mmio_case" = mmio-unmap-suite ]; then
    [ "$mmio_status" = 0 ] && [ "$mmio_output" = 'mmio::ownership_tests PASS' ] ||
      fail "MMIO ownership: status=$mmio_status output='$mmio_output'"
  else
    [ "$mmio_status" = -1 ] && [ "$mmio_output" = 'mmio::unmap_fault READY' ] ||
      fail "MMIO fault: status=$mmio_status output='$mmio_output'"
  fi
  printf '%s: status=%s %s\n' "$mmio_case" "$mmio_status" "$mmio_output"
done

printf '%s\n' "$listing" |
  grep -aqE -- '-r-xr-xr--[[:space:]]+[0-9]+[[:space:]]+system-tty-shim$' ||
  fail "the chmod shim did not install the exact mode"
printf '%s\n' "$listing" |
  grep -aqE -- '-r-xr--r--[[:space:]]+[0-9]+[[:space:]]+system-tty-direct$' ||
  fail "sysbox chmod did not install the exact mode"
printf '%s\n' "$listing" |
  grep -aqE -- '-rw-r--r--[[:space:]]+[0-9]+[[:space:]]+system-tty-default-file$' ||
  fail "System-created file did not use the creator-relative default"
printf '%s\n' "$listing" |
  grep -aqE -- 'drwxr-xr-x[[:space:]]+system-tty-default-dir$' ||
  fail "System-created directory did not use the creator-relative default"
vm_ssh '[ -e /user/tmp/system-tty-script-v1 ]' ||
  fail "the finalized System-role script did not run"
vm_ssh '[ -e /user/tmp/system-tty-script-v2 ]' ||
  fail "the replacement System-role script did not run"
if vm_ssh '[ -e /user/tmp/system-tty-edit-succeeded ]'; then
  fail "the finalized System-role script remained writable"
fi
printf '%s\n' "$listing" |
  grep -aqE -- '-r-xr--r--[[:space:]]+[0-9]+[[:space:]]+system-tty-script$' ||
  fail "the finalized System-role script regained write permission"

# The foreground rmux client remains observable while its detached server and
# pane are alive. Two rmux processes prove the detached spawn succeeded; the
# starred client proves Rush's pass-listed grant preserved System authority.
printf '/user/bin/rmux new -s system-role\r' >&3
rmux_ok=0
for _ in $(seq 1 40); do
  rmux_ps="$(ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 /system/bin/sysbox ps)"
  rmux_count="$(printf '%s\n' "$rmux_ps" |
    awk '
      {
        for (i = 1; i <= NF; i++) {
          if ($i == "/user/bin/rmux") {
            count++
          }
        }
      }
      END { print count + 0 }
    ')"
  if [ "$rmux_count" -ge 2 ] &&
    printf '%s\n' "$rmux_ps" | has_system_process /user/bin/rmux; then
    rmux_ok=1
    break
  fi
  sleep 0.25
done
[ "$rmux_ok" = 1 ] ||
  fail "pass-listed rmux did not retain System and launch its detached server: '$rmux_ps'"

stop_serial_test_vm
echo "-------- TEST-SYSTEM-TTY PASS ---------"
