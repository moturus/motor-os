#!/bin/bash
#
# Acceptance validation for the per-descriptor is_terminal redesign
# (docs/tui.md).
#
# This script boots its own VM: the sys-tty console check needs the serial
# console's stdin, which full-test.sh never connects. It covers the
# runtime-observable acceptance criteria:
#
#   - the invariant, mixed-stream, and duplication matrix, in both the Rust
#     std::io::IsTerminal path and the moto-rt C-ABI (VDSO) query path, via
#     `systest stdio-terminal-tests` (the same tests the full systest suite
#     runs via stdio::run_all_tests);
#   - children of the three terminal providers -- the sys-tty console, a
#     russhd pty session, and an rmux pane -- answer terminal;
#   - descendants of a non-pty ssh session answer non-terminal;
#   - mutating the environment after startup changes no existing descriptor's
#     answer, checked live in each of the contexts above (the probe's set=
#     and unset= fields).
#
# The remaining acceptance criteria are review or process properties, not
# runtime-testable here: no new kernel surface or boot work, staged-toolchain
# deployment safety, and full-test.sh itself passing.

if [ "${TEST_TUI_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export TEST_TUI_TIMEOUT_ACTIVE=1
  # See full-test.sh for why job control keeps timeout's process group safe
  # from SIGTTIN/SIGTTOU while preserving its whole-tree timeout.
  set -m
  timeout 600s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "test-tui: timed out after 600 seconds" >&2
  fi
  exit "$status"
fi

set -e

WD="$(dirname "$0")"

BUILD="debug"
if [ "${1:-}" = "--release" ]; then
  BUILD="release"
fi
ROOT_DIR="$WD/../.."
IMG_DIR="$WD/../../vm_images/$BUILD"
RMUX_TMPDIR=/devtools/tmp/test-tui-rmux

# Image selection mirrors full-test.sh so full-test-dev.sh covers this script
# against the dev image as well.
IMG_TARGET="${FULL_TEST_IMG_TARGET:-main.img}"
export MOTO_IMAGE="${FULL_TEST_IMAGE:-motor-os.img}"

if [ "${FULL_TEST_IMAGE_PREBUILT:-0}" != "1" ]; then
  if [ "$BUILD" = "release" ]; then
    make -C "$ROOT_DIR" "$IMG_TARGET" systest BUILD=release -j"$(nproc)"
  else
    make -C "$ROOT_DIR" "$IMG_TARGET" systest -j"$(nproc)"
  fi
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
SSH=(ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2)

vm_ssh() {
  "${SSH[@]}" "$@"
}

# stop_vm(): bounded teardown, shared with the other VM harnesses.
. "$WD/vm-cleanup.sh"

fail() {
  echo "test-tui: $*" >&2
  exit 1
}

CONSOLE_LOG=/tmp/test-tui.log
SCRATCH="$(mktemp -d)"
VMM_PID=""
TEST_DEVTOOLS_CREATED=0

remove_test_devtools() {
  if [ "$TEST_DEVTOOLS_CREATED" = "1" ] && [ -n "$VMM_PID" ] &&
    kill -0 "$VMM_PID" 2>/dev/null; then
    ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=2 -o ConnectionAttempts=1 \
      motor@192.168.4.2 /system/bin/rm -r /devtools >/dev/null 2>&1
    TEST_DEVTOOLS_CREATED=0
  fi
}

cleanup() {
  set +e
  remove_test_devtools
  stop_vm "$VMM_PID"
  VMM_PID=""
  exec 3>&-
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

# The serial console's stdin: the fifo stays open on fd 3 so console input
# can be typed at any point, and qemu never sees EOF until cleanup.
mkfifo "$SCRATCH/console-in"

echo "test-tui: starting a $BUILD VM; console log in $CONSOLE_LOG"
"$IMG_DIR/run-qemu.sh" < "$SCRATCH/console-in" > "$CONSOLE_LOG" 2>&1 &
VMM_PID="$!"
exec 3> "$SCRATCH/console-in"

until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /system/bin/echo " " > /dev/null; do
  if ! kill -0 "$VMM_PID" 2>/dev/null; then
    vmm_status=0
    wait "$VMM_PID" || vmm_status="$?"
    VMM_PID=""
    cat "$CONSOLE_LOG" >&2
    fail "QEMU exited before SSH became ready (status $vmm_status)"
  fi
  sleep 1
done

if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" != "1" ]; then
  vm_ssh "[ ! -e /devtools ]" ||
    fail "standard image unexpectedly packages /devtools"
  TEST_DEVTOOLS_CREATED=1
  printf '%s\n' \
    'mkdir /devtools' \
    'mkdir /devtools/tests' \
    'mkdir /devtools/tmp' \
    "put $ROOT_DIR/build/bin/$BUILD/systest /devtools/tests/systest" |
    sftp -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
      -i "$WD/test.key" motor@192.168.4.2
fi

# The probe is systest's report child: it prints one line of fields
# ("self=111 set=111 unset=111 key=0 dupfd=3 duporig=1 dupnew=1"), then reads
# "mask <mode>" / "exit" commands from stdin. Fields are extracted
# individually because console and pane output interleave the line with log
# noise and terminal escapes; stripping those escapes can glue arbitrary
# painted text right up against a field name, so matches are unanchored and
# the one substring collision -- "set=" inside "unset=" -- is removed first.
strip_escapes() {
  sed -e $'s/\033\\[[0-9;?$]*[a-zA-Z]//g' -e $'s/\033[78]//g'
}

report_field() {
  local text="$1"
  local key="$2"
  local cleaned

  cleaned="$(printf '%s\n' "$text" | strip_escapes)"
  if [ "$key" = "set" ]; then
    cleaned="${cleaned//unset=/}"
  fi
  printf '%s\n' "$cleaned" | grep -aoE "$key=[0-9]+" | tail -1 |
    sed "s/.*$key=//"
}

# The three-bit masks and the duplicate answers all follow one bit -- whether
# the queried context is a terminal endpoint -- and set=/unset= must equal
# self= (a started process's environment cannot change an open descriptor),
# while key= must be 0 (the launch hint is consumed, never live state).
check_report() {
  local label="$1"
  local text="$2"
  local mask="$3"
  local dup="$4"
  local tail_text
  local key
  local got

  # Enough context to diagnose without dumping a whole console log.
  tail_text="$(printf '%s' "$text" | tail -c 800)"
  for key in self set unset; do
    got="$(report_field "$text" "$key")"
    [ "$got" = "$mask" ] ||
      fail "$label: $key=$got, want $mask, in: '$tail_text'"
  done
  got="$(report_field "$text" key)"
  [ "$got" = "0" ] ||
    fail "$label: launch hint visible in environment: '$tail_text'"
  for key in duporig dupnew; do
    got="$(report_field "$text" "$key")"
    [ "$got" = "$dup" ] ||
      fail "$label: $key=$got, want $dup, in: '$tail_text'"
  done
}

wait_console() {
  local pattern="$1"

  for _ in $(seq 1 60); do
    if grep -aq "$pattern" "$CONSOLE_LOG"; then
      return
    fi
    sleep 0.5
  done
  fail "console did not print '$pattern' (log: $CONSOLE_LOG)"
}

# The console shell is a child of sys-tty, the serial-console terminal
# provider. Waiting for the report's last field before typing "exit" is the
# ordering: input typed earlier would reach the shell's line editor instead.
echo "-- sys-tty console child --"
wait_console "motor-os"
printf 'if [ "$PWD" = /user ] && [ "$HOME" = /user ]; then echo CONSOLE_"HOME_OK"; else echo CONSOLE_"HOME_BAD"; fi\n' >&3
wait_console "CONSOLE_HOME_"
if grep -aq "CONSOLE_HOME_BAD" "$CONSOLE_LOG"; then
  fail "sys-tty did not start the console shell with HOME and PWD set to /user"
fi
printf 'TMPDIR=/devtools/tmp /devtools/tests/systest stdio-terminal-report-child\n' >&3
wait_console "dupnew="
printf 'exit\n' >&3
check_report "sys-tty console child" "$(cat "$CONSOLE_LOG")" 111 1

# A non-pty ssh session: russhd removes the terminal hint, so the command and
# everything it spawns with inherited stdio answers non-terminal.
echo "-- non-pty ssh session --"
out="$(printf 'mask inherit\nexit\n' |
  vm_ssh "TMPDIR=/devtools/tmp /devtools/tests/systest stdio-terminal-report-child")"
check_report "non-pty ssh child" "$out" 000 0
[ "$(report_field "$out" mask)" = "000" ] ||
  fail "non-pty ssh grandchild is a terminal: '$out'"

# A forced-pty ssh session is a terminal; a descendant inheriting all three
# streams stays one, and capturing its stdout flips exactly that bit (the
# "> file" row of docs/tui.md's mask table, live against a real provider).
echo "-- russhd pty session --"
out="$(printf 'mask inherit\nmask outpiped\nexit\n' |
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "TMPDIR=/devtools/tmp /devtools/tests/systest stdio-terminal-report-child" 2>/dev/null)"
check_report "ssh pty child" "$out" 111 1
masks="$(printf '%s\n' "$out" | strip_escapes |
  grep -aoE 'mask=[01]+' | sed 's/.*mask=//' | tr '\n' ' ')"
[ "$masks" = "111 101 " ] ||
  fail "ssh pty descendant masks: got '$masks', want '111 101 ', in: '$out'"

# An rmux pane: the pane's shell runs the probe on the terminal rmux
# provides. The sleeps order piped keystrokes against the pane, as in
# full-test.sh's rmux checks; the second "exit" ends the pane's shell.
echo "-- rmux pane child --"
rmux_report_keys() {
  printf 'TMPDIR=/devtools/tmp /devtools/tests/systest stdio-terminal-report-child\n'
  sleep 5
  printf 'exit\n'
  sleep 2
  printf 'exit\n'
  sleep 1
}
set +e
out="$(rmux_report_keys |
  vm_ssh "TMPDIR=$RMUX_TMPDIR" /user/bin/rmux new -s test-tui 2>&1)"
rmux_status="$?"
set -e
if [ "$rmux_status" -ne 0 ]; then
  fail "rmux pane exited with status $rmux_status: '$(printf '%s' "$out" | tail -c 800)'"
fi
check_report "rmux pane child" "$out" 111 1

# The full invariant matrix from the design doc: mixed-stream rows through
# std::process::Command, environment mutation, duplication, the direct-spawn
# launch hint, and non-stdio descriptors -- exercising both Rust std and the
# moto-rt C-ABI query path.
echo "-- invariant matrix (systest stdio-terminal-tests) --"
out="$(vm_ssh "TMPDIR=/devtools/tmp /devtools/tests/systest stdio-terminal-tests")"
printf '%s\n' "$out"
[ "${out##*$'\n'}" = "PASS" ] ||
  fail "systest stdio-terminal-tests did not finish with PASS"

remove_test_devtools
stop_vm "$VMM_PID"
VMM_PID=""

echo "-------- TEST-TUI PASS ---------"
