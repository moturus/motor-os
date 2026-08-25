#!/bin/bash
#
# Acceptance validation for terminal descriptors and Ctrl+C routing
# (docs/tui.md and docs/plans/less-paging.md).
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

if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = "1" ]; then
  MOTOR_TEST_ROOT=/devtools
else
  MOTOR_TEST_ROOT=/user/tmp/motor-tests
fi
export MOTOR_TEST_ROOT
TEST_BIN="$MOTOR_TEST_ROOT/tests"
TEST_TMP="$MOTOR_TEST_ROOT/tmp"
RMUX_TMPDIR="$TEST_TMP/test-tui-rmux"

# Image selection mirrors full-test.sh so full-test-dev.sh covers this script
# against the dev image as well.
IMG_TARGET="${FULL_TEST_IMG_TARGET:-main.img}"
export MOTO_IMAGE="${FULL_TEST_IMAGE:-motor-os.qcow2}"

if [ "${FULL_TEST_IMAGE_PREBUILT:-0}" != "1" ]; then
  if [ "$BUILD" = "release" ]; then
    make -C "$ROOT_DIR" "$IMG_TARGET" systest crossterm-smoke BUILD=release -j"$(nproc)"
  else
    make -C "$ROOT_DIR" "$IMG_TARGET" systest crossterm-smoke -j"$(nproc)"
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
TEST_ROOT_CREATED=0
PTY_PID=""
PTY_OUT_FD=""
PTY_IN_FD=""
PTY_OUTPUT=""

remove_test_root() {
  if [ "$TEST_ROOT_CREATED" = "1" ] && [ -n "$VMM_PID" ] &&
    kill -0 "$VMM_PID" 2>/dev/null; then
    ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=2 -o ConnectionAttempts=1 \
      motor@192.168.4.2 /system/bin/rm -r "$MOTOR_TEST_ROOT" >/dev/null 2>&1
    TEST_ROOT_CREATED=0
  fi
}

cleanup() {
  set +e
  if [ -n "$PTY_IN_FD" ]; then
    exec {PTY_IN_FD}>&-
  fi
  if [ -n "$PTY_OUT_FD" ]; then
    exec {PTY_OUT_FD}<&-
  fi
  if [ -n "$PTY_PID" ]; then
    kill "$PTY_PID" 2>/dev/null
    wait "$PTY_PID" 2>/dev/null
  fi
  remove_test_root
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
  motor@192.168.4.2 /system/bin/rush -c true > /dev/null; do
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
  TEST_ROOT_CREATED=1
  printf '%s\n' \
    "mkdir $MOTOR_TEST_ROOT" \
    "mkdir $TEST_BIN" \
    "mkdir $TEST_TMP" \
    "put $ROOT_DIR/build/bin/$BUILD/systest $TEST_BIN/systest" \
    "put $ROOT_DIR/build/bin/$BUILD/crossterm-smoke $TEST_BIN/crossterm-smoke" |
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

# Run one command behind a forced SSH terminal and interact only after markers
# from the process under test. Duplicating coproc's descriptors keeps them
# valid after Bash notices that ssh has exited.
start_pty() {
  local command="$1"

  PTY_OUTPUT=""
  coproc CTRL_C_PTY {
    ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 "$command" 2>&1
  }
  PTY_PID="$!"
  exec {PTY_OUT_FD}<&"${CTRL_C_PTY[0]}"
  exec {PTY_IN_FD}>&"${CTRL_C_PTY[1]}"
}

wait_pty_output() {
  local pattern="$1"
  local label="$2"
  local byte
  local deadline=$((SECONDS + 20))
  local remaining

  while [ "$SECONDS" -lt "$deadline" ]; do
    remaining=$((deadline - SECONDS))
    if ! IFS= read -r -t "$remaining" -n 1 byte <&"$PTY_OUT_FD"; then
      break
    fi
    PTY_OUTPUT+="$byte"
    if [[ "$PTY_OUTPUT" == *"$pattern"* ]]; then
      return
    fi
  done
  fail "$label did not print '$pattern': '$(printf '%s' "$PTY_OUTPUT" | tail -c 800)'"
}

finish_pty() {
  local expected="$1"
  local label="$2"
  local remainder
  local read_status
  local status

  exec {PTY_IN_FD}>&-
  set +e
  remainder="$(cat <&"$PTY_OUT_FD")"
  read_status="$?"
  wait "$PTY_PID"
  status="$?"
  set -e
  PTY_OUTPUT+="$remainder"
  exec {PTY_OUT_FD}<&-
  PTY_PID=""

  [ "$read_status" -eq 0 ] || fail "$label output ended with status $read_status"
  [ "$status" -eq "$expected" ] ||
    fail "$label exited with status $status, want $expected: '$(printf '%s' "$PTY_OUTPUT" | tail -c 800)'"
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
printf 'TMPDIR=%s %s/systest stdio-terminal-report-child\n' "$TEST_TMP" "$TEST_BIN" >&3
wait_console "dupnew="
printf 'exit\n' >&3
check_report "sys-tty console child" "$(cat "$CONSOLE_LOG")" 111 1

# A non-pty ssh session: russhd removes the terminal hint, so the command and
# everything it spawns with inherited stdio answers non-terminal.
echo "-- non-pty ssh session --"
out="$(printf 'mask inherit\nexit\n' |
  vm_ssh "TMPDIR=$TEST_TMP $TEST_BIN/systest stdio-terminal-report-child")"
check_report "non-pty ssh child" "$out" 000 0
[ "$(report_field "$out" mask)" = "000" ] ||
  fail "non-pty ssh grandchild is a terminal: '$out'"

# A forced-pty ssh session is a terminal; a descendant inheriting all three
# streams stays one, and capturing its stdout flips exactly that bit (the
# "> file" row of docs/tui.md's mask table, live against a real provider).
echo "-- russhd pty session --"
out="$(printf 'mask inherit\nmask outpiped\nexit\n' |
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "TMPDIR=$TEST_TMP $TEST_BIN/systest stdio-terminal-report-child" 2>/dev/null)"
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
  printf 'TMPDIR=%s %s/systest stdio-terminal-report-child\n' "$TEST_TMP" "$TEST_BIN"
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
set +e
out="$(vm_ssh "TMPDIR=$TEST_TMP $TEST_BIN/systest stdio-terminal-tests")"
status="$?"
set -e
printf '%s\n' "$out"
[ "$status" -eq 0 ] ||
  fail "systest stdio-terminal-tests exited with status $status"
[ "${out##*$'\n'}" = "PASS" ] ||
  fail "systest stdio-terminal-tests did not finish with PASS"

echo "-- Ctrl+C Default and handler leaves --"
start_pty "TMPDIR=$TEST_TMP $TEST_BIN/systest ctrl-c-default-child"
wait_pty_output "CTRL_C_DEFAULT_READY" "terminal-stdin Default leaf"
printf '\003' >&"$PTY_IN_FD"
finish_pty 130 "terminal-stdin Default leaf"

# stdin is a pipe, so Ctrl+C reaches the leaf through its reserved terminal fd
# and a terminal-backed non-interactive rush remains Default between routes.
start_pty "/system/bin/rush -c 'echo | TMPDIR=$TEST_TMP $TEST_BIN/systest ctrl-c-default-child'"
wait_pty_output "CTRL_C_DEFAULT_READY" "terminal-fd3 Default leaf"
printf '\003' >&"$PTY_IN_FD"
finish_pty 130 "terminal-fd3 Default leaf"

start_pty "TMPDIR=$TEST_TMP $TEST_BIN/systest ctrl-c-handler-child"
wait_pty_output "CTRL_C_HANDLER_READY" "handler leaf"
printf '\003' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_HANDLER_CALLED" "handler leaf"
finish_pty 0 "handler leaf"

echo "-- Ctrl+C forwarding and route teardown --"
start_pty "TMPDIR=$TEST_TMP $TEST_BIN/systest ctrl-c-route-parent"
wait_pty_output "CTRL_C_NORMAL_CHILD_READY" "route normal child"
printf 'n' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_NORMAL_RESTORED" "route after normal child"
printf '\003' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_PARENT_AFTER_NORMAL" "route parent after normal child"
wait_pty_output "CTRL_C_SPIN_CHILD_READY" "route spinning child"
printf '\003x' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_SPIN_STATUS_130" "route interrupted child"
wait_pty_output "CTRL_C_TYPEAHEAD_X" "route type-ahead"
wait_pty_output "CTRL_C_KILL_RESTORED" "route after interrupted child"
printf '\003' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_PARENT_AFTER_KILL" "route parent after interrupted child"
finish_pty 0 "route parent"

echo "-- crossterm Ctrl+C adapter --"
start_pty "TMPDIR=$TEST_TMP $TEST_BIN/crossterm-smoke keys"
wait_pty_output "ready" "crossterm handler"
printf '\003' >&"$PTY_IN_FD"
wait_pty_output "key=Char('c')+KeyModifiers(CONTROL)" "crossterm handler"
printf 'q' >&"$PTY_IN_FD"
wait_pty_output "end=quit" "crossterm handler"
finish_pty 0 "crossterm handler"

echo "-- nested rmux, rush, and Default leaf --"
start_pty "TMPDIR=$RMUX_TMPDIR /user/bin/rmux new -s test-tui-ctrl-c"
wait_pty_output "motor-os" "nested rmux shell"
printf 'TMPDIR=%s %s/systest ctrl-c-default-child\n' "$TEST_TMP" "$TEST_BIN" >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_DEFAULT_READY" "nested Default leaf"
# The command is type-ahead for rush while Ctrl+C is routed through rmux and
# rush to the leaf. It must survive teardown and observe the leaf's status.
printf '\003echo CTRL_C_NESTED_STATUS=$?\n' >&"$PTY_IN_FD"
wait_pty_output "CTRL_C_NESTED_STATUS=130" "nested rush"
printf 'exit\n' >&"$PTY_IN_FD"
finish_pty 0 "nested rmux"

remove_test_root
stop_vm "$VMM_PID"
VMM_PID=""

echo "-------- TEST-TUI PASS ---------"
