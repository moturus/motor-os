#!/bin/bash
#
# Acceptance validation for in-band terminal size (docs/tui.md), from the
# application's end: rush and red are the programs in front of all three of this
# system's terminals, and what is checked here is that each lays out for the
# size the terminal last said it was, and redraws what it is holding when that
# size changes with no key typed. There is no `SIGWINCH` here to make that
# happen and no `TIOCGWINSZ` to ask afterwards; the only news of a resize is the
# report the terminal writes into the program's own stdin.
#
# The two clients fail differently, which is why both are here. The shell lays
# out one line and can re-read the width at every prompt; the editor owns every
# row on the screen and has only what it was told, so an editor that missed a
# report paints a whole screen at the wrong size and goes on doing it.
#
# The three terminals, and what each one contributes:
#
#   - the serial console, whose terminal is whatever is on the other end of the
#     wire. This script is that terminal, and it implements mode 2048 -- which
#     is the only way to test the console rung at all, since a fifo does not.
#     It needs the console's stdin, which full-test.sh never connects, so this
#     script boots its own VM (as test-tui.sh does, and for the same reason).
#   - a russhd pty session, where the size comes from the SSH client. `script`
#     gives the client a terminal to have a size at all and `stty` resizes it.
#   - an rmux pane, where the size is the geometry rmux computes for the pane
#     and a split is what changes it.
#
# Each check is written so that only the resize can have produced what it
# matches: a key would repaint too, so every assertion is made against the bytes
# that arrived before the next one was sent. Behind rmux, read completed frames.
#
# Since the console VM is here anyway, it also checks what rush's and rmux's
# host pty tests cannot: line discipline, byte costs, and panes on the
# serial console itself, where Enter arrives as CR and LF.

if [ "${TEST_TERMINAL_SIZE_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export TEST_TERMINAL_SIZE_TIMEOUT_ACTIVE=1
  # See full-test.sh for why job control keeps timeout's process group safe
  # from SIGTTIN/SIGTTOU while preserving its whole-tree timeout.
  set -m
  timeout 600s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "test-terminal-size: timed out after 600 seconds" >&2
  fi
  exit "$status"
fi

set -e

WD="$(dirname "$0")"

BUILD="debug"
VMM=qemu
SEEN_RELEASE=0
SEEN_VMM=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      [ "$SEEN_RELEASE" = 0 ] || { echo "test-terminal-size: duplicate --release" >&2; exit 2; }
      BUILD=release; SEEN_RELEASE=1; shift ;;
    --vmm)
      [ "$SEEN_VMM" = 0 ] || { echo "test-terminal-size: duplicate --vmm" >&2; exit 2; }
      [ "$#" -ge 2 ] || { echo "test-terminal-size: --vmm requires qemu, chv, or fc" >&2; exit 2; }
      VMM="$2"; SEEN_VMM=1; shift 2 ;;
    --vmm=*)
      [ "$SEEN_VMM" = 0 ] || { echo "test-terminal-size: duplicate --vmm" >&2; exit 2; }
      VMM="${1#--vmm=}"; SEEN_VMM=1; shift ;;
    *) echo "usage: $0 [--release] [--vmm qemu|chv|fc]" >&2; exit 2 ;;
  esac
done
case "$VMM" in qemu|chv|fc) ;; *) echo "test-terminal-size: unsupported VMM '$VMM'" >&2; exit 2 ;; esac
if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = 1 ] && [ "$VMM" = fc ]; then
  echo "test-terminal-size: Firecracker does not support developer images" >&2
  exit 2
fi
ROOT_DIR="$WD/../.."
. "$WD/vm-test-selection.sh"
TEST_VM_PHASE=standard
[ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" != 1 ] || TEST_VM_PHASE=developer
select_test_vm "$ROOT_DIR" "$BUILD" "$TEST_VM_PHASE" "$VMM"

. "$WD/test-roots.sh"
RMUX_TMPDIR="$TEST_TMP/test-terminal-size-rmux"

# Image selection mirrors full-test.sh so full-test-dev.sh covers this script
# against the dev image as well.
IMG_TARGET="${FULL_TEST_IMG_TARGET:-$TEST_VM_IMG_TARGET}"
export MOTO_IMAGE="${FULL_TEST_IMAGE:-$TEST_VM_IMAGE}"
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}"
export MOTO_SMP="${MOTO_SMP:-4}"
case "$VMM:$MOTO_IMAGE" in
  fc:*.img|fc:*.raw|qemu:*.qcow2|qemu:*.img|qemu:*.raw|chv:*.qcow2|chv:*.img|chv:*.raw) ;;
  fc:*) echo "test-terminal-size: Firecracker requires a raw image, not '$MOTO_IMAGE'" >&2; exit 2 ;;
  *) echo "test-terminal-size: unsupported image filename '$MOTO_IMAGE'" >&2; exit 2 ;;
esac

if [ "${FULL_TEST_IMAGE_PREBUILT:-0}" != "1" ]; then
  if [ "$BUILD" = "release" ]; then
    make -C "$ROOT_DIR" "$IMG_TARGET" BUILD=release -j"$(nproc)"
  else
    make -C "$ROOT_DIR" "$IMG_TARGET" -j"$(nproc)"
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

# stop_vm(): bounded teardown, shared with the other VM harnesses.
. "$WD/vm-cleanup.sh"
. "$WD/vm-test-serial.sh"

fail() {
  echo "test-terminal-size: $*" >&2
  exit 1
}

CONSOLE_LOG=/tmp/test-terminal-size.log
RED_STDERR_LOG=/tmp/test-terminal-size-red-stderr.log
RMUX_STDERR_LOG=/tmp/test-terminal-size-rmux-stderr.log
RMUX_CONSOLE_STDERR_LOG=/tmp/test-terminal-size-rmux-console-stderr.log
RMUX_CONSOLE_STARTED=0
: > "$RMUX_CONSOLE_STDERR_LOG"
: > "$RMUX_STDERR_LOG"
# The pty recordings live beside it, and outlive the run for the same reason:
# a check that fails here is not reproducible on demand, and the bytes are the
# only evidence of what the terminal actually said.
SCRATCH="$(mktemp -d)"
export MOTO_CHV_RUNTIME_DIR="$SCRATCH/chv"
export MOTO_FC_RUNTIME_DIR="$SCRATCH/fc"
export MOTO_FC_VSOCK_UDS=''
VMM_PID=""
VM_CHILD_PID=""
TEST_ROOT_CREATED=0
SESSION_PID=""
SSH_CONTROL_STARTED=0

save_red_stderr() {
  if [ -n "$VMM_PID" ] && serial_test_vm_alive; then
    ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=2 -o ConnectionAttempts=1 \
      motor@192.168.4.2 "/user/bin/cat $TEST_TMP/red-*.stderr" > "$RED_STDERR_LOG"
    if [ "$RMUX_CONSOLE_STARTED" = "1" ]; then
      ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=2 -o ConnectionAttempts=1 \
        motor@192.168.4.2 "/user/bin/cat $TEST_TMP/rmux-console.stderr" > "$RMUX_CONSOLE_STDERR_LOG"
    fi
  fi
}

remove_test_root() {
  if [ "$TEST_ROOT_CREATED" = "1" ] && [ -n "$VMM_PID" ] &&
    serial_test_vm_alive; then
    local dir
    for dir in "$TEST_TMP" "$NONE_TEST_ROOT"; do
      ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=2 -o ConnectionAttempts=1 \
        motor@192.168.4.2 /user/bin/rm -r "$dir" >/dev/null 2>&1 || true
    done
    TEST_ROOT_CREATED=0
  fi
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [ -n "$SESSION_PID" ]; then
    kill "$SESSION_PID" 2>/dev/null
    wait "$SESSION_PID" 2>/dev/null
  fi
  save_red_stderr
  remove_test_root
  if [ "$SSH_CONTROL_STARTED" = 1 ]; then
    ssh "${SSH_OPTIONS[@]}" -O exit motor@192.168.4.2 >/dev/null 2>&1 || status=1
  fi
  exec 3>&- 4>&-
  stop_serial_test_vm || status=1
  rm -rf "$SCRATCH"
  exit "$status"
}
trap cleanup EXIT

# Geometry probes need only red's screen stream; stderr may interleave in the
# middle of its bar. The wrapper gives red inherited, pipe-relayed stderr so
# runtime diagnostics are retained too. Stdin/stdout remain terminal streams.
start_red() {
  printf '/user/bin/rush -c red 2>%s/red-%s.stderr\r' "$TEST_TMP" "$1"
}

# The serial console's stdin: the fifo stays open on fd 3 so the console can be
# answered at any point, and the VMM never sees EOF until cleanup.
mkfifo "$SCRATCH/console-in"

exec 3<> "$SCRATCH/console-in"
start_serial_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG" \
  "$SCRATCH/console-in"

until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /user/bin/rush -c true >/dev/null; do
  if ! serial_test_vm_alive; then
    fail "$TEST_VM_LABEL exited before SSH became ready (log: $CONSOLE_LOG)"
  fi
  sleep 1
done
if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" != "1" ]; then
  ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 "[ ! -e /devtools ]" ||
    fail "standard image unexpectedly packages /devtools"
fi
# An earlier run's leftover test directories would fail the mkdirs below.
remove_test_roots ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2
TEST_ROOT_CREATED=1
test_root_mkdirs | sftp -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes \
  -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$WD/test-known-hosts" -i "$WD/test.key" motor@192.168.4.2

# Keep each SSH session's terminal state separate while sharing authentication.
# Connection setup should not consume the wait for the application's paint.
ssh "${SSH_OPTIONS[@]}" -M -S "$SCRATCH/ssh-control" -fN motor@192.168.4.2
SSH_CONTROL_STARTED=1
SSH_OPTIONS+=(-S "$SCRATCH/ssh-control" -o ControlMaster=no)

# A complete status bar records both dimensions as row:width.
red_bars() {
  LC_ALL=C grep -ao $'\033\\[[0-9]*;1H'"$1"$' \\[1\\] \\[No Name\\][^\033]*NORMAL | [0-9][0-9]*:[0-9][0-9]* ' |
    LC_ALL=C awk -F$'\033' '{
      row = $2; sub(/^\[/, "", row); sub(/;.*/, "", row)
      bar = $NF; sub(/^\[[0-9;]*m/, "", bar)
      printf "%s:%s ", row, length(bar)
    }'
}
RED_GROUND=$'\033\\[0m\033\\[38;5;233m\033\\[48;5;222m'
RMUX_GROUND=$'\033\\[0;38;5;233;48;5;222m'

completed_last_repaint() {
  # A full rmux repaint ends by restoring the cursor visibility. Do not expose
  # its status bar until that marker arrives: the SSH log can be read mid-write.
  LC_ALL=C awk '
    BEGIN { RS = "\033\\[2J" }
    { last = $0; seen = NR }
    END {
      shown = index(last, "\033[?25h")
      hidden = index(last, "\033[?25l")
      if (!shown || (hidden && hidden < shown))
        end = hidden
      else
        end = shown
      if (seen > 1 && end)
        printf "%s", substr(last, 1, end + 5)
    }'
}
# Replay cursor moves and erases into the picture seen by the terminal.
screen_rows() {
  LC_ALL=C.UTF-8 awk -v rows="$1" -v cols="$2" '
    function down() { r++; if (rows && r >= rows) r = rows - 1 }
    function erase(y, from, to,   x) { for (x = from; x < to; x++) delete g[y, x] }
    function clear_all() { delete g; r = 0; c = 0 }
    NR > 1 { s = s "\n" }
    { s = s $0 }
    END {
      n = split(s, ch, "")
      for (i = 1; i <= n; i++) {
        x = ch[i]
        if (x == "\r") c = 0
        else if (x == "\n") down()
        else if (x == "\b") { if (c > 0) c-- }
        else if (x == "\033" && ch[i + 1] == "[") {
          p = ""
          for (i += 2; i <= n && ch[i] !~ /[@-~]/; i++) p = p ch[i]
          f = ch[i]
          priv = sub(/^\?/, "", p)
          split(p, a, ";")
          k = a[1] + 0; m = k ? k : 1
          if (f == "H" || f == "f") { r = m - 1; c = (a[2] + 0 ? a[2] - 1 : 0) }
          else if (f == "A") r = r > m ? r - m : 0
          else if (f == "B") r += m
          else if (f == "C") c += m
          else if (f == "D") c = c > m ? c - m : 0
          else if (f == "G") c = m - 1
          else if (f == "K") erase(r, k == 0 ? c : 0, k == 1 ? c + 1 : cols)
          else if (f == "J" && k >= 2) clear_all()
          else if (f == "J") {
            erase(r, k == 0 ? c : 0, k == 0 ? cols : c + 1)
            for (y = k == 0 ? r + 1 : 0; y < (k == 0 ? maxr + 1 : r); y++) erase(y, 0, cols)
          } else if ((f == "h" || f == "l") && priv && (k == 1049 || k == 1047 || k == 47))
            clear_all()
          if (rows && r >= rows) r = rows - 1
          if (c >= cols) c = cols - 1
        } else if (x == "\033" && ch[i + 1] == "]") {
          for (i += 2; i <= n && ch[i] != "\007" && ch[i] != "\033"; i++) ;
          if (ch[i] == "\033") i++
        } else if (x == "\033") {
          x = ch[++i]
          if (x == "7") { sr = r; sc = c }
          else if (x == "8") { r = sr; c = sc }
        } else if (x >= " " && x != "\177") {
          if (c >= cols) { c = 0; down() }
          g[r, c++] = x
          if (r > maxr) maxr = r
        }
      }
      last = rows ? rows - 1 : maxr
      for (y = 0; y <= last; y++) {
        line = ""
        for (x = 0; x < cols; x++) line = line ((y, x) in g ? g[y, x] : " ")
        sub(/ +$/, "", line)
        out[y] = line
      }
      if (!rows) while (last >= 0 && out[last] == "") last--
      for (y = 0; y <= last; y++) print out[y]
    }'
}

# Poll only while the expected output is absent. A deadline diagnoses a missing
# event; successful steps advance as soon as their output arrives.
wait_for() {
  local deadline=$((SECONDS + 5))
  until "$@"; do
    [ "$SECONDS" -lt "$deadline" ] || fail "timed out: $*"
    sleep 0.01
  done
}

since() { tail -c "+$(($2 + 1))" "$1"; }
mark() { wc -c < "$1"; }
has() { since "$1" "$2" | LC_ALL=C grep -aFq -- "$3"; }
wait_text() { wait_for has "$@"; }
prompt() { wait_text "$1" "$2" $'\033[?25h'; }
console_since() { since "$CONSOLE_LOG" "$1"; }

console_command() {
  local at
  at="$(mark "$CONSOLE_LOG")"
  printf '%s\r' "$1" >&3
  wait_text "$CONSOLE_LOG" "$at" "$2"
  wait_text "$CONSOLE_LOG" "$at" $'\033[?2048h'
  prompt "$CONSOLE_LOG" "$at"
}

bars_are() {
  [ "$(since "$1" "$2" | red_bars "$RED_GROUND")" = "$3 " ]
}
wait_bars() { wait_for bars_are "$@"; }

# A refresh is consumed by rmux, never by its pane. Read the completed full
# frame so partial diffs cannot look like a missing or incorrectly sized bar.
frame_complete() {
  [ -n "$(since "$1" "$2" | completed_last_repaint)" ]
}
rmux_frame() {
  local at
  at="$(mark "$1")"
  printf '%b' "$RMUX_REFRESH" >&4
  wait_for frame_complete "$1" "$at"
  since "$1" "$at" | completed_last_repaint
}
rmux_bar() {
  local deadline=$((SECONDS + 5)) bar
  while :; do
    bar="$(rmux_frame "$1" | red_bars "$RMUX_GROUND")"
    [ "$bar" = "$2 " ] && return
    [ "$SECONDS" -lt "$deadline" ] || fail "rmux bar '$bar', want '$2' ($1)"
  done
}
rmux_row() {
  rmux_frame "$1" | screen_rows "$2" "$3" | grep -Fxq -- "$4"
}
rmux_contains() {
  rmux_frame "$1" | screen_rows "$2" "$3" | grep -Fq -- "$4"
}
rmux_row_contains() {
  rmux_frame "$1" | screen_rows "$2" "$3" | sed -n "${4}p" | grep -Fq -- "$5"
}
rmux_lacks() {
  local frame
  frame="$(rmux_frame "$1")" || return
  ! printf '%s' "$frame" | screen_rows "$2" "$3" | grep -Fq -- "$4"
}
rmux_status() {
  rmux_frame "$1" | screen_rows "$2" "$3" | tail -n 1 | grep -Fq -- "$4"
}
rmux_window_closed() {
  local frame
  frame="$(rmux_frame "$1")" || return
  ! printf '%s' "$frame" | screen_rows "$2" "$3" | tail -n 1 | grep -Fq '1:'
}

# A persistent input FIFO keeps script(1) from injecting EOF. The controller
# resizes its actual PTY; there is no second script coordinating by sleeps.
start_session() {
  local name="$1" terminal="$2" command tty_path
  shift 2
  SESSION_LOG="/tmp/test-terminal-size-$name.log"
  : > "$SESSION_LOG"
  rm -f "$SCRATCH/session-in" "$SCRATCH/session-tty"
  mkfifo "$SCRATCH/session-in"
  exec 4<> "$SCRATCH/session-in"
  if [ "$terminal" = pty ]; then
    printf -v command '%q ' ssh "${SSH_OPTIONS[@]}" -e none -tt motor@192.168.4.2 "$@"
    printf -v tty_path '%q' "$SCRATCH/session-tty"
    script -qef -E never -c "stty rows 30 cols 100; tty > $tty_path; exec $command" \
      "$SESSION_LOG" < "$SCRATCH/session-in" > /dev/null 2>> "$RMUX_STDERR_LOG" &
  else
    ssh "${SSH_OPTIONS[@]}" -e none motor@192.168.4.2 "$@" \
      < "$SCRATCH/session-in" > "$SESSION_LOG" 2>> "$RMUX_STDERR_LOG" &
  fi
  SESSION_PID="$!"
}
resize_session() {
  stty -F "$(cat "$SCRATCH/session-tty")" rows "$1" cols "$2"
}
finish_session() {
  wait_for session_finished
  wait "$SESSION_PID" || fail "terminal session failed ($SESSION_LOG)"
  SESSION_PID=""
  exec 4>&-
}
session_finished() { ! kill -0 "$SESSION_PID" 2>/dev/null; }
shell_exit() {
  local at
  at="$(mark "$1")"
  printf ':q\r' >&"$2"
  wait_text "$1" "$at" $'\033[?1049l'
  prompt "$1" "$at"
}

# Coverage kept in the component tests reached by full-test.sh:
# - Rush phase8.rs: editing, history, completion, wrapping, incremental output.
#   systest stdio_terminal.rs retains Motor's type-ahead and delayed CR/LF cases.
# - Crossterm motor/probe.rs: polling cadence and silence after subscription,
#   tested with supplied Instants rather than ten seconds of wall-clock time.
# - rmux pane.rs: unsubscribed children receive no resize bytes, checked with
#   an ordered output marker rather than waiting for top's next repaint.
# This driver retains first paint, resize without keys, size inheritance,
# serial CR/LF, and the console/SSH/pane paths that need the actual guest.
echo "-- serial console --"
prompt "$CONSOLE_LOG" 0
console_command 'echo PROMPT_WIDTH=$COLUMNS' 'PROMPT_WIDTH=80'
at="$(mark "$CONSOLE_LOG")"
printf '\033[?2048;1$y\033[48;30;100;0;0t' >&3
prompt "$CONSOLE_LOG" "$at"
console_command 'echo PROMPT_WIDTH=$COLUMNS' 'PROMPT_WIDTH=100'
at="$(mark "$CONSOLE_LOG")"
printf 'echo RESIZE-ME' >&3
wait_text "$CONSOLE_LOG" "$at" 'echo RESIZE-ME'
at="$(mark "$CONSOLE_LOG")"
printf '\033[48;20;60;0;0t' >&3
wait_text "$CONSOLE_LOG" "$at" 'echo RESIZE-ME'
prompt "$CONSOLE_LOG" "$at"
console_command '' $'\r\n'
console_command 'echo PROMPT_WIDTH=$COLUMNS; echo COLS=$COLUMNS,$LINES' 'COLS=60,20'
console_command 'echo PROMPT_WIDTH=$COLUMNS' 'PROMPT_WIDTH=60'
widths="$(grep -aoE 'PROMPT_WIDTH=[0-9]+' "$CONSOLE_LOG" | tr '\n' ' ')"
[ "$widths" = 'PROMPT_WIDTH=80 PROMPT_WIDTH=100 PROMPT_WIDTH=60 PROMPT_WIDTH=60 ' ] ||
  fail "console widths: $widths"

echo "-- red on the serial console --"
red_at="$(mark "$CONSOLE_LOG")"
start_red console >&3
wait_bars "$CONSOLE_LOG" "$red_at" '23:80'
printf '\033[?2048;1$y\033[48;20;60;0;0t' >&3
wait_bars "$CONSOLE_LOG" "$red_at" '23:80 19:60'
printf '\033[48;30;100;0;0t' >&3
wait_bars "$CONSOLE_LOG" "$red_at" '23:80 19:60 29:100'
shell_exit "$CONSOLE_LOG" 3

echo "-- rmux on the serial console --"
at="$(mark "$CONSOLE_LOG")"
printf '\033[?2048;1$y\033[48;30;100;0;0t' >&3
prompt "$CONSOLE_LOG" "$at"
rmux_at="$(mark "$CONSOLE_LOG")"
RMUX_CONSOLE_STARTED=1
printf 'TMPDIR=%s MOTOR_OS_CAPS=0x3ec /user/bin/rush -c rmux 2>%s/rmux-console.stderr\r' "$RMUX_TMPDIR" "$TEST_TMP" >&3
wait_text "$CONSOLE_LOG" "$rmux_at" $'\033[?2048h'
printf '\033[?2048;1$y\033[48;30;100;0;0t' >&3
exec 4>&3
RMUX_REFRESH='\001r'
[ "$VMM" != qemu ] || RMUX_REFRESH='\001\001r'
wait_for rmux_contains "$CONSOLE_LOG" 30 100 '/user$'
start_red console-rmux >&3
rmux_bar "$CONSOLE_LOG" '28:100'
printf '\033[48;20;60;0;0t' >&3
rmux_bar "$CONSOLE_LOG" '18:60'
printf ':q\r' >&3
wait_for rmux_contains "$CONSOLE_LOG" 20 60 '/user$'
printf '\033[48;30;100;0;0t' >&3
wait_for rmux_status "$CONSOLE_LOG" 30 100 '[0] '
mapfile -t rows < <(rmux_frame "$CONSOLE_LOG" | screen_rows 30 100)
[[ "${rows[29]}" == *'[0] '* ]] || fail "rmux status did not move to row 30"
[[ "${rows[19]}" != *'[0] '* ]] || fail "rmux status remained on row 20"

# Preserve the Motor-only line discipline and serial rendering assertions.
printf '\014' >&3
wait_for rmux_row_contains "$CONSOLE_LOG" 30 100 1 '/user$'
before="$(rmux_frame "$CONSOLE_LOG" | screen_rows 30 100 | grep -c '\$')"
printf "echo o''ne\r" >&3
wait_for rmux_row "$CONSOLE_LOG" 30 100 one
wait_for rmux_row_contains "$CONSOLE_LOG" 30 100 3 '/user$'
after="$(rmux_frame "$CONSOLE_LOG" | screen_rows 30 100 | grep -c '\$')"
[ "$after" = $((before + 1)) ] || fail "one Enter gave $((after - before)) prompts"
printf "echo a''aa; echo b''bb\r" >&3
wait_for rmux_row "$CONSOLE_LOG" 30 100 aaa
wait_for rmux_row "$CONSOLE_LOG" 30 100 bbb
wait_for rmux_row_contains "$CONSOLE_LOG" 30 100 6 '/user$'
at="$(mark "$CONSOLE_LOG")"
printf e >&3
wait_text "$CONSOLE_LOG" "$at" e
at="$(mark "$CONSOLE_LOG")"
printf x >&3
wait_text "$CONSOLE_LOG" "$at" x
rmux_frame "$CONSOLE_LOG" > /dev/null
out="$(console_since "$at")"
[ "${out%%$'\033[0m\033[2J'*}" = x ] ||
  fail "a pane keystroke wrote $(printf '%q' "${out%%$'\033[0m\033[2J'*}")"
at="$(mark "$CONSOLE_LOG")"
# Retain this session to keep the server alive. Later cases get fresh sessions
# and panes without repeating the cold server launch already exercised here.
printf '%b' "\025${RMUX_REFRESH%r}d" >&3
wait_text "$CONSOLE_LOG" "$at" $'\033[?1049l'
prompt "$CONSOLE_LOG" "$at"
exec 4>&-

echo "-- russhd pty session --"
start_session rush-ssh pty
prompt "$SESSION_LOG" 0
at="$(mark "$SESSION_LOG")"
printf 'echo PROMPT_WIDTH=$COLUMNS\r' >&4
wait_text "$SESSION_LOG" "$at" 'PROMPT_WIDTH=100'
prompt "$SESSION_LOG" "$at"
at="$(mark "$SESSION_LOG")"
printf 'echo RESIZE-ME' >&4
wait_text "$SESSION_LOG" "$at" 'echo RESIZE-ME'
at="$(mark "$SESSION_LOG")"
resize_session 20 60
wait_text "$SESSION_LOG" "$at" 'echo RESIZE-ME'
prompt "$SESSION_LOG" "$at"
at="$(mark "$SESSION_LOG")"
printf '\r' >&4
prompt "$SESSION_LOG" "$at"
at="$(mark "$SESSION_LOG")"
printf 'echo PROMPT_WIDTH=$COLUMNS; echo COLS=$COLUMNS,$LINES\r' >&4
wait_text "$SESSION_LOG" "$at" 'COLS=60,20'
prompt "$SESSION_LOG" "$at"
at="$(mark "$SESSION_LOG")"
printf 'echo PROMPT_WIDTH=$COLUMNS\r' >&4
wait_text "$SESSION_LOG" "$at" 'PROMPT_WIDTH=60'
prompt "$SESSION_LOG" "$at"
printf 'exit\r' >&4
finish_session
widths="$(grep -aoE 'PROMPT_WIDTH=[0-9]+' "$SESSION_LOG" | tr '\n' ' ')"
[ "$widths" = 'PROMPT_WIDTH=100 PROMPT_WIDTH=60 PROMPT_WIDTH=60 ' ] ||
  fail "SSH widths: $widths"

echo "-- red in a russhd pty session --"
start_session red-ssh pty
prompt "$SESSION_LOG" 0
red_at="$(mark "$SESSION_LOG")"
start_red ssh >&4
wait_bars "$SESSION_LOG" "$red_at" '29:100'
resize_session 20 60
wait_bars "$SESSION_LOG" "$red_at" '29:100 19:60'
shell_exit "$SESSION_LOG" 4
printf 'exit\r' >&4
finish_session

echo "-- rmux over ssh --"
start_session rmux-ssh pty "TMPDIR=$RMUX_TMPDIR" /user/bin/rmux new -s ssh-resize
RMUX_REFRESH='\001r'
wait_for rmux_contains "$SESSION_LOG" 30 100 '/user$'
start_red ssh-rmux >&4
rmux_bar "$SESSION_LOG" '28:100'
resize_session 20 60
rmux_bar "$SESSION_LOG" '18:60'
printf ':q\r' >&4
wait_for rmux_contains "$SESSION_LOG" 20 60 '/user$'
printf 'exit\r' >&4
finish_session

echo "-- rmux pane --"
start_session rmux-pane pipe "TMPDIR=$RMUX_TMPDIR" /user/bin/rmux new -s pane-resize
wait_for rmux_contains "$SESSION_LOG" 24 80 '/user$'
printf '\014' >&4
wait_for rmux_contains "$SESSION_LOG" 24 80 '/user$'
printf 'echo %s' "$(printf 'x%.0s' $(seq 1 45))" >&4
wait_for rmux_contains "$SESSION_LOG" 24 80 "$(printf 'x%.0s' $(seq 1 45))"
printf '\001|' >&4
wait_for rmux_row_contains "$SESSION_LOG" 24 80 2 "$(printf 'x%.0s' $(seq 1 20))"
# The tail must be on the next row, before any key reaches the resized shell.
mapfile -t rows < <(rmux_frame "$SESSION_LOG" | screen_rows 24 80)
[[ "${rows[1]}" == "$(printf 'x%.0s' $(seq 1 20))"* ]] ||
  fail "the split did not rewrap the half-typed line"
printf '\001c' >&4
wait_for rmux_status "$SESSION_LOG" 24 80 '1:'
printf 'exit\r' >&4
wait_for rmux_window_closed "$SESSION_LOG" 24 80
printf '\001o\003' >&4
wait_for rmux_contains "$SESSION_LOG" 24 80 '/user$'
printf 'echo COLS=$COLUMNS,$LINES\r' >&4
wait_for rmux_contains "$SESSION_LOG" 24 80 'COLS=40,23'
printf 'exit\r' >&4
wait_for rmux_lacks "$SESSION_LOG" 24 80 '│'
wait_for rmux_contains "$SESSION_LOG" 24 80 '/user$'
printf 'exit\r' >&4
finish_session

echo "-- red in an rmux pane --"
start_session red-pane pipe "TMPDIR=$RMUX_TMPDIR" /user/bin/rmux new -s red-resize
wait_for rmux_contains "$SESSION_LOG" 24 80 '/user$'
start_red pane >&4
rmux_bar "$SESSION_LOG" '22:80'
printf '\001-' >&4
rmux_bar "$SESSION_LOG" '10:80'
printf '\001c' >&4
wait_for rmux_status "$SESSION_LOG" 24 80 '1:'
printf 'exit\r' >&4
wait_for rmux_window_closed "$SESSION_LOG" 24 80
printf '\001o' >&4
printf ':q\r' >&4
wait_for rmux_lacks "$SESSION_LOG" 24 80 '[No Name]'
wait_for rmux_contains "$SESSION_LOG" 24 80 '/user$'
printf 'exit\r' >&4
wait_for rmux_lacks "$SESSION_LOG" 24 80 '─'
wait_for rmux_contains "$SESSION_LOG" 24 80 '/user$'
printf 'exit\r' >&4
finish_session

ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 "TMPDIR=$RMUX_TMPDIR" \
  /user/bin/rmux kill-session -t 0
save_red_stderr
remove_test_root
stop_serial_test_vm
echo "-------- TEST-TERMINAL-SIZE PASS ---------"
