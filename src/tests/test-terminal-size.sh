#!/bin/bash
#
# Acceptance validation for in-band terminal size
# (docs/plans/terminal-size-events.md), from the application's end: rush is the
# program in front of all three of this system's terminals, and what is checked
# here is that it lays every prompt out for the size the terminal last said it
# was, and redraws the line it is holding when that size changes with no key
# typed. There is no `SIGWINCH` here to make that happen and no `TIOCGWINSZ` to
# ask afterwards; the only news of a resize is the report the terminal writes
# into the program's own stdin.
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
# matches: a key would repaint too, so every assertion is made against the
# bytes that arrived before the next one was sent.

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
if [ "${1:-}" = "--release" ]; then
  BUILD="release"
fi
ROOT_DIR="$WD/../.."
IMG_DIR="$WD/../../vm_images/$BUILD"

# Image selection mirrors full-test.sh so full-test-dev.sh covers this script
# against the dev image as well.
IMG_TARGET="${FULL_TEST_IMG_TARGET:-main.img}"
export MOTO_IMAGE="${FULL_TEST_IMAGE:-motor-os.img}"

if [ "$BUILD" = "release" ]; then
  make -C "$ROOT_DIR" "$IMG_TARGET" BUILD=release -j"$(nproc)"
else
  make -C "$ROOT_DIR" "$IMG_TARGET" -j"$(nproc)"
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

fail() {
  echo "test-terminal-size: $*" >&2
  exit 1
}

CONSOLE_LOG=/tmp/test-terminal-size.log
SCRATCH="$(mktemp -d)"
VMM_PID=""

cleanup() {
  set +e
  stop_vm "$VMM_PID"
  VMM_PID=""
  exec 3>&-
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

# The serial console's stdin: the fifo stays open on fd 3 so the console can be
# answered at any point, and qemu never sees EOF until cleanup.
mkfifo "$SCRATCH/console-in"

echo "test-terminal-size: starting a $BUILD VM; console log in $CONSOLE_LOG"
"$IMG_DIR/run-qemu.sh" < "$SCRATCH/console-in" > "$CONSOLE_LOG" 2>&1 &
VMM_PID="$!"
exec 3> "$SCRATCH/console-in"

wait_console() {
  for _ in $(seq 1 120); do
    if grep -aq "$1" "$CONSOLE_LOG"; then
      return
    fi
    sleep 0.5
  done
  fail "the console never wrote '$1' (log: $CONSOLE_LOG)"
}

# The editor's prompt marker is a width gauge that costs nothing to read: rush
# opens every prompt with a reverse-video `%` and then a whole row of spaces
# (zsh's PROMPT_SP, `term.rs`'s `mark_partial_line`), so the run of spaces
# before the return to column 0 *is* the width it laid that prompt out for.
# Reads the recording on stdin and prints one width per prompt.
prompt_widths() {
  LC_ALL=C grep -ao $'\033\\[7m%\033\\[0m *\033\\[1G' |
    LC_ALL=C awk '{ gsub(/[^ ]/, ""); print length($0) + 1 }' |
    tr '\n' ' '
}

# Everything the console has said since byte $1.
console_since() {
  tail -c "+$(($1 + 1))" "$CONSOLE_LOG"
}

# ---- the serial console, in front of a terminal that implements mode 2048 ----
#
# The console is the one terminal whose size nobody in Motor OS knows: sys-tty
# is a byte pump with no opinion (plan §5), so the first prompt is painted at
# crossterm's non-blocking 80x24 fallback and the real size arrives afterwards.
# That is decision 8's deliberate asymmetry, and the point of this check is what
# happens *after* it -- that the size arrives at all without anyone pressing a
# key, and that it keeps arriving.
echo "-- serial console --"
wait_console $'\033\\[?2048h'

# The terminal's side of the handshake: DECRPM says the mode is set, and an
# enable is answered with the size straight away. The wait is for the client to
# have read it, so that the byte the quiet window starts at is one no probe
# still in flight from before the answer can land past.
printf '\033[?2048;1$y\033[48;30;100;0;0t' >&3
sleep 3
answered_at="$(wc -c < "$CONSOLE_LOG")"

# Enter, for a prompt laid out after the report landed.
printf '\r' >&3
sleep 3
printf 'echo RESIZE-ME' >&3
sleep 3

# The resize, and nothing else: no key is sent until this window is read, so
# whatever repaints the line here did it on the report alone.
resize_at="$(wc -c < "$CONSOLE_LOG")"
printf '\033[48;20;60;0;0t' >&3
sleep 3
console_since "$resize_at" | LC_ALL=C grep -aq 'echo RESIZE-ME' ||
  fail "the console's editor did not redraw its line for the new size"

printf '\r' >&3
sleep 3

# What the shell knows, the command it runs is told. Nothing set `$COLUMNS` for
# the console -- sys-tty has no opinion about the size -- so here the shell
# keeps it as a variable of its own rather than starting to export one nobody
# asked it to pass on, which is bash's rule and the one `Shell::set` follows.
printf 'echo COLS=$COLUMNS,$LINES\r' >&3
sleep 3
LC_ALL=C grep -aq 'COLS=60,20' "$CONSOLE_LOG" ||
  fail "the console ran a command at the old size (log: $CONSOLE_LOG)"

widths="$(prompt_widths < "$CONSOLE_LOG")"
[ "$widths" = "80 100 60 60 " ] ||
  fail "console prompt widths were '$widths', want '80 100 60 60 '"

# A client that has been answered stops asking, and the quiet is measured over
# everything since -- twelve seconds, comfortably more than the ten a probe
# would next have been due in. Both fallback rungs are gone: the cursor-free
# `CSI 18 t` and the corner probe alike, which is what a subscription is for
# (plan §1).
probes="$(console_since "$answered_at" |
  LC_ALL=C grep -ao $'\033\\[18t\|\033\\[9999;9999H' | wc -l)"
[ "$probes" = "0" ] ||
  fail "the console kept probing a terminal that had answered ($probes times)"

# ---- a russhd pty session ---------------------------------------------------
#
# Here the size is known before the child is spawned, so unlike the console
# there is nothing to converge on: the very first prompt is laid out for the
# `pty-req` geometry. `script` is what gives the ssh client a terminal to read a
# size from, `stty` resizes it under the running client, and the `SIGWINCH` that
# raises becomes the `window-change` russhd turns into a report.
echo "-- russhd pty session --"
until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /bin/echo " " > /dev/null; do
  if ! kill -0 "$VMM_PID" 2>/dev/null; then
    fail "QEMU exited before SSH became ready (log: $CONSOLE_LOG)"
  fi
  sleep 1
done

# `RESIZED` is written to this side's terminal, not into the session: it is a
# timestamp in the recording, marking the moment after which keys were typed
# again. Everything the editor did before it, it did unprompted.
ssh_login="$(printf '%q ' ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2)"
ssh_keys() {
  sleep 6
  printf 'echo RESIZE-ME'
  sleep 13
  printf '\r'
  sleep 4
  printf 'echo COLS=$COLUMNS,$LINES\r'
  sleep 4
  printf 'exit\r'
  sleep 3
}
out="$(ssh_keys | script -qc "stty rows 30 cols 100
$ssh_login </dev/tty 2>/dev/null &
sshpid=\$!
sleep 13
stty rows 20 cols 60
sleep 4
printf RESIZED > /dev/tty
wait \$sshpid" /dev/null)"

before="${out%%RESIZED*}"
[ "$before" != "$out" ] || fail "the pty harness never reached its resize"
case "$before" in
  *"echo RESIZE-ME"*"echo RESIZE-ME"*) ;;
  *) fail "the ssh session's editor did not redraw its line for the new size" ;;
esac
widths="$(printf '%s' "$out" | prompt_widths)"
[ "$widths" = "100 60 60 " ] ||
  fail "ssh pty prompt widths were '$widths', want '100 60 60 '"

# The shell knowing the size is only half of it: the program it launches is
# handed one too, in `$COLUMNS`/`$LINES`, and it is handed that one before it
# can ask for itself. A shell that let those go stale after a resize would give
# every command it ran the size the terminal used to be.
case "$out" in
  *"COLS=60,20"*) ;;
  *) fail "the ssh session ran a command at the old size: '$out'" ;;
esac

# ---- an rmux pane -----------------------------------------------------------
#
# A split halves the pane under the shell in it, which is the resize rmux's
# details.md §3.2 is written about. The line typed before the split fits one row
# of an 80-column pane and needs two rows of the ~40 it is left with, so the
# tail of it appearing on the pane's second row is the editor having been told.
#
# `C-a c` opens a second window: an rmux command, which never reaches the pane,
# and the `1:` it adds to the status line is the mark that the checked bytes
# came before any key the shell could have seen.
echo "-- rmux pane --"
rmux_keys() {
  sleep 3
  printf 'echo %s' "$(printf 'x%.0s' $(seq 1 45))"
  sleep 4
  printf '\001|'    # the split, and the last key the pane's shell may see
  sleep 5
  printf '\001c'    # the mark: a second window, which the pane never hears of
  sleep 4
  printf 'exit\r'   # the second window
  sleep 3
  printf '\001o'    # back to the pane that was split, and shrank
  sleep 2
  printf '\003'     # drop the half-typed line
  sleep 2
  printf 'echo COLS=$COLUMNS,$LINES\r'
  sleep 4
  printf 'exit\r'   # the pane it was split from
  sleep 3
  printf 'exit\r'   # and the one the split made
  sleep 3
}
out="$(rmux_keys | ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 /bin/rmux 2>&1)"
before="${out%%1:sh*}"
[ "$before" != "$out" ] || fail "rmux never opened the second window: '$out'"
printf '%s' "$before" |
  LC_ALL=C grep -aq $'\033\\[2;1H\\(\033\\[[0-9;]*m\\)\\{0,1\\}x\\{20,\\}' ||
  fail "the split did not reach the pane's editor: '$before'"

# A vertical rule at column 41 leaves the left pane 40 columns of the 80 it had
# and all 23 of its rows, and that is the size the command run in it is given.
case "$out" in
  *"COLS=40,23"*) ;;
  *) fail "the pane ran a command at the size before the split: '$out'" ;;
esac

stop_vm "$VMM_PID"
VMM_PID=""

echo "-------- TEST-TERMINAL-SIZE PASS ---------"
