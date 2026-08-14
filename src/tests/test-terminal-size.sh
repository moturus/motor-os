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
# that arrived before the next one was sent. Behind rmux that is a screen rather
# than a span of bytes, for the reason `settled_bar` is about.

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
RMUX_TMPDIR=/sys/tmp/test-terminal-size-rmux

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
# The pty recordings live beside it, and outlive the run for the same reason:
# a check that fails here is not reproducible on demand, and the bytes are the
# only evidence of what the terminal actually said.
SCRATCH="$(mktemp -d)"
VMM_PID=""

cleanup() {
  set +e
  stop_vm "$VMM_PID"
  VMM_PID=""
  exec 3>&- 4>&-
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

# The same as wait_console, counting only what the console has said since byte
# $1: every program that reaches the console subscribes, so the handshake worth
# waiting for is the next one and not the one already in the log.
wait_console_since() {
  for _ in $(seq 1 120); do
    if console_since "$1" | LC_ALL=C grep -aq "$2"; then
      return
    fi
    sleep 0.5
  done
  fail "the console never wrote '$2' after byte $1 (log: $CONSOLE_LOG)"
}

# Every status bar red painted, as `row:width`, from a recording on stdin.
#
# `render_status_bar` pads the bar to exactly the terminal's width and `draw`
# puts it on the row above the message bar, so one bar says both how wide red
# thinks the terminal is and how tall. Only a bar repainted from column 1 is
# counted, which a resize produces and a keystroke -- rewriting the columns it
# changed -- does not. $1 is the SGR the amber ground arrives as.
red_bars() {
  LC_ALL=C grep -ao $'\033\\[[0-9]*;1H'"$1"$' \\[1\\] \\[No Name\\][^\033]*' |
    LC_ALL=C awk -F$'\033' '{
      row = $2; sub(/^\[/, "", row); sub(/;.*/, "", row)
      bar = $NF; sub(/^\[[0-9;]*m/, "", bar)
      printf "%s:%s ", row, length(bar)
    }'
}

# How red spells its amber ground (`editor.rs`'s `paint_style`), and how rmux
# respells the same style when it repaints a pane from its own grid
# (`screen.rs`'s `sgr`) rather than forwarding the editor's bytes.
RED_GROUND=$'\033\\[0m\033\\[38;5;233m\033\\[48;5;222m'
RMUX_GROUND=$'\033\\[0;38;5;233;48;5;222m'

# The last completed full repaint in a recording on stdin, or nothing if there
# has not been one. `ESC[2J` reaches a console only from `screen.rs`; what a
# program inside a pane clears is its pane.
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

# The bar red has on rmux's screen, as `row:width`, once it is no longer $2 --
# the reading taken before whatever this is measuring, or "" for the first one
# of a session. "none" if it never settles.
#
# What rmux sends cannot be read as a screen. It repaints a pane from its own
# grid whenever it next draws, and that can fall in the middle of the editor's
# frame: the bar then arrives as two runs, the first from column 1 carrying no
# style and the rest from wherever it stopped, and no pattern matches it. So
# this asks for a screen rather than reading the difference between two of
# them. `refresh-client` makes rmux forget what is on the console (`screen.rs`'s
# `invalidate`), and the frame after it is a full one: every row from column 1,
# each style run whole.
#
# A refresh is idempotent and costs one frame, which is why waiting for the
# resize to arrive is a refresh rather than a sleep long enough to be sure. What
# an editor that never heard about it leaves behind is not the row it used to be
# on: a grid that shrank dropped the rows off the bottom -- `grid.rs`'s
# `reshape` clips and never reflows -- so the bar is gone from the screen
# altogether and the reading is "none".
#
# The refresh goes out on fd 4 as $RMUX_REFRESH, both of which each section sets
# for the keyboard it is driving. The fd, because the readings are taken inside
# command substitutions, where fd 1 is the substitution and not the terminal.
# The bytes, because rmux's prefix is `C-a` and so is qemu's: `-nographic`
# multiplexes the monitor onto the same stdio, and a lone `C-a` there is eaten
# by the emulator -- `C-a c` does not reach the guest at all, it switches to the
# qemu monitor. Doubling it is how qemu is told to pass its escape through.
settled_bar() {
  local log="$1" was="$2" since bar seen="none"
  for _ in $(seq 1 20); do
    since="$(wc -c < "$log")"
    printf '%b' "$RMUX_REFRESH" >&4
    for _ in $(seq 1 8); do
      sleep 0.3
      bar="$(tail -c "+$((since + 1))" "$log" |
        completed_last_repaint | red_bars "$RMUX_GROUND")"
      bar="${bar% }"
      [ -n "$bar" ] && break
    done
    if [ -n "$bar" ]; then
      seen="$bar"
      if [ "$bar" != "$was" ]; then
        break
      fi
    fi
  done
  printf '%s' "$seen"
}

# How many times red's bar text appears in $1 -- the plainest ASCII proof that
# the editor painted, usable from inside the `script -qc` shells below, where
# the console log's byte offsets are not available and escape sequences are
# awkward to quote. Occurrences, not lines: red writes no newlines, so a whole
# session can be one line.
bar_count_cmd() {
  printf "grep -ao '\\[1\\] \\[No Name\\]' %s 2>/dev/null | wc -l" "$1"
}

# The same count, for this shell rather than an inner one.
bar_count() {
  eval "$(bar_count_cmd "$1")"
}

# A command that succeeds once $2 holds red's bar on 1-based row $1, its ground
# spelled $3 -- how the ssh section waits for the repaint before closing the
# window it reads. Nothing composites there, so red's own frame is on the wire
# whole. The whole bar has to be matched and not just the cursor move in front
# of it: `ESC[{row};1H` alone is also what an erase writes on its way down the
# screen, and a wait that took one of those for the repaint would let the next
# key through before the frame it is there to wait for.
bar_at_row_cmd() {
  printf "grep -aq '%s\\[%s;1H%s \\[1\\] \\[No Name\\]' %s 2>/dev/null" \
    "$(printf '\033')" "$1" "$3" "$2"
}

# Wait until red has painted at all into the recording $1.
wait_bar() {
  for _ in $(seq 1 120); do
    if [ "$(bar_count "$1")" -gt 0 ]; then
      return
    fi
    sleep 0.5
  done
  fail "red never painted anything (log: $1)"
}

# Wait until red has painted $2 frames on the console since byte $1, its ground
# spelled $3.
#
# Every check below reads red's frames after making something happen, and the
# two have to be ordered: a resize sent before the editor has painted once is a
# resize the editor was simply started at, and proves nothing about resizing.
# Waiting for the frame rather than sleeping a guessed interval is what makes
# that ordering a fact -- and a red that never paints fails here, loudly, rather
# than turning into a confusing count later.
wait_red_bars() {
  local since="$1" want="$2" seen=0
  for _ in $(seq 1 60); do
    seen="$(console_since "$since" | red_bars "$RED_GROUND" | wc -w)"
    if [ "$seen" -ge "$want" ]; then
      return
    fi
    sleep 0.5
  done
  fail "red painted $seen of $want frames (log: $CONSOLE_LOG)"
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

# ---- red on the serial console ----------------------------------------------
#
# The editor is the other kind of client, and the harder one: it owns every row
# on the screen, so what it believes the size to be is on the wire in full, and
# it has no prompt to re-read a width at. On the console it starts out not
# knowing -- nobody set `$COLUMNS` here, which is what the check above is
# about -- so its first frame is crossterm's 80x24 fallback, painted without
# asking anyone and without waiting for an answer. That is decision 8's
# asymmetry; the point of the checks below is everything that comes after it.
echo "-- red on the serial console --"
red_at="$(wc -c < "$CONSOLE_LOG")"
printf 'red\r' >&3
wait_console_since "$red_at" $'\033\\[?2048h'
[ "$(console_since "$red_at" | red_bars "$RED_GROUND")" = "23:80 " ] ||
  fail "red's first console frame was not the 80x24 fallback (log: $CONSOLE_LOG)"

# The subscription, answered. Nothing has been typed since red started, so the
# frame that follows is the report's doing and can be nothing else's.
printf '\033[?2048;1$y\033[48;20;60;0;0t' >&3
wait_red_bars "$red_at" 2
bars="$(console_since "$red_at" | red_bars "$RED_GROUND")"
[ "$bars" = "23:80 19:60 " ] ||
  fail "red's console frames were '$bars', want '23:80 19:60 '"

# And it keeps arriving: a subscription is not a question answered once, which
# is the whole difference between it and the probe it replaced.
resize_at="$(wc -c < "$CONSOLE_LOG")"
printf '\033[48;30;100;0;0t' >&3
wait_red_bars "$resize_at" 1
bars="$(console_since "$resize_at" | red_bars "$RED_GROUND")"
[ "$bars" = "29:100 " ] ||
  fail "red did not repaint the console for the second resize: '$bars'"

printf ':q\r' >&3
sleep 3

# ---- rmux on the serial console ---------------------------------------------
#
# The whole design in one measurement, from the outside in: the terminal
# changes shape, crossterm turns the report into a resize, the client tells the
# server, the server relays out, the pane resizes, and the pane's own emulator
# reports the new size to the program subscribed inside it. That program is red
# again, because its status bar reads the same through two nested terminals as
# through one -- rmux is a terminal to the editor exactly as this script is a
# terminal to rmux.
#
# The client opens at 80x24 here and converges, which is the far side of its
# settlement window (`client.rs`'s `settle_size`): 200ms is a window and not a
# wait, and a terminal driven from a shell script over a serial line is nowhere
# near that fast. What the window promises is that nothing hangs when the
# answer is slow or never comes, which is this case; the case where it does
# arrive in time is `client.rs`'s own unit tests, a 200ms race being not
# something a shell script can win on purpose.
echo "-- rmux on the serial console --"
# rush re-asserts the mode whenever it takes the console back from a child.
# Answering keeps the shell that launches rmux from falling back to probing.
printf '\033[?2048;1$y\033[48;30;100;0;0t' >&3
sleep 2

rmux_at="$(wc -c < "$CONSOLE_LOG")"
printf 'TMPDIR=%s rmux\r' "$RMUX_TMPDIR" >&3
wait_console_since "$rmux_at" $'\033\\[?2048h'
answered_rmux_at="$(wc -c < "$CONSOLE_LOG")"
printf '\033[?2048;1$y\033[48;30;100;0;0t' >&3
# The client relayed it and the server laid out again: a screen that changed
# shape is repainted whole (`screen.rs`'s `draw`), so the clear is the report
# having gone all the way through and come back.
wait_console_since "$answered_rmux_at" $'\033\\[2J'
sleep 2

# red in the pane rmux has laid out: 29 rows of the console's 30, the last one
# being rmux's own status line. The pane's shell was spawned before the console
# answered and so was told 80x24 -- it is the report reaching *it* that makes
# `$COLUMNS` right for the editor it launches, one hop further in.
exec 4>&3
RMUX_REFRESH='\001\001r'    # doubled past qemu's console, see `settled_bar`
printf 'red\r' >&3
first="$(settled_bar "$CONSOLE_LOG" "")"

# The resize, sent only once the editor has painted once, so that what follows
# is a resize and not a size the editor was started at. Nothing is typed between
# here and the reading below except the refreshes it is taken with, which the
# pane never hears of.
printf '\033[48;20;60;0;0t' >&3
# 29 rows of pane in a 30-row console, then 19 in a 20-row one, each as wide as
# the console said it was.
bars="$first $(settled_bar "$CONSOLE_LOG" "$first")"
[ "$bars" = "28:100 18:60" ] ||
  fail "the console resize did not reach red inside rmux: '$bars', want '28:100 18:60'"

printf ':q\r' >&3
sleep 3
printf 'exit\r' >&3    # the pane, and with it rmux
sleep 4

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

# ---- red in a russhd pty session --------------------------------------------
#
# The editor's *first* frame is the whole of what this environment has to say.
# russhd knew the size before rush existed and rush passed it on, so red paints
# 100x30 straight away: there is no fallback frame here at all, which is the
# half of decision 8 the console cannot show. `REDRESIZED` marks the moment
# keys started again, exactly as `RESIZED` does above.
echo "-- red in a russhd pty session --"
red_ssh_log=/tmp/test-terminal-size-red-ssh.log
count="$(bar_count_cmd "$red_ssh_log")"
red_ssh_keys() {
  sleep 7
  printf 'red\r'
  # The mark below is written once the resize has been repainted, and no key
  # goes in before it: the frames this check reads have to be the resize's and
  # nothing else's, which a guessed interval cannot promise on a slow VM.
  for _ in $(seq 1 120); do
    grep -aq REDRESIZED "$red_ssh_log" && break
    sleep 0.5
  done
  sleep 2
  printf ':q\r'
  sleep 4
  printf 'exit\r'
  sleep 3
}
# `-f` is what makes the recording readable while it is being written: without
# it `script` holds the typescript in a buffer until the session ends, and every
# wait on it below silently falls through to its own timeout instead.
out="$(red_ssh_keys | script -qfc "stty rows 30 cols 100
$ssh_login </dev/tty 2>/dev/null &
sshpid=\$!
for _ in \$(seq 1 60); do
  [ \$($count) -gt 0 ] && break
  sleep 0.5
done
stty rows 20 cols 60
for _ in \$(seq 1 60); do
  $(bar_at_row_cmd 19 "$red_ssh_log" "$RED_GROUND") && break
  sleep 0.5
done
printf REDRESIZED > /dev/tty
wait \$sshpid" "$red_ssh_log")"

before="${out%%REDRESIZED*}"
[ "$before" != "$out" ] || fail "the pty harness never reached its resize"
bars="$(printf '%s' "$before" | red_bars "$RED_GROUND")"
[ "$bars" = "29:100 19:60 " ] ||
  fail "ssh pty red frames were '$bars', want '29:100 19:60 '"

# ---- rmux over ssh, with a terminal of its own ------------------------------
#
# The same chain as on the console with one more hop in front of it: the resize
# starts as a `SIGWINCH` on this host, becomes an SSH `window-change`, becomes
# russhd's report to the client, and goes on from there. Every link the design
# has is in this one measurement, and it is the only place they are all
# exercised at once.
#
# No settlement is needed here and none is used: russhd set `$COLUMNS` before
# the client existed, so `terminal::size()` is right on the first call and the
# opening frame is painted once without waiting for anything.
echo "-- rmux over ssh --"
rmux_login="$(printf '%q ' ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
  "TMPDIR=$RMUX_TMPDIR" /bin/rmux)"
rmux_ssh_log=/tmp/test-terminal-size-rmux-ssh.log
: > "$rmux_ssh_log"
: > "$SCRATCH/rmux-ssh-bars"
# The recording is kept rather than thrown at /dev/null, because everything this
# check does is timed off it: the resize has to come after the editor's first
# frame -- the same ordering the console section waits for -- and the readings
# are taken from it as it is written.
rmux_ssh_keys() {
  exec 4>&1
  RMUX_REFRESH='\001r'    # no qemu in this path: ssh carries the prefix as it is
  sleep 8
  printf 'red\r'
  wait_bar "$rmux_ssh_log"
  first="$(settled_bar "$rmux_ssh_log" "")"
  # The `stty` under the running client, which is what raises the `SIGWINCH`
  # that becomes the SSH `window-change`.
  : > "$SCRATCH/rmux-ssh-resize"
  printf '%s %s' "$first" "$(settled_bar "$rmux_ssh_log" "$first")" \
    > "$SCRATCH/rmux-ssh-bars"
  printf ':q\r'
  sleep 4
  printf 'exit\r'
  sleep 4
}
# The wait for the flag is bounded so that a reading which gives up ends the
# session rather than leaving it here: the keys are on the other end of this
# pipe, and a side that stops typing must not become a harness that hangs.
rmux_ssh_keys | script -qfc "stty rows 30 cols 100
$rmux_login </dev/tty 2>/dev/null &
sshpid=\$!
for _ in \$(seq 1 600); do
  [ -e $SCRATCH/rmux-ssh-resize ] && break
  sleep 0.2
done
stty rows 20 cols 60
wait \$sshpid" "$rmux_ssh_log" > /dev/null

bars="$(cat "$SCRATCH/rmux-ssh-bars")"
[ "$bars" = "28:100 18:60" ] ||
  fail "the ssh resize did not reach red inside rmux: '$bars', want '28:100 18:60'"

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
out="$(rmux_keys | ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 \
  "TMPDIR=$RMUX_TMPDIR" /bin/rmux 2>&1)"
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

# ---- red in an rmux pane ----------------------------------------------------
#
# The same pane and the other axis: `C-a -` stacks the panes, so what changes
# here is the row count, and the pane keeps every column it had.
echo "-- red in an rmux pane --"
# Recorded as it arrives, so the keys can wait on the editor rather than on a
# clock: the split must come after its first frame, or what is read afterwards
# is a size red was started at.
red_rmux_log=/tmp/test-terminal-size-rmux-pane.log
: > "$red_rmux_log"
: > "$SCRATCH/rmux-pane-bars"
red_rmux_keys() {
  exec 4>&1
  RMUX_REFRESH='\001r'
  sleep 4
  printf 'red\r'
  wait_bar "$red_rmux_log"
  first="$(settled_bar "$red_rmux_log" "")"

  printf '\001-'    # the split, and the last key the pane may see
  printf '%s %s' "$first" "$(settled_bar "$red_rmux_log" "$first")" \
    > "$SCRATCH/rmux-pane-bars"

  printf '\001c'    # the mark: a second window, which the pane never hears of
  sleep 4
  printf 'exit\r'   # the second window
  sleep 3
  printf '\001o'    # back to the pane that shrank
  sleep 2
  printf ':q\r'     # and out of the editor in it
  sleep 3
  printf 'exit\r'   # the pane it was split from
  sleep 3
  printf 'exit\r'   # and the one the split made
  sleep 3
}
out="$(red_rmux_keys |
  ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2 \
    "TMPDIR=$RMUX_TMPDIR" /bin/rmux 2>&1 |
  tee "$red_rmux_log")"
before="${out%%1:sh*}"
[ "$before" != "$out" ] || fail "rmux never opened the second window: '$out'"

# 23 rows of pane, not the 24 a client that had to guess would take, and then
# the 11 a stacked split leaves the top one. The width does not change, a
# stacked split being the other axis. The second reading is the one this check
# is for: a build with `get_terminal_size` pinned to the fallback still produces
# the first, because rmux settles before it paints its pane (decision 8) and a
# frame the compositor never sent is a frame nothing can observe. So what the
# pair says here is that nothing wrong ever reaches the screen and that the
# split reaches the editor; that red is laid out from `$COLUMNS` rather than
# corrected afterwards is shown over ssh, where it is visible.
bars="$(cat "$SCRATCH/rmux-pane-bars")"
[ "$bars" = "22:80 10:80" ] ||
  fail "rmux pane red frames were '$bars', want '22:80 10:80'"

stop_vm "$VMM_PID"
VMM_PID=""

echo "-------- TEST-TERMINAL-SIZE PASS ---------"
