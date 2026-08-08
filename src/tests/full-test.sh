#!/bin/bash

if [ "${FULL_TEST_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export FULL_TEST_TIMEOUT_ACTIVE=1
  # Let bash put timeout's process group in the foreground. Without job control,
  # timeout moves the suite into a background process group; a terminal
  # operation can then stop timeout and the entire suite with SIGTTIN/SIGTTOU.
  # Keeping timeout's separate group preserves its whole-process-tree timeout.
  set -m
  timeout 3600s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "full-test: timed out after 3600 seconds" >&2
  fi
  exit "$status"
fi

# abort on error
set -e

WD="$(dirname "$0")"

# Select the VM image build: debug by default, release with --release.
# run-qemu.sh lives in vm_images/<build>/, two levels up from src/tests/.
BUILD="debug"
if [ "${1:-}" = "--release" ]; then
  BUILD="release"
fi
# The repo root is two levels up from src/tests/.
ROOT_DIR="$WD/../.."
IMG_DIR="$WD/../../vm_images/$BUILD"

"$ROOT_DIR/src/tests/lorry-integration-driver-contract.sh"

# Build everything before running the tests.
if [ "$BUILD" = "release" ]; then
  make -C "$ROOT_DIR" all BUILD=release -j"$(nproc)"
  (cd "$ROOT_DIR/src/imager" && cargo test --release)
  "$ROOT_DIR/src/tests/lorry-integration-test.sh" --release --host-only
else
  make -C "$ROOT_DIR" all -j"$(nproc)"
  (cd "$ROOT_DIR/src/imager" && cargo test)
  "$ROOT_DIR/src/tests/lorry-integration-test.sh" --host-only
fi

# The benchmark's deadline tests use deliberately stalled host TCP peers.
if [ "$BUILD" = "release" ]; then
  cargo test --manifest-path "$ROOT_DIR/src/bin/rnetbench/Cargo.toml" --release
else
  cargo test --manifest-path "$ROOT_DIR/src/bin/rnetbench/Cargo.toml"
fi

# The netstack's own tests, under the exact feature closure sys-io builds it
# with: its packet-facing regressions run nowhere else in this suite, and a
# feature set that differs from sys-io's compiles different code.
NETSTACK_FEATURES="async,medium-ethernet,medium-ip,proto-ipv4,proto-ipv6,socket-icmp,socket-tcp,socket-udp,std"
if [ "$BUILD" = "release" ]; then
  cargo +nightly test --release \
    --manifest-path "$ROOT_DIR/src/sys/sys-io/netstack/Cargo.toml" \
    --no-default-features --features "$NETSTACK_FEATURES"
else
  cargo +nightly test \
    --manifest-path "$ROOT_DIR/src/sys/sys-io/netstack/Cargo.toml" \
    --no-default-features --features "$NETSTACK_FEATURES"
fi

# motor-fs's own tests: the filesystem's B+tree, transaction log, resize and
# readdir paths are covered here and nowhere else, against a host file-backed
# block device, in about a second. Must run from the crate directory --
# `src/sys/lib/motor-fs/.cargo/config.toml` supplies `--cfg tokio_unstable`,
# and cargo reads config only from the cwd and its ancestors, so a
# --manifest-path invocation from elsewhere drops the flag and fails to build.
if [ "$BUILD" = "release" ]; then
  (cd "$ROOT_DIR/src/sys/lib/motor-fs" && cargo test --quiet --release)
else
  (cd "$ROOT_DIR/src/sys/lib/motor-fs" && cargo test --quiet)
fi

# The host-side tests of the terminal programs: the parts that need no Motor OS
# at all run on Linux in seconds, so they run before the VM is even booted.
# rush's are here because its line editor is testable only over a terminal, and
# a pty is the one this host has -- including a resize, which on a pty is a
# `SIGWINCH` and on a Motor console is the answer to an `ESC[6n`.
for crate in red rmux rush; do
  if [ "$BUILD" = "release" ]; then
    (cd "$ROOT_DIR/src/bin/$crate" && cargo test --quiet --release)
  else
    (cd "$ROOT_DIR/src/bin/$crate" && cargo test --quiet)
  fi
done

# A fresh checkout leaves the key group-readable; ssh then silently ignores it.
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

# Some environments (e.g. a dev host behind qemu user-mode networking) cannot
# send external ICMP echo at all; probe once so external pings can tolerate it.
EXTERNAL_ICMP=1
ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || EXTERNAL_ICMP=0

# Ping an external host: name resolution must always succeed; a missing echo
# reply is tolerated iff the test host itself has no external ICMP.
ping_external() {
  local host="$1"
  local output

  if output="$(vm_ssh /bin/ping -c 1 "$host" 2>&1)"; then
    printf '%s\n' "$output"
    return
  fi
  printf '%s\n' "$output"
  if [ "$EXTERNAL_ICMP" = "0" ]; then
    case "$output" in
      *"Request timeout"*)
        echo "NOTE: '$host' resolved; echo reply skipped (host has no external ICMP)"
        return
        ;;
    esac
  fi
  fail "ping '$host' failed"
}

fail() {
  echo "full-test: $*" >&2
  exit 1
}

expect_ping_error() {
  local host="$1"
  local expected="$2"
  local output

  if output="$(vm_ssh /bin/ping -c 1 "$host" 2>&1)"; then
    printf '%s\n' "$output"
    fail "ping unexpectedly resolved '$host'"
  fi
  printf '%s\n' "$output"
  case "$output" in
    *"$expected"*) ;;
    *) fail "ping '$host' did not report '$expected'" ;;
  esac
}

wait_for_ping_error() {
  local host="$1"
  local expected="$2"
  local output=""

  for _ in $(seq 1 20); do
    if output="$(vm_ssh /bin/ping -c 1 "$host" 2>&1)"; then
      printf '%s\n' "$output"
      fail "ping unexpectedly resolved '$host'"
    fi
    case "$output" in
      *"$expected"*)
        printf '%s\n' "$output"
        return
        ;;
    esac
    sleep 0.1
  done

  printf '%s\n' "$output"
  fail "ping '$host' did not settle on '$expected'"
}

read_udp_socket_count() {
  local output=""
  local count=""
  local last_count=""

  for _ in $(seq 1 20); do
    count=""
    if output="$(vm_ssh /bin/stats get 2 2>&1)"; then
      count="$(printf '%s\n' "$output" |
        awk '$2 == "net.udp_sockets" { print $3 }')"
      if [ "$count" = "0" ]; then
        printf '0\n'
        return
      fi
      [ -z "$count" ] || last_count="$count"
    fi
    sleep 0.1
  done

  if [ -n "$last_count" ]; then
    printf '%s\n' "$last_count"
    return
  fi

  printf '%s\n' "$output" >&2
  fail "stats did not report net.udp_sockets"
}

DNS_RESOLVER_SSH_PID=""
VMM_PID=""

# cleanup routine
stop_vmm() {
  set +e
  if [ -n "$VMM_PID" ] && kill -0 "$VMM_PID" 2>/dev/null; then
    vm_ssh shutdown
    wait "$VMM_PID"
  fi
  VMM_PID=""
  if [ -n "$DNS_RESOLVER_SSH_PID" ]; then
    kill "$DNS_RESOLVER_SSH_PID" 2>/dev/null
    wait "$DNS_RESOLVER_SSH_PID"
  fi
}

# set the trap to call cleanup on exit
trap stop_vmm EXIT

echo "Starting Motor OS test."
echo "Console output is streamed below and saved to /tmp/full-test.log."
echo ""
echo ""


# FULL_TEST_QEMU_ARGS: optional extra qemu args (e.g. a monitor socket
# for hang forensics); run-qemu.sh passes "$@" through to qemu.
# Do not forward the guest's cursor-position query: tmux answers it on the
# pane's input, where the reply would be left for the shell after this run.
"$IMG_DIR/run-qemu.sh" ${FULL_TEST_QEMU_ARGS:-} \
  > >(sed -u $'s/\033\\[6n//g' | tee /tmp/full-test.log) 2>&1 &
VMM_PID="$!"

# A refused connection returns immediately, so OpenSSH's ConnectionAttempts
# does not reliably cover a slow debug boot. Retry explicitly; the overall
# 600-second harness timeout bounds this loop.
until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /bin/echo " "; do
  if ! kill -0 "$VMM_PID" 2>/dev/null; then
    vmm_status=0
    wait "$VMM_PID" || vmm_status="$?"
    VMM_PID=""
    cat /tmp/full-test.log >&2
    fail "QEMU exited before SSH became ready (status $vmm_status)"
  fi
  sleep 1
done
if ! kill -0 "$VMM_PID" 2>/dev/null; then
  vmm_status=0
  wait "$VMM_PID" || vmm_status="$?"
  VMM_PID=""
  cat /tmp/full-test.log >&2
  fail "SSH reached a VM after this run's QEMU exited (status $vmm_status)"
fi

vm_ssh /bin/ping -c 1 127.0.0.1
vm_ssh /bin/ping -c 1 localhost
expect_ping_error 2001:db8::1 NotConnected

echo "-- DNS resolver integration --"
vm_ssh /sys/dns-resolver --self-test
ping_external google.com
expect_ping_error does-not-exist.motor.invalid NotFound

udp_sockets="$(read_udp_socket_count)"
[ "$udp_sockets" = "0" ] ||
  fail "DNS tests left $udp_sockets active UDP socket(s)"

# Verify that numeric lookup is independent of the service, lookup failure is
# defined, and a later per-call client reconnects after the service restarts.
resolver_pid="$(vm_ssh /bin/ps |
  awk '$NF == "/sys/dns-resolver" { gsub(/\*/, "", $1); print $1; exit }')"
[ -n "$resolver_pid" ] || fail "could not find the dns-resolver process"
vm_ssh /bin/kill "$resolver_pid"
vm_ssh /bin/ping -c 1 127.0.0.1
wait_for_ping_error google.com NotConnected

"${SSH[@]}" /sys/dns-resolver >> /tmp/full-test-dns-resolver.log 2>&1 &
DNS_RESOLVER_SSH_PID="$!"

resolver_restarted=0
for _ in $(seq 1 20); do
  if vm_ssh /sys/dns-resolver --self-test; then
    resolver_restarted=1
    break
  fi
  sleep 0.1
done
[ "$resolver_restarted" = "1" ] ||
  fail "dns-resolver did not become ready after restart"
ping_external google.com

udp_sockets="$(read_udp_socket_count)"
[ "$udp_sockets" = "0" ] ||
  fail "restarted DNS service left $udp_sockets active UDP socket(s)"

# Let systest output flow to the console as it happens; tee keeps a copy so
# the verdict can still be checked. pipefail makes the pipeline carry
# systest's own status rather than tee's.
SYSTEST_LOG=/tmp/full-test-systest.log
systest_status=0
set -o pipefail
vm_ssh sys/tests/systest 2>&1 | tee "$SYSTEST_LOG" || systest_status="$?"
set +o pipefail
[ "$systest_status" -eq 0 ] ||
  fail "systest exited with status $systest_status"

# $(...) drops trailing newlines, so this is the last non-empty line.
systest_output="$(cat "$SYSTEST_LOG")"
[ "${systest_output##*$'\n'}" = "PASS" ] ||
  fail "systest did not finish with PASS"

# Inherited-stdio relay smoke: a nested rush spawns its child with
# inherited stdio, so the outer rush's stdin and stdout relay tasks
# carry both directions; the no-delay tail must not be lost to the
# child-exit race.
out="$(printf 'relay-smoke\n' | vm_ssh "/bin/rush -c 'read X && echo GOT=\$X'")"
[ "$out" = "GOT=relay-smoke" ] || fail "stdin relay smoke: got '$out'"
out="$(vm_ssh "/bin/rush -c 'echo tail-smoke'")"
[ "$out" = "tail-smoke" ] || fail "relay tail smoke: got '$out'"

# A background job's `$!` is the kernel's own pid for that child, so it is
# meaningful outside rush: `ps` lists it and `kill` finds it (rush's jobs.rs,
# docs/plans/pid-refactoring-design.md). The sleep is long enough that only a
# kill that landed lets `wait` return.
out="$(vm_ssh "/bin/rush -c 'sleep 3600 & B=\$!; /bin/ps; /bin/kill \$B; echo KILL_RC=\$?; wait; echo REAPED=\$B'")"
bang="$(printf '%s\n' "$out" | sed -n 's/^REAPED=//p')"
[ -n "$bang" ] || fail "rush did not reap the background job: '$out'"
printf '%s\n' "$out" | grep -q '^KILL_RC=0$' ||
  fail "kill by \$! failed: '$out'"
printf '%s\n' "$out" | awk -v pid="$bang" '$1 == pid { found = 1 } END { exit !found }' ||
  fail "\$! ($bang) is not a pid in the process list: '$out'"

# rmux: a pane is a terminal to the program in it, without a pty (rmux/details.md
# §3.1). The shell rmux spawns runs the command, and it prints its interactive
# prompt -- which it does only when is_terminal() says it is on a terminal, and
# which the non-interactive outer shell of an `ssh host cmd` never prints.
# rmux renders rather than relays now, so the command's output arrives painted.
out="$(printf 'echo $((21+21))\nexit\n' | vm_ssh /bin/rmux 2>&1)"
case "$out" in
  *42*) ;;
  *) fail "rmux pane did not run the command: '$out'" ;;
esac
case "$out" in
  *rush*) ;;
  *) fail "rmux pane's shell did not see a terminal: '$out'" ;;
esac
# And it borrows the console rather than keeping it: in on the alternate
# screen, out again on exit, so a session leaves the scrollback as it found it.
case "$out" in
  *$'\033'"[?1049h"*) ;;
  *) fail "rmux did not take the alternate screen" ;;
esac
case "$out" in
  *$'\033'"[?1049l"*) ;;
  *) fail "rmux did not give the console back" ;;
esac

# sysbox ls colors directory names like rush's prompt and leaves files in the
# terminal's default color. A pane supplies the terminal that enables colors;
# the child names do not appear in the command, so they only match ls output.
vm_ssh /bin/mkdir /sys/tmp/sysbox-ls-color
vm_ssh /bin/mkdir /sys/tmp/sysbox-ls-color/amber-dir
vm_ssh /bin/cp /bin/ls /sys/tmp/sysbox-ls-color/default-file
check_ls_colors() {
  local option="$1"
  local output
  local prefix
  local style

  output="$(printf '/bin/ls %s /sys/tmp/sysbox-ls-color\nexit\n' "$option" |
    vm_ssh /bin/rmux 2>&1)"
  case "$output" in
    *"amber-dir"*"default-file"*) ;;
    *) fail "ls $option did not list the color-test entries: '$output'" ;;
  esac
  prefix="${output%%amber-dir*}"
  style="$(printf '%s' "$prefix" | grep -Eao $'\033''\[[0-9;]*m' | tail -1)"
  [ "$style" = $'\033'"[0;1;38;5;214m" ] ||
    fail "ls $option directory style was '$style'"
  prefix="${output%%default-file*}"
  style="$(printf '%s' "$prefix" | grep -Eao $'\033''\[[0-9;]*m' | tail -1)"
  [ "$style" = $'\033'"[0m" ] || fail "ls $option file style was '$style'"
}
check_ls_colors ""
check_ls_colors "-l"

# rmux: scrollback and copy mode on the real thing (M8, rmux/details.md §7.5,
# §7.6). The motions and the compacted history are unit-tested on the host in
# milliseconds; what only Motor can show is a pane *here* keeping what it has
# printed, and `C-a [` reading it back through this console path.
#
# Thirty lines overflow the 23-row pane a console with no answer to the size
# probe gives (§3.2), so the earliest of them are in the history and nowhere
# else. The sleeps are the ordering: input comes down a pipe all at once, and a
# key pressed before the shell has printed anything would open copy mode on an
# empty buffer.
#
# **What is asserted is the indicator, not the picture.** The frame diff sends
# only the cells that changed (§6.3), and copy mode's first view is often the
# text already on screen -- so the screen saying nothing is correct, and a check
# that grepped for a line would be reading the frame *after* copy mode ended.
# tmux's `[above/total]` is exact: a total above zero is a pane that kept
# history, and `above == total` is `g` having reached the oldest line of it.
rmux_copy_mode_keys() {
  printf 'for I in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do echo LINE$I; done\n'
  sleep 5
  # `C-a [` enters copy mode, `g` goes to the oldest line kept, `q` leaves.
  printf '\001[g'
  sleep 2
  printf 'q'
  sleep 1
  printf 'exit\n'
}
out="$(rmux_copy_mode_keys | vm_ssh /bin/rmux 2>&1)"
indicator="$(printf '%s' "$out" | grep -ao 'copy mode -- \[[0-9]*/[0-9]*\]' | tail -1)"
[ -n "$indicator" ] || fail "rmux copy mode did not open: '$out'"
counts="${indicator##*[}"
above="${counts%%/*}"
total="${counts%]}"
total="${total##*/}"
[ "$total" -gt 0 ] || fail "the pane kept no scrollback: '$indicator'"
[ "$above" = "$total" ] ||
  fail "copy mode did not reach the oldest line kept: '$indicator'"

# crossterm on Motor OS, on the two terminals this system has (russhd and an
# rmux pane). There is no pty and no termios here, so what a program gets is a
# stdio pipe with something ANSI on the far end; the port's job is to make that
# indistinguishable from a terminal to everything built on crossterm.

# The size probe writes escape bytes into the same stdout the answers are
# printed on, so a reading can share a line with one; pick the readings out
# rather than matching whole lines.
crossterm_readings() {
  printf '%s\n' "$1" | grep -Eao 'key=.*|end=.*|size=[0-9]+x[0-9]+|resize=[0-9]+x[0-9]+|size-after=[0-9]+x[0-9]+'
}

# Keys. All of these arrive in one write, so what is under test is the decoding
# rather than any timing: an Enter that reaches a program as CR LF is one key
# (two would be `Enter` and then `Ctrl+J`, since raw mode is on), and a whole
# escape sequence is the key it spells rather than `Esc` and two letters.
out="$(printf 'hi\r\n\033[A\003q' | vm_ssh /sys/tests/crossterm-smoke keys 2>/dev/null)"
[ "$(crossterm_readings "$out")" = "key=Char('h')
key=Char('i')
key=Enter
key=Up
key=Char('c')+KeyModifiers(CONTROL)
key=Char('q')
end=quit" ] || fail "crossterm decoded the keys as '$(crossterm_readings "$out")'"

# An `ESC` that stays alone is the Escape key. Nothing can tell it apart from
# the start of a sequence except a clock, so the port gives up on it after
# `ESCAPE_TIME`; a decoder without that timer would wait here for ever.
lone_escape() {
  printf '\033'
  sleep 1
  printf 'q'
  sleep 1
}
out="$(lone_escape | vm_ssh /sys/tests/crossterm-smoke keys 2>/dev/null)"
[ "$(crossterm_readings "$out")" = "key=Esc
key=Char('q')
end=quit" ] || fail "crossterm did not report a lone Esc: '$(crossterm_readings "$out")'"

# The alternate screen, in and out again, and the same on the way out of a
# panic: Motor OS builds abort on panic, so nothing but a panic hook can give
# the terminal back.
out="$(vm_ssh /sys/tests/crossterm-smoke screen 2>/dev/null)"
case "$out" in
  *$'\033'"[?1049h"*$'\033'"[?1049l"*"screen=restored"*) ;;
  *) fail "crossterm did not take and give back the alternate screen: '$out'" ;;
esac
if out="$(vm_ssh /sys/tests/crossterm-smoke panic 2>&1)"; then
  fail "crossterm-smoke panic exited successfully"
fi
case "$out" in
  *$'\033'"[?1049h"*$'\033'"[?1049l"*) ;;
  *) fail "crossterm's panic hook did not restore the screen: '$out'" ;;
esac

# Size. Over ssh nothing answers `ESC[6n` -- the far end of this pipe is a shell
# variable -- so the size is the fallback and stays there, and one unanswered
# probe is the end of the asking.
out="$(vm_ssh /sys/tests/crossterm-smoke size 2>/dev/null)"
case "$out" in
  *"size=80x24"*"size-after=80x24"*) ;;
  *) fail "crossterm size over ssh: '$out'" ;;
esac
case "$out" in
  *"resize="*) fail "crossterm reported a resize nothing answered: '$out'" ;;
esac

# Inside a pane there is something that answers, and the answer is the pane.
# `COLUMNS`/`LINES` already say 80x23 there, so what the `resize=` line proves is
# the `ESC[6n` round trip itself: a Resize is only ever emitted from a reply the
# size probe claimed. Its stdin has to be held open -- rmux relays a pane's input
# from the client, and a client that has hung up sends no reply either.
crossterm_size_in_pane() {
  printf '/sys/tests/crossterm-smoke size\n'
  sleep 5
  printf 'exit\n'
  sleep 1
}
out="$(crossterm_size_in_pane | vm_ssh /bin/rmux 2>/dev/null)"
readings="$(crossterm_readings "$out")"
case "$readings" in
  "size=80x23"*) ;;
  *) fail "crossterm did not read the pane size from the environment: '$readings'" ;;
esac
# The last one, not the only one: rush probes for its own prompt width, and an
# answer it did not collect before spawning the child lands in the child's stdin
# (rmux/details.md §3.2). A probe a second later corrects it, which is the point.
[ "$(printf '%s\n' "$readings" | grep '^resize=' | tail -1)" = "resize=80x23" ] ||
  fail "crossterm did not settle on the pane size: '$readings'"
[ "${readings##*$'\n'}" = "size-after=80x23" ] ||
  fail "crossterm did not keep the pane size: '$readings'"

# SFTP integration test against the running VM (before the trap shuts it down).
"$WD/test-sftp.sh"

# Lorry owns only its isolated native smoke deadline and reuses this VM.
if [ "$BUILD" = "release" ]; then
  "$ROOT_DIR/src/tests/lorry-integration-test.sh" --release --native-only --reuse-running-vm
else
  "$ROOT_DIR/src/tests/lorry-integration-test.sh" --native-only --reuse-running-vm
fi

vm_ssh sys/tests/mio-test

vm_ssh sys/tests/tokio-tests

echo "-------- MOTOR OS FULL TEST PASS ---------"
