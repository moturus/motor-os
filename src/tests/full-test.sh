#!/bin/bash

if [ "${FULL_TEST_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export FULL_TEST_TIMEOUT_ACTIVE=1
  # Let bash put timeout's process group in the foreground. Without job control,
  # timeout moves the suite into a background process group; a terminal
  # operation can then stop timeout and the entire suite with SIGTTIN/SIGTTOU.
  # Keeping timeout's separate group preserves its whole-process-tree timeout.
  set -m
  timeout 600s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "full-test: timed out after 600 seconds" >&2
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

# Build everything before running the tests.
if [ "$BUILD" = "release" ]; then
  make -C "$ROOT_DIR" all BUILD=release -j"$(nproc)"
else
  make -C "$ROOT_DIR" all -j"$(nproc)"
fi

# The benchmark's deadline tests use deliberately stalled host TCP peers.
if [ "$BUILD" = "release" ]; then
  cargo test --manifest-path "$ROOT_DIR/src/bin/rnetbench/Cargo.toml" --release
else
  cargo test --manifest-path "$ROOT_DIR/src/bin/rnetbench/Cargo.toml"
fi

# The host-side tests of rmux and rush: the parts that need no Motor OS at all
# run on Linux in seconds, so they run before the VM is even booted. rush's are
# here because its line editor is testable only over a terminal, and a pty is
# the one this host has -- including the width probe's round trip, which is what
# a Motor console has instead of an ioctl (rush's `term::probe_width`).
for crate in rmux rush; do
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
      # NotConnected covers an AAAA-first DNS answer on a rig with no
      # IPv6 route (qemu user-mode networking): resolution -- the part
      # under test -- succeeded, only the echo cannot be delivered.
      *"Request timeout"* | *"NotConnected"*)
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

# SFTP integration test against the running VM (before the trap shuts it down).
"$WD/test-sftp.sh"

vm_ssh sys/tests/mio-test

vm_ssh sys/tests/tokio-tests

echo "-------- MOTOR OS FULL TEST PASS ---------"
