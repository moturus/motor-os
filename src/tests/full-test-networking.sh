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
. "$WD/vm-console-filter.sh"

# Build everything before running the tests.
if [ "$BUILD" = "release" ]; then
  make -C "$ROOT_DIR" main.img systest mio-test tokio-tests \
    BUILD=release -j"$(nproc)"
else
  make -C "$ROOT_DIR" main.img systest mio-test tokio-tests -j"$(nproc)"
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
NETSTACK_FEATURES="async,medium-ethernet,medium-ip,proto-ipv4,proto-ipv6,socket-icmp,socket-tcp,socket-tcp-cubic,socket-udp"
if [ "$BUILD" = "release" ]; then
  cargo +nightly test --release \
    --manifest-path "$ROOT_DIR/src/sys/sys-io/netstack/Cargo.toml" \
    --no-default-features --features "$NETSTACK_FEATURES"
else
  cargo +nightly test \
    --manifest-path "$ROOT_DIR/src/sys/sys-io/netstack/Cargo.toml" \
    --no-default-features --features "$NETSTACK_FEATURES"
fi

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

# stop_vm(): bounded teardown, shared with the other VM harnesses.
. "$WD/vm-cleanup.sh"

# Some environments (e.g. a dev host behind qemu user-mode networking) cannot
# send external ICMP echo at all; probe once so external pings can tolerate it.
EXTERNAL_ICMP=1
ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || EXTERNAL_ICMP=0

# Ping an external host: name resolution must always succeed; a missing echo
# reply is tolerated iff the test host itself has no external ICMP.
ping_external() {
  local host="$1"
  local output

  if output="$(vm_ssh /system/bin/ping -c 1 "$host" 2>&1)"; then
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

  if output="$(vm_ssh /system/bin/ping -c 1 "$host" 2>&1)"; then
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
    if output="$(vm_ssh /system/bin/ping -c 1 "$host" 2>&1)"; then
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
    if output="$(vm_ssh /system/bin/stats get 2 2>&1)"; then
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
  stop_vm "$VMM_PID"
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
# Do not forward the guest's terminal queries: a terminal response would be
# left on the shell's input after this run.
"$IMG_DIR/run-qemu.sh" ${FULL_TEST_QEMU_ARGS:-} \
  > >(filter_vm_console | tee /tmp/full-test.log) 2>&1 &
VMM_PID="$!"

# A refused connection returns immediately, so OpenSSH's ConnectionAttempts
# does not reliably cover a slow debug boot. Retry explicitly; the overall
# 600-second harness timeout bounds this loop.
until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /system/bin/echo " "; do
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

vm_ssh "[ ! -e /devtools ]" || fail "standard image unexpectedly packages /devtools"
printf '%s\n' \
  'mkdir /devtools' \
  'mkdir /devtools/tests' \
  'mkdir /devtools/tmp' \
  "put $ROOT_DIR/build/bin/$BUILD/systest /devtools/tests/systest" \
  "put $ROOT_DIR/build/bin/$BUILD/mio-test /devtools/tests/mio-test" \
  "put $ROOT_DIR/build/bin/$BUILD/tokio-tests /devtools/tests/tokio-tests" |
  sftp -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
    -i "$WD/test.key" motor@192.168.4.2

ping -c 1 -W 2 192.168.4.2
ping -c 1 -W 2 2001:db8::2
vm_ssh /system/bin/ping -c 1 192.168.4.1
vm_ssh /system/bin/ping -c 1 2001:db8::1
vm_ssh /system/bin/ping -c 1 127.0.0.1
vm_ssh /system/bin/ping -c 1 localhost

echo "-- DNS resolver integration --"
vm_ssh /system/services/dns-resolver --self-test
ping_external google.com
expect_ping_error does-not-exist.motor.invalid NotFound

udp_sockets="$(read_udp_socket_count)"
[ "$udp_sockets" = "0" ] ||
  fail "DNS tests left $udp_sockets active UDP socket(s)"

# Verify that numeric lookup is independent of the service, lookup failure is
# defined, and a later per-call client reconnects after the service restarts.
resolver_pid="$(vm_ssh /system/bin/ps |
  awk '$NF == "/system/services/dns-resolver" { gsub(/[+*?]/, "", $1); print $1; exit }')"
[ -n "$resolver_pid" ] || fail "could not find the dns-resolver process"
vm_ssh /system/bin/kill "$resolver_pid"
vm_ssh /system/bin/ping -c 1 127.0.0.1
wait_for_ping_error google.com NotConnected

"${SSH[@]}" MOTOR_OS_CAPS=0x8 /system/services/dns-resolver \
  >> /tmp/full-test-dns-resolver.log 2>&1 &
DNS_RESOLVER_SSH_PID="$!"

resolver_restarted=0
for _ in $(seq 1 20); do
  if vm_ssh /system/services/dns-resolver --self-test; then
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
vm_ssh "TMPDIR=/devtools/tmp /devtools/tests/systest" 2>&1 |
  tee "$SYSTEST_LOG" || systest_status="$?"
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
out="$(printf 'relay-smoke\n' | vm_ssh "/system/bin/rush -c 'read X && echo GOT=\$X'")"
[ "$out" = "GOT=relay-smoke" ] || fail "stdin relay smoke: got '$out'"
out="$(vm_ssh "/system/bin/rush -c 'echo tail-smoke'")"
[ "$out" = "tail-smoke" ] || fail "relay tail smoke: got '$out'"

# SFTP integration test against the running VM (before the trap shuts it down).
"$WD/test-sftp.sh"

vm_ssh "TMPDIR=/devtools/tmp /devtools/tests/mio-test"

vm_ssh "TMPDIR=/devtools/tmp /devtools/tests/tokio-tests"

echo "-------- MOTOR OS FULL TEST PASS ---------"
