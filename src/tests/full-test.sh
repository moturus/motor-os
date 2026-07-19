#!/bin/bash

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

# A fresh checkout leaves the key group-readable; ssh then silently ignores it.
chmod 600 "$WD/test.key"

SSH_OPTIONS=(
  -F /dev/null
  -p 2222
  -o IdentitiesOnly=yes
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

DNS_RESOLVER_SSH_PID=""

# cleanup routine
stop_vmm() {
  set +e
  vm_ssh shutdown
  if [ -n "$DNS_RESOLVER_SSH_PID" ]; then
    kill "$DNS_RESOLVER_SSH_PID" 2>/dev/null
    wait "$DNS_RESOLVER_SSH_PID"
  fi
}

# set the trap to call cleanup on exit
trap stop_vmm EXIT

echo "Starting Motor OS test."
echo "Console output is redirected to /tmp/full-test.log."
echo ""
echo ""


# FULL_TEST_QEMU_ARGS: optional extra qemu args (e.g. a monitor socket
# for hang forensics); run-qemu.sh passes "$@" through to qemu.
"$IMG_DIR/run-qemu.sh" ${FULL_TEST_QEMU_ARGS:-} &> /tmp/full-test.log &

# It takes some time to start sshd, especially with a debug build, so we
# have a large timeout and several retries. And the first "test" is just an empty echo.

ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=30 -o ConnectionAttempts=10 \
  motor@192.168.4.2 /bin/echo " "

vm_ssh /bin/ping -c 1 127.0.0.1
vm_ssh /bin/ping -c 1 localhost

echo "-- DNS resolver integration --"
vm_ssh /sys/dns-resolver --self-test
ping_external google.com
expect_ping_error does-not-exist.motor.invalid NotFound

udp_sockets="$(vm_ssh /bin/stats get 2 |
  awk '$2 == "net.udp_sockets" { print $3 }')"
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

udp_sockets="$(vm_ssh /bin/stats get 2 |
  awk '$2 == "net.udp_sockets" { print $3 }')"
[ "$udp_sockets" = "0" ] ||
  fail "restarted DNS service left $udp_sockets active UDP socket(s)"

vm_ssh sys/tests/systest

# SFTP integration test against the running VM (before the trap shuts it down).
"$WD/test-sftp.sh"

vm_ssh sys/tests/mio-test

vm_ssh sys/tests/tokio-tests
