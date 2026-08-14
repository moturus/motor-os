#!/bin/bash
#
# Direct hermetic gate for Gears. This script owns the profile-matched host
# suite and the Gears-specific Motor VM scenarios. The mock-provider and full
# agent-loop scenarios will be added here as they land.

if [ "${GEARS_TEST_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export GEARS_TEST_TIMEOUT_ACTIVE=1
  set -m
  timeout 600s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "gears-test: timed out after 600 seconds" >&2
  fi
  exit "$status"
fi

set -euo pipefail

WD="$(dirname "$0")"
ROOT_DIR="$WD/../.."
BUILD="debug"
profile_args=()

case "${1:-}" in
  "") ;;
  --release)
    BUILD="release"
    profile_args+=(--release)
    ;;
  *)
    echo "usage: $0 [--release]" >&2
    exit 2
    ;;
esac

required_image_executables=(
  img_files/generated/llvm/bin/cc
  img_files/generated/llvm/bin/c++
  img_files/generated/llvm/sys/tools/llvm/bin/llvm
  img_files/generated/rustc/sys/tools/rust/bin/rustc
  img_files/generated/rg/bin/rg
)
missing_prerequisite=0
for relative_path in "${required_image_executables[@]}"; do
  if [ ! -x "$ROOT_DIR/$relative_path" ]; then
    echo "gears-test: required executable is absent or not executable: $relative_path" >&2
    missing_prerequisite=1
  fi
done
if [ "$missing_prerequisite" -ne 0 ]; then
  echo "gears-test: generate the development-image toolchains with src/build-motor-os.sh" >&2
  exit 1
fi

echo "gears-test: running $BUILD host suite"
(
  cd "$ROOT_DIR/src/bin/gears"
  cargo test "${profile_args[@]}" --locked --offline
  cargo build "${profile_args[@]}" --locked --offline --example crossterm-frame
)

echo "gears-test: building $BUILD development image"
if [ "$BUILD" = "release" ]; then
  make -C "$ROOT_DIR" dev.img BUILD=release -j"$(nproc)"
else
  make -C "$ROOT_DIR" dev.img -j"$(nproc)"
fi

chmod 600 "$WD/test.key"
IMG_DIR="$ROOT_DIR/vm_images/$BUILD"
export MOTO_IMAGE=motor-os-dev.img
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

. "$WD/vm-cleanup.sh"

fail() {
  echo "gears-test: $*" >&2
  exit 1
}

SCRATCH="$(mktemp -d)"
CONSOLE_LOG="$SCRATCH/console.log"
VMM_PID=""
MOCK_SSH_PID=""
REMOTE_MOCK_PID=""
REMOTE_MOCK_LOG=""

stop_mock() {
  if [ -n "$REMOTE_MOCK_PID" ] && [ -n "$VMM_PID" ]; then
    timeout 5s "${SSH[@]}" /bin/kill "$REMOTE_MOCK_PID" > /dev/null 2>&1 || true
  fi
  if [ -n "$MOCK_SSH_PID" ] && kill -0 "$MOCK_SSH_PID" 2>/dev/null; then
    kill "$MOCK_SSH_PID" 2>/dev/null || true
    reap_within "$MOCK_SSH_PID" 5 || true
  fi
  MOCK_SSH_PID=""
  REMOTE_MOCK_PID=""
  REMOTE_MOCK_LOG=""
}

cleanup() {
  set +e
  stop_mock
  stop_vm "$VMM_PID"
  VMM_PID=""
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

start_mock() {
  local label="$1" scenario="$2" port="$3" remote_root="/user/gears-test"
  local remote_pid_file="$remote_root/$label-mock.pid"
  REMOTE_MOCK_LOG="$remote_root/$label-mock.log"
  "${SSH[@]}" "/bin/rush -c '/bin/gears-mock-provider \
    --addr 127.0.0.1:$port --scenario $scenario \
    --cert /sys/tests/gears/TEST_ONLY_PROVIDER_CERT.pem \
    --key /sys/tests/gears/TEST_ONLY_PROVIDER_KEY.pem \
    >$REMOTE_MOCK_LOG 2>&1 & echo \$! >$remote_pid_file; wait'" \
    > /dev/null 2>&1 &
  MOCK_SSH_PID="$!"

  local log="" pid=""
  for _ in {1..50}; do
    pid="$("${SSH[@]}" /bin/cat "$remote_pid_file" 2>/dev/null || true)"
    log="$("${SSH[@]}" /bin/cat "$REMOTE_MOCK_LOG" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]] && [[ "$log" == *"GEARS_MOCK_READY "* ]]; then
      REMOTE_MOCK_PID="$pid"
      return 0
    fi
    if ! kill -0 "$MOCK_SSH_PID" 2>/dev/null; then
      wait "$MOCK_SSH_PID" || true
      MOCK_SSH_PID=""
      fail "$label mock exited before becoming ready: $log"
    fi
    sleep 0.1
  done
  fail "$label mock did not become ready: $log"
}

finish_mock() {
  local label="$1" expected_requests="$2" port="$3" log="" status=0
  for _ in {1..50}; do
    kill -0 "$MOCK_SSH_PID" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$MOCK_SSH_PID" 2>/dev/null; then
    log="$("${SSH[@]}" /bin/cat "$REMOTE_MOCK_LOG" 2>/dev/null || true)"
    fail "$label mock did not stop after its scripted requests: $log"
  fi
  wait "$MOCK_SSH_PID" || status="$?"
  MOCK_SSH_PID=""
  REMOTE_MOCK_PID=""
  log="$("${SSH[@]}" /bin/cat "$REMOTE_MOCK_LOG")"
  REMOTE_MOCK_LOG=""
  [ "$status" -eq 0 ] || fail "$label mock exited $status: $log"
  [[ "$log" == *"GEARS_MOCK_DONE requests_complete"* ]] ||
    fail "$label mock did not complete: $log"

  local requests count=0 line
  requests="$(printf '%s\n' "$log" | grep '^GEARS_MOCK_REQUEST ' || true)"
  if [ -n "$requests" ]; then
    count="$(printf '%s\n' "$requests" | wc -l)"
  fi
  [ "$count" -eq "$expected_requests" ] ||
    fail "$label mock saw $count requests, expected $expected_requests: $log"
  while IFS= read -r line; do
    [[ "$line" == *" destination=127.0.0.1:$port "* ]] ||
      fail "$label request targeted something other than loopback: $line"
  done <<< "$requests"
}

write_provider_config() {
  local path="$1" port="$2"
  printf '%s\n' \
    'version = 1' \
    '[net]' \
    'egress_allowlist = ["127.0.0.1"]' \
    '[provider]' \
    "base_url = \"https://127.0.0.1:$port/v1\"" \
    'model = "test/model"' \
    'key_file = "/user/gears-test/TEST_ONLY_KEY"' \
    'ca_cert = "/sys/tests/gears/TEST_ONLY_CA.pem"' \
    '[permissions]' \
    'mode = "auto-approve"' |
    "${SSH[@]}" "/bin/rush -c 'cat >$path'"
}

echo "gears-test: starting $BUILD Motor VM"
"$IMG_DIR/run-qemu.sh" > "$CONSOLE_LOG" 2>&1 &
VMM_PID="$!"

until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /bin/echo " " > /dev/null; do
  if ! kill -0 "$VMM_PID" 2>/dev/null; then
    vmm_status=0
    wait "$VMM_PID" || vmm_status="$?"
    VMM_PID=""
    cat "$CONSOLE_LOG" >&2
    fail "QEMU exited before SSH became ready (status $vmm_status)"
  fi
  sleep 1
done

echo "gears-test: checking packaged prerequisites"
"${SSH[@]}" \
  '[ -x /bin/gears ] && [ -x /bin/rg ] && [ -x /bin/gears-mock-provider ] &&
   [ -x /sys/tests/gears-crossterm-frame ] &&
   [ -r /sys/tests/gears/TEST_ONLY_PROVIDER_CERT.pem ] &&
   [ -r /sys/tests/gears/TEST_ONLY_PROVIDER_KEY.pem ] &&
   [ -r /sys/tests/gears/TEST_ONLY_CA.pem ]' ||
  fail "development image is missing a Gears executable or test-only TLS fixture"
version="$("${SSH[@]}" /bin/gears --version)"
case "$version" in
  "gears "*) ;;
  *) fail "unexpected gears version output: '$version'" ;;
esac

echo "gears-test: checking russhd PTY carrier"
pty_version="$(ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
  /bin/gears --version 2>/dev/null)"
case "$pty_version" in
  "gears "*) ;;
  *) fail "Gears did not run through a russhd PTY: '$pty_version'" ;;
esac

frame="$(ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
  /sys/tests/gears-crossterm-frame 2>/dev/null)"
case "$frame" in
  *$'\033'"[?1049h"*"gears-crossterm-frame"*$'\033'"[?1049l"*"frame=restored"*) ;;
  *) fail "Gears' crossterm proof did not paint and restore one frame: '$frame'" ;;
esac

echo "gears-test: running hermetic Motor provider scenarios"
REMOTE_ROOT="/user/gears-test"
REMOTE_WORK="$REMOTE_ROOT/work"
"${SSH[@]}" "/bin/rush -c 'if [ -e $REMOTE_ROOT ]; then rm -r $REMOTE_ROOT; fi; \
  mkdir $REMOTE_ROOT; mkdir $REMOTE_WORK; \
  echo sk-test-only-motor >$REMOTE_ROOT/TEST_ONLY_KEY'"

FRAGMENTED_CONFIG="$REMOTE_ROOT/fragmented.toml"
write_provider_config "$FRAGMENTED_CONFIG" 19443
start_mock fragmented fragmented-sse 19443
fragmented_output="$("${SSH[@]}" "/bin/gears --config $FRAGMENTED_CONFIG \
  --workspace $REMOTE_WORK -p 'consume the fragmented response'" 2>&1)" ||
  fail "Gears fragmented scenario failed: $fragmented_output"
finish_mock fragmented 1 19443
[[ "$fragmented_output" == *"fragmented"* ]] ||
  fail "Gears did not print the fragmented completion: $fragmented_output"

TOOL_CONFIG="$REMOTE_ROOT/tool-round.toml"
write_provider_config "$TOOL_CONFIG" 19444
start_mock tool-round tool-round 19444
tool_output="$("${SSH[@]}" "/bin/gears --config $TOOL_CONFIG \
  --workspace $REMOTE_WORK -p 'run the scripted tool round'" 2>&1)" ||
  fail "Gears tool-round scenario failed: $tool_output"
finish_mock tool-round 2 19444
result="$("${SSH[@]}" /bin/cat "$REMOTE_WORK/result.txt")" ||
  fail "Gears tool round did not create result.txt"
[ "$result" = "made by gears" ] ||
  fail "unexpected result.txt contents: '$result'"
[[ "$tool_output" == *"tool complete"* ]] ||
  fail "Gears did not complete after its tool call: $tool_output"

stop_vm "$VMM_PID"
VMM_PID=""
echo "-------- GEARS TEST PASS ($BUILD) --------"
