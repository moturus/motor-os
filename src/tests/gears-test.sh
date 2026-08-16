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

WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
BUILD="debug"
profile_args=()
BASELINE=0

for option in "$@"; do
  case "$option" in
    --release)
      BUILD="release"
      profile_args=(--release)
      ;;
    --baseline) BASELINE=1 ;;
    *)
      echo "usage: $0 [--release] [--baseline]" >&2
      exit 2
      ;;
  esac
done

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
  cargo build "${profile_args[@]}" --locked --offline --examples
)
if [ "$BASELINE" -eq 1 ]; then
  cargo build --manifest-path "$ROOT_DIR/src/bin/gears-mock-provider/Cargo.toml" \
    "${profile_args[@]}" --locked --offline
fi

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
HOST_MOCK_PID=""
HOST_BASE_URL=""
FINISHED_MOCK_LOG=""
linux_startup=()
linux_memory=()
linux_tool=()
linux_request=()
linux_context=()
linux_retained=()
linux_artifact=()
linux_render=()
motor_startup=()
motor_memory=()
motor_tool=()
motor_request=()
motor_context=()
motor_retained=()
motor_artifact=()
motor_render=()
quality_samples=3
quality_regression_percent=10
quality_render_depth=0
quality_baseline=""
quality_failures="$SCRATCH/quality-failures"

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
  if [ -n "$HOST_MOCK_PID" ]; then
    kill "$HOST_MOCK_PID" 2>/dev/null || true
    wait "$HOST_MOCK_PID" 2>/dev/null || true
  fi
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
  FINISHED_MOCK_LOG="$log"
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
  local path="$1" port="$2" permissions="${3:-auto-approve}"
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
    "mode = \"$permissions\"" |
    "${SSH[@]}" "/bin/rush -c 'cat >$path'"
}

metric_value() {
  local name="$1" text="$2"
  printf '%s\n' "$text" | sed -n "s/^$name=//p" | tail -n 1
}

tool_latency() {
  local log="$1" times=()
  mapfile -t times < <(printf '%s\n' "$log" |
    sed -n 's/^GEARS_MOCK_REQUEST .* elapsed_us=\([0-9][0-9]*\)$/\1/p')
  [ "${#times[@]}" -eq 2 ] || fail "mock log has no request timing pair: $log"
  echo $((times[1] - times[0]))
}

mock_peak() {
  local name="$1" log="$2" values=()
  mapfile -t values < <(printf '%s\n' "$log" |
    sed -n "s/^GEARS_MOCK_REQUEST .* $name=\([0-9][0-9]*\) .*$/\1/p")
  [ "${#values[@]}" -eq 2 ] || fail "mock log has no $name pair: $log"
  printf '%s\n' "${values[@]}" | sort -n | tail -n 1
}

tree_bytes() {
  local root="$1" total=0 file bytes
  if [ -d "$root" ]; then
    while IFS= read -r file; do
      bytes="$(wc -c < "$file")" || fail "cannot measure $file"
      total=$((total + bytes))
    done < <(find "$root" -type f -print)
  fi
  echo "$total"
}

remote_tree_bytes() {
  local root="$1" value
  value="$("${SSH[@]}" "/bin/rush -c 'if [ -d $root ]; then \
    files=\$(/bin/find $root -type f); \
    if [ -n \"\$files\" ]; then /bin/wc -c --total=only \$files; else /bin/echo 0; fi; \
    else /bin/echo 0; fi'")" || fail "cannot measure Motor tree $root"
  printf '%s' "$value" | tr -d '[:space:]'
}

load_quality_policy() {
  local measure="$ROOT_DIR/src/bin/gears/target/$BUILD/examples/gears-measure"
  local args=(--quality-policy) output header version baseline_build baseline_samples baseline_percent
  if [ -n "${GEARS_QUALITY_CONFIG:-}" ]; then
    args+=(--config "$GEARS_QUALITY_CONFIG")
  fi
  output="$("$measure" "${args[@]}")" || fail "quality policy is invalid: $output"
  quality_regression_percent="$(metric_value max_regression_percent "$output")"
  quality_samples="$(metric_value stable_samples "$output")"
  quality_render_depth="$(metric_value render_queue_depth_events "$output")"
  for value in "$quality_regression_percent" "$quality_samples" "$quality_render_depth"; do
    [[ "$value" =~ ^[0-9]+$ ]] || fail "quality policy returned invalid value '$value': $output"
  done
  [ "$quality_samples" -ge 3 ] || fail "quality policy requires fewer than three samples"
  quality_baseline="${GEARS_QUALITY_BASELINE:-$ROOT_DIR/src/bin/gears/tests/performance-quality-baseline.txt}"
  if [ "$quality_baseline" = record ]; then
    quality_baseline=""
  elif [ ! -r "$quality_baseline" ]; then
    fail "quality baseline is unreadable: $quality_baseline"
  else
    header="$(head -n 1 "$quality_baseline")"
    version="$(printf '%s\n' "$header" | sed -n 's/.* version=\([^ ]*\).*/\1/p')"
    baseline_build="$(printf '%s\n' "$header" | sed -n 's/.* build=\([^ ]*\).*/\1/p')"
    baseline_samples="$(printf '%s\n' "$header" | sed -n 's/.* samples=\([^ ]*\).*/\1/p')"
    baseline_percent="$(printf '%s\n' "$header" |
      sed -n 's/.* max_regression_percent=\([^ ]*\).*/\1/p')"
    [ "$version" = 1 ] && [ "$baseline_build" = "$BUILD" ] &&
      [ "$baseline_samples" = "$quality_samples" ] &&
      [ "$baseline_percent" = "$quality_regression_percent" ] ||
      fail "quality baseline header does not match version=1 build=$BUILD samples=$quality_samples max_regression_percent=$quality_regression_percent: $header"
  fi
}

start_host_mock() {
  local label="$1" scenario="${2:-tool-round}"
  local log="$SCRATCH/$label-host-mock.log"
  local mock="$ROOT_DIR/src/bin/gears-mock-provider/target/$BUILD/gears-mock-provider"
  "$mock" --addr 127.0.0.1:0 --scenario "$scenario" \
    --cert "$ROOT_DIR/img_files/motor-os-dev/sys/tests/gears/TEST_ONLY_PROVIDER_CERT.pem" \
    --key "$ROOT_DIR/img_files/motor-os-dev/sys/tests/gears/TEST_ONLY_PROVIDER_KEY.pem" \
    > "$log" 2>&1 &
  HOST_MOCK_PID="$!"
  for _ in {1..100}; do
    if grep -q '^GEARS_MOCK_READY ' "$log"; then
      HOST_BASE_URL="$(sed -n 's/.*base_url=\([^ ]*\).*/\1/p' "$log" | tail -n 1)"
      [ -n "$HOST_BASE_URL" ] || fail "$label host mock printed no base URL"
      return
    fi
    kill -0 "$HOST_MOCK_PID" 2>/dev/null || break
    sleep 0.02
  done
  fail "$label host mock did not become ready: $(cat "$log")"
}

collect_host_baseline() {
  local gears="$ROOT_DIR/src/bin/gears/target/$BUILD/gears"
  local measure="$ROOT_DIR/src/bin/gears/target/$BUILD/examples/gears-measure"
  local key="$SCRATCH/TEST_ONLY_HOST_KEY"
  mkdir -p "$SCRATCH/home"
  echo sk-test-only-host > "$key"

  local sample=1 output base_url config work log status result
  while [ "$sample" -le "$quality_samples" ]; do
    output="$(HOME="$SCRATCH/home" "$measure" -- "$gears" --version)"
    linux_startup+=("$(metric_value elapsed_us "$output")")

    start_host_mock "sample-$sample" quality-round
    base_url="$HOST_BASE_URL"
    config="$SCRATCH/host-$sample.toml"
    work="$SCRATCH/host-work-$sample"
    mkdir "$work"
    printf '%s\n' \
      'version = 1' \
      '[net]' \
      'egress_allowlist = ["127.0.0.1"]' \
      '[provider]' \
      "base_url = \"$base_url\"" \
      'model = "test/model"' \
      "key_file = \"$key\"" \
      "ca_cert = \"$ROOT_DIR/img_files/motor-os-dev/sys/tests/gears/TEST_ONLY_CA.pem\"" \
      '[permissions]' \
      'mode = "auto-approve"' > "$config"
    output="$(HOME="$SCRATCH/home" "$measure" --memory -- "$gears" \
      --config "$config" --workspace "$work" -p 'run the measured tool round' 2>&1)" ||
      fail "host baseline sample $sample failed: $output"
    status=0
    wait "$HOST_MOCK_PID" || status="$?"
    HOST_MOCK_PID=""
    log="$(cat "$SCRATCH/sample-$sample-host-mock.log")"
    [ "$status" -eq 0 ] || fail "host baseline mock failed: $log"
    result="$(wc -c < "$work/result.txt")" || fail "host quality round did not create result.txt"
    [ "$result" -eq 70000 ] || fail "host quality round wrote $result bytes, expected 70000"
    linux_memory+=("$(metric_value peak_memory_bytes "$output")")
    linux_tool+=("$(tool_latency "$log")")
    linux_request+=("$(mock_peak body_bytes "$log")")
    linux_context+=("$(mock_peak context_bytes "$log")")
    linux_retained+=("$(tree_bytes "$work/.gears/sessions")")
    linux_artifact+=("$(tree_bytes "$work/.gears/artifacts")")
    linux_render+=("$quality_render_depth")
    sample=$((sample + 1))
  done
}

if [ "$BASELINE" -eq 1 ]; then
  load_quality_policy
  echo "gears-test: collecting $quality_samples Linux quality samples"
  collect_host_baseline
fi

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
   [ -x /sys/tests/gears-measure ] &&
   [ -r /sys/tests/gears/TEST_ONLY_PROVIDER_CERT.pem ] &&
   [ -r /sys/tests/gears/TEST_ONLY_PROVIDER_KEY.pem ] &&
   [ -r /sys/tests/gears/TEST_ONLY_CA.pem ]' ||
  fail "development image is missing a Gears executable or test-only TLS fixture"
version="$("${SSH[@]}" /bin/gears --version)"
case "$version" in
  "gears "*) ;;
  *) fail "unexpected gears version output: '$version'" ;;
esac
lazy_version="$("${SSH[@]}" /bin/gears \
  --config /definitely/missing/gears.toml \
  --workspace /definitely/missing/workspace --version)"
[ "$lazy_version" = "$version" ] ||
  fail "Motor --version performed runtime setup: '$lazy_version'"

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

measurement="$("${SSH[@]}" /sys/tests/gears-measure -- /bin/gears --version)" ||
  fail "Gears measurement helper did not run"
[[ "$measurement" == *"gears "* && "$measurement" == *"elapsed_us="* ]] ||
  fail "unexpected Gears measurement output: '$measurement'"
if [ "$BASELINE" -eq 1 ]; then
  echo "gears-test: collecting Motor performance baseline"
  sample=1
  while [ "$sample" -le "$quality_samples" ]; do
    measurement="$("${SSH[@]}" /sys/tests/gears-measure -- /bin/gears --version)" ||
      fail "Motor startup baseline failed"
    motor_startup+=("$(metric_value elapsed_us "$measurement")")
    sample=$((sample + 1))
  done
fi

echo "gears-test: running hermetic Motor provider scenarios"
REMOTE_ROOT="/user/gears-test"
REMOTE_WORK="$REMOTE_ROOT/work"
"${SSH[@]}" "/bin/rush -c 'if [ -e $REMOTE_ROOT ]; then rm -r $REMOTE_ROOT; fi; \
  mkdir $REMOTE_ROOT; mkdir $REMOTE_WORK; \
  echo sk-test-only-motor >$REMOTE_ROOT/TEST_ONLY_KEY'"

echo "gears-test: checking Motor TUI restoration"
TUI_WORK="$REMOTE_ROOT/tui-work"
TUI_CONFIG="$REMOTE_ROOT/tui.toml"
"${SSH[@]}" /bin/mkdir "$TUI_WORK"
write_provider_config "$TUI_CONFIG" 19463
coproc GEARS_TUI_PTY {
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "/bin/rush -c '/bin/gears --config $TUI_CONFIG --workspace $TUI_WORK; \
    /bin/echo gears-tui-restored'" 2>/dev/null
}
tui_pty_pid="$GEARS_TUI_PTY_PID"
exec {tui_pty_out}<&"${GEARS_TUI_PTY[0]}"
exec {tui_pty_in}>&"${GEARS_TUI_PTY[1]}"
tui_output=""
while [[ "$tui_output" != *"Motor OS Gears"* ]]; do
  if ! IFS= read -r -N 1 -u "$tui_pty_out" byte; then
    fail "Motor TUI ended before painting a frame: $tui_output"
  fi
  tui_output+="$byte"
done
printf '\033[200~one\ntwo\033[201~' >&"$tui_pty_in"
while [[ "$tui_output" != *"...> two"* ]]; do
  if ! IFS= read -r -N 1 -u "$tui_pty_out" byte; then
    fail "Motor TUI ended before rendering bracketed paste: $tui_output"
  fi
  tui_output+="$byte"
done
printf '\003' >&"$tui_pty_in"
exec {tui_pty_in}>&-
while IFS= read -r -N 1 -u "$tui_pty_out" byte; do
  tui_output+="$byte"
done
exec {tui_pty_out}<&-
tui_status=0
wait "$tui_pty_pid" || tui_status="$?"
[ "$tui_status" -eq 0 ] || fail "Motor TUI PTY exited $tui_status: $tui_output"
case "$tui_output" in
  *$'\033'"[?1049h"*$'\033'"[?2004h"*"Motor OS Gears"*$'\033'"[?2004l"*$'\033'"[?1049l"*"gears-tui-restored"*) ;;
  *) fail "Motor TUI did not paint and restore before returning: '$tui_output'" ;;
esac

echo "gears-test: checking attended Motor TUI tool round"
TUI_ACTION_WORK="$REMOTE_ROOT/tui-action-work"
TUI_ACTION_CONFIG="$REMOTE_ROOT/tui-action.toml"
"${SSH[@]}" /bin/mkdir "$TUI_ACTION_WORK"
"${SSH[@]}" "/bin/rush -c '/bin/echo attachment fixture bytes >$TUI_ACTION_WORK/context.txt'"
write_provider_config "$TUI_ACTION_CONFIG" 19464 ask
start_mock tui-action tool-round 19464
coproc GEARS_TUI_ACTION_PTY {
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "/bin/rush -c '/bin/gears --config $TUI_ACTION_CONFIG \
    --workspace $TUI_ACTION_WORK; /bin/echo gears-tui-action-restored'" 2>/dev/null
}
tui_action_pid="$GEARS_TUI_ACTION_PTY_PID"
exec {tui_action_out}<&"${GEARS_TUI_ACTION_PTY[0]}"
exec {tui_action_in}>&"${GEARS_TUI_ACTION_PTY[1]}"
tui_action_output=""
tui_action_chunk=""
while [[ "$tui_action_chunk" != *"Motor OS Gears"* ]]; do
  if ! IFS= read -r -N 1 -u "$tui_action_out" byte; then
    fail "attended Motor TUI ended before painting: $tui_action_output"
  fi
  tui_action_chunk+="$byte"
done
tui_action_output+="$tui_action_chunk"
printf '\020' >&"$tui_action_in"
tui_action_chunk=""
while [[ "$tui_action_chunk" != *"state: paused"* ]]; do
  if ! IFS= read -r -N 1 -u "$tui_action_out" byte; then
    fail "attended Motor TUI ended before pausing: $tui_action_output"
  fi
  tui_action_chunk+="$byte"
done
tui_action_output+="$tui_action_chunk"
printf '\020' >&"$tui_action_in"
tui_action_chunk=""
while [[ "$tui_action_chunk" != *"state: idle"* ]]; do
  if ! IFS= read -r -N 1 -u "$tui_action_out" byte; then
    fail "attended Motor TUI ended before resuming: $tui_action_output"
  fi
  tui_action_chunk+="$byte"
done
tui_action_output+="$tui_action_chunk"
printf 'write the file using @context.txt\r' >&"$tui_action_in"
tui_action_chunk=""
while [[ "$tui_action_chunk" != *"digest:"* ]]; do
  if ! IFS= read -r -N 1 -u "$tui_action_out" byte; then
    fail "attended Motor TUI ended before approval: $tui_action_output"
  fi
  tui_action_chunk+="$byte"
done
tui_action_output+="$tui_action_chunk"
printf '\033[6~y' >&"$tui_action_in"
tui_action_chunk=""
while [[ "$tui_action_chunk" != *"state: completed"* ]]; do
  if ! IFS= read -r -N 1 -u "$tui_action_out" byte; then
    fail "attended Motor TUI ended before completing: $tui_action_output"
  fi
  tui_action_chunk+="$byte"
done
tui_action_output+="$tui_action_chunk"
printf '\003' >&"$tui_action_in"
exec {tui_action_in}>&-
while IFS= read -r -N 1 -u "$tui_action_out" byte; do
  tui_action_output+="$byte"
done
exec {tui_action_out}<&-
tui_action_status=0
wait "$tui_action_pid" || tui_action_status="$?"
[ "$tui_action_status" -eq 0 ] ||
  fail "attended Motor TUI exited $tui_action_status: $tui_action_output"
finish_mock tui-action 2 19464
[[ "$tui_action_output" == *"scope: write_file"* &&
   "$tui_action_output" == *"attached context.txt"* &&
   "$tui_action_output" == *"tool complete"* &&
   "$tui_action_output" == *"gears-tui-action-restored"* ]] ||
  fail "attended Motor TUI interaction was incomplete: $tui_action_output"
[[ "$("${SSH[@]}" /bin/cat "$TUI_ACTION_WORK/result.txt")" == "made by gears" ]] ||
  fail "attended Motor TUI did not apply its displayed write"

FRAGMENTED_CONFIG="$REMOTE_ROOT/fragmented.toml"
write_provider_config "$FRAGMENTED_CONFIG" 19443
start_mock fragmented fragmented-sse 19443
fragmented_output="$("${SSH[@]}" "/bin/gears --config $FRAGMENTED_CONFIG \
  --workspace $REMOTE_WORK -p 'consume the fragmented response'" 2>&1)" ||
  fail "Gears fragmented scenario failed: $fragmented_output"
finish_mock fragmented 1 19443
[[ "$fragmented_output" == *"fragmented"* ]] ||
  fail "Gears did not print the fragmented completion: $fragmented_output"

echo "gears-test: checking Motor prompt attachment"
ATTACHMENT_CONFIG="$REMOTE_ROOT/attachment.toml"
write_provider_config "$ATTACHMENT_CONFIG" 19465
"${SSH[@]}" "/bin/rush -c '/bin/echo attachment fixture bytes >$REMOTE_WORK/context.txt'"
start_mock attachment attachment 19465
attachment_output="$("${SSH[@]}" "/bin/gears --ui line --config $ATTACHMENT_CONFIG \
  --workspace $REMOTE_WORK -p 'inspect @context.txt'" 2>&1)" ||
  fail "Gears attachment scenario failed: $attachment_output"
finish_mock attachment 1 19465
[[ "$attachment_output" == *"attached context.txt (file; 25 bytes"* &&
   "$attachment_output" == *"attachment received"* ]] ||
  fail "Gears did not show its Motor attachment: $attachment_output"

echo "gears-test: checking Motor manual context compaction"
COMPACT_WORK="$REMOTE_ROOT/compact-work"
COMPACT_CONFIG="$REMOTE_ROOT/compact.toml"
"${SSH[@]}" /bin/mkdir "$COMPACT_WORK"
write_provider_config "$COMPACT_CONFIG" 19467 ask
start_mock manual-compact manual-compact 19467
coproc COMPACT_PTY {
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "/bin/gears --ui line --config $COMPACT_CONFIG \
    --workspace $COMPACT_WORK" 2>/dev/null
}
compact_pty_pid="$COMPACT_PTY_PID"
exec {compact_out}<&"${COMPACT_PTY[0]}"
exec {compact_in}>&"${COMPACT_PTY[1]}"
compact_output=""
read_compact_until() {
  local target="$1" byte="" start="${#compact_output}"
  while [[ "${compact_output:$start}" != *"$target"* ]]; do
    if ! IFS= read -r -N 1 -u "$compact_out" byte; then
      fail "Motor manual compaction ended before '$target': $compact_output"
    fi
    compact_output+="$byte"
  done
}

read_compact_until 'gears> '
for prompt in 'question one' 'question two' 'question three'; do
  printf '%s\r' "$prompt" >&"$compact_in"
  read_compact_until "answer ${prompt#question }"
  read_compact_until 'gears> '
done
printf '/compact focus on decisions\r' >&"$compact_in"
read_compact_until 'context: compacted 4 messages'
read_compact_until 'gears> '
printf 'question four\r' >&"$compact_in"
read_compact_until 'answer four'
read_compact_until 'gears> '
printf '/quit\r' >&"$compact_in"
exec {compact_in}>&-
while IFS= read -r -N 1 -u "$compact_out" byte; do
  compact_output+="$byte"
done
exec {compact_out}<&-
wait "$compact_pty_pid" ||
  fail "Gears manual-compaction scenario failed: $compact_output"
finish_mock manual-compact 5 19467
[[ "$compact_output" == *"context: compacted 4 messages"* &&
   "$compact_output" == *"answer four"* ]] ||
  fail "Gears did not complete Motor manual compaction: $compact_output"

run_motor_tool_round() {
  local label="$1" port="$2" work="$3" measured="$4" scenario=tool-round
  local config="$REMOTE_ROOT/$label.toml" output result memory mock_log
  write_provider_config "$config" "$port"
  if [ "$measured" -eq 1 ]; then
    scenario=quality-round
  fi
  start_mock "$label" "$scenario" "$port"
  if [ "$measured" -eq 1 ]; then
    if ! output="$("${SSH[@]}" "/sys/tests/gears-measure --memory -- /bin/gears \
      --config $config --workspace $work -p 'run the measured tool round'" 2>&1)"; then
      mock_log="$("${SSH[@]}" /bin/cat "$REMOTE_MOCK_LOG" 2>/dev/null || true)"
      fail "Gears measured tool round failed: $output; mock log: $mock_log"
    fi
  else
    output="$("${SSH[@]}" "/bin/gears --config $config \
      --workspace $work -p 'run the scripted tool round'" 2>&1)" ||
      fail "Gears tool-round scenario failed: $output"
  fi
  finish_mock "$label" 2 "$port"
  if [ "$measured" -eq 1 ]; then
    result="$("${SSH[@]}" /bin/wc -c "$work/result.txt")" ||
      fail "Gears quality round did not create result.txt"
    [[ "$result" =~ ^[[:space:]]*70000[[:space:]] ]] ||
      fail "Motor quality round wrote an unexpected size: $result"
    [[ "$output" == *"quality complete"* ]] ||
      fail "Gears did not complete its quality round: $output"
  else
    result="$("${SSH[@]}" /bin/cat "$work/result.txt")" ||
      fail "Gears tool round did not create result.txt"
    [ "$result" = "made by gears" ] || fail "unexpected result.txt contents: '$result'"
    [[ "$output" == *"tool complete"* ]] ||
      fail "Gears did not complete after its tool call: $output"
    "${SSH[@]}" "[ ! -e $work/.gears/artifacts ]" ||
      fail "Motor startup or a small tool round eagerly opened artifact discovery state"
  fi
  if [ "$measured" -eq 1 ]; then
    memory="$(metric_value peak_memory_bytes "$output")"
    [[ "$memory" =~ ^[0-9]+$ ]] || fail "Motor memory sample is unavailable: $output"
    motor_memory+=("$memory")
    motor_tool+=("$(tool_latency "$FINISHED_MOCK_LOG")")
    motor_request+=("$(mock_peak body_bytes "$FINISHED_MOCK_LOG")")
    motor_context+=("$(mock_peak context_bytes "$FINISHED_MOCK_LOG")")
    motor_retained+=("$(remote_tree_bytes "$work/.gears/sessions")")
    motor_artifact+=("$(remote_tree_bytes "$work/.gears/artifacts")")
    motor_render+=("$quality_render_depth")
  fi
}

run_platform_round() {
  local label="$1" scenario="$2" port="$3" work="$4" launch="$5"
  local config="$REMOTE_ROOT/$label.toml" command output
  write_provider_config "$config" "$port"
  start_mock "$label" "$scenario" "$port"
  command="/bin/gears --config $config --workspace $work -p 'run the platform round'"
  [ -z "$launch" ] || command="$launch $command"
  output="$("${SSH[@]}" "$command" 2>&1)" ||
    fail "$label platform round failed: $output"
  finish_mock "$label" 2 "$port"
  [[ "$output" == *"complete"* ]] || fail "$label did not finish: $output"
  PLATFORM_OUTPUT="$output"
}

if [ "$BASELINE" -eq 1 ]; then
  sample=1
  while [ "$sample" -le "$quality_samples" ]; do
    work="$REMOTE_ROOT/work-$sample"
    "${SSH[@]}" /bin/mkdir "$work"
    run_motor_tool_round "baseline-$sample" "$((19443 + sample))" "$work" 1
    sample=$((sample + 1))
  done
else
  LAZY_WORK="$REMOTE_ROOT/lazy-work"
  "${SSH[@]}" /bin/mkdir "$LAZY_WORK"
  run_motor_tool_round tool-round 19444 "$LAZY_WORK" 0
fi

PATCH_WORK="$REMOTE_ROOT/patch-work"
PATCH_CONFIG="$REMOTE_ROOT/patch.toml"
"${SSH[@]}" /bin/mkdir "$PATCH_WORK"
printf '%s\n' 'old text' | "${SSH[@]}" "/bin/rush -c 'cat >$PATCH_WORK/edited'"
printf '%s\n' 'gone' | "${SSH[@]}" "/bin/rush -c 'cat >$PATCH_WORK/deleted'"
printf '%s\n' 'move me' | "${SSH[@]}" "/bin/rush -c 'cat >$PATCH_WORK/source'"
write_provider_config "$PATCH_CONFIG" 19462
start_mock patch patch-round 19462
patch_output="$("${SSH[@]}" "/bin/gears --config $PATCH_CONFIG \
  --workspace $PATCH_WORK -p 'apply one atomic patch'" 2>&1)" ||
  fail "Gears patch scenario failed: $patch_output"
finish_mock patch 2 19462
[[ "$("${SSH[@]}" /bin/cat "$PATCH_WORK/created")" == "new" &&
   "$("${SSH[@]}" /bin/cat "$PATCH_WORK/edited")" == "changed text" &&
   "$("${SSH[@]}" /bin/cat "$PATCH_WORK/destination")" == "moved me" ]] ||
  fail "Gears patch scenario wrote unexpected content: $patch_output"
"${SSH[@]}" "[ ! -e $PATCH_WORK/deleted ] && [ ! -e $PATCH_WORK/source ]" ||
  fail "Gears patch scenario did not delete its source files"
[[ "$patch_output" == *"patch complete"* ]] ||
  fail "Gears patch scenario did not complete: $patch_output"

PATCH_MODE_CONFIG="$REMOTE_ROOT/patch-mode.toml"
write_provider_config "$PATCH_MODE_CONFIG" 19463
start_mock patch-mode patch-mode-round 19463
patch_mode_output="$("${SSH[@]}" "/bin/gears --config $PATCH_MODE_CONFIG \
  --workspace $PATCH_WORK -p 'try a mode patch'" 2>&1)" ||
  fail "Gears patch-mode scenario failed: $patch_mode_output"
finish_mock patch-mode 2 19463
[[ "$patch_mode_output" == *"executable-bit changes are unsupported on Motor OS"* ]] ||
  fail "Gears did not explain the Motor mode refusal: $patch_mode_output"
"${SSH[@]}" "[ ! -e $PATCH_WORK/must-not-exist ]" ||
  fail "Gears applied a refused Motor mode patch"

EXPLORE_WORK="$REMOTE_ROOT/explore-work"
EXPLORE_CONFIG="$REMOTE_ROOT/explore.toml"
EXPLORE_LOG="$REMOTE_ROOT/explore.log"
"${SSH[@]}" /bin/mkdir "$EXPLORE_WORK"
"${SSH[@]}" /bin/mkdir "$EXPLORE_WORK/nested"
printf '%s\n' '[workspace]' 'members = []' |
  "${SSH[@]}" "/bin/rush -c 'cat >$EXPLORE_WORK/Cargo.toml'"
printf '%s\n' 'root instructions' |
  "${SSH[@]}" "/bin/rush -c 'cat >$EXPLORE_WORK/AGENTS.md'"
printf '%s\n' 'nested instructions' |
  "${SSH[@]}" "/bin/rush -c 'cat >$EXPLORE_WORK/nested/AGENTS.md'"
printf '%s\n' 'step5-motor-needle' |
  "${SSH[@]}" "/bin/rush -c 'cat >$EXPLORE_WORK/needle.txt'"
write_provider_config "$EXPLORE_CONFIG" 19461
printf '%s\n' '[trace]' "file = \"$EXPLORE_LOG\"" 'level = "debug"' |
  "${SSH[@]}" "/bin/rush -c 'cat >>$EXPLORE_CONFIG'"
start_mock explore explore-round 19461
explore_output="$("${SSH[@]}" "PATH=/bin /bin/gears --config $EXPLORE_CONFIG \
  --workspace $EXPLORE_WORK -p 'inspect the repository'" 2>&1)" ||
  fail "Gears exploration scenario failed: $explore_output"
finish_mock explore 2 19461
[[ "$explore_output" == *"needle.txt:1:step5-motor-needle"* &&
   "$explore_output" == *"exploration complete"* ]] ||
  fail "Gears exploration result was not normalized: $explore_output"
explore_trace="$("${SSH[@]}" /bin/cat "$EXPLORE_LOG")" ||
  fail "Gears exploration trace is missing"
[[ "$explore_trace" == *"search backend=rg program=/bin/rg"* ]] ||
  fail "Gears did not accept the packaged rg backend: $explore_trace"
explore_session="$("${SSH[@]}" "/bin/rush -c 'cat $EXPLORE_WORK/.gears/sessions/*.jsonl'")" ||
  fail "Gears exploration session is missing"
[[ "$explore_session" == *"nested/AGENTS.md; identity sha256:"* &&
   "$explore_session" == *"selected Rust backend: lorry"* ]] ||
  fail "Gears exploration session lacks nested instructions or Lorry profile: $explore_session"
explore_evidence="$("${SSH[@]}" "/bin/rush -c 'cat $EXPLORE_WORK/.gears/artifacts/v1/*/1/content'")" ||
  fail "Gears repository-profile artifact is missing"
[[ "$explore_evidence" == *'"rust_backend": "lorry"'* &&
   "$explore_evidence" == *'"path": "Cargo.toml"'* &&
   "$explore_evidence" == *'"program": "lorry"'* ]] ||
  fail "Gears repository-profile evidence is incomplete: $explore_evidence"

echo "gears-test: checking Motor P0 workflow"
WORKFLOW_WORK="$REMOTE_ROOT/p0-workflow"
WORKFLOW_CONFIG="$REMOTE_ROOT/p0-workflow.toml"
"${SSH[@]}" /bin/mkdir "$WORKFLOW_WORK"
"${SSH[@]}" /bin/mkdir "$WORKFLOW_WORK/src"
"${SSH[@]}" /bin/mkdir "$WORKFLOW_WORK/nested"
"${SSH[@]}" /bin/mkdir "$WORKFLOW_WORK/.cargo"
printf '%s\n' \
  '[package]' \
  'name = "p0-workflow"' \
  'version = "0.1.0"' \
  'edition = "2024"' |
  "${SSH[@]}" "/bin/rush -c 'cat >$WORKFLOW_WORK/Cargo.toml'"
printf '%s\n' \
  'version = 4' \
  '' \
  '[[package]]' \
  'name = "p0-workflow"' \
  'version = "0.1.0"' |
  "${SSH[@]}" "/bin/rush -c 'cat >$WORKFLOW_WORK/Cargo.lock'"
printf '%s\n' \
  'pub const LABEL: &str = "P0_WORKFLOW_OLD";' \
  '' \
  '#[test]' \
  'fn label_is_updated() {' \
  '    assert_eq!(LABEL, "P0_WORKFLOW_NEW");' \
  '}' |
  "${SSH[@]}" "/bin/rush -c 'cat >$WORKFLOW_WORK/src/lib.rs'"
printf '%s\n' \
  '[target.x86_64-unknown-motor]' \
  'linker = "/bin/cc"' |
  "${SSH[@]}" "/bin/rush -c 'cat >$WORKFLOW_WORK/.cargo/config.toml'"
printf '%s\n' 'root workflow rules' |
  "${SSH[@]}" "/bin/rush -c 'cat >$WORKFLOW_WORK/AGENTS.md'"
printf '%s\n' 'nested workflow rules' |
  "${SSH[@]}" "/bin/rush -c 'cat >$WORKFLOW_WORK/nested/AGENTS.md'"
printf '%s\n' '// inspected' |
  "${SSH[@]}" "/bin/rush -c 'cat >$WORKFLOW_WORK/nested/lib.rs'"

write_provider_config "$WORKFLOW_CONFIG" 19466 ask
start_mock p0-workflow p0-workflow 19466
coproc WORKFLOW_PTY {
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "PATH=/bin /bin/gears --ui line --config $WORKFLOW_CONFIG \
    --workspace $WORKFLOW_WORK" 2>/dev/null
}
workflow_pid="$WORKFLOW_PTY_PID"
exec {workflow_out}<&"${WORKFLOW_PTY[0]}"
exec {workflow_in}>&"${WORKFLOW_PTY[1]}"
workflow_output=""
read_workflow_until() {
  local target="$1" byte="" start="${#workflow_output}"
  while [[ "${workflow_output:$start}" != *"$target"* ]]; do
    if ! IFS= read -r -N 1 -u "$workflow_out" byte; then
      fail "Motor P0 workflow ended before '$target': $workflow_output"
    fi
    workflow_output+="$byte"
  done
}
read_workflow_until "gears> "
printf '/mode plan\r' >&"$workflow_in"
read_workflow_until "next task mode: plan"
printf 'complete the scripted P0 workflow\r' >&"$workflow_in"
read_workflow_until "allow enter code mode from plan?"
printf 'y\r' >&"$workflow_in"
read_workflow_until "allow patch?"
printf 'y\r' >&"$workflow_in"
read_workflow_until "p0 change ready"

printf '/checkpoint create applied\r' >&"$workflow_in"
read_workflow_until "checkpoint 3 created: applied"
printf '/checkpoint restore 2\r' >&"$workflow_in"
read_workflow_until "restore checkpoint 2?"
printf 'y\r' >&"$workflow_in"
read_workflow_until "restored 2 file states"
workflow_source="$("${SSH[@]}" /bin/cat "$WORKFLOW_WORK/src/lib.rs")" ||
  fail "Motor P0 restored source is missing"
[[ "$workflow_source" == *"P0_WORKFLOW_OLD"* ]] ||
  fail "Motor P0 plan checkpoint did not restore the source"
"${SSH[@]}" "[ ! -e $WORKFLOW_WORK/CHANGELOG.md ]" ||
  fail "Motor P0 plan checkpoint did not remove the created file"

printf '/checkpoint restore 3\r' >&"$workflow_in"
read_workflow_until "restore checkpoint 3?"
printf 'y\r' >&"$workflow_in"
read_workflow_until "restored 2 file states"
workflow_source="$("${SSH[@]}" /bin/cat "$WORKFLOW_WORK/src/lib.rs")" ||
  fail "Motor P0 reapplied source is missing"
workflow_changelog="$("${SSH[@]}" /bin/cat "$WORKFLOW_WORK/CHANGELOG.md")" ||
  fail "Motor P0 reapplied changelog is missing"
[[ "$workflow_source" == *"P0_WORKFLOW_NEW"* &&
   "$workflow_changelog" == "p0 workflow" ]] ||
  fail "Motor P0 applied checkpoint did not restore both files"

printf '/checkpoint restore 2\r' >&"$workflow_in"
read_workflow_until "restore checkpoint 2?"
printf '%s\n' \
  'pub const LABEL: &str = "P0_WORKFLOW_EXTERNAL";' \
  '' \
  '#[test]' \
  'fn label_is_updated() {' \
  '    assert_eq!(LABEL, "P0_WORKFLOW_NEW");' \
  '}' |
  "${SSH[@]}" "/bin/rush -c 'cat >$WORKFLOW_WORK/src/lib.rs'"
printf 'y\r' >&"$workflow_in"
read_workflow_until "conflict"
workflow_source="$("${SSH[@]}" /bin/cat "$WORKFLOW_WORK/src/lib.rs")" ||
  fail "Motor P0 conflicted source is missing"
workflow_changelog="$("${SSH[@]}" /bin/cat "$WORKFLOW_WORK/CHANGELOG.md")" ||
  fail "Motor P0 conflicted changelog is missing"
[[ "$workflow_source" == *"P0_WORKFLOW_EXTERNAL"* &&
   "$workflow_changelog" == "p0 workflow" ]] ||
  fail "Motor P0 stale restore overwrote an external change"

printf 'resolve the conflict, verify, and finish\r' >&"$workflow_in"
read_workflow_until "allow patch?"
printf 'y\r' >&"$workflow_in"
read_workflow_until "allow test?"
printf 'y\r' >&"$workflow_in"
read_workflow_until "p0 workflow complete"
printf '/quit\r' >&"$workflow_in"
exec {workflow_in}>&-
while IFS= read -r -N 1 -u "$workflow_out" byte; do
  workflow_output+="$byte"
done
exec {workflow_out}<&-
workflow_status=0
wait "$workflow_pid" || workflow_status="$?"
unset -f read_workflow_until
[ "$workflow_status" -eq 0 ] ||
  fail "Motor P0 workflow PTY exited $workflow_status: $workflow_output"
finish_mock p0-workflow 13 19466

[[ "$workflow_output" == *"P0_WORKFLOW_OLD"* &&
   "$workflow_output" == *"p0 change ready"* &&
   "$workflow_output" == *"conflict"* &&
   "$workflow_output" == *"p0 workflow complete"* &&
   "$workflow_output" != *"cannot run 'lorry'"* ]] ||
  fail "Motor P0 workflow output is incomplete: $workflow_output"
workflow_source="$("${SSH[@]}" /bin/cat "$WORKFLOW_WORK/src/lib.rs")" ||
  fail "Motor P0 workflow source is missing"
workflow_changelog="$("${SSH[@]}" /bin/cat "$WORKFLOW_WORK/CHANGELOG.md")" ||
  fail "Motor P0 workflow changelog is missing"
[[ "$workflow_source" == *"P0_WORKFLOW_NEW"* &&
   "$workflow_changelog" == "p0 workflow" ]] ||
  fail "Motor P0 workflow did not apply both file changes"
workflow_session="$("${SSH[@]}" \
  "/bin/rush -c 'cat $WORKFLOW_WORK/.gears/sessions/*.jsonl'")" ||
  fail "Motor P0 workflow session is missing"
[[ "$workflow_session" == *"Platform: Motor OS"* &&
   "$workflow_session" == *"nested workflow rules"* &&
   "$workflow_session" == *'"backend":"lorry"'* &&
   "$workflow_session" == *'"checkpoint":2'* &&
   "$workflow_session" == *'"mutation_generation":5'* &&
   "$workflow_session" == *'"mode":"review"'* &&
   "$workflow_session" == *'"verification_evidence":[1]'* ]] ||
  fail "Motor P0 workflow session lacks platform, plan, or evidence: $workflow_session"
workflow_patch_records="$(printf '%s\n' "$workflow_session" |
  grep '"record":"mutation"' | grep '"tool":"patch"' || true)"
workflow_patch_count="$(printf '%s\n' "$workflow_patch_records" |
  grep -c . || true)"
workflow_digest_count="$(printf '%s\n' "$workflow_patch_records" |
  sed -n 's/.*"digest":"\([^"]*\)".*/\1/p' | sort -u | grep -c . || true)"
[ "$workflow_patch_count" -eq 6 ] && [ "$workflow_digest_count" -eq 2 ] ||
  fail "Motor P0 patch approvals did not retain exact digests: $workflow_patch_records"
workflow_restore_records="$(printf '%s\n' "$workflow_session" |
  grep '"record":"mutation"' | grep '"tool":"restore_checkpoint"' || true)"
workflow_restore_count="$(printf '%s\n' "$workflow_restore_records" |
  grep -c . || true)"
workflow_restore_digests="$(printf '%s\n' "$workflow_restore_records" |
  sed -n 's/.*"digest":"\([^"]*\)".*/\1/p' | sort -u | grep -c . || true)"
[[ "$workflow_restore_count" -eq 9 && "$workflow_restore_digests" -eq 2 &&
   "$workflow_restore_records" == *"conflict"* ]] ||
  fail "Motor P0 checkpoint audit is incomplete: $workflow_restore_records"
workflow_artifacts="$("${SSH[@]}" \
  "/bin/rush -c 'cat $WORKFLOW_WORK/.gears/artifacts/v1/*/*/content'")" ||
  fail "Motor P0 workflow artifacts are missing"
[[ "$workflow_artifacts" == *"test result: ok"* ]] ||
  fail "Motor P0 workflow lacks raw native test evidence: $workflow_artifacts"

FLOOD_CONFIG="$REMOTE_ROOT/run-flood.toml"
write_provider_config "$FLOOD_CONFIG" 19460
start_mock run-flood run-flood 19460
flood_output="$("${SSH[@]}" "/bin/gears --config $FLOOD_CONFIG \
  --workspace $REMOTE_WORK -p 'drain both pipes'" 2>&1)" ||
  fail "Gears live-flood scenario failed: $flood_output"
finish_mock run-flood 2 19460
[[ "$flood_output" == *"BEGIN"* && "$flood_output" == *"stdout-0199"* &&
   "$flood_output" == *"stderr-0199"* && "$flood_output" == *"END"* &&
   "$flood_output" == *"flood complete"* ]] ||
  fail "Gears did not drain the live flood: $flood_output"
flood_request_bytes="$(printf '%s\n' "$FINISHED_MOCK_LOG" |
  sed -n 's/^GEARS_MOCK_REQUEST index=2 .* body_bytes=\([0-9][0-9]*\) .*/\1/p')"
[[ "$flood_request_bytes" =~ ^[0-9]+$ && "$flood_request_bytes" -lt 100000 ]] ||
  fail "Gears retained an unbounded flood result: $FINISHED_MOCK_LOG"

echo "gears-test: checking Motor mid-turn Ctrl-C"
INTERRUPT_WORK="$REMOTE_ROOT/interrupt-work"
INTERRUPT_CONFIG="$REMOTE_ROOT/interrupt.toml"
"${SSH[@]}" /bin/mkdir "$INTERRUPT_WORK"
write_provider_config "$INTERRUPT_CONFIG" 19456
start_mock interrupt interrupt-stream 19456

coproc GEARS_PTY {
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "/bin/gears --ui line --config $INTERRUPT_CONFIG --workspace $INTERRUPT_WORK" 2>/dev/null
}
gears_pty_pid="$GEARS_PTY_PID"
exec {gears_pty_out}<&"${GEARS_PTY[0]}"
exec {gears_pty_in}>&"${GEARS_PTY[1]}"
printf 'stream slowly\r' >&"$gears_pty_in"
interrupt_output=""
while [[ "$interrupt_output" != *"before cancel"* ]]; do
  if ! IFS= read -r -N 1 -u "$gears_pty_out" byte; then
    fail "Motor Gears ended before its first streamed token: $interrupt_output"
  fi
  interrupt_output+="$byte"
done
printf '\003' >&"$gears_pty_in"
while [[ "$interrupt_output" != *"- cancelled"* ]]; do
  if ! IFS= read -r -N 1 -u "$gears_pty_out" byte; then
    fail "Motor Gears ended without cancelling: $interrupt_output"
  fi
  interrupt_output+="$byte"
done
printf '/quit\r' >&"$gears_pty_in"
exec {gears_pty_in}>&-
while IFS= read -r -N 1 -u "$gears_pty_out" byte; do
  interrupt_output+="$byte"
done
exec {gears_pty_out}<&-
pty_status=0
wait "$gears_pty_pid" || pty_status="$?"
[ "$pty_status" -eq 0 ] || fail "Motor Ctrl-C PTY exited $pty_status: $interrupt_output"
finish_mock interrupt 1 19456
[[ "$interrupt_output" == *"^C"* && "$interrupt_output" == *"- cancelled"* ]] ||
  fail "Motor did not render in-band Ctrl-C cancellation: $interrupt_output"
[[ "$interrupt_output" != *"after cancel"* ]] ||
  fail "Motor rendered a token sent after cancellation: $interrupt_output"

interrupt_session="$(printf '%s' "$interrupt_output" |
  sed -n 's/.*- session \([0-9][0-9-]*\).*/\1/p' | head -n 1)"
[[ "$interrupt_session" =~ ^[0-9]+-[0-9]+$ ]] ||
  fail "Motor Ctrl-C run printed no session id: $interrupt_output"
INTERRUPT_RESUME_CONFIG="$REMOTE_ROOT/interrupt-resume.toml"
write_provider_config "$INTERRUPT_RESUME_CONFIG" 19457
start_mock interrupt-resume streamed-text 19457
resume_output="$("${SSH[@]}" "/bin/gears --config $INTERRUPT_RESUME_CONFIG \
  --workspace $INTERRUPT_WORK --resume $interrupt_session -p 'resume after cancellation'" 2>&1)" ||
  fail "Motor could not resume the cancelled session: $resume_output"
finish_mock interrupt-resume 1 19457
[[ "$resume_output" == *"hello from the mock"* ]] ||
  fail "Motor resumed session did not complete: $resume_output"

echo "gears-test: checking Motor foreground cancellation"
RUN_CANCEL_WORK="$REMOTE_ROOT/run-cancel-work"
RUN_CANCEL_CONFIG="$REMOTE_ROOT/run-cancel.toml"
"${SSH[@]}" /bin/mkdir "$RUN_CANCEL_WORK"
write_provider_config "$RUN_CANCEL_CONFIG" 19458
start_mock run-cancel run-cancel 19458

coproc RUN_CANCEL_PTY {
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "/bin/gears --ui line --config $RUN_CANCEL_CONFIG --workspace $RUN_CANCEL_WORK" 2>/dev/null
}
run_cancel_pty_pid="$RUN_CANCEL_PTY_PID"
exec {run_cancel_out}<&"${RUN_CANCEL_PTY[0]}"
exec {run_cancel_in}>&"${RUN_CANCEL_PTY[1]}"
printf 'run slowly\r' >&"$run_cancel_in"
run_cancel_output=""
while [[ "$run_cancel_output" != *"1.0s elapsed"* ]]; do
  if ! IFS= read -r -N 1 -u "$run_cancel_out" byte; then
    fail "Motor command ended before reporting elapsed time: $run_cancel_output"
  fi
  run_cancel_output+="$byte"
done
cancel_started="$SECONDS"
printf '\003' >&"$run_cancel_in"
while [[ "$run_cancel_output" != *"- cancelled"* ]]; do
  if ! IFS= read -r -N 1 -u "$run_cancel_out" byte; then
    fail "Motor command did not cancel: $run_cancel_output"
  fi
  run_cancel_output+="$byte"
done
[ "$((SECONDS - cancel_started))" -lt 5 ] ||
  fail "Motor direct child did not stop promptly: $run_cancel_output"
printf '/quit\r' >&"$run_cancel_in"
exec {run_cancel_in}>&-
while IFS= read -r -N 1 -u "$run_cancel_out" byte; do
  run_cancel_output+="$byte"
done
exec {run_cancel_out}<&-
run_cancel_status=0
wait "$run_cancel_pty_pid" || run_cancel_status="$?"
[ "$run_cancel_status" -eq 0 ] ||
  fail "Motor command-cancel PTY exited $run_cancel_status: $run_cancel_output"
finish_mock run-cancel 1 19458
[[ "$run_cancel_output" == *"killed the direct child"* &&
   "$run_cancel_output" == *"cannot guarantee descendant cleanup"* ]] ||
  fail "Motor cancellation did not report its process limit: $run_cancel_output"

run_cancel_session="$(printf '%s' "$run_cancel_output" |
  sed -n 's/.*- session \([0-9][0-9-]*\).*/\1/p' | head -n 1)"
[[ "$run_cancel_session" =~ ^[0-9]+-[0-9]+$ ]] ||
  fail "Motor command-cancel run printed no session id: $run_cancel_output"
RUN_CANCEL_RESUME_CONFIG="$REMOTE_ROOT/run-cancel-resume.toml"
write_provider_config "$RUN_CANCEL_RESUME_CONFIG" 19459
start_mock run-cancel-resume streamed-text 19459
run_cancel_resume="$("${SSH[@]}" "/bin/gears --config $RUN_CANCEL_RESUME_CONFIG \
  --workspace $RUN_CANCEL_WORK --resume $run_cancel_session -p 'resume after command cancellation'" 2>&1)" ||
  fail "Motor command-cancel session could not resume: $run_cancel_resume"
finish_mock run-cancel-resume 1 19459
[[ "$run_cancel_resume" == *"hello from the mock"* ]] ||
  fail "Motor command-cancel session did not resume: $run_cancel_resume"

echo "gears-test: checking Motor platform contract"
BUILD_WORK="$REMOTE_ROOT/build-fixture"
EMPTY_PATH="$REMOTE_ROOT/empty-path"
"${SSH[@]}" /bin/mkdir "$BUILD_WORK"
"${SSH[@]}" /bin/mkdir "$BUILD_WORK/src"
"${SSH[@]}" /bin/mkdir "$BUILD_WORK/.cargo"
"${SSH[@]}" /bin/mkdir "$EMPTY_PATH"
printf '%s\n' \
  '[package]' \
  'name = "gears-path-fixture"' \
  'version = "0.1.0"' \
  'edition = "2024"' \
  '' \
  '[dependencies]' |
  "${SSH[@]}" "/bin/rush -c 'cat >$BUILD_WORK/Cargo.toml'"
printf '%s\n' \
  'version = 4' \
  '' \
  '[[package]]' \
  'name = "gears-path-fixture"' \
  'version = "0.1.0"' |
  "${SSH[@]}" "/bin/rush -c 'cat >$BUILD_WORK/Cargo.lock'"
printf '%s\n' 'fn main() { println!("gears path fixture"); }' |
  "${SSH[@]}" "/bin/rush -c 'cat >$BUILD_WORK/src/main.rs'"
printf '%s\n' \
  '[target.x86_64-unknown-motor]' \
  'linker = "/bin/cc"' |
  "${SSH[@]}" "/bin/rush -c 'cat >$BUILD_WORK/.cargo/config.toml'"

run_platform_round build-standard build-round 19450 "$BUILD_WORK" ""
[[ "$PLATFORM_OUTPUT" != *"cannot run 'lorry'"* ]] ||
  fail "standard russhd PATH did not resolve Lorry: $PLATFORM_OUTPUT"
"${SSH[@]}" "[ -x $BUILD_WORK/target/lorry/debug/gears-path-fixture ]" ||
  fail "standard PATH build produced no executable"

"${SSH[@]}" /bin/rm -r "$BUILD_WORK/target"
run_platform_round build-explicit build-round 19451 "$BUILD_WORK" "PATH=/bin"
[[ "$PLATFORM_OUTPUT" != *"cannot run 'lorry'"* ]] ||
  fail "explicit Motor PATH did not resolve Lorry: $PLATFORM_OUTPUT"
"${SSH[@]}" "[ -x $BUILD_WORK/target/lorry/debug/gears-path-fixture ]" ||
  fail "explicit PATH build produced no executable"

path_index=0
for path_case in unset empty unsuitable; do
  case "$path_case" in
    unset) launch='unset PATH;' ;;
    empty) launch='PATH=' ;;
    unsuitable) launch="PATH=$EMPTY_PATH" ;;
  esac
  run_platform_round "build-$path_case" build-round "$((19452 + path_index))" \
    "$BUILD_WORK" "$launch"
  [[ "$PLATFORM_OUTPUT" == *"cannot run 'lorry'"* &&
     "$PLATFORM_OUTPUT" == *"PATH"* &&
     "$PLATFORM_OUTPUT" == *'Motor OS attempted argument vector ["lorry"'* ]] ||
    fail "$path_case PATH did not produce targeted Lorry guidance: $PLATFORM_OUTPUT"
  path_index=$((path_index + 1))
done

"${SSH[@]}" "[ ! -e $REMOTE_ROOT/cargo-spawned ]" ||
  fail "Cargo sentinel was present before its scenario"
run_platform_round cargo-refusal cargo-round 19455 "$BUILD_WORK" \
  "PATH=/sys/tests/gears/TEST_ONLY_CARGO_SENTINEL_BIN:/bin"
[[ "$PLATFORM_OUTPUT" == *"Motor OS does not provide Cargo"* &&
   "$PLATFORM_OUTPUT" == *"build or test"* && "$PLATFORM_OUTPUT" == *"lorry"* ]] ||
  fail "raw Cargo did not receive Motor guidance: $PLATFORM_OUTPUT"
"${SSH[@]}" "[ ! -e $REMOTE_ROOT/cargo-spawned ]" ||
  fail "Gears spawned raw Cargo on Motor"

report_metric() {
  local platform="$1" metric="$2" unit="$3"
  shift 3
  local values=("$@") sorted median min max spread status samples
  local baseline_median=none baseline_status=none regression=not-compared gate=recorded
  [ "${#values[@]}" -eq "$quality_samples" ] ||
    fail "$platform $metric has ${#values[@]} samples, expected $quality_samples"
  for value in "${values[@]}"; do
    [[ "$value" =~ ^[0-9]+$ ]] || fail "$platform $metric has invalid sample '$value'"
  done
  mapfile -t sorted < <(printf '%s\n' "${values[@]}" | sort -n)
  min="${sorted[0]}"
  median="${sorted[$((${#sorted[@]} / 2))]}"
  max="${sorted[$((${#sorted[@]} - 1))]}"
  if [ "$median" -eq 0 ]; then
    [ "$max" -eq "$min" ] && spread=0 || spread=unbounded
  else
    spread=$(((max - min) * 100 / median))
  fi
  status=stable
  [ "$spread" != unbounded ] && [ "$spread" -le "$quality_regression_percent" ] || status=noisy
  if [ -n "$quality_baseline" ]; then
    baseline_median="$(sed -n "/^platform=$platform metric=$metric /s/.* median=\([^ ]*\).*/\1/p" \
      "$quality_baseline" | tail -n 1)"
    baseline_status="$(sed -n "/^platform=$platform metric=$metric /s/.* status=\([^ ]*\).*/\1/p" \
      "$quality_baseline" | tail -n 1)"
    if [[ ! "$baseline_median" =~ ^[0-9]+$ ]] ||
       [[ ! "$baseline_status" =~ ^(stable|noisy)$ ]]; then
      gate=missing-baseline
      echo "$platform $metric has no valid baseline" >> "$quality_failures"
    elif [ "$status" = noisy ] || [ "$baseline_status" = noisy ]; then
      regression=not-gated
      gate=noisy
    elif [ "$median" -le "$baseline_median" ]; then
      regression=0
      gate=pass
    elif [ "$baseline_median" -eq 0 ]; then
      regression=unbounded
      gate=fail
      echo "$platform $metric grew from zero to $median $unit" >> "$quality_failures"
    else
      regression=$(((median - baseline_median) * 100 + baseline_median - 1))
      regression=$((regression / baseline_median))
      if [ "$median" -gt $((baseline_median * (100 + quality_regression_percent) / 100)) ]; then
        gate=fail
        echo "$platform $metric regressed $regression%, limit is $quality_regression_percent%" \
          >> "$quality_failures"
      else
        gate=pass
      fi
    fi
  fi
  samples="$(IFS=,; echo "${values[*]}")"
  printf 'platform=%s metric=%s unit=%s samples=%s median=%s spread_percent=%s status=%s baseline_median=%s regression_percent=%s gate=%s\n' \
    "$platform" "$metric" "$unit" "$samples" "$median" "$spread" "$status" \
    "$baseline_median" "$regression" "$gate"
}

if [ "$BASELINE" -eq 1 ]; then
  : > "$quality_failures"
  report="$({
    echo "gears_quality build=$BUILD samples=$quality_samples max_regression_percent=$quality_regression_percent"
    report_metric linux startup microseconds "${linux_startup[@]}"
    report_metric linux peak_rss bytes "${linux_memory[@]}"
    report_metric linux request bytes "${linux_request[@]}"
    report_metric linux context bytes "${linux_context[@]}"
    report_metric linux retained_session bytes "${linux_retained[@]}"
    report_metric linux artifact_storage bytes "${linux_artifact[@]}"
    report_metric linux render_queue_depth events "${linux_render[@]}"
    report_metric linux foreground_tool_turnaround microseconds "${linux_tool[@]}"
    report_metric motor startup microseconds "${motor_startup[@]}"
    report_metric motor sampled_process_memory bytes "${motor_memory[@]}"
    report_metric motor request bytes "${motor_request[@]}"
    report_metric motor context bytes "${motor_context[@]}"
    report_metric motor retained_session bytes "${motor_retained[@]}"
    report_metric motor artifact_storage bytes "${motor_artifact[@]}"
    report_metric motor render_queue_depth events "${motor_render[@]}"
    report_metric motor foreground_tool_turnaround microseconds "${motor_tool[@]}"
  })"
  printf '%s\n' "$report"
  if [ -n "${GEARS_BASELINE_REPORT:-}" ]; then
    printf '%s\n' "$report" > "$GEARS_BASELINE_REPORT"
  fi
  if [ -s "$quality_failures" ]; then
    cat "$quality_failures" >&2
    fail "stable quality regression exceeded the configured policy"
  fi
fi

stop_vm "$VMM_PID"
VMM_PID=""
echo "-------- GEARS TEST PASS ($BUILD) --------"
