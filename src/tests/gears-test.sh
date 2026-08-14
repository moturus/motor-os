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
motor_startup=()
motor_memory=()
motor_tool=()

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

start_host_mock() {
  local label="$1"
  local log="$SCRATCH/$label-host-mock.log"
  local mock="$ROOT_DIR/src/bin/gears-mock-provider/target/$BUILD/gears-mock-provider"
  "$mock" --addr 127.0.0.1:0 --scenario tool-round \
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

  local sample output base_url config work log status result
  for sample in 1 2 3; do
    output="$(HOME="$SCRATCH/home" "$measure" -- "$gears" --version)"
    linux_startup+=("$(metric_value elapsed_us "$output")")

    start_host_mock "sample-$sample"
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
    result="$(cat "$work/result.txt")" || fail "host baseline did not create result.txt"
    [ "$result" = "made by gears" ] || fail "unexpected host baseline result: '$result'"
    linux_memory+=("$(metric_value peak_memory_bytes "$output")")
    linux_tool+=("$(tool_latency "$log")")
  done
}

if [ "$BASELINE" -eq 1 ]; then
  echo "gears-test: collecting Linux performance baseline"
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
  for _ in 1 2 3; do
    measurement="$("${SSH[@]}" /sys/tests/gears-measure -- /bin/gears --version)" ||
      fail "Motor startup baseline failed"
    motor_startup+=("$(metric_value elapsed_us "$measurement")")
  done
fi

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

run_motor_tool_round() {
  local label="$1" port="$2" work="$3" measured="$4"
  local config="$REMOTE_ROOT/$label.toml" output result memory
  write_provider_config "$config" "$port"
  start_mock "$label" tool-round "$port"
  if [ "$measured" -eq 1 ]; then
    output="$("${SSH[@]}" "/sys/tests/gears-measure --memory -- /bin/gears \
      --config $config --workspace $work -p 'run the measured tool round'" 2>&1)" ||
      fail "Gears measured tool round failed: $output"
  else
    output="$("${SSH[@]}" "/bin/gears --config $config \
      --workspace $work -p 'run the scripted tool round'" 2>&1)" ||
      fail "Gears tool-round scenario failed: $output"
  fi
  finish_mock "$label" 2 "$port"
  result="$("${SSH[@]}" /bin/cat "$work/result.txt")" ||
    fail "Gears tool round did not create result.txt"
  [ "$result" = "made by gears" ] || fail "unexpected result.txt contents: '$result'"
  [[ "$output" == *"tool complete"* ]] ||
    fail "Gears did not complete after its tool call: $output"
  if [ "$measured" -eq 1 ]; then
    memory="$(metric_value peak_memory_bytes "$output")"
    [[ "$memory" =~ ^[0-9]+$ ]] || fail "Motor memory sample is unavailable: $output"
    motor_memory+=("$memory")
    motor_tool+=("$(tool_latency "$FINISHED_MOCK_LOG")")
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
  for sample in 1 2 3; do
    work="$REMOTE_ROOT/work-$sample"
    "${SSH[@]}" /bin/mkdir "$work"
    run_motor_tool_round "baseline-$sample" "$((19443 + sample))" "$work" 1
  done
else
  run_motor_tool_round tool-round 19444 "$REMOTE_WORK" 0
fi

echo "gears-test: checking Motor mid-turn Ctrl-C"
INTERRUPT_WORK="$REMOTE_ROOT/interrupt-work"
INTERRUPT_CONFIG="$REMOTE_ROOT/interrupt.toml"
"${SSH[@]}" /bin/mkdir "$INTERRUPT_WORK"
write_provider_config "$INTERRUPT_CONFIG" 19456
start_mock interrupt interrupt-stream 19456

coproc GEARS_PTY {
  ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
    "/bin/gears --config $INTERRUPT_CONFIG --workspace $INTERRUPT_WORK" 2>/dev/null
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
  local values=("$@") sorted median min max spread status
  for value in "${values[@]}"; do
    [[ "$value" =~ ^[0-9]+$ ]] || fail "$platform $metric has invalid sample '$value'"
  done
  mapfile -t sorted < <(printf '%s\n' "${values[@]}" | sort -n)
  min="${sorted[0]}"
  median="${sorted[1]}"
  max="${sorted[2]}"
  spread=$(((max - min) * 100 / median))
  status=stable
  [ "$spread" -le 10 ] || status=noisy
  printf 'platform=%s metric=%s unit=%s samples=%s,%s,%s median=%s spread_percent=%s status=%s\n' \
    "$platform" "$metric" "$unit" "${values[0]}" "${values[1]}" "${values[2]}" \
    "$median" "$spread" "$status"
}

if [ "$BASELINE" -eq 1 ]; then
  report="$({
    echo "gears_baseline build=$BUILD samples=3 noise_threshold_percent=10"
    report_metric linux startup microseconds "${linux_startup[@]}"
    report_metric linux peak_rss bytes "${linux_memory[@]}"
    report_metric linux foreground_tool_turnaround microseconds "${linux_tool[@]}"
    report_metric motor startup microseconds "${motor_startup[@]}"
    report_metric motor sampled_process_memory bytes "${motor_memory[@]}"
    report_metric motor foreground_tool_turnaround microseconds "${motor_tool[@]}"
  })"
  printf '%s\n' "$report"
  if [ -n "${GEARS_BASELINE_REPORT:-}" ]; then
    printf '%s\n' "$report" > "$GEARS_BASELINE_REPORT"
  fi
fi

stop_vm "$VMM_PID"
VMM_PID=""
echo "-------- GEARS TEST PASS ($BUILD) --------"
