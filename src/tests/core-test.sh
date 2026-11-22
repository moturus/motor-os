#!/bin/bash
# A fast gate for core OS changes: the src/sys subset of full-test.sh.
# Times every step and prints all the timings at the end.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/src/tests/full-test.sh"

core_options() {
  case "$*" in
    ''|--release) ;;
    *) echo "usage: $0 [--release]" >&2; return 2 ;;
  esac
  full_options "$@"
  CORE=1
  NATIVE_ARGS+=(--core)
}

# Microseconds since the epoch. EPOCHREALTIME's separator follows the locale.
core_now() {
  local now="$EPOCHREALTIME"
  CORE_NOW="${now//[!0-9]/}"
}

core_duration() {
  local us="$1"
  printf '%d:%02d.%d' $((us / 60000000)) $((us / 1000000 % 60)) $((us / 100000 % 10))
}

# Runs one step and records its wall time. Steps that run full-native-test.sh
# also record each crate in "$CORE_DETAIL".
core_step() {
  CORE_STEP="$1"
  shift
  CORE_DETAIL="$CORE_TIMES/${#CORE_LABELS[@]}"
  echo "core-test: --- $CORE_STEP"
  core_now
  CORE_STEP_START="$CORE_NOW"
  "$@"
  core_now
  CORE_LABELS+=("$CORE_STEP")
  CORE_US+=($((CORE_NOW - CORE_STEP_START)))
  CORE_STEP=
}

# Passes full-native-test.sh output through, timing the gaps between its
# per-crate headers.
core_crate_times() {
  local os="$1" label="$1 setup" start line
  core_now
  start="$CORE_NOW"
  while IFS= read -r line || [ -n "$line" ]; do
    printf '%s\n' "$line"
    case "$line" in
      "full-native-test: $os "*|'full-native-test: PASS '*) ;;
      *) continue ;;
    esac
    core_now
    printf '%s\t%s\n' "$label" $((CORE_NOW - start)) >> "$CORE_DETAIL"
    start="$CORE_NOW"
    label=
    case "$line" in
      'full-native-test: PASS '*) ;;
      *)
        label="${line#full-native-test: }"
        label="${label% (*)}"
        label="${label%"${label##*[! ]}"}" ;;
    esac
  done
  if [ -n "$label" ]; then
    core_now
    printf '%s (unfinished)\t%s\n' "$label" $((CORE_NOW - start)) >> "$CORE_DETAIL"
  fi
}

# Shortens very long words, such as feature lists, in a crate's label.
core_short_label() {
  local word words short=
  read -ra words <<< "$1"
  for word in "${words[@]}"; do
    [ "${#word}" -le 40 ] || word="${word:0:24}..."
    short="${short:+$short }$word"
  done
  printf '%s' "$short"
}

core_report_details() {
  local label us
  [ -f "$1" ] || return 0
  while IFS=$'\t' read -r label us; do
    printf '%9s    %s\n' "$(core_duration "$us")" "$(core_short_label "$label")"
  done < "$1"
}

core_report() {
  local i
  echo 'core-test: timings (m:ss.d)'
  for i in "${!CORE_LABELS[@]}"; do
    printf '%9s  %s\n' "$(core_duration "${CORE_US[i]}")" "${CORE_LABELS[i]}"
    core_report_details "$CORE_TIMES/$i"
  done
  core_now
  if [ -n "$CORE_STEP" ]; then
    printf '%9s  %s FAILED\n' "$(core_duration $((CORE_NOW - CORE_STEP_START)))" "$CORE_STEP"
    core_report_details "$CORE_TIMES/${#CORE_LABELS[@]}"
  fi
  printf '%9s  %s\n' "$(core_duration $((CORE_NOW - CORE_BEGIN)))" 'total'
}

core_exit() {
  local status=$?
  set +e
  core_report
  rm -r -- "$CORE_TIMES"
  if [ "$CORE_VMS" = 1 ]; then
    # cross_cleanup reads the exit status from $?.
    (exit "$status")
    cross_cleanup
  fi
  exit "$status"
}

core_linux_tests() {
  "$ROOT_DIR/src/tests/full-native-test.sh" "${NATIVE_ARGS[@]}" 2>&1 | core_crate_times linux
}

# cross_fresh_boot uploads systest. mio-test and tokio-tests are built in the
# native-test profile, as full-test.sh builds them with `lorry run`.
core_fresh_boot() {
  local name
  cross_fresh_boot
  for name in mio-test tokio-tests; do
    printf 'put "%s" "%s/%s"\nchmod 755 "%s/%s"\n' \
      "$ROOT_DIR/build/bin/$TEST_BUILD/$name" "$TEST_BIN" "$name" "$TEST_BIN" "$name" | vm_sftp
  done
}

# Runs a host-built test program as Interactive in the fresh-boot VM.
core_vm_program() {
  local name="$1" pass="$2"
  vm_ssh "MOTOR_OS_CAPS=0x3ec $TEST_BIN/$name" 2>&1 | tee "$RUN_DIR/$name.log"
  grep -qx "$pass" "$RUN_DIR/$name.log" || cross_fail "$name did not pass"
}

# Stops the fresh-boot VM, then boots a new copy for `lorry test`.
core_native_boot() {
  shutdown_test_image
  copy_test_image "$FULL_IMAGE" native
  boot_test_image native
  wait_vm_ssh
  check_guest_image_layout
}

core_motor_tests() {
  vm_ssh "MOTOR_OS_CAPS=0x3ec NATIVE_TEST_CAPS=0x3ec /user/bin/rush /none/dev/motor-os/src/tests/full-native-test.sh ${NATIVE_ARGS[*]}" 2>&1 |
    core_crate_times motor
  shutdown_test_image
}

core_main() {
  local channel
  core_options "$@"
  cd "$ROOT_DIR"
  mkdir -p build
  CORE_TIMES="$(mktemp -d "$ROOT_DIR/build/core-test-times.XXXXXX")"
  CORE_LABELS=()
  CORE_US=()
  CORE_STEP=
  CORE_VMS=0
  core_now
  CORE_BEGIN="$CORE_NOW"
  trap core_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  channel="$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)"
  [[ "$channel" =~ ^[A-Za-z0-9._-]+$ ]] || cross_fail 'expected one toolchain channel in rust-toolchain.toml'

  core_step 'host: toolchain identity check' full_check_toolchain "$channel"
  core_step 'host: make images and test programs' make -C "$ROOT_DIR" -j"$(nproc)" BUILD="$BUILD" \
    images systest crossterm-smoke wg-self-test rnetbench
  core_step 'host: make mio-test and tokio-tests' make -C "$ROOT_DIR" -j"$(nproc)" BUILD="$TEST_BUILD" \
    mio-test tokio-tests
  core_step 'host: make toolchain-archive' make -C "$ROOT_DIR" -j"$(nproc)" BUILD=release toolchain-archive
  core_step 'host: prepare native test inputs' "$ROOT_DIR/src/build-scripts/native-test-inputs.sh" "${NATIVE_ARGS[@]}"
  core_step 'host: cargo test (src/sys crates)' core_linux_tests

  cross_options "${PROFILE_ARGS[@]}" --vmm "$VMM" --cpus "$CPUS" --memory "$MEMORY_MIB"
  cross_setup
  CORE_VMS=1
  trap core_exit EXIT
  core_step 'host: build console test programs' cross_prepare_console_programs
  core_step 'vm: base image boot' cross_base
  core_step 'vm: toolchain install' full_install_toolchain "$channel"
  CROSS_IMAGE="$FULL_IMAGE"
  core_step 'vm: fresh boot checks (mem-placement, kernel-log-boot)' core_fresh_boot
  core_step 'vm: systest' core_vm_program systest 'systest: ALL PASS'
  core_step 'vm: mio-test' core_vm_program mio-test 'mio-test: ALL PASS'
  core_step 'vm: tokio-tests' core_vm_program tokio-tests 'tokio-tests PASS'
  core_step 'vm: native boot' core_native_boot
  core_step 'vm: upload native test inputs' full_upload_native_inputs
  core_step 'vm: lorry test (src/sys crates)' core_motor_tests
  core_step 'vm: System console checks' cross_system_console
  core_step 'vm: System OOM abort' cross_oom_abort
  echo "core-test: PASS ($BUILD image, $TEST_BUILD tests, $VMM)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then core_main "$@"; fi
