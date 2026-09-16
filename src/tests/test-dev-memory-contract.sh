#!/usr/bin/env bash
# Exercise the wrapper's real environment assignments without booting a VM.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/src/tests" "$temporary/src/bin/lorry/tests" "$temporary/bin"
cp "$WD/full-test-dev.sh" "$temporary/src/tests/"
for script in full-test.sh test-dev-sources.sh; do
  printf '%s\n' '#!/bin/bash' \
    'printf "%s %s %s\n" "${0##*/}" "${MOTO_MEMORY_MIB:-unset}" "$*" >> "$MEMORY_TEST_LOG"' \
    > "$temporary/src/tests/$script"
  chmod +x "$temporary/src/tests/$script"
done
printf '%s\n' '#!/bin/bash' 'exit 0' > "$temporary/bin/python3"
cp "$temporary/bin/python3" "$temporary/src/bin/lorry/tests/test-all.sh"
chmod +x "$temporary/bin/python3" "$temporary/src/bin/lorry/tests/test-all.sh"
export MEMORY_TEST_LOG="$temporary/observed"
export PATH="$temporary/bin:$PATH"

env -u MOTO_MEMORY_MIB bash "$temporary/src/tests/full-test-dev.sh" --release > "$temporary/wrapper.log"
expected=$'full-test.sh 8192 --release\ntest-dev-sources.sh 4096 --release'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'developer VM defaults changed' >&2; exit 1;
}
: > "$MEMORY_TEST_LOG"
MOTO_MEMORY_MIB=6144 bash "$temporary/src/tests/full-test-dev.sh" --release >> "$temporary/wrapper.log"
expected=$'full-test.sh 6144 --release\ntest-dev-sources.sh 6144 --release'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'developer VM caller override was not preserved' >&2; exit 1;
}

: > "$MEMORY_TEST_LOG"
env -u MOTO_MEMORY_MIB \
  bash "$temporary/src/tests/full-test-dev.sh" --release --vmm chv \
  >> "$temporary/wrapper.log"
expected=$'full-test.sh 8192 --release --vmm chv\ntest-dev-sources.sh 4096 --release --vmm chv'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'developer VMM selection was not forwarded to both phases' >&2; exit 1;
}
: > "$MEMORY_TEST_LOG"
if bash "$temporary/src/tests/full-test-dev.sh" --release --vmm fc \
    >> "$temporary/wrapper.log" 2>&1; then
  echo 'developer wrapper accepted Firecracker' >&2
  exit 1
fi
[ ! -s "$MEMORY_TEST_LOG" ] || {
  echo 'developer wrapper rejected Firecracker after starting a phase' >&2; exit 1;
}

# The candidate wrapper has its own 8 GiB default and preserves an override.
cp "$WD/test-candidate-vm.sh" "$temporary/src/tests/"
cp "$WD/vm-test-selection.sh" "$temporary/src/tests/"
cat > "$temporary/src/tests/vm-test-boot.sh" <<'EOF'
test_vm_configure_ssh() { :; }
start_test_vm() {
  local runner_dir="${1%/*}"
  local runner="${runner_dir##*/}/${1##*/}"
  local label="$2"
  shift 3
  printf 'candidate-vm %s %s %s %s %s\n' \
    "$MOTO_MEMORY_MIB" "$runner" "$label" "$MOTO_IMAGE" "${*:-no-args}" \
    >> "$MEMORY_TEST_LOG"
  sleep 60 &
  VMM_PID="$!"
}
EOF
printf '%s\n' 'filter_vm_console() { cat; }' > "$temporary/src/tests/vm-console-filter.sh"
cat > "$temporary/src/tests/vm-test-boot-check.sh" <<'EOF'
stop_test_vm_owned() {
  local vmm="$1" label="$2" process_status=0
  kill "$VMM_PID" 2>/dev/null || true
  wait "$VMM_PID" || process_status=$?
  VMM_PID=""
  printf 'candidate-stop %s %s %s\n' "$vmm" "$label" "$process_status" \
    >> "$MEMORY_TEST_LOG"
  [ "${MOCK_STOP_FAILURE:-0}" != 1 ]
}
EOF
for script in test-rust-analyzer-native.sh test-rust-analyzer-crates.sh test-unwind.sh \
  test-rustfmt-native.sh; do
  printf '%s\n' '#!/bin/bash' \
    'printf "%s\n" "${0##*/}" >> "$MEMORY_TEST_LOG"' \
    '[ "${MOCK_GUEST_FAILURE:-}" != "${0##*/}" ] || exit 7' \
    > "$temporary/src/tests/$script"
  chmod +x "$temporary/src/tests/$script"
done

: > "$MEMORY_TEST_LOG"
env -u MOTO_MEMORY_MIB -u FULL_TEST_QEMU_ARGS \
  bash "$temporary/src/tests/test-candidate-vm.sh" --release \
  >> "$temporary/wrapper.log"
expected=$'candidate-vm 8192 release/run-qemu.sh QEMU motor-os-dev.qcow2 no-args\ntest-rust-analyzer-native.sh\ntest-rust-analyzer-crates.sh\ntest-unwind.sh\ntest-rustfmt-native.sh\ncandidate-stop qemu QEMU 143'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'candidate VM default changed' >&2; exit 1;
}
: > "$MEMORY_TEST_LOG"
MOTO_MEMORY_MIB=6144 FULL_TEST_QEMU_ARGS='-nodefaults -no-shutdown' \
  bash "$temporary/src/tests/test-candidate-vm.sh" --release \
  >> "$temporary/wrapper.log"
expected=$'candidate-vm 6144 release/run-qemu.sh QEMU motor-os-dev.qcow2 -nodefaults -no-shutdown\ntest-rust-analyzer-native.sh\ntest-rust-analyzer-crates.sh\ntest-unwind.sh\ntest-rustfmt-native.sh\ncandidate-stop qemu QEMU 143'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'candidate VM caller override was not preserved' >&2; exit 1;
}
: > "$MEMORY_TEST_LOG"
MOTO_MEMORY_MIB=6144 FULL_TEST_QEMU_ARGS='-nodefaults -no-shutdown' \
  bash "$temporary/src/tests/test-candidate-vm.sh" --release --vmm chv \
  >> "$temporary/wrapper.log"
expected=$'candidate-vm 6144 release/run-chv.sh Cloud Hypervisor motor-os-dev.qcow2 no-args\ntest-rust-analyzer-native.sh\ntest-rust-analyzer-crates.sh\ntest-unwind.sh\ntest-rustfmt-native.sh\ncandidate-stop chv Cloud Hypervisor 143'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'candidate CHV selection or QEMU-only argument isolation failed' >&2; exit 1;
}
: > "$MEMORY_TEST_LOG"
if MOCK_STOP_FAILURE=1 \
    bash "$temporary/src/tests/test-candidate-vm.sh" --release --vmm chv \
    > "$temporary/teardown-failure.log" 2>&1; then
  echo 'candidate ignored owned VMM teardown failure' >&2
  exit 1
fi
! grep -q 'test-candidate-vm PASS' "$temporary/teardown-failure.log" || {
  echo 'candidate printed PASS before successful teardown' >&2; exit 1;
}
: > "$MEMORY_TEST_LOG"
set +e
MOCK_GUEST_FAILURE=test-unwind.sh \
  bash "$temporary/src/tests/test-candidate-vm.sh" --release --vmm chv \
  > "$temporary/guest-failure.log" 2>&1
guest_failure_status=$?
set -e
[ "$guest_failure_status" -eq 7 ] || {
  echo "candidate replaced original guest failure status $guest_failure_status" >&2; exit 1;
}
[ "$(tail -1 "$MEMORY_TEST_LOG")" = 'candidate-stop chv Cloud Hypervisor 143' ] || {
  echo 'candidate did not stop owned VMM after guest failure' >&2; exit 1;
}
: > "$MEMORY_TEST_LOG"
if bash "$temporary/src/tests/test-candidate-vm.sh" --release --vmm fc \
    >> "$temporary/wrapper.log" 2>&1; then
  echo 'candidate wrapper accepted Firecracker' >&2
  exit 1
fi
[ ! -s "$MEMORY_TEST_LOG" ] || {
  echo 'candidate wrapper rejected Firecracker after VM startup' >&2; exit 1;
}
echo 'test-dev-memory-contract PASS'
