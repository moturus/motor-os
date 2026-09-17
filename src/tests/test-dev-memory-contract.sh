#!/usr/bin/env bash
# Exercise the wrapper's real environment assignments without booting a VM.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/src/tests" "$temporary/src/bin/lorry/tests" \
  "$temporary/src/bin/httpd-axum/tests" "$temporary/bin"
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
cat > "$temporary/src/bin/httpd-axum/tests/run.sh" <<'EOF'
#!/bin/bash
printf 'httpd-axum %s %s %s\n' "${MOTO_MEMORY_MIB:-unset}" "${MOTO_IMAGE:-unset}" "$*" >> "$MEMORY_TEST_LOG"
EOF
chmod +x "$temporary/src/bin/httpd-axum/tests/run.sh"
export MEMORY_TEST_LOG="$temporary/observed"
export PATH="$temporary/bin:$PATH"

env -u MOTO_MEMORY_MIB -u MOTO_IMAGE bash "$temporary/src/tests/full-test-dev.sh" --release > "$temporary/wrapper.log"
expected=$'full-test.sh 8192 --release\nhttpd-axum unset unset --release\nhttpd-axum 4096 motor-os-dev.qcow2 --motor --release\ntest-dev-sources.sh 4096 --release'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'developer VM defaults changed' >&2; exit 1;
}
: > "$MEMORY_TEST_LOG"
MOTO_MEMORY_MIB=6144 MOTO_IMAGE=caller.qcow2 \
  bash "$temporary/src/tests/full-test-dev.sh" --release >> "$temporary/wrapper.log"
expected=$'full-test.sh 6144 --release\nhttpd-axum 6144 caller.qcow2 --release\nhttpd-axum 6144 motor-os-dev.qcow2 --motor --release\ntest-dev-sources.sh 6144 --release'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'developer VM caller override was not preserved' >&2; exit 1;
}

# The candidate wrapper has its own 8 GiB default and preserves an override.
cp "$WD/test-candidate-vm.sh" "$temporary/src/tests/"
cat > "$temporary/src/tests/vm-test-boot.sh" <<'EOF'
test_vm_configure_ssh() { :; }
start_test_vm() {
  printf 'candidate-vm %s %s %s\n' "$MOTO_MEMORY_MIB" "${1##*/}" "$MOTO_IMAGE" >> "$MEMORY_TEST_LOG"
  VMM_PID=""
}
EOF
printf '%s\n' 'filter_vm_console() { cat; }' > "$temporary/src/tests/vm-console-filter.sh"
printf '%s\n' 'stop_vm() { :; }' > "$temporary/src/tests/vm-cleanup.sh"
for script in test-rust-analyzer-native.sh test-rust-analyzer-crates.sh test-unwind.sh \
  test-rustfmt-native.sh; do
  printf '%s\n' '#!/bin/bash' \
    'printf "%s\n" "${0##*/}" >> "$MEMORY_TEST_LOG"' \
    > "$temporary/src/tests/$script"
  chmod +x "$temporary/src/tests/$script"
done

: > "$MEMORY_TEST_LOG"
env -u MOTO_MEMORY_MIB bash "$temporary/src/tests/test-candidate-vm.sh" --release \
  >> "$temporary/wrapper.log"
expected=$'candidate-vm 8192 release motor-os-dev.qcow2\ntest-rust-analyzer-native.sh\ntest-rust-analyzer-crates.sh\ntest-unwind.sh\ntest-rustfmt-native.sh'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'candidate VM default changed' >&2; exit 1;
}
: > "$MEMORY_TEST_LOG"
MOTO_MEMORY_MIB=6144 bash "$temporary/src/tests/test-candidate-vm.sh" --release \
  >> "$temporary/wrapper.log"
expected=$'candidate-vm 6144 release motor-os-dev.qcow2\ntest-rust-analyzer-native.sh\ntest-rust-analyzer-crates.sh\ntest-unwind.sh\ntest-rustfmt-native.sh'
[ "$(<"$MEMORY_TEST_LOG")" = "$expected" ] || {
  echo 'candidate VM caller override was not preserved' >&2; exit 1;
}
echo 'test-dev-memory-contract PASS'
