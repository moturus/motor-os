#!/bin/bash
# Exercise argument handling without building an image or starting a VM.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/src/tests" "$scratch/bin" \
  "$scratch/src/bin/httpd-axum/tests" "$scratch/src/bin/lorry/tests"
cp "$WD/full-test.sh" "$WD/full-test-dev.sh" "$scratch/src/tests/"
export MOTO_SIZE_TEST_LOG="$scratch/calls"
unset MOTO_SMP MOTO_MEMORY_MIB FULL_TEST_TIMEOUT_ACTIVE FULL_TEST_VERIFY_DEV_SOURCES

for tool in qemu-system-x86_64 cloud-hypervisor-static firecracker; do
  printf '#!/bin/sh\nexit 0\n' > "$scratch/bin/$tool"
  chmod +x "$scratch/bin/$tool"
done
export PATH="$scratch/bin:$PATH"
cat > "$scratch/src/tests/full-test-prepare.sh" <<'SH'
#!/bin/bash
printf '%s:%s:%s\n' "$MOTO_SMP" "$MOTO_MEMORY_MIB" "$*" > "$MOTO_SIZE_TEST_LOG"
exit 73
SH
chmod +x "$scratch/src/tests/full-test-prepare.sh"

invalid() {
  local status=0
  "$@" > "$scratch/error" 2>&1 || status=$?
  [ "$status" = 2 ] || { cat "$scratch/error"; echo "accepted invalid size: $*"; exit 1; }
}
for runner in full-test.sh full-test-dev.sh; do
  for value in '' 0 01 -1 abc; do
    invalid env MOTO_SMP="$value" "$scratch/src/tests/$runner" --release
    invalid env MOTO_MEMORY_MIB="$value" "$scratch/src/tests/$runner" --release
    invalid "$scratch/src/tests/$runner" --release --cpus "$value"
    invalid "$scratch/src/tests/$runner" --release --memory="$value"
  done
  invalid "$scratch/src/tests/$runner" --release --cpus
  invalid "$scratch/src/tests/$runner" --release --memory
  invalid "$scratch/src/tests/$runner" --release --cpus 1 --cpus=2
  invalid "$scratch/src/tests/$runner" --release --memory 256 --memory=512
done

prepared() {
  local expected="$1" status=0
  shift
  "$@" > "$scratch/output" 2>&1 || status=$?
  [ "$status" = 73 ] && [ "$(cat "$MOTO_SIZE_TEST_LOG")" = "$expected" ] || {
    cat "$scratch/output"; echo "incorrect main-image size: $*"; exit 1;
  }
}
prepared '4:1024:release qemu' "$scratch/src/tests/full-test.sh" --release
prepared '2:256:release qemu' env MOTO_SMP=2 MOTO_MEMORY_MIB=256 \
  "$scratch/src/tests/full-test.sh" --release
prepared '1:128:release qemu' env MOTO_SMP=bad MOTO_MEMORY_MIB=bad \
  "$scratch/src/tests/full-test.sh" --release --cpus=1 --memory 128

# Replace phase runners with recorders. The wrapper must consume size options
# and forward only arguments understood by these existing component interfaces.
: > "$scratch/src/tests/test-dev-path-locks.py"
for runner in src/tests/full-test.sh src/tests/test-dev-sources.sh \
  src/bin/httpd-axum/tests/run.sh; do
  cat > "$scratch/$runner" <<'SH'
#!/bin/bash
printf '%s:%s:%s\n' "$MOTO_SMP" "$MOTO_MEMORY_MIB" "$*" >> "$MOTO_SIZE_TEST_LOG"
SH
  chmod +x "$scratch/$runner"
done
printf '#!/bin/sh\nexit 0\n' > "$scratch/src/bin/lorry/tests/test-all.sh"
chmod +x "$scratch/src/bin/lorry/tests/test-all.sh"
developer() {
  local cpus="$1" repository_memory="$2" source_memory="$3"
  shift 3
  : > "$MOTO_SIZE_TEST_LOG"
  "$@" > "$scratch/output" 2>&1 || { cat "$scratch/output"; exit 1; }
  printf '%s\n' "$cpus:$repository_memory:--release --vmm qemu" \
    "$cpus:$source_memory:--motor --release --vmm qemu" \
    "$cpus:$source_memory:--release --vmm qemu" > "$scratch/expected"
  diff -u "$scratch/expected" "$MOTO_SIZE_TEST_LOG"
}
developer 4 8192 4096 "$scratch/src/tests/full-test-dev.sh" --release --vmm=qemu
developer 2 512 512 env MOTO_SMP=2 MOTO_MEMORY_MIB=512 \
  "$scratch/src/tests/full-test-dev.sh" --release --vmm qemu
developer 1 256 256 env MOTO_SMP=bad MOTO_MEMORY_MIB=bad \
  "$scratch/src/tests/full-test-dev.sh" --release --cpus 1 --memory=256 --vmm qemu
echo 'full-test size options PASS'
