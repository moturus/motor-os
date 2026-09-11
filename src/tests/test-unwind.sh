#!/usr/bin/env bash
# Build against the installed Motor sysroot and run in an already booted VM.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
for helper in versions lib native llvm; do
  . "$ROOT_DIR/src/toolchain-$helper.sh"
done
manifest="$ROOT_DIR/src/tests/unwind/Cargo.toml"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
cargo="$(rustup which cargo)"
target="$temporary/target"
common=(--locked --offline --target x86_64-unknown-motor
  --manifest-path "$manifest" --target-dir "$target")

"$cargo" build "${common[@]}" --release
"$cargo" build "${common[@]}" --profile release-lto
"$cargo" build "${common[@]}" --profile release-abort -vv \
  > "$temporary/abort-build.log" 2>&1
grep -F -- '-C panic=abort' "$temporary/abort-build.log" >/dev/null || {
  cat "$temporary/abort-build.log" >&2
  echo 'test-unwind: abort profile did not pass -C panic=abort' >&2
  exit 1
}

development_root="$(readlink -f "${MOTORH:-$ROOT_DIR/..}")"
EFFECTIVE_MOTOR_LLVM_REV="$MOTOR_LLVM_REV"
MOTOR_LLVM_TREE_STATE=clean
standalone_key="$(toolchain_standalone_llvm_key)"
elf_tools="$development_root/build/toolchain/standalone-llvm/$standalone_key/bin"
for profile in release release-lto release-abort; do
  binary="$target/x86_64-unknown-motor/$profile/motor-unwind-test"
  toolchain_validate_native_elf "$binary" "$elf_tools/llvm-readelf" "$binary" || {
    echo "test-unwind: $profile ELF validation failed" >&2
    exit 1
  }
done

runner="$ROOT_DIR/src/tests/test-rust-analyzer-crates.sh"
failures=0
run_guest() {
  local label="$1" binary="$2" command="$3" status=0
  "$runner" --run-motor "$binary" "$command" || status="$?"
  if [ "$status" -eq 0 ]; then
    echo "test-unwind: $label PASS"
  else
    echo "test-unwind: $label FAIL (status $status)" >&2
    failures=$((failures + 1))
  fi
}

run_guest abort "$target/x86_64-unknown-motor/release-abort/motor-unwind-test" abort-suite
run_guest release "$target/x86_64-unknown-motor/release/motor-unwind-test" suite
run_guest lto "$target/x86_64-unknown-motor/release-lto/motor-unwind-test" suite
[ "$failures" -eq 0 ] || exit 1
echo 'test-unwind PASS'
