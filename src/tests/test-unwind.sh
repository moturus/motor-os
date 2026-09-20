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
common=(--locked --offline --target x86_64-unknown-motor
  --manifest-path "$manifest")

development_root="$(readlink -f "${MOTORH:-$ROOT_DIR/..}")"
EFFECTIVE_MOTOR_LLVM_REV="$MOTOR_LLVM_REV"
MOTOR_LLVM_TREE_STATE=clean
standalone_key="$(toolchain_standalone_llvm_key)"
elf_tools="$development_root/build/toolchain/standalone-llvm/$standalone_key/bin"
assembly_images="$("$ROOT_DIR/src/resolve-toolchain-assembly.sh" --resolve)"
assembly_root="${assembly_images%/images}"
assembly_sysroot="$assembly_root/sysroot"

pure_target="$temporary/pure"
c_target="$temporary/c-runtime"
c_environment=(
  "MOTOR_TEST_CXX=$assembly_sysroot/bin/motor-clang++"
  "MOTOR_TEST_AR=$elf_tools/llvm-ar"
  "MOTOR_TEST_CXX_LIB=$assembly_sysroot/devtools/llvm/lib"
  "CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER=$assembly_sysroot/bin/motor-clang"
  "CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS=-C link-self-contained=no -C default-linker-libraries=yes"
)

build_pure() {
  "$cargo" build "${common[@]}" --target-dir "$pure_target" "$@"
}

build_c_runtime() {
  env "${c_environment[@]}" "$cargo" build "${common[@]}" \
    --target-dir "$c_target" --features cxx "$@"
}

for mode in pure c-runtime; do
  if [ "$mode" = pure ]; then
    build=build_pure
  else
    build=build_c_runtime
  fi
  "$build" --release
  "$build" --profile release-lto
  "$build" --profile release-abort -vv > "$temporary/$mode-abort-build.log" 2>&1
  grep -F -- '-C panic=abort' "$temporary/$mode-abort-build.log" >/dev/null || {
    cat "$temporary/$mode-abort-build.log" >&2
    echo "test-unwind: $mode abort profile did not pass -C panic=abort" >&2
    exit 1
  }
done

for mode_target in "pure:$pure_target" "c-runtime:$c_target"; do
  mode="${mode_target%%:*}"
  target="${mode_target#*:}"
  for profile in release release-lto release-abort; do
    binary="$target/x86_64-unknown-motor/$profile/motor-unwind-test"
    unstripped="$binary"
    if [ "$mode:$profile" = pure:release-abort ]; then
      unstripped=
    fi
    toolchain_validate_native_elf "$binary" "$elf_tools/llvm-readelf" "$unstripped" || {
      echo "test-unwind: $mode $profile ELF validation failed" >&2
      exit 1
    }
  done
done

ssh_options=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$ROOT_DIR/src/tests/test-known-hosts"
  -i "$ROOT_DIR/src/tests/test.key")
guest_dir="${MOTOR_TEST_ROOT:-/devtools}/tmp"
failures=0
run_guest() {
  local label="$1" binary="$2" command="$3" status=0
  local guest="$guest_dir/motor-unwind-$label-$$"
  printf 'put "%s" "%s"\nchmod 755 "%s"\n' "$binary" "$guest" "$guest" |
    sftp "${ssh_options[@]}" -P 2222 -b - motor@192.168.4.2
  ssh "${ssh_options[@]}" -p 2222 motor@192.168.4.2 "$guest" "$command" || status="$?"
  ssh "${ssh_options[@]}" -p 2222 motor@192.168.4.2 /system/bin/rm "$guest"
  if [ "$status" -eq 0 ]; then
    echo "test-unwind: $label PASS"
  else
    echo "test-unwind: $label FAIL (status $status)" >&2
    failures=$((failures + 1))
  fi
}

run_guest pure-abort \
  "$pure_target/x86_64-unknown-motor/release-abort/motor-unwind-test" abort-suite
run_guest c-runtime-abort \
  "$c_target/x86_64-unknown-motor/release-abort/motor-unwind-test" abort-suite
for profile in release release-lto; do
  run_guest "pure-$profile" \
    "$pure_target/x86_64-unknown-motor/$profile/motor-unwind-test" suite
  run_guest "c-runtime-$profile" \
    "$c_target/x86_64-unknown-motor/$profile/motor-unwind-test" suite
  if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = 1 ]; then
    run_guest "cxx-$profile" \
      "$c_target/x86_64-unknown-motor/$profile/motor-unwind-test" cxx-suite
  fi
done

if [ "${FULL_TEST_VERIFY_DEV_SOURCES:-0}" = 1 ]; then
  guest_source="/devtools/tmp/motor-unwind-test-$$.rs"
  guest_binary="/devtools/tmp/motor-unwind-native-$$"
  downloaded="$temporary/motor-unwind-native"
  printf 'put "%s" "%s"\n' "$ROOT_DIR/src/tests/unwind/src/main.rs" "$guest_source" |
    sftp "${ssh_options[@]}" -P 2222 -b - motor@192.168.4.2
  ssh "${ssh_options[@]}" -p 2222 motor@192.168.4.2 \
    /devtools/bin/rustc --edition=2024 -O "$guest_source" -o "$guest_binary"
  printf 'get "%s" "%s"\n' "$guest_binary" "$downloaded" |
    sftp "${ssh_options[@]}" -P 2222 -b - motor@192.168.4.2
  toolchain_validate_native_elf "$downloaded" "$elf_tools/llvm-readelf" "$downloaded"
  ssh "${ssh_options[@]}" -p 2222 motor@192.168.4.2 "$guest_binary" suite
  ssh "${ssh_options[@]}" -p 2222 motor@192.168.4.2 /system/bin/rm "$guest_source"
  ssh "${ssh_options[@]}" -p 2222 motor@192.168.4.2 /system/bin/rm "$guest_binary"
  echo 'test-unwind: native compilation PASS'
fi
[ "$failures" -eq 0 ] || exit 1
echo 'test-unwind PASS'
