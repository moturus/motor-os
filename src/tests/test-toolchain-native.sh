#!/usr/bin/env bash

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
for helper in versions lib sources bootstrap state assembly native; do
	. "$ROOT_DIR/src/toolchain-$helper.sh"
done
fail() { echo "test-toolchain-native: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
rust="$temporary/rust"
mkdir -p "$rust/library" "$temporary/prefix/bin" "$temporary/llvm/bin" \
	"$temporary/assembly/sysroot"
printf root > "$rust/Cargo.lock"
printf library > "$rust/library/Cargo.lock"
printf installed > "$temporary/prefix/bin/rustc"
chmod +x "$temporary/prefix/bin/rustc"
cat > "$temporary/llvm/bin/llvm-config" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> '$temporary/llvm-config-args'
case "\${1:-}" in
--bindir) printf '%s\n' '$temporary/llvm/bin' ;;
--cxxflags) printf '%s\n' '-I$temporary/llvm/include -DNDEBUG' ;;
--ldflags) printf '%s\n' '-L$temporary/llvm/lib' ;;
--fail) exit 23 ;;
*) printf '%s\n' '23.1.0' ;;
esac
EOF
printf '%s\n' '#!/bin/sh' 'exit 0' > "$temporary/llvm/bin/tool"
chmod +x "$temporary/llvm/bin/llvm-config" "$temporary/llvm/bin/tool"
ln -s tool "$temporary/llvm/bin/llvm-ar"
ln -s tool "$temporary/llvm/bin/llvm-ranlib"

MOTOR_SOURCE_MODE=managed
SELECTED_TOOLCHAIN_DESCRIPTION="$MOTOR_TOOLCHAIN_ID"
SELECTED_MOTOR_CARGO_REV="$MOTOR_CARGO_REV"
EFFECTIVE_MOTOR_RUST_REV="$MOTOR_RUST_REV"
EFFECTIVE_MOTOR_LLVM_REV="$MOTOR_LLVM_REV"
AUTHORING_SOURCE_DIGEST=none
TOOLCHAIN_PREFIX="$temporary/prefix"
TOOLCHAIN_STATE_ROOT="$temporary/state"
STANDALONE_LLVM_BIN="$temporary/llvm/bin"
ASSEMBLY_ROOT="$temporary/assembly"
ASSEMBLY_SYSROOT="$ASSEMBLY_ROOT/sysroot"
toolchain_capture_starting_locks "$rust"
toolchain_reverify_selected_sources() { :; }

cat > "$rust/x.py" <<EOF
#!/usr/bin/env bash
[ "\${PYTHONDONTWRITEBYTECODE:-}" = 1 ] || exit 8
[ "\${PYTHONPYCACHEPREFIX:-}" = '$TOOLCHAIN_STATE_ROOT/python-cache' ] || exit 9
binary='$rust/build/x86_64-unknown-linux-gnu/stage2-rustc/x86_64-unknown-motor/release/rustc-main'
mkdir -p "\$(dirname "\$binary")"
printf '%s\n' '$MOTOR_RUST_REV' '$MOTOR_TOOLCHAIN_ID' > "\$binary"
chmod +x "\$binary"
[ "\${MUTATE_PREFIX:-0}" != 1 ] || printf changed >> '$temporary/prefix/bin/rustc'
EOF
chmod +x "$rust/x.py"

toolchain_build_native_rustc "$rust" ''
toolchain_validate_native_rustc "$RUSTC_MAIN" || fail "native identity was rejected"
adapter="$ASSEMBLY_ROOT/native-llvm-config/bin/llvm-config"
target_llvm="$rust/build/x86_64-unknown-motor/llvm"
[ -x "$adapter" ] || fail "native llvm-config adapter is missing"
[ "$("$adapter" --bindir)" = "$temporary/llvm/bin" ] ||
	fail "native llvm-config adapter rewrote the host bindir"
[ "$("$adapter" --cxxflags)" = "-I$target_llvm/include -DNDEBUG" ] ||
	fail "native llvm-config adapter did not rewrite the include path"
[ "$("$adapter" --ldflags)" = "-L$target_llvm/lib" ] ||
	fail "native llvm-config adapter did not rewrite the library path"
[ "$("$adapter" --version)" = 23.1.0 ] ||
	fail "native llvm-config adapter changed non-path output"
set +e
"$adapter" --fail
status=$?
set -e
[ "$status" -eq 23 ] || fail "native llvm-config adapter hid a command failure"
[ "$(readlink "$ASSEMBLY_ROOT/native-llvm-config/bin/llvm-ar")" = \
	"$temporary/llvm/bin/llvm-ar" ] || fail "native llvm-ar link is wrong"
grep -Fqx 'llvm-config = "'"$ASSEMBLY_ROOT/native-llvm-config/bin/llvm-config"'"' \
	"$NATIVE_BOOTSTRAP_CONFIG" || fail "native bootstrap bypasses the adapter"
grep -Fqx -- '--cxxflags' "$temporary/llvm-config-args" ||
	fail "native llvm-config arguments were not forwarded"

ASSEMBLY_ROOT="$temporary/changed-assembly"
ASSEMBLY_SYSROOT="$ASSEMBLY_ROOT/sysroot"
mkdir -p "$ASSEMBLY_SYSROOT"
export MUTATE_PREFIX=1
if toolchain_build_native_rustc "$rust" '' 2>/dev/null; then
	fail "native bootstrap prefix mutation was accepted"
fi
[ -f "$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-REJECTED" ] ||
	fail "mutating native build did not reject its assembly"

echo "test-toolchain-native PASS"
