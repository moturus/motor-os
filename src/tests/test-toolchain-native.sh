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
