#!/usr/bin/env bash

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/build-motor-os.sh"
fail() { echo "test-toolchain-keyed-paths: $*" >&2; exit 1; }

MOTORH=/tmp/motor-toolchain-path-test
STANDALONE_LLVM_BIN="$MOTORH/llvm/bin"
TOOLCHAIN_PREFIX="$MOTORH/toolchains/key"
ASSEMBLY_ROOT="$MOTORH/assemblies/key"
ASSEMBLY_SYSROOT="$ASSEMBLY_ROOT/sysroot"
ASSEMBLY_BUILD_ROOT="$ASSEMBLY_ROOT/build"
ASSEMBLY_IMAGE_ROOT="$ASSEMBLY_ROOT/images"
activate_exact_assembly_paths

[ "$B" = "$STANDALONE_LLVM_BIN" ] || fail "standalone LLVM was not selected"
[ "$SYSROOT" = "$ASSEMBLY_ROOT/sysroot" ] || fail "sysroot is not assembly-keyed"
[ "$SHIM_TARGET_DIR" = "$ASSEMBLY_ROOT/build/moto-rt-cabi" ] ||
	fail "shim Cargo output is not assembly-keyed"
[ "$MOTOR_CARGO" = "$TOOLCHAIN_PREFIX/bin/cargo" ] ||
	fail "shim does not select the installed Cargo"
case "$(declare -f build_shim)" in
	*'cargo +dev-x86_64-unknown-motor'*|*'src/sys/target'*)
		fail "shim still uses a legacy toolchain or target directory" ;;
esac

echo "test-toolchain-keyed-paths PASS"
