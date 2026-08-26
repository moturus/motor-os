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
[ "$MOTOR_RUSTC" = "$TOOLCHAIN_PREFIX/bin/rustc" ] ||
	fail "assembly does not select the installed rustc"
[ "$MOTOR_RUSTDOC" = "$TOOLCHAIN_PREFIX/bin/rustdoc" ] ||
	fail "assembly does not select the installed rustdoc"
case "$(declare -f run_motor_cargo)" in
	*'RUSTC="$MOTOR_RUSTC" RUSTDOC="$MOTOR_RUSTDOC" "$MOTOR_CARGO"'*) ;;
	*) fail "assembly Cargo does not pin its compiler executables" ;;
esac
case "$(declare -f main)" in
	*'export RUSTUP_TOOLCHAIN="$MOTOR_RUSTUP_TOOLCHAIN"'*) ;;
	*) fail "later repository commands do not select the exact toolchain" ;;
esac
case "$(declare -f main)" in
	*'export PYTHONDONTWRITEBYTECODE=1'*\
*'export PYTHONPYCACHEPREFIX="$TOOLCHAIN_STATE_ROOT/python-cache"'*) ;;
	*) fail "assembly Python processes do not isolate bytecode" ;;
esac
case "$(declare -f build_shim)" in
	*'cargo +dev-x86_64-unknown-motor'*|*'src/sys/target'*)
		fail "shim still uses a legacy toolchain or target directory" ;;
esac
for producer in build_mlibc build_cxx_runtimes build_native_llvm; do
	case "$(declare -f "$producer")" in
		*'--wipe'*|*'rm -rf'*|*'$LLVM/build-'*)
			fail "$producer still wipes or uses source-relative build output" ;;
	esac
done
case "$(declare -f build_lua llvm_stage_image)" in
	*'rm -rf'*|*'$MOTORH/lua-$LUA_VER/src/lua'*|*'$LLVM/build-motor-native'*)
		fail "Lua or image staging still wipes or consumes unkeyed output" ;;
esac
case "$(declare -f rebuild_shim rustc_stage_image build_ripgrep build_images)" in
	*'cargo +dev-x86_64-unknown-motor'*|*'rm -rf'*|*'src/sys/target'*|*'build/native-toolchain'*)
		fail "later producers still wipe or consume legacy Cargo output" ;;
esac

echo "test-toolchain-keyed-paths PASS"
