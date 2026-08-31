#!/usr/bin/env bash

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-versions.sh"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-sources.sh"
. "$ROOT_DIR/src/toolchain-llvm.sh"
fail() { echo "test-toolchain-llvm: $*" >&2; exit 1; }

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
llvm="$temporary/llvm"
mkdir -p "$llvm/llvm"
git -C "$llvm" init -q
git -C "$llvm" config user.email test@example.com
git -C "$llvm" config user.name Test
printf 'source\n' > "$llvm/llvm/source"
git -C "$llvm" add llvm/source
git -C "$llvm" commit -qm source
EFFECTIVE_MOTOR_LLVM_REV="$(git -C "$llvm" rev-parse HEAD)"
MOTOR_LLVM_TREE_STATE=clean

fake_cmake="$temporary/cmake"
cat > "$fake_cmake" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$LLVM_TEST_CMAKE_ARGS"
while [ "$#" -gt 0 ]; do
  if [ "$1" = -B ]; then shift; mkdir -p "$1/bin"; fi
  shift
done
EOF
fake_ninja="$temporary/ninja"
cat > "$fake_ninja" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$LLVM_TEST_NINJA_ARGS"
build="$2"
shift 2
for target in "$@"; do
  case "$target" in
  clang) binaries='clang clang++' ;;
  lld) binaries='lld ld.lld' ;;
  llvm-libraries) continue ;;
  *) binaries="$target" ;;
  esac
  for binary in $binaries; do
    cat > "$build/bin/$binary" <<TOOL
#!/usr/bin/env bash
printf '%s\n' '$RUST_LLVM_VERSION'
TOOL
    chmod +x "$build/bin/$binary"
  done
done
mkdir -p "$build/lib"
: > "$build/lib/libLLVM-test.a"
cat > "$build/bin/llvm-config" <<TOOL
#!/usr/bin/env bash
case "\${1:-}:\${2:-}" in
--version:) printf '%s\n' '$RUST_LLVM_VERSION' ;;
--link-static:--libfiles) printf '%s\n' '$build/lib/libLLVM-test.a' ;;
*) exit 2 ;;
esac
TOOL
chmod +x "$build/bin/llvm-config"
EOF
chmod +x "$fake_cmake" "$fake_ninja"
export RUST_LLVM_VERSION
export MOTOR_CMAKE_COMMAND="$fake_cmake" MOTOR_NINJA_COMMAND="$fake_ninja"
export LLVM_TEST_CMAKE_ARGS="$temporary/cmake-args"
export LLVM_TEST_NINJA_ARGS="$temporary/ninja-args"

root="$temporary/build"
toolchain_build_standalone_llvm "$llvm" "$root"
[ "$TOOLCHAIN_LLVM_REUSED" = false ] || fail "first LLVM build was marked reused"
first_build="$STANDALONE_LLVM_BUILD"
expected_cmake="$temporary/expected-cmake-args"
printf '%s\n' -S "$llvm/llvm" -B "$first_build" \
	-G "$MOTOR_STANDALONE_LLVM_GENERATOR" \
	-DCMAKE_BUILD_TYPE="$MOTOR_STANDALONE_LLVM_BUILD_TYPE" \
	-DLLVM_ENABLE_ASSERTIONS="$MOTOR_STANDALONE_LLVM_ASSERTIONS" \
	-DLLVM_ENABLE_PROJECTS="$MOTOR_STANDALONE_LLVM_PROJECTS" \
	-DLLVM_TARGETS_TO_BUILD="$MOTOR_LLVM_TARGETS" \
	-DLLVM_INCLUDE_TESTS="$MOTOR_STANDALONE_LLVM_INCLUDE_TESTS" \
	-DCMAKE_C_COMPILER="$MOTOR_STANDALONE_LLVM_C_COMPILER" \
	-DCMAKE_CXX_COMPILER="$MOTOR_STANDALONE_LLVM_CXX_COMPILER" > "$expected_cmake"
cmp -s "$expected_cmake" "$LLVM_TEST_CMAKE_ARGS" ||
	fail "CMake did not receive the declared standalone LLVM configuration"
expected_ninja="$temporary/expected-ninja-args"
printf '%s\n' -C "$first_build" \
	"${MOTOR_STANDALONE_LLVM_NINJA_TARGETS[@]}" > "$expected_ninja"
cmp -s "$expected_ninja" "$LLVM_TEST_NINJA_ARGS" ||
	fail "Ninja did not receive the declared standalone LLVM targets"

static_library="$first_build/lib/libLLVM-test.a"
mv "$static_library" "$temporary/libLLVM-test.a"
if toolchain_validate_standalone_llvm "$first_build" 2>/dev/null; then
	fail "LLVM installation without a reported static library was accepted"
fi
mv "$temporary/libLLVM-test.a" "$static_library"

toolchain_build_standalone_llvm "$llvm" "$root"
[ "$TOOLCHAIN_LLVM_REUSED" = true ] || fail "exact LLVM build was not reused"
[ "$STANDALONE_LLVM_BUILD" = "$first_build" ] || fail "LLVM key is unstable"

original_assertions="$MOTOR_STANDALONE_LLVM_ASSERTIONS"
MOTOR_STANDALONE_LLVM_ASSERTIONS=ON
[ "$(toolchain_standalone_llvm_key)" != "$STANDALONE_LLVM_KEY" ] ||
	fail "standalone LLVM configuration did not re-key its build"
MOTOR_STANDALONE_LLVM_ASSERTIONS="$original_assertions"

printf 'author edit\n' >> "$llvm/llvm/source"
MOTOR_LLVM_TREE_STATE="$(toolchain_worktree_digest "$llvm" llvm)"
toolchain_build_standalone_llvm "$llvm" "$root"
[ "$STANDALONE_LLVM_BUILD" != "$first_build" ] || fail "LLVM edit did not select a new key"

blocked_root="$temporary/blocked"
blocked_key="$(toolchain_standalone_llvm_key)"
mkdir -p "$blocked_root/standalone-llvm/$blocked_key.building"
if toolchain_build_standalone_llvm "$llvm" "$blocked_root" 2>/dev/null; then
	fail "abandoned LLVM producer lock was ignored"
fi

echo "test-toolchain-llvm PASS"
