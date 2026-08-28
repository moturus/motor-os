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
while [ "$#" -gt 0 ]; do
  if [ "$1" = -B ]; then shift; mkdir -p "$1/bin"; fi
  shift
done
EOF
fake_ninja="$temporary/ninja"
cat > "$fake_ninja" <<EOF
#!/usr/bin/env bash
build="\$2"
shift 2
for binary in clang clang++ ld.lld llvm-ar llvm-ranlib llvm-nm \
  llvm-readelf llvm-strip llvm-objcopy llvm-config; do
  cat > "\$build/bin/\$binary" <<TOOL
#!/usr/bin/env bash
printf '%s\n' '$RUST_LLVM_VERSION'
TOOL
  chmod +x "\$build/bin/\$binary"
done
EOF
chmod +x "$fake_cmake" "$fake_ninja"
export MOTOR_CMAKE_COMMAND="$fake_cmake" MOTOR_NINJA_COMMAND="$fake_ninja"

root="$temporary/build"
toolchain_build_standalone_llvm "$llvm" "$root"
[ "$TOOLCHAIN_LLVM_REUSED" = false ] || fail "first LLVM build was marked reused"
first_build="$STANDALONE_LLVM_BUILD"
toolchain_build_standalone_llvm "$llvm" "$root"
[ "$TOOLCHAIN_LLVM_REUSED" = true ] || fail "exact LLVM build was not reused"
[ "$STANDALONE_LLVM_BUILD" = "$first_build" ] || fail "LLVM key is unstable"

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
