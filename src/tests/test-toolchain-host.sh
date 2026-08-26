#!/usr/bin/env bash

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
for helper in versions lib sources bootstrap state runtime prefix llvm host; do
	. "$ROOT_DIR/src/toolchain-$helper.sh"
done
fail() { echo "test-toolchain-host: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
export MOTORH="$temporary/motorh"
rust="$temporary/rust"
mkdir -p "$rust/library" "$rust/src/llvm-project/llvm" "$temporary/local-moto"
printf 'root lock\n' > "$rust/Cargo.lock"
printf 'library lock\n' > "$rust/library/Cargo.lock"
git -C "$rust/src/llvm-project" init -q
git -C "$rust/src/llvm-project" config user.email test@example.com
git -C "$rust/src/llvm-project" config user.name Test
printf 'llvm\n' > "$rust/src/llvm-project/llvm/source"
git -C "$rust/src/llvm-project" add llvm/source
git -C "$rust/src/llvm-project" commit -qm llvm

MOTOR_SOURCE_MODE=managed
SELECTED_RUSTUP_TOOLCHAIN_BASE="$MOTOR_RUSTUP_TOOLCHAIN_BASE"
SELECTED_TOOLCHAIN_DESCRIPTION="$MOTOR_TOOLCHAIN_ID"
SELECTED_UPSTREAM_RUST_REV="$UPSTREAM_RUST_REV"
SELECTED_RUST_VERSION="$UPSTREAM_RUST_VERSION"
SELECTED_STAGE0_REV="$UPSTREAM_STAGE0_REV"
SELECTED_RUST_LLVM_BASE_REV="$RUST_LLVM_BASE_REV"
SELECTED_MOTOR_CARGO_VERSION="$MOTOR_CARGO_VERSION"
SELECTED_MOTOR_CARGO_REV="$MOTOR_CARGO_REV"
EFFECTIVE_MOTOR_RUST_REV="$MOTOR_RUST_REV"
EFFECTIVE_MOTOR_LLVM_REV="$(git -C "$rust/src/llvm-project" rev-parse HEAD)"
MOTOR_RUST_TREE_STATE=clean
MOTOR_LLVM_TREE_STATE=clean
AUTHORING_SOURCE_DIGEST=none
MOTOR_ASSEMBLY_STATE=clean

# Source and package equivalence have focused tests; this checks transaction
# ordering without manufacturing the complete Rust superproject and crate.
toolchain_reverify_selected_sources() { :; }
toolchain_verify_moto_rt_package() {
	LOCKED_MOTO_RT_VERSION="$STDLIB_MOTO_RT_VERSION"
	LOCKED_MOTO_RT_CHECKSUM="$STDLIB_MOTO_RT_CHECKSUM"
	MOTO_RT_PACKAGE_COMPARISON=exact
}
fake_cmake="$temporary/cmake"
printf '%s\n' '#!/usr/bin/env bash' \
	'while [ "$#" -gt 0 ]; do if [ "$1" = -B ]; then shift; mkdir -p "$1/bin"; fi; shift; done' > "$fake_cmake"
fake_ninja="$temporary/ninja"
cat > "$fake_ninja" <<EOF
#!/usr/bin/env bash
build="\$2"
for binary in clang clang++ ld.lld llvm-ar llvm-ranlib llvm-nm llvm-readelf llvm-strip llvm-objcopy llvm-config; do
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\\n" "$RUST_LLVM_VERSION"' > "\$build/bin/\$binary"
  chmod +x "\$build/bin/\$binary"
done
EOF
chmod +x "$fake_cmake" "$fake_ninja"
export MOTOR_CMAKE_COMMAND="$fake_cmake" MOTOR_NINJA_COMMAND="$fake_ninja"

cat > "$rust/x.py" <<EOF
#!/usr/bin/env bash
[ "\${PYTHONDONTWRITEBYTECODE:-}" = 1 ] || exit 8
printf x >> '$temporary/xpy-runs'
[ "\${FAIL_XPY:-0}" != 1 ] || exit 7
while [ "\$#" -gt 0 ]; do
  if [ "\$1" = --config ]; then shift; config="\$1"; fi
  shift
done
prefix="\$(sed -n 's/^prefix = "\(.*\)"/\1/p' "\$config")"
mkdir -p "\$prefix/bin" "\$prefix/lib/rustlib/src/rust/library"
for target in x86_64-unknown-linux-gnu x86_64-unknown-motor; do
  mkdir -p "\$prefix/lib/rustlib/\$target/lib"
  : > "\$prefix/lib/rustlib/\$target/lib/libcore-test.rlib"
  : > "\$prefix/lib/rustlib/\$target/lib/libstd-test.rlib"
done
cat > "\$prefix/bin/tool" <<'TOOL'
#!/usr/bin/env bash
case "\$(basename "\$0")" in
rustc)
  if [ "\${1:-}" = -vV ]; then printf '%s\\n' 'rustc ($MOTOR_TOOLCHAIN_ID)' 'commit-hash: $MOTOR_RUST_REV';
  elif [ "\${1:-}" = --print ]; then dirname "\$(dirname "\$0")";
  else while [ "\$#" -gt 0 ]; do if [ "\$1" = -o ]; then shift; : > "\$1"; fi; shift; done; fi ;;
cargo) printf '%s\\n' 'cargo' 'release: $MOTOR_CARGO_VERSION' 'commit-hash: $MOTOR_CARGO_REV' ;;
*) printf '%s\\n' version ;;
esac
TOOL
chmod +x "\$prefix/bin/tool"
for binary in rustc rustdoc cargo cargo-clippy clippy-driver cargo-fmt rustfmt; do ln -s tool "\$prefix/bin/\$binary"; done
EOF
chmod +x "$rust/x.py"

fake_rustup="$temporary/rustup"
cat > "$fake_rustup" <<'EOF'
#!/usr/bin/env bash
case "$1:$2" in
toolchain:list) [ ! -f "$RUSTUP_STATE" ] || head -1 "$RUSTUP_STATE" ;;
toolchain:link) printf '%s\n%s\n' "$3" "$4" > "$RUSTUP_STATE" ;;
which:*) [ -f "$RUSTUP_STATE" ] && printf '%s/bin/%s\n' "$(tail -1 "$RUSTUP_STATE")" "$2" ;;
run:*) [ -f "$RUSTUP_STATE" ] && "$(tail -1 "$RUSTUP_STATE")/bin/$3" "${@:4}" ;;
esac
EOF
chmod +x "$fake_rustup"
export RUSTUP_STATE="$temporary/rustup-state"

toolchain_build_selected_host "$rust" '' "$MOTORH/build" \
	"$fake_rustup" "$temporary/cargo-home" "$temporary/local-moto"
[ "$(cat "$temporary/xpy-runs")" = x ] || fail "bootstrap did not run exactly once"
[ -f "$TOOLCHAIN_PREFIX/MOTOR-TOOLCHAIN-MANIFEST" ] || fail "prefix was not finalized"
[ ! -e "$TOOLCHAIN_PREFIX.building" ] || fail "successful producer lock remains"
toolchain_build_selected_host "$rust" '' "$MOTORH/build" \
	"$fake_rustup" "$temporary/cargo-home" "$temporary/local-moto"
[ "$(cat "$temporary/xpy-runs")" = x ] || fail "valid prefix was rebuilt"

printf 'new starting lock\n' > "$rust/Cargo.lock"
export FAIL_XPY=1
if toolchain_build_selected_host "$rust" '' "$MOTORH/build" \
	"$fake_rustup" "$temporary/cargo-home" "$temporary/local-moto" 2>/dev/null; then
	fail "failed bootstrap was accepted"
fi
[ -f "$TOOLCHAIN_PREFIX/MOTOR-TOOLCHAIN-REJECTED" ] ||
	fail "failed bootstrap prefix was not rejected"
[ -d "$TOOLCHAIN_PREFIX.building" ] || fail "failed producer lock was discarded"
[ "$(head -1 "$RUSTUP_STATE")" != "$MOTOR_RUSTUP_TOOLCHAIN" ] ||
	fail "failed prefix was registered"

echo "test-toolchain-host PASS"
