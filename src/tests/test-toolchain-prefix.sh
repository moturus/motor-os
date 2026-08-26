#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-versions.sh"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-prefix.sh"

fail() { echo "test-toolchain-prefix: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
prefix="$temporary/prefix"
mkdir -p "$prefix/bin" "$prefix/lib/rustlib/src/rust/library"
for target in x86_64-unknown-linux-gnu x86_64-unknown-motor; do
	mkdir -p "$prefix/lib/rustlib/$target/lib"
	: > "$prefix/lib/rustlib/$target/lib/libcore-test.rlib"
	: > "$prefix/lib/rustlib/$target/lib/libstd-test.rlib"
done

EFFECTIVE_MOTOR_RUST_REV="$MOTOR_RUST_REV"
EFFECTIVE_MOTOR_LLVM_REV="$MOTOR_LLVM_REV"
SELECTED_MOTOR_CARGO_REV="$MOTOR_CARGO_REV"
SELECTED_TOOLCHAIN_DESCRIPTION="$MOTOR_TOOLCHAIN_ID"
fake_tool="$temporary/tool"
cat > "$fake_tool" <<EOF
#!/usr/bin/env bash
case "\$(basename "\$0")" in
rustc)
  if [ "\${1:-}" = -vV ]; then
    printf '%s\n' 'rustc 1.99.0-dev ($MOTOR_TOOLCHAIN_ID)' \
      'binary: rustc' 'commit-hash: $MOTOR_RUST_REV' \
      'host: x86_64-unknown-linux-gnu' 'release: 1.99.0-dev'
  elif [ "\${1:-}" = --print ] && [ "\${2:-}" = sysroot ]; then
    printf '%s\n' '$prefix'
  else
    while [ "\$#" -gt 0 ]; do
      if [ "\$1" = -o ]; then shift; : > "\$1"; fi
      shift
    done
  fi ;;
cargo) printf '%s\n' 'cargo 1.99.0-dev' 'release: 1.99.0' \
  'commit-hash: $MOTOR_CARGO_REV' ;;
*) printf '%s 1.99.0-dev\n' "\$(basename "\$0")" ;;
esac
EOF
chmod +x "$fake_tool"
for binary in rustc rustdoc cargo cargo-clippy clippy-driver cargo-fmt rustfmt; do
	ln -s "$fake_tool" "$prefix/bin/$binary"
done

MOTOR_TOOLCHAIN_KEY="$(printf key | sha256sum | awk '{print $1}')"
MOTOR_RUSTUP_TOOLCHAIN="$MOTOR_RUSTUP_TOOLCHAIN_BASE-$MOTOR_TOOLCHAIN_KEY"
MOTOR_SOURCE_MODE=managed
MOTOR_ASSEMBLY_STATE=clean
SELECTED_UPSTREAM_RUST_REV="$UPSTREAM_RUST_REV"
START_RUST_ROOT_LOCK_SHA256="$MOTOR_RUST_ROOT_LOCK_SHA256"
START_RUST_LIBRARY_LOCK_SHA256="$MOTOR_RUST_LIBRARY_LOCK_SHA256"
LOCKED_MOTO_RT_VERSION="$STDLIB_MOTO_RT_VERSION"
LOCKED_MOTO_RT_CHECKSUM="$STDLIB_MOTO_RT_CHECKSUM"
MOTO_RT_PACKAGE_COMPARISON=exact

toolchain_validate_prefix "$prefix"
toolchain_write_prefix_manifest "$prefix"
toolchain_validate_prefix_manifest "$prefix"
chmod u+w "$prefix/MOTOR-TOOLCHAIN-MANIFEST"
printf '\n# stale\n' >> "$prefix/MOTOR-TOOLCHAIN-MANIFEST"
if toolchain_validate_prefix_manifest "$prefix" 2>/dev/null; then
	fail "stale prefix manifest was accepted"
fi
sed -i '$d' "$prefix/MOTOR-TOOLCHAIN-MANIFEST"
sed -i '$d' "$prefix/MOTOR-TOOLCHAIN-MANIFEST"

fake_rustup="$temporary/rustup"
cat > "$fake_rustup" <<'EOF'
#!/usr/bin/env bash
case "$1" in
toolchain)
  case "$2" in
  list) [ ! -f "$RUSTUP_TEST_STATE" ] || printf '%s\n' "$MOTOR_RUSTUP_TOOLCHAIN" ;;
  link) printf '%s\n' "$4" > "$RUSTUP_TEST_STATE" ;;
  esac ;;
which)
  [ -f "$RUSTUP_TEST_STATE" ] || exit 1
  printf '%s/bin/%s\n' "$(cat "$RUSTUP_TEST_STATE")" "$2" ;;
run)
  [ -f "$RUSTUP_TEST_STATE" ] || exit 1
  "$(cat "$RUSTUP_TEST_STATE")/bin/$3" "${@:4}" ;;
esac
EOF
chmod +x "$fake_rustup"
export RUSTUP_TEST_STATE="$temporary/rustup-state" MOTOR_RUSTUP_TOOLCHAIN
toolchain_register_prefix "$fake_rustup" "$prefix"
toolchain_validate_rustup_link "$fake_rustup" "$prefix"

new_prefix="$temporary/new-prefix"
toolchain_claim_prefix "$new_prefix"
[ "$TOOLCHAIN_PREFIX_REUSED" = false ] && [ -d "$new_prefix.building" ] ||
	fail "new prefix was not exclusively claimed"
mkdir "$new_prefix"
toolchain_complete_prefix "$new_prefix"
toolchain_claim_prefix "$new_prefix"
[ "$TOOLCHAIN_PREFIX_REUSED" = true ] || fail "existing prefix was not selected for reuse"

touch "$prefix/MOTOR-TOOLCHAIN-REJECTED"
if toolchain_validate_prefix "$prefix" 2>/dev/null; then
	fail "rejected prefix was accepted"
fi

echo "test-toolchain-prefix PASS"
