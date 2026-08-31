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
STANDALONE_LLVM_BIN="$temporary/llvm/bin"
mkdir -p "$STANDALONE_LLVM_BIN"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$STANDALONE_LLVM_BIN/lld"
chmod +x "$STANDALONE_LLVM_BIN/lld"
for target in x86_64-unknown-linux-gnu x86_64-unknown-motor; do
	mkdir -p "$prefix/lib/rustlib/$target/lib"
	: > "$prefix/lib/rustlib/$target/lib/libcore-test.rlib"
	: > "$prefix/lib/rustlib/$target/lib/libstd-test.rlib"
done

EFFECTIVE_MOTOR_RUST_REV="$MOTOR_RUST_REV"
EFFECTIVE_MOTOR_LLVM_REV="$MOTOR_LLVM_REV"
SELECTED_MOTOR_CARGO_REV="$MOTOR_CARGO_REV"
SELECTED_MOTOR_CARGO_VERSION="$MOTOR_CARGO_VERSION"
SELECTED_TOOLCHAIN_DESCRIPTION="$MOTOR_TOOLCHAIN_ID"
SELECTED_RUST_VERSION="$UPSTREAM_RUST_VERSION"
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
cargo) printf '%s\n' 'cargo 1.99.0-dev' 'release: 1.99.0-dev' \
  'commit-hash: $MOTOR_CARGO_REV' ;;
rust-analyzer) printf '%s\n' 'rust-analyzer 1.99.0-dev (${MOTOR_RUST_REV:0:9} 2026-08-30)' ;;
rust-analyzer-proc-macro-srv)
  [ "\${RUST_ANALYZER_INTERNALS_DO_NOT_USE:-}" = 'this is unstable' ] || exit 9
  printf '%s\n' 'rust-analyzer-proc-macro-srv 1.99.0-dev (${MOTOR_RUST_REV:0:9} 2026-08-30)' ;;
*) printf '%s 1.99.0-dev\n' "\$(basename "\$0")" ;;
esac
EOF
chmod +x "$fake_tool"
for binary in rustc rustdoc cargo cargo-clippy clippy-driver cargo-fmt rustfmt \
	rust-analyzer; do
	ln -s "$fake_tool" "$prefix/bin/$binary"
done
mkdir -p "$prefix/libexec"
ln "$fake_tool" "$prefix/libexec/rust-analyzer-proc-macro-srv"
toolchain_stage_rust_lld "$prefix" "$STANDALONE_LLVM_BIN"

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
STANDALONE_LLVM_CONFIG_DIGEST="$(toolchain_standalone_llvm_config_digest)"

if toolchain_validate_rust_analyzer_version \
	"rust-analyzer 1.98.0-dev (${MOTOR_RUST_REV:0:9} 2026-08-30)" \
	rust-analyzer 2>/dev/null; then
	fail "rust-analyzer with the wrong release was accepted"
fi
if toolchain_validate_rust_analyzer_version \
	"rust-analyzer 1.99.0-dev (aaaaaaaaa 2026-08-30)" \
	rust-analyzer 2>/dev/null; then
	fail "rust-analyzer with the wrong commit was accepted"
fi
mv "$prefix/bin/rust-analyzer" "$temporary/rust-analyzer"
if toolchain_validate_prefix "$prefix" 2>/dev/null; then
	fail "prefix without rust-analyzer was accepted"
fi
mv "$temporary/rust-analyzer" "$prefix/bin/rust-analyzer"
mv "$prefix/libexec/rust-analyzer-proc-macro-srv" "$temporary/proc-macro-srv"
if toolchain_validate_prefix "$prefix" 2>/dev/null; then
	fail "prefix without the proc-macro server was accepted"
fi
mv "$temporary/proc-macro-srv" "$prefix/libexec/rust-analyzer-proc-macro-srv"
rust_lld="$prefix/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
mv "$rust_lld" "$temporary/rust-lld"
if toolchain_validate_prefix "$prefix" 2>/dev/null; then
	fail "prefix without rust-lld was accepted"
fi
mv "$temporary/rust-lld" "$rust_lld"
printf changed >> "$rust_lld"
if toolchain_validate_prefix "$prefix" 2>/dev/null; then
	fail "prefix with a changed rust-lld was accepted"
fi
cp "$STANDALONE_LLVM_BIN/lld" "$rust_lld"
chmod +x "$rust_lld"

toolchain_validate_prefix "$prefix"
toolchain_write_prefix_manifest "$prefix"
toolchain_validate_prefix_manifest "$prefix"
[ "$(cat "$prefix/lib/rustlib/MOTOR-TOOLCHAIN-KEY")" = "$MOTOR_TOOLCHAIN_KEY" ] ||
	fail "prefix key stamp is missing"
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
  if [ "${RUSTUP_TEST_WRONG_BINARY:-}" = "$2" ]; then
    printf '%s\n' "$RUSTUP_TEST_WRONG_PATH"
    exit
  fi
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
wrong_rust_analyzer="$temporary/wrong-rust-analyzer"
ln "$fake_tool" "$wrong_rust_analyzer"
if RUSTUP_TEST_WRONG_BINARY=rust-analyzer \
	RUSTUP_TEST_WRONG_PATH="$wrong_rust_analyzer" \
	toolchain_validate_rustup_link "$fake_rustup" "$prefix" 2>/dev/null; then
	fail "rustup resolving rust-analyzer outside the prefix was accepted"
fi

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
