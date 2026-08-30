#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-versions.sh"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-bootstrap.sh"

fail() {
  echo "test-toolchain-versions: $*" >&2
  exit 1
}

toolchain_validate_versions
[ "$MOTOR_TOOLCHAIN_KEY_SCHEMA" = motor-toolchain-key-v2 ] ||
  fail "unexpected toolchain key schema"
[ "$MOTOR_ASSEMBLY_KEY_SCHEMA" = motor-assembly-key-v2 ] ||
  fail "unexpected assembly key schema"
expected_llvm_tools='llvm-cov llvm-nm llvm-objcopy llvm-objdump llvm-profdata llvm-readobj llvm-size llvm-strip llvm-ar llvm-as llvm-dis llvm-link llc opt'
[ "${MOTOR_RUST_BOOTSTRAP_LLVM_TOOLS[*]}" = "$expected_llvm_tools" ] ||
  fail "Rust bootstrap LLVM tool contract differs"

key="$(toolchain_clean_key)"
[[ "$key" =~ ^[0-9a-f]{64}$ ]] || fail "invalid clean key: $key"
[ "$key" = "$(toolchain_clean_key)" ] || fail "clean key is not deterministic"
[ "$(toolchain_clean_name)" = "$MOTOR_RUSTUP_TOOLCHAIN_BASE-$key" ] ||
  fail "rustup name does not contain the complete clean key"

original_cargo_rev="$MOTOR_CARGO_REV"
MOTOR_CARGO_REV="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[ "$key" != "$(toolchain_clean_key)" ] || fail "Cargo revision did not change the key"
MOTOR_CARGO_REV="$original_cargo_rev"

original_build_tools="$MOTOR_BUILD_TOOLS"
MOTOR_BUILD_TOOLS="cargo,clippy,rustdoc,rustfmt,src"
[ "$key" != "$(toolchain_clean_key)" ] || fail "build tools did not change the key"
MOTOR_BUILD_TOOLS="$original_build_tools"

original_assertions="$MOTOR_STANDALONE_LLVM_ASSERTIONS"
MOTOR_STANDALONE_LLVM_ASSERTIONS=ON
[ "$key" != "$(toolchain_clean_key)" ] ||
  fail "standalone LLVM configuration did not change the key"
MOTOR_STANDALONE_LLVM_ASSERTIONS="$original_assertions"

[ "$(toolchain_hash_pairs a bc)" != "$(toolchain_hash_pairs ab c)" ] ||
  fail "field boundaries are ambiguous"
newline_value=$'first\nsecond:third'
[ "$(toolchain_hash_pairs value "$newline_value")" = \
  "$(toolchain_hash_pairs value "$newline_value")" ] ||
  fail "embedded newlines are not deterministic"

if toolchain_can_publish_stable; then
  fail "beta tuple authorized stable publication"
fi
MOTOR_TOOLCHAIN_MATURITY=stable
UPSTREAM_RUST_REF=refs/tags/1.99.0
MOTOR_TOOLCHAIN_ID=1.99.0-motor.1
toolchain_can_publish_stable || fail "well-formed stable tuple was rejected"

echo "test-toolchain-versions PASS"
