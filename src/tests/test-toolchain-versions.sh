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
[ "$MOTOR_TOOLCHAIN_KEY_SCHEMA" = motor-toolchain-key-v4 ] ||
  fail "unexpected toolchain key schema"
[ "$MOTOR_ASSEMBLY_KEY_SCHEMA" = motor-assembly-key-v6 ] ||
  fail "unexpected assembly key schema"
# Userspace add-ons are no part of the toolchain declaration.
for name in HELIX_REPOSITORY HELIX_REF HELIX_REV MOTOR_LUA_VERSION \
  LOCAL_MOTO_RT_VERSION LOCAL_MOTO_SYS_VERSION; do
  [ -z "${!name:-}" ] || fail "$name is declared as a toolchain input"
done
expected_llvm_tools='llvm-cov llvm-nm llvm-objcopy llvm-objdump llvm-profdata llvm-readobj llvm-size llvm-strip llvm-ar llvm-as llvm-dis llvm-link llc opt'
[ "${MOTOR_RUST_BOOTSTRAP_LLVM_TOOLS[*]}" = "$expected_llvm_tools" ] ||
  fail "Rust bootstrap LLVM tool contract differs"

key="$(toolchain_clean_key)"
[[ "$key" =~ ^[0-9a-f]{64}$ ]] || fail "invalid clean key: $key"
[ "$key" = "$(toolchain_clean_key)" ] || fail "clean key is not deterministic"
[ "$(toolchain_clean_name)" = "$MOTOR_RUSTUP_TOOLCHAIN_BASE-$key" ] ||
  fail "rustup name does not contain the complete clean key"

# The key names what is compiled, how, and where it installs.
for name in MOTOR_RUST_REV MOTOR_LLVM_REV MOTOR_TOOLCHAIN_ID MOTOR_RUSTUP_TOOLCHAIN_BASE \
  MOTOR_RUST_CHANNEL; do
  original="${!name}"
  printf -v "$name" '%s' "${original%?}x"
  [ "$key" != "$(toolchain_clean_key)" ] || fail "$name did not change the key"
  printf -v "$name" '%s' "$original"
done
# Values that follow from the Rust commit, and plain labels, are no key input.
for name in UPSTREAM_RUST_VERSION UPSTREAM_RUST_REV UPSTREAM_STAGE0_REV RUST_LLVM_BASE_REV \
  MOTOR_CARGO_VERSION MOTOR_CARGO_REV UPSTREAM_CARGO_REV MOTOR_RUST_ROOT_LOCK_SHA256 \
  MOTOR_RUST_LIBRARY_LOCK_SHA256 MOTOR_RUST_ANALYZER_LOCK_SHA256 MOTOR_TOOLCHAIN_MATURITY; do
  original="${!name}"
  printf -v "$name" '%s' "${original%?}x"
  [ "$key" = "$(toolchain_clean_key)" ] || fail "$name is a redundant key input"
  printf -v "$name" '%s' "$original"
done
for name in MOTOR_BUILD_HOST MOTOR_BUILD_TARGETS MOTOR_BUILD_TOOLS MOTOR_BUILD_EXTENDED \
  MOTOR_BUILD_DOCS MOTOR_BUILD_SUBMODULES MOTOR_BUILD_LOCKED_DEPS \
  MOTOR_OPTIMIZED_COMPILER_BUILTINS MOTOR_DOWNLOAD_CI_LLVM MOTOR_OMIT_GIT_HASH; do
  [ -z "${!name:-}" ] || fail "$name is declared but configures nothing"
done

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
