#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-versions.sh"
. "$ROOT_DIR/src/toolchain-lib.sh"

fail() {
  echo "test-toolchain-versions: $*" >&2
  exit 1
}

toolchain_validate_versions

key="$(toolchain_clean_key)"
[[ "$key" =~ ^[0-9a-f]{64}$ ]] || fail "invalid clean key: $key"
[ "$key" = "$(toolchain_clean_key)" ] || fail "clean key is not deterministic"
[ "$(toolchain_clean_name)" = "$MOTOR_RUSTUP_TOOLCHAIN_BASE-$key" ] ||
  fail "rustup name does not contain the complete clean key"

original_cargo_rev="$MOTOR_CARGO_REV"
MOTOR_CARGO_REV="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[ "$key" != "$(toolchain_clean_key)" ] || fail "Cargo revision did not change the key"
MOTOR_CARGO_REV="$original_cargo_rev"

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
