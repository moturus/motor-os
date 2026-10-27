#!/bin/bash
# Manually invoked host and Motor OS acceptance gate for Gears.
set -euo pipefail
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../../../.." && pwd)"
cd "$ROOT_DIR"
PROFILE=debug
PROFILE_ARGS=()
case "$*" in
  "") ;;
  --release) PROFILE=release; PROFILE_ARGS=(--release) ;;
  *) echo "usage: $0 [--release]" >&2; exit 2 ;;
esac
# External sources can carry their own rust-toolchain.toml.
export RUSTUP_TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"

echo "-- Gears host tests ($PROFILE) --"
"$TEST_DIR/test-gears-http.sh" "${PROFILE_ARGS[@]}"
"$TEST_DIR/test-gears-batteries.sh" "${PROFILE_ARGS[@]}"

echo "-- Gears Motor OS build ($PROFILE) --"
make -C "$ROOT_DIR" dev.img BUILD="$PROFILE" -j"$(nproc)"
CARGO_TARGET_DIR="$ROOT_DIR/build/obj/$PROFILE/gears" \
  cargo build --locked --offline --manifest-path src/bin/gears/Cargo.toml \
  --target x86_64-unknown-motor --examples "${PROFILE_ARGS[@]}"

# Retain the existing native-source phase's bounded runtime. The child owns
# the VM and tears it down on success, failure, or timeout.
timeout 1500s "$TEST_DIR/test-vm.sh" "${PROFILE_ARGS[@]}"
echo "gears full-test.sh ($PROFILE) ALL PASS"
