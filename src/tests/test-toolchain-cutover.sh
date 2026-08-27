#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-versions.sh"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-bootstrap.sh"

fail() {
  echo "test-toolchain-cutover: $*" >&2
  exit 1
}

expected_name="$(toolchain_clean_name)"
selected_name="$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' \
  "$ROOT_DIR/rust-toolchain.toml")"
[ "$selected_name" = "$expected_name" ] || fail "root selector does not match clean tuple"

sysroot="$(cd "$ROOT_DIR" && rustc --print sysroot)"
stamp="$sysroot/lib/rustlib/MOTOR-TOOLCHAIN-KEY"
[ -f "$stamp" ] || fail "selected sysroot has no key stamp"
[ "$(cat "$stamp")" = "$(toolchain_clean_key)" ] || fail "selected sysroot has wrong key"
[ "$(readlink -f "$(rustup which rustc --toolchain "$selected_name")")" = \
  "$(readlink -f "$sysroot/bin/rustc")" ] ||
  fail "rustup resolves a different rustc"
[ "$(readlink -f "$(rustup which cargo --toolchain "$selected_name")")" = \
  "$(readlink -f "$sysroot/bin/cargo")" ] ||
  fail "rustup resolves a different Cargo"
(cd "$ROOT_DIR" && cargo -Vv) | grep -Fqx "commit-hash: $MOTOR_CARGO_REV" ||
  fail "root override selected the wrong Cargo"

make_debug="$(make -n -C "$ROOT_DIR" sys-init)"
case "$make_debug" in
  *"build/obj/$(toolchain_clean_key)/debug/sys-init"*) ;;
  *) fail "debug Cargo output is not keyed by the selected toolchain" ;;
esac
make_release="$(make -n -C "$ROOT_DIR" sys-init BUILD=release)"
case "$make_release" in
  *"build/obj/$(toolchain_clean_key)/release/sys-init"*) ;;
  *) fail "release Cargo output is not keyed by the selected toolchain" ;;
esac

for path in Makefile src/boot/x64.mbr/build.sh src/boot/x64.boot/build.sh \
  src/boot/x64.kloader/build.sh src/sys/lib/rt.vdso/build.sh \
  src/bin/curl/build-motor.sh; do
  ! grep -Fq 'cargo +dev-x86_64-unknown-motor' "$ROOT_DIR/$path" ||
    fail "$path still selects the legacy toolchain"
done
! grep -Fq 'cargo +nightly' "$ROOT_DIR/src/tests/full-test.sh" ||
  fail "full-test.sh still selects ambient nightly"
! grep -Fq 'cargo +nightly' "$ROOT_DIR/src/tests/full-test-networking.sh" ||
  fail "full-test-networking.sh still selects ambient nightly"
for target in src/boot/x64.kloader/kloader.json src/sys/kernel/kernel.json; do
  ! grep -Fq 'x86-softfloat' "$ROOT_DIR/$target" ||
    fail "$target still uses the removed Rust ABI alias"
  (cd "$ROOT_DIR" && rustc -Zunstable-options --print cfg --target "$target") >/dev/null ||
    fail "$target is rejected by the selected rustc"
done

echo "test-toolchain-cutover PASS"
