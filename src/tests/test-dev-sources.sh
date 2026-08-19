#!/bin/bash
#
# Native compiler and packaged-source acceptance gate for the developer image.

if [ "${TEST_DEV_SOURCES_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export TEST_DEV_SOURCES_TIMEOUT_ACTIVE=1
  set -m
  timeout 900s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "test-dev-sources: timed out after 900 seconds" >&2
  fi
  exit "$status"
fi

set -euo pipefail

WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
BUILD=debug
if [ "${1:-}" = "--release" ]; then
  BUILD=release
fi
IMG_DIR="$ROOT_DIR/vm_images/$BUILD"
export MOTO_IMAGE=motor-os-dev.img
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-4096}"

if [ "${FULL_TEST_IMAGE_PREBUILT:-0}" != "1" ]; then
  if [ "$BUILD" = release ]; then
    make -C "$ROOT_DIR" dev.img BUILD=release -j"$(nproc)"
  else
    make -C "$ROOT_DIR" dev.img -j"$(nproc)"
  fi
fi

chmod 600 "$WD/test.key"
SSH_OPTIONS=(
  -F /dev/null
  -p 2222
  -o IdentitiesOnly=yes
  -o BatchMode=yes
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key"
)
SSH=(ssh "${SSH_OPTIONS[@]}" motor@192.168.4.2)

vm_ssh() {
  "${SSH[@]}" "$@"
}

. "$WD/vm-cleanup.sh"

fail() {
  echo "test-dev-sources: $*" >&2
  exit 1
}

CONSOLE_LOG=/tmp/test-dev-sources.log
VMM_PID=""
cleanup() {
  set +e
  stop_vm "$VMM_PID"
  VMM_PID=""
}
trap cleanup EXIT

echo "test-dev-sources: starting a $BUILD developer VM; console log in $CONSOLE_LOG"
"$IMG_DIR/run-qemu.sh" > "$CONSOLE_LOG" 2>&1 &
VMM_PID="$!"
until ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=5 -o ConnectionAttempts=1 \
  motor@192.168.4.2 /system/bin/echo " " > /dev/null; do
  if ! kill -0 "$VMM_PID" 2>/dev/null; then
    fail "QEMU exited before SSH became ready (log: $CONSOLE_LOG)"
  fi
  sleep 1
done

echo "-- Developer source trees --"
for package in red lorry gears; do
  vm_ssh "[ -f /devtools/src/src/bin/$package/Cargo.toml ]" ||
    fail "developer image is missing /devtools/src/src/bin/$package/Cargo.toml"
  vm_ssh "[ ! -d /devtools/src/src/bin/$package/target ]" ||
    fail "developer image contains /devtools/src/src/bin/$package/target"
  vm_ssh "[ ! -d /devtools/src/src/bin/$package/.lorry/vendor ]" ||
    fail "developer image contains materialized dependencies for $package"
done
vm_ssh "[ ! -e /devtools/src/src/bin/curl ]" ||
  fail "developer image exposes curl as a Motor-native source project"
for package in moto-rt moto-sys; do
  vm_ssh "[ -f /devtools/src/src/sys/lib/$package/Cargo.toml ]" ||
    fail "developer image is missing /devtools/src/src/sys/lib/$package/Cargo.toml"
done
vm_ssh "[ ! -e /devtools/lorry/vendor ]" ||
  fail "developer image still contains a Lorry system seed"
vm_ssh "[ -r /system/cfg/ssl/ca-certificates.crt ]" ||
  fail "developer image is missing the public CA trust bundle"
vm_ssh "[ -f /user/cfg/lorry.toml ]" ||
  fail "developer image is missing the writable-repository configuration"

cc_version="$(vm_ssh /devtools/bin/cc --version 2>&1)" ||
  fail "native cc --version failed: $cc_version"
case "$cc_version" in
  *"clang version"*) ;;
  *) fail "native cc --version returned unexpected output: $cc_version" ;;
esac
vm_ssh "/devtools/bin/cc /devtools/src/hello.c -o /devtools/tmp/hello-c"
vm_ssh /devtools/tmp/hello-c
vm_ssh "/devtools/bin/c++ /devtools/src/hello.cpp -o /devtools/tmp/hello-cpp"
vm_ssh /devtools/tmp/hello-cpp
vm_ssh "/devtools/bin/rustc /devtools/src/hello.rs -o /devtools/tmp/hello-rust"
vm_ssh /devtools/tmp/hello-rust
vm_ssh "/devtools/bin/cc /devtools/src/native-fstat.c -o /devtools/tmp/native-fstat"
[ "$(vm_ssh /devtools/tmp/native-fstat)" = "native-fstat PASS" ] ||
  fail "native non-PTY fstat fixture failed"
pty_fstat="$(ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
  /devtools/tmp/native-fstat pty 2>&1)" ||
  fail "native PTY fstat fixture failed: $pty_fstat"
case "$pty_fstat" in
  *"native-fstat PASS"*) ;;
  *) fail "native PTY fstat fixture returned unexpected output: $pty_fstat" ;;
esac
if bad_cc="$(vm_ssh /devtools/bin/cc --definitely-invalid-motor-test-option 2>&1)"; then
  fail "native cc accepted an intentionally invalid option"
fi
case "$bad_cc" in
  *"error:"*) ;;
  *) fail "native cc failure lost its diagnostic: $bad_cc" ;;
esac
vm_ssh "/devtools/bin/cc /devtools/src/native-temp.c -o /devtools/tmp/native-temp"
[ "$(vm_ssh /devtools/tmp/native-temp)" = "native-temp PASS" ] ||
  fail "native libc PATH, shell, or temporary-directory contract failed"
vm_ssh "/devtools/bin/c++ /devtools/src/native-temp.cpp -o /devtools/tmp/native-temp-cpp"
[ "$(vm_ssh /devtools/tmp/native-temp-cpp)" = "native-temp-cpp PASS" ] ||
  fail "native libc++ temporary-directory contract failed"

rust_temp='use std::env; fn main() { println!("{}", env::temp_dir().display()); }'
printf '%s\n' "$rust_temp" | vm_ssh "/system/bin/rush -c 'cat >/devtools/tmp/temp-contract.rs'"
vm_ssh "/devtools/bin/rustc /devtools/tmp/temp-contract.rs -o /devtools/tmp/temp-contract"
[ "$(vm_ssh "/system/bin/rush -c 'unset TMPDIR; /devtools/tmp/temp-contract'")" = /user/tmp ] ||
  fail "Rust std did not use the Motor temp fallback"
[ "$(vm_ssh "TMPDIR=/devtools/tmp /devtools/tmp/temp-contract")" = /devtools/tmp ] ||
  fail "Rust std ignored explicit TMPDIR"

# Build trees are scratch. Retaining all four at once exhausts the deliberately
# bounded 2 GiB developer image before the second independent Gears build.
for package in red; do
  vm_ssh "cd /devtools/src/src/bin/$package && TMPDIR=/devtools/tmp /devtools/bin/lorry vendor --accept-all" ||
    fail "developer image cannot vendor /devtools/src/src/bin/$package"
  vm_ssh "cd /devtools/src/src/bin/$package && TMPDIR=/devtools/tmp /devtools/bin/lorry build" ||
    fail "developer image cannot natively build /devtools/src/$package"
  vm_ssh "/system/bin/rm -r /devtools/src/src/bin/$package/target"
done
vm_ssh "cd /devtools/src/src/bin/lorry && TMPDIR=/devtools/tmp /devtools/bin/lorry vendor --accept-all" ||
  fail "developer image cannot vendor /devtools/src/src/bin/lorry"
vm_ssh "cd /devtools/src/src/bin/lorry && TMPDIR=/devtools/tmp /devtools/bin/lorry build" ||
  fail "developer image cannot natively build /devtools/src/lorry"
vm_ssh "/system/bin/cp /devtools/src/src/bin/lorry/target/lorry/debug/lorry /devtools/tmp/native-lorry"
vm_ssh "/system/bin/rm -r /devtools/src/src/bin/lorry/target"
vm_ssh "cd /devtools/src/src/bin/gears && TMPDIR=/devtools/tmp /devtools/bin/lorry vendor --accept-all" ||
  fail "developer image cannot vendor /devtools/src/src/bin/gears"
vm_ssh "cd /devtools/src/src/bin/gears && TMPDIR=/devtools/tmp /devtools/bin/lorry build" ||
  fail "developer image cannot natively build /devtools/src/gears"
vm_ssh "/system/bin/rm -r /devtools/src/src/bin/gears/target"
vm_ssh "cd /devtools/src/src/bin/gears && TMPDIR=/devtools/tmp /devtools/tmp/native-lorry build" ||
  fail "the natively built Lorry cannot rebuild Gears"

stop_vm "$VMM_PID"
VMM_PID=""
echo "-------- TEST-DEV-SOURCES PASS ---------"
