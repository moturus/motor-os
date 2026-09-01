#!/bin/bash
#
# Native compiler and packaged-source acceptance gate for the developer image.
# Non-Lorry work runs this gate only with --release. If that work necessarily
# changes src/bin/lorry, a debug run requires an explicit user decision.

if [ "${TEST_DEV_SOURCES_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export TEST_DEV_SOURCES_TIMEOUT_ACTIVE=1
  set -m
  timeout 1500s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "test-dev-sources: timed out after 1500 seconds" >&2
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
export MOTO_IMAGE=motor-os-dev.qcow2
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-4096}"
NATIVE_FIXTURE_DIR=/devtools/tmp/native-tests
NATIVE_FIXTURES=(native-fstat.c native-temp.c native-temp.cpp)
LORRY_VENDOR_ENV="TMPDIR=/devtools/tmp"
if [ "$BUILD" = debug ]; then
  LORRY_VENDOR_ENV="$LORRY_VENDOR_ENV LORRY_CURL_STDERR_SPILL_LIMIT_BYTES=104857600"
fi

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
SCP_OPTIONS=(
  -F /dev/null
  -P 2222
  -o IdentitiesOnly=yes
  -o BatchMode=yes
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key"
)
SCP=(scp "${SCP_OPTIONS[@]}")

vm_ssh() {
  "${SSH[@]}" "$@"
}

expect_guest_mode() {
  local directory="$1"
  local name="$2"
  local expected="$3"
  local description="$4"
  local listing

  listing="$(vm_ssh "/system/bin/ls -l $directory")" ||
    fail "cannot inspect $description"
  if ! printf '%s\n' "$listing" | awk -v name="$name" -v expected="$expected" '
    $NF == name { found = 1; if ($1 != expected) exit 1 }
    END { if (!found) exit 1 }
  '; then
    fail "$description does not have mode $expected: $listing"
  fi
}

expect_nested_guest_mode() {
  local root="$1"
  local name="$2"
  local expected="$3"
  local description="$4"
  local paths path directory listing

  paths="$(vm_ssh "/system/bin/find $root -type f -name $name")" ||
    fail "cannot find $description"
  [ -n "$paths" ] || fail "no $description was produced"
  while IFS= read -r path; do
    directory="${path%/*}"
    listing="$(vm_ssh "/system/bin/ls -l $directory")" ||
      fail "cannot inspect $description at $path"
    if printf '%s\n' "$listing" |
      awk -v name="$name" -v expected="$expected" '$NF == name && $1 == expected { found = 1 } END { exit !found }'; then
      continue
    fi
    fail "$description does not have mode $expected: $listing"
  done <<< "$paths"
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
  motor@192.168.4.2 /system/bin/rush -c true > /dev/null; do
  if ! kill -0 "$VMM_PID" 2>/dev/null; then
    fail "QEMU exited before SSH became ready (log: $CONSOLE_LOG)"
  fi
  sleep 1
done

echo "-- Developer source trees --"
for package in red lorry; do
  vm_ssh "[ -f /devtools/src/motor-os/bin/$package/Cargo.toml ]" ||
    fail "developer image is missing /devtools/src/motor-os/bin/$package/Cargo.toml"
  vm_ssh "[ ! -d /devtools/src/motor-os/bin/$package/target ]" ||
    fail "developer image contains /devtools/src/motor-os/bin/$package/target"
  vm_ssh "[ ! -d /devtools/src/motor-os/bin/$package/.lorry/vendor ]" ||
    fail "developer image contains materialized dependencies for $package"
done
vm_ssh "[ ! -e /devtools/src/motor-os/bin/curl ]" ||
  fail "developer image exposes curl as a Motor-native source project"
for package in moto-rt moto-sys; do
  vm_ssh "[ -f /devtools/src/motor-os/sys/lib/$package/Cargo.toml ]" ||
    fail "developer image is missing /devtools/src/motor-os/sys/lib/$package/Cargo.toml"
done
for source in "${NATIVE_FIXTURES[@]}"; do
  vm_ssh "[ ! -e /devtools/src/$source ]" ||
    fail "developer image contains test-only source /devtools/src/$source"
done
vm_ssh "[ -f /devtools/lorry/vendor/repository.toml ]" ||
  fail "developer image is missing the writable Lorry repository"
vm_ssh "[ -d /devtools/lorry/cache ]" ||
  fail "developer image is missing the Lorry cache directory"
vm_ssh "[ ! -e /user/cfg/lorry ]" ||
  fail "developer image still contains the old Lorry state directory"
vm_ssh "[ -z \"\$(/system/bin/find /devtools/lorry/vendor/objects -type f)\" ]" ||
  fail "developer image contains preinstalled Lorry dependency objects"
vm_ssh "[ -f /devtools/lorry/readme.txt ]" ||
  fail "developer image is missing /devtools/lorry/readme.txt"
expect_guest_mode /devtools lorry drwxrwx--- "Lorry state directory"
expect_guest_mode /devtools/lorry vendor drwxrwx--- "Lorry repository directory"
expect_guest_mode /devtools/lorry cache drwxrwx--- "Lorry cache directory"
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
vm_ssh "[ ! -e $NATIVE_FIXTURE_DIR ] || /system/bin/rm -r $NATIVE_FIXTURE_DIR" ||
  fail "cannot clear the native-fixture upload directory"
vm_ssh "/system/bin/mkdir $NATIVE_FIXTURE_DIR" ||
  fail "cannot create the native-fixture upload directory"
for source in "${NATIVE_FIXTURES[@]}"; do
  [ -f "$ROOT_DIR/src/sys/tests/$source" ] ||
    fail "host checkout is missing src/sys/tests/$source"
  "${SCP[@]}" "$ROOT_DIR/src/sys/tests/$source" \
    "motor@192.168.4.2:$NATIVE_FIXTURE_DIR/$source" ||
    fail "cannot upload src/sys/tests/$source"
done
vm_ssh "/devtools/bin/cc $NATIVE_FIXTURE_DIR/native-fstat.c -o /devtools/tmp/native-fstat"
vm_ssh "/devtools/bin/cc /devtools/src/hello-world/hello.c -o /devtools/tmp/hello-c"
expect_guest_mode /devtools/tmp native-fstat -rwxr-xr-- "freshly linked native-fstat"
expect_guest_mode /devtools/tmp hello-c -rwxr-xr-- "freshly linked hello-c"
vm_ssh /devtools/tmp/hello-c
vm_ssh "/devtools/bin/c++ /devtools/src/hello-world/hello.cpp -o /devtools/tmp/hello-cpp"
vm_ssh /devtools/tmp/hello-cpp
vm_ssh "/devtools/bin/rustc /devtools/src/hello-world/hello.rs -o /devtools/tmp/hello-rust"
vm_ssh /devtools/tmp/hello-rust
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
vm_ssh "/devtools/bin/cc $NATIVE_FIXTURE_DIR/native-temp.c -o /devtools/tmp/native-temp"
[ "$(vm_ssh /devtools/tmp/native-temp)" = "native-temp PASS" ] ||
  fail "native libc PATH, shell, or temporary-directory contract failed"
vm_ssh "/devtools/bin/c++ $NATIVE_FIXTURE_DIR/native-temp.cpp -o /devtools/tmp/native-temp-cpp"
[ "$(vm_ssh /devtools/tmp/native-temp-cpp)" = "native-temp-cpp PASS" ] ||
  fail "native libc++ temporary-directory contract failed"
vm_ssh "/system/bin/rm -r $NATIVE_FIXTURE_DIR"

rust_temp='use std::env; fn main() { println!("{}", env::temp_dir().display()); }'
printf '%s\n' "$rust_temp" | vm_ssh "/system/bin/rush -c 'cat >/devtools/tmp/temp-contract.rs'"
vm_ssh "/devtools/bin/rustc /devtools/tmp/temp-contract.rs -o /devtools/tmp/temp-contract"
[ "$(vm_ssh "/system/bin/rush -c 'unset TMPDIR; /devtools/tmp/temp-contract'")" = /user/tmp ] ||
  fail "Rust std did not use the Motor temp fallback"
[ "$(vm_ssh "TMPDIR=/devtools/tmp /devtools/tmp/temp-contract")" = /devtools/tmp ] ||
  fail "Rust std ignored explicit TMPDIR"

# Build trees are scratch. Remove each one after its boundary check so later
# independent builds retain enough room for their own outputs.
for package in red; do
  vm_ssh "cd /devtools/src/motor-os/bin/$package && $LORRY_VENDOR_ENV /devtools/bin/lorry vendor --accept-all" ||
    fail "developer image cannot vendor /devtools/src/motor-os/bin/$package"
  vm_ssh "cd /devtools/src/motor-os/bin/$package && TMPDIR=/devtools/tmp /devtools/bin/lorry build" ||
    fail "developer image cannot natively build /devtools/src/$package"
  expect_nested_guest_mode "/devtools/src/motor-os/bin/$package/target/lorry/debug/build" \
    build-script-build -rwxr-xr-- "Cargo-uplifted $package build scripts"
  vm_ssh "/system/bin/rm -r /devtools/src/motor-os/bin/$package/target"
done
vm_ssh "[ -n \"\$(/system/bin/find /devtools/lorry/vendor/objects -type f)\" ]" ||
  fail "Lorry did not populate /devtools/lorry/vendor"
vm_ssh "[ -n \"\$(/system/bin/find /devtools/lorry/cache -type f)\" ]" ||
  fail "Lorry did not populate /devtools/lorry/cache"
vm_ssh "[ ! -e /user/cfg/lorry ]" ||
  fail "Lorry recreated its old state directory"
vm_ssh "cd /devtools/src/motor-os/bin/lorry && $LORRY_VENDOR_ENV /devtools/bin/lorry vendor --accept-all" ||
  fail "developer image cannot vendor /devtools/src/motor-os/bin/lorry"
vm_ssh "cd /devtools/src/motor-os/bin/lorry && TMPDIR=/devtools/tmp /devtools/bin/lorry build" ||
  fail "developer image cannot natively build /devtools/src/lorry"
vm_ssh "/system/bin/cp /devtools/src/motor-os/bin/lorry/target/lorry/debug/lorry /devtools/tmp/native-lorry"
vm_ssh "/system/bin/rm -r /devtools/src/motor-os/bin/lorry/target"

stop_vm "$VMM_PID"
VMM_PID=""
echo "-------- TEST-DEV-SOURCES PASS ---------"
