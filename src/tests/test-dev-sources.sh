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
VMM=qemu
SEEN_RELEASE=0
SEEN_VMM=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      [ "$SEEN_RELEASE" = 0 ] || { echo "test-dev-sources: duplicate --release" >&2; exit 2; }
      BUILD=release
      SEEN_RELEASE=1
      shift
      ;;
    --vmm)
      [ "$SEEN_VMM" = 0 ] || { echo "test-dev-sources: duplicate --vmm" >&2; exit 2; }
      [ "$#" -ge 2 ] || { echo "test-dev-sources: --vmm requires qemu or chv" >&2; exit 2; }
      VMM="$2"
      SEEN_VMM=1
      shift 2
      ;;
    --vmm=*)
      [ "$SEEN_VMM" = 0 ] || { echo "test-dev-sources: duplicate --vmm" >&2; exit 2; }
      VMM="${1#--vmm=}"
      SEEN_VMM=1
      shift
      ;;
    *) echo "usage: $0 [--release] [--vmm qemu|chv]" >&2; exit 2 ;;
  esac
done
case "$VMM" in
  qemu|chv) ;;
  fc) echo "test-dev-sources: Firecracker does not support developer images" >&2; exit 2 ;;
  *) echo "test-dev-sources: unsupported VMM '$VMM'" >&2; exit 2 ;;
esac
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-selection.sh"
select_test_vm "$ROOT_DIR" "$BUILD" developer "$VMM"
export MOTO_IMAGE="$TEST_VM_IMAGE"
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-4096}"
VM_RUNTIME_DIR="$(mktemp -d "${TMPDIR:-/tmp}/test-dev-sources-runtime.XXXXXX")"
export MOTO_CHV_RUNTIME_DIR="$VM_RUNTIME_DIR/chv"
DEV_TMP=/user/tmp/dev-sources
NATIVE_FIXTURE_DIR="$DEV_TMP/native-tests"
NATIVE_FIXTURES=(native-fstat.c native-temp.c native-temp.cpp)
SYS_LIB=/devtools/src/motor-os/sys/lib
SYS_LIB_CRATES=(moto-rt moto-sys moto-mpmc moto-async moto-ipc)
LORRY_VENDOR_ENV=""
if [ "$BUILD" = debug ]; then
  LORRY_VENDOR_ENV="LORRY_CURL_STDERR_SPILL_LIMIT_BYTES=104857600"
fi

if [ "${FULL_TEST_IMAGE_PREBUILT:-0}" != "1" ]; then
  if [ "$BUILD" = release ]; then
    make -C "$ROOT_DIR" "$TEST_VM_IMG_TARGET" BUILD=release -j"$(nproc)"
  else
    make -C "$ROOT_DIR" "$TEST_VM_IMG_TARGET" -j"$(nproc)"
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

count_guest_files() {
  local listing
  listing="$(vm_ssh "/system/bin/find $1 -type f")" || fail "cannot list $1"
  awk 'NF { files++ } END { print files + 0 }' <<< "$listing"
}

# The #[test] functions of a staged source file, named as libtest reports them.
source_tests() {
  local tests
  tests="$(awk -v prefix="$2" '
    /#\[test\]/ { test = 1; next }
    test && match($0, /fn [a-z0-9_]+\(/) {
      print prefix substr($0, RSTART + 3, RLENGTH - 4)
      test = 0
    }' "$ROOT_DIR/src/sys/lib/$1")"
  [ -n "$tests" ] || fail "found no tests in src/sys/lib/$1"
  printf '%s\n' "$tests"
}

# The native test may compile only the staged sources, plus the build scripts
# of dependencies, which Lorry never caches. Every test of the three crates
# must pass. Lorry reports on stderr; the harnesses' results arrive on stdout,
# not in step with it.
check_native_tests() {
  local progress="$1" results="$2" compiled passed expected missing
  compiled="$(awk -v staged=" ($SYS_LIB/" '
    /^Compiling / && index($0, staged) == 0 && !/ \[build script\]$/' "$progress")"
  [ -z "$compiled" ] && ! grep -q '^Rebuilding global dependency cache$' "$progress" ||
    fail "native lorry test compiled dependencies that make dev.img prepared: $compiled"
  passed="$(awk '/^test .* \.\.\. ok$/ { print $2 }' "$results")"
  expected="$(source_tests moto-mpmc/tests/fallible.rs ''
    source_tests moto-async/tests/fallible.rs ''
    source_tests moto-async/src/timeq.rs timeq::
    source_tests moto-ipc/src/stdio_pipe.rs stdio_pipe::tests::)" ||
    fail "cannot list the tests of $SYS_LIB"
  # comm matches each line once, so a name both fallible harnesses use must
  # pass twice.
  missing="$(LC_ALL=C comm -23 <(LC_ALL=C sort <<< "$expected") \
    <(LC_ALL=C sort <<< "$passed"))"
  [ -z "$missing" ] || fail "native tests did not pass: $(tr '\n' ' ' <<< "$missing")"
}

. "$WD/vm-test-boot-check.sh"

fail() {
  echo "test-dev-sources: $*" >&2
  exit 1
}

CONSOLE_LOG=/tmp/test-dev-sources.log
runner_args=()
if [ "$VMM" = qemu ] && [ -n "${FULL_TEST_QEMU_ARGS:-}" ]; then
  # Keep the suite's existing QEMU-only argument splitting.
  runner_args+=(${FULL_TEST_QEMU_ARGS})
fi
VMM_PID=""
cleanup() {
  local status=$?
  set +e
  trap - EXIT
  if [ -n "$VMM_PID" ]; then
    stop_test_vm_owned "$VMM" "$TEST_VM_LABEL" || {
      [ "$status" -ne 0 ] || status=1
    }
  fi
  exit "$status"
}
trap cleanup EXIT

echo "test-dev-sources: runner=$TEST_VM_RUNNER profile=$TEST_VM_PROFILE image=$MOTO_IMAGE"
echo "test-dev-sources: console log in $CONSOLE_LOG; runtime in $VM_RUNTIME_DIR"
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG" \
  "${runner_args[@]}"

echo "-- Developer source trees --"
for package in red gears lorry; do
  vm_ssh "[ -f /devtools/src/motor-os/bin/$package/Cargo.toml ]" ||
    fail "developer image is missing /devtools/src/motor-os/bin/$package/Cargo.toml"
  vm_ssh "[ ! -d /devtools/src/motor-os/bin/$package/target ]" ||
    fail "developer image contains /devtools/src/motor-os/bin/$package/target"
  vm_ssh "[ ! -d /devtools/src/motor-os/bin/$package/.lorry/vendor ]" ||
    fail "developer image contains materialized dependencies for $package"
done
vm_ssh "[ ! -e /devtools/src/motor-os/bin/curl ]" ||
  fail "developer image exposes curl as a Motor-native source project"
# make dev.img admitted the staged library sources, compiled their
# dependencies, and removed the build tree (src/prepare-dev-image.sh).
for crate in "${SYS_LIB_CRATES[@]}"; do
  vm_ssh "[ -f $SYS_LIB/$crate/Cargo.toml ]" ||
    fail "developer image is missing $SYS_LIB/$crate/Cargo.toml"
done
for file in Cargo.toml Cargo.lock .lorry/dependencies-v2.toml; do
  vm_ssh "[ -f $SYS_LIB/$file ]" || fail "developer image is missing $SYS_LIB/$file"
done
vm_ssh "[ ! -e $SYS_LIB/target ]" || fail "developer image contains $SYS_LIB/target"
for source in "${NATIVE_FIXTURES[@]}"; do
  vm_ssh "[ ! -e /devtools/src/$source ]" ||
    fail "developer image contains test-only source /devtools/src/$source"
done
for role in user none; do
  vm_ssh "[ -f /devtools/lorry/$role/vendor/repository.toml ]" ||
    fail "developer image is missing the writable $role Lorry repository"
  vm_ssh "[ -d /devtools/lorry/$role/cache ]" ||
    fail "developer image is missing the $role Lorry cache directory"
done
# Only the Interactive role holds the library sources' dependencies.
vm_ssh "[ -z \"\$(/system/bin/find /devtools/lorry/none/vendor/objects -type f)\" ]" ||
  fail "developer image contains preinstalled none Lorry dependency objects"
user_objects="$(count_guest_files /devtools/lorry/user/vendor/objects)"
user_cache_files="$(count_guest_files /devtools/lorry/user/cache)"
[ "$user_objects" -gt 0 ] || fail "developer image lacks the dependencies of $SYS_LIB"
[ "$user_cache_files" -gt 0 ] ||
  fail "developer image lacks the compiled dependencies of $SYS_LIB"
vm_ssh "[ ! -e /user/cfg/lorry ]" ||
  fail "developer image still contains the old Lorry state directory"
vm_ssh "[ -f /devtools/lorry/readme.txt ]" ||
  fail "developer image is missing /devtools/lorry/readme.txt"
expect_guest_mode /devtools lorry drwxr-xr-x "Lorry state directory"
expect_guest_mode /devtools/lorry user drwxrwx--- "Interactive Lorry state"
expect_guest_mode /devtools/lorry none drwxrwxrwx "None Lorry state"
expect_guest_mode /devtools/lorry/user vendor drwxrwx--- "Interactive Lorry repository"
expect_guest_mode /devtools/lorry/user cache drwxrwx--- "Interactive Lorry cache"
vm_ssh "[ -r /system/cfg/ssl/ca-certificates.crt ]" ||
  fail "developer image is missing the public CA trust bundle"
for config in /user/cfg/lorry.toml /none/cfg/lorry.toml; do
  vm_ssh "[ -f $config ]" || fail "developer image is missing $config"
done

cc_version="$(vm_ssh /devtools/bin/cc --version 2>&1)" ||
  fail "native cc --version failed: $cc_version"
case "$cc_version" in
  *"clang version"*) ;;
  *) fail "native cc --version returned unexpected output: $cc_version" ;;
esac
vm_ssh "[ ! -e $DEV_TMP ] || /system/bin/rm -r $DEV_TMP" ||
  fail "cannot clear $DEV_TMP"
vm_ssh "/system/bin/mkdir $DEV_TMP && /system/bin/mkdir $NATIVE_FIXTURE_DIR" ||
  fail "cannot create the native-fixture upload directory"
for source in "${NATIVE_FIXTURES[@]}"; do
  [ -f "$ROOT_DIR/src/sys/tests/$source" ] ||
    fail "host checkout is missing src/sys/tests/$source"
  "${SCP[@]}" "$ROOT_DIR/src/sys/tests/$source" \
    "motor@192.168.4.2:$NATIVE_FIXTURE_DIR/$source" ||
    fail "cannot upload src/sys/tests/$source"
done
vm_ssh "/devtools/bin/cc $NATIVE_FIXTURE_DIR/native-fstat.c -o $DEV_TMP/native-fstat"
vm_ssh "/devtools/bin/cc /devtools/src/hello-world/hello.c -o $DEV_TMP/hello-c"
expect_guest_mode $DEV_TMP native-fstat -rwxr-xr-- "freshly linked native-fstat"
expect_guest_mode $DEV_TMP hello-c -rwxr-xr-- "freshly linked hello-c"
vm_ssh $DEV_TMP/hello-c
vm_ssh "/devtools/bin/c++ /devtools/src/hello-world/hello.cpp -o $DEV_TMP/hello-cpp"
vm_ssh $DEV_TMP/hello-cpp
vm_ssh "/devtools/bin/rustc /devtools/src/hello-world/hello.rs -o $DEV_TMP/hello-rust"
vm_ssh $DEV_TMP/hello-rust
[ "$(vm_ssh $DEV_TMP/native-fstat)" = "native-fstat PASS" ] ||
  fail "native non-PTY fstat fixture failed"
pty_fstat="$(ssh "${SSH_OPTIONS[@]}" -tt motor@192.168.4.2 \
  $DEV_TMP/native-fstat pty 2>&1)" ||
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
vm_ssh "/devtools/bin/cc $NATIVE_FIXTURE_DIR/native-temp.c -o $DEV_TMP/native-temp"
[ "$(vm_ssh $DEV_TMP/native-temp)" = "native-temp PASS" ] ||
  fail "native libc PATH, shell, or temporary-directory contract failed"
vm_ssh "/devtools/bin/c++ $NATIVE_FIXTURE_DIR/native-temp.cpp -o $DEV_TMP/native-temp-cpp"
[ "$(vm_ssh $DEV_TMP/native-temp-cpp)" = "native-temp-cpp PASS" ] ||
  fail "native libc++ temporary-directory contract failed"
vm_ssh "/system/bin/rm -r $NATIVE_FIXTURE_DIR"

rust_temp='use std::env; fn main() { println!("{}", env::temp_dir().display()); }'
printf '%s\n' "$rust_temp" | vm_ssh "/system/bin/rush -c 'cat >$DEV_TMP/temp-contract.rs'"
vm_ssh "/devtools/bin/rustc $DEV_TMP/temp-contract.rs -o $DEV_TMP/temp-contract"
[ "$(vm_ssh "/system/bin/rush -c 'unset TMPDIR; $DEV_TMP/temp-contract'")" = /user/tmp ] ||
  fail "Rust std did not use the Motor temp fallback"
[ "$(vm_ssh "TMPDIR=/none/tmp $DEV_TMP/temp-contract")" = /none/tmp ] ||
  fail "Rust std ignored explicit TMPDIR"

# Build trees are scratch. Remove each one after its boundary check so later
# independent builds retain enough room for their own outputs.
for package in red gears; do
  vm_ssh "cd /devtools/src/motor-os/bin/$package && $LORRY_VENDOR_ENV /devtools/bin/lorry vendor --accept-all" ||
    fail "developer image cannot vendor /devtools/src/motor-os/bin/$package"
  vm_ssh "cd /devtools/src/motor-os/bin/$package && /devtools/bin/lorry build" ||
    fail "developer image cannot natively build /devtools/src/$package"
  expect_nested_guest_mode "/devtools/src/motor-os/bin/$package/target/lorry/debug/build" \
    build-script-build -rwxr-xr-- "Cargo-uplifted $package build scripts"
  vm_ssh "/system/bin/rm -r /devtools/src/motor-os/bin/$package/target"
done
[ "$(count_guest_files /devtools/lorry/user/vendor/objects)" -gt "$user_objects" ] ||
  fail "Lorry did not populate /devtools/lorry/user/vendor"
[ "$(count_guest_files /devtools/lorry/user/cache)" -gt "$user_cache_files" ] ||
  fail "Lorry did not populate /devtools/lorry/user/cache"
vm_ssh "[ ! -e /user/cfg/lorry ]" ||
  fail "Lorry recreated its old state directory"
vm_ssh "cd /devtools/src/motor-os/bin/lorry && $LORRY_VENDOR_ENV /devtools/bin/lorry vendor --accept-all" ||
  fail "developer image cannot vendor /devtools/src/motor-os/bin/lorry"
vm_ssh "cd /devtools/src/motor-os/bin/lorry && /devtools/bin/lorry build" ||
  fail "developer image cannot natively build /devtools/src/lorry"
vm_ssh "/system/bin/cp /devtools/src/motor-os/bin/lorry/target/lorry/debug/lorry $DEV_TMP/native-lorry"
vm_ssh "/system/bin/rm -r /devtools/src/motor-os/bin/lorry/target"

# The library sources' tests, offline: the image carries the admitted
# workspace and its compiled dependencies, made with the same four jobs.
echo "-- Native tests of $SYS_LIB --"
native_progress="$VM_RUNTIME_DIR/native-tests.err"
native_results="$VM_RUNTIME_DIR/native-tests.out"
native_status=0
vm_ssh "cd $SYS_LIB && /devtools/bin/lorry test -j 4" \
  > "$native_results" 2> "$native_progress" || native_status=$?
cat "$native_progress" "$native_results"
[ "$native_status" -eq 0 ] ||
  fail "native lorry test in $SYS_LIB failed with status $native_status"
check_native_tests "$native_progress" "$native_results"
vm_ssh "/system/bin/rm -r $SYS_LIB/target"

kill -0 "$VMM_PID" 2>/dev/null ||
  fail "owned $TEST_VM_LABEL exited before final teardown"
stop_test_vm_owned "$VMM" "$TEST_VM_LABEL" ||
  fail "owned $TEST_VM_LABEL teardown failed"
echo "-------- TEST-DEV-SOURCES PASS ---------"
