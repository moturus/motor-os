#!/usr/bin/env bash
# Install the native toolchain archive on a developer VM, as a user does, and
# build and run programs with what it installed. The VM boots a copy of the
# developer image: Lorry binds the installed toolchain by file size and mtime,
# so installing into the image itself would invalidate the dependency caches
# that its preparation warmed for the suites after this one.

if [ "${TEST_NATIVE_TOOLCHAIN_INSTALL_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export TEST_NATIVE_TOOLCHAIN_INSTALL_TIMEOUT_ACTIVE=1
  set -m
  timeout 600s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "test-native-toolchain-install: timed out after 600 seconds" >&2
  fi
  exit "$status"
fi

set -euo pipefail

WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
BUILD=debug
VMM=qemu
usage() { echo "usage: $0 [--release] [--vmm qemu|chv]" >&2; exit 2; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release) BUILD=release; shift ;;
    --vmm) [ "$#" -ge 2 ] || usage; VMM="$2"; shift 2 ;;
    --vmm=*) VMM="${1#--vmm=}"; shift ;;
    *) usage ;;
  esac
done
fail() { echo "test-native-toolchain-install: $*" >&2; exit 1; }
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-boot-check.sh"
. "$WD/vm-test-selection.sh"
select_test_vm "$ROOT_DIR" "$BUILD" developer "$VMM"
image="$TEST_VM_IMG_DIR/$TEST_VM_IMAGE"
[ -f "$image" ] || fail "the developer image is missing: $image"

host_sysroot="$(cd "$ROOT_DIR" && rustc --print sysroot)"
toolchain="$(sed -n 's/^toolchain=//p' "$host_sysroot/manifest")"
archive="$(readlink -f "${MOTORH:-$ROOT_DIR/..}")/motor-toolchain-$toolchain.tar.zst"
[ -f "$archive" ] || fail "the native toolchain archive is missing: $archive"
manifest="$ROOT_DIR/build/assembly/images/libc/devtools/toolchain/manifest"

copy=motor-os-dev-toolchain-install.qcow2
export MOTO_IMAGE="$copy"
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-4096}"
VM_RUNTIME_DIR="$(mktemp -d "${TMPDIR:-/tmp}/test-native-toolchain-install.XXXXXX")"
export MOTO_CHV_RUNTIME_DIR="$VM_RUNTIME_DIR/chv"
CONSOLE_LOG=/tmp/test-native-toolchain-install.log
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
  rm -f "$TEST_VM_IMG_DIR/$copy"
  rm -rf "$VM_RUNTIME_DIR"
  exit "$status"
}
trap cleanup EXIT
cp --reflink=auto "$image" "$TEST_VM_IMG_DIR/$copy"
test_vm_configure_ssh
echo "test-native-toolchain-install: runner=$TEST_VM_RUNNER image=$copy console=$CONSOLE_LOG"
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG"

sftp_options=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key" -P 2222)
guest=/user/tmp/native-toolchain-install
package="$guest/motor-toolchain-$toolchain"
started="$SECONDS"
vm_ssh "/system/bin/mkdir $guest"
printf 'put "%s" "%s/archive.tar.zst"\n' "$archive" "$guest" |
  sftp "${sftp_options[@]}" -b - motor@192.168.4.2 > /dev/null
vm_ssh "/system/bin/tar -x -f $guest/archive.tar.zst -C $guest"

# A different installed toolchain is replaced only when asked.
vm_ssh "/system/bin/rush -c 'echo toolchain=x86_64-unknown-motor-0.0.0 > /devtools/toolchain/manifest'"
if vm_ssh "$package/install.sh" > /dev/null 2>&1; then
  fail "install.sh replaced a different toolchain without --replace"
fi
vm_ssh "$package/install.sh --replace"
[ "$(vm_ssh /system/bin/cat /devtools/toolchain/manifest)" = "$(cat "$manifest")" ] ||
  fail "the installed manifest differs from the archive's"
vm_ssh "/system/bin/rm -r $guest"
echo "test-native-toolchain-install: installed $toolchain in $((SECONDS - started)) s"

src=/devtools/src/hello-world
out=/user/tmp/native-toolchain-hello
vm_ssh "/devtools/bin/cc $src/hello.c -o $out-c"
[ "$(vm_ssh "$out-c")" = "Hello from Motor-native clang!" ] || fail "hello.c did not run"
vm_ssh "/devtools/bin/c++ $src/hello.cpp -o $out-cpp"
[ "$(vm_ssh "$out-cpp")" = "Hello from Motor-native clang++!" ] || fail "hello.cpp did not run"
vm_ssh "/devtools/bin/rustc -O $src/hello.rs -o $out-rs"
[ "$(vm_ssh "$out-rs")" = $'hello from rustc running natively on motor os\n10! = 3628800' ] ||
  fail "hello.rs did not run"
vm_ssh "/devtools/bin/clippy-driver -O $src/hello.rs -o $out-clippy"
# The native tools are built from the same sources as the host toolchain's.
[ "$(vm_ssh /devtools/bin/rustfmt --version)" = "$("$host_sysroot/bin/rustfmt" --version)" ] ||
  fail "rustfmt reports a different version"
[ "$(vm_ssh /devtools/rust/bin/rust-analyzer --version)" = \
  "$("$host_sysroot/bin/rust-analyzer" --version)" ] ||
  fail "rust-analyzer reports a different version"
# 0x204 is CAP_SPAWN and CAP_FS_WRITE without CAP_INTERACTIVE: the None role.
vm_ssh "MOTOR_OS_CAPS=0x204 /devtools/rust/bin/rustc --version" > /dev/null ||
  fail "the None role cannot run the installed rustc"

kill -0 "$VMM_PID" 2>/dev/null || fail "owned $TEST_VM_LABEL exited before final teardown"
stop_test_vm_owned "$VMM" "$TEST_VM_LABEL" || fail "owned $TEST_VM_LABEL teardown failed"
echo "test-native-toolchain-install PASS"
