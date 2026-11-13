#!/usr/bin/env bash
# Install twice on a copy of the standard image, reboot for PATH changes,
# and build and run programs as None with the installed toolchain.

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
case "$VMM" in qemu|chv) ;; *) usage ;; esac
fail() { echo "test-native-toolchain-install: $*" >&2; exit 1; }
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-boot-check.sh"
. "$WD/vm-test-selection.sh"
select_test_vm "$ROOT_DIR" "$BUILD" standard "$VMM"
image="$TEST_VM_IMG_DIR/$TEST_VM_IMAGE"
[ -f "$image" ] || fail "the standard image is missing: $image"

host_sysroot="$(cd "$ROOT_DIR" && rustc --print sysroot)"
toolchain="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$ROOT_DIR/rust-toolchain.toml")"
archive="$(bash "$ROOT_DIR/src/build-scripts/toolchain-archive.sh" "$BUILD")"
echo "test-native-toolchain-install: archive=$archive"
sha256sum "$archive"

copy=motor-os-toolchain-install.qcow2
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

mode() {
  local path="$1" expected="$2" actual
  actual="$(vm_ssh "/user/bin/ls -l ${path%/*}" | awk -v name="${path##*/}" '$NF == name { print $1 }')"
  [ "$actual" = "$expected" ] || fail "$path has mode $actual, expected $expected"
}

sftp_options=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts"
  -i "$WD/test.key" -P 2222)
guest=/user/tmp/native-toolchain-install
package="$guest/motor-toolchain-$toolchain"
started="$SECONDS"
vm_ssh '[ ! -e /devtools ] && [ ! -e /system/bin ] && [ ! -e /user/bin/dev/lorry ]'
vm_ssh "/user/bin/mkdir $guest"
printf 'put "%s" "%s/archive.tar.zst"\n' "$archive" "$guest" |
  sftp "${sftp_options[@]}" -b - motor@192.168.4.2 > /dev/null
vm_ssh "/user/bin/tar -x -f $guest/archive.tar.zst -C $guest"
# An additional library exercises discovery, permissions, and stale-file
# removal independently of the known compiler and tool library names.
vm_ssh "/user/bin/mkdir -p $package/images/motor/user/lib/install-probe /user/lib/install-keep"
vm_ssh "echo payload > $package/images/motor/user/lib/install-probe/data"
vm_ssh "/user/bin/chmod rwxrw---- $package/images/motor/user/lib/install-probe/data"

# Observe transient files while both installs run, including a caller's shared
# TMPDIR. The helper lives in a subdirectory outside the directories it scans.
rustc --edition=2024 -D warnings -O --target x86_64-unknown-motor \
  "$WD/toolchain-install-privacy.rs" -o "$VM_RUNTIME_DIR/privacy"
vm_ssh '/user/bin/mkdir /none/tmp/install-privacy'
printf 'put "%s" "/none/tmp/install-privacy/watch"\n' "$VM_RUNTIME_DIR/privacy" |
  sftp "${sftp_options[@]}" -b - motor@192.168.4.2 > /dev/null
vm_ssh '/user/bin/chmod rwxr-xr-x /none/tmp/install-privacy/watch'
# Exercise a valid large configuration so an unsafe staged rewrite remains
# visible while it is copied. The comments also check complete preservation.
awk 'BEGIN {for (i=0; i<32768; i++) print "# installer privacy and configuration preservation regression"}' \
  > "$VM_RUNTIME_DIR/sshd-comments"
printf 'put "%s" "/none/tmp/install-privacy/comments"\n' "$VM_RUNTIME_DIR/sshd-comments" |
  sftp "${sftp_options[@]}" -b - motor@192.168.4.2 > /dev/null
vm_ssh '/user/bin/cat /none/tmp/install-privacy/comments >> /user/cfg/sshd.toml'
coproc PRIVACY { vm_ssh 'MOTOR_OS_CAPS=0x204 /none/tmp/install-privacy/watch'; }
privacy_pid="$PRIVACY_PID"
exec {privacy_in}>&"${PRIVACY[1]}" {privacy_out}<&"${PRIVACY[0]}"
IFS= read -r ready <&"$privacy_out"
[ "$ready" = ready ] || fail 'privacy observer did not start'

# Keep a private expected copy to check that extending PATH preserves the host
# key and every other setting. Never print either configuration on failure.
vm_ssh '/user/bin/cat /user/cfg/sshd.toml' > "$VM_RUNTIME_DIR/sshd-before.toml"
sed -E 's|^(path[[:space:]]*=[[:space:]]*")([^"]*)(".*)$|\1\2:/user/bin/dev\3|' \
  "$VM_RUNTIME_DIR/sshd-before.toml" > "$VM_RUNTIME_DIR/sshd-expected.toml"
check_ssh_config() {
  vm_ssh '/user/bin/cat /user/cfg/sshd.toml' > "$VM_RUNTIME_DIR/sshd-after.toml"
  cmp -s "$VM_RUNTIME_DIR/sshd-expected.toml" "$VM_RUNTIME_DIR/sshd-after.toml" ||
    fail 'installation changed SSH configuration beyond extending PATH'
  if vm_ssh 'MOTOR_OS_CAPS=0x204 /user/bin/cat /user/cfg/sshd.toml' > /dev/null 2>&1; then
    fail 'None can read the SSH configuration'
  fi
  if ! kill -0 "$privacy_pid" 2>/dev/null; then
    wait "$privacy_pid" || fail 'privacy observer failed during installation'
    fail 'privacy observer exited before installation completed'
  fi
}
# A caller's shared temporary directory must not make private edits public.
vm_ssh "TMPDIR=/none/tmp $package/install.sh"
check_ssh_config
mode /user/lib/install-probe/data -rwxrw-r--
for source in hello.c hello.cpp hello.rs; do
  mode "/none/dev/hello-world/$source" -rwxrw-rw-
done
# Reinstallation removes stale libraries and preserves local configuration.
vm_ssh 'echo stale > /user/lib/llvm/stale-install && echo stale > /user/lib/rust/stale-install && echo stale > /user/lib/install-probe/stale-install'
vm_ssh "/user/bin/rush -c 'echo \"# installer-preservation-probe\" >> /user/cfg/cargo/config.toml'"
vm_ssh '/user/bin/chmod rwxr-xr-x /user/cfg/cargo && /user/bin/chmod rwxr-x--- /user/cfg/helix'
vm_ssh "$package/install.sh"
check_ssh_config
mode /user/cfg/cargo drwxr-xr-x
mode /user/cfg/helix drwxr-x---
# Restore shared settings for the following None-role compiler/editor checks.
vm_ssh '/user/bin/chmod rwxrwxr-x /user/cfg/cargo /user/cfg/helix'
printf 'done\n' >&"$privacy_in"
cat <&"$privacy_out"
wait "$privacy_pid" || fail 'installation exposed the SSH host key to None'
exec {privacy_in}>&- {privacy_out}<&-
vm_ssh '/user/bin/rm -r /none/tmp/install-privacy'
if ! vm_ssh '[ ! -e /user/lib/llvm/stale-install ] && [ ! -e /user/lib/rust/stale-install ] && [ ! -e /user/lib/install-probe/stale-install ]'; then
  fail "install.sh left stale files in the toolchain directories"
fi
vm_ssh '[ -d /user/lib/install-keep ]' || fail 'installation removed an unrelated library'
vm_ssh '/user/bin/cat /user/cfg/cargo/config.toml' | grep -qx '# installer-preservation-probe' ||
  fail "reinstallation replaced user configuration"

# Replace an actual shipped command, including the immutable image-built case.
printf 'put "%s" "%s/curl"\n' "$ROOT_DIR/build/bin/$BUILD/curl" "$guest" |
  sftp "${sftp_options[@]}" -b - motor@192.168.4.2 > /dev/null
vm_ssh "/user/bin/cp $guest/curl /user/bin/.curl-new &&
  /user/bin/chmod rwxrwxr-x /user/bin/.curl-new &&
  /user/bin/mv /user/bin/.curl-new /user/bin/curl"
curl_version="$(vm_ssh /user/bin/curl --version)"
case "$curl_version" in 'curl '*) ;; *) fail 'replacement curl did not run' ;; esac
vm_ssh "/user/bin/rm -r $guest"
echo "test-native-toolchain-install: installed $toolchain in $((SECONDS - started)) s"

# russhd reads PATH once at startup; test the persisted installation after reboot.
stop_test_vm_owned "$VMM" "$TEST_VM_LABEL" || fail "shutdown before reboot failed"
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$VM_RUNTIME_DIR/reboot.log"
[ "$(vm_ssh /user/bin/printenv PATH)" = 'PATH=/user/bin:/user/bin/dev' ] || fail 'SSH PATH was not extended once'
vm_ssh '[ ! -e /devtools ] && [ ! -e /system/bin ]'
[ "$(vm_ssh rustc --print sysroot)" = /user/lib/rust ] || fail 'wrong native Rust sysroot'
for path in /user/bin/curl /user/bin/dev/ar /user/bin/dev/lorry \
    /user/bin/dev/rustc /user/bin/dev/rust-analyzer /user/lib/llvm/bin/llvm \
    /user/lib/rust/bin/rustc /user/lib/helix/hx; do
  mode "$path" -rwxrwxr-x
  if vm_ssh "MOTOR_OS_CAPS=0x204 /user/bin/rush -c 'echo denied >>$path'" > /dev/null 2>&1; then
    fail "None can write $path"
  fi
done
mode /user/cfg/cargo/config.toml -rwxrw-r--
mode /user/lib/llvm/include/stdio.h -rwxrw-r--
mode /none/dev/hello-world drwxrwxrwx
mode /none/dev/hello-world/hello.rs -rwxrw-rw-
vm_ssh 'MOTOR_OS_CAPS=0x204 /user/bin/cat /user/cfg/cargo/config.toml' > /dev/null

# Exercise the development commands shipped alongside the compilers, using
# the same None role that will build and edit projects with them.
for command in 'gix --version' 'hx --version' 'sed --version' 'lua -v' \
    'javy --version' 'wasmi --version' 'wasmtime --version' 'wasmtime-rt --version'; do
  vm_ssh "MOTOR_OS_CAPS=0x204 $command" > /dev/null || fail "installed $command did not run"
done
[ "$(vm_ssh "MOTOR_OS_CAPS=0x204 qjs --eval 'print(6 * 7)'")" = 42 ] ||
  fail 'installed QuickJS did not run'

src=/none/dev/hello-world
out=/none/tmp/native-toolchain-hello
vm_ssh "MOTOR_OS_CAPS=0x204 cc $src/hello.c -o $out-c"
[ "$(vm_ssh "$out-c")" = "Hello from Motor-native clang!" ] || fail "hello.c did not run"
vm_ssh "MOTOR_OS_CAPS=0x204 c++ $src/hello.cpp -o $out-cpp"
[ "$(vm_ssh "$out-cpp")" = "Hello from Motor-native clang++!" ] || fail "hello.cpp did not run"
vm_ssh "MOTOR_OS_CAPS=0x204 rustc -O $src/hello.rs -o $out-rs"
[ "$(vm_ssh "$out-rs")" = $'hello from rustc running natively on motor os\n10! = 3628800' ] ||
  fail "hello.rs did not run"
vm_ssh "MOTOR_OS_CAPS=0x204 clippy-driver -O $src/hello.rs -o $out-clippy"
vm_ssh "MOTOR_OS_CAPS=0x204 ar --version" > /dev/null
vm_ssh "MOTOR_OS_CAPS=0x204 lorry new /none/tmp/installed-lorry"
[ "$(vm_ssh 'MOTOR_OS_CAPS=0x204 lorry run --offline --manifest-path /none/tmp/installed-lorry/Cargo.toml')" = 'Hello, world!' ] ||
  fail 'installed Lorry did not build and run a project'
# The native tools are built from the same sources as the host toolchain's.
[ "$(vm_ssh /user/bin/dev/rustfmt --version)" = "$("$host_sysroot/bin/rustfmt" --version)" ] ||
  fail "rustfmt reports a different version"
[ "$(vm_ssh /user/lib/rust/bin/rust-analyzer --version)" = \
  "$("$host_sysroot/bin/rust-analyzer" --version)" ] ||
  fail "rust-analyzer reports a different version"
# 0x204 is CAP_SPAWN and CAP_FS_WRITE without CAP_INTERACTIVE: the None role.
vm_ssh "MOTOR_OS_CAPS=0x204 /user/lib/rust/bin/rustc --version" > /dev/null ||
  fail "the None role cannot run the installed rustc"

kill -0 "$VMM_PID" 2>/dev/null || fail "owned $TEST_VM_LABEL exited before final teardown"
stop_test_vm_owned "$VMM" "$TEST_VM_LABEL" || fail "owned $TEST_VM_LABEL teardown failed"
echo "test-native-toolchain-install PASS"
