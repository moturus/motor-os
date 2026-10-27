#!/bin/bash
# Run against a disposable copy of the developer image prepared by full-test.sh.
set -euo pipefail
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../../../.." && pwd)"
WD="$ROOT_DIR/src/tests"
PROFILE=debug
PROFILE_ARGS=()
case "$*" in
  "") ;;
  --release) PROFILE=release; PROFILE_ARGS=(--release) ;;
  *) echo "usage: $0 [--release]" >&2; exit 2 ;;
esac
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-selection.sh"
. "$WD/vm-test-boot-check.sh"
fail() { echo "gears test-vm: $*" >&2; exit 1; }
select_test_vm "$ROOT_DIR" "$PROFILE" developer qemu
test_vm_configure_ssh
IMG_DIR="$ROOT_DIR/vm_images/$PROFILE"
WORK="$(mktemp -d "$ROOT_DIR/build/gears-vm-$PROFILE.XXXXXX")"
OVERLAY="gears-tests-$$.qcow2"
VMM_PID=""
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [ -n "$VMM_PID" ]; then
    stop_test_vm_owned qemu "$TEST_VM_LABEL" || status=1
  fi
  rm -f "$IMG_DIR/$OVERLAY"
  echo "Gears VM logs: $WORK"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
qemu-img create -q -f qcow2 -F qcow2 -b motor-os-dev.qcow2 "$IMG_DIR/$OVERLAY"
export MOTO_IMAGE="$OVERLAY"
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-4096}"
export MOTO_SMP="${MOTO_SMP:-4}"
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$WORK/console.log"

# Test payloads are uploaded only by this gate, not installed by make dev.img.
export GEARS_VM_TEST_DIR=/user/tmp/gears-tests
EXAMPLES="$ROOT_DIR/build/obj/$PROFILE/gears/x86_64-unknown-motor/$PROFILE/examples"
vm_ssh "/system/bin/mkdir $GEARS_VM_TEST_DIR"
scp -q -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
  -i "$WD/test.key" "$EXAMPLES/tool-smoke" "$EXAMPLES/workflow-smoke" \
  "$EXAMPLES/mock-provider" "$TEST_DIR/tls/TEST_ONLY_"*.pem \
  "motor@192.168.4.2:$GEARS_VM_TEST_DIR/"
vm_ssh "/system/bin/chmod rwxr-xr-- $GEARS_VM_TEST_DIR/tool-smoke $GEARS_VM_TEST_DIR/workflow-smoke $GEARS_VM_TEST_DIR/mock-provider"

for binary in gears gears-batteries; do
  vm_ssh "[ -x /devtools/bin/$binary ]" || fail "missing installed $binary"
done
for file in gears.toml gears-batteries.toml tools/sh/tool.toml; do
  vm_ssh "[ -f /user/cfg/gears/$file ]" || fail "missing installed $file"
done
"$TEST_DIR/test-gears-http-vm.sh" "${PROFILE_ARGS[@]}"
"$TEST_DIR/test-gears-batteries-vm.sh" "${PROFILE_ARGS[@]}"

if [ "$PROFILE" = release ]; then
  # Native source acceptance is release-only; both profiles run the workflows above.
  SOURCE=/devtools/src/motor-os/bin/gears
  vm_ssh "[ -f $SOURCE/Cargo.toml ] && [ ! -d $SOURCE/target ] && [ ! -d $SOURCE/.lorry/vendor ]" ||
    fail "packaged Gears sources are missing or contain build artifacts"
  vm_ssh "cd $SOURCE && /devtools/bin/lorry vendor --accept-all"
  vm_ssh "cd $SOURCE && /devtools/bin/lorry build --release"
  scripts="$(vm_ssh "/system/bin/find $SOURCE/target/lorry/release/build -type f -name build-script-build")"
  [ -n "$scripts" ] || fail "native build did not produce build scripts"
  while IFS= read -r path; do
    mode="$(vm_ssh "/system/bin/ls -l ${path%/*}" | awk '$NF == "build-script-build" { print $1 }')"
    [ "$mode" = -rwxr-xr-- ] || fail "native build-script mode is $mode: $path"
  done <<< "$scripts"
  vm_ssh "cd $SOURCE && /devtools/bin/lorry test --release"
  out="$(vm_ssh "cd $SOURCE && /devtools/bin/lorry run --release -- --version")"
  printf '%s\n' "$out" | grep -qx 'gears [0-9][0-9.]*' || fail "lorry run did not start gears: $out"
fi
kill -0 "$VMM_PID" 2>/dev/null || fail "owned VM exited before teardown"
stop_test_vm_owned qemu "$TEST_VM_LABEL" || fail "VM teardown failed"
echo "gears test-vm.sh ($PROFILE) ALL PASS"
