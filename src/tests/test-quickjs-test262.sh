#!/usr/bin/env bash
# Upstream Test262 with QuickJS-NG's own runner, built natively on a copy of the
# developer image. It mainly catches compiler and libc regressions. Preparation
# fetches the corpus at the revision the QuickJS tag pins; the VM run is offline.
if [ "${TEST_QUICKJS_TEST262_TIMEOUT_ACTIVE:-0}" != "1" ]; then
  export TEST_QUICKJS_TEST262_TIMEOUT_ACTIVE=1
  set -m
  timeout 1200s "$0" "$@" < /dev/null
  status=$?
  set +m
  if [ "$status" -eq 124 ]; then
    echo "test-quickjs-test262: timed out after 1200 seconds" >&2
  fi
  exit "$status"
fi
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
VMM=qemu
usage() { echo "usage: $0 --release [--vmm qemu|chv]" >&2; exit 2; }
release=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release) release=true; shift ;;
    --vmm) [ "$#" -ge 2 ] || usage; VMM="$2"; shift 2 ;;
    --vmm=*) VMM="${1#--vmm=}"; shift ;;
    *) usage ;;
  esac
done
[ "$release" = true ] || usage
fail() { echo "test-quickjs-test262: $*" >&2; exit 1; }

# The same summary as the Linux baseline for this QuickJS tag and corpus.
EXPECTED="Result: 40/82220 errors, 4802 excluded, 5736 skipped"
checkout="$ROOT_DIR/external-sources/quickjs-0.18.0"
source="$ROOT_DIR/build/assembly/build/quickjs/src"
[ -f "$source/run-test262.c" ] && [ -d "$checkout/.git" ] ||
  fail "build QuickJS first with src/build-motor-os.sh"
revision="$(git -C "$checkout" ls-tree HEAD test262 | awk '$2 == "commit" { print $3 }')"
[ -n "$revision" ] || fail "the QuickJS checkout pins no test262 revision"
corpus="$ROOT_DIR/external-sources/test262-$revision"
if [ ! -e "$corpus" ]; then
  echo "test-quickjs-test262: fetching the test262 corpus at $revision"
  rm -rf "$corpus.part"
  git init --quiet "$corpus.part"
  git -C "$corpus.part" fetch --quiet --depth 1 https://github.com/tc39/test262.git "$revision"
  git -C "$corpus.part" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
  mv "$corpus.part" "$corpus"
fi
[ "$(git -C "$corpus" rev-parse HEAD)" = "$revision" ] &&
  [ -z "$(git -C "$corpus" status --porcelain)" ] ||
  fail "the test262 corpus is not a clean checkout of $revision: $corpus"

. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-boot-check.sh"
. "$WD/vm-test-selection.sh"
select_test_vm "$ROOT_DIR" release developer "$VMM"
image="$TEST_VM_IMG_DIR/$TEST_VM_IMAGE"
[ -f "$image" ] || fail "the developer image is missing: $image"
copy=motor-os-dev-test262.qcow2
export MOTO_IMAGE="$copy"
export MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-4096}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/test-quickjs-test262.XXXXXX")"
export MOTO_CHV_RUNTIME_DIR="$WORK/chv"
CONSOLE_LOG=/tmp/test-quickjs-test262.log
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
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT

# The runner and its headers come from the patched source the image was built
# from. Motor's tar reads GNU-format archives, compressed with zstd or not.
(cd "$source" && tar --format=gnu -cf "$WORK/source.tar" run-test262.c test262.conf \
  test262_errors.txt ./*.h)
tar --format=gnu -C "$corpus" --transform 's,^,test262/,' -cf - harness test |
  zstd -q -o "$WORK/suite.tar.zst"
cp --reflink=auto "$image" "$TEST_VM_IMG_DIR/$copy"
test_vm_configure_ssh
echo "test-quickjs-test262: runner=$TEST_VM_RUNNER image=$copy console=$CONSOLE_LOG"
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$CONSOLE_LOG"
guest=/user/tmp/quickjs-test262
vm_ssh "/system/bin/mkdir $guest"
printf 'put "%s" "%s/%s"\n' "$WORK/source.tar" "$guest" source.tar "$WORK/suite.tar.zst" "$guest" suite.tar.zst |
  sftp -F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$WD/test-known-hosts" -i "$WD/test.key" -P 2222 \
    -b - motor@192.168.4.2 > /dev/null
vm_ssh "/system/bin/rush -c 'cd $guest && tar -x -f source.tar && tar -x -f suite.tar.zst'"
vm_ssh "/system/bin/rush -c 'cd $guest && cc -O2 -D_GNU_SOURCE -I. run-test262.c /devtools/quickjs/lib/libqjs.a -o run-test262'"
started="$SECONDS"
status=0
out="$(vm_ssh "/system/bin/rush -c 'cd $guest && ./run-test262 -m -c test262.conf -a -t 3'" 2>&1)" ||
  status=$?
result="$(printf '%s\n' "$out" | grep -a '^Result: ' | tail -1 || true)"
echo "test-quickjs-test262: ${result:-no summary} in $((SECONDS - started)) s, status $status"
[ "$status" -eq 0 ] || { printf '%s\n' "$out" | tail -40 >&2; fail "run-test262 exited with $status"; }
[ "$result" = "$EXPECTED" ] || fail "expected '$EXPECTED'"
kill -0 "$VMM_PID" 2>/dev/null || fail "owned $TEST_VM_LABEL exited before final teardown"
stop_test_vm_owned "$VMM" "$TEST_VM_LABEL" || fail "owned $TEST_VM_LABEL teardown failed"
echo "test-quickjs-test262 PASS"
