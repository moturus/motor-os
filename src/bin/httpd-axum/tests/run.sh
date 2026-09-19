#!/usr/bin/env bash
# Component-only gate. Motor mode boots a snapshot of an existing OS image.
set -euo pipefail
COMPONENT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROOT_DIR="$(cd "$COMPONENT_DIR/../../.." && pwd)"
cd "$ROOT_DIR"
BUILD=debug
VMM=qemu
motor=0
profile=()
usage() { echo "usage: $0 [--release] [--motor [--vmm qemu|chv]]" >&2; exit 2; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release) BUILD=release; profile=(--release); shift ;;
    --motor) motor=1; shift ;;
    --vmm) [ "$#" -ge 2 ] || usage; VMM="$2"; shift 2 ;;
    --vmm=*) VMM="${1#--vmm=}"; shift ;;
    *) usage ;;
  esac
done
case "$VMM" in qemu|chv) ;; *) usage ;; esac
if [ "$motor" = 0 ]; then
  exec cargo test --offline --manifest-path "$COMPONENT_DIR/Cargo.toml" "${profile[@]}" --tests
fi

WD="$ROOT_DIR/src/tests"
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-selection.sh"
. "$WD/vm-cleanup.sh"
fail() { echo "httpd-axum component: $*" >&2; exit 1; }
VM_BUILD="${HTTPD_AXUM_VM_BUILD:-$BUILD}"
case "$VM_BUILD" in debug|release) ;; *) fail "invalid VM build: $VM_BUILD" ;; esac
temporary="$(mktemp -d /tmp/httpd-axum-component.XXXXXX)"
VMM_PID=""
snapshot=""
cleanup() {
  local status=$?
  trap - EXIT
  stop_vm "$VMM_PID"
  [ -z "$snapshot" ] || rm -f "$snapshot"
  if [ "$status" = 0 ]; then
    rm -rf "$temporary"
  else
    echo "Component failure artifacts: $temporary" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
cargo test --offline --manifest-path "$COMPONENT_DIR/Cargo.toml" "${profile[@]}" \
  --target x86_64-unknown-motor --tests --no-run --message-format=json > "$temporary/build.jsonl"
python3 - "$temporary/build.jsonl" > "$temporary/executables.tsv" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    record = json.loads(line)
    if record.get('reason') != 'compiler-artifact' or not record.get('executable'):
        continue
    kind = record['target']['kind']
    if kind == ['test'] or (kind == ['bin'] and not record['profile']['test']):
        print(record['target']['name'], record['executable'], sep='\t')
PY

test_vm_configure_ssh
# A caller such as full-test-dev.sh names its own image; the standard one
# applies otherwise. Either way the guest's writes are discarded.
select_test_vm "$ROOT_DIR" "$VM_BUILD" standard "$VMM"
image="${MOTO_IMAGE:-$TEST_VM_IMAGE}"
runner_args=()
if [ "$VMM" = qemu ]; then
  runner_args=(-snapshot)
else
  # Cloud Hypervisor has no snapshot mode, so it boots a disposable copy. Its
  # launcher takes a bare filename beside the original.
  snapshot="$TEST_VM_IMG_DIR/httpd-axum-snapshot-$$.${image##*.}"
  cp "$TEST_VM_IMG_DIR/$image" "$snapshot"
  image="${snapshot##*/}"
fi
export MOTO_IMAGE="$image"
export MOTO_CHV_RUNTIME_DIR="$temporary/chv"
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$temporary/console.log" \
  "${runner_args[@]}"
guest="/user/tmp/httpd-component-$(date +%s)-$$"
vm_ssh /system/bin/mkdir "$guest"
upload() {
  local name="$1" executable="$2"
  printf 'put "%s" "%s/%s"\nchmod 755 "%s/%s"\n' \
    "$executable" "$guest" "$name" "$guest" "$name" |
    sftp -b - -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
      -i "$WD/test.key" motor@192.168.4.2
}
while IFS=$'\t' read -r name executable; do
  if [ "$name" = httpd-axum ]; then upload "$name" "$executable"; fi
done < "$temporary/executables.tsv"
# Keep only the server and one test executable in the small guest filesystem.
ran=0
expected=$(($(wc -l < "$temporary/executables.tsv") - 1))
[ "$expected" -gt 0 ] || fail "Cargo produced no component tests"
while IFS=$'\t' read -r name executable; do
  if [ "$name" != httpd-axum ]; then
    upload "$name" "$executable"
    vm_ssh "TMPDIR=$guest HTTPD_AXUM_BIN=$guest/httpd-axum $guest/$name" < /dev/null
    vm_ssh /system/bin/rm "$guest/$name" < /dev/null
    ran=$((ran + 1))
  fi
done < "$temporary/executables.tsv"
[ "$ran" = "$expected" ] || fail "ran $ran of $expected test targets"
vm_ssh /system/bin/rm -r "$guest"
echo "httpd-axum Motor component tests PASS ($BUILD, $ran test targets)"
