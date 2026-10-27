#!/usr/bin/env bash
# Native Lorry builds of real Motor OS projects in the release developer image:
# red, rush and russhd from this checkout, and Helix from its managed
# fork checkout (external-sources/helix, as in src/build-motor-os.sh). Each project is
# vendored online in the guest, then built with /devtools/bin/lorry: a debug
# build, or a release build with --release. Every project is attempted; the
# run fails if any of them failed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LORRY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
HELIX="$ROOT_DIR/external-sources/helix"
WD="$ROOT_DIR/src/tests"
IMG_DIR="$ROOT_DIR/vm_images/release"
BUDGET_SECONDS="${LORRY_NATIVE_PROJECTS_TIMEOUT:-3600}"
REMOTE_ROOT=/user/tmp/lorry-native-projects
# project, guest directory below REMOTE_ROOT, built executable.
PROJECTS=(
    "red motor-os/src/bin/red red"
    "rush motor-os/src/bin/rush rush"
    "russhd motor-os/src/bin/russhd russhd"
    "helix helix hx"
)

fail() {
    echo "test-native-projects: $*" >&2
    exit 1
}

PROFILE=debug
BUILD_ARGUMENTS=""
case "$*" in
    "") ;;
    --release) PROFILE=release BUILD_ARGUMENTS=" --release" ;;
    *) fail "usage: test-native-projects.sh [--release]" ;;
esac

case "$BUDGET_SECONDS" in
    '' | *[!0-9]* | 0) fail "LORRY_NATIVE_PROJECTS_TIMEOUT must be a positive integer" ;;
esac
[ -f "$IMG_DIR/motor-os-dev.qcow2" ] ||
    fail "Motor developer image is absent; build it before running Lorry tests"
[ -z "$(git -C "$HELIX" status --porcelain)" ] ||
    fail "$HELIX has local changes"

RUN_ID="projects-$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVIDENCE_DIR="$LORRY_DIR/target/lorry/native-projects/$RUN_ID"
WORK="$(mktemp -d /tmp/lorry-native-projects-XXXXXX)"
# Builds write gigabytes; a disposable overlay keeps them out of the image.
OVERLAY="motor-os-dev-native-projects-$$.qcow2"
mkdir -p "$EVIDENCE_DIR"

. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-test-selection.sh"
. "$WD/vm-test-boot-check.sh"
select_test_vm "$ROOT_DIR" release developer qemu
test_vm_configure_ssh

VMM_PID=""
cleanup() {
    local status="$?"
    trap - EXIT
    set +e
    [ -z "$VMM_PID" ] || stop_test_vm_owned qemu "$TEST_VM_LABEL" || status=1
    rm -f "$IMG_DIR/$OVERLAY"
    rm -rf "$WORK"
    [ "$status" -eq 0 ] || echo "test-native-projects: evidence retained at $EVIDENCE_DIR" >&2
    exit "$status"
}
trap cleanup EXIT

# Tracked files only, laid out as in their checkouts so path dependencies
# such as ../../sys/lib resolve.
stage() {
    local checkout="$1" destination="$2"
    shift 2
    mkdir -p "$destination"
    git -C "$checkout" ls-files -z -- "$@" |
        tar -C "$checkout" --null -T - -cf - | tar -C "$destination" -xf -
}
stage "$ROOT_DIR" "$WORK/lorry-native-projects/motor-os" \
    src/bin/red src/bin/rush src/bin/russhd src/sys/lib
stage "$HELIX" "$WORK/lorry-native-projects/helix" .
printf 'profile: %s\nhelix: %s\n' "$PROFILE" "$(git -C "$HELIX" rev-parse HEAD)" >"$EVIDENCE_DIR/summary.txt"

qemu-img create -q -f qcow2 -F qcow2 -b motor-os-dev.qcow2 "$IMG_DIR/$OVERLAY"
export MOTO_IMAGE="$OVERLAY" MOTO_SMP="${LORRY_VM_SMP:-8}"
export MOTO_MEMORY_MIB="${LORRY_VM_MEMORY_MIB:-8192}"
start_test_vm "$TEST_VM_RUNNER" "$TEST_VM_LABEL" "$EVIDENCE_DIR/console.log"
DEADLINE=$((SECONDS + BUDGET_SECONDS))

# Runs one guest command under the remaining budget, logging to $1.log.
guest() {
    local log="$EVIDENCE_DIR/$1.log"
    shift
    local remaining=$((DEADLINE - SECONDS))
    [ "$remaining" -gt 0 ] || { echo "budget of ${BUDGET_SECONDS}s exhausted" >"$log"; return 1; }
    timeout "$remaining" "${SSH[@]}" "$*" </dev/null >"$log" 2>&1
}

scp -q -r -F /dev/null -P 2222 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" \
    -i "$WD/test.key" "$WORK/lorry-native-projects" motor@192.168.4.2:/user/tmp/ ||
    fail "cannot upload the project sources"

failed=()
for entry in "${PROJECTS[@]}"; do
    read -r name directory executable <<<"$entry"
    path="$REMOTE_ROOT/$directory"
    start="$SECONDS"
    result=PASS
    if ! guest "$name-vendor" "cd $path && /devtools/bin/lorry vendor --accept-all"; then
        result="FAIL (vendor)"
    elif ! guest "$name-build" "cd $path && /devtools/bin/lorry build$BUILD_ARGUMENTS"; then
        result="FAIL (build)"
    elif ! guest "$name-check" "[ -f $path/target/lorry/$PROFILE/$executable ]"; then
        result="FAIL (no $executable)"
    fi
    # Later projects need the space.
    guest "$name-clean" "[ ! -d $path/target ] || /system/bin/rm -r $path/target" ||
        fail "cannot remove the $name build tree"
    echo "$name: $result $((SECONDS - start))s" | tee -a "$EVIDENCE_DIR/summary.txt"
    [ "$result" = PASS ] || failed+=("$name")
done

[ "${#failed[@]}" -eq 0 ] || fail "native builds failed: ${failed[*]}"
echo "PASS: Lorry natively built red, rush, russhd and Helix ($PROFILE)"
