#!/usr/bin/env bash
# Release-only installed-tool checks. Preparation may fetch; VM tests are offline.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
image=both
memory=both
prepare=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release) shift ;;
    --image) image="${2:?missing image}"; shift 2 ;;
    --memory) memory="${2:?missing memory}"; shift 2 ;;
    --prepare) prepare=true; shift ;;
    *) echo "usage: $0 [--release] [--prepare] [--image wasm|dev|both] [--memory 224|256|both]" >&2; exit 2 ;;
  esac
done
case "$image" in wasm) images=(wasm);; dev) images=(dev);; both) images=(wasm dev);; *) exit 2;; esac
case "$memory" in 224|256) sizes=("$memory");; both) sizes=(256 224);; *) exit 2;; esac
key="$(cat "$(rustc --print sysroot)/lib/rustlib/MOTOR-TOOLCHAIN-KEY")"
target="$ROOT_DIR/build/obj/$key/release/javy-smoke"
binary="$target/x86_64-unknown-motor/release/javy-smoke"
if [ "$prepare" = true ]; then
  targets=()
  for variant in "${images[@]}"; do targets+=("$variant.img"); done
  make -C "$ROOT_DIR" "${targets[@]}" BUILD=release -j"$(nproc)"
  CARGO_TARGET_DIR="$target" cargo build --locked --release --target x86_64-unknown-motor \
    --manifest-path "$WD/javy-smoke/Cargo.toml"
  exit
fi
[ -x "$binary" ] || { echo "run $0 --prepare first" >&2; exit 1; }
if [ "${JAVY_TEST_TIMED:-0}" != 1 ]; then
  exec timeout 600s env JAVY_TEST_TIMED=1 "$0" --image "$image" --memory "$memory"
fi
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-cleanup.sh"
fail() { echo "test-javy: $*" >&2; exit 1; }
test_vm_configure_ssh
VMM_PID=""
trap 'stop_vm "$VMM_PID"' EXIT
evidence="$(mktemp -d "$ROOT_DIR/build/javy-images.XXXXXX")"
assembly="$("$ROOT_DIR/src/resolve-toolchain-assembly.sh" --resolve)"
export MOTO_SMP=2
for variant in "${images[@]}"; do
  export MOTO_IMAGE="motor-os-$variant.qcow2"
  sha256sum "$ROOT_DIR/vm_images/release/$MOTO_IMAGE" > "$evidence/$variant-image.sha256"
  for size in "${sizes[@]}"; do
    export MOTO_MEMORY_MIB="$size"
    label="$variant-$size"
    start_test_vm "$ROOT_DIR/vm_images/release/run-qemu.sh" QEMU "$evidence/$label-console.log" -snapshot
    sftp_options=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" -i "$WD/test.key" -P 2222)
    {
      printf 'put "%s" /user/tmp/javy-smoke\n' "$binary"
      printf 'get /user/bin/javy "%s"\n' "$evidence/installed-javy"
      printf 'get /user/bin/wasmi "%s"\n' "$evidence/installed-wasmi"
    } | sftp "${sftp_options[@]}" -b - motor@192.168.4.2
    cmp "$assembly/javy/user/bin/javy" "$evidence/installed-javy"
    cmp "$assembly/javy/user/bin/wasmi" "$evidence/installed-wasmi"
    vm_ssh /user/tmp/javy-smoke 2>&1 | tee "$evidence/$label.log"
    vm_ssh shutdown
    status=0
    wait "$VMM_PID" || status=$?
    VMM_PID=""
    [ "$status" = 33 ] || fail "QEMU exited with $status after $label"
  done
done
echo "test-javy PASS; evidence=$evidence"
