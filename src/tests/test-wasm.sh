#!/usr/bin/env bash
# Release-only installed-tool checks. Preparation may fetch; VM tests are offline.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
image=both
memory=both
vmm=qemu
prepare=false
linux_identity=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release) shift ;;
    --image) image="${2:?missing image}"; shift 2 ;;
    --memory) memory="${2:?missing memory}"; shift 2 ;;
    --vmm) vmm="${2:?missing vmm}"; shift 2 ;;
    --vmm=*) vmm="${1#--vmm=}"; shift ;;
    --prepare) prepare=true; shift ;;
    --linux-identity) linux_identity=(--linux-identity); shift ;;
    *) echo "usage: $0 [--release] [--prepare] [--image wasm|dev|both] [--memory 224|256|both] [--vmm qemu|chv] [--linux-identity]" >&2; exit 2 ;;
  esac
done
case "$image" in wasm) images=(wasm);; dev) images=(dev);; both) images=(wasm dev);; *) exit 2;; esac
case "$memory" in 224|256) sizes=("$memory");; both) sizes=(256 224);; *) exit 2;; esac
case "$vmm" in qemu) vmm_label=QEMU;; chv) vmm_label="Cloud Hypervisor";; *) exit 2;; esac
# The repository's toolchain selector names the key, so resolve it from the
# root whatever the caller's directory is.
cd "$ROOT_DIR"
key="$(cat "$(rustc --print sysroot)/lib/rustlib/MOTOR-TOOLCHAIN-KEY")"
suites=(javy-smoke wasmtime-smoke)
binary() { echo "$ROOT_DIR/build/obj/$key/release/$1/x86_64-unknown-motor/release/$1"; }
if [ "$prepare" = true ]; then
  targets=()
  for variant in "${images[@]}"; do targets+=("$variant.img"); done
  make -C "$ROOT_DIR" "${targets[@]}" BUILD=release -j"$(nproc)"
  for suite in "${suites[@]}"; do
    CARGO_TARGET_DIR="$ROOT_DIR/build/obj/$key/release/$suite" cargo build --locked --release \
      --target x86_64-unknown-motor --manifest-path "$WD/$suite/Cargo.toml"
  done
  exit
fi
for suite in "${suites[@]}"; do
  [ -x "$(binary "$suite")" ] || { echo "run $0 --prepare first" >&2; exit 1; }
done
if [ "${WASM_TEST_TIMED:-0}" != 1 ]; then
  exec timeout 600s env WASM_TEST_TIMED=1 "$0" --image "$image" --memory "$memory" --vmm "$vmm" \
    "${linux_identity[@]}"
fi
. "$WD/vm-console-filter.sh"
. "$WD/vm-test-boot.sh"
. "$WD/vm-cleanup.sh"
fail() { echo "test-wasm: $*" >&2; exit 1; }
test_vm_configure_ssh
VMM_PID=""
snapshot=""
cleanup() { stop_vm "$VMM_PID"; [ -z "$snapshot" ] || rm -f "$snapshot"; }
trap cleanup EXIT
# The VM lock is taken per boot, so hold a checkout-level lock across the whole
# matrix: a contending run must not replace this run's evidence.
exec 8>"$ROOT_DIR/build/wasm-images.lock"
flock -n 8 || fail "another test-wasm.sh run is active in this checkout"
# One evidence tree per checkout: a run replaces whatever the previous run left.
evidence="$ROOT_DIR/build/wasm-images"
rm -rf "$evidence"
mkdir -p "$evidence"
assembly="$("$ROOT_DIR/src/resolve-toolchain-assembly.sh" --resolve)"
export MOTO_SMP=2
export MOTO_CHV_RUNTIME_DIR="$evidence/chv"
for variant in "${images[@]}"; do
  image_file="motor-os-$variant.qcow2"
  sha256sum "$ROOT_DIR/vm_images/release/$image_file" > "$evidence/$variant-image.sha256"
  for size in "${sizes[@]}"; do
    export MOTO_MEMORY_MIB="$size"
    label="$variant-$size"
    runner_args=()
    if [ "$vmm" = qemu ]; then
      runner_args=(-snapshot)
      export MOTO_IMAGE="$image_file"
    else
      # Cloud Hypervisor has no snapshot mode, so each boot uses a disposable
      # copy; the launcher takes a bare filename beside the original.
      snapshot="$ROOT_DIR/vm_images/release/wasm-snapshot-$$.qcow2"
      cp "$ROOT_DIR/vm_images/release/$image_file" "$snapshot"
      export MOTO_IMAGE="${snapshot##*/}"
    fi
    start_test_vm "$ROOT_DIR/vm_images/release/run-$vmm.sh" "$vmm_label" \
      "$evidence/$label-console.log" "${runner_args[@]}"
    sftp_options=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes
      -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WD/test-known-hosts" -i "$WD/test.key" -P 2222)
    installed=(javy/devtools/bin/javy javy/devtools/bin/wasmi wasmtime/devtools/bin/wasmtime-rt)
    {
      for suite in "${suites[@]}"; do printf 'put "%s" /user/tmp/%s\n' "$(binary "$suite")" "$suite"; done
      for tool in "${installed[@]}"; do
        printf 'get /%s "%s"\n' "${tool#*/}" "$evidence/installed-${tool##*/}"
      done
    } | sftp "${sftp_options[@]}" -b - motor@192.168.4.2
    for tool in "${installed[@]}"; do cmp "$assembly/$tool" "$evidence/installed-${tool##*/}"; done
    for suite in "${suites[@]}"; do
      args=()
      # Linux byte identity depends on neither image nor memory: the first boot checks it.
      if [ "$suite" = javy-smoke ]; then args=("${linux_identity[@]}"); linux_identity=(); fi
      vm_ssh "/user/tmp/$suite" "${args[@]}" 2>&1 | tee -a "$evidence/$label.log"
    done
    vm_ssh shutdown
    status=0
    wait "$VMM_PID" || status=$?
    VMM_PID=""
    case "$vmm:$status" in
      qemu:33 | chv:0 | chv:143) ;;
      *) fail "$vmm_label exited with $status after $label" ;;
    esac
    [ -z "$snapshot" ] || { rm -f "$snapshot"; snapshot=""; }
  done
done
echo "test-wasm PASS; evidence=$evidence"
