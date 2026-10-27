#!/usr/bin/env bash
# Release-only installed-tool checks. Preparation may fetch; VM tests are offline.
set -euo pipefail
WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
image=both
memory=both
vmm=qemu
selection=both
prepare=false
vms=()
linux_identity=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release) shift ;;
    --image) image="${2:?missing image}"; shift 2 ;;
    --memory) memory="${2:?missing memory}"; shift 2 ;;
    --vm) vms+=("${2:?missing vm}"); shift 2 ;;
    --vmm) vmm="${2:?missing vmm}"; shift 2 ;;
    --vmm=*) vmm="${1#--vmm=}"; shift ;;
    --prepare) prepare=true; shift ;;
    --suite) selection="${2:?missing suite}"; shift 2 ;;
    --linux-identity) linux_identity=(--linux-identity); shift ;;
    *) echo "usage: $0 [--release] [--prepare] [--suite javy|wasmtime|both] [--image wasm|dev|both] [--memory 224|256|both] [--vm IMAGE:MIB]... [--vmm qemu|chv] [--linux-identity]" >&2; exit 2 ;;
  esac
done
case "$image" in wasm) images=(wasm);; dev) images=(dev);; both) images=(wasm dev);; *) exit 2;; esac
case "$memory" in 224|256) sizes=("$memory");; both) sizes=(256 224);; *) exit 2;; esac
# Explicit VMs replace the image/memory matrix.
if [ "${#vms[@]}" = 0 ]; then
  for variant in "${images[@]}"; do for size in "${sizes[@]}"; do vms+=("$variant:$size"); done; done
fi
for vm in "${vms[@]}"; do
  case "$vm" in wasm:224|wasm:256|dev:224|dev:256) ;; *) echo "test-wasm: bad VM $vm" >&2; exit 2;; esac
done
case "$vmm" in qemu) vmm_label=QEMU;; chv) vmm_label="Cloud Hypervisor";; *) exit 2;; esac
# rust-toolchain.toml names the toolchain, so build from the root whatever the
# caller's directory is.
cd "$ROOT_DIR"
case "$selection" in
  javy) suites=(javy-smoke);;
  wasmtime) suites=(wasmtime-smoke);;
  both) suites=(javy-smoke wasmtime-smoke);;
  *) echo "test-wasm: unknown suite $selection" >&2; exit 2;;
esac
binary() { echo "$ROOT_DIR/build/obj/release/$1/x86_64-unknown-motor/release/$1"; }
if [ "$prepare" = true ]; then
  targets=()
  for vm in "${vms[@]}"; do
    case " ${targets[*]} " in *" ${vm%:*}.img "*) ;; *) targets+=("${vm%:*}.img");; esac
  done
  make -C "$ROOT_DIR" "${targets[@]}" BUILD=release -j"$(nproc)"
  for suite in "${suites[@]}"; do
    CARGO_TARGET_DIR="$ROOT_DIR/build/obj/release/$suite" cargo build --locked --release \
      --target x86_64-unknown-motor --manifest-path "$WD/$suite/Cargo.toml"
  done
  exit
fi
for suite in "${suites[@]}"; do
  [ -x "$(binary "$suite")" ] || { echo "run $0 --prepare first" >&2; exit 1; }
done
if [ "${WASM_TEST_TIMED:-0}" != 1 ]; then
  vm_args=()
  for vm in "${vms[@]}"; do vm_args+=(--vm "$vm"); done
  exec timeout 600s env WASM_TEST_TIMED=1 "$0" --suite "$selection" --vmm "$vmm" "${linux_identity[@]}" "${vm_args[@]}"
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
assembly="$ROOT_DIR/build/assembly/images"
# Test inputs are staged in the assembly, outside the images, and uploaded per boot.
test_inputs="$ROOT_DIR/build/assembly/tests"
for name in javy wasmtime; do
  (cd "$test_inputs/$name" && sha256sum --quiet -c SHA256SUMS) ||
    fail "no current $name test inputs; run src/build-motor-os.sh --javy-only --wasmtime-only"
done
export MOTO_SMP=2
export MOTO_CHV_RUNTIME_DIR="$evidence/chv"
# Checks that depend on neither image nor memory run on the first VM only.
once=(--determinism "${linux_identity[@]}")
for vm in "${vms[@]}"; do
  variant="${vm%:*}" size="${vm#*:}"
  image_file="motor-os-$variant.qcow2"
  sha256sum "$ROOT_DIR/vm_images/release/$image_file" > "$evidence/$variant-image.sha256"
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
    # Keep fixtures and retained outputs on disk for the low-RAM qualification.
    # Role None can traverse this directory; its own TMPDIR remains on memfs.
    printf 'mkdir /none/wasm-tests\n'
    for name in javy wasmtime; do
      printf 'mkdir /none/wasm-tests/%s-tests\n' "$name"
      for file in "$test_inputs/$name"/*; do
        printf 'put "%s" /none/wasm-tests/%s-tests/%s\n' "$file" "$name" "${file##*/}"
      done
    done
    for tool in "${installed[@]}"; do
      printf 'get /%s "%s"\n' "${tool#*/}" "$evidence/installed-${tool##*/}"
    done
  } | sftp "${sftp_options[@]}" -b - motor@192.168.4.2
  for tool in "${installed[@]}"; do cmp "$assembly/$tool" "$evidence/installed-${tool##*/}"; done
  for suite in "${suites[@]}"; do
    args=()
    if [ "$suite" = javy-smoke ]; then args=("${once[@]}"); once=(); fi
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
echo "test-wasm PASS; evidence=$evidence"
