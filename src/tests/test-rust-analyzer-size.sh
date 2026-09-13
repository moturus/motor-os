#!/usr/bin/env bash
# Measure fresh images, never compare a guest-mutated disk with a fresh one.
set -euo pipefail

check_size() {
  local label="$1" observed="$2" limit="$3"
  [[ "$observed" =~ ^[0-9]+$ ]] && [ "$observed" -le "$limit" ] || {
    echo "$label: observed=$observed bytes, approved maximum=$limit" >&2
    return 1
  }
}

measure() {
  local root assembly key imager evidence binary sources variant bytes_without bytes_with
  root="$(cd "$(dirname "$0")/../.." && pwd)"
  assembly="$("$root/src/select-toolchain-assembly.sh" --resolve)"
  key="$(<"$(rustc --print sysroot)/lib/rustlib/MOTOR-TOOLCHAIN-KEY")"
  imager="$root/build/obj/$key/release/imager/release/imager"
  [ -x "$imager" ] || { echo 'build a release image before measuring analyzer size' >&2; return 1; }
  evidence="$(mktemp -d "$root/build/ra-image-growth.XXXXXX")"
  binary="$(stat -c %s "$assembly/rust-analyzer/devtools/rust/bin/rust-analyzer")"
  sources="$(find "$assembly/rust-analyzer/devtools/rust/lib/rustlib/src/rust/library" \
    -type f -printf '%s\n' | awk '{bytes += $1} END {printf "%.0f", bytes}')"
  printf 'binary_bytes=%s\nrust_src_bytes=%s\n' "$binary" "$sources" > "$evidence/sizes"
  check_size binary "$binary" 33554432
  check_size rust-src "$sources" 83886080
  [ "$(grep -cxF -- '  - "rust-analyzer"' "$root/src/imager/motor-os-dev.yaml")" = 1 ]
  [ "$(grep -cxF -- '  - "rust-analyzer/devtools/rust/bin/rust-analyzer"' "$root/src/imager/motor-os-dev.yaml")" = 1 ]
  for variant in without with; do
    # Only remove the analyzer overlay and its required executable; all other
    # inputs, permissions, source snapshots, and virtual capacity remain equal.
    awk -v variant="$variant" -v destination="$evidence/$variant.qcow2" \
      -v policy="$root/src/imager/motor-os-permissions.yaml" '
      /^permission_policy:/ {print "permission_policy: \"" policy "\""; next}
      /^img_name:/ {print "img_name: \"" destination "\""; next}
      variant == "without" && /^  - "rust-analyzer"$/ {next}
      variant == "without" && /^  - "rust-analyzer\/devtools\/rust\/bin\/rust-analyzer"$/ {next}
      {print}
    ' "$root/src/imager/motor-os-dev.yaml" > "$evidence/$variant.yaml"
    flock "$root/build/imager.lock" env MOTOR_ASSEMBLY_IMAGE_ROOT="$assembly" \
      "$imager" "$root" release "$evidence/$variant.yaml" > "$evidence/$variant.log" 2>&1
    qemu-img info --output=json "$evidence/$variant.qcow2" > "$evidence/$variant-info.json"
  done
  bytes_without="$(stat -c %s "$evidence/without.qcow2")"
  bytes_with="$(stat -c %s "$evidence/with.qcow2")"
  printf 'without_qcow2_bytes=%s\nwith_qcow2_bytes=%s\nqcow2_growth_bytes=%s\n' \
    "$bytes_without" "$bytes_with" "$((bytes_with - bytes_without))" >> "$evidence/sizes"
  check_size qcow2-growth "$((bytes_with - bytes_without))" 134217728
  echo "test-rust-analyzer-size PASS; evidence=$evidence"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  measure "$@"
fi
