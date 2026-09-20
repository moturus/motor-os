#!/usr/bin/env bash
# Measure fresh images whose only content difference is packaged rustfmt.
set -euo pipefail

RUSTFMT_BINARY_MAX_BYTES=22020096
RUSTFMT_QCOW2_GROWTH_MAX_BYTES=22020096

check_rustfmt_size() {
  local label="$1" observed="$2" limit="$3"
  [[ "$observed" =~ ^[0-9]+$ ]] && [ "$observed" -le "$limit" ] || {
    echo "$label: observed=$observed bytes, approved maximum=$limit" >&2
    return 1
  }
}

measure_rustfmt() {
  local root assembly key imager evidence without_assembly variant variant_assembly
  local binary launcher bytes_without bytes_with growth
  root="$(cd "$(dirname "$0")/../.." && pwd)"
  assembly="$("$root/src/resolve-toolchain-assembly.sh" --resolve)"
  key="$(<"$(rustc --print sysroot)/lib/rustlib/MOTOR-TOOLCHAIN-KEY")"
  imager="$root/build/obj/$key/release/imager/release/imager"
  [ -x "$imager" ] || {
    echo 'build a release image before measuring rustfmt size' >&2
    return 1
  }
  evidence="$(mktemp -d "$root/build/rustfmt-image-growth.XXXXXX")"
  without_assembly="$evidence/without-assembly"
  binary="$(stat -c %s "$assembly/rustc/devtools/rust/bin/rustfmt")"
  launcher="$(stat -c %s "$assembly/rustc/devtools/bin/rustfmt")"
  printf 'assembly_images=%s\nbinary_bytes=%s\nlauncher_bytes=%s\n' \
    "$assembly" "$binary" "$launcher" > "$evidence/sizes"
  check_rustfmt_size rustfmt-binary "$binary" "$RUSTFMT_BINARY_MAX_BYTES"

  [ "$(grep -cxF -- '  - "rustc/devtools/bin/rustfmt"' "$root/src/imager/motor-os-dev.yaml")" = 1 ] ||
    { echo 'developer image must require the rustfmt launcher exactly once' >&2; return 1; }
  [ "$(grep -cxF -- '  - "rustc/devtools/rust/bin/rustfmt"' "$root/src/imager/motor-os-dev.yaml")" = 1 ] ||
    { echo 'developer image must require the rustfmt binary exactly once' >&2; return 1; }

  # Hard links keep every other assembly byte identical without duplicating
  # the multi-gigabyte toolchain. Removing these two links cannot alter it.
  mkdir "$without_assembly"
  cp -al "$assembly/." "$without_assembly"
  rm "$without_assembly/rustc/devtools/bin/rustfmt"
  rm "$without_assembly/rustc/devtools/rust/bin/rustfmt"
  for variant in without with; do
    awk -v variant="$variant" -v destination="$evidence/$variant.qcow2" \
      -v policy="$root/src/imager/motor-os-permissions.yaml" '
      /^permission_policy:/ {print "permission_policy: \"" policy "\""; next}
      /^img_name:/ {print "img_name: \"" destination "\""; next}
      variant == "without" && /^  - "rustc\/devtools\/bin\/rustfmt"$/ {next}
      variant == "without" && /^  - "rustc\/devtools\/rust\/bin\/rustfmt"$/ {next}
      {print}
    ' "$root/src/imager/motor-os-dev.yaml" > "$evidence/$variant.yaml"
    variant_assembly="$assembly"
    [ "$variant" = without ] && variant_assembly="$without_assembly"
    flock "$root/build/imager.lock" env MOTOR_ASSEMBLY_IMAGE_ROOT="$variant_assembly" \
      "$imager" "$root" release "$evidence/$variant.yaml" > "$evidence/$variant.log" 2>&1
    qemu-img info --output=json "$evidence/$variant.qcow2" > "$evidence/$variant-info.json"
  done
  rm -rf "$without_assembly"

  bytes_without="$(stat -c %s "$evidence/without.qcow2")"
  bytes_with="$(stat -c %s "$evidence/with.qcow2")"
  growth="$((bytes_with - bytes_without))"
  printf 'without_qcow2_bytes=%s\nwith_qcow2_bytes=%s\nqcow2_growth_bytes=%s\n' \
    "$bytes_without" "$bytes_with" "$growth" >> "$evidence/sizes"
  check_rustfmt_size rustfmt-qcow2-growth "$growth" "$RUSTFMT_QCOW2_GROWTH_MAX_BYTES"
  echo "test-rustfmt-size PASS; evidence=$evidence"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  measure_rustfmt "$@"
fi
