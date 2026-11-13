#!/usr/bin/env bash
# Repackage the selected release with current development payloads, under build/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
profile="${1:-}"
case "$profile:$#" in
    debug:1|release:1) ;;
    *) echo "usage: $0 debug|release" >&2; exit 2 ;;
esac
source "$ROOT/src/build-scripts/toolchain-overlays.sh"
toolchain_root="${MOTOR_TOOLCHAIN_SOURCE:-$ROOT/../motor-os-toolchain}"
source "$toolchain_root/lib/toolchain-package.sh"
name="$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' "$ROOT/rust-toolchain.toml")"
release="$(realpath "${MOTORH:-$ROOT/..}")/motor-toolchain-$name.tar.zst"
[ -f "$release" ] || { echo "toolchain: release archive missing: $release" >&2; exit 1; }
tar="$ROOT/build/assembly/build/motor-os-tar-linux/release/tar"
[ -x "$tar" ] || { echo "toolchain: build the host archive tool first: $tar" >&2; exit 1; }
output="$ROOT/build/toolchain/$profile"
mkdir -p "$output"
work="$(mktemp -d "$output/.repackage.XXXXXX")"
trap 'rm -rf "$work"' EXIT
"$tar" -x -f "$release" -C "$work"
original="$work/motor-toolchain-$name"
toolchain_validate_images "$original/images"
toolchain_collect_overlays "$ROOT" "$ROOT/build/bin/$profile" \
    "$ROOT/build/assembly/images" "$ROOT/build/bin/$profile/imager" "$work/current"
for overlay in "${MOTOR_TOOLCHAIN_OVERLAYS[@]}"; do
    rm -rf "$original/images/$overlay"
    mv "$work/current/$overlay" "$original/images/$overlay"
done
toolchain_package "$tar" "$output" "$name" "$original/images"
printf '%s\n' "$output/motor-toolchain-$name.tar.zst"
