#!/bin/bash
set -e

TARGET_DIR="${CARGO_TARGET_DIR:-../../target}"
SCRIPT_DIR="$(dirname $(readlink -f $0))"
cd "$SCRIPT_DIR"

RUSTFLAGS="-C force-frame-pointers=yes " \
cargo build --target iort.json -Zbuild-std=core,alloc \
  -Zbuild-std-features=compiler-builtins-mem --no-default-features $@

if [[ "$1" == "--release" ]] ; then
  strip -o "${SCRIPT_DIR}/iort.vdso" "${TARGET_DIR}/iort/release/iort"
else
  strip -o "${SCRIPT_DIR}/iort.vdso" "${TARGET_DIR}/iort/debug/iort"
fi
