#!/bin/bash
set -e

TARGET_DIR="${CARGO_TARGET_DIR:-../../target}"
SCRIPT_DIR="$(dirname $(readlink -f $0))"
cd "$SCRIPT_DIR"

RUSTFLAGS="-C force-frame-pointers=yes " \
cargo build --target rt.json -Zbuild-std=core,alloc \
  -Zbuild-std-features=compiler-builtins-mem --no-default-features $@

if [[ "$1" == "--release" ]] ; then
  strip -o "${SCRIPT_DIR}/rt.vdso" "${TARGET_DIR}/rt/release/rt"
else
  strip -o "${SCRIPT_DIR}/rt.vdso" "${TARGET_DIR}/rt/debug/rt"
fi
