#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD=debug
if [ "${1:-}" = --release ]; then
  BUILD=release
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--release]" >&2
  exit 2
fi
BIN_DIR="$ROOT_DIR/build/bin/$BUILD"
TEST_DIR="$(mktemp -d)"
trap 'rm -r "$TEST_DIR"' EXIT

# The staged ELF must be stripped, including when Cargo retains debug info.
sections="$(readelf -SW "$BIN_DIR/kloader")"
if printf '%s\n' "$sections" | awk '
  /[[:space:]]\.(debug_[^[:space:]]*|symtab|strtab)[[:space:]]/ { found = 1 }
  END { exit !found }
'; then
  echo "test-kloader-image: staged ELF still contains debug information or symbols" >&2
  exit 1
fi

# Stripping must preserve the embedded kernel byte for byte.
objcopy -O binary --only-section=.kernel_image \
  "$BIN_DIR/kloader" "$TEST_DIR/kernel"
cmp "$BIN_DIR/kernel" "$TEST_DIR/kernel"

echo "test-kloader-image ($BUILD) PASS"
