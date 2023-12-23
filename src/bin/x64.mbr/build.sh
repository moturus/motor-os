#!/bin/sh

set -e

cargo build --release -Zbuild-std=core --target mbr.json \
    -Zbuild-std-features=compiler-builtins-mem

objcopy -I elf32-i386 -O binary "${CARGO_TARGET_DIR}/mbr/release/mbr" \
    "${MOTO_BIN}/mbr.bin"

