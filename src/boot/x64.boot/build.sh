#!/bin/sh

set -e

cargo build --release -Zbuild-std=core --target boot.json \
    -Zbuild-std-features=compiler-builtins-mem

objcopy -I elf32-i386 -O binary "${CARGO_TARGET_DIR}/boot/release/boot" \
    "${MOTO_BIN}/boot.bin"
