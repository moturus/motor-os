#!/bin/bash
set -e

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN_DIR="${MOTO_BIN:-target}"

SCRIPT_DIR="$(dirname $(readlink -f $0))"
cd "$SCRIPT_DIR"

if [[ $# == 0 ]] ; then

echo "kloader debug build"

RUSTFLAGS="-C force-frame-pointers=yes " \
cargo build --target kloader.json \
    -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
    --color=always 2>&1

cargo clippy --target kloader.json \
    -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
    --color=always 2>&1

# The binary is used inside initd.
objcopy -I elf64-x86-64 -O binary "${TARGET_DIR}/kloader/debug/kloader" \
    "${BIN_DIR}/kloader.bin"

# The elf file is used by cloud-hypervisor as the bootloader.
cp "${TARGET_DIR}/kloader/debug/kloader" "${BIN_DIR}/kloader"

elif [[ $# != 1 ]] ; then

echo "kloader build.sh takes no or a single '--release' parameter"
exit 1

elif [[ "$1" != "--release" ]] ; then

echo "kloader build.sh takes no or a single '--release' parameter"
exit 1

else

echo "kloader release build"


cargo build --release --no-default-features --target kloader.json \
    -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
    --color=always 2>&1

cargo clippy --release --no-default-features --target kloader.json \
    -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
    --color=always 2>&1

# The binary is used inside initd.
objcopy -I elf64-x86-64 -O binary "${TARGET_DIR}/kloader/release/kloader" \
    "${BIN_DIR}/kloader.bin"

# The elf file is used by cloud-hypervisor as the bootloader.
cp "${TARGET_DIR}/kloader/release/kloader" "${BIN_DIR}/kloader"

fi

echo "kloader done"

