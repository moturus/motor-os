#!/bin/bash
set -e

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN_DIR="${MOTO_BIN:-target}"

SCRIPT_DIR="$(dirname $(readlink -f $0))"
cd "$SCRIPT_DIR"

# The kernel ELF is embedded (see layout.ld), so it must be built first.
export MOTO_KERNEL_ELF="${MOTO_KERNEL_ELF:-${BIN_DIR}/kernel}"
if [[ ! -f "$MOTO_KERNEL_ELF" ]] ; then
    echo "kloader: kernel not found at $MOTO_KERNEL_ELF; build the kernel first"
    exit 1
fi

# kloader.bin (the flat image for the BIOS path) takes every allocated
# section except .kernel_image. Listing them is what keeps objcopy from
# padding the output up to the removed section's segment.
flat_sections() {
    readelf -S --wide "$1" | sed 's/\[ *\([0-9]*\)\]/[\1]/' |
        awk '$1 ~ /^\[[0-9]+\]$/ && $8 ~ /A/ && $2 != ".kernel_image" { printf "-j %s ", $2 }'
}

# A section the linker placed after .kernel_image would drag the flat image
# out to 34 MB, and a read-only one right before it would put the 33 MB gap
# into the ELF; layout.ld orders the known sections to avoid both.
check_sizes() {
    if [[ "$(stat -c %s "${BIN_DIR}/kloader.bin")" -ge $((1 << 20)) ]] ; then
        echo "kloader: kloader.bin is over 1 MB: a section follows .kernel_image (see layout.ld)"
        exit 1
    fi
    if [[ "$(stat -c %s "${BIN_DIR}/kloader")" -ge $((4 << 20)) ]] ; then
        echo "kloader: the kloader ELF is over 4 MB: .kernel_image shares a segment (see layout.ld)"
        exit 1
    fi
}

if [[ $# == 0 ]] ; then

echo "kloader debug build"

RUSTFLAGS="-C force-frame-pointers=yes " \
cargo build --target kloader.json -Zjson-target-spec \
    -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
    --color=always 2>&1

cargo clippy --target kloader.json -Zjson-target-spec \
    -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
    --color=always 2>&1

# The binary is used inside initd.
objcopy -I elf64-x86-64 -O binary $(flat_sections "${TARGET_DIR}/kloader/debug/kloader") \
    "${TARGET_DIR}/kloader/debug/kloader" "${BIN_DIR}/kloader.bin"

# Stage a stripped ELF for the VMM; retain symbols in the Cargo artifact.
strip -o "${BIN_DIR}/kloader" "${TARGET_DIR}/kloader/debug/kloader"
check_sizes

elif [[ $# != 1 ]] ; then

echo "kloader build.sh takes no or a single '--release' parameter"
exit 1

elif [[ "$1" != "--release" ]] ; then

echo "kloader build.sh takes no or a single '--release' parameter"
exit 1

else

echo "kloader release build"


cargo build --release --no-default-features --target kloader.json -Zjson-target-spec \
    -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
    --color=always 2>&1

cargo clippy --release --no-default-features --target kloader.json -Zjson-target-spec \
    -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
    --color=always 2>&1

# The binary is used inside initd.
objcopy -I elf64-x86-64 -O binary $(flat_sections "${TARGET_DIR}/kloader/release/kloader") \
    "${TARGET_DIR}/kloader/release/kloader" "${BIN_DIR}/kloader.bin"

# Stage a stripped ELF for the VMM; retain the original Cargo artifact.
strip -o "${BIN_DIR}/kloader" "${TARGET_DIR}/kloader/release/kloader"
check_sizes

fi

echo "kloader done"
