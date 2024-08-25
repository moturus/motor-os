# First Stage: Bootsector

Cloned from https://github.com/rust-osdev/bootloader/tree/main/bios/boot_sector

This executable needs to fit into the 512-byte boot sector, so we need to use all kinds of tricks to keep the size down.

## Build Commands

1. `cargo build --release -Zbuild-std=core --target mbr.json -Zbuild-std-features=compiler-builtins-mem
2. `objcopy -I elf32-i386 -O binary target/mbr/release/mbr target/mbr.bin
