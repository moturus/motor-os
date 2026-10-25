# LLVM, mlibc, and the Motor C/C++ toolchain

LLVM/Clang, mlibc, and the C++ runtime are part of the Motor toolchain, which
[motor-os-toolchain](https://github.com/moturus/motor-os-toolchain) builds
and packages; its README describes the build. This document describes what
the toolchain provides for C and C++ on Linux and on Motor OS.

## Sources

The current toolchain, `x86_64-unknown-motor-1.99.1`, is Rust 1.99.1 on LLVM
23.1.1:

- Motor LLVM (branch `motor-os-1.99.1`), at the commit that the Motor Rust
  branch's `src/llvm-project` gitlink names, so the host compilers and rustc's
  LLVM come from the same commit;
- Motor mlibc (branch `motor-os-rustc`), including its C-ABI shim and
  lockfile.

The toolchain repository's `versions.sh` names the Rust and mlibc branches,
and the build takes their heads.

Executable-permission support is a cross-repository compatibility boundary.
This toolchain combines the Motor OS fd wrapper descended from `fb4d6989`,
mlibc with the permission support from `0cece7e5`, and LLVM `606d4754c103`
(the 1.99.1-line rebase of `7c2a7b21e3dc`, a cherry-pick of `bc769e6e44a4`).
Do not mix an older shim, libc, or linker binary into a toolchain: a new
output may remain writable or Cargo's copied build scripts may become
non-executable.

mlibc `39d67d64` leaves main-executable relocation to Motor's loader, avoiding
redundant startup passes that would make lazily relocated pages resident.
Commit `52bed56c` additionally maps Motor's `CrossesDevices` error to `EXDEV`.
Commit `9abf5139` hosts the `moto-rt-cabi` shim crate and its lockfile.

## What the toolchain contains

The toolchain build produces, in dependency order:

1. Standalone Linux-host Clang, LLD, and LLVM utilities for the Motor target.
2. `libmoto_rt_cabi.a`, the Rust C-ABI shim over Motor's RT.VDSO, including
   the emulated-TLS runtime, from `sysdeps/motor/moto-rt-cabi` in mlibc.
3. compiler-rt builtins, with the shim remaining the sole emulated-TLS owner.
4. mlibc headers, `crt1.o`, `libc.a`, and companion libraries.
5. libunwind, libc++abi, and libc++, with exceptions enabled.
6. Native Motor LLVM/Clang/LLD as one multicall `llvm` executable.

On Linux, the host toolchain carries Clang, LLD, and the LLVM tools in
`lib/rustlib/x86_64-unknown-linux-gnu/bin`, and the cross sysroot in
`lib/rustlib/x86_64-unknown-motor/sysroot`:

```text
sysroot/bin/              motor-clang, motor-clang++, motor-rust-cc
sysroot/devtools/llvm/    headers and libraries
```

`motor-clang` and `motor-clang++` compile and link C and C++ for Motor OS;
the Motor OS build uses them for Lua, Helix's C++ grammars, gix, curl, and
Lorry.

## Development-image layout

The development image contains:

```text
/devtools/llvm/bin/llvm       native LLVM/Clang/LLD multicall binary
/devtools/llvm/include/       C and C++ headers
/devtools/llvm/lib/           mlibc, compiler-rt, and C++ libraries
/devtools/llvm/cfg/           clang target configuration
/devtools/bin/cc              C compiler/linker launcher
/devtools/bin/c++             C++ launcher
/system/cfg/libc/             mlibc runtime configuration
```

Examples inside the development VM:

```sh
cc /devtools/src/hello-world/hello.c -o /user/tmp/hello
/user/tmp/hello

c++ /devtools/src/hello-world/hello.cpp -o /user/tmp/hello-cxx
/user/tmp/hello-cxx

/devtools/llvm/bin/llvm clang --version
```

Clang's Motor toolchain owns the C/C++ startup and runtime link recipe. Plain C
and C++ programs receive `crt1.o`, mlibc, compiler-rt, and the appropriate C++
libraries. `-nostdlib`, `-nostartfiles`, and `-nodefaultlibs` remain meaningful
so rustc can produce a pure-Rust binary without pulling in mlibc.

A newer native toolchain installs over the image's with the `install.sh` of
its archive; see [toolchain.md](toolchain.md#5-installing-the-native-toolchain-on-motor-os).
