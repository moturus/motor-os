# LLVM, mlibc, and the Motor C/C++ toolchain

LLVM/Clang, mlibc, and the C++ runtime are built by the unified
`src/build-motor-os.sh` workflow. This document describes that component and
its outputs; it is not a separate branch-switching or cache-clearing recipe.

## Source identity

The current beta tuple is declared in `src/toolchain-versions.sh`:

- upstream Rust LLVM base `21cf28432798952d942bacc6bcee3a328faa3638`;
- Motor LLVM `2dcc671e2eb723ef61a664bde9823fbe880e4e19`;
- Motor mlibc `62f9495700537ded14a2a6fae9373227fe5ec5ca`.

The Motor Rust revision's `src/llvm-project` gitlink must equal the declared
Motor LLVM revision. The standalone host compiler and rustc's host/native LLVM
builds therefore consume the same effective LLVM commit and source tree. A
managed build rejects a mismatched gitlink, remote, revision, or dirty checkout.

LLVM changes are tested through the Rust checkout that owns the submodule:

```sh
src/build-motor-os.sh \
  --source-mode authoring \
  --rust-source /absolute/path/to/rust \
  --authoring-base FULL_40_CHARACTER_BASE_COMMIT
```

Authoring mode hashes the current Rust and LLVM commits plus modified and
untracked content. It does not fetch, switch, reset, stash, clean, or update
either worktree.

## Build graph

The unified workflow builds this closure in dependency order:

1. Standalone Linux-host Clang, LLD, and LLVM utilities for the Motor target.
2. `libmoto_rt_cabi.a`, the Rust C-ABI shim over Motor's RT.VDSO, including the
   emulated-TLS runtime.
3. compiler-rt builtins, with the shim remaining the sole emulated-TLS owner.
4. mlibc headers, `crt1.o`, `libc.a`, and companion libraries.
5. libunwind, libc++abi, and libc++, with exceptions enabled.
6. Native Motor LLVM/Clang/LLD as one multicall `llvm` executable.
7. Lua as an end-to-end native C application.

All reusable products live under the selected assembly key:

```text
$MOTORH/assemblies/<assembly-key>/
  build/                 isolated component build trees
  sysroot/devtools/llvm/ headers and libraries
  sysroot/bin/           motor-clang, motor-clang++, motor-rust-cc
  images/llvm/           native LLVM and development-image files
  images/libc/           mlibc configuration for standard/dev images
```

No component writes the old shared `$MOTORH/motor-sysroot`, sibling LLVM build
directory, `src/sys/target`, or tracked `img_files` trees. A complete assembly
is reused only after its manifest and required artifacts validate. A change to
LLVM, mlibc, the local runtime closure, or native configuration selects a new
key rather than deleting the old tree.

## Development-image layout

The development image contains:

```text
/devtools/llvm/bin/llvm       native LLVM/Clang/LLD multicall binary
/devtools/llvm/include/       C and C++ headers
/devtools/llvm/lib/           mlibc, compiler-rt, and C++ libraries
/devtools/cfg/llvm/           clang target configuration
/devtools/bin/cc              C compiler/linker launcher
/devtools/bin/c++             C++ launcher
/system/cfg/libc/             mlibc runtime configuration
```

Examples inside the development VM:

```sh
cc /devtools/src/hello.c -o /user/tmp/hello
/user/tmp/hello

c++ /devtools/src/hello.cpp -o /user/tmp/hello-cxx
/user/tmp/hello-cxx

/devtools/llvm/bin/llvm clang --version
```

Clang's Motor toolchain owns the C/C++ startup and runtime link recipe. Plain C
and C++ programs receive `crt1.o`, mlibc, compiler-rt, and the appropriate C++
libraries. `-nostdlib`, `-nostartfiles`, and `-nodefaultlibs` remain meaningful
so rustc can produce a pure-Rust binary without pulling in mlibc.

## Build and validation

Build or validate the complete managed tuple:

```sh
src/build-motor-os.sh --source-mode managed
```

The workflow checks the standalone/native LLVM identities, required symbols,
mlibc and C++ artifacts, linker wrappers, and the completed assembly manifest
before it exposes generated image roots. The final development image and
`$MOTORH/assemblies/<assembly-key>/MOTOR-ASSEMBLY-MANIFEST` record the exact
LLVM, mlibc, runtime, and artifact identities.

Run the repository integration gates after changes:

```sh
src/tests/full-test.sh
src/tests/full-test.sh --release
```

Do not recreate the removed `dev-x86_64-unknown-motor` toolchain, manually
switch sibling branches, or clear shared caches. Update a managed source only
through a reviewed revision/ref change in `src/toolchain-versions.sh`; local
Rust/LLVM work belongs in authoring mode.
