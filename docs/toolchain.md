# The Motor OS toolchain

Motor OS is built with a Motor toolchain that is built and released outside
this repository, by
[motor-os-toolchain](https://github.com/moturus/motor-os-toolchain), whose
README describes how it is built, packaged, and changed. A toolchain is named
by the Motor target and the Rust version it is based on, for example
`x86_64-unknown-motor-1.99.1`, and comes as two archives. This document
describes how this repository uses them. The quick start is
in [build.md](build.md), the build of the external sources and images in
[build-motor-os.md](build-motor-os.md).

## 1. The pieces

| Piece | Where | Tracked? |
|---|---|---|
| The toolchain version | `rust-toolchain.toml` | yes |
| The Linux-host toolchain: rustc, Cargo, Clang, LLD, the host and Motor standard libraries, the C/C++ cross sysroot | installed from `motor-toolchain-<version>-x86_64-linux.tar.zst`, by default in `~/.local/share/motor/toolchains/<version>`, and linked into rustup | no |
| The native toolchain archive | `$MOTORH/motor-toolchain-<version>.tar.zst` | no |
| The assembly: the image overlays of the native toolchain and of the external sources, and the external sources' build trees | `build/assembly/` | no |
| External sources (Lua and wasi-sdk are releases; the others follow a fork branch or revision) | `external-sources/{ripgrep,helix,sed,motor-os-tar,javy,wasmtime,lua-<version>,wasi-sdk-<version>-x86_64-linux}` | no |
| Motor OS build outputs | `build/obj/<profile>/…` | no |
| Images | `vm_images/<profile>/` | no |

`MOTORH` defaults to the parent of the checkout. The build reads the native
archive from there and writes nothing there.

## 2. Installing a toolchain

The host installer requires rustup on `PATH` before it copies the toolchain.
If rustup is not installed yet, install it without selecting a default:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
  sh -s -- -y --default-toolchain none
. "$HOME/.cargo/env"
```

Download the two archives of the version `rust-toolchain.toml` names from the
toolchain repository's release of that version into `$MOTORH`, or build them
with its `build-toolchain.sh`, which writes them next to its checkout: in
`$MOTORH` when the checkout is there. Then install the host toolchain:

```sh
cd "$MOTORH"
tar -xaf motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst
motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux/install.sh
rm -rf motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux
```

GNU tar needs the `zstd` program for `-a` with a `.zst` archive.
`install.sh` copies the toolchain to its installation directory (`--prefix
DIR` selects another one) and runs `rustup toolchain link`, so the unpacked
archive is not needed afterwards. The native archive stays where it is:
`src/build-motor-os.sh` unpacks its overlays into the assembly on every run.

## 3. How everyday commands find the toolchain

1. `rust-toolchain.toml` names the toolchain. rustup resolves `cargo`,
   `rustc`, `rustfmt`, and `rust-analyzer` to its installation. No
   `+channel` selectors are used anywhere.
2. Everything else follows from the sysroot: the cross sysroot is
   `$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-motor/sysroot`, with
   `bin/motor-clang` and `bin/motor-clang++` and the C/C++ headers and
   libraries under `devtools/llvm`, and the host LLVM tools (`llvm-ar`,
   `llvm-strip`, `llvm-readelf`, ...) are in
   `$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin`.
   `lorry`, `gix`, `curl`, Helix, Lua, and the tests that link C or C++ use
   them.
3. Image targets hand `build/assembly/images` to the imager as
   `MOTOR_ASSEMBLY_IMAGE_ROOT`. The image YAML lists what it takes from there
   (`assembly_dirs`, `assembly_required_executables`); the base image takes
   nothing.

## 4. The assembly

`src/build-motor-os.sh` fills `build/assembly/`, which `make clean` removes
with the rest of `build/`:

- the external sources, built with the toolchain on every run: Lua,
  ripgrep, Helix, uutils sed, tar and zstd, Javy with Wasmi, and Wasmtime,
  with their Cargo target directories, and the dependencies of the developer
  image's library sources;
- the native toolchain's overlays `llvm`, `rustc`, `rust-analyzer`, and
  `libc`, unpacked from the native archive with motor-os-tar's `tar` built
  for Linux on every run, so a replaced archive takes effect.

Every toolchain overlay carries the toolchain's manifest as
`devtools/toolchain/manifest`; the developer image exposes it as
`/devtools/toolchain/manifest`.

## 5. Installing the native toolchain on Motor OS

The native archive also installs on a running developer VM. `/devtools`
belongs to the Interactive role ([fs-permissions.md](fs-permissions.md)), so
an ordinary session can replace the toolchain there:

```sh
mkdir /user/toolchain
cd /user/toolchain
tar -x -f motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst
motor-toolchain-x86_64-unknown-motor-1.99.1/install.sh
```

`install.sh` replaces `/devtools/llvm` and `/devtools/rust`, copies the
launchers, the examples, and the manifest, and refuses to replace a
different toolchain without `--replace`. It then makes the programs
executable by every role, and the launchers editable by Interactive as well,
as they are on the image. The developer-image suite does exactly this on a
copy of the image, in
`src/tests/test-native-toolchain-install.sh`, and builds and runs programs
with what was installed. An install invalidates Lorry's compiled
dependencies, which are bound to the installed toolchain files' sizes and
modification times, so the next native build compiles them again.

## 6. Rust runtime and native formatting

The selected Motor target defaults to `panic=unwind`. rustc,
rustfmt, rust-analyzer, and ordinary applications use the standard Motor
sysroots; the analyzer's private patched-library build has been retired.
Salsa cancellation and rustfmt's speculative parsing require real unwinding.
System binaries retain explicit abort profiles in both image modes;
packaged ripgrep uses its ordinary release profile and unwinds. Application
opt-out examples are in [build-rustc.md](build-rustc.md#panic-strategy-and-unwinding).

The VDSO and `moto-rt` C ABI shim build `core` and `alloc` with their own
abort profiles using `-Zbuild-std=core,alloc`. The VDSO's debug build keeps
`core`, `alloc`, and `compiler_builtins` optimized without assertions,
matching the prebuilt sysroot behavior and avoiding runtime latency growth.

Rust std registers the executable's unwind metadata finder during Motor's
`std::rt::init`. For mlibc-linked binaries it also registers through
`.init_array.00001`, before ordinary C++ static constructors can throw.
Both entry paths must keep this registration. The finder reads static ELF
metadata without allocation, locks, or I/O. A static library with neither
the Rust entry path nor constructors has no standalone initialization.

In Rust-linked programs containing C++, the pure Rust unwinder owns the
`_Unwind_*` ABI for both languages. Rust rlibs precede the driver's library
group, so libunwind's competing implementation is not extracted. Pure C/C++
programs use LLVM libunwind. Native rustc, rustfmt, and rust-analyzer must
define `_Unwind_RaiseException` exactly once and contain no `__unw_` symbols.

The finder requires static PIEs linked at nominal address zero, with the
ELF and program headers mapped in the first readable `PT_LOAD` at file
offset zero. `__ehdr_start` then gives the load bias. `PT_GNU_EH_FRAME`
must lie entirely inside a readable load segment. Host cross-links through
GNU ld and native/clang links through LLD both satisfy this layout; custom
linker scripts that move the headers are unsupported. The toolchain build
checks this layout, unwind-provider symbols, constructors, unwind sections,
and static-PIE protections on its native tools, and
`src/build-scripts/validate-native-elf.sh` checks the same of Motor OS
programs linked through the cross sysroot.
`src/tests/test-unwind.sh` validates its own binaries and exercises both
entry paths, abort and fat-LTO builds, and Rust/C++ destructor propagation.

Native rustfmt is built by Rust bootstrap with the compiler-private Motor
rlibs, packaged at `/devtools/rust/bin/rustfmt`, and exposed through the
`/devtools/bin/rustfmt` launcher.
Helix selects the binary through its server's `RUSTFMT` environment; see
the [editor guide](helix.md#native-rust-integration).

rustfmt searches the input directory and its ancestors, then `/user`, then
`/user/cfg/rustfmt` for `rustfmt.toml` or `.rustfmt.toml`. Motor ignores
`HOME` and `XDG_CONFIG_HOME` for these lookups; `dirs` and `dirs-sys` are
compiled only off Motor, with no additional fork. Native fixtures cover
project and user configuration, ignored environment settings, editions, macros,
and parser/lexer-error recovery. The size gates bound both the stripped
formatter and its fresh-image growth at 21 MiB. Runtime, editor, and size
gates are wired into `src/tests/full-test.sh`, with native formatting and
editor cases in its developer-image branch.


## 7. Changing the toolchain

1. Get the new version's two archives: a release, or a local build of the
   toolchain repository, which `--dev` names `<version>-dev`.
2. With both archives in `$MOTORH`, install the host archive.
3. Put the version into `rust-toolchain.toml`.
4. Run `make clean`, which removes all build artifacts, then
   `src/build-motor-os.sh`, which builds the external sources and the images
   again with the new toolchain.
5. Because the standard library of every OS binary changes, run the core
   gate from AGENTS.md: three debug and three release runs of
   `src/tests/full-test.sh`, then `src/tests/full-test-dev.sh --release`.
6. Commit `rust-toolchain.toml` with any changes the new version needed.

An archive rebuilt under the same name, as a local `-dev` build is, is a
toolchain change too: install the host archive again, run `make clean`, and
run `src/build-motor-os.sh`.

## 8. Failures you will see, and what they mean

- `rustc is not on PATH` (Makefile): the build script installed rustup, and
  the shell it was started from still has the old `PATH`. Open a new shell or
  run `. "$HOME/.cargo/env"`.
- rustup's `toolchain '<version>' is not installed`: install the host
  archive of the version `rust-toolchain.toml` names.
- `the native toolchain archive is missing`: put
  `motor-toolchain-<version>.tar.zst` in `$MOTORH`.
- `static image directory ".../build/assembly/images/..." is absent` (imager):
  run `src/build-motor-os.sh`, which builds the assembly.
- `make` ends every failed build with a `BUILD FAILED` summary naming the
  failed recipe and pointing at `build/make-last.log`.

## 9. File map

| File | Role |
|---|---|
| `rust-toolchain.toml` | the toolchain version |
| `src/build-motor-os.sh`, `src/build-scripts/build-base.sh` | the external sources, the native toolchain's overlays, and the images; host provisioning |
| `src/build-scripts/external-sources.sh`, `src/build-scripts/build-javy.sh`, `src/build-scripts/build-wasmtime.sh` | the external sources' checkouts, and Javy and Wasmtime |
| `src/build-scripts/validate-native-elf.sh` | the loader's requirements, checked on cross-linked Motor programs |
| `src/tests/test-external-sources.sh` | offline contract test of the external-source stage |
| `src/tests/test-native-toolchain-install.sh` | the native archive installed on a developer VM |
