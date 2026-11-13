# The Motor OS toolchain

Motor OS is built with a Motor OS toolchain that is built and released outside
this repository, by
[motor-os-toolchain](https://github.com/moturus/motor-os-toolchain), whose
README describes how it is built, packaged, and changed. A toolchain is named
by the Motor OS target and the Rust version it is based on, for example
`x86_64-unknown-motor-1.99.1`, and comes as two archives. This document
describes how this repository uses them. The quick start is
in [build.md](build.md), the build of the external sources and images in
[build-motor-os.md](build-motor-os.md).

## 1. The pieces

`rust-toolchain.toml` pins only the version, not a toolchain source commit or
content digest. A published release is immutable. A Motor OS-side change under
the same Rust version gets a release number, for example
`x86_64-unknown-motor-1.99.1-3`; local builds use
`x86_64-unknown-motor-1.99.1-dev`. A beta baseline may be named
`x86_64-unknown-motor-1.100.0-beta`.

The toolchain builder fetches the heads of the Rust, mlibc, motor-os-tar, and
Motor OS branches in its `versions.sh`; Rust's gitlinks select LLVM and Cargo.
Every toolchain build starts from an empty build tree and produces both archives
and their `.sha256` files next to its checkout. Published versions are
distributed as GitHub releases tagged with the version. The Motor OS checkout
builds the development programs with the new compilers for the native archive.
`build-toolchain.sh --motor-os PATH` uses an existing checkout instead of cloning
Motor OS into the toolchain build directory. Its incremental build trees stay
in that checkout.

| Piece | Where | Tracked? |
|---|---|---|
| The toolchain version | `rust-toolchain.toml` | yes |
| The Linux-host toolchain: rustc, Cargo, Clang, LLD, the host and Motor OS standard libraries, the C/C++ cross sysroot | installed from `motor-toolchain-<version>-x86_64-linux.tar.zst`, by default in `~/.local/share/motor/toolchains/<version>`, and linked into rustup | no |
| The native toolchain archive | `$MOTORH/motor-toolchain-<version>.tar.zst` | no |
| The assembly: the image overlays of the native toolchain and of the external sources, and the external sources' build trees | `build/assembly/` | no |
| External sources (Lua and wasi-sdk are releases; the others follow a fork branch or revision) | `external-sources/{ripgrep,helix,sed,motor-os-tar,javy,wasmtime,lua-<version>,wasi-sdk-<version>-x86_64-linux}` | no |
| Motor OS build outputs | `build/obj/<profile>/…` | no |
| Images | `vm_images/<profile>/` | no |

`MOTORH` defaults to the parent of the checkout. The build reads the native
archive from there and writes nothing there.

Rust std and the compiler tools use published `moto-rt`; mlibc owns the
`moto-rt-cabi` shim and its lockfile, using published `moto-rt` and `moto-sys`.
Neither build compares those versions with the runtime crates in this
checkout: `rt.vdso` checks compatibility at runtime. The toolchain
repository's [runtime-crate reference and local override guide](https://github.com/moturus/motor-os-toolchain#the-motor-runtime-crates)
describes changing them, including unpublished runtime work in a local
`--dev` build.

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
tar -xaf motor-toolchain-x86_64-unknown-motor-1.99.1-3-x86_64-linux.tar.zst
motor-toolchain-x86_64-unknown-motor-1.99.1-3-x86_64-linux/install.sh
rm -rf motor-toolchain-x86_64-unknown-motor-1.99.1-3-x86_64-linux
```

GNU tar needs the `zstd` program for `-a` with a `.zst` archive.
Each archive extracts into one directory named after the archive, containing
`install.sh` and either `toolchain/` (Linux-host payload) or `images/`
(native overlays). The host archive can be removed after installation;
keep the native archive available for image builds.
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
   libraries under `user/lib/llvm`, and the host LLVM tools (`llvm-ar`,
   `llvm-strip`, `llvm-readelf`, ...) are in
   `$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin`.
   `lorry`, `gix`, `curl`, Helix, Lua, and the tests that link C or C++ use
   them.
3. Image targets hand `build/assembly/images` to the imager as
   `MOTOR_ASSEMBLY_IMAGE_ROOT`. The image YAML lists what it takes from there
   (`assembly_dirs`, `assembly_required_executables`); the base image takes
   nothing.

The host installation follows Rust's directory layout:

```text
bin/                                           rustc, rustdoc, Cargo, Clippy,
                                               rustfmt, rust-analyzer
libexec/rust-analyzer-proc-macro-srv             host proc-macro server
lib/rustlib/x86_64-unknown-linux-gnu/lib/         host standard library
lib/rustlib/x86_64-unknown-linux-gnu/bin/         Clang, LLD, LLVM tools
lib/rustlib/x86_64-unknown-linux-gnu/lib/clang/23/ Clang resource directory
lib/rustlib/x86_64-unknown-motor/lib/             Motor OS standard library
lib/rustlib/x86_64-unknown-motor/sysroot/         cross C/C++ sysroot and wrappers
lib/rustlib/src/rust/library/                   rust-src
```

The cross wrappers find their tools and resource directory relative to
themselves, so the installation does not depend on the toolchain build's
original paths. `motor-clang` and `motor-clang++` compile and link C/C++;
`motor-rust-cc` supplies the C runtime link recipe for Rust bootstrap.

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

The standard and wasm images take the `libc` overlay's runtime configuration
under `/system/cfg/libc`. The developer image takes all four overlays:

| Path on Motor OS | Contents |
|---|---|
| `/user/lib/llvm/bin/llvm` | native Clang, LLD, and LLVM tools as one multicall executable |
| `/user/lib/llvm/{include,lib,cfg}` | C/C++ headers, static libraries, startup object, Clang resource headers and configuration |
| `/user/lib/rust/bin/` | rustc, rustfmt, clippy-driver, rust-analyzer |
| `/user/lib/rust/lib/rustlib/x86_64-unknown-motor/lib/` | complete Motor OS Rust libraries, including `.rlib` and `.rmeta` files and linker support |
| `/user/lib/rust/lib/rustlib/src/rust/library/` | matching `rust-src` for rust-analyzer |
| `/user/bin/dev/` | Rush launchers: cc, c++, ar, rustc, rustfmt, clippy-driver, rust-analyzer |
| `/none/dev/hello-world/` | C, C++, and Rust examples |

The native archive also contains Lorry, gix, mdbg, Helix, sed, Lua, QuickJS,
Javy/Wasmi, Wasmtime, the documentation site, the host imager, and configuration
defaults. Compiler launchers and mlibc use `/user/bin/rush` and `/user/bin/sh`.
The shared Cargo home is `/user/cfg/cargo`; its `config.toml` supplies Motor's
C/C++ target flags for Cargo and Lorry.

`make toolchain-archive BUILD=release` rebuilds this checkout's development
programs and repackages the selected native archive with those programs and
the staged external development overlays. It calls the packaging helper in
`../motor-os-toolchain` (`MOTOR_TOOLCHAIN_SOURCE` selects another checkout).
Outputs and scratch files stay under `build/toolchain/release`; the original
archive in `$MOTORH` is unchanged. Run `src/build-motor-os.sh` to rebuild the
external overlays when their sources change. Tests always repackage with the
current payloads and installer, including the Linux imager.

There is no native Cargo, rustdoc, separate proc-macro server, or shared
`librustc_driver`; Lorry is the native build driver. The host cross wrappers,
host standard library, and static LLVM build libraries are not image files.

## 5. Installing the native toolchain on Motor OS

The native archive installs on a running standard VM as Interactive. It puts
commands in `/user/bin/dev`, libraries in `/user/lib`, and editable examples in
`/none/dev` ([fs-permissions.md](fs-permissions.md)).

Copy the native archive into `/user/` on the VM first, then extract into an
empty directory:

```sh
mkdir /user/toolchain
cd /user/toolchain
tar -x -f /user/motor-toolchain-x86_64-unknown-motor-1.99.1-3.tar.zst
motor-toolchain-x86_64-unknown-motor-1.99.1-3/install.sh
```

`install.sh` replaces the owned library trees, installs commands through
temporary files, and preserves existing configuration and examples. It sets
programs to `rwxrwxr-x` and library data to `rwxrw-r--`, so None can use the
toolchain without changing it. mlibc's `hosts`, `services`, and `shells`
configuration stays in the image's `/system/cfg/libc`.
The installer appends `/user/bin/dev` once to the console and SSH PATH settings.
Reboot after installation to activate those settings.

`src/tests/test-native-toolchain-install.sh` installs twice on a copy of the
standard image, checks replacement of a shipped command, reboots, and builds
and runs programs with the installed tools as None. An install invalidates
Lorry's compiled dependencies, which are bound to the installed toolchain files'
sizes and modification times, so the next native build compiles them again.

## 6. Rust runtime and native formatting

<a id="rust-runtime-and-native-formatting"></a>

The selected Motor OS target defaults to `panic=unwind`. rustc,
rustfmt, rust-analyzer, and ordinary applications use the standard Motor OS
sysroots; the analyzer's private patched-library build has been retired.
Salsa cancellation and rustfmt's speculative parsing require real unwinding.
System binaries retain explicit abort profiles in both image modes;
packaged ripgrep uses its ordinary release profile and unwinds. Application
opt-out examples are in [build-rustc.md](build-rustc.md#panic-strategy-and-unwinding).

The VDSO and `moto-rt` C ABI shim build `core` and `alloc` with their own
abort profiles using `-Zbuild-std=core,alloc`. The VDSO's debug build keeps
`core`, `alloc`, and `compiler_builtins` optimized without assertions,
matching the prebuilt sysroot behavior and avoiding runtime latency growth.

Rust std registers the executable's unwind metadata finder during Motor OS's
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

Native rustfmt is built by Rust bootstrap with the compiler-private Motor OS
rlibs, packaged at `/user/lib/rust/bin/rustfmt`, and exposed through the
`/user/bin/dev/rustfmt` launcher.
Helix selects the binary through its server's `RUSTFMT` environment; see
the [editor guide](helix.md#native-rust-integration).

rustfmt searches the input directory and its ancestors, then `/user`, then
`/user/cfg/rustfmt` for `rustfmt.toml` or `.rustfmt.toml`. Motor OS ignores
`HOME` and `XDG_CONFIG_HOME` for these lookups; `dirs` and `dirs-sys` are
compiled only off Motor OS, with no additional fork. Native fixtures cover
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
run `src/build-motor-os.sh`, then the same validation gates.

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
| `src/build-scripts/validate-native-elf.sh` | the loader's requirements, checked on cross-linked Motor OS programs |
| `src/tests/test-external-sources.sh` | offline contract test of the external-source stage |
| `src/tests/test-toolchain-bootstrap.sh`, `src/tests/test-toolchain-archive.sh` | offline release-source and archive contracts |
| `src/tests/test-native-toolchain-install.sh` | the native archive installed twice on a standard VM |
