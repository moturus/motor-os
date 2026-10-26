# A standalone Motor OS toolchain build

Status: in progress (2026-10-25; proposed 2026-10-22). Steps 0 to 2 are
complete; steps 3 and 4 are implemented and passed one release run of each
full-test suite. Section 6 lists what remains. This document
records the dependency audit of the current toolchain build and a
high-level design for building the toolchain outside the Motor OS
repository.

## Goal

One shell script, living outside the Motor OS repository, that:

- fetches the moturus forks of Rust (with its LLVM and Cargo gitlinks) and
  mlibc from `github.com/moturus/`, and never the Motor OS repository;
- takes its Motor runtime crates from crates.io;
- builds the archive tools from the separate `moturus/motor-os-tar` repository;
- builds the complete toolchain: the Linux-host cross toolchain
  (rustc, Cargo, Clang, LLD, Motor std, C/C++ sysroot) and the native
  Motor OS toolchain (rustc, rustfmt, clippy-driver, rust-analyzer, the
  LLVM multicall, headers and libraries);
- packages the result as tar files that can be distributed and consumed
  without the build host, by the Motor OS repository and by third parties.

The toolchain is named `x86_64-unknown-motor-1.99.1`, the Motor target
triple followed by the Rust version. That name is the rustup toolchain
name, the archive name, the install directory, and what the Motor OS
repository pins. There are no content-derived keys.

The userspace programs that `build-motor-os.sh` builds after the toolchain
(Lua, ripgrep, Helix, uutils sed, Javy with Wasmi, Wasmtime: the external
sources) are not part of the toolchain
and stay where they are.

## 1. Audit: what the toolchain build takes from where

The toolchain build today is in `src/build-motor-os.sh` with the
`src/toolchain-*.sh` helpers. Its toolchain inputs, by origin:

| Input | Origin today | Status for a standalone build |
|---|---|---|
| Rust fork (`moturus/rust`) with the Motor LLVM and upstream Cargo gitlinks | GitHub | fine |
| mlibc fork (`moturus/mlibc`, `sysdeps/motor`), including the C ABI shim crate `sysdeps/motor/moto-rt-cabi` with its `Cargo.lock` and `moto_rt.h` | GitHub | fine (since mlibc `9abf5139`, Motor OS commit `a3d739f9`) |
| mlibc's Meson dependencies: `frigg`, `libsmarter`, freestanding C and C++ headers | GitHub, selected by mlibc's wrap files | fine; fetched as part of the mlibc build |
| Rust submodules: `library/backtrace`, `src/doc/book`, `src/doc/reference`, `src/tools/rustc-perf`, `src/tools/cargo` | `github.com/rust-lang` | fine; inherent to building Rust |
| Stage 0 bootstrap compiler | `static.rust-lang.org`, selected by the fork's `src/stage0` | fine; inherent to building Rust |
| Compiler-workspace forks: `libc`, `rust_libloading`, `stacker`, `rust-ctrlc` | `github.com/moturus` via the fork's lockfile | fine |
| `moto-rt` 0.17.9 (Rust std's Motor runtime, and the shim's) | crates.io, pinned by the fork's `library/Cargo.lock` and by the shim's `Cargo.lock` | fine |
| `moto-sys` 0.3.2 (the shim's) | crates.io, pinned by the shim's `Cargo.lock` | fine |
| rust-analyzer patched crates: `url` 2.5.8 and `inventory` 0.3.24 | crates.io archives, patched with `src/patches/*.patch` | patches must move out of the Motor OS repository |
| Content-digest helper `src/toolchain-content-tree` | local checkout | goes away with the content keys |
| `src/toolchain-versions.sh`, the declaration of the source tuple | local checkout | moves; the Motor OS repository then pins a toolchain version instead |
| Host packages: clang, cmake, ninja, meson, python3, nasm, zlib, openssl, pkg-config, curl, rustup | apt | fine; QEMU and the tap network are not toolchain inputs |

Step 1 adds `moturus/motor-os-tar` as another GitHub input. The toolchain builder
builds its Linux `tar` for packaging; the Motor OS build builds the same
source for Linux image preparation and builds native `tar` and `zstd` for
the images. Neither build takes these tools from a Motor OS source path.

**No toolchain input comes from the Motor OS checkout any more.** Until
`a3d739f9` the C ABI shim (`libmoto_rt_cabi.a` and `moto_rt.h`) was built
from `src/sys/lib/moto-rt-cabi` against the local `moto-rt` and `moto-sys`
by path, which was the one blocking local dependency. The shim now lives in
the mlibc fork: its `Cargo.toml` names `moto-rt = "0.17.9"` (feature `libc`)
and `moto-sys = "0.3.2"` from the registry, its `Cargo.lock` is committed,
its `build.rs` emits a compile-time assertion that `MOTO_RT_VERSION` in
`moto_rt.h` equals `moto_rt::RT_VERSION` of the dependency actually
selected, and it is marked `publish = false`. The toolchain builder
snapshots the pinned mlibc revision with `git archive`, runs
`cargo fetch --locked` and then an offline `-Zbuild-std=core,alloc` build
in that snapshot, and takes the header from the same snapshot. The
published `moto-sdk` crate is not a toolchain input.

What remains local in the toolchain stages is build infrastructure, plus
two references to the checkout that a standalone build cannot keep:

- the `moto-rt` major-version compatibility check in `toolchain-runtime.sh`,
  which compares std's locked `moto-rt` against `src/sys/lib/moto-rt`; it
  protects the Motor OS tree, not the toolchain;
- the Motor OS revision used for the toolchain build, recorded for provenance.

Everything else that looks local is not an input: mlibc's sysdeps include
`moto_rt.h` from the same mlibc tree; the LLVM fork's Motor driver
(`Motor.cpp`) hard-codes the `/devtools/llvm` layout itself; Rust std links
the crates.io `moto-rt`; the fork's bootstrap carries its own Motor target
logic.

What the Motor OS repository consumes from the toolchain, and must keep
getting from the packaged form:

- the rustup-linked host prefix, found through `rust-toolchain.toml`, with
  `rust-src` for the `-Zbuild-std` boot and kernel builds;
- the cross sysroot: `motor-clang`, `motor-clang++`, `motor-rust-cc`, the
  headers and static libraries under `sysroot/devtools/llvm`, used by
  `lorry`, `gix`, `curl`, Helix, and `test-unwind.sh`;
- the image overlays `images/{llvm,rustc,rust-analyzer,libc}`, listed by
  the imager YAML files through `assembly_dirs`;
- the standalone LLVM `bin` directory, which the external-source builds use for
  `llvm-ar`, `llvm-strip`, `llvm-readelf`, and the Lua C build.

Today these are found through two content-derived identities: the
toolchain key (a hash of the Rust and LLVM commits and build
configuration, stamped into the prefix as `MOTOR-TOOLCHAIN-KEY`, which the
Makefile keys object directories on) and the assembly key (toolchain key
plus mlibc commit and native configuration, naming `assemblies/<key>`,
which `resolve-toolchain-assembly.sh` derives). The design below replaces
both with the version name.

## 2. Design

### 2.1 Identity: a version, not a key

The toolchain is `x86_64-unknown-motor-<rust version>`, for example
`x86_64-unknown-motor-1.99.1`. The version is the upstream Rust version
the fork is based on; the first release targets 1.99.1 (step 0 in
section 5). A pre-release built from upstream's beta branch is
`x86_64-unknown-motor-1.100.0-beta`. Both
`x86_64-unknown-motor-1.99.1` and `x86_64-unknown-motor-1.99.1-2` were
accepted by `rustup toolchain link` with rustup 1.29.1; the previous
version-first name was rejected as a custom toolchain name.

The declaration (today `src/toolchain-versions.sh`, then `versions.sh`)
names the repositories and the Rust, mlibc, and tar branches whose heads
are built (the Rust gitlinks select LLVM and Cargo), and drops `MOTOR_TOOLCHAIN_ID`,
`MOTOR_RUSTUP_TOOLCHAIN_BASE`, the key schemas, and the key derivation.

A published version is immutable. If a Motor-side input (mlibc, the LLVM
fork, a build recipe) must change after publication under the same Rust
version, that is a new release of the toolchain and needs a distinguishable
name; see section 4. Local builds may be replaced explicitly as in 2.4.

### 2.2 Repositories and ownership

A new repository, `moturus/motor-os-toolchain`, holds the build. Its name
does not matter to any script:
no file in Motor OS refers to it, a person clones it by hand and runs its
entry point, and everything downstream works from the version name alone.
It contains:

- `build-toolchain.sh`, the single entry point, and the existing
  `toolchain-*.sh` helpers moved from `src/`, minus the key derivation
  and the content-tree digests;
- `versions.sh`, the source tuple (today `src/toolchain-versions.sh`);
- `patches/` for the rust-analyzer crate patches;
- a README that replaces the toolchain build parts of `docs/toolchain.md`,
  `docs/build-motor-os.md`, `docs/build-llvm.md`, and `docs/build-rustc.md`,
  including the runtime-crate reference list and local-override procedure
  of 2.9.

It has no tests of its own (decided 2026-10-25): the build itself and the
Motor OS tests that use its archives are its validation.

The Motor OS repository keeps `rust-toolchain.toml`, the Makefile, the
imager YAML fields, the external-source builds, the images, and the VM tests.

A separate new repository, `moturus/motor-os-tar`, holds the Rust archive tools.
Both the toolchain builder and the Motor OS builder fetch and build them
from there. Creating this repository is part of step 1; the tools do not
live in Motor OS's `src/bin`.

### 2.3 The C ABI shim

Settled by the move to mlibc. The standalone build builds the shim exactly
as it does today: from the mlibc source, with the
crate's own lockfile, against the published `moto-rt` and `moto-sys`. No
crates.io release of the shim is needed, and nothing in the toolchain
build reads `src/sys`. A shim change is an mlibc commit on the recipe's
branch and a new toolchain release. Section 2.9
lists every place the runtime crates are referenced and how to build
against local copies.

Having no Motor OS checkout means the `moto-rt` compatibility check is
dropped, not moved; see the runtime check in section 4. The build also
stops recording a Motor OS revision.

### 2.4 Build stages

The stages are the ones that exist today, minus everything after the
toolchain:

1. provision host packages and rustup (optional, `--provision`);
2. check out the heads of the declared Rust, mlibc, and tar branches, and
   the LLVM and Cargo commits that the Rust gitlinks name;
3. build the standalone host LLVM/Clang/LLD;
4. run Rust bootstrap, install the host prefix (rustc, Cargo, host and
   Motor std, Clippy, rustfmt, rust-analyzer, `rust-src`);
5. build the target side: mlibc source snapshot, shim, compiler-rt
   builtins, mlibc, libunwind, libc++abi, libc++, native LLVM, native
   rustc, rustfmt, clippy-driver, native rust-analyzer;
6. build the Linux `tar` from `moturus/motor-os-tar` and package.

Every build starts from nothing (decided 2026-10-24, after review): it
fetches shallow clones of the heads of the branches `versions.sh` names
(branches, not commits: decided 2026-10-25) into `build/`,
builds everything there, writes the two archives and a checksum file for
each next to its checkout, and removes `build/`. A failed build leaves `build/`
for inspection, and the next run deletes it. There are no build locks, no
reuse of earlier build trees or source checkouts, no `--replace`, and no
source verification beyond fetching the named branches: Rust bootstrap runs
Cargo with `--locked`, so a lockfile that does not match its manifests
fails the build. Concurrent builds in one checkout, or sources changed
during a build, are user error. The keys, rejection markers, and
content-tree digests go too.

Authoring mode is dropped. A repository in `versions.sh` may be a local
path, so local Rust, LLVM, and mlibc work is committed to branches of local
checkouts that `versions.sh` then names; `--dev`
names the result `x86_64-unknown-motor-1.99.1-dev`. Local builds are
packaged like releases and can be used by the Motor OS build; they are not
published as releases.

### 2.5 Packaging

The host toolchain is one rustup toolchain directory, laid out the way
Rust lays out its own: the cross sysroot sits under the target's rustlib
directory, and the host LLVM tools sit where the `llvm-tools` component
puts them, next to `rust-lld`. Nothing lives beside the prefix.

This is the intended host layout. Any remaining host artifact or runtime
dependency details will be resolved during implementation and ordinary
toolchain use; they do not need further planning here.

```
x86_64-unknown-motor-1.99.1/                     the rustup toolchain
  bin/                                           rustc, rustdoc, cargo, rustfmt, cargo-clippy,
                                                 clippy-driver, rust-analyzer
  lib/rustlib/x86_64-unknown-linux-gnu/lib/      host std
  lib/rustlib/x86_64-unknown-linux-gnu/bin/      rust-lld, rust-objcopy, and the host LLVM tools
                                                 the wrappers and the external-source builds call: clang,
                                                 ld.lld (a script running rust-lld), llvm-ar,
                                                 llvm-strip, llvm-readelf, llvm-nm, llvm-objcopy,
                                                 llvm-ranlib
  lib/rustlib/x86_64-unknown-linux-gnu/lib/clang/23/   clang's resource directory
  lib/rustlib/x86_64-unknown-motor/lib/          Motor std
  lib/rustlib/x86_64-unknown-motor/sysroot/      the cross sysroot: bin/{motor-clang, motor-clang++,
                                                 motor-rust-cc}, devtools/llvm/{include,lib}
                                                 (headers, libc, the shim, builtins, libunwind,
                                                 libc++abi, libc++, crt1.o)
  lib/rustlib/src/rust/library/                  rust-src
```

The wrappers reach clang and lld by a path relative to themselves and
pass the resource directory explicitly, as the on-image driver config
does today. The Motor OS build derives every path from
`rustc --print sysroot`:

```
$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-motor/sysroot/bin/motor-clang
$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-ar
```

Two archives per version, both produced for release and local development
builds:

| Archive | Contents | Used by |
|---|---|---|
| `motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst` | a Linux `install.sh` and `toolchain/`, the rustup toolchain directory above: the Linux-host cross toolchain | Linux cross builds: the Motor OS repository, the userspace programs built beside it, third parties |
| `motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst` | `images/` (the overlays `llvm`, `rustc`, `rust-analyzer`, `libc`) and a native `install.sh` | the Motor OS imager on Linux, or a user on a running Motor OS VM who downloads it and installs it natively |

The sysroot wrappers and the bootstrap configuration embed absolute paths
today (`$MOTORH/build/toolchain/standalone-llvm/<key>/bin`), so the
packaged wrappers must resolve the LLVM tools relative to their own
location instead. Each archive unpacks into one top-level directory named
like the archive, the way Rust's own tarballs do, with `install.sh` and the
payload inside it.

### 2.6 Where the archives go and how they are installed

**Output of the build.** The toolchain build writes the two archives and a
checksum file for each next to its checkout, in its parent directory, and
leaves nothing else (decided 2026-10-25):

```
../motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst
../motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst.sha256
../motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst
../motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst.sha256
```

**Distribution.** The files of a version are published as one GitHub
release of the toolchain repository, tagged with the version. Nothing in
Motor OS refers to the release, the repository, or the checksums; a person
downloads what they need.

**Where the Motor OS build finds them.** Motor OS development uses the parent
directory of the Motor OS checkout, `$MOTORH`, for the archives only. The
Motor OS build reads the native archive there and writes nothing there: its
external sources and build trees stay in the checkout, in `external-sources/`
and `build/` (decided 2026-10-25):

```
$MOTORH/
  motor-os/                                           the checkout
  motor-os-toolchain/                                 the toolchain checkout, for a local build
  motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst  the native archive, found by name
  motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst   (downloaded, installed, may be deleted)
  motor-toolchain-*.tar.zst.sha256                    their checksums
```

The Motor OS repository pins the version and nothing else: no toolchain
repository, no commit, no digest.

**Installing the host toolchain on Linux.** The host archive carries an
`install.sh` at its top level, like Rust's tarballs:

```sh
tar -xaf motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst
motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux/install.sh
```

The Linux `install.sh` installs the payload into
`~/.local/share/motor/toolchains/<version>` by default, then runs
`rustup toolchain link <version> <installation-directory>`.
`--prefix DIR` selects another installation directory. The payload lives
outside rustup's registration directory; rustup creates the link to it.
After that, `rust-toolchain.toml` with
`channel = "x86_64-unknown-motor-1.99.1"` selects it, and
`rustc --print sysroot` is the only path the Makefile derives anything
from (the layout in 2.5 makes that sufficient). The archive can be deleted
once installed.

**Using the native toolchain from Linux (the imager).** As implemented,
`src/build-motor-os.sh` expects `$MOTORH/motor-toolchain-<version>.tar.zst`,
where `<version>` is the channel in `rust-toolchain.toml`, unpacks it on
every run with the native `tar` built for Linux, and moves its four overlays
into the checkout's `build/assembly/images/`, beside those of the external
sources. The imager's `assembly_dirs` point at that one directory, which the
Makefile passes. The archive stays where it is. A local build supplies the
same archive with its `-dev` version named in `rust-toolchain.toml`, so it
follows the same path.

**Installing the native toolchain on Motor OS.** A user on a running Motor
OS VM downloads the native archive and runs the `install.sh` inside it, a
Rush script:

```sh
curl -O https://.../motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst
tar -xaf motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst
motor-toolchain-x86_64-unknown-motor-1.99.1/install.sh
```

`install.sh` replaces `/devtools/llvm` and `/devtools/rust` and copies the
rest of the overlays' `devtools/` trees (the launchers in `/devtools/bin`
and the examples) over what is there. An existing installation is replaced
with the requested toolchain.
Everything it installs lives under `/devtools`, so an install never writes
to `/system`. Three things follow:

- `/devtools` and everything below it belong to the Interactive role
  (decided 2026-10-24), since an ssh session is Interactive and no image
  offers a System session. The permission policy gives `/devtools` the
  modes of `/user`; `/devtools/lorry/user` and `/devtools/lorry/none` keep
  theirs.
- mlibc's runtime configuration stays in the image's `/system/cfg/libc`.
  The planned `/devtools/cfg/libc` lookup in the mlibc fork is not done; it
  needs a pushed mlibc commit and a new recipe.
- Unpacking needs a native tool: the standard and developer images carry
  `tar` and `zstd` from `moturus/motor-os-tar` in `/system/bin`. Copies keep
  the modes the unpacking session gave the files, which no lower role may
  execute, so `install.sh` then makes the programs executable by every role
  and the launchers editable by Interactive, as they are on the image.

### 2.7 Toolchain files on Motor OS

Everything the toolchain puts on a Motor OS image, as staged by the four
toolchain overlays of the completed 1.99.1 build
(`images/{libc,llvm,rustc,rust-analyzer}`).
The standard and wasm images take only the `libc` overlay; the developer
image takes all four. Paths are absolute on the image; sizes refer to the
staged files. This is today's layout; with the native install described in
2.6, the `libc` configuration gains a `/devtools/cfg/libc` home that
shadows `/system/cfg/libc`, and the rest stays as listed.

**`libc` overlay (every image)**

| Path | Size | What it is |
|---|---:|---|
| `/system/cfg/libc/hosts` | 79 B | mlibc runtime configuration, read from `/system/cfg/libc` instead of `/etc` (`MLIBC_SYSCONFDIR`) |
| `/system/cfg/libc/services` | 28 B | same |
| `/system/cfg/libc/shells` | 32 B | same |

**`llvm` overlay (developer image): the C and C++ toolchain**

| Path | Size | What it is |
|---|---:|---|
| `/devtools/bin/cc` | 286 B | Rush script: `exec /devtools/llvm/bin/llvm clang "$@"` |
| `/devtools/bin/c++` | 159 B | Rush script: `exec /devtools/llvm/bin/llvm clang --driver-mode=g++ "$@"` |
| `/devtools/llvm/bin/llvm` | 101 MiB | the native LLVM multicall binary: clang, lld, and the LLVM tools, selected by the first argument |
| `/devtools/llvm/cfg/x86_64-unknown-motor.cfg` | 42 B | clang driver config: `-resource-dir /devtools/llvm/lib/clang/23` |
| `/devtools/llvm/lib/clang/23/include/` | 295 files | clang's resource headers (intrinsics, `stddef.h`, `stdint.h`, the offload and vendor wrapper subdirectories) |
| `/devtools/llvm/lib/crt1.o` | 2.4 KiB | mlibc program entry object |
| `/devtools/llvm/lib/libc.a` | 3.7 MiB | mlibc |
| `/devtools/llvm/lib/libmoto_rt_cabi.a` | 705 KiB | the C ABI shim over the Motor runtime, from the mlibc fork's `sysdeps/motor/moto-rt-cabi` |
| `/devtools/llvm/lib/libclang_rt.builtins-x86_64.a` | 191 KiB | compiler-rt builtins, emulated TLS removed |
| `/devtools/llvm/lib/libunwind.a` | 131 KiB | LLVM libunwind |
| `/devtools/llvm/lib/libc++abi.a` | 587 KiB | libc++abi |
| `/devtools/llvm/lib/libc++.a` | 2.4 MiB | libc++ |
| `/devtools/llvm/lib/lib{dl,m,pthread,resolv,rt,ssp,ssp_nonshared,util}.a` | 1 KiB each | mlibc's empty compatibility archives, so `-lm`, `-lpthread`, and friends link |
| `/devtools/llvm/include/*.h` | 68 files | mlibc's top-level C headers (`stdio.h`, `pthread.h`, `unistd.h`, ...), plus `moto_rt.h` from the shim, `mlibc-config.h`, and libunwind's `unwind.h`, `libunwind.h`, `__libunwind_config.h`, `unwind_itanium.h`, `unwind_arm_ehabi.h`, `libunwind.modulemap` |
| `/devtools/llvm/include/{abi-bits,bits,sys,netinet,net,arpa,mach-o}/` | 137 files | mlibc's header subdirectories (49, 51, 25, 8, 2, 1, 1 files) |
| `/devtools/llvm/include/c++/v1/` | 1689 files | libc++ headers |
| `/devtools/src/hello-world/hello.c`, `hello.cpp` | 95 B, 292 B | smoke-test sources for `cc` and `c++` |

**`rustc` overlay (developer image): the native Rust toolchain**

| Path | Size | What it is |
|---|---:|---|
| `/devtools/bin/rustc` | 54 B | Rush script: `exec /devtools/rust/bin/rustc "$@"` |
| `/devtools/bin/rustfmt` | 56 B | Rush script: `exec /devtools/rust/bin/rustfmt "$@"` |
| `/devtools/bin/clippy-driver` | 62 B | Rush script: `exec /devtools/rust/bin/clippy-driver "$@"` |
| `/devtools/rust/bin/rustc` | 114 MiB | native rustc (static; `rustc_driver` is linked in, so the executable path is the sysroot anchor) |
| `/devtools/rust/bin/rustfmt` | 19 MiB | native rustfmt |
| `/devtools/rust/bin/clippy-driver` | 126 MiB | native Clippy driver |
| `/devtools/rust/lib/rustlib/x86_64-unknown-motor/lib/` | 58 files, 115 MiB | the Motor standard library as `.rlib` + `.rmeta` pairs: `core`, `alloc`, `std`, `test`, `proc_macro`, `panic_abort`, `panic_unwind`, `unwind`, `unwinding`, `compiler_builtins`, `moto_rt`, `std_detect`, `sysroot`, `getopts`, `addr2line`, `gimli`, `object`, `memchr`, `miniz_oxide`, `adler2`, `hashbrown`, `cfg_if`, `libc`, `rustc_demangle`, `rustc_literal_escaper`, `rustc_std_workspace_{core,alloc,std}` |
| `/devtools/src/hello-world/hello.rs` | 498 B | smoke-test source for `rustc` |

There is no Cargo on the image; Lorry is the native build driver.
The entire Motor standard-library directory is shipped, including the
`.rmeta` siblings of the `.rlib` files and any subdirectories, as the
current build stages it.

**`rust-analyzer` overlay (developer image)**

| Path | Size | What it is |
|---|---:|---|
| `/devtools/rust/bin/rust-analyzer` | 28 MiB | native rust-analyzer, built from the fork's workspace with the patched `url` and `inventory` crates |
| `/devtools/rust/lib/rustlib/src/rust/library/` | 3609 files, 81 MiB | `rust-src`: the standard library sources the analyzer indexes (`core`, `alloc`, `std`, `test`, `proc_macro`, `panic_*`, `unwind`, `compiler-builtins`, `portable-simd`, `stdarch`, `backtrace`, `std_detect`, `sysroot`, `rtstartup`, `profiler_builtins`, `rustc-std-workspace-*`, `windows-sys`, `windows_link`, `coretests`, `alloctests`, `vendor`, with `Cargo.toml`, `Cargo.lock`, and `.cargo/`) |

The current native build stages no separate
`rust-analyzer-proc-macro-srv` or shared `librustc_driver` library; those
are host artifacts. The native archive contains the complete four
overlays above, including their wrapper scripts, example sources,
configuration, headers, libraries, and Rust sources.

Not on the image, by design: the host cross wrappers (`motor-clang`,
`motor-clang++`, `motor-rust-cc`), the standalone host LLVM, Cargo, the
host standard library, and the static LLVM libraries. The `/devtools/llvm`
layout is what the LLVM fork's Motor driver expects, so it is fixed by the
fork, not by the imager.

### 2.8 Size

Measured on this host for the current build (mlibc `52bed56c`); the shim
move does not change them materially:

| Product | Size |
|---|---:|
| host prefix | 923 MiB |
| cross sysroot | 26 MiB |
| standalone LLVM build tree | 1.7 GiB, of which tools 412 MiB and static libraries 325 MiB |
| image overlays, toolchain only (`llvm`, `rustc`, `rust-analyzer`, `libc`) | 617 MiB |
| target-side `build/` trees | 6.5 GiB, not shipped |

The host archive ships the LLVM tools the sysroot wrappers and the external-source
builds call (clang, lld, `llvm-ar`, `llvm-strip`, `llvm-readelf`,
`llvm-nm`, `llvm-objcopy`, `llvm-ranlib`) and the clang resource
directory, not the static LLVM libraries, which only the Rust bootstrap
needs. The staged directories are uncompressed today; zstd compression
and stripping the host prefix should reduce the archive sizes.

### 2.9 Where the runtime crates are referenced, and using local copies

Three Motor OS crates enter the toolchain: `moto-rt` (linked by Rust std
and, through the `ctrlc` fork, by the compiler tools built for Motor),
`moto-sys` (used by the shim), and `moto-rt-cabi` (the shim itself). In the
normal state the first two come from crates.io and the third from the
mlibc fork, and no path, Git source, or `[patch]` points at a Motor OS
checkout (the rule in `docs/crates.md`). Every reference, by repository:

| Repository | File | Reference |
|---|---|---|
| `moturus/rust` | `library/std/Cargo.toml` | `[target.'cfg(target_os = "motor")'.dependencies]` `moto-rt = { version = "0.17.9", features = ['rustc-dep-of-std'], public = true }` |
| `moturus/rust` | `library/Cargo.toml`, `[patch.crates-io]` | no Motor entry; this is where a local `moto-rt` goes for std |
| `moturus/rust` | `library/Cargo.lock` | `moto-rt 0.17.9` from the registry, dependency of `std` |
| `moturus/rust` | `Cargo.toml` (root), `[patch.crates-io]` | `ctrlc = { git = "https://github.com/moturus/rust-ctrlc.git", branch = "motor-os-rustc" }`, plus the `libc`, `libloading`, `stacker` forks (which do not use the runtime crates) |
| `moturus/rust-ctrlc` | `Cargo.toml` | `[target.'cfg(target_os = "motor")'.dependencies]` `moto-rt = "0.17"` |
| `moturus/rust` | `Cargo.lock` (root) | `moto-rt 0.17.9` from the registry, dependency of `ctrlc` |
| `moturus/mlibc` | `sysdeps/motor/moto-rt-cabi/Cargo.toml` | `moto-rt = { version = "0.17.9", features = ["libc"] }`, `moto-sys = "0.3.2"` |
| `moturus/mlibc` | `sysdeps/motor/moto-rt-cabi/Cargo.lock` | both from the registry; the build runs `cargo fetch --locked` and builds `--locked --offline` |
| `moturus/mlibc` | `sysdeps/motor/moto-rt-cabi/moto_rt.h` | `#define MOTO_RT_VERSION 17u`; the crate's `build.rs` asserts it equals `moto_rt::RT_VERSION` of the `moto-rt` actually selected |
| `moturus/motor-os-toolchain` | `versions.sh` | `MOTOR_MLIBC_BRANCH` selects the shim source; only shim changes committed to that branch are built |
| Motor OS | `src/toolchain-runtime.sh` | checks that `src/sys/lib/moto-rt` shares its major version with std's locked `moto-rt`; a check, not an input; dropped with the move (section 4) |
| Motor OS | `src/sys/Cargo.toml`, `[patch.crates-io]`; `src/sys/lib/moto-sys/Cargo.toml` | the OS itself uses `lib/moto-rt` and `lib/moto-sys` by path, and `moto-sys` names `moto-rt = { version = "0.17", path = "../moto-rt" }`; the published crates use crates.io; not toolchain inputs |

Not referenced anywhere: the LLVM fork, the Cargo and rust-analyzer
workspaces (their lockfiles carry no Motor crate), the `libc`,
`libloading`, and `stacker` forks.

**Using local copies.** The supported path for a runtime change is to
publish `moto-rt` (and `moto-sys` if it changed), select the new version
in the manifests above, and refresh the lockfiles. Building against the
checkout's `src/sys/lib/moto-rt` and `moto-sys` instead, before
publishing, is a local build, with `MOTOR=/absolute/path/to/motor-os`:

1. Rust fork, `library/Cargo.toml`, under `[patch.crates-io]`:
   `moto-rt = { path = "$MOTOR/src/sys/lib/moto-rt" }`. If the local
   version is outside `0.17.9`'s requirement, also bump the version in
   `library/std/Cargo.toml`, or Cargo reports the patch as unused.
2. Rust fork, root `Cargo.toml`, the same line under its
   `[patch.crates-io]`, for `ctrlc`'s `moto-rt` (`"0.17"`; bump the fork
   if the local major version changed).
3. Rust fork: refresh both lockfiles with `cargo update -p moto-rt
   --manifest-path library/Cargo.toml` and `cargo update -p moto-rt`,
   since the build runs Cargo with `--locked`, and commit.
4. mlibc fork, `sysdeps/motor/moto-rt-cabi/Cargo.toml`: add
   `[patch.crates-io]` with `moto-rt = { path = "$MOTOR/src/sys/lib/moto-rt" }`
   and `moto-sys = { path = "$MOTOR/src/sys/lib/moto-sys" }` (bumping the
   two version requirements if needed), run `cargo update -p moto-rt -p
   moto-sys` in that directory, and commit. Keep `MOTO_RT_VERSION` in
   `moto_rt.h` equal to the local `moto_rt::RT_VERSION`, or the shim fails
   to compile.
5. Point `MOTOR_RUST_REPOSITORY`, `MOTOR_RUST_BRANCH`,
   `MOTOR_MLIBC_REPOSITORY`, and `MOTOR_MLIBC_BRANCH` in `versions.sh` at the
   local checkouts and their branches; a repository may be a path, and a
   fresh clone of a branch sees only committed changes. Build with `--dev`.
6. The shim never needs a path override itself: it is built from the
   mlibc branch, so a shim change is an mlibc commit (step 4).

The planned `--local-runtime` option is dropped (2026-10-24): with local
repositories in `versions.sh`, the procedure above needs no option of its
own. The resulting `-dev` archives can be installed and used by the Motor OS
build in the same way as a release. They are for local use and are not
published as releases. The toolchain repository's README carries this
table and procedure; `docs/toolchain.md` points to it.

## 3. What changes in the Motor OS repository

As implemented in step 4:

- **The toolchain build moved out.** `src/build-motor-os.sh` lost its
  toolchain stages: it checks that the native archive of the version
  `rust-toolchain.toml` names is in `$MOTORH`, unpacks the native
  toolchain's overlays, builds the userspace programs, and builds the images.
  The toolchain helpers (`src/toolchain-*.sh`), `src/patches`, their
  contract tests, and `src/toolchain-content-tree` are gone. The
  declaration is the toolchain version alone, in `rust-toolchain.toml`.
- **The Motor OS build got simpler.** Nothing selects, resolves, or checks
  the toolchain: `rust-toolchain.toml` names it, rustup provides it, and the
  build only exports the name as `RUSTUP_TOOLCHAIN` so that Helix and Javy,
  which pin toolchains of their own, use it too. The Makefile finds the
  cross sysroot under `rustc --print sysroot`. Object directories,
  `build/obj/<profile>/`, and the assembly, `build/assembly/`, have fixed
  paths; the assembly holds the native toolchain's overlays (unpacked by
  `src/build-motor-os.sh` on every run) beside those of the external
  sources. The toolchain and assembly keys, assembly identity validation,
  `src/resolve-toolchain-assembly.sh`, and
  `test-toolchain-cutover.sh` are gone. Apart from `src/build-motor-os.sh`,
  the build scripts are in `src/build-scripts/`.
- **Nothing is written next to the checkout.** The external sources (the fork
  checkouts, the Lua release, wasi-sdk) are fetched into `external-sources/`,
  which Git ignores, and the assembly is in `build/`, so `make clean`
  removes it too. From `$MOTORH` the build reads only the native archive.
- **The runtime compatibility check went away.** Neither build compares
  `moto-rt` versions (section 4).
- **The userspace programs built beside Motor OS keep their LLVM tools.**
  Lua, ripgrep, Helix, uutils sed, Javy with Wasmi, and Wasmtime use
  `llvm-ar`, `llvm-strip`, and `llvm-readelf` from the toolchain's
  `lib/rustlib/x86_64-unknown-linux-gnu/bin`. Lua is compiled and linked
  with `motor-clang`, so no clang configuration file is written anywhere.
  A new external source builds `tar` and `zstd` from `moturus/motor-os-tar` for the
  standard and developer images, and the Linux `tar` that unpacks the
  native archive.
- **`/devtools` belongs to Interactive** in the permission policy, so the
  native archive installs on a running developer VM (section 2.6).
- **The ELF validator stays as a copy.** `src/build-scripts/validate-native-elf.sh`
  checks gix and `test-unwind.sh`'s programs as the moved helper did.
- **Tests.** `src/tests/test-native-toolchain-install.sh` installs the
  native archive on a VM booted from a copy of the developer image and
  builds and runs C, C++, and Rust programs with what it installed. The copy
  matters: Lorry binds the installed toolchain by file size and mtime, so an
  install into the shared image invalidated the dependencies its
  preparation compiled, which `test-dev-sources.sh` checks. Three tests of the toolchain's sources left with them
  and are dropped: the patched `url` and `inventory` crates' unit tests
  (`test-rust-analyzer-crates.sh` keeps only its stdlib check), and the
  dependency-graph checks of `test-rust-analyzer-sources.sh` and
  `test-rustfmt-sources.sh`.
- **Docs.** The toolchain build documentation moved to the toolchain
  repository's README; `docs/toolchain.md` describes installation,
  selection, and the update procedure, and `docs/assembly-resolution.md` is
  gone.

Nothing in `src/sys` changes for this plan.

## 4. Constraints and decisions

Decided in review from 2026-10-23 to 2026-10-25:

- **The build uses the network.** It fetches the declared forks and
  `moturus/motor-os-tar`, Rust's upstream submodules and Stage 0 compiler,
  crates.io dependencies, mlibc's Meson dependencies, and host packages
  as needed.
- **A Motor-side rebuild of the same Rust version** gets a release number
  after the version, from the second release on:
  `x86_64-unknown-motor-1.99.1-2`, the way distributions number package
  rebuilds.
- **Content keys go.** Reuse and rejection by key are replaced by the
  rule that a published version's recipe never changes.
- **Every toolchain build starts from nothing** (2026-10-24, after review
  of step 2). No incremental rebuilds, source checkouts kept between runs,
  build locks, build stamps, or source verification: a build fetches the
  heads of the named branches, builds, writes two archives and their checksums next to its
  checkout, and removes everything else. Nothing pins or records a commit:
  `versions.sh` names branches (2026-10-25). Concurrent builds or
  sources changed during a build are
  user error. Authoring mode and the planned `--local-runtime` option are
  dropped in favour of local repositories in `versions.sh` (2.4, 2.9).
- **The Motor OS repository pins the version only.** Never the toolchain
  repository, a commit, or a digest. The cross toolchain is found through
  rustup, the native toolchain as `../motor-toolchain-<version>.tar.zst`
  next to the checkout. Archives are published as GitHub releases of the
  toolchain repository.
- **Host layout follows Rust's own** (2.5), and archives install as in
  2.6: the cross sysroot under
  `lib/rustlib/x86_64-unknown-motor/sysroot`, the host LLVM tools under
  `lib/rustlib/x86_64-unknown-linux-gnu/bin`.
- **Native install lives under `/devtools`**, which belongs to the
  Interactive role with all its child directories (2026-10-24), so an
  ordinary session can install. The planned mlibc lookup of
  `/devtools/cfg/libc` before `/system/cfg/libc` is not done (2.6).
- **Motor OS gets native `tar` and `zstd` from `moturus/motor-os-tar`** (step 1),
  as Rust programs built on `structured-zstd`. The toolchain builder and
  Motor OS builder both build the archive tools from this repository.
  Checked against the 1.99.1 Motor target:
  `structured-zstd` 0.2.5 (pure Rust, compression and decompression,
  streaming; dependencies `fastrand` and `twox-hash`) builds for Motor,
  and so does `ruzstd`. The `tar` crate does not: it and `filetime` are
  written for `cfg(unix)` and `cfg(windows)` (`std::os::unix`,
  `OsStr::as_bytes`, `libc`, `Metadata::mtime`), and Motor is neither;
  `tar-no-std` builds but reads regular files only. The native `tar` is
  therefore its own program of about 500 lines: ustar headers with the
  `prefix` field, GNU `././@LongLink` and pax `path` and `size` records,
  directories and regular files, `-c`, `-x`, `-t`, zstd in process.
  Motor's `std::fs::Permissions` exposes only read-only, so executable
  bits are set through `moto_rt::fs::set_perm` with `PERM_EXEC`, as the
  imager's `chmod` does. The toolchain builder creates the archives with
  the same program built for Linux, so the extractor reads exactly what
  was written.
- **The external sources** (Lua, ripgrep, Helix, uutils sed, Javy with
  Wasmi, Wasmtime: the userspace programs built beside Motor OS) are not
  toolchain components. Their builds stay in `build-motor-os.sh`, which
  fetches them into the checkout's `external-sources/` and builds in its
  `build/`; it writes nothing next to the checkout (2026-10-25). Every run
  builds them all again, with no stamps; after installing a different or
  rebuilt toolchain, the user runs `make clean`, which removes all build
  artifacts (2026-10-25).
- **No build-time `moto-rt` compatibility check** (2026-10-24). The
  toolchain builds std against the `moto-rt` its lockfile references from
  crates.io, and the Motor OS build uses the toolchain to build whatever is
  in the repository; no build script compares the two versions. `rt.vdso`
  checks compatibility at runtime. Note to carry over into the build
  documentation.
- **No extra tests or validation are currently needed.** Regular
  toolchain usage and Motor OS builds will expose missing artifacts and
  integration problems. Existing Motor OS tests and build checks remain,
  the toolchain repository has no tests (2026-10-25), and no new
  packaging smoke tests, relocation tests, signature verification, or
  failure-injection gates are required by this plan.

## 5. Suggested order of work

0. Rebase the forks onto Rust 1.99.1, so the first standalone release is
   `x86_64-unknown-motor-1.99.1` with no beta suffix. This is work in two
   repositories outside Motor OS: `moturus/rust` and
   `moturus/llvm-project`, each on a new branch named for 1.99.1. Upstream
   1.99.1 is 57 commits past the fork's beta base; the 26 Motor commits on
   the Rust fork overlap it in two files
   (`compiler/rustc_session/src/filesearch.rs`,
   `src/bootstrap/src/core/build_steps/llvm.rs`) plus the LLVM gitlink,
   which is re-pointed on purpose. The LLVM fork moves from 23.1.0-rc1 to
   23.1.1 (309 upstream commits); its 5 Motor commits overlap in one file
   (`libcxx/include/__config`). The Cargo gitlink and Stage 0 (stable
   1.98.0) follow upstream; the three lock hashes are re-declared; mlibc
   and the shim are unaffected. Upstream now makes a rustc-to-LLVM version
   mismatch a hard error, so both LLVM builds must come from the rebased
   fork, as they do today. Do this in the toolchain builder's authoring
   mode and run the existing gates, so a rebase problem is told apart
   from a move problem. The completed work also needed the Motor OS build
   changes described below.

   Status (2026-10-24): complete. Rebased on `motor-os-1.99.1` branches in
   the authoring checkout `$MOTORH/rust` and pushed. Two things the
   file overlap did not predict: upstream 1.99.1 restructured
   `current_dll_path` into one cached function over per-platform
   `dll_path` helpers, so Motor's override became a Motor `dll_path`; and
   Lorry inferred the Cargo compatibility family from `1.99.0` only, so
   `src/bin/lorry` now accepts any `1.99.x` release. The LLVM fork branch
   carried one commit past the declared revision ("Disable fallback host
   include paths for Motor"); it is included. The authoring build
   completed the host toolchain, the assembly, the external sources, and all images,
   and the candidate gates (full test in debug and release, developer
   image in release, all minus the checks that reject authoring names by
   design) passed. The fork branches are pushed. The managed build of the
   declared tuple exposed two toolchain build defects, both fixed with
   contract tests: a declared revision that moves a gitlink made the managed
   checkout look dirty before its submodules were updated, and the native
   LLVM tree under the Rust checkout was reused across assemblies, where
   cmake, seeing a different compiler, dropped the Motor cross-build
   defines. The managed build completed `motor-1.99.1-72fe77b6…` and its
   assembly; the selector points at it and the core gate (three debug,
   three release, developer image in release) is complete.
1. Create the `moturus/motor-os-tar` repository for the Rust archive programs:
   one `tar` with `-c`, `-x`, `-t`, and zstd compression through
   `structured-zstd`, plus a `zstd` command for plain `.zst` files. The
   toolchain builder builds `tar` for Linux and creates its archives with
   it. The Motor OS builder builds the same `tar` for Linux image
   preparation and builds both commands for Motor OS, putting them on
   the standard and developer images.
   (Done before this step: the shim moved into the mlibc fork, mlibc
   `9abf5139`, Motor OS `a3d739f9`, so the toolchain stages no longer read
   `src/sys`.)

   Status (2026-10-24): complete; pushed as `moturus/motor-os-tar`.
2. Create the toolchain repository; move the scripts, patches, and
   contract tests; replace the key derivation with version naming; drop
   the two remaining checkout references (remove the `moto-rt`
   compatibility check and `motor_os_rev`); lay the prefix out as in 2.5, with
   the cross sysroot and the host LLVM tools inside it and relocatable wrappers;
   build the 1.99.1 tuple from outside the checkout as
   `x86_64-unknown-motor-1.99.1`.

   Status (2026-10-24): complete, uncommitted in `$MOTORH/motor-os-toolchain`.
   First done with managed sources kept in `sources/`, build trees reused
   from `build/<name>/work`, one build lock per name, and `--replace`; the
   review of that version found races and stale-reuse defects in exactly
   that machinery, so it was removed: every build now starts from nothing
   (section 4). The build does not register the toolchain with rustup;
   the Linux `install.sh` does. Motor OS tests compare the
   native rustfmt and rust-analyzer with the host toolchain's. Rust bootstrap and the native
   builds use the shipped relocatable wrappers, so every build exercises
   them; the C stages still compile with the standalone Clang of the build
   tree. Clang's Motor driver runs `ld.lld` from its own directory, so
   `ld.lld` is a script running `rust-lld -flavor gnu` rather than a second
   73 MB copy of lld, and the Motor builtins also sit in the toolchain's
   resource directory, as they did for the old wrappers' Clang. Without the
   tree digests, a git-style crate patch applied inside the toolchain
   checkout was silently skipped; the preparation now runs `git apply`
   under `GIT_CEILING_DIRECTORIES`. The managed build took 42
   minutes after 6 minutes of clones and uses about 30 GB. Its overlays have
   the same file lists as the assembly the old pipeline built from the same
   sources, and differ only in embedded build paths and the compiler
   description. A copy of the toolchain moved to another directory built C,
   C++, Rust, and Rust-with-C programs and `motor-os-tar`, which ran on the
   standard image with the same output as builds with the current
   toolchain; the native rustc, rustfmt, clippy-driver, rust-analyzer, and
   Clang ran on the developer image and built working programs there.
   On 2026-10-25 the repository's tests were removed (section 2.2).
3. Packaging: the two archives and their checksums, created with the
   native `tar` built for Linux; the Linux `install.sh`; the native
   `install.sh` (Rush) and the `/devtools/cfg/libc` layout, which needs
   the mlibc fork's runtime configuration lookup on the recipe's mlibc
   branch. Local development builds produce the same two archive
   types with a `-dev` version.

   Status (2026-10-24): done except the `/devtools/cfg/libc` layout. The
   build fetches the head of `moturus/motor-os-tar`'s `MOTOR_TAR_BRANCH`, builds its
   `tar` with the new host toolchain, and writes both archives and a
   `.sha256` file for each next to its checkout. The Linux `install.sh` copies the
   toolchain to `~/.local/share/motor/toolchains/<name>` (or `--prefix`)
   and links it into rustup. The native `install.sh`, a Rush script,
   replaces `/devtools/llvm` and `/devtools/rust` and copies the launchers
   and examples, replacing any previous installation. mlibc's configuration
   stays in the image's `/system/cfg/libc`.
4. Switch the Motor OS repository: `rust-toolchain.toml` names the
   version; the Makefile derives paths from `rustc --print sysroot` and
   unpacks the native archive from next to the checkout; remove the
   resolver, the keyed paths, the moved scripts and tests, and the
   documentation of the key model; run the full core gate.

   Status (2026-10-24): switched as described in section 3, uncommitted.
   The native archive is unpacked by `src/build-motor-os.sh`, not the
   Makefile, into the assembly beside the external sources. The
   developer-image suite installs the native archive on a copy of the
   developer image in its own phase. Validation found six defects in the
   switch, each fixed before the final runs: the Wasmtime fetch test
   did not set `SYSROOT`; a new sed-check expectation assumed a relative
   `ls` path; installing into the shared developer image invalidated
   Lorry's prepared dependencies; the wrapper contract tests had no
   recorder for the moved phase; Lorry's C++ contract read the compiler
   path out of a wrapper that is now relocatable; and Lorry's native test
   compared the toolchain's Motor target directory, which now also holds
   the C cross sysroot, with the image's. On the finished tree,
   `src/tests/full-test-dev.sh --release` and
   `src/tests/full-test.sh --release` passed. On 2026-10-25, after the
   archives moved next to the toolchain checkout, the toolchain was rebuilt,
   Motor OS was rebuilt from an empty object tree and assembly, and both
   runs passed again. Later that
   day `versions.sh` switched from commits to branches; the rebuilt
   toolchain took the same commits from the branch heads, its native
   archive is byte-identical, and after another clean rebuild both runs
   passed again. Then the external sources moved into `external-sources/` and
   the assembly into `build/`; after `make clean`, fresh clones of them,
   and a rebuild, both runs passed again. Finally the external sources lost
   their build stamps, so every run builds them again (a rerun with nothing
   changed takes about 1.5 minutes), and `make clean` was fixed to remove
   all build artifacts; after `make clean` and a rebuild, both runs passed
   again. Then the remaining code of the key model went: the toolchain
   selection and name checks, the per-toolchain object and assembly
   directories, and the assembly resolver; and the build scripts other than
   `src/build-motor-os.sh` moved into `src/build-scripts/`; after `make clean`
   and a rebuild, `src/tests/full-test-dev.sh --release` passed. The rest of
   the core gate (three debug and three release full-test runs) is open.

## 6. Remaining work and open questions

Remaining work:

1. The core gate of step 4: `src/tests/full-test.sh` three times in debug
   and three times in release. The new toolchain has passed one release run
   of `full-test.sh` and one of `full-test-dev.sh`; no debug build has been
   tested with it.
2. A release of the toolchain: publish the two archives and their checksum
   files as a GitHub release tagged with the version (2.6).

Open questions:

1. The `/devtools/cfg/libc` lookup (2.6, step 3): implement it, which takes
   a commit on the mlibc fork's branch and a toolchain
   rebuild, or drop it and keep mlibc's configuration in the image's
   `/system/cfg/libc`, which a native install cannot change?
2. This work changed `src/bin/lorry/tests`, so AGENTS.md asks whether the
   developer-image gate should also run in debug.
