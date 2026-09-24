# Motor OS toolchain selection

This document explains how the Motor OS compiler toolchain is declared,
built, identified, selected by everyday commands, and changed. It describes
what the scripts do today. The quick start is in [build.md](build.md), the
producer's stages in [build-motor-os.md](build-motor-os.md), how ordinary builds
find the assembly in [assembly-resolution.md](assembly-resolution.md), and the LLVM and
native Rust components in [build-llvm.md](build-llvm.md) and
[build-rustc.md](build-rustc.md).

## 1. The pieces

| Piece | Where | Tracked? |
|---|---|---|
| Declaration of the source tuple | `src/toolchain-versions.sh` | yes |
| Root selector naming the exact host toolchain | `rust-toolchain.toml` | yes |
| Managed source checkouts | `$MOTORH/toolchain-src/{rust,mlibc}` | no |
| Add-on sources (follow a fork branch; Lua is a release) | `$MOTORH/{ripgrep,helix,sed,lua-<version>}` | no |
| Host toolchain prefixes | `$MOTORH/toolchains/<rustup name>` | no |
| Standalone LLVM/Clang builds | `$MOTORH/build/toolchain/standalone-llvm/<llvm key>` | no |
| Assemblies (C sysroot, native tools, image overlays) | `$MOTORH/assemblies/<assembly key>` | no |
| Generated bootstrap state per toolchain key | `$MOTORH/toolchain-state/<toolchain key>` | no |
| Motor OS build outputs | `build/obj/<toolchain key>/<profile>/…` | no |
| Images | `vm_images/<profile>/` | no |

`MOTORH` defaults to the parent of the checkout. The producer,
`src/build-motor-os.sh`, creates everything in the untracked rows. Ordinary
commands (`make`, `cargo`, the tests) only consume them.

The declaration is data only. The values that matter most:

- `MOTOR_RUST_REPOSITORY`, `MOTOR_RUST_REF`, `MOTOR_RUST_REV`: the moturus
  Rust fork, its development branch, and the exact commit to build. The commit
  must be reachable from the branch; the branch tip itself is never used.
- `MOTOR_LLVM_REV` and `MOTOR_CARGO_REV`: the `src/llvm-project` and
  `src/tools/cargo` gitlinks that the Rust commit must carry. They are
  declared so that a wrong gitlink is an error, not a surprise.
- `UPSTREAM_RUST_REV`, `UPSTREAM_STAGE0_REV`, `RUST_LLVM_BASE_REV`: the
  upstream Rust base, its Stage 0 bootstrap compiler, and the upstream LLVM
  commit that the Motor LLVM patches sit on. Recorded for lineage; the
  producer checks them against the fork, and they are no key input.
- `MOTOR_RUST_ROOT_LOCK_SHA256`, `MOTOR_RUST_LIBRARY_LOCK_SHA256`,
  `MOTOR_RUST_ANALYZER_LOCK_SHA256`: hashes of the three Cargo lockfiles at
  `MOTOR_RUST_REV`. A checkout whose lockfiles differ, or a bootstrap run
  that rewrites one, is rejected. They are checks, not key inputs.
- `MOTOR_MLIBC_REV`: the libc commit.
- No runtime crate version is declared. Rust std links the `moto-rt` that the
  Rust fork's library lock selects, which the lock hash above covers. The
  local `moto-rt` only has to share its major version (`0.17` for `0.17.6`);
  its content and lower version parts are never compared, and `moto-sys` is
  not checked at all.
- `MOTOR_TOOLCHAIN_ID` and `MOTOR_RUSTUP_TOOLCHAIN_BASE`: the human-readable
  lineage (`1.99.0-beta-f47d5bb-motor.dev.2`) and the prefix of the rustup
  name (`motor-1.99.0-beta-f47d5bb-dev.2`).

The declaration covers the C, C++, and Rust toolchain only. Userspace add-ons
(Lua, ripgrep, Helix, sed) are declared in `src/build-motor-os.sh`, and the vsock
test backend belongs to the test harness.

## 2. Identities

Every product is named by a SHA-256 key over its inputs, so different inputs
never overwrite each other and a product can be validated against the inputs
that should have produced it.

Keys name the C, C++, and Rust toolchain only: its external sources (commits,
lockfile hashes, crate checksums) and its declared configuration. No file of
this repository is hashed into a key, so editing a build script, a patch
file, or the local runtime never forces a rebuild. Userspace add-ons are no
key input either.

**Toolchain key.** Hash of what is compiled, how, and where it installs: the
effective Rust and LLVM commits and their tree states, the authoring digest
(`none` for managed builds), the declared versions, archive checksums, and
prepared-tree digests of the patched rust-analyzer crates
(`src/patches/crates.sh`), the normalized bootstrap configuration (which
carries the compiler description, the channel, and every bootstrap option),
the standalone LLVM configuration, and the rustup base, because the prefix
path is named after it. A patch that changes a crate does so through its
declared tree digest, which the producer checks against the prepared crate.

Everything else about a toolchain follows from those inputs and is no key
input: the Rust commit fixes its upstream base, Stage 0, Cargo, and
lockfiles, so the declared lineage values and lockfile hashes are checks of
the fork, not identity. The toolchain id and maturity are labels. Manifests
record only values that follow from the key, so an equal key always means an
equal manifest.

**Rustup name.** `<rustup base>-<toolchain key>`, for example
`motor-1.99.0-beta-f47d5bb-dev.2-774c61a5…`. Authoring builds use
`motor-authoring-<version>-<12 hex of the base>-<key>` instead, so they can
never be mistaken for a managed build. The prefix carries
`MOTOR-TOOLCHAIN-MANIFEST` and the stamp `lib/rustlib/MOTOR-TOOLCHAIN-KEY`.

**Clean key and clean name.** The toolchain key that a managed build of the
declaration with clean trees and unchanged lockfiles produces. It is computed
from `src/toolchain-versions.sh` alone (`toolchain_clean_key` in
`src/toolchain-lib.sh`), which is what lets a test decide whether the tracked
selector names the declared tuple without building anything.

**Assembly key.** Hash of the toolchain key, the mlibc commit and tree state,
and the native configuration digest (the recipes for native LLVM, rustc,
rustfmt, and rust-analyzer). Editing `src/build-motor-os.sh`, a toolchain
script, moto-rt, moto-sys, or the shim keeps the same assembly, and so does a
version bump of the local runtime crates. The C ABI shim inside an assembly
is the one built when the assembly was produced; to rebuild it, remove
`$MOTORH/assemblies/<assembly key>` and run the producer. The assembly root
and each toolchain overlay carry `MOTOR-ASSEMBLY-MANIFEST`; the developer
image exposes it as `/devtools/toolchain/manifest`.

**Add-ons.** Lua, ripgrep, Helix, and sed are userspace programs built with
the finished toolchain. They are staged beside the assembly's overlays
(`images/lua`, `images/rg`, `images/helix`, `images/sed`) because they link
against its sysroot, but they are no part of its key, manifest, or validation.
Lua is a release version; ripgrep, Helix, and sed follow one branch of their
fork (sed is uutils sed, from `moturus/sed`). Each
records the source it was built from in `ADDON-<name>` inside the assembly,
and the producer rebuilds that add-on alone when the source differs.
The manifest's `motor_os_rev` and `assembly_state` record the producer's Git
revision and whether the shim sources had uncommitted changes. Neither is
keyed, so a later checkout reuses the assembly with its original provenance.

## 3. How everyday commands select the toolchain

1. `rust-toolchain.toml` names the exact rustup toolchain. rustup resolves
   `cargo`, `rustc`, `rustfmt`, and `rust-analyzer` to
   `$MOTORH/toolchains/<that name>`, which the producer registered with
   `rustup toolchain link`. No `+channel` selectors are used anywhere.
2. The Makefile reads the stamp from `rustc --print sysroot` and refuses to
   run with a toolchain that has none. The key becomes the object directory,
   `build/obj/<toolchain key>/<profile>`, so two toolchains never share
   incremental state.
3. Targets that need the C sysroot or the image overlays (`lorry`, `curl`,
   `main.img`, `dev.img`) run `src/resolve-toolchain-assembly.sh --resolve`.
   The script reads the stamp, derives the assembly key that the current
   checkout expects, and looks for that assembly beside the toolchain, in
   the `assemblies` directory next to `toolchains`. The root must validate
   (read-only manifest, identical manifests in every toolchain overlay,
   required outputs present, recorded digests matching). A missing assembly
   is an error naming the key and the producer. Nothing is chosen or stored.
4. The imager receives the validated overlay root as
   `MOTOR_ASSEMBLY_IMAGE_ROOT`; the image YAML lists what it takes from there
   (`assembly_dirs`, `assembly_required_executables`). The base image takes
   nothing from an assembly.
5. `src/tests/full-test.sh` runs `test-toolchain-cutover.sh`, which requires
   the selector to equal the clean name, the selected sysroot's stamp to
   equal the clean key, rustup to resolve to that sysroot, and make's object
   paths to carry that key. The other `test-toolchain-*.sh` scripts are
   offline contract tests of the individual helpers.

The chain is therefore: tracked selector → rustup name → prefix and stamp →
toolchain key → assembly key → overlays and sysroot.

## 4. What the producer does

`src/build-motor-os.sh` with no options is managed mode:

1. Provisions host packages, rustup, and VM networking (`src/build-base.sh`).
2. Prepares the managed checkouts: clones `MOTOR_RUST_REPOSITORY` and the
   mlibc repository if absent, verifies the `origin` URL, fetches
   `MOTOR_RUST_REF`, requires `MOTOR_RUST_REV` to be reachable from it,
   requires a clean worktree, checks out that commit detached, and verifies
   the LLVM and Cargo gitlinks against the declaration. It never switches,
   resets, stashes, or cleans a worktree with local changes.
3. Hashes the three lockfiles and derives the toolchain key, prefix path,
   rustup name, and `toolchain-state` directory.
4. Builds standalone LLVM/Clang from the Rust checkout's `src/llvm-project`
   under its own configuration key, or reuses a completed one.
5. Renders `toolchain-state/<key>/bootstrap.toml` and claims the prefix. An
   existing prefix directory is reused after validation of every component,
   source commit, sysroot, lock hash, and compile probe; otherwise `x.py`
   installs rustc, rustdoc, Cargo, host and Motor std, Clippy, rust-analyzer,
   rustfmt, and `rust-src` into it, and the manifest and stamp are written
   read-only. The prefix is then linked into rustup.
6. Derives the assembly key and claims the assembly. A completed assembly is
   reused after validation; otherwise it builds the C ABI shim, compiler-rt,
   mlibc, libc++, native LLVM, native rustc and rustfmt, and native
   rust-analyzer, and writes the manifest. For a new or a reused assembly
   alike, it then updates the add-on checkouts and rebuilds the add-ons
   whose source changed.
7. Checks that `src/resolve-toolchain-assembly.sh --resolve` returns the
   assembly it just produced, so `make` will use exactly that one.
8. If `rust-toolchain.toml` exists, exports `RUSTUP_TOOLCHAIN=<new name>` and
   runs `make images BUILD=release`, so the images come from the toolchain it
   just built even when the tracked selector still names an older one. It
   never edits `rust-toolchain.toml`.

Both claims use a sibling `.building` directory as the lock; it records the
producer's pid. A lock whose producer is gone marks an interrupted build, and
the next run discards that incomplete product and builds it again. When
validation fails, the producer leaves a `MOTOR-TOOLCHAIN-REJECTED` or
`MOTOR-ASSEMBLY-REJECTED` marker, so a bad product is kept for diagnosis
instead of being silently rebuilt. Complete older keyed products are never
deleted by a build.

### Rust runtime and native formatting

The selected `.dev.2` Motor target defaults to `panic=unwind`. rustc,
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
linker scripts that move the headers are unsupported. The shared validator
in `src/toolchain-native.sh` checks this layout, unwind-provider symbols,
constructors, unwind sections, and static-PIE protections on native tools.
`src/tests/test-unwind.sh` validates its own binaries and exercises both
entry paths, abort and fat-LTO builds, and Rust/C++ destructor propagation.

Native rustfmt is built by Rust bootstrap with the compiler-private Motor
rlibs, packaged at `/devtools/rust/bin/rustfmt`, and exposed through the
`/devtools/bin/rustfmt` launcher. The launcher sets `TMPDIR=/devtools/tmp`.
Helix selects the binary through its server's `RUSTFMT` environment; see
the [editor guide](helix.md#native-rust-integration).

rustfmt searches the input directory and its ancestors, then `/user`, then
`/user/cfg/rustfmt` for `rustfmt.toml` or `.rustfmt.toml`. Motor ignores
`HOME` and `XDG_CONFIG_HOME` for these lookups; `dirs` and `dirs-sys` are
compiled only off Motor, with no additional fork. Native fixtures cover
project and user configuration, ignored environment settings, editions, macros,
and parser/lexer-error recovery. The size gates bound both the stripped
formatter and its fresh-image growth at 21 MiB. Source, producer, runtime,
editor, and size gates are wired into `src/tests/full-test.sh`, with native
formatting and editor cases in its developer-image branch.

### Authoring mode

```sh
src/build-motor-os.sh --source-mode authoring \
    --rust-source /absolute/path/to/rust \
    --authoring-base <full upstream Rust commit>
```

This builds a developer's own Rust checkout (with its `src/llvm-project`
submodule) instead of the managed one. The checkout may hold unpushed
commits, modified files, and untracked files; all of them enter a content
digest that becomes part of the toolchain key, and the effective commits are
the two `HEAD`s. The base commit must be an ancestor of the Rust `HEAD`, and
the LLVM and Cargo gitlinks derived from the base must be ancestors of what
the checkout uses. The result gets the `motor-authoring-…` name. It can be used
by `make` from a checkout whose `rust-toolchain.toml` names it, which is how
candidates are tested, but the cutover test rejects it by design, so candidates
are validated with direct test commands rather than with `full-test.sh`.

## 5. Changing the toolchain

A build never advances a toolchain branch or refreshes a toolchain
dependency; every change to the tuple is an edit of
`src/toolchain-versions.sh`. Only the userspace add-ons follow a branch. The
current procedure:

1. Push the fork branches so the new commits are reachable from the declared
   refs (LLVM first when its patches changed, then Rust with the updated
   gitlink). Nothing is built from an unpushed commit in managed mode.
2. Edit the declaration: `MOTOR_RUST_REV`; `MOTOR_LLVM_REV` and
   `MOTOR_CARGO_REV` when the gitlinks moved; the upstream base, Stage 0, and
   LLVM base when the fork was rebased; the lockfile hashes when a lockfile
   changed; and `MOTOR_TOOLCHAIN_ID` with `MOTOR_RUSTUP_TOOLCHAIN_BASE` for a
   new lineage step. Only the commits, the id, and the rustup base change the
   key; the other values are checks that the fork is what was declared.
   `test-toolchain-versions.sh` checks the file's shape.
3. Run `src/build-motor-os.sh`. It builds and links the new prefix, builds
   the new assembly, rebuilds the images, and prints
   `host toolchain: <name>`.
4. Put that name into `rust-toolchain.toml`. Until this is done, `make` still
   selects the previous toolchain and its assembly.
5. Because the standard library of every OS binary changes, run the core
   gate from AGENTS.md on the new tuple: three debug and three release runs
   of `src/tests/full-test.sh`, then `src/tests/full-test-dev.sh --release`.
6. Commit the declaration, the selector, and the documentation together and
   push. A clean checkout then reproduces the same key and name, so its
   tracked selector matches what its own producer run installs.

Rust std moves to a newer `moto-rt` the same way: publish the crate, select
it in the fork's `library/Cargo.lock`, commit that on the fork branch, and
declare the new Rust commit and lock hash. The local `moto-rt` may run ahead
of std within one major version without any of this.

The stable release converts `MOTOR_TOOLCHAIN_MATURITY` to `stable`,
`UPSTREAM_RUST_REF` to the `1.99.0` tag, and the id to `1.99.0-motor.1`,
after rebasing both forks onto the final upstream commits, and then creates
immutable source tags in the forks. It is deferred until upstream 1.99.0
exists. Only source refs are published; no binary toolchain is.

## 6. Failures you will see, and what they mean

- `rustc is not on PATH` (Makefile): the build script installed rustup, and
  the shell it was started from still has the old `PATH`. Open a new shell or
  run `. "$HOME/.cargo/env"`.
- `selected Rust toolchain is not a stamped Motor toolchain` (Makefile):
  `rust-toolchain.toml` names a toolchain that is not installed here. Run the
  producer; if the name it prints differs, the selector is behind the
  declaration.
- `no assembly <key> exists for toolchain <key>`: this toolchain has no
  assembly for the declared inputs. Either none was built on this host, or a
  declared assembly input changed since (the mlibc commit or the native
  configuration). Run the producer; it builds or reuses the matching
  assembly.
- `<commit> is not reachable from <ref>`: the declaration names a commit that
  is not on the pushed fork branch.
- `<product> is being built by process <pid>`: another build holds the
  `.building` lock. Wait for it. If that pid belongs to an unrelated process
  (the pid was reused after a reboot), remove the `.building` directory.
- `<product> was rejected: <reason>`: see the next item; the message names the
  product and lock directories to remove once the cause is fixed.
- `assembly is being built, or its build was interrupted` from `make`: run
  `src/build-motor-os.sh`; it finishes or restarts that assembly.
- `MOTOR-TOOLCHAIN-REJECTED` or `MOTOR-ASSEMBLY-REJECTED` present: validation
  failed after a build; the manifest next to it says which check.
- `make` ends every failed build with a `BUILD FAILED` summary naming the
  failed recipe and pointing at `build/make-last.log`.

## 7. File map

| File | Role |
|---|---|
| `src/toolchain-versions.sh` | the declaration (data only) |
| `src/toolchain-lib.sh` | key derivation, declaration validation, manifest helpers |
| `src/toolchain-sources.sh` | managed checkouts, gitlink checks, authoring resolution |
| `src/toolchain-host.sh`, `src/toolchain-bootstrap.sh` | host prefix build, bootstrap configuration |
| `src/toolchain-llvm.sh` | standalone LLVM/Clang |
| `src/toolchain-prefix.sh`, `src/toolchain-state.sh` | prefix claim, validation, stamp, rustup link, lockfile capture |
| `src/toolchain-runtime.sh`, `src/toolchain-assembly.sh` | moto-rt package check, assembly key, manifest, claim |
| `src/toolchain-native.sh`, `src/toolchain-native-rust-analyzer.sh` | native rustc, rustfmt, rust-analyzer builds and ELF validation |
| `src/toolchain-rust-analyzer*.sh`, `src/toolchain-patched-crates.sh` | rust-analyzer provisioning and its pinned patched crates |
| `src/resolve-toolchain-assembly.sh` | assembly resolution for `make` and the imager |
| `src/build-motor-os.sh`, `src/build-base.sh` | the producer and host provisioning |
| `src/tests/test-toolchain-*.sh` | offline contract tests of the above; `test-toolchain-cutover.sh` ties the selector to the declaration |
| `src/tests/test-build-addons.sh` | offline contract test of the add-on stage of the producer |
