# Building the complete Motor OS toolchain

`src/build-motor-os.sh` is the single supported entry point for building the
Motor OS compiler/runtime assembly and all release images. It builds Linux-host
Rust tools, standalone LLVM/Clang, the C/C++ sysroot, native Motor LLVM and
rustc, and the OS from one reviewed source tuple.

The current development tuple is the exact Rust 1.99 beta baseline declared in
`src/toolchain-versions.sh`. The Motor fork uses Rust's `dev` channel, so its
Cargo reports `1.99.0-dev`; this is a beta development assembly, not the final
`1.99.0-motor.1` source release.

## Quick start

On Ubuntu 24.04 or 26.04:

```sh
mkdir motor-dev
cd motor-dev
git clone https://github.com/moturus/motor-os.git
cd motor-os
src/build-motor-os.sh
```

`MOTORH` defaults to the parent of the Motor OS checkout. Set it before running
the script only when the development root should live elsewhere:

```sh
export MOTORH=/absolute/path/to/motor-dev
src/build-motor-os.sh --source-mode managed
```

The script installs missing host packages and rustup, so initial provisioning
uses `sudo` and the network. It also configures TAP/KVM prerequisites. Set
`MOTOR_SKIP_HOST_NETWORK_SETUP=1` only after independently verifying that the
required VM networking is already configured.

## Source modes

Managed mode is the default. It resolves the full commits and repository URLs
from `src/toolchain-versions.sh` into private build checkouts:

```text
$MOTORH/toolchain-src/rust/
  src/llvm-project/       Motor LLVM at the Rust gitlink
  src/tools/cargo/        upstream Cargo at the declared gitlink
$MOTORH/toolchain-src/mlibc/
```

Managed inputs must exactly match the declaration. A wrong remote, missing or
unreachable commit, incorrect gitlink, dirty file, or untracked file is an
error. The build never advances a branch, runs `cargo update`, or silently
changes a dependency selection.

Rust and LLVM development uses explicit authoring mode instead of editing the
managed checkout:

```sh
src/build-motor-os.sh \
  --source-mode authoring \
  --rust-source /absolute/path/to/rust \
  --authoring-base FULL_40_CHARACTER_BASE_COMMIT
```

The supplied Rust checkout owns its `src/llvm-project` submodule. Local and
unpushed commits, modified files, and untracked files in both trees become
content-addressed authoring inputs. The build reads them without fetching,
switching, resetting, stashing, cleaning, or updating either worktree. An
authoring toolchain has a distinct non-release description and key and cannot
replace the checked-in managed selector or satisfy source-publication checks.

This separation is what permits work on Motor's Rust and LLVM patches without
weakening the clean managed-build policy.

## Build order and outputs

The workflow performs these stages:

1. Provision host packages, rustup, and VM prerequisites. No global rustup
   default is selected or changed.
2. Resolve and verify the exact Rust, LLVM, Cargo, and mlibc inputs. Hash the
   starting Rust root and library lockfiles.
3. Build standalone host LLVM from the effective LLVM tree and use it as
   rustc's host LLVM.
4. Run Rust bootstrap once to install Linux-host rustc/rustdoc, Cargo, host and
   Motor std, Clippy, rust-analyzer, rustfmt/`cargo-fmt`, and `rust-src` into
   an immutable key-qualified prefix.
5. Register that prefix under its exact rustup name and validate every
   component, source commit, sysroot, lock hash, and both host/target compile
   probes.
6. Fetch the locked `src/sys` workspace dependencies, derive an assembly key,
   and build the C-ABI shim, compiler-rt builtins, mlibc,
   libc++/libc++abi/libunwind, native LLVM, Lua, native rustc, and ripgrep in
   that assembly's private directories.
7. Write immutable host and assembly manifests, then build the base, standard,
   and development images with the exact generated roots.

The two identity levels deliberately differ:

```text
$MOTORH/toolchains/<exact-rustup-name>/
    immutable host compiler prefix, keyed by compiler inputs

$MOTORH/assemblies/<assembly-key>/
    build/       component build trees
    sysroot/     C/C++ cross sysroot and linker wrappers
    images/      generated libc, rg, LLVM, and rustc image overlays
```

A local `moto-rt` or mlibc change selects a new assembly without pretending to
be a different compiler lineage. A Rust, LLVM, Cargo, bootstrap configuration,
or Rust lock selection change selects a new host toolchain prefix as well.
Motor OS component outputs are further isolated under
`build/obj/<toolchain-key>/<profile>/<component>`.

The final images are:

```text
vm_images/release/motor-os-base.img
vm_images/release/motor-os.qcow2
vm_images/release/motor-os-dev.qcow2
```

The standard image includes generated libc configuration and ripgrep. The
development image additionally includes LLVM/Clang, the native Rust toolchain,
headers, libraries, and the complete assembly manifest under
`/devtools/toolchain/manifest`. Generated `/devtools` content is never allowed
to leak into the base or standard image.

## Inspecting the selected tuple

The root `rust-toolchain.toml` names the exact managed toolchain. Bare commands
from the repository therefore select its Cargo and compiler:

```sh
rustc -vV
cargo -Vv
rustc --print sysroot
rustup which cargo
```

The selected sysroot contains:

```text
MOTOR-TOOLCHAIN-MANIFEST
lib/rustlib/MOTOR-TOOLCHAIN-KEY
```

Each completed assembly contains `MOTOR-ASSEMBLY-MANIFEST`; the same content is
copied into every generated overlay. To list local assemblies without guessing
a key:

```sh
find "$MOTORH/assemblies" -mindepth 2 -maxdepth 2 \
  -name MOTOR-ASSEMBLY-MANIFEST -print
```

The manifests record declared and effective Rust/LLVM revisions, Cargo
identity, Stage 0, lock hashes, runtime identities, source state, both keys,
and hashes of the native compiler and sysroot products.

The build also pins its validated assembly for later commands in this checkout.
Inspect or change that host-local selection with:

```sh
src/select-toolchain-assembly.sh --show
src/select-toolchain-assembly.sh --list
src/select-toolchain-assembly.sh --pin ASSEMBLY_KEY
```

See [Selecting a toolchain assembly](assembly-selection.md) for discovery,
validation, noninteractive behavior, and recovery details.

## Re-running and failures

Re-run the same command after a failure. A completed matching prefix or
assembly is reused only after full manifest and artifact validation. Older
keys are retained so invalidation mistakes remain visible; the workflow does
not broadly clear Cargo, LLVM, mlibc, or image build directories.

An adjacent `.building` directory means a producer is active or a previous run
was interrupted. A `MOTOR-TOOLCHAIN-REJECTED` or `MOTOR-ASSEMBLY-REJECTED`
marker preserves an invalid result for diagnosis. Resolve the underlying
source, lockfile, or build defect before removing any marker or output.

If Rust bootstrap rewrites a lockfile, that run's prefix is rejected because
its starting key no longer describes the produced artifact. Review and commit
the visible lockfile change in the Rust fork; the next run derives a new key.

For a deliberately clean managed rebuild, first set and verify the development
root. Then remove the keyed outputs and Rust bootstrap state before rerunning
the build:

```sh
(
  set -eu
  test -n "${MOTORH:-}" && test "$MOTORH" != /
  rm -rf -- "$MOTORH/toolchains"/* \
    "$MOTORH/toolchain-state"/* \
    "$MOTORH/assemblies"/* \
    "$MOTORH/build/toolchain/standalone-llvm"/* \
    "$MOTORH/toolchain-src/rust/build"
  src/build-motor-os.sh --source-mode managed
)
```

The globs include adjacent `.building` producer locks. Inspect the expanded
`MOTORH` and these paths before deleting them. Remove standalone LLVM only
together with all assemblies: their sysroot wrappers refer to that keyed LLVM
directory. The Rust `build/` tree is disposable after a successful build
because each assembly contains copies of the native rustc and LLVM images it
needs.

## Building and testing the repository

After the managed build, the root selector drives ordinary commands:

```sh
make -j"$(nproc)"
make -j"$(nproc)" BUILD=release
cargo fmt --manifest-path src/sys/Cargo.toml --all --check
src/tests/full-test.sh
src/tests/full-test.sh --release
```

Do not add explicit `+nightly`, `+stable`, or legacy `+dev-*` selectors. Rust's
Stage 0 compiler is used only internally by `x.py`.

The final stable-release rebase and immutable source tags are intentionally
deferred until upstream Rust 1.99.0 is published. See
[toolchain.md](toolchain.md), section 6.1, for that release procedure.
