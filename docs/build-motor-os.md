# Building Motor OS with its external sources

`src/build-motor-os.sh` is the single supported entry point for building the
external sources and all release images with the Motor OS toolchain that
`rust-toolchain.toml` names. The scripts it and the Makefile use are in
`src/build-scripts/`. The toolchain itself is built and released by
[motor-os-toolchain](https://github.com/moturus/motor-os-toolchain);
[toolchain.md](toolchain.md) describes how this repository installs and uses
it. The current toolchain is `x86_64-unknown-motor-1.99.1`: upstream Rust
1.99.1 with the Motor OS patches. Its compilers use Rust's `dev` channel, so
rustc and Cargo report `1.99.1-dev`.

## Quick start

On Ubuntu 24.04 or 26.04, install rustup before the host toolchain. If it is
not installed yet:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
  sh -s -- -y --default-toolchain none
. "$HOME/.cargo/env"
```

If rustup is already installed, ensure it is on `PATH`. With the two
toolchain archives downloaded into the development root:

```sh
mkdir motor-dev
cd motor-dev
git clone https://github.com/moturus/motor-os.git
tar -xaf motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst
motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux/install.sh
rm -rf motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux
cd motor-os
src/build-motor-os.sh
```

The native archive, `motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst`,
stays in the development root, `MOTORH`, which defaults to the parent of the
Motor OS checkout. Set it before running the script only when the archives
live elsewhere:

```sh
export MOTORH=/absolute/path/to/motor-dev
src/build-motor-os.sh
```

The script reads only the native archive from there and writes nothing
there. Everything else stays in the checkout: the external sources in
`external-sources/`, the build trees and the assembly in `build/`, and the
images in `vm_images/`.

The script installs missing host packages and rustup, so initial provisioning
uses `sudo` and the network. It also configures TAP/KVM prerequisites. Every
`sudo` command runs in this first step, before anything is built; the long
build that follows never asks for a password. Set
`MOTOR_SKIP_HOST_NETWORK_SETUP=1` only after independently verifying that the
required VM networking is already configured.

## External sources

The external sources are the userspace programs built beside Motor OS:
ripgrep, Helix, uutils sed, Lua, tar and zstd, Javy/Wasmi, and Wasmtime. They
are cloned into `external-sources/`, which Git ignores. ripgrep, Helix, sed,
and motor-os-tar follow one branch of their forks, in
`external-sources/ripgrep`, `external-sources/helix`, `external-sources/sed`,
and `external-sources/motor-os-tar`. Javy/Wasmi and Wasmtime are built from
one branch of their forks at the exact revision declared in
`src/build-scripts/external-sources.sh`, in `external-sources/javy` and
`external-sources/wasmtime`: a clean checkout is moved to that revision, and
commits that are not on the fork's branch are never left behind. Everything
the forks depend on — Wasmi, Wizer, Tokio, Mio and target-lexicon by git, and
the Motor OS crates `moto-rt` and `moto-sys` from crates.io — is pinned by the
forks' lockfiles, which Cargo fetches; no fork refers to another checkout,
and this tree's `src/sys/lib` is not an input of the external sources. Lua is
a release, and so is the wasi-sdk that javy-smoke's test plugins need; both
are downloaded into `external-sources/`.

Before building, the script prepares all external sources and checks their
lockfiles. The shared inventory in `src/build-scripts/external-sources.sh`
covers ripgrep, Helix, sed, motor-os-tar, Javy, Wasmtime, the independent
Motor OS test workspaces in the forks, and the Motor OS smoke/plugin workspaces.
Upstream-only release and standalone fuzz workspaces are excluded. The
`--javy-only` and `--wasmtime-only` paths check their selected workspaces
too.

The check uses `cargo update --workspace --locked`: Cargo retains existing
dependency selections wherever valid, prints required changes, and refuses to
modify a stale lockfile. Builds may fetch registry metadata for this check.
All workspace failures are reported together in `build/external-lockfiles.log`,
along with the selected source commits and working-tree status. A stale
lockfile must be updated and reviewed in its owning repository; validation
never repairs it automatically.

Before offline compilation, Javy and Wasmtime fetch their complete locked
dependency graphs. Target-filtered fetches can miss host dependencies reached
through Motor OS-only dependency edges, even when Motor OS and Linux are fetched
separately. Fetching without a target filter also makes cold-cache builds
independent of packages left over from earlier builds.
Wasmtime's independent `motor-tests` workspace is fetched separately using
its own lockfile before offline compilation.

To validate an existing set of checkouts without fetching or compiling:

```sh
src/build-scripts/check-external-sources.sh
```

This command uses the same inventory and the Motor OS Cargo, with `--offline`.
Missing checkouts or cached dependency metadata fail validation with their
original diagnostics; they are not reported as version drift.

## Build order and outputs

The workflow performs these stages:

1. Check that the native archive of the toolchain `rust-toolchain.toml`
   names is in `$MOTORH`, then provision host packages, rustup, and VM
   prerequisites. No global rustup default is selected or changed.
2. Export that name as `RUSTUP_TOOLCHAIN`, so that the external sources that
   pin toolchains of their own build with it too. It must be installed in
   rustup.
3. Prepare the external sources and check their lockfiles.
4. Unpack the native toolchain's overlays into the assembly with
   motor-os-tar's `tar`, built for Linux.
5. Build the external sources into the assembly: Lua, ripgrep,
   Helix, sed, tar and zstd, Javy/Wasmi, and Wasmtime, and fetch the
   dependencies of the developer image's library sources. Every run builds
   them all again; their Cargo target directories in the assembly keep that
   incremental.
6. Build the base, standard, development, and wasm images with
   `make images BUILD=release`.

The assembly holds what the images take from outside the tree:

```text
build/assembly/
    build/       the external sources' build trees
    images/      toolchain overlays (libc, llvm, rustc, rust-analyzer),
                 overlays of the external sources (lua, rg, tar, helix, sed,
                 javy, wasmtime), and sys-lib-deps
    tests/       the Javy and Wasmtime test inputs
```

Motor OS components build in `build/obj/<profile>/<component>`.

The final images are:

```text
vm_images/release/motor-os-base.img
vm_images/release/motor-os.qcow2
vm_images/release/motor-os-dev.qcow2
vm_images/release/motor-os-wasm.qcow2
```

The standard image includes the libc configuration, ripgrep, tar, and zstd.
The development image additionally includes LLVM/Clang, the native Rust
toolchain, rust-analyzer with matching `rust-src`, headers, and libraries.
Generated `/devtools` content is never allowed to leak into the base or
standard image.

The native rust-analyzer lives at `/devtools/rust/bin/rust-analyzer` and its
sources at `/devtools/rust/lib/rustlib/src/rust/library`. The image contains
no Cargo shim and does not launch the server at boot. See the
[native server guide](build-rustc.md#native-motor-os-rust-analyzer) for the
explicit Lorry environment, trusted-project configuration, and current
acceptance status.

## Inspecting the toolchain

The root `rust-toolchain.toml` names the toolchain. Bare commands from the
repository therefore run its Cargo and compiler:

```sh
rustc -vV
cargo -Vv
```

## Re-running and failures

Re-run the same command after a failure. Every run builds the external
sources again and unpacks the native toolchain's overlays again; Cargo and
make rebuild only what changed.

After installing a different toolchain, or a rebuild of the same one, remove
all build artifacts first:

```sh
make clean
src/build-motor-os.sh
```

`make clean` removes all of `build/`, the assembly included, and the other
build artifacts in the tree, but not `external-sources/`.

## Building and testing the repository

After the build, the root selector drives ordinary commands:

```sh
make -j"$(nproc)"
make -j"$(nproc)" BUILD=release
cargo fmt --manifest-path src/sys/Cargo.toml --all --check
src/tests/full-test.sh
src/tests/full-test.sh --release
```

Do not add explicit `+nightly`, `+stable`, or legacy `+dev-*` selectors. See
[toolchain.md](toolchain.md), section 7, for moving to another toolchain.
