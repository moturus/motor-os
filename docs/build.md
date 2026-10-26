# Building Motor OS

Motor OS is cross-compiled on Linux. The supported build entry point has been
tested on Ubuntu 24.04 and 26.04. It needs the Motor toolchain that
`rust-toolchain.toml` names, `x86_64-unknown-motor-1.99.1`, as two archives
from [motor-os-toolchain](https://github.com/moturus/motor-os-toolchain): its
release, or a build of that repository.

First build the toolchain, which does not need a Motor OS checkout. On
Ubuntu 24.04 or 26.04, create the development root and clone the toolchain
repository inside it:

```sh
sudo apt-get update
sudo apt-get install git zstd
mkdir motor-dev
cd motor-dev
git clone https://github.com/moturus/motor-os-toolchain.git
cd motor-os-toolchain
./build-toolchain.sh --provision
cd ..
```

`--provision` installs missing build packages with `sudo` and installs rustup.
The build fetches the sources selected by the toolchain repository's
`versions.sh` and builds both the Linux-host cross toolchain and the native
Motor OS toolchain. It writes these files into its parent directory,
`motor-dev`, where the commands above leave you:

```text
motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst
motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst.sha256
motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst
motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst.sha256
```

Each toolchain build starts from scratch, replaces archives of the same name,
and removes its `build/` directory after success. Allow about 30 GB of disk
space during the build; the toolchain README estimates about 50 minutes on
24 cores. See its [build instructions](https://github.com/moturus/motor-os-toolchain#building)
for details. The resulting toolchain name must match `rust-toolchain.toml`
in the Motor OS checkout.

Alternatively, download both archives and their checksum files from a matching
toolchain release into `motor-dev`, then enter that directory. GNU tar needs
`zstd` on the host to extract the `.tar.zst` archive.

Install rustup before the host toolchain. If it is not installed yet:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
  sh -s -- -y --default-toolchain none
. "$HOME/.cargo/env"
```

If rustup was installed by `--provision`, load it into your current shell with
`. "$HOME/.cargo/env"`; otherwise ensure it is on `PATH`. From `motor-dev`,
verify both archives, install the host toolchain, and build Motor OS:

```sh
sha256sum -c motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst.sha256
sha256sum -c motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst.sha256
git clone https://github.com/moturus/motor-os.git
tar -xaf motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux.tar.zst
motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux/install.sh
rm -rf motor-toolchain-x86_64-unknown-motor-1.99.1-x86_64-linux
cd motor-os
src/build-motor-os.sh
```

`install.sh` installs the Linux-host toolchain and links it into rustup; the
native archive, `motor-toolchain-x86_64-unknown-motor-1.99.1.tar.zst`, stays
in the development root ([toolchain.md](toolchain.md)). The script installs
missing host packages and rustup, configures the VM host, builds the external
sources, and creates the base, standard, developer, and wasm release images.
Package installation and VM networking setup use `sudo`, and both run at the
very start, so the rest of the build can be left unattended; the external
sources and dependencies come from the network. If the build is interrupted or
fails, run the same command again.

Ordinary repository commands use the selected toolchain without a
`+nightly`, `+stable`, or legacy `+dev-*` selector:

```sh
cargo -Vv
make -j"$(nproc)"
cargo fmt --manifest-path src/sys/Cargo.toml --all --check
```

The build reads the native archive from the parent of the Motor OS checkout
(the development root) and writes nothing there. Everything it fetches or
builds stays in the checkout, in directories Git ignores:

```text
external-sources/
    ripgrep/ helix/ sed/ motor-os-tar/
                 fork checkouts that follow a branch
    javy/ wasmtime/
                 the Javy/Wasmi and Wasmtime fork checkouts, at their revisions
    lua-<version>/
                 the Lua release
    wasi-sdk-24.0-x86_64-linux/
                 pinned wasi-sdk for the QuickJS code of the Javy test plugins
build/assembly/  the image overlays of the native toolchain and of the
                 external sources, and the external sources' build trees
build/obj/       the Motor OS build trees
vm_images/       the images
```

If the native archive lives elsewhere, set its directory explicitly:

```sh
export MOTORH=/absolute/path/to/motor-dev
src/build-motor-os.sh
```

The build exports the selected name as `RUSTUP_TOOLCHAIN`, so external
sources that carry their own selectors use the same Motor toolchain.
It checks the external workspaces' lockfiles before compiling; failures
are collected in `build/external-lockfiles.log`. Update a stale lockfile in
its owning repository; the build does not repair it. See the
[external-source guide](build-motor-os.md#external-sources).

Every run of `src/build-motor-os.sh` builds all external sources again, which
Cargo keeps incremental. After installing a different or rebuilt toolchain,
run `make clean` first: it removes all build artifacts, including the assembly
and images, while keeping `external-sources/`. There are no toolchain or
assembly content keys to isolate old objects. Follow the
[toolchain update procedure](toolchain.md#7-changing-the-toolchain), including
its validation gates, for either a new version or a replacement `-dev` build.

With a built assembly, build just Javy, Wasmtime, and their images with:

```sh
src/build-motor-os.sh --javy-only --wasmtime-only
make dev.img wasm.img BUILD=release -j"$(nproc)"
```

Both images install `/devtools/bin/javy`, `/devtools/bin/wasmi` and the
runtime-only `/devtools/bin/wasmtime-rt`, with Javy's default plugin at
`/devtools/javy/plugins/default.wasm` and build provenance under
`/devtools/javy` and `/devtools/wasmtime`. See
[WebAssembly on Motor OS](wasm.md) for the installed files and the developer
image's example under `/devtools/src/wasm`.

The developer image also stages Motor OS library sources in
`/devtools/src/motor-os/sys/lib` for offline native `lorry test` runs: moto-sdk
with moto-rt and moto-sys. Their crates.io dependencies are an overlay of the
assembly too, locked to `src/sys/Cargo.lock`. moto-sdk uses tokio only on
Unix, and Motor OS never builds it, but Cargo.lock covers every target. So the
staged workspace
patches tokio to an empty placeholder package, `tokio-placeholder`, and no
tokio sources reach the image. When the lock changes the dependencies, refresh
that overlay with:

```sh
src/build-motor-os.sh --sys-lib-deps-only
```

`make dev.img` then boots the new image once under QEMU to admit that
workspace and compile its dependencies: about 10 seconds for a release image
and 4 minutes for a debug one. So it needs the `moto-tap` network below and no
other running VM.

The wasm image has a 1 GiB data partition and does not include the native
development toolchain. The full Wasmtime compiler follows in a later milestone.

On Motor, compile into a writable directory and execute with explicit masks:

```sh
MOTOR_OS_CAPS=0x200 /devtools/bin/javy build hello.js -o /none/tmp/hello.wasm
MOTOR_OS_CAPS=0 /devtools/bin/wasmi /none/tmp/hello.wasm
```

Javy and Wasmtime follow published `moturus` branches and record resolved
revisions, the toolchain, native library content, and input digests in
`/devtools/javy/sources.txt` and `/devtools/wasmtime/sources.txt`. Their test
inputs are staged outside the images, in the assembly's `tests/javy` and
`tests/wasmtime`, and uploaded by the tests; the Wasmtime fixtures and two
custom Javy plugins are built with a pinned upstream Rust that has the
`wasm32-wasip1`/`wasm32-wasip2` targets, the plugins' QuickJS code with the
pinned wasi-sdk. Build-time downloads are
digest-checked; the installed-tool tests require no Internet access:

```sh
src/tests/test-wasm.sh --prepare
src/tests/test-wasm.sh
```

By default these Rust checks run both release images at 256 and 224 MiB
(`--vm IMAGE:MIB` selects VMs instead), with the repeat-for-identical-bytes
checks on the first VM only: Javy static and
dynamic compilation, TypeScript, default and custom plugins, Wasmi execution,
memory limits and a deliberately refused page fault, errors, fuel and
permission refusals, and `wasmtime-rt` lifecycle, limits, artifact
refusals, TypeScript and WASI p2 sockets. `src/tests/full-test-dev.sh --release`
runs them on the wasm image at 224 MiB and the developer image at 256 MiB, and
the Linux identity checks once; debug suites skip them.
Engine regressions remain in the owning forks. Upstream Brotli is used; compressed
source bytes can differ between Linux and Motor because their math libraries
round some logarithms differently.

For the external sources, the build stages, and their outputs, see
[Building Motor OS with its external sources](build-motor-os.md); for how the
toolchain is installed, selected, and changed, see [toolchain.md](toolchain.md).
The C/C++ and Rust toolchains on Linux and on Motor OS are described in
[build-llvm.md](build-llvm.md) and [build-rustc.md](build-rustc.md). Which
Motor OS crates are published, and how programs depend on them, is in
[Motor OS crates](crates.md).

## Run Motor OS

The release images are written beneath `vm_images/release`, together with a
statically linked [imager](imager.md) in `vm_images/release/tools/` for editing
them on any x86-64 Linux host. To boot the standard image:

```sh
cd vm_images/release
./run-qemu.sh
```

While the VM is running, connect with
`src/vm_scripts/ssh-into-motor-os-vm.sh`, or directly:

```sh
ssh -p 2222 -o IdentitiesOnly=yes -i src/tests/test.key motor@192.168.4.2
```

The build also creates the `moto-tap` host interface and installs the IPv4
forwarding and nftables masquerade rules that let VMs reach the Internet. These
settings do not survive a host reboot; restore them afterwards with
`vm_images/release/create-tap.sh` (it uses `sudo`), or by re-running
`src/build-motor-os.sh`.

Run the full debug or release integration suite from the repository root:

```sh
src/tests/full-test.sh
src/tests/full-test.sh --release
```

The suite runs under QEMU, which the build installs. It also boots the image
once under Cloud Hypervisor and once under Firecracker when
`cloud-hypervisor-static` and `firecracker` are on `PATH`. Without them those
two boot checks are skipped, and the suite says so after its final `PASS` line.
Selecting one of them with `--vmm chv` or `--vmm fc` requires its binary.
