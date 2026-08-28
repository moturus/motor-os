# Building Motor OS

Motor OS is cross-compiled on Linux. The supported build entry point has been
tested on Ubuntu 24.04 and 26.04.

```sh
mkdir motor-dev
cd motor-dev
git clone https://github.com/moturus/motor-os.git
cd motor-os
src/build-motor-os.sh
```

The script installs missing host packages and rustup, configures the VM host,
checks out the exact Rust, LLVM, Cargo, and mlibc revisions declared in
`src/toolchain-versions.sh`, builds the complete host and native toolchains,
and creates all three release images. Package installation and VM networking
setup use `sudo`; managed source and dependency acquisition uses the network.

The repository's `rust-toolchain.toml` selects the exact, key-qualified Motor
toolchain. After the unified build succeeds, ordinary repository commands use
that toolchain without a `+nightly`, `+stable`, or legacy `+dev-*` selector:

```sh
cargo -Vv
make -j"$(nproc)"
cargo fmt --manifest-path src/sys/Cargo.toml --all --check
```

Build products are isolated by their complete input identities. By default,
the parent of the Motor OS checkout contains:

```text
toolchain-src/   exact managed Rust/LLVM and mlibc sources
toolchains/      immutable key-qualified host toolchain prefixes
assemblies/      keyed C sysroots, native tools, and generated image roots
```

Re-running `src/build-motor-os.sh` validates and reuses a complete matching
prefix or assembly. It does not broadly delete older keyed outputs.

For the source layout, authoring mode, generated manifests, and update policy,
see [Building the complete toolchain](build-motor-os.md). The LLVM/C++ and
native Rust components are described in [build-llvm.md](build-llvm.md) and
[build-rustc.md](build-rustc.md); they are not separate build entry points.
Persistent host selection and recovery commands are documented in
[Selecting a toolchain assembly](assembly-selection.md).

## Run Motor OS

The release images are written beneath `vm_images/release`. To boot the
standard image:

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
