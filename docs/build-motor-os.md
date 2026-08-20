# Building all of Motor OS

Motor OS is cross-compiled on Linux. The complete build includes:

* the Rust target toolchain used to build Motor OS;
* the Motor C and C++ sysroot based on mlibc;
* host LLVM/Clang tools that cross-compile for Motor OS;
* LLVM/Clang and rustc binaries that run natively on Motor OS;
* Lua, ripgrep (`/system/bin/rg`), and the native compiler sample programs;
* all Motor OS services and utilities, including the DNS resolver;
* the final bootable release image.

The first complete build takes several hours because it builds LLVM twice and
also builds a native Rust compiler. Re-running the build is incremental.
A fast SSD and at least 100 GB of free disk space are recommended.

## Install the initial host tools

The build requires an x86-64 Linux host with KVM. The automated workflow is
written for Ubuntu 24.04, including Ubuntu 24.04 under WSL2.

Install Git so the Motor OS repository can be cloned:

```sh
sudo apt update
sudo apt install git
```

The build script installs any other missing packages, including the compiler
tools, Meson, Ninja, QEMU, and development libraries. It also installs rustup
when necessary. Those setup steps use `sudo` and require network access.

## Create the Motor OS development directory

All source repositories and cross-build outputs use one common parent
directory:

```text
$MOTORH/
  motor-os/
  rust/
  llvm-project/
  mlibc/
  ripgrep/
  motor-sysroot/
  lua-5.4.8/
```

Create that directory and clone Motor OS:

```sh
export MOTORH=$HOME/motorh
mkdir -p "$MOTORH"
cd "$MOTORH"
git clone https://github.com/moturus/motor-os.git
cd motor-os
```

`MOTORH` defaults to the parent of the Motor OS checkout, so exporting it is
optional when using the layout above.

## Build everything

Run the unified build:

```sh
cd "$MOTORH/motor-os"
./src/build-motor-os.sh
```

The workflow performs the following stages in order.

### 1. Build the moto-rt v17 Motor Rust target

The script:

* installs the required Ubuntu packages;
* installs the pinned `nightly-2026-06-19` Rust toolchain and `rust-src`;
* clones `moturus/rust` branch `motor-os-rt-v17` when it is absent;
* builds the stage-2 `x86_64-unknown-motor` target libraries and Clippy;
* registers them as the `dev-x86_64-unknown-motor` rustup toolchain;
* configures the `moto-tap` interface and `/dev/kvm` access.

The standalone base workflow can build its image at this point. The unified
build deliberately skips that intermediate image because the final compiler
replaces these outputs before all three definitive images are built.

### 2. Build LLVM, mlibc, and the C/C++ sysroot

The script clones the `motor-os-rustc` branches of the Motor mlibc and LLVM
forks, then builds:

* host Clang, LLD, and LLVM utilities targeting `x86_64-unknown-motor`;
* `libmoto_rt_cabi.a`, compiler-rt builtins, mlibc, and `crt1.o`;
* libunwind, libc++abi, and libc++;
* the LLVM multicall binary that runs natively on Motor OS;
* Lua for Motor OS.

The cross sysroot is written to:

```text
$MOTORH/motor-sysroot/devtools/llvm
```

This is also the C SDK used to compile and link the DNS resolver. There is no
separate downloaded DNS SDK.

### 3. Build native rustc and the final image

The Rust checkout is switched from `motor-os-rt-v17` to the Motor
compiler-only `motor-os-rustc` branch. The script
then:

* builds a Rust compiler that runs on `x86_64-unknown-motor`;
* builds the host and Motor standard libraries together with Clippy;
* verifies that the registered stage-2 toolchain can compile for both targets;
* rebuilds `libmoto_rt_cabi.a` with that final toolchain;
* verifies that its startup and memory fallbacks are weak, then links the DNS
  resolver without the bootstrap toolchain's duplicate-symbol compatibility
  option;
* stages the native Rust compiler and target sysroot;
* clones or safely fast-forwards the clean Motor ripgrep `master` checkout,
  cross-builds it with the final Motor toolchain, and stages it as `/system/bin/rg`;
* clears Cargo outputs made by the replaced bootstrap compiler;
* runs `make images BUILD=release`, which builds the base, standard, and
  development images with their exact component closures.

The final images are:

```text
$MOTORH/motor-os/vm_images/release/motor-os-base.img
$MOTORH/motor-os/vm_images/release/motor-os.qcow2
$MOTORH/motor-os/vm_images/release/motor-os-dev.qcow2
```

## Generated image inputs

Files stored in Git are cumulative static overlays under:

```text
img_files/motor-os-base/
img_files/motor-os/
img_files/motor-os-dev/
```

Native compiler artifacts are generated separately:

```text
img_files/generated/llvm/
img_files/generated/rustc/
img_files/generated/rg/
img_files/generated/libc/
```

These generated directories are ignored by Git. The standard image combines
the base and standard static overlays with generated libc configuration and
ripgrep. The development image adds its static overlay and the LLVM and Rust
trees. This keeps large compiler outputs, generated headers, libraries, and
configuration files separate from the repository's static image content.

`make all` builds the standard image and therefore requires the generated libc
and ripgrep overlays. It does not consume LLVM or rustc. `make dev.img`
requires all generated roots and fails rather than silently producing a
partial development image. The unified build populates every generated root
before its final image build.

## Re-running and diagnosing the build

The build scripts reuse existing source checkouts and incremental compiler
outputs. Re-run the same command after a failure:

```sh
./src/build-motor-os.sh
```

Ripgrep is the narrow exception to the other source checkouts' clone-once
behavior: each run fetches the Motor fork's current `master` and fast-forwards
an existing clean `master` checkout. The script refuses to overwrite a dirty,
detached, locally-ahead, or diverged ripgrep checkout and asks for manual
resolution instead.

The native Rust stage intentionally clears Motor OS Cargo outputs after
replacing the compiler. Cargo identifies two locally built compilers with the
same version too coarsely to safely reuse those artifacts.

Detailed standalone recipes and troubleshooting notes remain in
[build-llvm.md](build-llvm.md) and [build-rustc.md](build-rustc.md).

## Run Motor OS

If the build completed successfully, boot the development image to exercise
the native toolchains:

```sh
cd "$MOTORH/motor-os/vm_images/release"
MOTO_IMAGE=motor-os-dev.qcow2 ./run-qemu.sh
```

In another terminal, connect over SSH:

```sh
cd "$MOTORH/motor-os"
./ssh-into-motor-os-vm.sh
```

The native tools can then be checked inside Motor OS:

```sh
/devtools/llvm/bin/llvm clang --version
/devtools/bin/rustc --version
rg --version
ping google.com
```

To build the release image and run the complete VM integration suite, including
DNS resolution, use:

```sh
cd "$MOTORH/motor-os"
./src/tests/full-test.sh --release
```
