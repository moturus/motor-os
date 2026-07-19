# Building all of Motor OS

Motor OS is cross-compiled on Linux. The complete build includes:

* the Rust target toolchain used to build Motor OS;
* the Motor C and C++ sysroot based on mlibc;
* host LLVM/Clang tools that cross-compile for Motor OS;
* LLVM/Clang and rustc binaries that run natively on Motor OS;
* Lua and the native compiler sample programs;
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

### 1. Bootstrap the Motor Rust target

The script:

* installs the required Ubuntu packages;
* installs the pinned `nightly-2026-06-19` Rust toolchain and `rust-src`;
* clones the Rust repository when it is absent;
* builds the stage-2 `x86_64-unknown-motor` target libraries and Clippy;
* registers them as the `dev-x86_64-unknown-motor` rustup toolchain;
* configures the `moto-tap` interface and `/dev/kvm` access.

The old base workflow built a Motor OS image at this point. The unified build
deliberately defers that image: `/sys/dns-resolver` contains an mlibc C bridge,
so it cannot be linked until the next stage has produced the C sysroot.

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
$MOTORH/motor-sysroot/sys/tools/llvm
```

This is also the C SDK used to compile and link the DNS resolver. There is no
separate downloaded DNS SDK.

### 3. Build native rustc and the final image

The Rust checkout is switched to the Motor `motor-os-rustc` branch. The script
then:

* builds a Rust compiler that runs on `x86_64-unknown-motor`;
* builds the host and Motor standard libraries together with Clippy;
* verifies that the registered stage-2 toolchain can compile for both targets;
* rebuilds `libmoto_rt_cabi.a` with that final toolchain;
* verifies that its startup and memory fallbacks are weak, then links the DNS
  resolver without the bootstrap toolchain's duplicate-symbol compatibility
  option;
* stages the native Rust compiler and target sysroot;
* clears Cargo outputs made by the replaced bootstrap compiler;
* runs `make all BUILD=release`, which builds every Motor OS binary, the DNS
  resolver, and the final image.

The final image is:

```text
$MOTORH/motor-os/vm_images/release/motor-os.img
```

## Generated image inputs

Files stored in Git remain under:

```text
img_files/motor-os/
```

Native compiler artifacts are generated separately:

```text
img_files/generated/llvm/
img_files/generated/rustc/
```

These generated directories are ignored by Git. The imager combines all three
directories at the filesystem root. This keeps large compiler outputs,
generated headers, libraries, and configuration files separate from the
repository's static image content.

A normal `make all` also works when either generated directory is absent; the
resulting image simply does not contain that native toolchain. The unified
build always populates both directories before its final image build.

## Re-running and diagnosing the build

The build scripts reuse existing source checkouts and incremental compiler
outputs. Re-run the same command after a failure:

```sh
./src/build-motor-os.sh
```

The native Rust stage intentionally clears Motor OS Cargo outputs after
replacing the compiler. Cargo identifies two locally built compilers with the
same version too coarsely to safely reuse those artifacts.

Detailed standalone recipes and troubleshooting notes remain in
[build-llvm.md](build-llvm.md) and [build-rustc.md](build-rustc.md).

## Run Motor OS

If the build completed successfully:

```sh
cd "$MOTORH/motor-os/vm_images/release"
./run-qemu.sh
```

In another terminal, connect over SSH:

```sh
cd "$MOTORH/motor-os"
./ssh-into-motor-os-vm.sh
```

The native tools can then be checked inside Motor OS:

```sh
/sys/tools/llvm/bin/llvm clang --version
/sys/tools/rust/bin/rustc --version
ping google.com
```

To build the release image and run the complete VM integration suite, including
DNS resolution, use:

```sh
cd "$MOTORH/motor-os"
./src/tests/full-test.sh --release
```
