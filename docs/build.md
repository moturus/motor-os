# Building Motor OS

Motor OS is built on Linux. There are three steps:

* install build tools on the host Linux (10-20 min)
* build Motor OS target for Rust (30-60 min)
* build Motor OS (2-5 min)

Time estimates above assume a fairly modern 8-core/16-thread x64 CPU
or better, and a fast SSD drive.

## Install build tools

Motor OS requires Linux host, as it depends on KVM. While any
Linux will probably do, the instructions below assume you are
running Ubuntu 22.04. This will also work with Ubuntu 22.04 under WSL2.

(1) Install the following packages:

```
$ sudo apt update
$ sudo apt upgrade
$ sudo apt install git
$ sudo apt install build-essential
$ sudo apt install nasm
$ sudo apt install clang cmake ninja-build libz-dev libssl-dev pkg-config
```

(2) [Install Rust](https://www.rust-lang.org/tools/install).

(3) Add the following Rust magic:

```
$ rustup default nightly-2025-10-16
$ rustup component add rust-src --toolchain nightly-2025-10-16-x86_64-unknown-linux-gnu
```

(Note: we pin to a specific nightly version for better reproducibility.
See e.g. [issue 18](https://github.com/moturus/motor-os/issues/18)).

## Build Motor OS target/toolchain for Rust

Motor OS is a [Tier-3 target in Rust](https://doc.rust-lang.org/nightly/rustc/platform-support/motor.html),
which means it has to be compiled locally, as Rust does not provide
pre-built toolchain for Tier-3 targets.

Check out Rust sources:

```
$ cd $MOTORH
$ git clone https://github.com/rust-lang/rust.git
$ cd rust
```

Create `bootstrap.toml` file $MOTORH/rust:

```
change-id = 146458

profile = "library"

[build]
host = ["x86_64-unknown-linux-gnu"]
target = ["x86_64-unknown-linux-gnu", "x86_64-unknown-motor"]

[rust]
deny-warnings = false
incremental = true
# debug = true
# debuginfo-level = 2
```

Build Rust Motor OS target/toolchain:

```
$ cd $MOTORH/rust
$ TARGET=x86_64-unknown-motor \
    CARGO_CFG_TARGET_ARCH=x86_64 \
    CARGO_CFG_TARGET_VENDOR=unknown \
    CARGO_CFG_TARGET_OS=motor \
    CARGO_CFG_TARGET_ENV="" \
    ./x.py build --stage 2 clippy library
```
Note: Tier-3 target API is unstable, so the step above may fail. In this case
please open an issue in [Motor OS repo](https://github.com/moturus/motor-os).

Register the new toolchain:

```
$ rustup toolchain link dev-x86_64-unknown-motor \
    $MOTORH/rust/build/x86_64-unknown-linux-gnu/stage2
```

## Clone the Motor OS repo:

```
$ export MOTORH=$HOME/motorh
$ mkdir $MOTORH
$ cd $MOTORH
$ git clone https://github.com/moturus/motor-os.git
$ cd motor-os
$ git submodule update --init --recursive
```


## Build Motor OS

```
$ cd $MOTORH/motor-os
$ make all BUILD=release -j$(nproc)
```

Note: Tier-3 target API is unstable, so the step above may fail. In this case
please open an issue in [Motor OS repo](https://github.com/moturus/motor-os).

## Create a tap device that our VMs will use

```
$ sudo ip tuntap add mode tap moto-tap
$ sudo ip addr add 192.168.4.1/24 dev moto-tap
$ sudo ip link set moto-tap up
```

## Run Motor OS

If all of the above completed successfully, you can now do

```
$ sudo apt install qemu-system
$ sudo chmod a+rw /dev/kvm
$ cd $MOTORH/motor-os/vm_images/release
$ ./run-qemu-web.sh
```

to run the minimal image with a web server, which you can access from the host at http://192.168.4.2. To run the full image
with serial console, use ```./run-qemu-full.sh```
