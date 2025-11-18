# Building Motor OS

Motor OS is built (cross-compiled) on Linux. There are three steps:

* install build tools on the host Linux (10-20 min)
* build Motor OS target for Rust (10-30 min)
* build Motor OS (2-5 min)

Time estimates above assume a fairly modern 8-core/16-thread x64 CPU
or better, and a fast SSD drive.

## Install build tools

Motor OS requires Linux host, as it depends on KVM. While any
Linux will probably do, the instructions below assume you are
running Ubuntu 24.04. This will also work with Ubuntu 24.04 under WSL2.

(1) Install the following packages:

```sh
sudo apt update
sudo apt upgrade
sudo apt install git
sudo apt install build-essential
sudo apt install nasm
sudo apt install clang cmake ninja-build libz-dev libssl-dev pkg-config
```

(2) [Install Rust](https://www.rust-lang.org/tools/install).

(3) Add the following Rust magic:

```sh
rustup default nightly-2025-11-17
rustup component add rust-src --toolchain nightly-2025-11-17-x86_64-unknown-linux-gnu
```

(Note: we pin to a specific nightly version for better reproducibility.
See e.g. [issue 18](https://github.com/moturus/motor-os/issues/18)).

## Clone the Motor OS repo

```sh
export MOTORH=$HOME/motorh
mkdir $MOTORH
cd $MOTORH
git clone https://github.com/moturus/motor-os.git
cd motor-os
```

## Build Motor OS target/toolchain for Rust

Motor OS is a [Tier-3 target in Rust](https://doc.rust-lang.org/nightly/rustc/platform-support/motor.html),
which means it has to be compiled locally, as Rust does not provide
pre-built toolchains for Tier-3 targets.

Check out Rust sources:

```sh
cd $MOTORH
git clone https://github.com/rust-lang/rust.git
cd rust
```

Create `bootstrap.toml` file in $MOTORH/rust, as shown below:

```sh
cat > $MOTORH/rust/bootstrap.toml << EOF
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
EOF
```

Build Rust Motor OS target/toolchain:

```sh
cd $MOTORH/rust
./x.py build --stage 2 clippy library src/tools/remote-test-server
```

Note: Tier-3 target API is unstable, so the step above may fail. In this case
please open an issue in [Motor OS repo](https://github.com/moturus/motor-os).

Register the new toolchain:

```sh
rustup toolchain link dev-x86_64-unknown-motor \
  $MOTORH/rust/build/x86_64-unknown-linux-gnu/stage2
```

## Build Motor OS

```sh
cd $MOTORH/motor-os
make all BUILD=release -j$(nproc)
```

Note: Tier-3 target API is unstable, so the step above may fail. In this case
please open an issue in [Motor OS repo](https://github.com/moturus/motor-os).

## Create a tap device that our VMs will use

`$MOTORH/motor-os/vm_images/release/create-tap.sh`

## Run Motor OS

If all of the above completed successfully, you can now do

```sh
sudo apt install qemu-system
sudo chmod a+rw /dev/kvm
cd $MOTORH/motor-os/vm_images/release
./run-qemu.sh
```

to run Motor OS in qemu.

While Motor OS is running, you can ssh into it using
`ssh-into-motor-os-vm.sh` script, or via

```sh
ssh -p 2222 -o IdentitiesOnly=yes -i test.key motor@192.168.4.2
```

## Test

A test script is available:

```sh
cd $MOTORH/motor-os/vm_images/release
./full-test.sh
```
