# Building Motūrus OS

Motūrus OS is built on Linux. There are three steps:

* install build tools on the host Linux (10-20 min)
* build Motūrus OS target for Rust (30-60 min)
* build Motūrus OS (2-5 min)

Time estimates above assume a fairly modern 8-core/16-thread x64 CPU
or better, and a fast SSD drive.

## Install build tools

Motūrus OS requires Linux host, as it depends on KVM. While any
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
$ rustup default nightly
$ rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
$ cargo install --force cargo-make
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

## Build Motūrus OS target for Rust

Check out Rust sources with Motūrus target added:

```
$ cd $MOTORH
$ git clone -b moturus-2024-01-28 https://github.com/moturus/rust.git
```

Build Rust Motūrus target/toolchain:

```
$ cd $MOTORH/rust
$ ./x.py build --stage 2 library
```

Register the new toolchain:

```
$ rustup toolchain link dev-x86_64-unknown-moturus \
    $MOTORH/rust/build/x86_64-unknown-linux-gnu/stage2
```

## Build Motūrus OS

```
$ cd $MOTORH/motor-os
$ cargo make boot_img_release
```

## Run Motūrus OS

If all of the above completed successfully, you can now do

```
$ sudo apt install qemu-system
$ sudo chmod a+rw /dev/kvm
$ cd $MOTORH/motor-os/vm_images/release
$ ./run-qemu-web.sh
```

to run the minimal image with a web server, which you can access from the host at http://localhost:10023. To run the full image
with serial console, use ```./run-qemu-full.sh```
