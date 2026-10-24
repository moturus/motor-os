#!/usr/bin/env bash
# Exact source tuple for the Rust 1.99.1 Motor toolchain.
#
# This file is data only. Derived keys, checkout observations, and Motor OS
# worktree state belong in generated manifests.

MOTOR_GENERATED_MANIFEST_SCHEMA="motor-toolchain-manifest-v1"
MOTOR_TOOLCHAIN_KEY_SCHEMA="motor-toolchain-key-v4"
MOTOR_ASSEMBLY_KEY_SCHEMA="motor-assembly-key-v6"

MOTOR_TOOLCHAIN_ID="1.99.1-motor.1"
MOTOR_RUSTUP_TOOLCHAIN_BASE="motor-1.99.1"
MOTOR_TOOLCHAIN_MATURITY="stable"

UPSTREAM_RUST_VERSION="1.99.1"
UPSTREAM_RUST_REPOSITORY="https://github.com/rust-lang/rust.git"
UPSTREAM_RUST_REF="refs/tags/1.99.1"
UPSTREAM_RUST_REV="58cf8f9c35b355199727627d07ae34a4e2846d67"
UPSTREAM_STAGE0_REV="88d9e12ae178fab0fb5cc050a94da85685d449ea"

RUST_LLVM_VERSION="23.1.1"
RUST_LLVM_REPOSITORY="https://github.com/rust-lang/llvm-project.git"
RUST_LLVM_BASE_REV="1b9c0d5ff9bbe7634aead059efe6b11a7eeba145"

MOTOR_LLVM_REPOSITORY="https://github.com/moturus/llvm-project.git"
MOTOR_LLVM_REF="refs/heads/motor-os-1.99.1"
MOTOR_LLVM_REV="366c9278e2bf5ac6e539694efcccf7fc585a3504"

MOTOR_RUST_REPOSITORY="https://github.com/moturus/rust.git"
MOTOR_RUST_REF="refs/heads/motor-os-1.99.1"
MOTOR_RUST_REV="5e1a4656d25fe8a581fab4f208b416d7259fce91"
MOTOR_RUST_CHANNEL="dev"
MOTOR_CARGO_VERSION="1.99.1-dev"
MOTOR_CARGO_REPOSITORY="https://github.com/rust-lang/cargo.git"
MOTOR_CARGO_REV="5f94df4789f005f9a352888e8355ffc645b7ed0e"
RUST_BACKTRACE_REPOSITORY="https://github.com/rust-lang/backtrace-rs.git"
RUST_BOOK_REPOSITORY="https://github.com/rust-lang/book.git"
RUST_REFERENCE_REPOSITORY="https://github.com/rust-lang/reference.git"
RUSTC_PERF_REPOSITORY="https://github.com/rust-lang/rustc-perf.git"
MOTOR_RUST_ROOT_LOCK_SHA256="cfbe753cea718ff0ed64f2967e2c0abba23227814bd0d13b6014a7b9622acb64"
MOTOR_RUST_LIBRARY_LOCK_SHA256="c4701b265ea530775126b6c7c92a3895d0b2f07fbd16c1a2f475633dce635e34"
MOTOR_RUST_ANALYZER_LOCK_SHA256="be2b1876e92a88208cc6e1b59d6ee12e128c3ee4cab31b6323a32134348c4706"
UPSTREAM_CARGO_REV="5f94df4789f005f9a352888e8355ffc645b7ed0e"

MOTOR_MLIBC_REPOSITORY="https://github.com/moturus/mlibc.git"
MOTOR_MLIBC_REF="refs/heads/motor-os-rustc"
MOTOR_MLIBC_REV="9abf5139f8948020ffd8b96f0ad22c8247818b27"

MOTOR_LLVM_TARGETS="X86"

MOTOR_STANDALONE_LLVM_GENERATOR="Ninja"
MOTOR_STANDALONE_LLVM_BUILD_TYPE="Release"
MOTOR_STANDALONE_LLVM_ASSERTIONS="OFF"
MOTOR_STANDALONE_LLVM_PROJECTS="clang;lld"
MOTOR_STANDALONE_LLVM_INCLUDE_TESTS="OFF"
MOTOR_STANDALONE_LLVM_C_COMPILER="clang"
MOTOR_STANDALONE_LLVM_CXX_COMPILER="clang++"
MOTOR_RUST_BOOTSTRAP_LLVM_TOOLS=(
  llvm-cov llvm-nm llvm-objcopy llvm-objdump llvm-profdata llvm-readobj
  llvm-size llvm-strip llvm-ar llvm-as llvm-dis llvm-link llc opt
)
MOTOR_STANDALONE_LLVM_NINJA_TARGETS=(
  clang lld llvm-ranlib llvm-readelf llvm-config llvm-libraries
  "${MOTOR_RUST_BOOTSTRAP_LLVM_TOOLS[@]}"
)

# Keys name the C, C++, and Rust toolchain only: its external sources and its
# build configuration (toolchain_key in toolchain-lib.sh, toolchain_assembly_key
# in toolchain-assembly.sh). No file of this repository is hashed into a key,
# and userspace add-ons (Lua, ripgrep, Helix, sed) are declared in
# build-motor-os.sh.
