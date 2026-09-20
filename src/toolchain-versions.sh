#!/usr/bin/env bash
# Exact source tuple for the in-progress Rust 1.99 Motor toolchain.
#
# This file is data only. Derived keys, checkout observations, and Motor OS
# worktree state belong in generated manifests.

MOTOR_GENERATED_MANIFEST_SCHEMA="motor-toolchain-manifest-v1"
MOTOR_TOOLCHAIN_KEY_SCHEMA="motor-toolchain-key-v4"
MOTOR_ASSEMBLY_KEY_SCHEMA="motor-assembly-key-v6"

MOTOR_TOOLCHAIN_ID="1.99.0-beta-f47d5bb-motor.dev.2"
MOTOR_RUSTUP_TOOLCHAIN_BASE="motor-1.99.0-beta-f47d5bb-dev.2"
MOTOR_TOOLCHAIN_MATURITY="beta"

UPSTREAM_RUST_VERSION="1.99.0"
UPSTREAM_RUST_REPOSITORY="https://github.com/rust-lang/rust.git"
UPSTREAM_RUST_REF="refs/heads/beta"
UPSTREAM_RUST_REV="f47d5bb13648d5c859f5b438eb7dc834b9729961"
UPSTREAM_STAGE0_REV="08d5b675a9b2abdca5e2fe4eabe0e07bbda15d49"

RUST_LLVM_VERSION="23.1.0-rc1"
RUST_LLVM_REPOSITORY="https://github.com/rust-lang/llvm-project.git"
RUST_LLVM_BASE_REV="21cf28432798952d942bacc6bcee3a328faa3638"

MOTOR_LLVM_REPOSITORY="https://github.com/moturus/llvm-project.git"
MOTOR_LLVM_REF="refs/heads/motor-os-1.99.0-beta-f47d5bb"
MOTOR_LLVM_REV="7c2a7b21e3dc7be1f0c41d443bc420bcc774b1d4"

MOTOR_RUST_REPOSITORY="https://github.com/moturus/rust.git"
MOTOR_RUST_REF="refs/heads/motor-os-1.99.0-beta-f47d5bb"
MOTOR_RUST_REV="b4eb29b6f00ae2190f565f56595d51403c8baf13"
MOTOR_RUST_CHANNEL="dev"
MOTOR_CARGO_VERSION="1.99.0-dev"
MOTOR_CARGO_REPOSITORY="https://github.com/rust-lang/cargo.git"
MOTOR_CARGO_REV="eb98b54bc9f3c74519f43d066cb3fd02ebc88df0"
RUST_BACKTRACE_REPOSITORY="https://github.com/rust-lang/backtrace-rs.git"
RUST_BOOK_REPOSITORY="https://github.com/rust-lang/book.git"
RUST_REFERENCE_REPOSITORY="https://github.com/rust-lang/reference.git"
RUSTC_PERF_REPOSITORY="https://github.com/rust-lang/rustc-perf.git"
MOTOR_RUST_ROOT_LOCK_SHA256="b38dc5b991122b4f630a818cae6669a7d2065597632a1b3055a683fe35951939"
MOTOR_RUST_LIBRARY_LOCK_SHA256="a975b500e40752e08f2f664666ed078325f7eb37d27d5fca7eeb73199dcf7665"
MOTOR_RUST_ANALYZER_LOCK_SHA256="be2b1876e92a88208cc6e1b59d6ee12e128c3ee4cab31b6323a32134348c4706"
UPSTREAM_CARGO_REV="eb98b54bc9f3c74519f43d066cb3fd02ebc88df0"

MOTOR_MLIBC_REPOSITORY="https://github.com/moturus/mlibc.git"
MOTOR_MLIBC_REF="refs/heads/motor-os-rustc"
MOTOR_MLIBC_REV="0cece7e5cfbd7f43ffb5968ced80056a655cb70f"

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
# and userspace add-ons (Lua, ripgrep, Helix) are declared in build-motor-os.sh.
