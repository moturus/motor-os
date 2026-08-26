#!/usr/bin/env bash
# Exact source tuple for the in-progress Rust 1.99 Motor toolchain.
#
# This file is data only. Derived keys, checkout observations, and Motor OS
# worktree state belong in generated manifests.

MOTOR_GENERATED_MANIFEST_SCHEMA="motor-toolchain-manifest-v1"
MOTOR_TOOLCHAIN_KEY_SCHEMA="motor-toolchain-key-v1"
MOTOR_ASSEMBLY_KEY_SCHEMA="motor-assembly-key-v2"

MOTOR_TOOLCHAIN_ID="1.99.0-beta-f47d5bb-motor.dev.1"
MOTOR_RUSTUP_TOOLCHAIN_BASE="motor-1.99.0-beta-f47d5bb-dev.1"
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
MOTOR_LLVM_REV="95478fe45b1a9c826e577546b4d7744d90b9de2c"

MOTOR_RUST_REPOSITORY="https://github.com/moturus/rust.git"
MOTOR_RUST_REF="refs/heads/motor-os-1.99.0-beta-f47d5bb"
MOTOR_RUST_REV="b4f2a3146a4d87d85036cc4646aa2dadfe64bf51"
MOTOR_RUST_CHANNEL="dev"
MOTOR_CARGO_VERSION="1.99.0-dev"
MOTOR_CARGO_REPOSITORY="https://github.com/rust-lang/cargo.git"
MOTOR_CARGO_REV="eb98b54bc9f3c74519f43d066cb3fd02ebc88df0"
MOTOR_RUST_ROOT_LOCK_SHA256="6edfd4b9bf0bd44ef122e3041b272e7d8d24e3ddd952d3c0444cb8f2cdd66176"
MOTOR_RUST_LIBRARY_LOCK_SHA256="73b0c194b27ba6dd6fd208bcdbd2df2f62caeaa85b485facaa44933ad3c442f3"
UPSTREAM_CARGO_REV="eb98b54bc9f3c74519f43d066cb3fd02ebc88df0"

MOTOR_MLIBC_REPOSITORY="https://github.com/moturus/mlibc.git"
MOTOR_MLIBC_REF="refs/heads/motor-os-rustc"
MOTOR_MLIBC_REV="62f9495700537ded14a2a6fae9373227fe5ec5ca"

STDLIB_MOTO_RT_VERSION="0.17.5"
STDLIB_MOTO_RT_CHECKSUM="0d957efc93bb603844e45d66f45c9b999168ff8f7630da91f3a7308c498a7ccc"
LOCAL_MOTO_RT_VERSION="0.17.5"
MOTOR_LUA_VERSION="5.4.8"

MOTOR_BUILD_HOST="x86_64-unknown-linux-gnu"
MOTOR_BUILD_TARGETS="x86_64-unknown-linux-gnu,x86_64-unknown-motor"
MOTOR_BUILD_TOOLS="cargo,clippy,rustdoc,rustfmt,src"
MOTOR_LLVM_TARGETS="X86"
MOTOR_BUILD_EXTENDED="true"
MOTOR_BUILD_DOCS="false"
MOTOR_BUILD_SUBMODULES="false"
MOTOR_BUILD_LOCKED_DEPS="false"
MOTOR_OPTIMIZED_COMPILER_BUILTINS="false"
MOTOR_DOWNLOAD_CI_LLVM="false"
MOTOR_OMIT_GIT_HASH="false"

# Reviewed inputs to the local runtime/sysroot content digest. Directories are
# traversed canonically by the assembly implementation.
MOTOR_OS_RUNTIME_INPUTS=(
  "src/sys/Cargo.toml"
  "src/sys/lib/moto-rt"
  "src/sys/lib/moto-sys"
  "src/sys/lib/moto-rt-cabi"
  "src/build-motor-os.sh"
)

MOTOR_TOOLCHAIN_KEY_FIELDS=(
  toolchain_id rustup_base source_mode selected_rustup_base selected_description
  upstream_rust_version upstream_rust_rev stage0_rev rust_llvm_base_rev
  upstream_cargo_rev cargo_version cargo_rev effective_rust_rev effective_llvm_rev
  rust_tree_state llvm_tree_state authoring_source_digest
  rust_root_lock_sha256 rust_library_lock_sha256 bootstrap_config_digest
  rust_channel build_host
  build_targets build_tools build_extended build_docs build_submodules
  build_locked_deps optimized_compiler_builtins download_ci_llvm llvm_targets
  omit_git_hash declared_rust_rev declared_llvm_rev
)

MOTOR_ASSEMBLY_KEY_FIELDS=(
  toolchain_key mlibc_rev mlibc_tree_state motor_os_runtime_tree
  local_moto_rt_version native_configuration_digest
)
