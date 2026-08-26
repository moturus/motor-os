#!/usr/bin/env bash
# Shared, offline-safe helpers for the exact Motor toolchain tuple.

toolchain_die() {
  echo "toolchain: $*" >&2
  return 1
}

toolchain_require_hex() {
  local name="$1" value="$2" width="$3"
  [[ "$value" =~ ^[0-9a-f]{$width}$ ]] ||
    toolchain_die "$name must be $width lowercase hexadecimal characters"
}

toolchain_validate_versions() {
  local name
  for name in \
    MOTOR_GENERATED_MANIFEST_SCHEMA MOTOR_TOOLCHAIN_KEY_SCHEMA \
    MOTOR_ASSEMBLY_KEY_SCHEMA MOTOR_TOOLCHAIN_ID \
    MOTOR_RUSTUP_TOOLCHAIN_BASE MOTOR_TOOLCHAIN_MATURITY \
    UPSTREAM_RUST_VERSION UPSTREAM_RUST_REPOSITORY UPSTREAM_RUST_REF \
    UPSTREAM_RUST_REV UPSTREAM_STAGE0_REV RUST_LLVM_VERSION \
    RUST_LLVM_REPOSITORY RUST_LLVM_BASE_REV MOTOR_LLVM_REPOSITORY \
    MOTOR_LLVM_REF MOTOR_LLVM_REV MOTOR_RUST_REPOSITORY MOTOR_RUST_REF \
    MOTOR_RUST_REV MOTOR_RUST_CHANNEL MOTOR_CARGO_VERSION \
    MOTOR_CARGO_REPOSITORY MOTOR_CARGO_REV \
    MOTOR_RUST_ROOT_LOCK_SHA256 MOTOR_RUST_LIBRARY_LOCK_SHA256 \
    MOTOR_MLIBC_REPOSITORY MOTOR_MLIBC_REF MOTOR_MLIBC_REV \
    STDLIB_MOTO_RT_VERSION STDLIB_MOTO_RT_CHECKSUM LOCAL_MOTO_RT_VERSION; do
    [ -n "${!name:-}" ] || toolchain_die "missing declared field $name"
  done

  for name in UPSTREAM_RUST_REV UPSTREAM_STAGE0_REV RUST_LLVM_BASE_REV \
    MOTOR_LLVM_REV MOTOR_RUST_REV MOTOR_CARGO_REV MOTOR_MLIBC_REV; do
    toolchain_require_hex "$name" "${!name}" 40 || return
  done
  for name in MOTOR_RUST_ROOT_LOCK_SHA256 MOTOR_RUST_LIBRARY_LOCK_SHA256 \
    STDLIB_MOTO_RT_CHECKSUM; do
    toolchain_require_hex "$name" "${!name}" 64 || return
  done

  case "$MOTOR_TOOLCHAIN_MATURITY" in
    beta|stable) ;;
    *) toolchain_die "unsupported maturity $MOTOR_TOOLCHAIN_MATURITY" ;;
  esac
  [ "$STDLIB_MOTO_RT_VERSION" = "$LOCAL_MOTO_RT_VERSION" ] ||
    toolchain_die "local and std moto-rt versions differ"
}

toolchain_serialize_pairs() {
  [ $(( $# % 2 )) -eq 0 ] || toolchain_die "serializer requires name/value pairs"
  local LC_ALL=C name value
  while [ "$#" -gt 0 ]; do
    name="$1"
    value="$2"
    shift 2
    [ -n "$name" ] || toolchain_die "serializer field name is empty"
    printf '%s:%s%s:%s' "${#name}" "$name" "${#value}" "$value"
  done
}

toolchain_hash_pairs() {
  toolchain_serialize_pairs "$@" | sha256sum | awk '{print $1}'
}

toolchain_clean_key() {
  toolchain_hash_pairs \
    schema "$MOTOR_TOOLCHAIN_KEY_SCHEMA" \
    toolchain_id "$MOTOR_TOOLCHAIN_ID" \
    rustup_base "$MOTOR_RUSTUP_TOOLCHAIN_BASE" \
    source_mode managed \
    selected_description "$MOTOR_TOOLCHAIN_ID" \
    upstream_rust_version "$UPSTREAM_RUST_VERSION" \
    upstream_rust_rev "$UPSTREAM_RUST_REV" \
    stage0_rev "$UPSTREAM_STAGE0_REV" \
    rust_llvm_base_rev "$RUST_LLVM_BASE_REV" \
    cargo_version "$MOTOR_CARGO_VERSION" \
    cargo_rev "$MOTOR_CARGO_REV" \
    effective_rust_rev "$MOTOR_RUST_REV" \
    effective_llvm_rev "$MOTOR_LLVM_REV" \
    rust_tree_state clean llvm_tree_state clean authoring_source_digest none \
    rust_root_lock_sha256 "$MOTOR_RUST_ROOT_LOCK_SHA256" \
    rust_library_lock_sha256 "$MOTOR_RUST_LIBRARY_LOCK_SHA256" \
    rust_channel "$MOTOR_RUST_CHANNEL" build_host "$MOTOR_BUILD_HOST" \
    build_targets "$MOTOR_BUILD_TARGETS" build_tools "$MOTOR_BUILD_TOOLS" \
    build_extended "$MOTOR_BUILD_EXTENDED" build_docs "$MOTOR_BUILD_DOCS" \
    build_submodules "$MOTOR_BUILD_SUBMODULES" \
    build_locked_deps "$MOTOR_BUILD_LOCKED_DEPS" \
    optimized_compiler_builtins "$MOTOR_OPTIMIZED_COMPILER_BUILTINS" \
    download_ci_llvm "$MOTOR_DOWNLOAD_CI_LLVM" \
    llvm_targets "$MOTOR_LLVM_TARGETS" omit_git_hash "$MOTOR_OMIT_GIT_HASH" \
    declared_rust_rev "$MOTOR_RUST_REV" declared_llvm_rev "$MOTOR_LLVM_REV"
}

toolchain_clean_name() {
  printf '%s-%s\n' "$MOTOR_RUSTUP_TOOLCHAIN_BASE" "$(toolchain_clean_key)"
}

toolchain_can_publish_stable() {
  [ "$MOTOR_TOOLCHAIN_MATURITY" = stable ] &&
    [[ "$UPSTREAM_RUST_REF" == refs/tags/* ]] &&
    [[ "$MOTOR_TOOLCHAIN_ID" =~ ^[0-9]+\.[0-9]+\.[0-9]+-motor\.[0-9]+$ ]]
}
