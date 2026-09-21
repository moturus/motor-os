#!/usr/bin/env bash
# Shared, offline-safe helpers for the exact Motor toolchain tuple.

. "$(dirname "${BASH_SOURCE[0]}")/toolchain-rust-analyzer-identity.sh"

toolchain_die() {
  echo "toolchain: $*" >&2
  return 1
}

# A producer lock is a `.building` directory beside a keyed output; it records
# the producer's pid. A lock whose producer is gone marks an interrupted build:
# its incomplete output is discarded, so a re-run builds it again. A rejected
# output is kept for diagnosis.
toolchain_recover_lock() {
  local what="$1" output="$2" rejected="${3:-}" lock="${2}.building" pid
  [ -e "$lock" ] || return 0
  case "$output" in
    /?*) ;;
    *) toolchain_die "$what path is not absolute: $output"; return 1 ;;
  esac
  pid="$(cat "$lock/pid" 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && [ -e "/proc/$pid" ]; then
    toolchain_die "$what is being built by process $pid; wait for it to finish." \
      "If process $pid is not a Motor OS build, remove $lock and re-run"
    return 1
  fi
  if [ -n "$rejected" ] && [ -e "$output/$rejected" ]; then
    toolchain_die "$what was rejected: $(head -1 "$output/$rejected");" \
      "fix the cause, remove $output and $lock, and re-run"
    return 1
  fi
  echo "toolchain: discarding the interrupted build of $what: $output" >&2
  rm -rf -- "$output" "$lock"
}

toolchain_take_lock() {
  mkdir "$1" 2>/dev/null && printf '%s\n' "$$" > "$1/pid"
}

toolchain_release_lock() {
  rm -f "$1/pid"
  rmdir "$1"
}

toolchain_manifest_package_version() {
  local manifest="$1"
  awk '
    $0 == "[package]" { package = 1; next }
    /^\[/ { package = 0 }
    package && /^[[:space:]]*version[[:space:]]*=/ {
      line = $0
      sub(/^[^=]*=[[:space:]]*"/, "", line)
      sub(/"[[:space:]]*$/, "", line)
      print line
      n++
    }
    END { if (n != 1) exit 1 }
  ' "$manifest"
}

# The part of a version that Cargo treats as incompatible when it changes:
# "0.17" for 0.17.6, "2" for 2.3.1.
toolchain_compat_version() {
  local version="$1"
  [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.[0-9]+ ]] ||
    toolchain_die "not a semantic version: $version" || return
  if [ "${BASH_REMATCH[1]}" = 0 ]; then
    printf '0.%s\n' "${BASH_REMATCH[2]}"
  else
    printf '%s\n' "${BASH_REMATCH[1]}"
  fi
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
    MOTOR_CARGO_REPOSITORY MOTOR_CARGO_REV RUST_BACKTRACE_REPOSITORY \
    RUST_BOOK_REPOSITORY RUST_REFERENCE_REPOSITORY RUSTC_PERF_REPOSITORY \
    UPSTREAM_CARGO_REV \
    MOTOR_RUST_ROOT_LOCK_SHA256 MOTOR_RUST_LIBRARY_LOCK_SHA256 MOTOR_RUST_ANALYZER_LOCK_SHA256 \
    MOTOR_MLIBC_REPOSITORY MOTOR_MLIBC_REF MOTOR_MLIBC_REV \
    MOTOR_STANDALONE_LLVM_GENERATOR MOTOR_STANDALONE_LLVM_BUILD_TYPE \
    MOTOR_STANDALONE_LLVM_ASSERTIONS MOTOR_STANDALONE_LLVM_PROJECTS \
    MOTOR_STANDALONE_LLVM_INCLUDE_TESTS MOTOR_STANDALONE_LLVM_C_COMPILER \
    MOTOR_STANDALONE_LLVM_CXX_COMPILER; do
    [ -n "${!name:-}" ] || toolchain_die "missing declared field $name"
  done

  for name in UPSTREAM_RUST_REV UPSTREAM_STAGE0_REV RUST_LLVM_BASE_REV \
    MOTOR_LLVM_REV MOTOR_RUST_REV MOTOR_CARGO_REV UPSTREAM_CARGO_REV \
    MOTOR_MLIBC_REV; do
    toolchain_require_hex "$name" "${!name}" 40 || return
  done
  for name in MOTOR_RUST_ROOT_LOCK_SHA256 MOTOR_RUST_LIBRARY_LOCK_SHA256 \
    MOTOR_RUST_ANALYZER_LOCK_SHA256; do
    toolchain_require_hex "$name" "${!name}" 64 || return
  done

  case "$MOTOR_TOOLCHAIN_MATURITY" in
    beta|stable) ;;
    *) toolchain_die "unsupported maturity $MOTOR_TOOLCHAIN_MATURITY" ;;
  esac
  [ "${#MOTOR_RUST_BOOTSTRAP_LLVM_TOOLS[@]}" -gt 0 ] ||
    toolchain_die "Rust bootstrap LLVM tool list is empty"
  [ "${#MOTOR_STANDALONE_LLVM_NINJA_TARGETS[@]}" -gt 0 ] ||
    toolchain_die "standalone LLVM ninja target list is empty"
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

toolchain_standalone_llvm_config_digest() {
  local IFS=,
  toolchain_hash_pairs schema motor-standalone-llvm-config-v2 \
    generator "$MOTOR_STANDALONE_LLVM_GENERATOR" \
    build_type "$MOTOR_STANDALONE_LLVM_BUILD_TYPE" \
    assertions "$MOTOR_STANDALONE_LLVM_ASSERTIONS" \
    projects "$MOTOR_STANDALONE_LLVM_PROJECTS" targets "$MOTOR_LLVM_TARGETS" \
    tests "$MOTOR_STANDALONE_LLVM_INCLUDE_TESTS" \
    c_compiler "$MOTOR_STANDALONE_LLVM_C_COMPILER" \
    cxx_compiler "$MOTOR_STANDALONE_LLVM_CXX_COMPILER" \
    ninja_targets "${MOTOR_STANDALONE_LLVM_NINJA_TARGETS[*]}"
}

# The key names what is compiled, how, and where it installs. Everything else
# about a toolchain follows from these inputs: the Rust commit fixes its
# upstream base, Stage 0, Cargo, and lockfiles, and the bootstrap configuration
# carries the compiler description and every bootstrap option. The rustup base
# stays because the prefix path is named after it.
toolchain_key() {
  local name
  for name in SELECTED_RUSTUP_TOOLCHAIN_BASE \
    EFFECTIVE_MOTOR_RUST_REV EFFECTIVE_MOTOR_LLVM_REV \
    MOTOR_RUST_TREE_STATE MOTOR_LLVM_TREE_STATE AUTHORING_SOURCE_DIGEST \
    RUST_ANALYZER_INPUTS_DIGEST BOOTSTRAP_CONFIG_DIGEST \
    STANDALONE_LLVM_CONFIG_DIGEST; do
    [ -n "${!name:-}" ] || toolchain_die "missing toolchain-key input $name" || return
  done
  toolchain_hash_pairs \
    schema "$MOTOR_TOOLCHAIN_KEY_SCHEMA" \
    rustup_base "$SELECTED_RUSTUP_TOOLCHAIN_BASE" \
    effective_rust_rev "$EFFECTIVE_MOTOR_RUST_REV" \
    effective_llvm_rev "$EFFECTIVE_MOTOR_LLVM_REV" \
    rust_tree_state "$MOTOR_RUST_TREE_STATE" \
    llvm_tree_state "$MOTOR_LLVM_TREE_STATE" \
    authoring_source_digest "$AUTHORING_SOURCE_DIGEST" \
    rust_analyzer_inputs_digest "$RUST_ANALYZER_INPUTS_DIGEST" \
    bootstrap_config_digest "$BOOTSTRAP_CONFIG_DIGEST" \
    standalone_llvm_config_digest "$STANDALONE_LLVM_CONFIG_DIGEST"
}

toolchain_clean_key() {
  local SELECTED_RUSTUP_TOOLCHAIN_BASE="$MOTOR_RUSTUP_TOOLCHAIN_BASE"
  local EFFECTIVE_MOTOR_RUST_REV="$MOTOR_RUST_REV"
  local EFFECTIVE_MOTOR_LLVM_REV="$MOTOR_LLVM_REV"
  local MOTOR_RUST_TREE_STATE=clean MOTOR_LLVM_TREE_STATE=clean
  local AUTHORING_SOURCE_DIGEST=none
  local RUST_ANALYZER_INPUTS_DIGEST
  RUST_ANALYZER_INPUTS_DIGEST="$(toolchain_rust_analyzer_inputs_digest)" || return
  local BOOTSTRAP_CONFIG_DIGEST STANDALONE_LLVM_CONFIG_DIGEST
  BOOTSTRAP_CONFIG_DIGEST="$(
    toolchain_bootstrap_identity_digest "$MOTOR_TOOLCHAIN_ID"
  )" || return
  STANDALONE_LLVM_CONFIG_DIGEST="$(
    toolchain_standalone_llvm_config_digest
  )" || return
  toolchain_key
}

toolchain_clean_name() {
  printf '%s-%s\n' "$MOTOR_RUSTUP_TOOLCHAIN_BASE" "$(toolchain_clean_key)"
}

toolchain_can_publish_stable() {
  [ "$MOTOR_TOOLCHAIN_MATURITY" = stable ] &&
    [[ "$UPSTREAM_RUST_REF" == refs/tags/* ]] &&
    [[ "$MOTOR_TOOLCHAIN_ID" =~ ^[0-9]+\.[0-9]+\.[0-9]+-motor\.[0-9]+$ ]]
}
