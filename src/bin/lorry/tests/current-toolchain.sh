#!/usr/bin/env bash
# Resolve the exact managed Motor toolchain used by Lorry's Cargo oracles.

lorry_toolchain_fail() {
    echo "current-toolchain: $*" >&2
    return 1
}

lorry_manifest_value() {
    local manifest="$1" key="$2"
    awk -F= -v key="$key" '
        $1 == key { value = substr($0, length(key) + 2); count++ }
        END { if (count != 1 || value == "") exit 1; print value }
    ' "$manifest"
}

lorry_load_current_toolchain() {
    local script_dir repository_root toolchain_file toolchain_key
    local prefix prefix_manifest cargo_verbose rustc_verbose
    local assembly_manifest assembly_root assembly_key candidate
    local -a candidates=()

    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || return
    repository_root="${LORRY_REPOSITORY_ROOT:-$(cd "$script_dir/../../../.." && pwd)}"
    . "$repository_root/src/toolchain-versions.sh"

    toolchain_file="$repository_root/rust-toolchain.toml"
    [ -f "$toolchain_file" ] ||
        lorry_toolchain_fail "exact root selector is absent: $toolchain_file" || return
    LORRY_MOTOR_TOOLCHAIN="$(sed -n \
        's/^channel = "\([^"]*\)"$/\1/p' "$toolchain_file")"
    [ -n "$LORRY_MOTOR_TOOLCHAIN" ] ||
        lorry_toolchain_fail "root selector has no unique channel" || return
    case "$LORRY_MOTOR_TOOLCHAIN" in
        "$MOTOR_RUSTUP_TOOLCHAIN_BASE-"*)
            toolchain_key="${LORRY_MOTOR_TOOLCHAIN#"$MOTOR_RUSTUP_TOOLCHAIN_BASE-"}"
            ;;
        *) lorry_toolchain_fail "root selector is not the declared exact Motor toolchain" || return ;;
    esac
    [ "${#toolchain_key}" -eq 64 ] ||
        lorry_toolchain_fail "root selector has a non-canonical toolchain key" || return
    case "$toolchain_key" in *[!0-9a-f]*)
        lorry_toolchain_fail "root selector has a non-canonical toolchain key" || return ;;
    esac

    LORRY_TEST_CARGO="$(rustup which cargo --toolchain "$LORRY_MOTOR_TOOLCHAIN")" || return
    LORRY_TEST_RUSTC="$(rustup which rustc --toolchain "$LORRY_MOTOR_TOOLCHAIN")" || return
    [ -x "$LORRY_TEST_CARGO" ] && [ -x "$LORRY_TEST_RUSTC" ] ||
        lorry_toolchain_fail "rustup resolved an incomplete Motor toolchain" || return
    prefix="$($LORRY_TEST_RUSTC --print sysroot)" || return
    prefix_manifest="$prefix/MOTOR-TOOLCHAIN-MANIFEST"
    [ -f "$prefix_manifest" ] ||
        lorry_toolchain_fail "installed prefix manifest is absent: $prefix_manifest" || return
    [ "$(lorry_manifest_value "$prefix_manifest" schema)" = \
        "$MOTOR_GENERATED_MANIFEST_SCHEMA" ] ||
        lorry_toolchain_fail "installed prefix manifest has the wrong schema" || return
    [ "$(lorry_manifest_value "$prefix_manifest" toolchain_key)" = "$toolchain_key" ] ||
        lorry_toolchain_fail "installed prefix manifest has the wrong toolchain key" || return
    [ "$(lorry_manifest_value "$prefix_manifest" rustup_toolchain)" = \
        "$LORRY_MOTOR_TOOLCHAIN" ] ||
        lorry_toolchain_fail "installed prefix manifest has the wrong rustup name" || return
    [ "$(lorry_manifest_value "$prefix_manifest" cargo_rev)" = "$MOTOR_CARGO_REV" ] ||
        lorry_toolchain_fail "installed prefix manifest has the wrong Cargo revision" || return
    [ "$(lorry_manifest_value "$prefix_manifest" effective_rust_rev)" = \
        "$MOTOR_RUST_REV" ] ||
        lorry_toolchain_fail "installed prefix manifest has the wrong Rust revision" || return
    [ "$(lorry_manifest_value "$prefix_manifest" effective_llvm_rev)" = \
        "$MOTOR_LLVM_REV" ] ||
        lorry_toolchain_fail "installed prefix manifest has the wrong LLVM revision" || return
    [ "$(cat "$prefix/lib/rustlib/MOTOR-TOOLCHAIN-KEY")" = "$toolchain_key" ] ||
        lorry_toolchain_fail "installed prefix key stamp does not match" || return

    cargo_verbose="$($LORRY_TEST_CARGO -Vv)" || return
    grep -Fqx "release: $MOTOR_CARGO_VERSION" <<< "$cargo_verbose" ||
        lorry_toolchain_fail "Cargo does not report $MOTOR_CARGO_VERSION" || return
    grep -Fqx "commit-hash: $MOTOR_CARGO_REV" <<< "$cargo_verbose" ||
        lorry_toolchain_fail "Cargo does not report $MOTOR_CARGO_REV" || return
    rustc_verbose="$($LORRY_TEST_RUSTC -vV)" || return
    grep -Fqx "commit-hash: $MOTOR_RUST_REV" <<< "$rustc_verbose" ||
        lorry_toolchain_fail "rustc does not report $MOTOR_RUST_REV" || return

    if [ -n "${LORRY_ASSEMBLY_MANIFEST:-}" ]; then
        candidates+=("$LORRY_ASSEMBLY_MANIFEST")
    elif [ -d "$repository_root/../assemblies" ]; then
        while IFS= read -r candidate; do
            [ "$(lorry_manifest_value "$candidate" toolchain_key 2>/dev/null || true)" = \
                "$toolchain_key" ] && candidates+=("$candidate")
        done < <(find "$repository_root/../assemblies" -mindepth 2 -maxdepth 2 \
            -type f -name MOTOR-ASSEMBLY-MANIFEST -print | LC_ALL=C sort)
    fi
    [ "${#candidates[@]}" -eq 1 ] ||
        lorry_toolchain_fail "expected one assembly manifest for $toolchain_key; set LORRY_ASSEMBLY_MANIFEST explicitly" || return
    assembly_manifest="$(realpath "${candidates[0]}")" || return
    assembly_root="$(dirname "$assembly_manifest")"
    assembly_key="$(lorry_manifest_value "$assembly_manifest" assembly_key)" || return
    [ "$(basename "$assembly_root")" = "$assembly_key" ] ||
        lorry_toolchain_fail "assembly manifest is outside its keyed directory" || return
    [ "$(lorry_manifest_value "$assembly_manifest" schema)" = \
        "$MOTOR_GENERATED_MANIFEST_SCHEMA" ] ||
        lorry_toolchain_fail "assembly manifest has the wrong schema" || return
    [ "$(lorry_manifest_value "$assembly_manifest" toolchain_key)" = "$toolchain_key" ] ||
        lorry_toolchain_fail "assembly manifest has the wrong toolchain key" || return
    [ "$(lorry_manifest_value "$assembly_manifest" rustup_toolchain)" = \
        "$LORRY_MOTOR_TOOLCHAIN" ] ||
        lorry_toolchain_fail "assembly manifest has the wrong rustup name" || return
    [ "$(lorry_manifest_value "$assembly_manifest" effective_rust_rev)" = \
        "$MOTOR_RUST_REV" ] ||
        lorry_toolchain_fail "assembly manifest has the wrong Rust revision" || return
    [ "$(lorry_manifest_value "$assembly_manifest" effective_llvm_rev)" = \
        "$MOTOR_LLVM_REV" ] ||
        lorry_toolchain_fail "assembly manifest has the wrong LLVM revision" || return

    LORRY_MOTOR_LINKER="$assembly_root/sysroot/bin/motor-clang"
    LORRY_MOTOR_SYSROOT="$assembly_root/images/rustc/devtools/rust"
    [ -x "$LORRY_MOTOR_LINKER" ] ||
        lorry_toolchain_fail "manifest-selected Motor linker is absent" || return
    [ -d "$LORRY_MOTOR_SYSROOT/lib/rustlib/x86_64-unknown-motor" ] ||
        lorry_toolchain_fail "manifest-selected Motor Rust sysroot is incomplete" || return

    LORRY_ASSEMBLY_MANIFEST="$assembly_manifest"
    export LORRY_MOTOR_TOOLCHAIN LORRY_TEST_CARGO LORRY_TEST_RUSTC
    export LORRY_MOTOR_LINKER LORRY_MOTOR_SYSROOT LORRY_ASSEMBLY_MANIFEST
    printf '%s\n%s\n' '== Exact Motor Cargo oracle ==' "$cargo_verbose" >&2
}
