#!/usr/bin/env bash
# Resolve the Motor toolchain used by Lorry's Cargo oracles: the one the
# repository's rust-toolchain.toml names, and the native Rust sysroot in the
# assembly.

lorry_toolchain_fail() {
    echo "current-toolchain: $*" >&2
    return 1
}

lorry_load_current_toolchain() {
    local script_dir repository_root toolchain_file prefix cargo_verbose

    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || return
    repository_root="${LORRY_REPOSITORY_ROOT:-$(cd "$script_dir/../../../.." && pwd)}"

    toolchain_file="$repository_root/rust-toolchain.toml"
    [ -f "$toolchain_file" ] ||
        lorry_toolchain_fail "root selector is absent: $toolchain_file" || return
    LORRY_MOTOR_TOOLCHAIN="$(sed -n \
        's/^channel = "\([^"]*\)"$/\1/p' "$toolchain_file")"
    [ -n "$LORRY_MOTOR_TOOLCHAIN" ] ||
        lorry_toolchain_fail "root selector has no unique channel" || return

    LORRY_TEST_CARGO="$(rustup which cargo --toolchain "$LORRY_MOTOR_TOOLCHAIN")" || return
    LORRY_TEST_RUSTC="$(rustup which rustc --toolchain "$LORRY_MOTOR_TOOLCHAIN")" || return
    [ -x "$LORRY_TEST_CARGO" ] && [ -x "$LORRY_TEST_RUSTC" ] ||
        lorry_toolchain_fail "rustup resolved an incomplete Motor toolchain" || return
    prefix="$($LORRY_TEST_RUSTC --print sysroot)" || return
    cargo_verbose="$($LORRY_TEST_CARGO -Vv)" || return

    LORRY_MOTOR_LINKER="$prefix/lib/rustlib/x86_64-unknown-motor/sysroot/bin/motor-clang"
    LORRY_MOTOR_SYSROOT="$repository_root/build/assembly/images/rustc/devtools/rust"
    [ -x "$LORRY_MOTOR_LINKER" ] ||
        lorry_toolchain_fail "the toolchain's Motor linker is absent" || return
    [ -d "$LORRY_MOTOR_SYSROOT/lib/rustlib/x86_64-unknown-motor" ] ||
        lorry_toolchain_fail "the assembly has no Motor Rust sysroot; run src/build-motor-os.sh" ||
        return

    export LORRY_MOTOR_TOOLCHAIN LORRY_TEST_CARGO LORRY_TEST_RUSTC
    export LORRY_MOTOR_LINKER LORRY_MOTOR_SYSROOT
    printf '%s\n%s\n' '== Motor Cargo oracle ==' "$cargo_verbose" >&2
}
