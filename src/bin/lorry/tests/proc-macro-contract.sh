#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: proc-macro-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
MOTOR_TARGET="x86_64-unknown-motor"
MOTOR_TOOLCHAIN="${LORRY_MOTOR_TOOLCHAIN:-dev-x86_64-unknown-motor}"
MOTOR_LINKER="${LORRY_MOTOR_LINKER:-/home/posk/motor-dev/motor-sysroot/bin/motor-clang}"
MOTOR_SYSROOT="${LORRY_MOTOR_SYSROOT:-$ROOT_DIR/img_files/generated/rustc/devtools/rust}"
TOOLCHAIN="nightly-2026-06-19"
NATIVE_RUSTC="$(rustup which rustc --toolchain "$TOOLCHAIN")"
WORK="$(mktemp -d /tmp/lorry-proc-macro-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME:?}/.rustup}"
export HOME="$WORK/home"
mkdir -p "$HOME/.config/lorry" "$WORK/project/src" \
    "$WORK/project/derive-answer/src" "$WORK/project/macro-helper/src" \
    "$WORK/project/.cargo"
printf 'config-version = 1\n[cache]\ndirectory = "%s"\n[policy.rules.local-proc-macro]\naction = "allow"\nname = "derive-answer"\nsource = "path"\nallow-proc-macro = true\n' "$WORK/cache" \
    >"$HOME/.config/lorry/lorry.toml"
printf '[target.%s]\nlinker = "%s"\nrustflags = ["--sysroot=%s"]\n' \
    "$MOTOR_TARGET" "$MOTOR_LINKER" "$MOTOR_SYSROOT" \
    >"$WORK/project/.cargo/config.toml"

printf '%s\n' \
    '[package]' \
    'name = "proc-macro-app"' \
    'version = "0.1.0"' \
    'edition = "2024"' \
    '' \
    '[dependencies]' \
    'derive-answer = { path = "derive-answer" }' \
    'macro-helper = { path = "macro-helper", features = ["target-context"] }' \
    >"$WORK/project/Cargo.toml"
printf '%s\n' \
    'use derive_answer::{Answer, add_one, answer_value};' \
    '#[derive(Answer)]' \
    'struct Value;' \
    '#[answer_value]' \
    'struct Attributed;' \
    'fn main() {' \
    '    println!("{}", Value::answer() + add_one!(0) + Attributed::answer() + macro_helper::target_value());' \
    '}' \
    >"$WORK/project/src/main.rs"
printf '%s\n' \
    '[package]' \
    'name = "derive-answer"' \
    'version = "0.1.0"' \
    'edition = "2024"' \
    '' \
    '[lib]' \
    'proc-macro = true' \
    '' \
    '[dependencies]' \
    'macro-helper = { path = "../macro-helper", features = ["macro-context"] }' \
    >"$WORK/project/derive-answer/Cargo.toml"
printf '%s\n' \
    'extern crate proc_macro;' \
    'use proc_macro::TokenStream;' \
    '#[proc_macro_derive(Answer)]' \
    'pub fn derive_answer(_: TokenStream) -> TokenStream {' \
    '    macro_helper::implementation().parse().unwrap()' \
    '}' \
    '#[proc_macro]' \
    'pub fn add_one(input: TokenStream) -> TokenStream {' \
    '    println!("proc-macro stdout is preserved");' \
    '    format!("({input} + 1)").parse().unwrap()' \
    '}' \
    '#[proc_macro_attribute]' \
    'pub fn answer_value(_: TokenStream, item: TokenStream) -> TokenStream {' \
    '    format!("{item} impl Attributed {{ fn answer() -> u32 {{ 41 }} }}").parse().unwrap()' \
    '}' >"$WORK/project/derive-answer/src/lib.rs"
printf '%s\n' \
    '[package]' \
    'name = "macro-helper"' \
    'version = "0.1.0"' \
    'edition = "2024"' \
    '' \
    '[features]' \
    'macro-context = []' \
    'target-context = []' >"$WORK/project/macro-helper/Cargo.toml"
printf '%s\n' \
    '#[cfg(feature = "macro-context")]' \
    'pub fn implementation() -> &'"'"'static str {' \
    '    "impl Value { fn answer() -> u32 { 42 } }"' \
    '}' \
    '#[cfg(feature = "target-context")]' \
    'pub fn target_value() -> u32 { 0 }' >"$WORK/project/macro-helper/src/lib.rs"
printf '%s\n' \
    'version = 4' \
    '[[package]]' \
    'name = "proc-macro-app"' \
    'version = "0.1.0"' \
    'dependencies = ["derive-answer", "macro-helper"]' \
    '[[package]]' \
    'name = "derive-answer"' \
    'version = "0.1.0"' \
    'dependencies = ["macro-helper"]' \
    '[[package]]' \
    'name = "macro-helper"' \
    'version = "0.1.0"' >"$WORK/project/Cargo.lock"

(
    cd "$WORK/project"
    "$LORRY" vendor --accept-all >/dev/null
    RUSTC="$NATIVE_RUSTC" "$LORRY" build >"$WORK/proc-macro.stdout" 2>&1
    grep -F "proc-macro stdout is preserved" "$WORK/proc-macro.stdout" >/dev/null
    [ "$(RUSTC="$NATIVE_RUSTC" "$LORRY" run)" = 84 ]
    "$LORRY" clean
    RUSTC="$NATIVE_RUSTC" "$LORRY" build
    [ "$(RUSTC="$NATIVE_RUSTC" "$LORRY" run)" = 84 ]
    "$LORRY" +"$MOTOR_TOOLCHAIN" build --target "$MOTOR_TARGET"
)
find "$WORK/project/target/lorry/debug/deps" -maxdepth 1 -type f \
    -name 'libderive_answer-*.so' | grep -q .
[ "$(find "$WORK/project/target/lorry/debug/deps" -maxdepth 1 -type f \
    -name 'libmacro_helper-*.rlib' | wc -l)" -eq 2 ]
if find "$WORK/project/target/lorry/$MOTOR_TARGET/debug/deps" \
    -maxdepth 1 -type f -name 'libderive_answer-*.so' | grep -q .; then
    echo "proc macro was incorrectly compiled as a Motor target artifact" >&2
    exit 1
fi

echo "PASS: derive, function-like, and attribute macros execute as compiler-host units"
