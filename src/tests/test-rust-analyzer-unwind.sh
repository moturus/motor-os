#!/usr/bin/env bash
# Exercise the analyzer's private Rust library in the existing developer VM.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-versions.sh"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-rust-analyzer-unwind.sh"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
cargo="$(rustup which cargo)"
export RUSTC="$(rustup which rustc)"
source="$("$RUSTC" --print sysroot)/lib/rustlib/src/rust/library"
toolchain_prepare_rust_analyzer_library "$source" "$temporary/library"
if toolchain_prepare_rust_analyzer_library "$source" "$temporary/library" 2>/dev/null; then
	toolchain_die 'accepted an existing library destination'; exit 1
fi
assembly_images="$("$ROOT_DIR/src/select-toolchain-assembly.sh" --resolve)"
__CARGO_TESTS_ONLY_SRC_ROOT="$temporary/library" \
CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="${assembly_images%/images}/sysroot/bin/motor-clang" \
CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS="$(toolchain_rust_analyzer_unwind_flags)" \
	"$cargo" build --release --locked --offline --target x86_64-unknown-motor \
	--manifest-path "$ROOT_DIR/src/tests/rust-analyzer-unwind/Cargo.toml" \
	--target-dir "$temporary/target" -Z build-std=std,panic_unwind
cmp "$source/Cargo.lock" "$temporary/library/Cargo.lock"
binary="$temporary/target/x86_64-unknown-motor/release/rust-analyzer-unwind-test"
runner="$ROOT_DIR/src/tests/test-rust-analyzer-crates.sh"
"$runner" --run-motor "$binary"
echo 'test-rust-analyzer-unwind PASS'
