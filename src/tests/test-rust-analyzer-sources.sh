#!/usr/bin/env bash
# Test the external implementation consumed by the selected host toolchain.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
for helper in versions lib sources bootstrap state runtime assembly patched-crates rust-analyzer; do
	. "$ROOT_DIR/src/toolchain-$helper.sh"
done
. "$ROOT_DIR/src/patches/crates.sh"
profile=debug
profile_args=()
if [ "${1:-}" = --release ] && [ "$#" = 1 ]; then
	profile=release; profile_args=(--release)
elif [ "$#" != 0 ]; then
	echo "usage: $0 [--release]" >&2; exit 2
fi
MOTORH="$(realpath "${MOTORH:-$ROOT_DIR/..}")"
rust="$(realpath "${MOTOR_RUST_SOURCE:-$MOTORH/toolchain-src/rust}")"
toolchain_bootstrap_absolute_path rust "$rust"
cargo="$(rustup which cargo)"
export RUSTC="$(rustup which rustc)"
revision="$("$RUSTC" -vV | sed -n 's/^commit-hash: //p')"
[ "$(git -C "$rust" rev-parse HEAD)" = "$revision" ] || {
	toolchain_die 'analyzer test sources differ from the selected compiler'; exit 1;
}
toolchain_capture_starting_locks "$rust"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
toolchain_prepare_rust_analyzer "$ROOT_DIR" "$rust" "$MOTORH" \
	"${CARGO_HOME:-$HOME/.cargo}" "$temporary" false
# Validate the standalone patched-crate locks before exercising the analyzer
# workspace, which otherwise does not resolve their development dependencies.
for manifest in "$RUST_ANALYZER_URL_SOURCE/Cargo.toml" \
	"$RUST_ANALYZER_INVENTORY_SOURCE/Cargo.toml"; do
	"$cargo" metadata --manifest-path "$manifest" --locked --offline \
		--no-deps --format-version 1 >/dev/null
done
sysroot="$("$RUSTC" --print sysroot)"
key="$(cat "$sysroot/lib/rustlib/MOTOR-TOOLCHAIN-KEY")"
toolchain_require_hex toolchain_key "$key" 64
graph="$("$cargo" tree --manifest-path "$rust/src/tools/rust-analyzer/Cargo.toml" \
	--locked --offline -p rust-analyzer --target x86_64-unknown-motor \
	--edges normal,build --prefix none --format '{p}' \
	--config "$RUST_ANALYZER_CARGO_CONFIG")"
if grep -Eq '^(dirs-sys|tikv-jemallocator|tikv-jemalloc-sys|mimalloc|libmimalloc-sys) ' <<< "$graph"; then
	toolchain_die 'native analyzer graph contains a disabled platform/allocator dependency'; exit 1
fi
"$cargo" test --manifest-path "$rust/src/tools/rust-analyzer/Cargo.toml" \
	--locked --offline "${profile_args[@]}" -p stdx --lib \
	--config "$RUST_ANALYZER_CARGO_CONFIG" \
	--target-dir "$ROOT_DIR/build/obj/$key/$profile/rust-analyzer-stdx"

# The hook has no bootstrap dependencies, so its actual source can be tested
# with std alone instead of rebuilding the entire bootstrap test harness.
printf '#[path = "%s"] mod hook;\n' \
	"$rust/src/bootstrap/src/core/build_steps/tool/motor_rust_analyzer.rs" |
	"$RUSTC" --edition 2024 --test -o "$temporary/bootstrap-hook-tests" -
"$temporary/bootstrap-hook-tests"
toolchain_postbuild_locks_unchanged "$rust"
toolchain_prepare_rust_analyzer "$ROOT_DIR" "$rust" "$MOTORH" \
	"${CARGO_HOME:-$HOME/.cargo}" "$temporary" false
echo 'test-rust-analyzer-sources PASS'
