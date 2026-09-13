#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-rust-analyzer-identity.sh"
fail() { echo "test-toolchain-rust-analyzer-identity: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/src/patches"
cp "$ROOT_DIR/src/patches/"* "$temporary/src/patches/"
for helper in patched-crates rust-analyzer rust-analyzer-identity; do
	cp "$ROOT_DIR/src/toolchain-$helper.sh" "$temporary/src/"
done
baseline="$(toolchain_rust_analyzer_inputs_digest)"
[ "$baseline" = "$(toolchain_rust_analyzer_inputs_digest "$temporary")" ] ||
	fail 'identity depends on host location'
for input in src/patches/crates.sh src/patches/url-2.5.8-motor.patch \
	src/patches/inventory-0.3.24-motor.patch src/toolchain-patched-crates.sh \
	src/toolchain-rust-analyzer.sh src/toolchain-rust-analyzer-identity.sh; do
	printf '\n# changed input\n' >> "$temporary/$input"
	[ "$baseline" != "$(toolchain_rust_analyzer_inputs_digest "$temporary")" ] ||
		fail "input does not affect identity: $input"
	cp "$ROOT_DIR/$input" "$temporary/$input"
done
mv "$temporary/src/patches/url-2.5.8-motor.patch" "$temporary/saved.patch"
if toolchain_rust_analyzer_inputs_digest "$temporary" >/dev/null 2>&1; then
	fail 'missing patch accepted'
fi
echo 'test-toolchain-rust-analyzer-identity PASS'
