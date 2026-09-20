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
# No file of this repository is hashed: only declared values re-key.
for input in src/patches/url-2.5.8-motor.patch \
	src/patches/inventory-0.3.24-motor.patch src/toolchain-patched-crates.sh \
	src/toolchain-rust-analyzer.sh src/toolchain-rust-analyzer-identity.sh; do
	printf '\n# changed input\n' >> "$temporary/$input"
	[ "$baseline" = "$(toolchain_rust_analyzer_inputs_digest "$temporary")" ] ||
		fail "repository file re-keys the toolchain: $input"
done
printf '\n# a comment\n' >> "$temporary/src/patches/crates.sh"
[ "$baseline" = "$(toolchain_rust_analyzer_inputs_digest "$temporary")" ] ||
	fail 'a comment in the declaration re-keys the toolchain'
for value in MOTOR_URL_VERSION=9.9.9 MOTOR_INVENTORY_VERSION=9.9.9 \
	MOTOR_URL_TREE_SHA256="$(printf tree | sha256sum | awk '{print $1}')" \
	MOTOR_INVENTORY_CHECKSUM="$(printf archive | sha256sum | awk '{print $1}')"; do
	cp "$ROOT_DIR/src/patches/crates.sh" "$temporary/src/patches/crates.sh"
	printf '%s\n' "$value" >> "$temporary/src/patches/crates.sh"
	[ "$baseline" != "$(toolchain_rust_analyzer_inputs_digest "$temporary")" ] ||
		fail "declared value does not affect identity: ${value%%=*}"
done
cp "$ROOT_DIR/src/patches/crates.sh" "$temporary/src/patches/crates.sh"
printf 'MOTOR_URL_TREE_SHA256=not-hex\n' >> "$temporary/src/patches/crates.sh"
if toolchain_rust_analyzer_inputs_digest "$temporary" >/dev/null 2>&1; then
	fail 'malformed declared tree digest accepted'
fi
echo 'test-toolchain-rust-analyzer-identity PASS'
