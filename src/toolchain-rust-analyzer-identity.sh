#!/usr/bin/env bash
# Offline identity for the analyzer's prepared sources, independent of host paths.

# Only the declared values enter the digest. Each tree digest pins the patched
# crate, so neither a patch file nor a script of this repository is hashed.
toolchain_rust_analyzer_inputs_digest() (
	set -euo pipefail
	local root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}" name
	. "$root/src/patches/crates.sh"
	for name in MOTOR_URL_CHECKSUM MOTOR_URL_TREE_SHA256 \
		MOTOR_INVENTORY_CHECKSUM MOTOR_INVENTORY_TREE_SHA256; do
		toolchain_require_hex "$name" "${!name}" 64 || exit 1
	done
	toolchain_hash_pairs schema motor-rust-analyzer-inputs-v2 \
		url_version "$MOTOR_URL_VERSION" url_archive "$MOTOR_URL_CHECKSUM" \
		url_tree "$MOTOR_URL_TREE_SHA256" \
		inventory_version "$MOTOR_INVENTORY_VERSION" inventory_archive "$MOTOR_INVENTORY_CHECKSUM" \
		inventory_tree "$MOTOR_INVENTORY_TREE_SHA256"
)
