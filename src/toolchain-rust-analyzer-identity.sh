#!/usr/bin/env bash
# Offline identity for the analyzer's prepared sources, independent of host paths.

toolchain_rust_analyzer_inputs_digest() (
	set -euo pipefail
	local root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}" path
	local -a fields=(schema motor-rust-analyzer-inputs-v1)
	. "$root/src/patches/crates.sh"
	for path in \
		src/patches/crates.sh \
		"src/patches/url-$MOTOR_URL_VERSION-motor.patch" \
		"src/patches/inventory-$MOTOR_INVENTORY_VERSION-motor.patch" \
		src/toolchain-patched-crates.sh src/toolchain-rust-analyzer.sh \
		src/toolchain-rust-analyzer-identity.sh; do
		[ -f "$root/$path" ] || { toolchain_die "missing analyzer input: $path"; exit 1; }
		fields+=("$path" "$(sha256sum "$root/$path" | awk '{print $1}')")
	done
	for path in MOTOR_URL_CHECKSUM MOTOR_URL_TREE_SHA256 \
		MOTOR_INVENTORY_CHECKSUM MOTOR_INVENTORY_TREE_SHA256; do
		toolchain_require_hex "$path" "${!path}" 64 || exit 1
	done
	toolchain_hash_pairs "${fields[@]}" \
		url_version "$MOTOR_URL_VERSION" url_archive "$MOTOR_URL_CHECKSUM" \
		url_tree "$MOTOR_URL_TREE_SHA256" \
		inventory_version "$MOTOR_INVENTORY_VERSION" inventory_archive "$MOTOR_INVENTORY_CHECKSUM" \
		inventory_tree "$MOTOR_INVENTORY_TREE_SHA256"
)
