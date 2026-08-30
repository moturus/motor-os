#!/usr/bin/env bash
# Starting-state identity and post-build acceptance for Rust bootstrap.

toolchain_sha256_file() {
	local path="$1"
	[ -f "$path" ] || toolchain_die "required identity file is missing: $path"
	sha256sum "$path" | awk '{print $1}'
}

toolchain_capture_starting_locks() {
	local rust="$1"
	START_RUST_ROOT_LOCK_SHA256="$(toolchain_sha256_file "$rust/Cargo.lock")" || return
	START_RUST_LIBRARY_LOCK_SHA256="$(toolchain_sha256_file "$rust/library/Cargo.lock")" || return
}

toolchain_derive_identity() {
	STANDALONE_LLVM_CONFIG_DIGEST="$(
		toolchain_standalone_llvm_config_digest
	)" || return
	BOOTSTRAP_CONFIG_DIGEST="$(
		toolchain_bootstrap_identity_digest "$SELECTED_TOOLCHAIN_DESCRIPTION"
	)" || return
	MOTOR_TOOLCHAIN_KEY="$(toolchain_key)" || return
	MOTOR_RUSTUP_TOOLCHAIN="$SELECTED_RUSTUP_TOOLCHAIN_BASE-$MOTOR_TOOLCHAIN_KEY"
	toolchain_require_hex MOTOR_TOOLCHAIN_KEY "$MOTOR_TOOLCHAIN_KEY" 64
}

toolchain_mark_prefix_rejected() {
	local prefix="$1" reason="$2" marker temporary
	[ -d "$prefix" ] || toolchain_die "cannot reject missing prefix: $prefix" || return
	marker="$prefix/MOTOR-TOOLCHAIN-REJECTED"
	temporary="$(mktemp "${marker}.tmp.XXXXXX")"
	printf '%s\n' "$reason" > "$temporary"
	chmod 0444 "$temporary"
	if [ -e "$marker" ]; then
		rm -f "$temporary"
		toolchain_die "toolchain prefix was already rejected: $prefix"
		return 1
	fi
	mv "$temporary" "$marker"
}

toolchain_postbuild_locks_unchanged() {
	local rust="$1"
	POST_RUST_ROOT_LOCK_SHA256="$(toolchain_sha256_file "$rust/Cargo.lock")" || return
	POST_RUST_LIBRARY_LOCK_SHA256="$(toolchain_sha256_file "$rust/library/Cargo.lock")" || return
	if [ "$START_RUST_ROOT_LOCK_SHA256" = "$POST_RUST_ROOT_LOCK_SHA256" ] &&
		[ "$START_RUST_LIBRARY_LOCK_SHA256" = "$POST_RUST_LIBRARY_LOCK_SHA256" ]; then
		return 0
	fi
	TOOLCHAIN_LOCK_REWRITE_REASON="Rust lockfiles changed during bootstrap; root $START_RUST_ROOT_LOCK_SHA256 -> $POST_RUST_ROOT_LOCK_SHA256; library $START_RUST_LIBRARY_LOCK_SHA256 -> $POST_RUST_LIBRARY_LOCK_SHA256"
	toolchain_die "$TOOLCHAIN_LOCK_REWRITE_REASON"
}

toolchain_check_postbuild_locks() {
	local rust="$1" prefix="$2"
	toolchain_postbuild_locks_unchanged "$rust" && return 0
	toolchain_mark_prefix_rejected "$prefix" "$TOOLCHAIN_LOCK_REWRITE_REASON" || return
	toolchain_die "$TOOLCHAIN_LOCK_REWRITE_REASON; preserved and rejected $prefix"
}
