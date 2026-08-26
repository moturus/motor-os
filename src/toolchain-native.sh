#!/usr/bin/env bash
# Native Motor rustc build from the same selected Rust and LLVM source tuple.

toolchain_reject_assembly() {
	local reason="$1" marker="$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-REJECTED" temporary
	mkdir -p "$ASSEMBLY_ROOT"
	if [ ! -e "$marker" ]; then
		temporary="$(mktemp "${marker}.tmp.XXXXXX")"
		printf '%s\n' "$reason" > "$temporary"
		chmod 0444 "$temporary"
		mv "$temporary" "$marker"
	fi
	toolchain_die "$reason; preserved $ASSEMBLY_ROOT"
}

toolchain_validate_native_rustc() {
	local binary="$1"
	[ -x "$binary" ] || toolchain_die "native rustc was not produced: $binary" || return
	grep -aFq "$EFFECTIVE_MOTOR_RUST_REV" "$binary" ||
		toolchain_die "native rustc lacks the effective Rust revision" || return
	grep -aFq "$SELECTED_TOOLCHAIN_DESCRIPTION" "$binary" ||
		toolchain_die "native rustc lacks the selected release description"
}

toolchain_build_native_rustc() {
	local rust="$1" authoring_base="$2" expected_digest="$AUTHORING_SOURCE_DIGEST"
	local prefix_before prefix_after
	toolchain_generate_cross_wrappers "$ASSEMBLY_SYSROOT" "$STANDALONE_LLVM_BIN" || return
	NATIVE_BOOTSTRAP_CONFIG="$ASSEMBLY_ROOT/native-bootstrap.toml"
	toolchain_generate_bootstrap_config "$NATIVE_BOOTSTRAP_CONFIG" "$rust" \
		"$TOOLCHAIN_PREFIX" "$ASSEMBLY_SYSROOT" "$STANDALONE_LLVM_BIN" \
		"$SELECTED_TOOLCHAIN_DESCRIPTION" || return
	toolchain_reverify_selected_sources \
		"$rust" "$authoring_base" "$expected_digest" || return
	prefix_before="$(toolchain_content_tree_digest "$TOOLCHAIN_PREFIX" .)" || return
	if ! (cd "$rust" && PYTHONDONTWRITEBYTECODE=1 \
		./x.py --config "$NATIVE_BOOTSTRAP_CONFIG" build \
		--stage 2 compiler --host x86_64-unknown-motor \
		--target x86_64-unknown-motor); then
		toolchain_reject_assembly "native Rust bootstrap failed"
		return 1
	fi
	if ! toolchain_postbuild_locks_unchanged "$rust"; then
		toolchain_reject_assembly "$TOOLCHAIN_LOCK_REWRITE_REASON"
		return 1
	fi
	toolchain_reverify_selected_sources \
		"$rust" "$authoring_base" "$expected_digest" || {
		toolchain_reject_assembly "Rust sources changed during native bootstrap"
		return 1
	}
	prefix_after="$(toolchain_content_tree_digest "$TOOLCHAIN_PREFIX" .)" || return
	[ "$prefix_before" = "$prefix_after" ] || {
		toolchain_reject_assembly "native bootstrap modified the installed prefix"
		return 1
	}
	RUSTC_MAIN="$rust/build/x86_64-unknown-linux-gnu/stage2-rustc/x86_64-unknown-motor/release/rustc-main"
	toolchain_validate_native_rustc "$RUSTC_MAIN" || {
		toolchain_reject_assembly "native rustc identity validation failed"
		return 1
	}
}
