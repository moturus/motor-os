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

toolchain_render_native_llvm_config() {
	local real_bin="$1" target_root="$2" real_root
	local real_bin_q real_root_q target_root_q
	toolchain_bootstrap_absolute_path real_llvm_bin "$real_bin" || return
	toolchain_bootstrap_absolute_path target_llvm_root "$target_root" || return
	real_root="$(dirname "$real_bin")"
	printf -v real_bin_q %q "$real_bin/llvm-config"
	printf -v real_root_q %q "$real_root"
	printf -v target_root_q %q "$target_root"
	cat <<EOF
#!/usr/bin/env bash
set -euo pipefail
real=$real_bin_q
real_root=$real_root_q
target_root=$target_root_q
if [ "\$#" -eq 1 ] && [ "\$1" = --bindir ]; then
	exec "\$real" "\$@"
fi
output="\$("\$real" "\$@")"
printf '%s\n' "\${output//"\$real_root"/"\$target_root"}"
EOF
}

toolchain_generate_native_llvm_config() {
	local output_bin="$1" real_bin="$2" target_root="$3"
	local output temporary tool link
	toolchain_bootstrap_absolute_path native_llvm_bin "$output_bin" || return
	[ -x "$real_bin/llvm-config" ] ||
		toolchain_die "standalone llvm-config is not executable: $real_bin/llvm-config" || return
	mkdir -p "$output_bin"
	output="$output_bin/llvm-config"
	temporary="$(mktemp "${output}.tmp.XXXXXX")"
	if ! toolchain_render_native_llvm_config \
		"$real_bin" "$target_root" > "$temporary"; then
		rm -f "$temporary"
		return 1
	fi
	chmod 0755 "$temporary"
	if [ -e "$output" ]; then
		if ! cmp -s "$temporary" "$output" || [ ! -x "$output" ]; then
			rm -f "$temporary"
			toolchain_die "existing native llvm-config adapter does not match: $output"
			return 1
		fi
		rm -f "$temporary"
	else
		mv "$temporary" "$output"
	fi
	for tool in llvm-ar llvm-ranlib; do
		[ -x "$real_bin/$tool" ] ||
			toolchain_die "standalone LLVM tool is not executable: $real_bin/$tool" || return
		link="$output_bin/$tool"
		if [ -L "$link" ] && [ "$(readlink "$link")" = "$real_bin/$tool" ]; then
			continue
		fi
		[ ! -e "$link" ] && [ ! -L "$link" ] ||
			toolchain_die "existing native LLVM tool link does not match: $link" || return
		ln -s "$real_bin/$tool" "$link"
	done
}

toolchain_build_native_rustc() {
	local rust="$1" authoring_base="$2" expected_digest="$AUTHORING_SOURCE_DIGEST"
	local prefix_before prefix_after native_llvm_bin target_llvm_root
	toolchain_generate_cross_wrappers "$ASSEMBLY_SYSROOT" "$STANDALONE_LLVM_BIN" || return
	native_llvm_bin="$ASSEMBLY_ROOT/native-llvm-config/bin"
	target_llvm_root="$rust/build/x86_64-unknown-motor/llvm"
	toolchain_generate_native_llvm_config \
		"$native_llvm_bin" "$STANDALONE_LLVM_BIN" "$target_llvm_root" || return
	NATIVE_BOOTSTRAP_CONFIG="$ASSEMBLY_ROOT/native-bootstrap.toml"
	toolchain_generate_bootstrap_config "$NATIVE_BOOTSTRAP_CONFIG" "$rust" \
		"$TOOLCHAIN_PREFIX" "$ASSEMBLY_SYSROOT" "$native_llvm_bin" \
		"$SELECTED_TOOLCHAIN_DESCRIPTION" || return
	toolchain_reverify_selected_sources \
		"$rust" "$authoring_base" "$expected_digest" || return
	prefix_before="$(toolchain_content_tree_digest "$TOOLCHAIN_PREFIX" .)" || return
	if ! (cd "$rust" && PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPYCACHEPREFIX="$TOOLCHAIN_STATE_ROOT/python-cache" \
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
