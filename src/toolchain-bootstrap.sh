#!/usr/bin/env bash
# Deterministic Rust bootstrap configuration for the exact Motor tuple.

toolchain_bootstrap_absolute_path() {
	local name="$1" value="$2"
	case "$value" in
		/*) ;;
		*) toolchain_die "$name must be an absolute path" ;;
	esac
	case "$value" in
		*'"'*|*'\'*|*$'\n'*|*$'\r'*)
			toolchain_die "$name contains a character unsupported in bootstrap TOML"
			;;
	esac
}

toolchain_render_bootstrap_config() {
	local prefix="$1" sysroot="$2" llvm_bin="$3" description="$4"
	toolchain_bootstrap_absolute_path prefix "$prefix" || return
	toolchain_bootstrap_absolute_path sysroot "$sysroot" || return
	toolchain_bootstrap_absolute_path llvm_bin "$llvm_bin" || return
	[[ "$description" =~ ^[A-Za-z0-9._+-]+$ ]] ||
		toolchain_die "invalid bootstrap description: $description" || return

	cat <<EOF
change-id = "ignore"
profile = "library"

[build]
host = ["x86_64-unknown-linux-gnu"]
target = ["x86_64-unknown-linux-gnu", "x86_64-unknown-motor"]
description = "$description"
submodules = false
extended = true
tools = ["cargo", "clippy", "rustdoc", "rustfmt", "src"]
docs = false
optimized-compiler-builtins = false
locked-deps = false

[install]
prefix = "$prefix"
sysconfdir = "etc"

[rust]
channel = "dev"
omit-git-hash = false
deny-warnings = false
incremental = true

[llvm]
download-ci-llvm = false
targets = "X86"
experimental-targets = ""
static-libstdcpp = false

[target.x86_64-unknown-motor]
cc = "$sysroot/bin/motor-clang"
cxx = "$sysroot/bin/motor-clang++"
ar = "$llvm_bin/llvm-ar"
ranlib = "$llvm_bin/llvm-ranlib"
linker = "$sysroot/bin/motor-rust-cc"
EOF
}

# Hash the semantic configuration without host paths or the key-derived prefix.
toolchain_bootstrap_identity_digest() {
	local description="$1"
	toolchain_render_bootstrap_config \
		/MOTOR_TOOLCHAIN_PREFIX /MOTOR_SYSROOT /MOTOR_LLVM_BIN "$description" |
		sha256sum | awk '{print $1}'
}

toolchain_generate_bootstrap_config() {
	local output="$1" rust_source="$2" prefix="$3" sysroot="$4"
	local llvm_bin="$5" description="$6" output_path rust_path temporary
	toolchain_bootstrap_absolute_path output "$output" || return
	toolchain_bootstrap_absolute_path rust_source "$rust_source" || return
	output_path="$(readlink -m "$output")"
	rust_path="$(readlink -m "$rust_source")"
	case "$output_path" in
		"$rust_path"|"$rust_path"/*)
			toolchain_die "bootstrap config must be outside the Rust source: $output_path"
			return 1
			;;
	esac

	mkdir -p "$(dirname "$output_path")"
	temporary="$(mktemp "${output_path}.tmp.XXXXXX")"
	if ! toolchain_render_bootstrap_config \
		"$prefix" "$sysroot" "$llvm_bin" "$description" > "$temporary"; then
		rm -f "$temporary"
		return 1
	fi
	chmod 0644 "$temporary"
	if [ -e "$output_path" ]; then
		if ! cmp -s "$temporary" "$output_path"; then
			rm -f "$temporary"
			toolchain_die "existing bootstrap config does not match the selected tuple: $output_path"
			return 1
		fi
		rm -f "$temporary"
		return 0
	fi
	mv "$temporary" "$output_path"
}
