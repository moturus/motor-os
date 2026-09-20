#!/usr/bin/env bash
# Build the standalone Motor server, using the assembly's driver-managed libc link.

toolchain_fetch_rust_analyzer_library() {
	local rust="$1" prefix="$2"
	RUSTC="$prefix/bin/rustc" "$prefix/bin/cargo" fetch --locked \
		--manifest-path "$rust/library/Cargo.toml"
}

toolchain_validate_native_rust_analyzer() {
	local binary="$1"
	[ -x "$binary" ] || { toolchain_die "analyzer is not executable: $binary"; return 1; }
	grep -aFq "$EFFECTIVE_MOTOR_RUST_REV" "$binary" &&
		grep -aFq "$RUST_ANALYZER_RELEASE" "$binary" &&
		grep -aFq "$SELECTED_TOOLCHAIN_DESCRIPTION" "$binary" || {
		toolchain_die "analyzer ELF lacks the selected source/release identity"; return 1;
	}
}

toolchain_rust_analyzer_release() {
	# Motor's pinned bootstrap uses the dev channel; reject a changed channel
	# until its release-suffix rule and native recipe are reviewed together.
	[ "$MOTOR_RUST_CHANNEL" = dev ] || { toolchain_die 'unsupported native analyzer channel'; return 1; }
	RUST_ANALYZER_RELEASE="$SELECTED_RUST_VERSION-dev"
	[[ "$VALIDATED_RUST_ANALYZER_VERSION" == "rust-analyzer $RUST_ANALYZER_RELEASE ("* ]] || {
		toolchain_die 'host analyzer release differs from the native recipe'; return 1;
	}
}

toolchain_rust_analyzer_manifest_fields() (
	set -euo pipefail
	local source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" name version checksum tree
	. "$source_dir/patches/crates.sh"
	for name in url inventory; do
		if [ "$name" = url ]; then
			version="$MOTOR_URL_VERSION"; checksum="$MOTOR_URL_CHECKSUM"; tree="$MOTOR_URL_TREE_SHA256"
		else
			version="$MOTOR_INVENTORY_VERSION"; checksum="$MOTOR_INVENTORY_CHECKSUM"; tree="$MOTOR_INVENTORY_TREE_SHA256"
		fi
		printf 'rust_analyzer_%s_version=%s\nrust_analyzer_%s_archive_sha256=%s\n' \
			"$name" "$version" "$name" "$checksum"
		printf 'rust_analyzer_%s_tree_sha256=%s\n' "$name" "$tree"
	done
)

toolchain_build_native_rust_analyzer() (
	set -euo pipefail
	local rust="$1" cargo_home="$2" authoring_base="$3" binary destination temporary='' library
	local expected_digest="$AUTHORING_SOURCE_DIGEST"
	toolchain_rust_analyzer_release || exit 1
	toolchain_reverify_selected_sources "$rust" "$authoring_base" "$expected_digest" || exit 1
	toolchain_reverify_rust_analyzer "$rust" "$cargo_home" || exit 1
	mkdir -p "$ASSEMBLY_BUILD_ROOT" || exit 1
	trap 'rm -rf "$temporary"' EXIT
	(cd "$rust/src/tools/rust-analyzer" && \
		RUSTC="$TOOLCHAIN_PREFIX/bin/rustc" \
		CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
		CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$ASSEMBLY_SYSROOT/bin/motor-clang" \
		CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS="-C link-self-contained=no -C default-linker-libraries=yes" \
		CFG_RELEASE="$RUST_ANALYZER_RELEASE" CFG_RELEASE_CHANNEL="$MOTOR_RUST_CHANNEL" \
		"$TOOLCHAIN_PREFIX/bin/cargo" build --release --locked --offline \
		--target x86_64-unknown-motor -p rust-analyzer \
		--config "$RUST_ANALYZER_CARGO_CONFIG" \
		--target-dir "$ASSEMBLY_BUILD_ROOT/rust-analyzer") || exit 1
	toolchain_postbuild_locks_unchanged "$rust" || exit 1
	toolchain_reverify_rust_analyzer "$rust" "$cargo_home" || exit 1
	binary="$ASSEMBLY_BUILD_ROOT/rust-analyzer/x86_64-unknown-motor/release/rust-analyzer"
	toolchain_reverify_selected_sources "$rust" "$authoring_base" "$expected_digest" || exit 1
	toolchain_validate_native_elf "$binary" "$STANDALONE_LLVM_BIN/llvm-readelf" "$binary" || exit 1
	toolchain_validate_native_rust_analyzer "$binary" || exit 1
	library="$TOOLCHAIN_PREFIX/lib/rustlib/src/rust/library"
	[ -f "$library/core/src/lib.rs" ] && [ -f "$library/std/src/lib.rs" ] || {
		toolchain_die 'selected rust-src is incomplete'; exit 1;
	}
	destination="$ASSEMBLY_IMAGE_ROOT/rust-analyzer"
	[ ! -e "$destination" ] && [ ! -L "$destination" ] || {
		toolchain_die "unvalidated analyzer staging already exists: $destination"; exit 1;
	}
	mkdir -p "$ASSEMBLY_IMAGE_ROOT" || exit 1
	temporary="$(mktemp -d "$ASSEMBLY_IMAGE_ROOT/.rust-analyzer.XXXXXX")" || exit 1
	mkdir -p "$temporary/devtools/rust/bin" "$temporary/devtools/rust/lib/rustlib/src/rust" || exit 1
	# The compiler identity is in this non-allocated section; stripping it
	# would discard provenance while leaving the server's own version intact.
	"$STANDALONE_LLVM_BIN/llvm-strip" --keep-section=.comment \
		-o "$temporary/devtools/rust/bin/rust-analyzer" "$binary" || exit 1
	chmod 755 "$temporary/devtools/rust/bin/rust-analyzer" || exit 1
	toolchain_validate_native_elf "$temporary/devtools/rust/bin/rust-analyzer" \
		"$STANDALONE_LLVM_BIN/llvm-readelf" "$binary" || exit 1
	toolchain_validate_native_rust_analyzer "$temporary/devtools/rust/bin/rust-analyzer" || exit 1
	cp -a "$library" "$temporary/devtools/rust/lib/rustlib/src/rust/" || exit 1
	# These are analysis inputs, including host-only CI scripts, not guest tools.
	find "$temporary/devtools/rust/lib/rustlib/src/rust/library" -type f \
		-exec chmod a-x {} + || exit 1
	mv -T "$temporary" "$destination" || exit 1
)
