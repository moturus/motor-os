#!/usr/bin/env bash
# Build the standalone Motor server, using the assembly's driver-managed libc link.
. "$(dirname "${BASH_SOURCE[0]}")/toolchain-rust-analyzer-unwind.sh"

toolchain_validate_rust_analyzer_elf() {
	local binary="$1" readelf="$2" headers sections dynamic symbols
	[ -x "$binary" ] || { toolchain_die "analyzer is not executable: $binary"; return 1; }
	headers="$("$readelf" -W -h -l "$binary")" || return
	sections="$("$readelf" -W -S "$binary")" || return
	dynamic="$("$readelf" -W -d "$binary")" || return
	symbols="$("$readelf" -W --dyn-syms "$binary")" || return
	if ! awk '
		/Class:.*ELF64/ { class++ }
		/Data:.*little endian/ { endian++ }
		/Type:.*DYN/ { pie++ }
		/Machine:.*Advanced Micro Devices X86-64/ { machine++ }
		$1 == "INTERP" || $1 == "TLS" { bad = 1 }
		$1 == "GNU_STACK" { stack++; if ($0 ~ /E/) bad = 1 }
		$1 == "LOAD" && /W/ && /E/ { bad = 1 }
		END { exit !(class == 1 && endian == 1 && pie == 1 && machine == 1 && stack == 1 && !bad) }
	' <<< "$headers"; then
		toolchain_die "analyzer ELF is not a compatible non-executable-stack x86-64 static PIE"; return 1
	fi
	if ! awk '
		{ sub(/^.*\] +/, "") }
		$1 == ".init_array" && $2 == "INIT_ARRAY" && $5 !~ /^0+$/ { found++ }
		$1 == ".eh_frame_hdr" && $5 !~ /^0+$/ { header++ }
		$1 == ".eh_frame" && $5 !~ /^0+$/ { frames++ }
		$1 == ".gcc_except_table" && $5 !~ /^0+$/ { exceptions++ }
		END { exit found != 1 || header != 1 || frames != 1 || exceptions != 1 }
	' <<< "$sections" || ! awk '
		/NEEDED|TEXTREL/ { bad = 1 }
		/\(INIT_ARRAYSZ\)/ && $3 > 0 { array++ }
		END { exit bad || array != 1 }
	' <<< "$dynamic" || ! awk '
		$7 == "UND" && $1 != "0:" { bad = 1 }
		END { exit bad }
	' <<< "$symbols"; then
		toolchain_die "analyzer ELF has invalid constructors, unwind tables, dependencies, relocations, or symbols"; return 1
	fi
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
		printf 'rust_analyzer_%s_patch_sha256=%s\nrust_analyzer_%s_tree_sha256=%s\n' \
			"$name" "$(sha256sum "$source_dir/patches/$name-$version-motor.patch" | awk '{print $1}')" \
			"$name" "$tree"
	done
)

toolchain_build_native_rust_analyzer() (
	set -euo pipefail
	local rust="$1" cargo_home="$2" authoring_base="$3" binary destination temporary='' library unwind_root
	local expected_digest="$AUTHORING_SOURCE_DIGEST"
	toolchain_rust_analyzer_release || exit 1
	toolchain_reverify_selected_sources "$rust" "$authoring_base" "$expected_digest" || exit 1
	toolchain_reverify_rust_analyzer "$rust" "$cargo_home" || exit 1
	mkdir -p "$ASSEMBLY_BUILD_ROOT" || exit 1
	unwind_root="$(mktemp -d "$ASSEMBLY_BUILD_ROOT/.analyzer-library.XXXXXX")" || exit 1
	trap 'rm -rf "$unwind_root" "$temporary"' EXIT
	toolchain_prepare_rust_analyzer_library "$rust/library" "$unwind_root/library" || exit 1
	(cd "$rust/src/tools/rust-analyzer" && \
		RUSTC="$TOOLCHAIN_PREFIX/bin/rustc" \
		CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
		__CARGO_TESTS_ONLY_SRC_ROOT="$unwind_root/library" \
		CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$ASSEMBLY_SYSROOT/bin/motor-clang" \
		CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS="$(toolchain_rust_analyzer_unwind_flags)" \
		CFG_RELEASE="$RUST_ANALYZER_RELEASE" CFG_RELEASE_CHANNEL="$MOTOR_RUST_CHANNEL" \
		"$TOOLCHAIN_PREFIX/bin/cargo" build --release --locked --offline \
		--target x86_64-unknown-motor -p rust-analyzer \
		--config "$RUST_ANALYZER_CARGO_CONFIG" \
		--target-dir "$ASSEMBLY_BUILD_ROOT/rust-analyzer" \
		-Z build-std=std,panic_unwind) || exit 1
	cmp "$rust/library/Cargo.lock" "$unwind_root/library/Cargo.lock" || exit 1
	toolchain_postbuild_locks_unchanged "$rust" || exit 1
	toolchain_reverify_rust_analyzer "$rust" "$cargo_home" || exit 1
	binary="$ASSEMBLY_BUILD_ROOT/rust-analyzer/x86_64-unknown-motor/release/rust-analyzer"
	toolchain_reverify_selected_sources "$rust" "$authoring_base" "$expected_digest" || exit 1
	toolchain_validate_rust_analyzer_elf "$binary" "$STANDALONE_LLVM_BIN/llvm-readelf" || exit 1
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
	toolchain_validate_rust_analyzer_elf "$temporary/devtools/rust/bin/rust-analyzer" \
		"$STANDALONE_LLVM_BIN/llvm-readelf" || exit 1
	cp -a "$library" "$temporary/devtools/rust/lib/rustlib/src/rust/" || exit 1
	# These are analysis inputs, including host-only CI scripts, not guest tools.
	find "$temporary/devtools/rust/lib/rustlib/src/rust/library" -type f \
		-exec chmod a-x {} + || exit 1
	mv -T "$temporary" "$destination" || exit 1
)
