#!/usr/bin/env bash
# Salsa cancels analyses with resume_unwind, even without a user-code panic.

toolchain_fetch_rust_analyzer_library() {
	local rust="$1" prefix="$2"
	# Provision all locked platforms: Xous already locks the pure Rust unwinder.
	# This acquisition step is separate from offline builds and regular tests.
	RUSTC="$prefix/bin/rustc" "$prefix/bin/cargo" fetch --locked \
		--manifest-path "$rust/library/Cargo.toml"
}

toolchain_prepare_rust_analyzer_library() (
	set -euo pipefail
	local source="$1" destination="$2" helpers
	helpers="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	[ ! -e "$destination" ] && [ ! -L "$destination" ] || {
		toolchain_die "analyzer library destination already exists: $destination"; exit 1;
	}
	[ "$(sha256sum "$source/Cargo.lock" | awk '{print $1}')" = "$MOTOR_RUST_LIBRARY_LOCK_SHA256" ] || {
		toolchain_die 'analyzer library lock differs from the selected Rust source'; exit 1;
	}
	cp -a "$source" "$destination" || exit 1
	patch --batch --fuzz=0 --no-backup-if-mismatch -d "$destination" -p1 \
		< "$helpers/patches/rust-analyzer-unwind.patch"
)

toolchain_rust_analyzer_unwind_flags() {
	# Static PIE supplies the unwind tables. LLD's text/header symbols need
	# aliases matching the pure-Rust unwinder's GNU ELF table finder.
	printf '%s\n' '-C panic=unwind -C link-self-contained=no -C default-linker-libraries=yes -C link-arg=-Wl,--defsym=__etext=_etext -C link-arg=-Wl,--defsym=__GNU_EH_FRAME_HDR=ADDR(.eh_frame_hdr)'
}
