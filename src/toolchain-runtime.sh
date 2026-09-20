#!/usr/bin/env bash
# Offline compatibility check between Rust std's moto-rt and the local runtime.

toolchain_lock_package_identity() {
	local lock="$1" package="$2"
	awk -v wanted="$package" '
		function value(line) {
			sub(/^[^=]*=[[:space:]]*"/, "", line)
			sub(/"[[:space:]]*$/, "", line)
			return line
		}
		function finish() {
			if (name == wanted) {
				found++
				result = version "\t" source "\t" checksum
			}
		}
		$0 == "[[package]]" {
			if (active) finish()
			active = 1; name = version = source = checksum = ""
			next
		}
		active && /^[[:space:]]*name[[:space:]]*=/ { name = value($0); next }
		active && /^[[:space:]]*version[[:space:]]*=/ { version = value($0); next }
		active && /^[[:space:]]*source[[:space:]]*=/ { source = value($0); next }
		active && /^[[:space:]]*checksum[[:space:]]*=/ { checksum = value($0); next }
		END {
			if (active) finish()
			if (found != 1 || result ~ /^\t/ || result ~ /\t\t/ || result ~ /\t$/) exit 1
			print result
		}
	' "$lock"
}

toolchain_find_cached_crate() {
	local cargo_home="$1" filename="$2" checksum="$3" candidate
	while IFS= read -r candidate; do
		if [ "$(sha256sum "$candidate" | awk '{print $1}')" = "$checksum" ]; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done < <(find "$cargo_home/registry/cache" -type f -name "$filename" -print 2>/dev/null | LC_ALL=C sort)
	return 1
}

# Rust std links the moto-rt crate that the Rust fork locks (the declared
# library lock hash covers it); the rest of Motor OS links the local one. Both
# call the same RT.VDSO, so they only have to be compatible: the local version
# may differ from std's below the major version.
toolchain_check_moto_rt_compat() {
	local rust="$1" local_package="$2" identity local_version
	identity="$(toolchain_lock_package_identity "$rust/library/Cargo.lock" moto-rt)" ||
		toolchain_die "Rust library lock has no unique complete moto-rt package" || return
	IFS=$'\t' read -r LOCKED_MOTO_RT_VERSION LOCKED_MOTO_RT_SOURCE \
		LOCKED_MOTO_RT_CHECKSUM <<< "$identity"
	[ "$LOCKED_MOTO_RT_SOURCE" = registry+https://github.com/rust-lang/crates.io-index ] ||
		toolchain_die "Rust std moto-rt is not selected from crates.io" || return
	local_version="$(toolchain_manifest_package_version "$local_package/Cargo.toml")" ||
		toolchain_die "cannot read the local moto-rt package version" || return
	[ "$(toolchain_compat_version "$local_version")" = \
		"$(toolchain_compat_version "$LOCKED_MOTO_RT_VERSION")" ] ||
		toolchain_die "local moto-rt $local_version and Rust std moto-rt" \
			"$LOCKED_MOTO_RT_VERSION differ in their major version"
}
