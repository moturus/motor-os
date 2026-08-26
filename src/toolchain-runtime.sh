#!/usr/bin/env bash
# Offline identity checks between Rust std's moto-rt and the local runtime.

toolchain_manifest_package_version() {
	local manifest="$1"
	awk '
		$0 == "[package]" { package = 1; next }
		/^\[/ { package = 0 }
		package && /^[[:space:]]*version[[:space:]]*=/ {
			line = $0
			sub(/^[^=]*=[[:space:]]*"/, "", line)
			sub(/"[[:space:]]*$/, "", line)
			print line
			n++
		}
		END { if (n != 1) exit 1 }
	' "$manifest"
}

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

toolchain_cached_crate() {
	local cargo_home="$1" filename="$2" checksum="$3" candidate
	while IFS= read -r candidate; do
		if [ "$(sha256sum "$candidate" | awk '{print $1}')" = "$checksum" ]; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done < <(find "$cargo_home/registry/cache" -type f -name "$filename" -print 2>/dev/null | LC_ALL=C sort)
	toolchain_die "cached $filename with checksum $checksum is unavailable"
}

toolchain_compare_moto_rt_package() {
	local cargo="$1" local_package="$2" archive="$3" version="$4"
	local temporary archive_root path archive_path
	temporary="$(mktemp -d)"
	archive_root="moto-rt-$version"
	if ! "$cargo" package --list --allow-dirty --offline \
		--manifest-path "$local_package/Cargo.toml" > "$temporary/local.list"; then
		rm -rf "$temporary"
		return 1
	fi
	while IFS= read -r path; do
		case "$path" in
			"$archive_root"/*)
				case "/${path#"$archive_root"/}/" in
					*/../*) rm -rf "$temporary"; return 1 ;;
				esac
				;;
			*) rm -rf "$temporary"; return 1 ;;
		esac
	done < <(tar -tzf "$archive")
	mkdir "$temporary/archive"
	tar -xzf "$archive" -C "$temporary/archive"
	if [ -n "$(find "$temporary/archive/$archive_root" -mindepth 1 \
		! -type d ! -type f -print -quit)" ]; then
		rm -rf "$temporary"
		return 1
	fi
	find "$temporary/archive/$archive_root" -type f -printf '%P\n' |
		LC_ALL=C sort > "$temporary/archive.list"
	for list in local archive; do
		sed -e '/^\.cargo_vcs_info\.json$/d' -e '/^Cargo\.lock$/d' \
			-e '/^Cargo\.toml$/d' -e 's/^Cargo\.toml\.orig$/Cargo.toml/' \
			"$temporary/$list.list" | LC_ALL=C sort -u > "$temporary/$list.normalized"
	done
	if ! cmp -s "$temporary/local.normalized" "$temporary/archive.normalized"; then
		rm -rf "$temporary"
		return 1
	fi
	while IFS= read -r path; do
		archive_path="$path"
		[ "$path" != Cargo.toml ] || archive_path=Cargo.toml.orig
		if [ ! -f "$local_package/$path" ] ||
			[ "$(sha256sum "$local_package/$path" | awk '{print $1}')" != \
			"$(sha256sum "$temporary/archive/$archive_root/$archive_path" | awk '{print $1}')" ]; then
			rm -rf "$temporary"
			return 1
		fi
	done < "$temporary/local.normalized"
	rm -rf "$temporary"
}

toolchain_verify_moto_rt_package() {
	local rust="$1" local_package="$2" cargo="$3" cargo_home="$4"
	local identity local_version archive
	identity="$(toolchain_lock_package_identity "$rust/library/Cargo.lock" moto-rt)" ||
		toolchain_die "Rust library lock has no unique complete moto-rt package" || return
	IFS=$'\t' read -r LOCKED_MOTO_RT_VERSION LOCKED_MOTO_RT_SOURCE \
		LOCKED_MOTO_RT_CHECKSUM <<< "$identity"
	[ "$LOCKED_MOTO_RT_VERSION" = "$STDLIB_MOTO_RT_VERSION" ] ||
		toolchain_die "Rust std moto-rt version differs from the declared tuple" || return
	[ "$LOCKED_MOTO_RT_CHECKSUM" = "$STDLIB_MOTO_RT_CHECKSUM" ] ||
		toolchain_die "Rust std moto-rt checksum differs from the declared tuple" || return
	[ "$LOCKED_MOTO_RT_SOURCE" = registry+https://github.com/rust-lang/crates.io-index ] ||
		toolchain_die "Rust std moto-rt is not selected from crates.io" || return
	local_version="$(toolchain_manifest_package_version "$local_package/Cargo.toml")" ||
		toolchain_die "cannot read the local moto-rt package version" || return
	[ "$local_version" = "$LOCAL_MOTO_RT_VERSION" ] &&
		[ "$local_version" = "$LOCKED_MOTO_RT_VERSION" ] ||
		toolchain_die "local and Rust std moto-rt versions differ" || return
	archive="$(toolchain_cached_crate "$cargo_home" \
		"moto-rt-$LOCKED_MOTO_RT_VERSION.crate" "$LOCKED_MOTO_RT_CHECKSUM")" || return
	if toolchain_compare_moto_rt_package \
		"$cargo" "$local_package" "$archive" "$LOCKED_MOTO_RT_VERSION"; then
		MOTO_RT_PACKAGE_COMPARISON=exact
		return 0
	fi
	if [ "${MOTOR_ASSEMBLY_STATE:-}" = development-dirty ]; then
		MOTO_RT_PACKAGE_COMPARISON=development-dirty
		echo "toolchain: local moto-rt differs from its crates.io package (development-dirty)" >&2
		return 0
	fi
	toolchain_die "local moto-rt content differs from the locked crates.io package"
}
