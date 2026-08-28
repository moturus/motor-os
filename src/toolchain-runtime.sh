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

toolchain_cached_crate() {
	toolchain_find_cached_crate "$@" ||
		toolchain_die "cached $2 with checksum $3 is unavailable"
}

# Drop the members Cargo generates while packaging; the author's manifest is
# published as Cargo.toml.orig.
toolchain_normalize_moto_rt_list() {
	sed -e '/^\.cargo_vcs_info\.json$/d' -e '/^Cargo\.lock$/d' \
		-e '/^Cargo\.toml$/d' -e 's/^Cargo\.toml\.orig$/Cargo.toml/' "$1" |
		LC_ALL=C sort -u
}

toolchain_moto_rt_archive_members_ok() {
	local archive="$1" archive_root="$2" path
	while IFS= read -r path; do
		case "$path" in
			"$archive_root"/*)
				case "/${path#"$archive_root"/}/" in
					*/../*) return 1 ;;
				esac
				;;
			*) return 1 ;;
		esac
	done < <(tar -tzf "$archive" 2>/dev/null)
	return 0
}

# Unpack the exact cached crate into a new temporary directory, print that
# directory, and list the published files in its archive.normalized.
toolchain_unpack_moto_rt_archive() {
	local archive="$1" version="$2" root temporary
	temporary="$(mktemp -d)" || return
	root="$temporary/archive/moto-rt-$version"
	if ! toolchain_moto_rt_archive_members_ok "$archive" "moto-rt-$version" ||
		! mkdir "$temporary/archive" ||
		! tar -xzf "$archive" -C "$temporary/archive" 2>/dev/null ||
		[ ! -d "$root" ] ||
		[ -n "$(find "$root" -mindepth 1 ! -type d ! -type f -print -quit)" ]; then
		rm -rf "$temporary"
		toolchain_die "cached $(basename "$archive") is not a plain moto-rt package" || return
	fi
	find "$root" -type f -printf '%P\n' | LC_ALL=C sort > "$temporary/archive.list"
	toolchain_normalize_moto_rt_list "$temporary/archive.list" \
		> "$temporary/archive.normalized"
	if [ ! -s "$temporary/archive.normalized" ]; then
		rm -rf "$temporary"
		toolchain_die "cached $(basename "$archive") publishes no files" || return
	fi
	printf '%s\n' "$temporary"
}

# Compare every published file with the local package and name each
# difference. This needs no Cargo, so it cannot see local files that are not
# published; toolchain_compare_moto_rt_package covers the file set.
toolchain_compare_moto_rt_files() {
	local local_package="$1" unpacked="$2" version="$3" path published status=0
	while IFS= read -r path; do
		published="$unpacked/archive/moto-rt-$version/$path"
		[ "$path" != Cargo.toml ] || published="$published.orig"
		if [ ! -f "$local_package/$path" ]; then
			echo "toolchain: moto-rt $path is published but missing locally" >&2
			status=1
		elif ! cmp -s "$published" "$local_package/$path"; then
			echo "toolchain: moto-rt $path differs from the published $version package" >&2
			status=1
		fi
	done < "$unpacked/archive.normalized"
	return "$status"
}

# Full comparison: the file set Cargo would package, then every file.
toolchain_compare_moto_rt_package() {
	local local_package="$1" unpacked="$2" version="$3" status=0
	toolchain_normalize_moto_rt_list "$unpacked/local.list" > "$unpacked/local.normalized"
	if ! cmp -s "$unpacked/archive.normalized" "$unpacked/local.normalized"; then
		LC_ALL=C comm -23 "$unpacked/archive.normalized" "$unpacked/local.normalized" |
			sed 's/^/toolchain: moto-rt published file is not packaged locally: /' >&2
		LC_ALL=C comm -13 "$unpacked/archive.normalized" "$unpacked/local.normalized" |
			sed 's/^/toolchain: moto-rt local package adds unpublished file: /' >&2
		status=1
	fi
	toolchain_compare_moto_rt_files "$local_package" "$unpacked" "$version" || status=1
	return "$status"
}

toolchain_resolve_moto_rt_identity() {
	local rust="$1" local_package="$2" identity local_version
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
}

# A difference is fatal for a clean assembly and recorded for a dirty one.
toolchain_moto_rt_package_differs() {
	if [ "${MOTOR_ASSEMBLY_STATE:-}" = development-dirty ]; then
		MOTO_RT_PACKAGE_COMPARISON=development-dirty
		echo "toolchain: local moto-rt differs from its crates.io package (development-dirty)" >&2
		return 0
	fi
	echo "toolchain: restore the published moto-rt $LOCKED_MOTO_RT_VERSION content, or publish" \
		"a new version and select it in the Rust fork and src/toolchain-versions.sh" >&2
	toolchain_die "local moto-rt content differs from the locked crates.io package"
}

# Content check that runs before the LLVM and Rust builds. Without a Motor
# Cargo it cannot list the local package, so it compares every published file
# and leaves file-set differences to toolchain_verify_moto_rt_package. The
# first Rust bootstrap fetches the crate, so its absence only defers.
toolchain_precheck_moto_rt_package() {
	local rust="$1" local_package="$2" cargo_home="$3" archive unpacked status=0
	toolchain_resolve_moto_rt_identity "$rust" "$local_package" || return
	if ! archive="$(toolchain_find_cached_crate "$cargo_home" \
		"moto-rt-$LOCKED_MOTO_RT_VERSION.crate" "$LOCKED_MOTO_RT_CHECKSUM")"; then
		echo "toolchain: moto-rt-$LOCKED_MOTO_RT_VERSION.crate is not cached yet;" \
			"its package check runs after Rust bootstrap" >&2
		return 0
	fi
	unpacked="$(toolchain_unpack_moto_rt_archive "$archive" "$LOCKED_MOTO_RT_VERSION")" || return
	toolchain_compare_moto_rt_files "$local_package" "$unpacked" \
		"$LOCKED_MOTO_RT_VERSION" || status=1
	rm -rf "$unpacked"
	[ "$status" -ne 0 ] || return 0
	toolchain_moto_rt_package_differs
}

toolchain_verify_moto_rt_package() {
	local rust="$1" local_package="$2" cargo="$3" cargo_home="$4"
	local archive unpacked status=0
	toolchain_resolve_moto_rt_identity "$rust" "$local_package" || return
	archive="$(toolchain_cached_crate "$cargo_home" \
		"moto-rt-$LOCKED_MOTO_RT_VERSION.crate" "$LOCKED_MOTO_RT_CHECKSUM")" || return
	unpacked="$(toolchain_unpack_moto_rt_archive "$archive" "$LOCKED_MOTO_RT_VERSION")" || return
	# Listing with the lock file makes Cargo resolve the whole src/sys
	# workspace, whose git-patched forks a fresh Cargo home lacks; the
	# comparison drops Cargo.lock anyway.
	if ! "$cargo" package --list --allow-dirty --offline --exclude-lockfile \
		--manifest-path "$local_package/Cargo.toml" > "$unpacked/local.list"; then
		rm -rf "$unpacked"
		toolchain_die "cannot list the local moto-rt package" || return
	fi
	toolchain_compare_moto_rt_package "$local_package" "$unpacked" \
		"$LOCKED_MOTO_RT_VERSION" || status=1
	rm -rf "$unpacked"
	if [ "$status" -eq 0 ]; then
		MOTO_RT_PACKAGE_COMPARISON=exact
		return 0
	fi
	toolchain_moto_rt_package_differs
}
