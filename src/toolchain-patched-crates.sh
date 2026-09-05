#!/usr/bin/env bash
# Prepare published crates without modifying registry caches or Rust sources.
# Callers source toolchain-lib.sh, toolchain-sources.sh and toolchain-assembly.sh.

toolchain_prepare_patched_crate() (
	set -euo pipefail
	local root="$1" name="$2" version="$3" checksum="$4" archive="$5" patch="$6"
	local key destination temporary source path kind expected actual
	[[ "$name" =~ ^[a-zA-Z0-9_-]+$ && "$version" =~ ^[0-9][a-zA-Z0-9.+-]*$ ]] ||
		{ toolchain_die "invalid patched-crate name or version"; exit 1; }
	toolchain_require_hex crate_checksum "$checksum" 64 || exit 1
	[ "$(sha256sum "$archive" | awk '{print $1}')" = "$checksum" ] ||
		{ toolchain_die "$name $version archive checksum mismatch"; exit 1; }
	patch="$(realpath "$patch")" || exit 1
	key="$(toolchain_hash_pairs schema motor-patched-crate-v1 name "$name" \
		version "$version" archive "$checksum" \
		patch "$(sha256sum "$patch" | awk '{print $1}')")" || exit 1
	mkdir -p "$root" || exit 1
	root="$(realpath "$root")" || exit 1
	destination="$root/$name-$version-$key"
	temporary="$(mktemp -d "$root/.prepare.XXXXXX")" || exit 1
	trap 'rm -rf "$temporary"' EXIT
	# Reject links and noncanonical paths before tar can create anything.
	tar -tzf "$archive" --quoting-style=escape > "$temporary/members" || exit 1
	tar -tvzf "$archive" > "$temporary/kinds" || exit 1
	[ -s "$temporary/members" ] || { toolchain_die "empty crate archive"; exit 1; }
	while IFS= read -r path; do
		case "$path" in
			"$name-$version/"*) ;;
			*) toolchain_die "unexpected crate archive path: $path"; exit 1 ;;
		esac
		case "/$path" in
			*/../*|*/./*|*//*|*\\*) toolchain_die "noncanonical crate archive path"; exit 1 ;;
		esac
	done < "$temporary/members"
	while IFS= read -r kind; do
		case "$kind" in
			[-d]*) ;;
			*) toolchain_die "crate archive contains a link or special file"; exit 1 ;;
		esac
	done < "$temporary/kinds"
	mkdir "$temporary/unpacked" || exit 1
	tar -xzf "$archive" --no-same-owner --no-same-permissions -C "$temporary/unpacked" || exit 1
	source="$temporary/unpacked/$name-$version"
	[ -f "$source/Cargo.toml" ] || { toolchain_die "crate manifest missing"; exit 1; }
	(cd "$source" && git apply --no-index --check "$patch" && git apply --no-index "$patch") || exit 1
	expected="$(toolchain_content_tree_digest "$source" .)" || exit 1
	if [ ! -e "$destination" ] && [ ! -L "$destination" ]; then
		# A concurrent producer may win; validate its tree below in either case.
		mv -T --no-clobber "$source" "$destination" || exit 1
	fi
	[ -d "$destination" ] && [ ! -L "$destination" ] ||
		{ toolchain_die "patched-crate destination is not a directory: $destination"; exit 1; }
	actual="$(toolchain_content_tree_digest "$destination" .)" || exit 1
	[ "$actual" = "$expected" ] ||
		{ toolchain_die "patched crate changed; preserving $destination"; exit 1; }
	printf '%s\n' "$destination"
)
