#!/usr/bin/env bash
# Workspace-scoped sources shared by host bootstrap and the native analyzer.

toolchain_rust_analyzer_crate() {
	local root="$1" motorh="$2" cargo_home="$3" name="$4" acquire="$5"
	local version checksum expected archive directory temporary source
	case "$name" in
		url)
			version="$MOTOR_URL_VERSION"; checksum="$MOTOR_URL_CHECKSUM"
			expected="$MOTOR_URL_TREE_SHA256" ;;
		inventory)
			version="$MOTOR_INVENTORY_VERSION"; checksum="$MOTOR_INVENTORY_CHECKSUM"
			expected="$MOTOR_INVENTORY_TREE_SHA256" ;;
		*) toolchain_die "unsupported analyzer patch: $name"; return 1 ;;
	esac
	case "$acquire" in
		true|false) ;;
		*) toolchain_die "invalid analyzer acquisition mode: $acquire"; return 1 ;;
	esac
	toolchain_require_hex prepared_tree "$expected" 64 || return
	if ! archive="$(toolchain_find_cached_crate "$cargo_home" "$name-$version.crate" "$checksum")"; then
		directory="$motorh/patched-crates/archives"
		archive="$directory/$name-$version-$checksum.crate"
		if [ ! -e "$archive" ]; then
			[ "$acquire" = true ] || {
				toolchain_die "missing offline archive: $name $version"; return 1;
			}
			mkdir -p "$directory" || return
			temporary="$(mktemp "$directory/.download.XXXXXX")" || return
			if ! curl --fail --location --proto '=https' --proto-redir '=https' \
				"https://static.crates.io/crates/$name/$name-$version.crate" -o "$temporary" ||
				[ "$(sha256sum "$temporary" | awk '{print $1}')" != "$checksum" ]; then
				rm -f "$temporary"
				toolchain_die "cannot acquire verified $name $version"; return 1
			fi
			mv -T --no-clobber "$temporary" "$archive" || return
			rm -f "$temporary"
		fi
	fi
	source="$(toolchain_prepare_patched_crate "$motorh/patched-crates" "$name" \
		"$version" "$checksum" "$archive" "$root/src/patches/$name-$version-motor.patch")" || return
	[ "$(toolchain_content_tree_digest "$source" .)" = "$expected" ] || {
		toolchain_die "prepared $name differs from the declared tree; preserving $source"; return 1;
	}
	printf '%s\n' "$source"
}

toolchain_render_rust_analyzer_config() {
	local url="$1" inventory="$2"
	toolchain_bootstrap_absolute_path url "$url" || return
	toolchain_bootstrap_absolute_path inventory "$inventory" || return
	printf '[patch.crates-io]\nurl = { path = "%s" }\ninventory = { path = "%s" }\n' \
		"$url" "$inventory"
}

toolchain_generate_rust_analyzer_config() {
	local output="$1" rust="$2" url="$3" inventory="$4" temporary
	toolchain_bootstrap_absolute_path output "$output" || return
	toolchain_bootstrap_absolute_path rust "$rust" || return
	# Resolve parents as well as the output so symlinks cannot hide a source write.
	[ ! -L "$output" ] || { toolchain_die "analyzer config is a symlink: $output"; return 1; }
	output="$(readlink -m "$output")" || return
	rust="$(readlink -m "$rust")" || return
	case "$output" in
		"$rust"|"$rust"/*)
			toolchain_die "analyzer config must be outside Rust sources"; return 1 ;;
	esac
	mkdir -p "$(dirname "$output")" || return
	temporary="$(mktemp "$output.tmp.XXXXXX")" || return
	if ! toolchain_render_rust_analyzer_config "$url" "$inventory" > "$temporary"; then
		rm -f "$temporary"; return 1
	fi
	chmod 0644 "$temporary"
	if [ -e "$output" ]; then
		if ! cmp -s "$temporary" "$output"; then
			rm -f "$temporary"
			toolchain_die "analyzer config changed; preserving $output"; return 1
		fi
		rm -f "$temporary"
	else
		mv "$temporary" "$output"
	fi
}

toolchain_prepare_rust_analyzer() {
	local root="$1" rust="$2" motorh="$3" cargo_home="$4" state="$5" acquire="$6"
	RUST_ANALYZER_URL_SOURCE="$(toolchain_rust_analyzer_crate \
		"$root" "$motorh" "$cargo_home" url "$acquire")" || return
	RUST_ANALYZER_INVENTORY_SOURCE="$(toolchain_rust_analyzer_crate \
		"$root" "$motorh" "$cargo_home" inventory "$acquire")" || return
	RUST_ANALYZER_CARGO_CONFIG="$state/rust-analyzer-cargo.toml"
	toolchain_generate_rust_analyzer_config "$RUST_ANALYZER_CARGO_CONFIG" "$rust" \
		"$RUST_ANALYZER_URL_SOURCE" "$RUST_ANALYZER_INVENTORY_SOURCE"
}

toolchain_reverify_rust_analyzer() {
	local rust="$1" cargo_home="$2"
	[ "$(toolchain_rust_analyzer_inputs_digest)" = "$RUST_ANALYZER_INPUTS_DIGEST" ] || {
		toolchain_die "analyzer input recipes changed during the build"; return 1;
	}
	toolchain_prepare_rust_analyzer "$MOTOR" "$rust" "$MOTORH" "$cargo_home" \
		"$TOOLCHAIN_STATE_ROOT" false
}

toolchain_fetch_rust_analyzer() {
	local rust="$1" prefix="$2" manifest
	# Provisioning may acquire sources; native check/build and regular tests are offline.
	(cd "$rust/src/tools/rust-analyzer" && RUSTC="$prefix/bin/rustc" \
		"$prefix/bin/cargo" fetch --locked --target x86_64-unknown-motor \
		--config "$RUST_ANALYZER_CARGO_CONFIG") || return
	for manifest in "$RUST_ANALYZER_URL_SOURCE/Cargo.toml" \
		"$RUST_ANALYZER_INVENTORY_SOURCE/Cargo.toml"; do
		RUSTC="$prefix/bin/rustc" "$prefix/bin/cargo" fetch --locked \
			--manifest-path "$manifest" || return
	done
	toolchain_postbuild_locks_unchanged "$rust"
}
