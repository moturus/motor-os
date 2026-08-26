#!/usr/bin/env bash
# Canonical Motor runtime closure and C/native assembly identity.

toolchain_runtime_closure() {
	local cargo="$1" root="$2" output packages expected
	output="$(mktemp)"
	if ! "$cargo" tree --locked --offline --edges normal --prefix none \
		--format '{p}' --manifest-path \
		"$root/src/sys/lib/moto-rt-cabi/Cargo.toml" > "$output"; then
		rm -f "$output"
		return 1
	fi
	packages="$(sed -n 's/^\([^ ]*\) v.*/\1/p' "$output" | LC_ALL=C sort -u)"
	rm -f "$output"
	expected='moto-rt
moto-rt-cabi
moto-sys'
	[ "$packages" = "$expected" ] ||
		toolchain_die "moto-rt-cabi resolved closure changed; review it explicitly: ${packages//$'\n'/,}"
	printf '%s\n' "$packages"
}

toolchain_selected_lock_digest() {
	local lock="$1" package block record
	record="$(mktemp)"
	toolchain_serialize_pairs schema motor-runtime-lock-v1 > "$record"
	for package in moto-rt moto-rt-cabi moto-sys; do
		block="$(awk -v wanted="$package" 'BEGIN { RS="" }
			$0 ~ "(^|\n)name = \"" wanted "\"(\n|$)" { print; n++ }
			END { if (n != 1) exit 1 }' "$lock")" || {
			rm -f "$record"
			toolchain_die "Cargo.lock lacks one unique $package block"
			return 1
		}
		toolchain_serialize_pairs package "$package" block "$block" >> "$record"
	done
	sha256sum "$record" | awk '{print $1}'
	rm -f "$record"
}

toolchain_content_tree_digest() (
	set -euo pipefail
	local root="$1" temporary record list path relative kind mode content special
	shift
	temporary="$(mktemp -d)"
	trap 'rm -rf "$temporary"' EXIT
	record="$temporary/record"
	list="$temporary/list"
	toolchain_serialize_pairs schema motor-runtime-content-v1 > "$record"
	for path in "$@"; do
		[ -e "$root/$path" ] || [ -L "$root/$path" ] ||
			toolchain_die "runtime input is missing: $path" || exit
		if [ -d "$root/$path" ]; then
			special="$(find "$root/$path" ! -type d ! -type f ! -type l -print -quit)"
			[ -z "$special" ] || toolchain_die "unsupported runtime file kind: $special" || exit
			find "$root/$path" \( -type f -o -type l \) -print0
		else
			printf '%s\0' "$root/$path"
		fi
	done | LC_ALL=C sort -zu > "$list"
	while IFS= read -r -d '' path; do
		relative="${path#"$root"/}"
		content="$path"
		if [ -L "$path" ]; then
			kind=symlink; mode=120000; content="$temporary/link"
			readlink -n "$path" > "$content"
		elif [ -f "$path" ]; then
			kind=file
			if [ -x "$path" ]; then mode=100755; else mode=100644; fi
		else
			toolchain_die "unsupported runtime file kind: $path"
			exit 1
		fi
		toolchain_serialize_pairs path "$relative" kind "$kind" mode "$mode" >> "$record"
		toolchain_emit_file_field content "$content" >> "$record"
	done < "$list"
	sha256sum "$record" | awk '{print $1}'
)

toolchain_native_configuration_digest() {
	toolchain_hash_pairs schema motor-native-config-v1 target x86_64-unknown-motor \
		build_type Release llvm_projects 'clang;lld' llvm_targets X86 \
		llvm_assertions true libc_subdir devtools/llvm libc_config system/cfg/libc \
		lua_version "$MOTOR_LUA_VERSION" \
		cc /MOTOR_SYSROOT/bin/motor-clang \
		cxx /MOTOR_SYSROOT/bin/motor-clang++ \
		linker /MOTOR_SYSROOT/bin/motor-rust-cc
}

toolchain_assembly_key() {
	toolchain_hash_pairs schema "$MOTOR_ASSEMBLY_KEY_SCHEMA" \
		toolchain_key "$MOTOR_TOOLCHAIN_KEY" mlibc_rev "$MOTOR_MLIBC_REV" \
		mlibc_tree_state "$MOTOR_MLIBC_TREE_STATE" \
		motor_os_runtime_tree "$MOTOR_OS_RUNTIME_TREE" \
		local_moto_rt_version "$LOCAL_MOTO_RT_VERSION" \
		native_configuration_digest "$NATIVE_CONFIGURATION_DIGEST"
}

toolchain_derive_assembly_identity() {
	local root="$1" mlibc="$2" cargo="$3" closure content lock_state
	closure="$(toolchain_runtime_closure "$cargo" "$root")" || return
	content="$(toolchain_content_tree_digest "$root" \
		"${MOTOR_OS_RUNTIME_INPUTS[@]}")" || return
	lock_state="$(toolchain_selected_lock_digest "$root/src/sys/Cargo.lock")" || return
	MOTOR_OS_RUNTIME_TREE="$(toolchain_hash_pairs schema motor-os-runtime-v1 \
		closure "$closure" content "$content" selected_lock "$lock_state")"
	MOTOR_OS_REV="$(git -C "$root" rev-parse HEAD)" || return
	MOTOR_MLIBC_TREE_STATE="$(toolchain_worktree_digest "$mlibc" mlibc)" || return
	if [ -n "$(git -C "$root" status --porcelain=v1 -- \
		"${MOTOR_OS_RUNTIME_INPUTS[@]}" src/sys/Cargo.lock)" ] ||
		[ "$MOTOR_MLIBC_TREE_STATE" != clean ]; then
		MOTOR_ASSEMBLY_STATE=development-dirty
	fi
	NATIVE_CONFIGURATION_DIGEST="$(toolchain_native_configuration_digest)"
	MOTOR_ASSEMBLY_KEY="$(toolchain_assembly_key)"
	ASSEMBLY_ROOT="$MOTORH/assemblies/$MOTOR_ASSEMBLY_KEY"
	ASSEMBLY_SYSROOT="$ASSEMBLY_ROOT/sysroot"
	ASSEMBLY_BUILD_ROOT="$ASSEMBLY_ROOT/build"
	ASSEMBLY_IMAGE_ROOT="$ASSEMBLY_ROOT/images"
}
