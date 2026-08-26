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

toolchain_validate_assembly_outputs() {
	local path
	for path in \
		"$ASSEMBLY_SYSROOT/devtools/llvm/lib/libc.a" \
		"$ASSEMBLY_SYSROOT/devtools/llvm/lib/libc++.a" \
		"$ASSEMBLY_SYSROOT/devtools/llvm/lib/libmoto_rt_cabi.a" \
		"$ASSEMBLY_IMAGE_ROOT/llvm/devtools/llvm/bin/llvm" \
		"$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin/rustc" \
		"$ASSEMBLY_IMAGE_ROOT/rg/system/bin/rg" \
		"$ASSEMBLY_IMAGE_ROOT/libc/system/cfg/libc/shells"; do
		[ -f "$path" ] || toolchain_die "assembly output is missing: $path" || return
	done
}

toolchain_render_assembly_manifest() {
	local producer_motor_os_rev="${1:-$MOTOR_OS_REV}"
	cat <<EOF
schema=$MOTOR_GENERATED_MANIFEST_SCHEMA
toolchain_key=$MOTOR_TOOLCHAIN_KEY
assembly_key=$MOTOR_ASSEMBLY_KEY
toolchain_id=$MOTOR_TOOLCHAIN_ID
toolchain_maturity=$MOTOR_TOOLCHAIN_MATURITY
rustup_toolchain=$MOTOR_RUSTUP_TOOLCHAIN
source_mode=$MOTOR_SOURCE_MODE
assembly_state=$MOTOR_ASSEMBLY_STATE
compiler_channel=$MOTOR_RUST_CHANNEL
build_host=$MOTOR_BUILD_HOST
build_targets=$MOTOR_BUILD_TARGETS
selected_description=$SELECTED_TOOLCHAIN_DESCRIPTION
selected_upstream_rust_version=$SELECTED_RUST_VERSION
selected_upstream_rust_rev=$SELECTED_UPSTREAM_RUST_REV
selected_stage0_rev=$SELECTED_STAGE0_REV
selected_rust_llvm_base_rev=$SELECTED_RUST_LLVM_BASE_REV
selected_cargo_version=$SELECTED_MOTOR_CARGO_VERSION
selected_cargo_rev=$SELECTED_MOTOR_CARGO_REV
declared_rust_rev=$MOTOR_RUST_REV
effective_rust_rev=$EFFECTIVE_MOTOR_RUST_REV
rust_tree_state=$MOTOR_RUST_TREE_STATE
declared_llvm_rev=$MOTOR_LLVM_REV
effective_llvm_rev=$EFFECTIVE_MOTOR_LLVM_REV
llvm_tree_state=$MOTOR_LLVM_TREE_STATE
authoring_source_digest=$AUTHORING_SOURCE_DIGEST
root_lock_sha256=$START_RUST_ROOT_LOCK_SHA256
library_lock_sha256=$START_RUST_LIBRARY_LOCK_SHA256
bootstrap_config_digest=$BOOTSTRAP_CONFIG_DIGEST
stdlib_moto_rt_version=$LOCKED_MOTO_RT_VERSION
stdlib_moto_rt_checksum=$LOCKED_MOTO_RT_CHECKSUM
stdlib_moto_rt_package_comparison=$MOTO_RT_PACKAGE_COMPARISON
local_moto_rt_version=$LOCAL_MOTO_RT_VERSION
motor_os_rev=$producer_motor_os_rev
motor_os_runtime_tree=$MOTOR_OS_RUNTIME_TREE
mlibc_rev=$MOTOR_MLIBC_REV
mlibc_tree_state=$MOTOR_MLIBC_TREE_STATE
native_configuration_digest=$NATIVE_CONFIGURATION_DIGEST
host_rustc_verbose_base64=$(printf '%s' "$VALIDATED_RUSTC_VERBOSE" | base64 -w0)
host_cargo_verbose_base64=$(printf '%s' "$VALIDATED_CARGO_VERBOSE" | base64 -w0)
native_rustc_sha256=$(sha256sum "$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin/rustc" | awk '{print $1}')
native_llvm_sha256=$(sha256sum "$ASSEMBLY_IMAGE_ROOT/llvm/devtools/llvm/bin/llvm" | awk '{print $1}')
ripgrep_sha256=$(sha256sum "$ASSEMBLY_IMAGE_ROOT/rg/system/bin/rg" | awk '{print $1}')
libc_sha256=$(sha256sum "$ASSEMBLY_SYSROOT/devtools/llvm/lib/libc.a" | awk '{print $1}')
libcxx_sha256=$(sha256sum "$ASSEMBLY_SYSROOT/devtools/llvm/lib/libc++.a" | awk '{print $1}')
moto_rt_cabi_sha256=$(sha256sum "$ASSEMBLY_SYSROOT/devtools/llvm/lib/libmoto_rt_cabi.a" | awk '{print $1}')
libc_config_sha256=$(sha256sum "$ASSEMBLY_IMAGE_ROOT/libc/system/cfg/libc/shells" | awk '{print $1}')
EOF
}

toolchain_generated_manifest_paths() {
	local root
	for root in llvm rustc rg libc; do
		printf '%s/%s\n' "$ASSEMBLY_IMAGE_ROOT/$root" devtools/toolchain/manifest
	done
}

toolchain_validate_assembly_manifest() {
	local manifest="$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-MANIFEST" expected image_manifest
	local producer_motor_os_rev
	toolchain_validate_assembly_outputs || return
	[ -f "$manifest" ] || toolchain_die "assembly manifest is missing: $manifest" || return
	[ "$(stat -c %a "$manifest")" = 444 ] ||
		toolchain_die "assembly manifest is writable: $manifest" || return
	producer_motor_os_rev="$(sed -n 's/^motor_os_rev=//p' "$manifest")"
	if ! printf '%s\n' "$producer_motor_os_rev" | grep -Eq '^[0-9a-f]{40}$'; then
		toolchain_die "assembly manifest has an invalid producer Motor OS revision: $manifest"
		return 1
	fi
	expected="$(mktemp)"
	# The root revision is provenance, not an assembly-key input. Preserve the
	# producer revision when an unchanged runtime closure reuses this assembly.
	toolchain_render_assembly_manifest "$producer_motor_os_rev" > "$expected"
	if ! cmp -s "$expected" "$manifest"; then
		rm -f "$expected"
		toolchain_die "assembly manifest does not match the selected inputs: $manifest"
		return 1
	fi
	rm -f "$expected"
	while IFS= read -r image_manifest; do
		[ -f "$image_manifest" ] && cmp -s "$manifest" "$image_manifest" || {
			toolchain_die "generated-root manifest does not match: $image_manifest"
			return 1
		}
	done < <(toolchain_generated_manifest_paths)
}

toolchain_claim_assembly() {
	local lock="${ASSEMBLY_ROOT}.building"
	if [ -e "$lock" ]; then
		toolchain_die "assembly has an active or abandoned producer lock: $lock"
		return 1
	fi
	if [ -d "$ASSEMBLY_ROOT" ]; then
		toolchain_validate_assembly_manifest || return
		TOOLCHAIN_ASSEMBLY_REUSED=true
		return 0
	fi
	mkdir -p "$(dirname "$ASSEMBLY_ROOT")"
	mkdir "$lock" || return
	mkdir "$ASSEMBLY_ROOT" || return
	TOOLCHAIN_ASSEMBLY_REUSED=false
}

toolchain_complete_assembly() {
	local lock="${ASSEMBLY_ROOT}.building"
	local manifest="$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-MANIFEST" image_manifest temporary
	[ -d "$lock" ] || toolchain_die "assembly producer lock is missing: $lock" || return
	toolchain_validate_assembly_outputs || return
	[ ! -e "$manifest" ] || toolchain_die "refusing to replace assembly manifest: $manifest" || return
	temporary="$(mktemp "${manifest}.tmp.XXXXXX")"
	toolchain_render_assembly_manifest > "$temporary"
	chmod 0444 "$temporary"
	mv "$temporary" "$manifest"
	while IFS= read -r image_manifest; do
		mkdir -p "$(dirname "$image_manifest")"
		cp "$manifest" "$image_manifest"
		chmod 0444 "$image_manifest"
	done < <(toolchain_generated_manifest_paths)
	toolchain_validate_assembly_manifest || return
	rmdir "$lock"
}
