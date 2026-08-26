#!/usr/bin/env bash
# Validation and rustup registration for immutable installed toolchain prefixes.

toolchain_validate_prefix() {
	local prefix="$1" binary target probe
	[ ! -e "$prefix/MOTOR-TOOLCHAIN-REJECTED" ] ||
		toolchain_die "toolchain prefix is rejected: $prefix" || return
	for binary in rustc rustdoc cargo cargo-clippy clippy-driver cargo-fmt rustfmt; do
		[ -x "$prefix/bin/$binary" ] ||
			toolchain_die "installed toolchain lacks $binary: $prefix" || return
	done
	[ -d "$prefix/lib/rustlib/src/rust/library" ] ||
		toolchain_die "installed toolchain lacks rust-src: $prefix" || return
	for target in x86_64-unknown-linux-gnu x86_64-unknown-motor; do
		[ -n "$(find "$prefix/lib/rustlib/$target/lib" -maxdepth 1 \
			-type f -name 'libcore-*.rlib' -print -quit 2>/dev/null)" ] ||
			toolchain_die "installed toolchain lacks core for $target" || return
		[ -n "$(find "$prefix/lib/rustlib/$target/lib" -maxdepth 1 \
			-type f -name 'libstd-*.rlib' -print -quit 2>/dev/null)" ] ||
			toolchain_die "installed toolchain lacks std for $target" || return
	done

	VALIDATED_RUSTC_VERBOSE="$($prefix/bin/rustc -vV)" || return
	grep -Fqx "commit-hash: $EFFECTIVE_MOTOR_RUST_REV" \
		<<< "$VALIDATED_RUSTC_VERBOSE" ||
		toolchain_die "installed rustc reports the wrong commit" || return
	grep -Fq "($SELECTED_TOOLCHAIN_DESCRIPTION)" \
		<<< "$VALIDATED_RUSTC_VERBOSE" ||
		toolchain_die "installed rustc reports the wrong description" || return
	VALIDATED_CARGO_VERBOSE="$($prefix/bin/cargo -Vv)" || return
	grep -Fqx "commit-hash: $SELECTED_MOTOR_CARGO_REV" \
		<<< "$VALIDATED_CARGO_VERBOSE" ||
		toolchain_die "installed Cargo reports the wrong commit" || return
	VALIDATED_RUSTDOC_VERSION="$($prefix/bin/rustdoc --version)" || return
	VALIDATED_CLIPPY_VERSION="$($prefix/bin/clippy-driver --version)" || return
	VALIDATED_RUSTFMT_VERSION="$($prefix/bin/rustfmt --version)" || return
	VALIDATED_RUSTC_SYSROOT="$($prefix/bin/rustc --print sysroot)" || return
	[ "$(readlink -f "$VALIDATED_RUSTC_SYSROOT")" = "$(readlink -f "$prefix")" ] ||
		toolchain_die "installed rustc reports a different sysroot" || return

	probe="$(mktemp -d)"
	printf 'pub fn motor_toolchain_probe() {}\n' > "$probe/probe.rs"
	for target in x86_64-unknown-linux-gnu x86_64-unknown-motor; do
		if ! "$prefix/bin/rustc" --crate-type rlib --target "$target" \
			-o "$probe/probe-$target.rlib" "$probe/probe.rs"; then
			rm -rf "$probe"
			toolchain_die "installed rustc cannot compile for $target"
			return 1
		fi
		[ -f "$probe/probe-$target.rlib" ] || {
			rm -rf "$probe"
			toolchain_die "installed rustc produced no probe for $target"
			return 1
		}
	done
	rm -rf "$probe"
}

toolchain_render_prefix_manifest() {
	cat <<EOF
schema=$MOTOR_GENERATED_MANIFEST_SCHEMA
toolchain_key=$MOTOR_TOOLCHAIN_KEY
assembly_key=not-applicable
rustup_toolchain=$MOTOR_RUSTUP_TOOLCHAIN
toolchain_id=$MOTOR_TOOLCHAIN_ID
source_mode=$MOTOR_SOURCE_MODE
assembly_state=$MOTOR_ASSEMBLY_STATE
selected_description=$SELECTED_TOOLCHAIN_DESCRIPTION
selected_upstream_rust_rev=$SELECTED_UPSTREAM_RUST_REV
effective_rust_rev=$EFFECTIVE_MOTOR_RUST_REV
declared_rust_rev=$MOTOR_RUST_REV
effective_llvm_rev=$EFFECTIVE_MOTOR_LLVM_REV
declared_llvm_rev=$MOTOR_LLVM_REV
cargo_rev=$SELECTED_MOTOR_CARGO_REV
root_lock_sha256=$START_RUST_ROOT_LOCK_SHA256
library_lock_sha256=$START_RUST_LIBRARY_LOCK_SHA256
moto_rt_version=$LOCKED_MOTO_RT_VERSION
moto_rt_checksum=$LOCKED_MOTO_RT_CHECKSUM
moto_rt_package_comparison=$MOTO_RT_PACKAGE_COMPARISON
rustc_verbose_base64=$(printf '%s' "$VALIDATED_RUSTC_VERBOSE" | base64 -w0)
cargo_verbose_base64=$(printf '%s' "$VALIDATED_CARGO_VERBOSE" | base64 -w0)
rustdoc_version_base64=$(printf '%s' "$VALIDATED_RUSTDOC_VERSION" | base64 -w0)
clippy_version_base64=$(printf '%s' "$VALIDATED_CLIPPY_VERSION" | base64 -w0)
rustfmt_version_base64=$(printf '%s' "$VALIDATED_RUSTFMT_VERSION" | base64 -w0)
rustc_sysroot=.
EOF
}

toolchain_validate_prefix_manifest() {
	local prefix="$1" manifest expected
	manifest="$prefix/MOTOR-TOOLCHAIN-MANIFEST"
	[ -f "$manifest" ] || toolchain_die "toolchain prefix has no manifest: $prefix" || return
	[ "$(stat -c %a "$manifest")" = 444 ] ||
		toolchain_die "toolchain prefix manifest is writable: $manifest" || return
	expected="$(mktemp)"
	toolchain_render_prefix_manifest > "$expected"
	if ! cmp -s "$expected" "$manifest"; then
		rm -f "$expected"
		toolchain_die "toolchain prefix manifest does not match the selected tuple: $prefix"
		return 1
	fi
	rm -f "$expected"
}

toolchain_write_prefix_manifest() {
	local prefix="$1" manifest temporary
	manifest="$prefix/MOTOR-TOOLCHAIN-MANIFEST"
	[ ! -e "$manifest" ] || toolchain_die "refusing to replace prefix manifest: $manifest" || return
	temporary="$(mktemp "${manifest}.tmp.XXXXXX")"
	toolchain_render_prefix_manifest > "$temporary"
	chmod 0444 "$temporary"
	mv "$temporary" "$manifest"
}

toolchain_validate_rustup_link() {
	local rustup="$1" prefix="$2" binary resolved
	for binary in rustc rustdoc cargo cargo-clippy clippy-driver cargo-fmt rustfmt; do
		resolved="$($rustup which "$binary" --toolchain "$MOTOR_RUSTUP_TOOLCHAIN" 2>/dev/null)" ||
			toolchain_die "rustup cannot resolve $binary from $MOTOR_RUSTUP_TOOLCHAIN" || return
		[ -x "$resolved" ] || toolchain_die "rustup resolved missing $binary: $resolved" || return
		[ "$(readlink -f "$resolved")" = "$(readlink -f "$prefix/bin/$binary")" ] ||
			toolchain_die "rustup resolved $binary outside the keyed prefix" || return
	done
}

toolchain_register_prefix() {
	local rustup="$1" prefix="$2"
	if "$rustup" toolchain list | awk '{print $1}' |
		grep -Fqx "$MOTOR_RUSTUP_TOOLCHAIN"; then
		toolchain_validate_rustup_link "$rustup" "$prefix"
		return
	fi
	"$rustup" toolchain link "$MOTOR_RUSTUP_TOOLCHAIN" "$prefix" || return
	toolchain_validate_rustup_link "$rustup" "$prefix"
}

toolchain_claim_prefix() {
	local prefix="$1" lock
	lock="${prefix}.building"
	if [ -d "$prefix" ]; then
		TOOLCHAIN_PREFIX_REUSED=true
		return 0
	fi
	[ ! -e "$prefix" ] || toolchain_die "toolchain prefix path is not a directory: $prefix" || return
	if ! mkdir "$lock" 2>/dev/null; then
		toolchain_die "toolchain prefix has an active or abandoned producer lock: $lock"
		return 1
	fi
	TOOLCHAIN_PREFIX_REUSED=false
}

toolchain_complete_prefix() {
	local prefix="$1" lock
	lock="${prefix}.building"
	[ -d "$lock" ] || toolchain_die "toolchain producer lock is missing: $lock" || return
	rmdir "$lock"
}
