#!/usr/bin/env bash
# Transactional installation of the selected Linux-host Motor Rust toolchain.

toolchain_reverify_selected_sources() {
	local rust="$1" authoring_base="$2" expected_digest="$3"
	local expected_rust="$EFFECTIVE_MOTOR_RUST_REV"
	local expected_llvm="$EFFECTIVE_MOTOR_LLVM_REV"
	local expected_description="$SELECTED_TOOLCHAIN_DESCRIPTION"
	case "$MOTOR_SOURCE_MODE" in
		managed) toolchain_verify_managed_rust "$rust" ;;
		authoring)
			toolchain_authoring_resolve "$rust" "$authoring_base" || return
			[ "$AUTHORING_SOURCE_DIGEST" = "$expected_digest" ] &&
				[ "$EFFECTIVE_MOTOR_RUST_REV" = "$expected_rust" ] &&
				[ "$EFFECTIVE_MOTOR_LLVM_REV" = "$expected_llvm" ] &&
				[ "$SELECTED_TOOLCHAIN_DESCRIPTION" = "$expected_description" ] ||
				toolchain_die "authoring sources changed while being consumed"
			;;
		*) toolchain_die "unsupported source mode: $MOTOR_SOURCE_MODE" ;;
	esac
}

toolchain_reject_incomplete_prefix() {
	local prefix="$1" reason="$2"
	mkdir -p "$prefix"
	if [ ! -e "$prefix/MOTOR-TOOLCHAIN-REJECTED" ]; then
		toolchain_mark_prefix_rejected "$prefix" "$reason" || return
	fi
	toolchain_die "$reason; preserved $prefix"
}

toolchain_accept_new_prefix() {
	local rust="$1" authoring_base="$2" expected_digest="$3"
	local prefix="$4" local_moto_rt="$5" cargo_home="$6"
	if ! (cd "$rust" && PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPYCACHEPREFIX="$TOOLCHAIN_STATE_ROOT/python-cache" \
		./x.py --config "$BOOTSTRAP_CONFIG" install --stage 2); then
		toolchain_reject_incomplete_prefix "$prefix" "Rust bootstrap install failed"
		return 1
	fi
	toolchain_stage_rust_lld "$prefix" "$STANDALONE_LLVM_BIN" || {
		toolchain_reject_incomplete_prefix "$prefix" "rust-lld staging failed"
		return 1
	}
	toolchain_check_postbuild_locks "$rust" "$prefix" || return
	toolchain_reverify_selected_sources \
		"$rust" "$authoring_base" "$expected_digest" || {
		toolchain_reject_incomplete_prefix "$prefix" "Rust sources changed during bootstrap"
		return 1
	}
	toolchain_validate_prefix "$prefix" || {
		toolchain_reject_incomplete_prefix "$prefix" "installed prefix validation failed"
		return 1
	}
	toolchain_verify_moto_rt_package "$rust" "$local_moto_rt" \
		"$prefix/bin/cargo" "$cargo_home" || {
		toolchain_reject_incomplete_prefix "$prefix" "moto-rt package validation failed"
		return 1
	}
	toolchain_write_prefix_manifest "$prefix" || return
	toolchain_complete_prefix "$prefix"
}

toolchain_build_selected_host() {
	local rust="$1" authoring_base="$2" build_root="$3" rustup="$4"
	local cargo_home="$5" local_moto_rt="$6" expected_digest
	toolchain_capture_starting_locks "$rust" || return
	toolchain_derive_identity || return
	expected_digest="$AUTHORING_SOURCE_DIGEST"
	TOOLCHAIN_PREFIX="$MOTORH/toolchains/$MOTOR_RUSTUP_TOOLCHAIN"
	TOOLCHAIN_STATE_ROOT="$MOTORH/toolchain-state/$MOTOR_TOOLCHAIN_KEY"
	BOOTSTRAP_SYSROOT="$TOOLCHAIN_STATE_ROOT/bootstrap-sysroot"

	toolchain_reverify_selected_sources \
		"$rust" "$authoring_base" "$expected_digest" || return
	# A stale local runtime fails here, before the LLVM and Rust builds.
	toolchain_precheck_moto_rt_package "$rust" "$local_moto_rt" "$cargo_home" || return
	toolchain_build_standalone_llvm "$rust/src/llvm-project" "$build_root" || return
	toolchain_generate_cross_wrappers "$BOOTSTRAP_SYSROOT" "$STANDALONE_LLVM_BIN" || return
	BOOTSTRAP_CONFIG="$TOOLCHAIN_STATE_ROOT/bootstrap.toml"
	toolchain_generate_bootstrap_config "$BOOTSTRAP_CONFIG" "$rust" \
		"$TOOLCHAIN_PREFIX" "$BOOTSTRAP_SYSROOT" "$STANDALONE_LLVM_BIN" \
		"$SELECTED_TOOLCHAIN_DESCRIPTION" || return

	toolchain_claim_prefix "$TOOLCHAIN_PREFIX" || return
	if [ "$TOOLCHAIN_PREFIX_REUSED" = true ]; then
		toolchain_validate_prefix "$TOOLCHAIN_PREFIX" || return
		toolchain_verify_moto_rt_package "$rust" "$local_moto_rt" \
			"$TOOLCHAIN_PREFIX/bin/cargo" "$cargo_home" || return
		toolchain_validate_prefix_manifest "$TOOLCHAIN_PREFIX" || return
	else
		toolchain_accept_new_prefix "$rust" "$authoring_base" "$expected_digest" \
			"$TOOLCHAIN_PREFIX" "$local_moto_rt" "$cargo_home" || return
	fi
	toolchain_register_prefix "$rustup" "$TOOLCHAIN_PREFIX"
}
