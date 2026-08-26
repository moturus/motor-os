#!/usr/bin/env bash
# Keyed standalone LLVM used by the Rust bootstrap and C sysroot producers.

toolchain_standalone_llvm_config_digest() {
	toolchain_hash_pairs schema motor-standalone-llvm-config-v1 \
		generator Ninja build_type Release assertions true \
		projects 'clang;lld' targets X86 tests false \
		c_compiler clang cxx_compiler clang++
}

toolchain_standalone_llvm_key() {
	toolchain_hash_pairs schema motor-standalone-llvm-key-v1 \
		effective_llvm_rev "$EFFECTIVE_MOTOR_LLVM_REV" \
		llvm_tree_state "$MOTOR_LLVM_TREE_STATE" \
		configuration_digest "$(toolchain_standalone_llvm_config_digest)"
}

toolchain_render_standalone_llvm_manifest() {
	cat <<EOF
schema=motor-standalone-llvm-manifest-v1
key=$STANDALONE_LLVM_KEY
effective_llvm_rev=$EFFECTIVE_MOTOR_LLVM_REV
declared_llvm_rev=$MOTOR_LLVM_REV
llvm_tree_state=$MOTOR_LLVM_TREE_STATE
configuration_digest=$(toolchain_standalone_llvm_config_digest)
version=$RUST_LLVM_VERSION
EOF
}

toolchain_validate_standalone_llvm() {
	local build="$1" binary version expected
	expected="$(mktemp)"
	toolchain_render_standalone_llvm_manifest > "$expected"
	if ! cmp -s "$expected" "$build/MOTOR-LLVM-MANIFEST"; then
		rm -f "$expected"
		toolchain_die "standalone LLVM manifest does not match: $build"
		return 1
	fi
	rm -f "$expected"
	for binary in clang clang++ ld.lld llvm-ar llvm-ranlib llvm-nm \
		llvm-readelf llvm-strip llvm-objcopy llvm-config; do
		[ -x "$build/bin/$binary" ] ||
			toolchain_die "standalone LLVM lacks $binary: $build" || return
	done
	version="$($build/bin/llvm-config --version)" || return
	[ "$version" = "$RUST_LLVM_VERSION" ] ||
		toolchain_die "standalone LLVM version is $version, expected $RUST_LLVM_VERSION" || return
	"$build/bin/clang" --version | grep -Fq "$RUST_LLVM_VERSION" ||
		toolchain_die "standalone Clang reports the wrong version"
}

toolchain_verify_llvm_selection() {
	local llvm="$1" tree
	[ "$(git -C "$llvm" rev-parse HEAD)" = "$EFFECTIVE_MOTOR_LLVM_REV" ] ||
		toolchain_die "LLVM HEAD changed while it was being consumed" || return
	tree="$(toolchain_worktree_digest "$llvm" llvm)" || return
	[ "$tree" = "$MOTOR_LLVM_TREE_STATE" ] ||
		toolchain_die "LLVM worktree changed while it was being consumed"
}

toolchain_build_standalone_llvm() {
	local llvm="$1" root="$2" cmake="${MOTOR_CMAKE_COMMAND:-cmake}"
	local ninja="${MOTOR_NINJA_COMMAND:-ninja}" lock manifest temporary
	STANDALONE_LLVM_KEY="$(toolchain_standalone_llvm_key)" || return
	STANDALONE_LLVM_BUILD="$root/standalone-llvm/$STANDALONE_LLVM_KEY"
	STANDALONE_LLVM_BIN="$STANDALONE_LLVM_BUILD/bin"
	lock="${STANDALONE_LLVM_BUILD}.building"
	if [ -e "$lock" ]; then
		toolchain_die "standalone LLVM has an active or abandoned producer lock: $lock"
		return 1
	fi
	if [ -d "$STANDALONE_LLVM_BUILD" ]; then
		toolchain_validate_standalone_llvm "$STANDALONE_LLVM_BUILD" || return
		TOOLCHAIN_LLVM_REUSED=true
		return 0
	fi
	mkdir -p "$(dirname "$STANDALONE_LLVM_BUILD")"
	if ! mkdir "$lock" 2>/dev/null; then
		toolchain_die "standalone LLVM has an active or abandoned producer lock: $lock"
		return 1
	fi
	TOOLCHAIN_LLVM_REUSED=false
	toolchain_verify_llvm_selection "$llvm" || return
	"$cmake" -S "$llvm/llvm" -B "$STANDALONE_LLVM_BUILD" -G Ninja \
		-DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON \
		-DLLVM_ENABLE_PROJECTS='clang;lld' -DLLVM_TARGETS_TO_BUILD=X86 \
		-DLLVM_INCLUDE_TESTS=OFF -DCMAKE_C_COMPILER=clang \
		-DCMAKE_CXX_COMPILER=clang++ || return
	"$ninja" -C "$STANDALONE_LLVM_BUILD" clang lld llvm-ar llvm-ranlib \
		llvm-nm llvm-readelf llvm-strip llvm-objcopy llvm-config || return
	toolchain_verify_llvm_selection "$llvm" || return
	manifest="$STANDALONE_LLVM_BUILD/MOTOR-LLVM-MANIFEST"
	temporary="$(mktemp "${manifest}.tmp.XXXXXX")"
	toolchain_render_standalone_llvm_manifest > "$temporary"
	chmod 0444 "$temporary"
	mv "$temporary" "$manifest"
	toolchain_validate_standalone_llvm "$STANDALONE_LLVM_BUILD" || return
	rmdir "$lock"
}
