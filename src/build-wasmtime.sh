#!/usr/bin/env bash
# Runtime-only Wasmtime add-on, sourced by build-motor-os.sh after toolchain
# selection and after build-javy.sh, whose helpers it shares.

build_wasmtime() {
	# The orchestrator's selection (managed or authoring) overrides Wasmtime's
	# own rust-toolchain.toml for the fetch and is inherited by motor-build.sh.
	[ -n "${RUSTUP_TOOLCHAIN:-}" ] || die "no Rust toolchain was selected for Wasmtime"
	(
		cd "$MOTORH/wasmtime/motor-runtime"
		cargo fetch --locked --target x86_64-unknown-motor
		cd ..
		CARGO_NET_OFFLINE=true MOTOR_BUILD_DIR="$ASSEMBLY_BUILD_ROOT/wasmtime" \
			JOBS="$(wasm_addon_jobs)" ./motor-build.sh runtime
	)
	local cfg="$WASMTIME_IMG/devtools/cfg/wasmtime"
	mkdir -p "$WASMTIME_IMG/devtools/bin" "$cfg"
	install -m 755 "$ASSEMBLY_BUILD_ROOT/wasmtime/runtime/x86_64-unknown-motor/release/wasmtime-rt" \
		"$WASMTIME_IMG/devtools/bin/wasmtime-rt"
	printf '%s\n' "$WASMTIME_SOURCE_MANIFEST" > "$cfg/sources.txt"
	(cd "$WASMTIME_IMG" && sha256sum devtools/bin/wasmtime-rt devtools/cfg/wasmtime/sources.txt \
		> "$cfg/SHA256SUMS")
}

build_wasmtime_addon() {
	WASMTIME_SOURCES=(wasmtime:motor-48.0.1 target-lexicon:motor-0.13.5 tokio:motor-1.51.1 mio:motor-1.2.0)
	WASMTIME_IMG="$ASSEMBLY_IMAGE_ROOT/wasmtime"
	[ "$(readlink -f "$MOTORH/motor-os")" = "$MOTOR" ] ||
		die "Wasmtime's sibling motor-os path must resolve to this checkout: $MOTORH/motor-os"
	local spec repo branch source
	for spec in "${WASMTIME_SOURCES[@]}"; do
		repo=${spec%%:*}; branch=${spec#*:}
		update_addon_source "$repo" "$MOTORH/$repo" "https://github.com/moturus/$repo.git" "$branch"
	done
	WASMTIME_SOURCE_MANIFEST="$(wasm_source_manifest "${WASMTIME_SOURCES[*]}" src/build-wasmtime.sh)"
	source="$(printf '%s\n' "$WASMTIME_SOURCE_MANIFEST" | sha256sum | cut -d' ' -f1)"
	# All outputs must still match, not just the executable used by ensure_addon.
	if ! (cd "$WASMTIME_IMG" && sha256sum --status -c devtools/cfg/wasmtime/SHA256SUMS) 2>/dev/null; then
		rm -f "$ASSEMBLY_ROOT/ADDON-wasmtime"
	fi
	ensure_addon wasmtime "$source" "$WASMTIME_IMG" devtools/bin/wasmtime-rt build_wasmtime
}
