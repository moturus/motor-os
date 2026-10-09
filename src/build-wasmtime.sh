#!/usr/bin/env bash
# Runtime-only Wasmtime add-on and its precompiled test fixtures, sourced by
# build-motor-os.sh after toolchain selection and after build-javy.sh, whose
# helpers and inputs it shares.

# Motor variants of upstream p2 socket programs, built from the fork.
WASMTIME_GUEST_PROGRAMS=(p2_tcp_bind p2_tcp_bind_listen_order p2_tcp_connect
	p2_tcp_sample_application p2_tcp_sockopts p2_tcp_states p2_tcp_streams p2_udp_bind
	p2_udp_connect p2_udp_sample_application p2_udp_send_to_closed_receiver
	p2_udp_sockopts p2_udp_states)
# Core-module fixtures in the fork's motor-runtime/fixtures.
WASMTIME_CORE_FIXTURES=(lifecycle limits-elements limits-memories limits-tables memory-grow
	memory-too-large)

# Fixtures are precompiled by a host compiler built from the runtime's own
# sources, so their engine version and configuration always match it.
build_wasmtime_fixtures() {
	local root="$MOTORH/wasmtime" build="$ASSEMBLY_BUILD_ROOT/wasmtime"
	local out="$WASMTIME_IMG/devtools/cfg/wasmtime/fixtures"
	local plugin="$ASSEMBLY_BUILD_ROOT/javy-inputs/plugin.wasm"
	local javy_linux="$ASSEMBLY_BUILD_ROOT/javy-inputs/javy-linux"
	local typescript="$ASSEMBLY_IMAGE_ROOT/javy/devtools/cfg/javy/typescript-workload.js"
	# Upstream Javy 9.1.0 for Linux compiles the TypeScript fixture.
	printf '%s  %s\n%s  %s\n%s  %s\n' "$JAVY_PLUGIN_SHA" "$plugin" "$JAVY_LINUX_SHA" "$javy_linux" \
		"$JAVY_TYPESCRIPT_SHA" "$typescript" |
		sha256sum --quiet -c - || die "the Wasmtime fixtures need the Javy add-on's inputs"
	mkdir -p "$out"
	(
		cd "$root"
		CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$build/host" cargo build --locked --release \
			--manifest-path motor-runtime/Cargo.toml --features compile --bin compile \
			-j "$(wasm_addon_jobs)"
		export RUSTUP_TOOLCHAIN="$WASM_GUEST_TOOLCHAIN"
		cargo fetch --locked --target wasm32-wasip2
		local bins=() program
		for program in "${WASMTIME_GUEST_PROGRAMS[@]}"; do bins+=(--bin "$program"); done
		CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$build/guests" cargo build --locked --release \
			--target wasm32-wasip2 -p test-programs --features motor "${bins[@]}"
	)
	local compile="$build/host/release/compile" name
	rm -f "$out"/*.cwasm "$build/typescript.wasm"
	for name in "${WASMTIME_CORE_FIXTURES[@]}"; do
		"$compile" pulley64 core "$root/motor-runtime/fixtures/$name.wat" "$out/$name.cwasm"
	done
	"$compile" pulley64 core "$root/motor-runtime/fixtures/lifecycle.wat" \
		"$out/lifecycle-epoch.cwasm" --epoch
	# Native code for a Pulley runtime: the runtime must refuse it.
	"$compile" x86_64-unknown-motor core "$root/motor-runtime/fixtures/lifecycle.wat" \
		"$out/lifecycle-native.cwasm"
	for name in "${WASMTIME_GUEST_PROGRAMS[@]}"; do
		"$compile" pulley64 component "$build/guests/wasm32-wasip2/release/$name.wasm" \
			"$out/$name.cwasm"
	done
	"$javy_linux" build "$typescript" -C plugin="$plugin" -C deterministic \
		-o "$build/typescript.wasm"
	"$compile" pulley64 core "$build/typescript.wasm" "$out/typescript.cwasm"
}

build_wasmtime() {
	# The orchestrator's selection (managed or authoring) overrides Wasmtime's
	# own rust-toolchain.toml for the fetch and is inherited by motor-build.sh.
	[ -n "${RUSTUP_TOOLCHAIN:-}" ] || die "no Rust toolchain was selected for Wasmtime"
	(
		cd "$MOTORH/wasmtime/motor-runtime"
		cargo fetch --locked --target x86_64-unknown-motor
		cargo fetch --locked --target x86_64-unknown-linux-gnu
		cd ..
		CARGO_NET_OFFLINE=true MOTOR_BUILD_DIR="$ASSEMBLY_BUILD_ROOT/wasmtime" \
			JOBS="$(wasm_addon_jobs)" ./motor-build.sh runtime
	)
	local cfg="$WASMTIME_IMG/devtools/cfg/wasmtime"
	mkdir -p "$WASMTIME_IMG/devtools/bin" "$cfg"
	install -m 755 "$ASSEMBLY_BUILD_ROOT/wasmtime/runtime/x86_64-unknown-motor/release/wasmtime-rt" \
		"$WASMTIME_IMG/devtools/bin/wasmtime-rt"
	build_wasmtime_fixtures
	printf '%s\n' "$WASMTIME_SOURCE_MANIFEST" > "$cfg/sources.txt"
	(cd "$WASMTIME_IMG" && sha256sum devtools/bin/wasmtime-rt devtools/cfg/wasmtime/sources.txt \
		devtools/cfg/wasmtime/fixtures/* > "$cfg/SHA256SUMS")
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
	WASMTIME_SOURCE_MANIFEST="$(
		wasm_source_manifest "${WASMTIME_SOURCES[*]}" src/build-wasmtime.sh
		printf 'guest-toolchain=%s\n' "$(RUSTUP_TOOLCHAIN="$WASM_GUEST_TOOLCHAIN" rustc --version)"
		printf 'plugin=%s\ntypescript=%s\njavy-linux=%s\n' "$JAVY_PLUGIN_SHA" \
			"$JAVY_TYPESCRIPT_SHA" "$JAVY_LINUX_SHA"
	)"
	source="$(printf '%s\n' "$WASMTIME_SOURCE_MANIFEST" | sha256sum | cut -d' ' -f1)"
	# All outputs must still match, not just the executable used by ensure_addon.
	if ! (cd "$WASMTIME_IMG" && sha256sum --status -c devtools/cfg/wasmtime/SHA256SUMS) 2>/dev/null; then
		rm -f "$ASSEMBLY_ROOT/ADDON-wasmtime"
	fi
	ensure_addon wasmtime "$source" "$WASMTIME_IMG" devtools/bin/wasmtime-rt build_wasmtime
}
