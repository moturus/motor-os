#!/usr/bin/env bash
# Javy/Wasmi add-on, sourced by build-motor-os.sh after toolchain selection.

javy_download() {
	local url="$1" digest="$2" output="$3"
	if [ ! -f "$output" ]; then
		curl --fail --location "$url" -o "$output.part"
		printf '%s  %s\n' "$digest" "$output.part" | sha256sum -c -
		mv "$output.part" "$output"
	fi
	printf '%s  %s\n' "$digest" "$output" | sha256sum -c -
}

javy_source_manifest() (
	cd "$MOTOR"
	printf 'assembly=%s\n' "${ASSEMBLY_ROOT##*/}"
	printf 'rustc=%s\n' "$(rustc --version)"
	printf 'target=x86_64-unknown-motor\nprofile=release\n'
	local spec repo branch
	for spec in "${JAVY_SOURCES[@]}"; do
		repo=${spec%%:*}; branch=${spec#*:}
		printf '%s=https://github.com/moturus/%s.git %s %s\n' \
			"$repo" "$repo" "$branch" "$(git -C "$MOTORH/$repo" rev-parse HEAD)"
	done
	sha256sum rust-toolchain.toml src/build-javy.sh src/tests/javy-smoke/fixtures/typescript-workload.js
	# Include local native-library edits as well as their committed contents.
	git ls-files -z --cached --others --exclude-standard src/sys/lib |
		LC_ALL=C sort -zu | xargs -0 sha256sum | sha256sum
	printf 'plugin=%s\ntypescript=%s\n' "$JAVY_PLUGIN_SHA" "$JAVY_TYPESCRIPT_SHA"
)

# Binaryen's C++ units are memory-hungry: allow 1.5 GiB per job and bound by
# CPUs. The fork's own default is two jobs.
javy_jobs() {
	local cpus memory
	cpus="$(nproc)"
	memory="$(awk '/^MemAvailable:/ { print int($2 / 1572864) }' /proc/meminfo)"
	[ "${memory:-0}" -ge 2 ] || memory=2
	[ "$memory" -le "$cpus" ] && echo "$memory" || echo "$cpus"
}

build_javy() {
	local inputs="$ASSEMBLY_BUILD_ROOT/javy-inputs" cfg="$JAVY_IMG/devtools/cfg/javy"
	mkdir -p "$inputs"
	javy_download https://github.com/bytecodealliance/javy/releases/download/v9.1.0/plugin.wasm.gz \
		dc237a6fb9c7e58423456a12fc3c4e7a97d9d1eeb91b89ca73db76b78ae95e83 "$inputs/plugin.wasm.gz"
	gzip -dc "$inputs/plugin.wasm.gz" > "$inputs/plugin.wasm"
	printf '%s  %s\n' "$JAVY_PLUGIN_SHA" "$inputs/plugin.wasm" | sha256sum -c -
	javy_download https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz \
		10e108c9cf7d5f2879053dff18515fb405abf2ccef63eaaf017d9c571687a1d3 "$inputs/typescript.tgz"
	# Fetch with the Motor toolchain that motor-build.sh selects, not Javy's own
	# rust-toolchain.toml, so one Cargo resolves and builds the lockfile.
	(
		cd "$MOTORH/javy"
		RUSTUP_TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$MOTOR/rust-toolchain.toml")"
		[ -n "$RUSTUP_TOOLCHAIN" ] || die "no Rust channel in $MOTOR/rust-toolchain.toml"
		export RUSTUP_TOOLCHAIN
		cargo fetch --locked --target x86_64-unknown-motor
		CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/javy" JOBS="$(javy_jobs)" \
			JAVY_DEFAULT_PLUGIN="$inputs/plugin.wasm" ./motor-build.sh
	)
	mkdir -p "$JAVY_IMG/devtools/bin" "$cfg"
	local tool
	for tool in javy wasmi; do
		install -m 755 "$ASSEMBLY_BUILD_ROOT/javy/x86_64-unknown-motor/release/$tool" \
			"$JAVY_IMG/devtools/bin/$tool"
	done
	install -m 644 "$inputs/plugin.wasm" "$cfg/plugin.wasm"
	tar -xOf "$inputs/typescript.tgz" package/lib/typescript.js > "$cfg/typescript-workload.js"
	cat "$MOTOR/src/tests/javy-smoke/fixtures/typescript-workload.js" >> "$cfg/typescript-workload.js"
	printf '%s  %s\n' "$JAVY_TYPESCRIPT_SHA" "$cfg/typescript-workload.js" | sha256sum -c -
	tar -xOf "$inputs/typescript.tgz" package/LICENSE.txt > "$cfg/typescript-LICENSE.txt"
	tar -xOf "$inputs/typescript.tgz" package/ThirdPartyNoticeText.txt > "$cfg/typescript-NOTICES.txt"
	printf '%s\n' "$JAVY_SOURCE_MANIFEST" > "$cfg/sources.txt"
	(cd "$JAVY_IMG" && sha256sum devtools/bin/{javy,wasmi} devtools/cfg/javy/* > "$cfg/SHA256SUMS")
}

build_javy_addon() {
	JAVY_SOURCES=(javy:motor-9.1.0 wasmi:motor-1.1.0 wasmtime:motor-48.0.1)
	JAVY_PLUGIN_SHA=180230f9346dc4b7d7139791280c9f4da09b2292eef751a3d35ae80154d88350
	JAVY_TYPESCRIPT_SHA=4969f6546b830e751b6797be028accd242fd24e6e506661c51ddcd16b2646d68
	JAVY_IMG="$ASSEMBLY_IMAGE_ROOT/javy"
	[ "$(readlink -f "$MOTORH/motor-os")" = "$MOTOR" ] ||
		die "Javy's sibling motor-os path must resolve to this checkout: $MOTORH/motor-os"
	local spec repo branch source
	for spec in "${JAVY_SOURCES[@]}"; do
		repo=${spec%%:*}; branch=${spec#*:}
		update_addon_source "$repo" "$MOTORH/$repo" "https://github.com/moturus/$repo.git" "$branch"
	done
	JAVY_SOURCE_MANIFEST="$(javy_source_manifest)"
	source="$(printf '%s\n' "$JAVY_SOURCE_MANIFEST" | sha256sum | cut -d' ' -f1)"
	# All outputs must still match, not just the executable used by ensure_addon.
	if ! (cd "$JAVY_IMG" && sha256sum --status -c devtools/cfg/javy/SHA256SUMS) 2>/dev/null; then
		rm -f "$ASSEMBLY_ROOT/ADDON-javy"
	fi
	ensure_addon javy "$source" "$JAVY_IMG" devtools/bin/javy build_javy
}
