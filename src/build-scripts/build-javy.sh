#!/usr/bin/env bash
# The Javy/Wasmi external source and helpers that Wasmtime's build shares,
# sourced by build-motor-os.sh after toolchain selection.

# Digests of the default plugin and the TypeScript workload; the Wasmtime build
# compiles the same inputs into its fixtures.
JAVY_PLUGIN_SHA=180230f9346dc4b7d7139791280c9f4da09b2292eef751a3d35ae80154d88350
JAVY_TYPESCRIPT_SHA=4969f6546b830e751b6797be028accd242fd24e6e506661c51ddcd16b2646d68
# Upstream Javy 9.1.0 for Linux. With the same plugin and flags its output
# equals Motor Javy's byte for byte, which javy-smoke checks.
JAVY_LINUX_GZ_SHA=a68b122d48eb3dfc1b801d4e14c39271fde3638243d3272d206e376ac9189e39
JAVY_LINUX_SHA=f6f12dc42ffcaa1c19244b1a332893d636d0d56d26e02089d94dc296b22fa719

javy_download() {
	local url="$1" digest="$2" output="$3"
	if [ ! -f "$output" ]; then
		curl --fail --location "$url" -o "$output.part"
		printf '%s  %s\n' "$digest" "$output.part" | sha256sum -c -
		mv "$output.part" "$output"
	fi
	printf '%s  %s\n' "$digest" "$output" | sha256sum -c -
}

# The provenance that the Javy and Wasmtime overlays record: the toolchain,
# each "repo:branch[:revision]" source in $1 at its checked-out commit with the
# git dependencies its lockfiles pin, and the checkout files given after it.
wasm_source_manifest() (
	local sources="$1" spec repo branch revision
	shift
	cd "$MOTOR"
	printf 'toolchain=%s\n' "$RUSTUP_TOOLCHAIN"
	printf 'rustc=%s\n' "$(rustc --version)"
	printf 'target=x86_64-unknown-motor\nprofile=release\n'
	for spec in $sources; do
		IFS=: read -r repo branch revision <<< "$spec"
		printf '%s=https://github.com/moturus/%s.git %s %s\n' \
			"$repo" "$repo" "$branch" "$(git -C "$EXTERNAL_SOURCES/$repo" rev-parse HEAD)"
		(cd "$EXTERNAL_SOURCES/$repo" && git ls-files -z '*Cargo.lock' |
			xargs -0 grep -h '^source = "git+' | LC_ALL=C sort -u | sed 's/^source = /  /')
	done
	sha256sum rust-toolchain.toml "$@"
)

javy_source_manifest() {
	local plugins
	mapfile -t plugins < <(cd "$MOTOR" && git ls-files --cached --others --exclude-standard \
		src/tests/javy-smoke/plugins | LC_ALL=C sort)
	wasm_source_manifest "${JAVY_SOURCES[*]}" src/build-scripts/build-javy.sh \
		src/tests/javy-smoke/fixtures/typescript-workload.js src/tests/javy-smoke/fixtures/hello.js \
		"${plugins[@]}"
	printf 'guest-toolchain=%s\n' "$(RUSTUP_TOOLCHAIN="$WASM_GUEST_TOOLCHAIN" rustc --version)"
	printf 'plugin=%s\ntypescript=%s\njavy-linux=%s\nwasi-sdk=%s\n' "$JAVY_PLUGIN_SHA" \
		"$JAVY_TYPESCRIPT_SHA" "$JAVY_LINUX_SHA" "$WASI_SDK_SHA"
}

# Binaryen's C++ units and fat-LTO links are memory-hungry: allow 1.5 GiB per
# job and bound by CPUs. The forks' own default is two jobs.
wasm_build_jobs() {
	local cpus memory
	cpus="$(nproc)"
	memory="$(awk '/^MemAvailable:/ { print int($2 / 1572864) }' /proc/meminfo)"
	[ "${memory:-0}" -ge 2 ] || memory=2
	[ "$memory" -le "$cpus" ] && echo "$memory" || echo "$cpus"
}

# Digests of what Linux Javy builds from javy-smoke's identity inputs, which
# that suite compiles on Motor with the same flags.
javy_linux_reference() {
	local inputs="$1" tests="$2" out="$ASSEMBLY_BUILD_ROOT/javy-linux-reference" mode
	javy_download https://github.com/bytecodealliance/javy/releases/download/v9.1.0/javy-x86_64-linux-v9.1.0.gz \
		"$JAVY_LINUX_GZ_SHA" "$inputs/javy-linux.gz"
	gzip -dc "$inputs/javy-linux.gz" > "$inputs/javy-linux"
	printf '%s  %s\n' "$JAVY_LINUX_SHA" "$inputs/javy-linux" | sha256sum -c -
	chmod 755 "$inputs/javy-linux"
	rm -rf "$out"
	mkdir -p "$out"
	for mode in compressed uncompressed omitted; do
		"$inputs/javy-linux" build "$MOTOR/src/tests/javy-smoke/fixtures/hello.js" \
			-C plugin="$inputs/plugin.wasm" -C deterministic -C source=$mode -o "$out/hello-$mode.wasm"
	done
	"$inputs/javy-linux" build "$tests/typescript-workload.js" -C plugin="$inputs/plugin.wasm" \
		-C deterministic -C source=compressed -o "$out/typescript-compressed.wasm"
	(cd "$out" && sha256sum hello-*.wasm typescript-compressed.wasm) > "$tests/linux-reference.txt"
}

# javy-smoke's custom plugins, raw: the suite initializes them on Motor.
build_javy_test_plugins() {
	local tests="$1" build="$ASSEMBLY_BUILD_ROOT/javy-plugins"
	[ -d "${WASI_SDK:-}" ] || die "the Javy test plugins need wasi-sdk"
	(
		cd "$MOTOR/src/tests/javy-smoke/plugins"
		export RUSTUP_TOOLCHAIN="$WASM_GUEST_TOOLCHAIN" WASI_SDK
		cargo fetch --locked
		CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$build" cargo build --locked --release \
			-p javy-smoke-plugin-p1 --target wasm32-wasip1
		CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$build" cargo build --locked --release \
			-p javy-smoke-plugin-p2 --target wasm32-wasip2
	)
	install -m 644 "$build/wasm32-wasip1/release/javy_smoke_plugin_p1.wasm" "$tests/plugin-p1.wasm"
	install -m 644 "$build/wasm32-wasip2/release/javy_smoke_plugin_p2.wasm" "$tests/plugin-p2.wasm"
}

build_javy() {
	local inputs="$ASSEMBLY_BUILD_ROOT/javy-inputs" data="$JAVY_IMG/devtools/javy" manifest
	manifest="$(javy_source_manifest)"
	mkdir -p "$inputs"
	javy_download https://github.com/bytecodealliance/javy/releases/download/v9.1.0/plugin.wasm.gz \
		dc237a6fb9c7e58423456a12fc3c4e7a97d9d1eeb91b89ca73db76b78ae95e83 "$inputs/plugin.wasm.gz"
	# Javy's build script rebuilds the CLI whenever this file is rewritten.
	[ -f "$inputs/plugin.wasm" ] || gzip -dc "$inputs/plugin.wasm.gz" > "$inputs/plugin.wasm"
	printf '%s  %s\n' "$JAVY_PLUGIN_SHA" "$inputs/plugin.wasm" | sha256sum -c -
	javy_download https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz \
		10e108c9cf7d5f2879053dff18515fb405abf2ccef63eaaf017d9c571687a1d3 "$inputs/typescript.tgz"
	# RUSTUP_TOOLCHAIN overrides Javy's own rust-toolchain.toml for the fetch
	# and is inherited by motor-build.sh.
	(
		cd "$EXTERNAL_SOURCES/javy"
		# Fetch the complete locked graph, including host build dependencies.
		cargo fetch --locked
		CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/javy" JOBS="$(wasm_build_jobs)" \
			MOTOR_SYSROOT="$SYSROOT" JAVY_DEFAULT_PLUGIN="$inputs/plugin.wasm" \
			./motor-build.sh
	)
	rm -rf "$JAVY_TESTS"
	mkdir -p "$JAVY_IMG/devtools/bin" "$data/plugins" "$JAVY_TESTS"
	local tool
	for tool in javy wasmi; do
		install -m 755 "$ASSEMBLY_BUILD_ROOT/javy/x86_64-unknown-motor/release/$tool" \
			"$JAVY_IMG/devtools/bin/$tool"
	done
	install -m 644 "$inputs/plugin.wasm" "$data/plugins/default.wasm"
	printf '%s\n' "$manifest" > "$data/sources.txt"
	(cd "$JAVY_IMG" && sha256sum devtools/bin/{javy,wasmi} devtools/javy/plugins/default.wasm \
		devtools/javy/sources.txt > "$data/SHA256SUMS")
	# Test inputs stay out of the images; test-wasm.sh uploads them.
	local ts="$JAVY_TESTS/typescript-workload.js"
	tar -xOf "$inputs/typescript.tgz" package/lib/typescript.js > "$ts"
	cat "$MOTOR/src/tests/javy-smoke/fixtures/typescript-workload.js" >> "$ts"
	printf '%s  %s\n' "$JAVY_TYPESCRIPT_SHA" "$ts" | sha256sum -c -
	tar -xOf "$inputs/typescript.tgz" package/LICENSE.txt > "$JAVY_TESTS/typescript-LICENSE.txt"
	tar -xOf "$inputs/typescript.tgz" package/ThirdPartyNoticeText.txt \
		> "$JAVY_TESTS/typescript-NOTICES.txt"
	javy_linux_reference "$inputs" "$JAVY_TESTS"
	build_javy_test_plugins "$JAVY_TESTS"
	(cd "$JAVY_TESTS" && sha256sum typescript-workload.js typescript-LICENSE.txt \
		typescript-NOTICES.txt linux-reference.txt plugin-p1.wasm plugin-p2.wasm > SHA256SUMS)
}
