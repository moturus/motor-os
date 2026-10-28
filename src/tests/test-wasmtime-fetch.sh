#!/usr/bin/env bash
# Exercise the producer's fetch with an empty cache and a file-only registry.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/build-motor-os.sh"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
fail() { echo "test-wasmtime-fetch: $*" >&2; exit 1; }
export RUSTUP_TOOLCHAIN="$TOOLCHAIN"
export CARGO_HOME="$temporary/cargo-home"
export CARGO_TARGET_DIR="$temporary/target"
EXTERNAL_SOURCES="$temporary/external-sources"
SYSROOT="$temporary/sysroot"
ASSEMBLY_ROOT="$temporary/assembly"
ASSEMBLY_BUILD_ROOT="$temporary/build"
WASMTIME_IMG="$temporary/image"
WASMTIME_TESTS="$temporary/tests"
wasmtime_source_manifest() { echo fixture; }
registry="$temporary/registry"
runtime="$EXTERNAL_SOURCES/wasmtime"
mkdir -p "$registry/fe/tc" "$temporary/downloads" "$CARGO_HOME" \
	"$runtime/src" "$runtime/motor-tests/src" "$EXTERNAL_SOURCES/bridge/src"
for version in 1.0.0 2.0.0; do
	mkdir -p "$temporary/fetch-leaf-$version/src"
	cat > "$temporary/fetch-leaf-$version/Cargo.toml" <<EOF
[package]
name = "fetch-leaf"
version = "$version"
edition = "2024"
EOF
	: > "$temporary/fetch-leaf-$version/src/lib.rs"
	tar -czf "$temporary/downloads/fetch-leaf-$version.crate" -C "$temporary" "fetch-leaf-$version"
	checksum="$(sha256sum "$temporary/downloads/fetch-leaf-$version.crate" | cut -d' ' -f1)"
	printf '{"name":"fetch-leaf","vers":"%s","deps":[],"cksum":"%s","features":{},"yanked":false}\n' \
		"$version" "$checksum" >> "$registry/fe/tc/fetch-leaf"
done
printf '{"dl":"file://%s/downloads/{crate}-{version}.crate"}\n' "$temporary" > "$registry/config.json"
git -C "$registry" init -q
git -C "$registry" add .
git -C "$registry" -c user.name=Test -c user.email=test@example.com commit -qm fixture
cat > "$CARGO_HOME/config.toml" <<EOF
[source.crates-io]
replace-with = "fixture"
[source.fixture]
registry = "file://$registry"
EOF
cat > "$runtime/Cargo.toml" <<'EOF'
[package]
name = "fetch-runtime"
version = "1.0.0"
edition = "2024"
[workspace]
[target.'cfg(target_os = "motor")'.dependencies]
fetch-bridge = { path = "../bridge" }
EOF
cat > "$EXTERNAL_SOURCES/bridge/Cargo.toml" <<'EOF'
[package]
name = "fetch-bridge"
version = "1.0.0"
edition = "2024"
[workspace]
[target.'cfg(not(target_os = "motor"))'.dependencies]
fetch-leaf = "=1.0.0"
EOF
: > "$runtime/src/lib.rs"
: > "$EXTERNAL_SOURCES/bridge/src/lib.rs"
# An independent lockfile can select a version absent from the main workspace.
cat > "$runtime/motor-tests/Cargo.toml" <<'EOF'
[package]
name = "fetch-policy-tests"
version = "1.0.0"
edition = "2024"
[workspace]
[dependencies]
fetch-leaf = "=2.0.0"
EOF
: > "$runtime/motor-tests/src/lib.rs"
cat > "$EXTERNAL_SOURCES/wasmtime/motor-build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$CARGO_NET_OFFLINE" = true ]
manifest=Cargo.toml
[ "$1" != tests ] || manifest=motor-tests/Cargo.toml
cargo build --locked --manifest-path "$manifest" --target x86_64-unknown-motor --lib
EOF
chmod +x "$EXTERNAL_SOURCES/wasmtime/motor-build.sh"
(
	cd "$runtime"
	cargo generate-lockfile
	cp Cargo.lock "$temporary/original.lock"
	cargo generate-lockfile --manifest-path motor-tests/Cargo.toml
	cp motor-tests/Cargo.lock "$temporary/original-tests.lock"
)
# The registry leaf is still uncached. Separate target walks miss this host
# dependency below the Motor-only bridge; the producer must fetch it first.
# Run the real producer fetch and offline build; image staging is unrelated.
install() { :; }
sha256sum() { cat > /dev/null; }
build_wasmtime_fixtures() {
	(cd "$runtime" && CARGO_NET_OFFLINE=true ./motor-build.sh tests)
}
build_wasmtime
cmp "$runtime/Cargo.lock" "$temporary/original.lock" || fail "the producer changed the lockfile"
cmp "$runtime/motor-tests/Cargo.lock" "$temporary/original-tests.lock" ||
	fail "the producer changed the test lockfile"
echo "test-wasmtime-fetch PASS"
