#!/usr/bin/env bash
# Exercise the producer's fetch with an empty cache and a file-only registry.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/build-motor-os.sh"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
fail() { echo "test-wasm-addon-fetch: $*" >&2; exit 1; }
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-$(sed -n 's/^channel = "\(.*\)"/\1/p' "$ROOT_DIR/rust-toolchain.toml")}"
export CARGO_HOME="$temporary/cargo-home"
export CARGO_TARGET_DIR="$temporary/target"
MOTORH="$temporary/motorh"
ASSEMBLY_BUILD_ROOT="$temporary/build"
WASMTIME_IMG="$temporary/image"
WASMTIME_TESTS="$temporary/tests"
WASMTIME_SOURCE_MANIFEST=fixture
registry="$temporary/registry"
runtime="$MOTORH/wasmtime/motor-runtime"
mkdir -p "$registry/fe/tc" "$temporary/downloads" "$CARGO_HOME" \
	"$runtime/src" "$MOTORH/bridge/src" "$temporary/fetch-leaf-1.0.0/src"
cat > "$temporary/fetch-leaf-1.0.0/Cargo.toml" <<'EOF'
[package]
name = "fetch-leaf"
version = "1.0.0"
edition = "2024"
EOF
: > "$temporary/fetch-leaf-1.0.0/src/lib.rs"
tar -czf "$temporary/downloads/fetch-leaf-1.0.0.crate" -C "$temporary" fetch-leaf-1.0.0
checksum="$(sha256sum "$temporary/downloads/fetch-leaf-1.0.0.crate" | cut -d' ' -f1)"
printf '{"dl":"file://%s/downloads/{crate}-{version}.crate"}\n' "$temporary" > "$registry/config.json"
printf '{"name":"fetch-leaf","vers":"1.0.0","deps":[],"cksum":"%s","features":{},"yanked":false}\n' \
	"$checksum" > "$registry/fe/tc/fetch-leaf"
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
fetch-bridge = { path = "../../bridge" }
EOF
cat > "$MOTORH/bridge/Cargo.toml" <<'EOF'
[package]
name = "fetch-bridge"
version = "1.0.0"
edition = "2024"
[workspace]
[target.'cfg(not(target_os = "motor"))'.dependencies]
fetch-leaf = "=1.0.0"
EOF
: > "$runtime/src/lib.rs"
: > "$MOTORH/bridge/src/lib.rs"
cat > "$MOTORH/wasmtime/motor-build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$CARGO_NET_OFFLINE" = true ]
cargo build --locked --manifest-path motor-runtime/Cargo.toml --target x86_64-unknown-motor --lib
EOF
chmod +x "$MOTORH/wasmtime/motor-build.sh"
(
	cd "$runtime"
	cargo generate-lockfile
	cp Cargo.lock "$temporary/original.lock"
)
# The registry leaf is still uncached. Separate target walks miss this host
# dependency below the Motor-only bridge; the producer must fetch it first.
# Run the real producer fetch and offline build; image staging is unrelated.
install() { :; }
sha256sum() { cat > /dev/null; }
build_wasmtime_fixtures() { :; }
build_wasmtime
cmp "$runtime/Cargo.lock" "$temporary/original.lock" || fail "the producer changed the lockfile"
echo "test-wasm-addon-fetch PASS"
