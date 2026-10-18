#!/usr/bin/env bash

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-rust-analyzer.sh"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
fail() { echo "test-toolchain-rust-analyzer-fetch: $*" >&2; exit 1; }

cargo="$(rustup which cargo)"
rustc="$(rustup which rustc)"
prefix="$temporary/prefix"
rust="$temporary/rust"
registry="$temporary/registry"
export CARGO_HOME="$temporary/cargo"
mkdir -p "$prefix/bin" "$CARGO_HOME" "$registry/index/ho/st" "$rust/src/tools"
ln -s "$cargo" "$prefix/bin/cargo"
ln -s "$rustc" "$prefix/bin/rustc"
cat > "$CARGO_HOME/config.toml" <<EOF
[net]
offline = true
[source.crates-io]
replace-with = "fixture"
[source.fixture]
local-registry = "$registry"
EOF

for name in rust-analyzer url inventory host-only; do
  directory="$temporary/$name-1.0.0"
  mkdir -p "$directory/src"
  printf '[package]\nname = "%s"\nversion = "1.0.0"\nedition = "2021"\n' "$name" \
    > "$directory/Cargo.toml"
  printf '#![no_std]\n' > "$directory/src/lib.rs"
done
tar -czf "$registry/host-only-1.0.0.crate" -C "$temporary" host-only-1.0.0
checksum="$(sha256sum "$registry/host-only-1.0.0.crate" | awk '{print $1}')"
printf '{"name":"host-only","vers":"1.0.0","deps":[],"cksum":"%s","features":{},"yanked":false}\n' \
  "$checksum" > "$registry/index/ho/st/host-only"

mv "$temporary/rust-analyzer-1.0.0" "$rust/src/tools/rust-analyzer"
workspace="$rust/src/tools/rust-analyzer"
cat >> "$workspace/Cargo.toml" <<'EOF'

[target.'cfg(target_os = "linux")'.dependencies]
host-only = "=1.0.0"
EOF
RUST_ANALYZER_URL_SOURCE="$temporary/url-1.0.0"
RUST_ANALYZER_INVENTORY_SOURCE="$temporary/inventory-1.0.0"
RUST_ANALYZER_CARGO_CONFIG="$temporary/patches.toml"
: > "$RUST_ANALYZER_CARGO_CONFIG"
for directory in "$workspace" "$RUST_ANALYZER_URL_SOURCE" "$RUST_ANALYZER_INVENTORY_SOURCE"; do
  RUSTC="$rustc" "$cargo" generate-lockfile --offline --manifest-path "$directory/Cargo.toml"
done
cp "$workspace/Cargo.lock" "$temporary/expected.lock"
toolchain_postbuild_locks_unchanged() {
  cmp "$workspace/Cargo.lock" "$temporary/expected.lock" || fail 'fetch changed the lockfile'
}

# Cargo's cross-build resolver also requests Linux sources. Verify that the
# acquisition step populated the empty cache before starting the offline build.
toolchain_fetch_rust_analyzer "$rust" "$prefix"
host_manifests=("$CARGO_HOME"/registry/src/*/host-only-1.0.0/Cargo.toml)
[ "${#host_manifests[@]}" -eq 1 ] && [ -f "${host_manifests[0]}" ] ||
  fail 'fetch omitted the host-platform dependency from the cache'
RUSTC="$rustc" "$cargo" build --manifest-path "$workspace/Cargo.toml" \
  --offline --locked --target x86_64-unknown-motor --target-dir "$temporary/target"
cmp "$workspace/Cargo.lock" "$temporary/expected.lock" || fail 'build changed the lockfile'

echo 'test-toolchain-rust-analyzer-fetch PASS'
