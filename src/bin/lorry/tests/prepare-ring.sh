#!/usr/bin/env bash
# A native C/archiver fixture, using only the host's existing Cargo/Git cache.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: prepare-ring.sh OUTPUT LORRY" >&2; exit 2; }
DESTINATION="$(realpath -m "$1")"
LORRY="$(realpath "$2")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
CARGO_CACHE="${CARGO_HOME:-$HOME/.cargo}"
REVISION="$(sed -n 's|^source = "git+https://github.com/moturus/ring.git[^#]*#\([^"]*\)"$|\1|p' "$ROOT_DIR/src/bin/russhd/Cargo.lock")"
[ -n "$REVISION" ] || { echo "ring revision is absent" >&2; exit 1; }
RING_SOURCE=""
for candidate in "$CARGO_CACHE"/git/checkouts/ring-*/*; do
    if [ "$(git -C "$candidate" rev-parse HEAD 2>/dev/null)" = "$REVISION" ]; then
        RING_SOURCE="$candidate"
        break
    fi
done
[ -n "$RING_SOURCE" ] || { echo "ring $REVISION is absent from Cargo's local cache" >&2; exit 1; }
mkdir -p "$DESTINATION/ring-fixture/src" "$DESTINATION/ring-fixture/ring"
git -C "$RING_SOURCE" archive "$REVISION" | tar -xf - -C "$DESTINATION/ring-fixture/ring"
cat >"$DESTINATION/ring-fixture/Cargo.toml" <<'EOF'
[package]
name = "lorry-ring-fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
ring = { path = "ring" }
getrandom = { version = "=0.2.17", features = ["rdrand"] }
EOF
cat >"$DESTINATION/ring-fixture/src/main.rs" <<'EOF'
fn main() {
    let digest = ring::digest::digest(&ring::digest::SHA256, b"abc");
    assert_eq!(digest.as_ref(), &[
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ]);
    println!("ring native compiler and archiver PASS");
}
EOF
"$LORRY_TEST_CARGO" generate-lockfile --offline --manifest-path "$DESTINATION/ring-fixture/Cargo.toml"
"$LORRY_TEST_RUSTC" --edition=2024 -D warnings -O "$SCRIPT_DIR/helpers/cache-curl.rs" -o "$DESTINATION/cache-curl"
"$DESTINATION/cache-curl" prepare "$CARGO_CACHE" "$DESTINATION/crates-io" "$DESTINATION/ring-fixture/Cargo.lock"
mkdir -p "$DESTINATION/home/.config/lorry"
cat >"$DESTINATION/home/.config/lorry/lorry.toml" <<EOF
config-version = 1
[repositories]
user = "$DESTINATION/ring-repository"
[network]
curl = "$DESTINATION/crates-io/curl"
[policy]
default = "allow"
EOF
(cd "$DESTINATION/ring-fixture" && env HOME="$DESTINATION/home" RUSTC="$LORRY_TEST_RUSTC" "$LORRY" fetch --locked)
