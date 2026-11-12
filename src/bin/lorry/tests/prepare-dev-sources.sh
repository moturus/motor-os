#!/usr/bin/env bash
# Supply the developer-source gate from local Cargo/Git caches, without sockets.
set -euo pipefail
export CARGO_NET_OFFLINE=true
[ "$#" -eq 1 ] || { echo "usage: prepare-dev-sources.sh OUTPUT" >&2; exit 2; }
OUTPUT="$(realpath -m "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
LORRY_DIR="$SCRIPT_DIR/.."
source "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain
mkdir -p "$OUTPUT/workspace" "$OUTPUT/home/.config/lorry" "$OUTPUT/payload"

RUSTC="$LORRY_TEST_RUSTC" "$LORRY_TEST_CARGO" build \
    --manifest-path "$LORRY_DIR/Cargo.toml" --release --locked --offline
"$LORRY_TEST_RUSTC" --edition=2024 -D warnings -O \
    "$SCRIPT_DIR/helpers/cache-curl.rs" -o "$OUTPUT/cache-curl"
"$OUTPUT/cache-curl" prepare "${CARGO_HOME:-$HOME/.cargo}" "$OUTPUT/crates-io" \
    "$ROOT_DIR/src/bin/red/Cargo.lock" "$LORRY_DIR/Cargo.lock"

# Materialize the locked Git tree on Linux; the guest transport only needs
# registry records and archives. Keep the guest's ordinary registry acquisition.
git -C "$ROOT_DIR" ls-files -z -- src/bin/red src/bin/lorry src/sys/lib |
    tar -C "$ROOT_DIR" --null -T - -cf - | tar -C "$OUTPUT/workspace" -xf -
cat >"$OUTPUT/home/.config/lorry/lorry.toml" <<EOF
config-version = 1
use-cargo-registry = false
[repositories]
user = "$OUTPUT/repository"
[network]
curl = "$OUTPUT/crates-io/curl"
[policy]
default = "allow"
EOF
awk '
  /^\[policy.limits\]/ { limits = 1; print; next }
  limits && /^\[/ { exit }
  limits { print }
' "$ROOT_DIR/img_files/motor-os-dev/user/cfg/lorry.toml" >>"$OUTPUT/home/.config/lorry/lorry.toml"
for package in red lorry; do
    (cd "$OUTPUT/workspace/src/bin/$package" && \
        HOME="$OUTPUT/home" RUSTC="$LORRY_TEST_RUSTC" \
        "$LORRY_DIR/target/release/lorry" fetch --locked)
done
tar -C "$OUTPUT/workspace/src/bin" -cf "$OUTPUT/payload/git.tar" \
    red/.lorry/vendor/git lorry/.lorry/vendor/git
mv "$OUTPUT/crates-io/index" "$OUTPUT/crates-io/archives" "$OUTPUT/payload/"
"$LORRY_TEST_RUSTC" --edition=2024 -D warnings -O --target x86_64-unknown-motor \
    -Clink-self-contained=no -Cdefault-linker-libraries=yes \
    -Clinker="$LORRY_MOTOR_LINKER" \
    "$SCRIPT_DIR/helpers/cache-curl.rs" -o "$OUTPUT/payload/curl"
tar -C "$OUTPUT/payload" -cf "$OUTPUT/dependencies.tar" index archives curl git.tar
