#!/usr/bin/env bash
# Run the direct packaged server in the already booted developer VM.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
manifest="$ROOT_DIR/src/tests/rust-analyzer-smoke/Cargo.toml"
target="$ROOT_DIR/src/tests/rust-analyzer-smoke/target"
evidence_parent="$(mktemp -d /tmp/motor-ra-native.XXXXXX)"
cargo build --manifest-path "$manifest" --target-dir "$target" --release --locked --offline
cargo build --manifest-path "$manifest" --target-dir "$target" --release --locked --offline \
  --target x86_64-unknown-motor --bin rust-analyzer-resource-sampler
"$target/release/rust-analyzer-smoke" --native "$evidence_parent/case" \
  "$target/x86_64-unknown-motor/release/rust-analyzer-resource-sampler"
echo "test-rust-analyzer-native PASS; evidence=$evidence_parent/case"
