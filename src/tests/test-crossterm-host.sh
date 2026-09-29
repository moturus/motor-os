#!/bin/bash
#
# test-crossterm-host.sh -- the crossterm revision Rush ships, tested on this host.
#
# Rush's lockfile pins crossterm (a moturus fork) to one revision. Its library
# tests, the line-end reads Rush relies on among them, run on a copy of exactly
# that source, since Cargo's checkout is not ours to write to: once with each
# Unix event source. Rush's pty tests then run over the source that the
# ordinary Rush pass does not use.
#
# Testing is offline. --prepare, which full-test-prepare.sh runs, is the one
# step that fetches, and it builds the tests ahead of the suite's clock.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
RUSH_DIR="$ROOT_DIR/src/bin/rush"

profile=debug
profile_args=()
prepare=0
for arg in "$@"; do
  case "$arg" in
    --release) profile=release; profile_args=(--release) ;;
    --prepare) prepare=1 ;;
    *) echo "usage: $0 [--release] [--prepare]" >&2; exit 2 ;;
  esac
done

network_args=(--offline)
test_args=()
if [ "$prepare" = 1 ]; then
  network_args=()
  test_args=(--no-run)
  cargo fetch --locked --manifest-path "$RUSH_DIR/Cargo.toml"
fi

source_dir="$(cargo metadata --locked --offline --format-version 1 \
  --manifest-path "$RUSH_DIR/Cargo.toml" |
  python3 -c 'import json, os, sys
[path] = [p["manifest_path"] for p in json.load(sys.stdin)["packages"]
          if p["name"] == "crossterm"]
print(os.path.dirname(path))')"

copy="$(mktemp -d /tmp/crossterm-host.XXXXXX)"
trap 'rm -rf "$copy"' EXIT
cp -R "$source_dir/." "$copy"
chmod -R u+w "$copy"

targets="$ROOT_DIR/build/crossterm-host/$profile"
for features in events events,use-dev-tty; do
  (cd "$copy" && CARGO_TARGET_DIR="$targets/$features" cargo test --quiet \
    --locked "${network_args[@]}" "${profile_args[@]}" --lib \
    --no-default-features --features "$features" "${test_args[@]}")
done

(cd "$RUSH_DIR" && CARGO_TARGET_DIR="$targets/rush-dev-tty" cargo test --quiet \
  --locked "${network_args[@]}" "${profile_args[@]}" --features dev-tty \
  --test phase8 "${test_args[@]}")
