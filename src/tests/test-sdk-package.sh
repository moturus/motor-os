#!/bin/bash
#
# test-sdk-package.sh -- moto-sdk as crates.io would ship it.
#
# Packaging leaves the src/sys workspace behind: path dependencies become
# registry ones, and the workspace's [patch] no longer applies. So this script
# packages moto-sdk, extracts the .crate under build/ and builds it on its own,
# against crates.io only: on Unix, where its tests run, and on Motor OS with
# std, with std and test-support, and with only core and alloc (as rt.vdso
# builds it). The Motor test binaries, the re-export check among them, only
# compile here; they run natively under full-test-dev.sh.
#
# sdk-package/Cargo.lock pins the build. Each direct dependency is locked at
# the lowest version the manifest allows, so the declared floors are what is
# tested. After moto-sdk's dependencies change, --update-lock writes a new
# lock; it needs the network.
#
# Testing is offline. --prepare, which full-test-prepare.sh runs, fetches and
# builds ahead of the suite's clock.

set -euo pipefail

WD="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$WD/../.." && pwd)"
LOCK="$WD/sdk-package/Cargo.lock"
OUT="$ROOT_DIR/build/sdk-package"
MOTOR=x86_64-unknown-motor

mode=test
profile_args=()
for arg in "$@"; do
  case "$arg" in
    --release) profile_args=(--release) ;;
    --prepare) mode=prepare ;;
    --update-lock) mode=update-lock ;;
    *) echo "usage: $0 [--release] [--prepare | --update-lock]" >&2; exit 2 ;;
  esac
done

fail() {
  echo "test-sdk-package: $*" >&2
  exit 1
}

network_args=(--offline)
[ "$mode" = test ] || network_args=()

# The .crate a publish would upload.
rm -rf "$OUT/crate" "$OUT"/.staging.*
mkdir -p "$OUT"
(cd "$ROOT_DIR/src/sys" && CARGO_TARGET_DIR="$OUT/crate" cargo package --quiet \
  --locked "${network_args[@]}" --no-verify --allow-dirty -p moto-sdk)
staging="$(mktemp -d "$OUT/.staging.XXXXXX")"
tar -xzf "$OUT"/crate/package/moto-sdk-*.crate -C "$staging" --strip-components=1 \
  --touch

if [ "$mode" = update-lock ]; then
  (cd "$staging" && cargo generate-lockfile --quiet -Zdirect-minimal-versions)
  cp "$staging/Cargo.lock" "$LOCK"
  rm -rf "$staging"
  echo "wrote $LOCK"
  exit 0
fi

# Cargo decides freshness by file dates, but stamps every packaged file with
# one fixed date. So the files are dated at extraction instead, and each
# distinct content keeps its directory: unchanged sources keep their dates,
# and changed ones postdate every earlier build.
cp "$LOCK" "$staging/Cargo.lock"
key="$(cd "$staging" && find . -type f ! -name .cargo_vcs_info.json -print0 |
  sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)"
SOURCE="$OUT/source-$key"
if [ -d "$SOURCE" ]; then
  rm -rf "$staging"
else
  mv "$staging" "$SOURCE"
fi
find "$OUT" -mindepth 1 -maxdepth 1 -name 'source-*' ! -name "source-$key" \
  -exec rm -rf {} +
cd "$SOURCE"

[ "$mode" = test ] || cargo fetch --quiet --locked

# Every dependency comes from crates.io: no path, Git or patched source.
packages="$(grep -c '^\[\[package\]\]$' Cargo.lock)"
registry="$(grep -c '^source = "registry+https://github.com/rust-lang/crates.io-index"$' Cargo.lock)"
[ "$registry" -eq $((packages - 1)) ] ||
  fail "$LOCK takes a dependency from outside crates.io"

# Each direct dependency is locked at the lowest version the manifest allows.
direct="$(cargo tree --locked --offline --target all -e normal,build,dev \
  --depth 1 --prefix none --format '{p}')" ||
  fail "$LOCK does not match moto-sdk's manifest; run $0 --update-lock"
checked=0
while read -r name requirement; do
  case "$requirement" in
    "" | *[!0-9.]*) fail "$name: cannot check requirement '$requirement'" ;;
    *.*.*) floor="$requirement" ;;
    *.*) floor="$requirement.0" ;;
    *) floor="$requirement.0.0" ;;
  esac
  printf '%s\n' "$direct" | grep -qxE "$name v${floor//./\\.}( \(proc-macro\))?" ||
    fail "$name is not locked at $floor, the lowest version allowed; run $0 --update-lock"
  checked=$((checked + 1))
done < <(awk '/^\[/ {
    dep = ""
    if (match($0, /dependencies\.[^]]+\]$/)) dep = substr($0, RSTART + 13, RLENGTH - 14)
  }
  dep != "" && /^version = / { v = $3; gsub(/"/, "", v); print dep, v; dep = "" }' Cargo.toml)
[ "$checked" -gt 0 ] || fail "found no dependency requirements in the packaged manifest"

test_args=()
[ "$mode" = test ] || test_args=(--no-run)
export CARGO_TARGET_DIR="$OUT/target"
cargo test --quiet --locked "${network_args[@]}" "${profile_args[@]}" "${test_args[@]}"
cargo test --quiet --locked "${network_args[@]}" "${profile_args[@]}" --target "$MOTOR" --no-run
cargo build --quiet --locked "${network_args[@]}" "${profile_args[@]}" --target "$MOTOR" \
  --features test-support
cargo build --quiet --locked "${network_args[@]}" "${profile_args[@]}" --target "$MOTOR" \
  --no-default-features -Zbuild-std=core,alloc
if [ "$mode" = test ]; then
  echo "moto-sdk package PASS"
fi
