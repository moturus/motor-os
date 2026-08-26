#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-sources.sh"

fail() {
  echo "test-toolchain-submodules: $*" >&2
  exit 1
}

commit_all() {
  local repo="$1" message="$2"
  git -C "$repo" add -A
  git -C "$repo" -c user.name=Test -c user.email=test@example.com \
    commit -q -m "$message"
  git -C "$repo" rev-parse HEAD
}

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT
llvm="$TMP_ROOT/llvm"
cargo="$TMP_ROOT/cargo"
backtrace="$TMP_ROOT/backtrace"
rust_source="$TMP_ROOT/rust-source"

git init -q -b motor "$llvm"
printf 'base\n' > "$llvm/input"
llvm_base="$(commit_all "$llvm" base)"
printf 'motor\n' >> "$llvm/input"
llvm_motor="$(commit_all "$llvm" motor)"
git init -q -b main "$cargo"
printf 'cargo\n' > "$cargo/input"
cargo_rev="$(commit_all "$cargo" base)"
git init -q -b main "$backtrace"
printf 'backtrace\n' > "$backtrace/input"
backtrace_rev="$(commit_all "$backtrace" base)"

git init -q -b motor "$rust_source"
mkdir -p "$rust_source/src/tools" "$rust_source/library"
git -C "$rust_source" -c protocol.file.allow=always submodule add -q \
  "$llvm" src/llvm-project
git -C "$rust_source/src/llvm-project" checkout -q --detach "$llvm_base"
git -C "$rust_source" -c protocol.file.allow=always submodule add -q \
  "$cargo" src/tools/cargo
git -C "$rust_source" -c protocol.file.allow=always submodule add -q \
  "$backtrace" library/backtrace
printf '1.99.0\n' > "$rust_source/src/version"
printf 'compiler_git_commit_hash=%040d\n' 8 > "$rust_source/src/stage0"
printf 'root lock\n' > "$rust_source/Cargo.lock"
printf 'library lock\n' > "$rust_source/library/Cargo.lock"
rust_base="$(commit_all "$rust_source" base)"
git -C "$rust_source/src/llvm-project" checkout -q "$llvm_motor"
rust_motor="$(commit_all "$rust_source" motor)"

managed="$TMP_ROOT/managed-rust"
git clone -q --no-recurse-submodules "$rust_source" "$managed"
git -C "$managed" checkout -q --detach "$rust_motor"
toolchain_managed_submodule "$managed" src/llvm-project "$llvm" \
  refs/heads/motor "$llvm_motor"
toolchain_managed_submodule "$managed" src/tools/cargo "$cargo" \
  "$cargo_rev" "$cargo_rev"
toolchain_managed_submodule "$managed" library/backtrace "$backtrace" \
  "$backtrace_rev" "$backtrace_rev"
[ "$(git -C "$managed/src/llvm-project" rev-parse HEAD)" = "$llvm_motor" ] ||
  fail "LLVM submodule revision mismatch"
[ "$(git -C "$managed/src/tools/cargo" rev-parse HEAD)" = "$cargo_rev" ] ||
  fail "Cargo submodule revision mismatch"
[ "$(git -C "$managed/library/backtrace" rev-parse HEAD)" = "$backtrace_rev" ] ||
  fail "backtrace submodule revision mismatch"
toolchain_assert_ancestor "$managed" "$rust_base" "$rust_motor" Rust
toolchain_assert_ancestor "$managed/src/llvm-project" "$llvm_base" "$llvm_motor" LLVM

printf 'dirty\n' >> "$managed/src/llvm-project/input"
before="$(git -C "$managed/src/llvm-project" rev-parse HEAD)"
if toolchain_managed_submodule "$managed" src/llvm-project "$llvm" \
  refs/heads/motor "$llvm_motor" >/dev/null 2>&1; then
  fail "dirty submodule was accepted"
fi
[ "$(git -C "$managed/src/llvm-project" rev-parse HEAD)" = "$before" ] ||
  fail "dirty submodule switched revisions"
grep -q dirty "$managed/src/llvm-project/input" || fail "dirty submodule was changed"

echo "test-toolchain-submodules PASS"
