#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-sources.sh"

fail() {
  echo "test-toolchain-authoring-sources: $*" >&2
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
llvm_source="$TMP_ROOT/llvm-source"
cargo_source="$TMP_ROOT/cargo-source"
backtrace_source="$TMP_ROOT/backtrace-source"
book_source="$TMP_ROOT/book-source"
reference_source="$TMP_ROOT/reference-source"
rustc_perf_source="$TMP_ROOT/rustc-perf-source"
rust="$TMP_ROOT/rust"

git init -q -b main "$llvm_source"
printf 'llvm base\n' > "$llvm_source/input"
llvm_base="$(commit_all "$llvm_source" base)"
git init -q -b main "$cargo_source"
printf '[package]\nname="cargo"\nversion="0.100.0"\n' > "$cargo_source/Cargo.toml"
cargo_rev="$(commit_all "$cargo_source" base)"
git init -q -b main "$backtrace_source"
printf 'backtrace\n' > "$backtrace_source/input"
backtrace_rev="$(commit_all "$backtrace_source" base)"
git init -q -b main "$book_source"
printf 'book\n' > "$book_source/input"
book_rev="$(commit_all "$book_source" base)"
git init -q -b main "$reference_source"
printf 'reference\n' > "$reference_source/input"
reference_rev="$(commit_all "$reference_source" base)"
git init -q -b main "$rustc_perf_source"
printf 'rustc-perf\n' > "$rustc_perf_source/input"
rustc_perf_rev="$(commit_all "$rustc_perf_source" base)"

git init -q -b main "$rust"
mkdir -p "$rust/src/tools" "$rust/src/doc" "$rust/library"
git -C "$rust" -c protocol.file.allow=always submodule add -q \
  "$llvm_source" src/llvm-project
git -C "$rust" -c protocol.file.allow=always submodule add -q \
  "$cargo_source" src/tools/cargo
git -C "$rust" -c protocol.file.allow=always submodule add -q \
  "$backtrace_source" library/backtrace
git -C "$rust" -c protocol.file.allow=always submodule add -q \
  "$book_source" src/doc/book
git -C "$rust" -c protocol.file.allow=always submodule add -q \
  "$reference_source" src/doc/reference
git -C "$rust" -c protocol.file.allow=always submodule add -q \
  "$rustc_perf_source" src/tools/rustc-perf
printf '1.99.0\n' > "$rust/src/version"
printf 'compiler_git_commit_hash=%040d\n' 8 > "$rust/src/stage0"
printf 'build/\nbootstrap.toml\n' > "$rust/.gitignore"
printf 'base\n' > "$rust/input"
base="$(commit_all "$rust" base)"

MOTOR_RUST_REPOSITORY="$TMP_ROOT/motor-rust"
UPSTREAM_RUST_REPOSITORY="$TMP_ROOT/upstream-rust"
MOTOR_LLVM_REPOSITORY="$llvm_source"
RUST_LLVM_REPOSITORY="$TMP_ROOT/upstream-llvm"
MOTOR_CARGO_REPOSITORY="$cargo_source"
RUST_BACKTRACE_REPOSITORY="$backtrace_source"
RUST_BOOK_REPOSITORY="$book_source"
RUST_REFERENCE_REPOSITORY="$reference_source"
RUSTC_PERF_REPOSITORY="$rustc_perf_source"
UPSTREAM_RUST_REV=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
MOTOR_RUST_CHANNEL=dev
git -C "$rust" remote add origin "$MOTOR_RUST_REPOSITORY"
git -C "$rust" remote add rust-lang "$UPSTREAM_RUST_REPOSITORY"
git -C "$rust/src/llvm-project" remote add rust-lang "$RUST_LLVM_REPOSITORY"

printf 'rust patch\n' >> "$rust/input"
rust_head="$(commit_all "$rust" rust-patch)"
printf 'llvm patch\n' >> "$rust/src/llvm-project/input"
llvm_head="$(commit_all "$rust/src/llvm-project" llvm-patch)"

refs_before="$(git -C "$rust" for-each-ref --format='%(refname) %(objectname)')"
state_before="$(git -C "$rust" status --porcelain=v1 --untracked-files=all)"
toolchain_authoring_resolve "$rust" "$base"
[ "$EFFECTIVE_MOTOR_RUST_REV" = "$rust_head" ] || fail "wrong effective Rust revision"
[ "$EFFECTIVE_MOTOR_LLVM_REV" = "$llvm_head" ] || fail "wrong effective LLVM revision"
[ "$SELECTED_MOTOR_CARGO_REV" = "$cargo_rev" ] || fail "wrong Cargo gitlink"
[ "$SELECTED_MOTOR_CARGO_VERSION" = 1.99.0-dev ] || fail "wrong Cargo release"
[ "$MOTOR_ASSEMBLY_STATE" = development-authoring ] || fail "clean patch stack marked dirty"
[[ "$AUTHORING_SOURCE_DIGEST" =~ ^[0-9a-f]{64}$ ]] || fail "invalid source digest"
[ "$refs_before" = "$(git -C "$rust" for-each-ref --format='%(refname) %(objectname)')" ] ||
  fail "authoring resolution changed a Rust ref"
[ "$state_before" = "$(git -C "$rust" status --porcelain=v1 --untracked-files=all)" ] ||
  fail "authoring resolution changed the Rust worktree"

clean_digest="$AUTHORING_SOURCE_DIGEST"
printf 'dirty\n' >> "$rust/input"
printf 'untracked\n' > "$rust/src/llvm-project/local-input"
toolchain_authoring_resolve "$rust" "$base"
[ "$MOTOR_ASSEMBLY_STATE" = development-dirty ] || fail "dirty sources marked clean"
[ "$clean_digest" != "$AUTHORING_SOURCE_DIGEST" ] || fail "dirty sources reused the clean digest"

git -C "$rust" add src/llvm-project
toolchain_authoring_resolve "$rust" "$base" || fail "pending LLVM gitlink was rejected"
initial_base_dirty_digest="$AUTHORING_SOURCE_DIGEST"

git -C "$rust/src/tools/cargo" -c user.name=Test -c user.email=test@example.com \
  commit -q --allow-empty -m other
if toolchain_authoring_resolve "$rust" "$base" >/dev/null 2>&1; then
  fail "changed Cargo submodule was accepted"
fi
git -C "$rust/src/tools/cargo" checkout -q --detach "$cargo_rev"

git -C "$rust/library/backtrace" -c user.name=Test -c user.email=test@example.com \
  commit -q --allow-empty -m other
if toolchain_authoring_resolve "$rust" "$base" >/dev/null 2>&1; then
  fail "changed backtrace submodule was accepted"
fi
git -C "$rust/library/backtrace" checkout -q --detach "$backtrace_rev"

git -C "$rust/src/doc/book" -c user.name=Test -c user.email=test@example.com \
  commit -q --allow-empty -m other
if toolchain_authoring_resolve "$rust" "$base" >/dev/null 2>&1; then
  fail "changed book submodule was accepted"
fi
git -C "$rust/src/doc/book" checkout -q --detach "$book_rev"

git -C "$rust/src/doc/reference" -c user.name=Test -c user.email=test@example.com \
  commit -q --allow-empty -m other
if toolchain_authoring_resolve "$rust" "$base" >/dev/null 2>&1; then
  fail "changed reference submodule was accepted"
fi
git -C "$rust/src/doc/reference" checkout -q --detach "$reference_rev"

git -C "$rust/src/tools/rustc-perf" -c user.name=Test -c user.email=test@example.com \
  commit -q --allow-empty -m other
if toolchain_authoring_resolve "$rust" "$base" >/dev/null 2>&1; then
  fail "changed rustc-perf submodule was accepted"
fi
git -C "$rust/src/tools/rustc-perf" checkout -q --detach "$rustc_perf_rev"

printf 'changed-stage0\n' >> "$rust/src/stage0"
if toolchain_authoring_resolve "$rust" "$base" >/dev/null 2>&1; then
  fail "changed Stage 0 was accepted"
fi
git -C "$rust" checkout -- src/stage0

git -C "$rust" remote set-url rust-lang "$TMP_ROOT/wrong-upstream"
if toolchain_authoring_resolve "$rust" "$base" >/dev/null 2>&1; then
  fail "wrong authoring remote was accepted"
fi
git -C "$rust" remote set-url rust-lang "$UPSTREAM_RUST_REPOSITORY"

git -C "$rust/src/llvm-project" checkout -q --orphan unrelated
git -C "$rust/src/llvm-project" -c user.name=Test -c user.email=test@example.com \
  commit -q --allow-empty -m unrelated
if toolchain_authoring_resolve "$rust" "$base" >/dev/null 2>&1; then
  fail "unrelated LLVM history was accepted"
fi
git -C "$rust/src/llvm-project" checkout -q "$llvm_head"

toolchain_authoring_resolve "$rust" "$rust_head"
[ "$SELECTED_UPSTREAM_RUST_REV" = "$rust_head" ] || fail "later full base was ignored"
[ "$initial_base_dirty_digest" != "$AUTHORING_SOURCE_DIGEST" ] ||
  fail "different base reused its digest"

if toolchain_authoring_resolve "$rust" "${base:0:12}" >/dev/null 2>&1; then
  fail "short authoring base was accepted"
fi

echo "test-toolchain-authoring-sources PASS"
