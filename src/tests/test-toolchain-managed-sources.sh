#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-sources.sh"

fail() {
  echo "test-toolchain-managed-sources: $*" >&2
  exit 1
}

commit_file() {
  local repo="$1" value="$2" message="$3"
  printf '%s\n' "$value" > "$repo/input"
  git -C "$repo" add input
  git -C "$repo" -c user.name=Test -c user.email=test@example.com \
    commit -q -m "$message"
  git -C "$repo" rev-parse HEAD
}

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

stage0_repo="$TMP_ROOT/stage0"
git init -q -b main "$stage0_repo"
mkdir -p "$stage0_repo/src"
{
  printf 'compiler_git_commit_hash=%040d\n' 8
  head -c 1048576 /dev/zero | tr '\0' x
  printf '\n'
} > "$stage0_repo/src/stage0"
git -C "$stage0_repo" add src/stage0
git -C "$stage0_repo" -c user.name=Test -c user.email=test@example.com \
  commit -q -m stage0
stage0_commit="$(git -C "$stage0_repo" rev-parse HEAD)"
if ! stage0_revision="$(toolchain_stage0_revision \
  "$stage0_repo" "$stage0_commit")"; then
  fail "large Stage 0 metadata could not be read"
fi
[ "$stage0_revision" = 0000000000000000000000000000000000000008 ] ||
  fail "wrong Stage 0 revision: $stage0_revision"

remote="$TMP_ROOT/remote"
git init -q -b development "$remote"
first="$(commit_file "$remote" one first)"
git -C "$remote" tag formal "$first"
second="$(commit_file "$remote" two second)"

managed="$TMP_ROOT/managed"
toolchain_managed_checkout "$remote" refs/heads/development "$first" "$managed"
[ "$(git -C "$managed" rev-parse HEAD)" = "$first" ] ||
  fail "development ref did not retain the pinned ancestor"
[ -z "$(git -C "$managed" branch --show-current)" ] ||
  fail "managed checkout is not detached"

printf 'dirty\n' >> "$managed/input"
before="$(git -C "$managed" rev-parse HEAD)"
if toolchain_managed_checkout "$remote" refs/heads/development "$second" "$managed" \
  >/dev/null 2>&1; then
  fail "dirty checkout was accepted"
fi
[ "$(git -C "$managed" rev-parse HEAD)" = "$before" ] ||
  fail "dirty checkout switched revisions"
grep -q dirty "$managed/input" || fail "dirty checkout content was changed"

git -C "$managed" checkout -- input
printf 'untracked\n' > "$managed/local-input"
if toolchain_managed_checkout "$remote" refs/heads/development "$second" "$managed" \
  >/dev/null 2>&1; then
  fail "untracked input was accepted"
fi
[ -f "$managed/local-input" ] || fail "untracked input was removed"

wrong="$TMP_ROOT/wrong"
git clone -q "$remote" "$wrong"
git -C "$wrong" remote set-url origin "$TMP_ROOT/not-the-remote"
wrong_head="$(git -C "$wrong" rev-parse HEAD)"
if toolchain_managed_checkout "$remote" refs/heads/development "$first" "$wrong" \
  >/dev/null 2>&1; then
  fail "wrong remote was accepted"
fi
[ "$(git -C "$wrong" rev-parse HEAD)" = "$wrong_head" ] ||
  fail "wrong-remote checkout was changed"

tagged="$TMP_ROOT/tagged"
toolchain_managed_checkout "$remote" refs/tags/formal "$first" "$tagged"
git -C "$remote" tag -f formal "$second" >/dev/null
stale="$TMP_ROOT/stale-tag"
if toolchain_managed_checkout "$remote" refs/tags/formal "$first" "$stale" \
  >/dev/null 2>&1; then
  fail "moved formal tag was accepted"
fi

missing="$TMP_ROOT/missing"
if toolchain_managed_checkout "$remote" refs/heads/development \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$missing" >/dev/null 2>&1; then
  fail "missing revision was accepted"
fi

git -C "$remote" remote add origin "$remote"
linked="$TMP_ROOT/linked"
git -C "$remote" worktree add -q --detach "$linked" "$first"
if toolchain_managed_checkout "$remote" refs/heads/development "$first" "$linked" \
  >/dev/null 2>&1; then
  fail "linked managed worktree was accepted"
fi

# A declared revision that moves a gitlink: the stale submodule worktree is not
# dirt in the superproject, the submodule is then detached at its new gitlink,
# and the whole tree is clean afterwards. Real submodule edits still block.
sub_remote="$TMP_ROOT/sub-remote"
git init -q -b main "$sub_remote"
sub_first="$(commit_file "$sub_remote" sub-one "sub first")"
sub_second="$(commit_file "$sub_remote" sub-two "sub second")"
super_remote="$TMP_ROOT/super-remote"
git init -q -b main "$super_remote"
git -C "$super_remote" -c protocol.file.allow=always \
  submodule add -q "$sub_remote" sub
git -C "$super_remote/sub" checkout -q "$sub_first"
git -C "$super_remote" add sub
git -C "$super_remote" -c user.name=Test -c user.email=test@example.com \
  commit -q -m "super first"
super_first="$(git -C "$super_remote" rev-parse HEAD)"
git -C "$super_remote/sub" checkout -q "$sub_second"
git -C "$super_remote" add sub
git -C "$super_remote" -c user.name=Test -c user.email=test@example.com \
  commit -q -m "super second"
super_second="$(git -C "$super_remote" rev-parse HEAD)"
super="$TMP_ROOT/managed-super"
toolchain_managed_checkout "$super_remote" refs/heads/main "$super_first" "$super"
toolchain_managed_submodule "$super" sub "$sub_remote" refs/heads/main "$sub_first" \
  >/dev/null 2>&1 || fail "submodule was not initialized at its gitlink"
[ "$(git -C "$super/sub" rev-parse HEAD)" = "$sub_first" ] ||
  fail "submodule is not at the first gitlink"
toolchain_managed_checkout "$super_remote" refs/heads/main "$super_second" "$super" \
  >/dev/null 2>&1 || fail "a moved gitlink was rejected as a dirty checkout"
[ "$(git -C "$super" rev-parse HEAD)" = "$super_second" ] ||
  fail "superproject did not move to the second revision"
toolchain_managed_submodule "$super" sub "$sub_remote" refs/heads/main "$sub_second" \
  >/dev/null 2>&1 || fail "submodule did not follow the moved gitlink"
[ "$(git -C "$super/sub" rev-parse HEAD)" = "$sub_second" ] ||
  fail "submodule is not at the second gitlink"
toolchain_assert_clean "$super" || fail "tree is not clean after the submodule update"
printf 'dirty\n' >> "$super/sub/input"
if toolchain_managed_submodule "$super" sub "$sub_remote" refs/heads/main "$sub_second" \
  >/dev/null 2>&1; then
  fail "a modified submodule was accepted"
fi
grep -q dirty "$super/sub/input" || fail "modified submodule content was changed"
git -C "$super/sub" checkout -q -- input

# Exercise the verifier under nounset before constructing its full Rust fixture.
# It must reach the expected missing-LLVM diagnostic, not abort while deriving
# the LLVM path from its first local variable.
MOTOR_RUST_REV="$second" UPSTREAM_RUST_REV="$first" \
RUST_LLVM_BASE_REV="$first" MOTOR_LLVM_REV="$second" \
  toolchain_verify_managed_rust "$remote" 2> "$TMP_ROOT/verify-error" || true
grep -q 'LLVM base is missing' "$TMP_ROOT/verify-error" ||
  fail "managed Rust verifier did not initialize its source paths"

echo "test-toolchain-managed-sources PASS"
