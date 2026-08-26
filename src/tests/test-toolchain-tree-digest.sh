#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-sources.sh"

fail() {
  echo "test-toolchain-tree-digest: $*" >&2
  exit 1
}

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT
repo="$TMP_ROOT/source"
git init -q -b main "$repo"
printf 'build/\nbootstrap.toml\nignored/\n' > "$repo/.gitignore"
printf 'tracked\n' > "$repo/input"
git -C "$repo" add .gitignore input
git -C "$repo" -c user.name=Test -c user.email=test@example.com \
  commit -q -m base

[ "$(toolchain_worktree_digest "$repo" rust)" = clean ] ||
  fail "clean tree was marked dirty"
printf 'generated\n' > "$repo/bootstrap.toml"
mkdir "$repo/build"
printf 'output\n' > "$repo/build/artifact"
[ "$(toolchain_worktree_digest "$repo" rust)" = clean ] ||
  fail "reviewed ignored outputs changed the digest"

printf 'changed\n' >> "$repo/input"
tracked_digest="$(toolchain_worktree_digest "$repo" rust)"
[[ "$tracked_digest" =~ ^[0-9a-f]{64}$ ]] || fail "tracked change was not hashed"
chmod +x "$repo/input"
[ "$tracked_digest" != "$(toolchain_worktree_digest "$repo" rust)" ] ||
  fail "executable mode did not change the digest"
git -C "$repo" checkout -- input

newline_path=$'new\ninput'
printf 'untracked contents\n' > "$repo/$newline_path"
untracked_digest="$(toolchain_worktree_digest "$repo" rust)"
ln -s $'target\nwith-newline' "$repo/link"
[ "$untracked_digest" != "$(toolchain_worktree_digest "$repo" rust)" ] ||
  fail "symlink target did not change the digest"

copy="$TMP_ROOT/copy"
cp -a "$repo" "$copy"
[ "$(toolchain_worktree_digest "$repo" rust)" = \
  "$(toolchain_worktree_digest "$copy" rust)" ] ||
  fail "absolute checkout path changed the digest"

mkdir "$repo/ignored"
printf 'unknown\n' > "$repo/ignored/input"
if toolchain_worktree_digest "$repo" rust >/dev/null 2>&1; then
  fail "unreviewed ignored path was accepted"
fi
rm "$repo/ignored/input"
rmdir "$repo/ignored"

nested="$repo/nested"
git init -q "$nested"
if toolchain_worktree_digest "$repo" rust >/dev/null 2>&1; then
  fail "nested repository was accepted"
fi
rm -rf "$nested"

mkfifo "$repo/special"
if toolchain_worktree_digest "$repo" rust >/dev/null 2>&1; then
  fail "special file was accepted"
fi

echo "test-toolchain-tree-digest PASS"
