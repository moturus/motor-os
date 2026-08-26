#!/usr/bin/env bash
# Exact, non-destructive source checkout handling for the Motor toolchain.

toolchain_git_absolute_dir() {
  local repo="$1" selector="$2"
  git -C "$repo" rev-parse --path-format=absolute "$selector"
}

toolchain_assert_independent_checkout() {
  local repo="$1" git_dir common_dir
  git_dir="$(git -C "$repo" rev-parse --absolute-git-dir)" ||
    toolchain_die "not a Git checkout: $repo"
  common_dir="$(toolchain_git_absolute_dir "$repo" --git-common-dir)" || return
  [ "$git_dir" = "$common_dir" ] ||
    toolchain_die "managed checkout is a linked worktree: $repo"
}

toolchain_assert_remote() {
  local repo="$1" expected="$2" actual
  actual="$(git -C "$repo" remote get-url origin 2>/dev/null)" ||
    toolchain_die "managed checkout has no origin remote: $repo"
  [ "$actual" = "$expected" ] ||
    toolchain_die "wrong origin for $repo: expected $expected, found $actual"
}

toolchain_assert_clean() {
  local repo="$1" state
  state="$(git -C "$repo" status --porcelain=v1 --untracked-files=all)" ||
    toolchain_die "cannot inspect checkout state: $repo"
  [ -z "$state" ] || toolchain_die "managed checkout is dirty: $repo"
}

toolchain_clone_managed() {
  local repository="$1" destination="$2" seed="${3:-}"
  [ ! -e "$destination" ] ||
    toolchain_die "managed checkout destination already exists: $destination"
  mkdir -p "$(dirname "$destination")"
  if [ -n "$seed" ] && git -C "$seed" rev-parse --git-dir >/dev/null 2>&1; then
    git clone --origin origin --reference-if-able "$seed" --dissociate \
      "$repository" "$destination"
  else
    git clone --origin origin "$repository" "$destination"
  fi
}

toolchain_fetch_declared_ref() {
  local repo="$1" ref="$2" revision="$3" fetched
  git -C "$repo" fetch --no-tags origin "$ref" ||
    toolchain_die "cannot fetch declared ref $ref from $repo"
  fetched="$(git -C "$repo" rev-parse 'FETCH_HEAD^{commit}')" || return
  git -C "$repo" cat-file -e "$revision^{commit}" 2>/dev/null ||
    toolchain_die "declared revision $revision is missing from $repo"

  case "$ref" in
    refs/tags/*)
      [ "$fetched" = "$revision" ] ||
        toolchain_die "tag $ref does not resolve to $revision"
      ;;
    *)
      git -C "$repo" merge-base --is-ancestor "$revision" "$fetched" ||
        toolchain_die "$revision is not reachable from $ref"
      ;;
  esac
}

toolchain_managed_checkout() {
  local repository="$1" ref="$2" revision="$3" destination="$4"
  local seed="${5:-}"
  toolchain_require_hex revision "$revision" 40 || return

  if [ ! -e "$destination" ]; then
    toolchain_clone_managed "$repository" "$destination" "$seed" || return
  fi
  git -C "$destination" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    toolchain_die "managed path is not a Git worktree: $destination"
  toolchain_assert_independent_checkout "$destination" || return
  toolchain_assert_remote "$destination" "$repository" || return
  toolchain_fetch_declared_ref "$destination" "$ref" "$revision" || return

  # This check deliberately precedes checkout. Never switch, stash, reset, or
  # clean a worktree containing user changes.
  toolchain_assert_clean "$destination" || return
  git -C "$destination" checkout --detach "$revision" ||
    toolchain_die "cannot detach $destination at $revision"
  [ "$(git -C "$destination" rev-parse HEAD)" = "$revision" ] ||
    toolchain_die "checkout did not select $revision: $destination"
  toolchain_assert_clean "$destination"
}
