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

toolchain_ignored_path_allowed() {
  local source_kind="$1" path="$2"
  case "$source_kind:$path" in
    rust:build/|rust:build/*|rust:bootstrap.toml) return 0 ;;
    *) return 1 ;;
  esac
}

toolchain_validate_ignored_paths() {
  local repo="$1" source_kind="$2" path
  while IFS= read -r -d '' path; do
    if ! toolchain_ignored_path_allowed "$source_kind" "$path"; then
      toolchain_die "unsupported ignored authoring path: $repo/$path"
      return 1
    fi
  done < <(git -C "$repo" ls-files --others --ignored --exclude-standard \
    --directory -z)
}

toolchain_reject_nested_repositories() {
  local repo="$1" path
  while IFS= read -r -d '' path; do
    case "$path" in
      */)
        if [ -e "$repo/$path.git" ]; then
          toolchain_die "unsupported nested repository: $repo/$path"
          return 1
        fi
        ;;
    esac
  done < <(git -C "$repo" ls-files --others --exclude-standard --directory -z)
}

toolchain_reject_special_files() {
  local repo="$1" special
  special="$(find "$repo" -name .git -type d -prune -o \
    ! -type f ! -type d ! -type l -print -quit)"
  [ -z "$special" ] || toolchain_die "unsupported authoring file kind: $special"
}

toolchain_emit_file_field() {
  local name="$1" file="$2" LC_ALL=C size
  size="$(wc -c < "$file")"
  size="${size//[[:space:]]/}"
  printf '%s:%s%s:' "${#name}" "$name" "$size"
  command cat "$file"
}

# Print "clean" or a SHA-256 digest of all non-ignored changes relative to
# HEAD. Additional arguments are pathspecs excluded from the tracked diff;
# declared submodules are identified separately by their exact commits.
toolchain_worktree_digest() (
  set -euo pipefail
  local repo="$1" source_kind="$2"
  shift 2
  local tmp record tracked untracked path full kind mode content dirty=0
  local -a pathspec=(.)
  for path in "$@"; do
    pathspec+=(":(exclude)$path")
  done

  toolchain_validate_ignored_paths "$repo" "$source_kind" || exit 1
  toolchain_reject_nested_repositories "$repo" || exit 1
  toolchain_reject_special_files "$repo" || exit 1
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  record="$tmp/record"
  tracked="$tmp/tracked"
  untracked="$tmp/untracked"
  toolchain_serialize_pairs schema motor-authoring-tree-v1 > "$record"

  git -C "$repo" -c core.quotePath=true diff --binary --full-index \
    --no-ext-diff --no-textconv HEAD -- "${pathspec[@]}" > "$tracked" || exit 1
  if [ -s "$tracked" ]; then
    dirty=1
    toolchain_emit_file_field tracked_diff "$tracked" >> "$record"
  fi

  git -C "$repo" ls-files --others --exclude-standard -z > "$untracked" || exit 1
  while IFS= read -r -d '' path; do
    dirty=1
    full="$repo/$path"
    content="$tmp/content"
    if [ -L "$full" ]; then
      kind=symlink
      mode=120000
      readlink -n "$full" > "$content"
    elif [ -f "$full" ]; then
      kind=file
      if [ -x "$full" ]; then mode=100755; else mode=100644; fi
      content="$full"
    else
      toolchain_die "unsupported authoring file kind: $full"
      exit 1
    fi
    toolchain_serialize_pairs path "$path" kind "$kind" mode "$mode" >> "$record"
    toolchain_emit_file_field content "$content" >> "$record"
  done < "$untracked"

  if [ "$dirty" -eq 0 ]; then
    printf 'clean\n'
  else
    sha256sum "$record" | awk '{print $1}'
  fi
)
