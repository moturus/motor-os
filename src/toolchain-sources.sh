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

toolchain_assert_named_remote() {
  local repo="$1" name="$2" expected="$3" actual
  if ! actual="$(git -C "$repo" remote get-url "$name" 2>/dev/null)"; then
    toolchain_die "missing $name remote in $repo"
    return 1
  fi
  if [ "$actual" != "$expected" ]; then
    toolchain_die "wrong $name remote in $repo: expected $expected, found $actual"
    return 1
  fi
}

toolchain_gitlink() {
  local repo="$1" revision="$2" path="$3" line mode type hash
  line="$(git -C "$repo" ls-tree "$revision" -- "$path")" || return
  read -r mode type hash _ <<< "$line"
  if [ "$mode" != 160000 ] || [ "$type" != commit ] || [ -z "$hash" ]; then
    toolchain_die "$path is not a gitlink at $revision"
    return 1
  fi
  printf '%s\n' "$hash"
}

toolchain_stage0_revision() {
  local repo="$1" revision="$2" value
  value="$(git -C "$repo" show "$revision:src/stage0" |
    awk -F= '$1 == "compiler_git_commit_hash" { print $2; exit }')" || return
  toolchain_require_hex stage0_revision "$value" 40 || return
  printf '%s\n' "$value"
}

toolchain_authoring_resolve() {
  local rust="$1" base="$2" llvm cargo backtrace book reference
  local rust_head llvm_head cargo_head
  local effective_llvm_gitlink index_llvm_gitlink index_cargo_gitlink stage0_at_head
  toolchain_require_hex authoring_base "$base" 40 || return
  if ! git -C "$rust" cat-file -e "$base^{commit}" 2>/dev/null; then
    toolchain_die "authoring base is missing from $rust: $base"
    return 1
  fi
  rust_head="$(git -C "$rust" rev-parse HEAD)" || return
  if ! git -C "$rust" merge-base --is-ancestor "$base" "$rust_head"; then
    toolchain_die "authoring base is not an ancestor of Rust HEAD"
    return 1
  fi

  toolchain_assert_named_remote "$rust" origin "$MOTOR_RUST_REPOSITORY" || return
  toolchain_assert_named_remote "$rust" rust-lang "$UPSTREAM_RUST_REPOSITORY" || return
  llvm="$rust/src/llvm-project"
  cargo="$rust/src/tools/cargo"
  backtrace="$rust/library/backtrace"
  book="$rust/src/doc/book"
  reference="$rust/src/doc/reference"
  if ! git -C "$llvm" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    toolchain_die "LLVM submodule is not initialized: $llvm"
    return 1
  fi
  if ! git -C "$cargo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    toolchain_die "Cargo submodule is not initialized: $cargo"
    return 1
  fi
  if ! git -C "$backtrace" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    toolchain_die "backtrace submodule is not initialized: $backtrace"
    return 1
  fi
  toolchain_assert_named_remote "$llvm" origin "$MOTOR_LLVM_REPOSITORY" || return
  toolchain_assert_named_remote "$llvm" rust-lang "$RUST_LLVM_REPOSITORY" || return
  toolchain_assert_named_remote "$cargo" origin "$MOTOR_CARGO_REPOSITORY" || return
  toolchain_assert_named_remote "$backtrace" origin "$RUST_BACKTRACE_REPOSITORY" || return
  toolchain_assert_named_remote "$book" origin "$RUST_BOOK_REPOSITORY" || return
  toolchain_assert_named_remote "$reference" origin "$RUST_REFERENCE_REPOSITORY" || return

  SELECTED_UPSTREAM_RUST_REV="$base"
  SELECTED_RUST_VERSION="$(git -C "$rust" show "$base:src/version")" || return
  SELECTED_STAGE0_REV="$(toolchain_stage0_revision "$rust" "$base")" || return
  SELECTED_RUST_LLVM_BASE_REV="$(toolchain_gitlink "$rust" "$base" src/llvm-project)" || return
  SELECTED_MOTOR_CARGO_REV="$(toolchain_gitlink "$rust" "$base" src/tools/cargo)" || return
  SELECTED_MOTOR_CARGO_VERSION="$SELECTED_RUST_VERSION-$MOTOR_RUST_CHANNEL"

  if [ "$base" = "$UPSTREAM_RUST_REV" ]; then
    if ! { [ "$SELECTED_RUST_VERSION" = "$UPSTREAM_RUST_VERSION" ] &&
      [ "$SELECTED_STAGE0_REV" = "$UPSTREAM_STAGE0_REV" ] &&
      [ "$SELECTED_RUST_LLVM_BASE_REV" = "$RUST_LLVM_BASE_REV" ] &&
      [ "$SELECTED_MOTOR_CARGO_REV" = "$MOTOR_CARGO_REV" ]; }; then
      toolchain_die "declared upstream Rust tuple does not match its source"
      return 1
    fi
  fi

  stage0_at_head="$(toolchain_stage0_revision "$rust" "$rust_head")" || return
  if [ "$stage0_at_head" != "$SELECTED_STAGE0_REV" ]; then
    toolchain_die "authoring Rust HEAD changes the selected Stage 0"
    return 1
  fi
  if ! git -C "$rust" diff --quiet HEAD -- src/stage0; then
    toolchain_die "authoring worktree changes src/stage0"
    return 1
  fi

  effective_llvm_gitlink="$(toolchain_gitlink "$rust" "$rust_head" src/llvm-project)" || return
  if [ "$(toolchain_gitlink "$rust" "$rust_head" src/tools/cargo)" != \
    "$SELECTED_MOTOR_CARGO_REV" ]; then
    toolchain_die "authoring Rust HEAD changes the selected Cargo gitlink"
    return 1
  fi
  index_llvm_gitlink="$(git -C "$rust" ls-files --stage src/llvm-project | awk '{print $2}')"
  toolchain_require_hex llvm_index_gitlink "$index_llvm_gitlink" 40 || return
  index_cargo_gitlink="$(git -C "$rust" ls-files --stage src/tools/cargo | awk '{print $2}')"
  if [ "$index_cargo_gitlink" != "$SELECTED_MOTOR_CARGO_REV" ]; then
    toolchain_die "authoring index changes the selected Cargo gitlink"
    return 1
  fi

  llvm_head="$(git -C "$llvm" rev-parse HEAD)" || return
  cargo_head="$(git -C "$cargo" rev-parse HEAD)" || return
  for revision in "$effective_llvm_gitlink" "$index_llvm_gitlink" "$llvm_head"; do
    if ! git -C "$llvm" cat-file -e "$revision^{commit}" 2>/dev/null; then
      toolchain_die "LLVM authoring revision is missing: $revision"
      return 1
    fi
    if ! git -C "$llvm" merge-base --is-ancestor \
      "$SELECTED_RUST_LLVM_BASE_REV" "$revision"; then
      toolchain_die "LLVM authoring revision does not descend from its selected base"
      return 1
    fi
  done
  if ! git -C "$llvm" merge-base --is-ancestor "$effective_llvm_gitlink" "$llvm_head"; then
    toolchain_die "LLVM worktree is behind the gitlink in Rust HEAD"
    return 1
  fi
  if ! git -C "$llvm" merge-base --is-ancestor "$index_llvm_gitlink" "$llvm_head"; then
    toolchain_die "LLVM worktree is behind the staged Rust gitlink"
    return 1
  fi

  if [ "$cargo_head" != "$SELECTED_MOTOR_CARGO_REV" ]; then
    toolchain_die "Cargo submodule is not at the selected gitlink"
    return 1
  fi
  toolchain_assert_clean "$cargo" || return
  toolchain_validate_ignored_paths "$cargo" cargo || return
  toolchain_verify_exact_submodule "$rust" library/backtrace \
    "$RUST_BACKTRACE_REPOSITORY" || return
  toolchain_verify_exact_submodule "$rust" src/doc/book \
    "$RUST_BOOK_REPOSITORY" || return
  toolchain_verify_exact_submodule "$rust" src/doc/reference \
    "$RUST_REFERENCE_REPOSITORY" || return

  MOTOR_RUST_TREE_STATE="$(toolchain_worktree_digest "$rust" rust \
    src/llvm-project src/tools/cargo)" || return
  if [ "$index_llvm_gitlink" != "$effective_llvm_gitlink" ]; then
    MOTOR_RUST_TREE_STATE="$(toolchain_hash_pairs tree "$MOTOR_RUST_TREE_STATE" \
      llvm_index_gitlink "$index_llvm_gitlink")"
  fi
  MOTOR_LLVM_TREE_STATE="$(toolchain_worktree_digest "$llvm" llvm)" || return
  EFFECTIVE_MOTOR_RUST_REV="$rust_head"
  EFFECTIVE_MOTOR_LLVM_REV="$llvm_head"
  MOTOR_SOURCE_MODE=authoring
  AUTHORING_SOURCE_DIGEST="$(toolchain_hash_pairs \
    schema motor-authoring-source-v1 selected_base "$base" \
    rust_rev "$rust_head" rust_tree "$MOTOR_RUST_TREE_STATE" \
    llvm_rev "$llvm_head" llvm_tree "$MOTOR_LLVM_TREE_STATE")"
  SELECTED_RUSTUP_TOOLCHAIN_BASE="motor-authoring-$SELECTED_RUST_VERSION-${base:0:12}"
  SELECTED_TOOLCHAIN_DESCRIPTION="$SELECTED_RUST_VERSION-motor+authoring.$AUTHORING_SOURCE_DIGEST"
  if [ "$MOTOR_RUST_TREE_STATE" = clean ] && [ "$MOTOR_LLVM_TREE_STATE" = clean ]; then
    MOTOR_ASSEMBLY_STATE=development-authoring
  else
    MOTOR_ASSEMBLY_STATE=development-dirty
  fi
}

toolchain_managed_submodule() {
  local parent="$1" path="$2" repository="$3" ref="$4" revision="$5"
  local seed="${6:-}" destination expected top
  destination="$parent/$path"
  expected="$(toolchain_gitlink "$parent" HEAD "$path")" || return
  if [ "$expected" != "$revision" ]; then
    toolchain_die "$path gitlink is $expected, expected $revision"
    return 1
  fi

  top="$(git -C "$destination" rev-parse --show-toplevel 2>/dev/null || true)"
  if [ "$(readlink -f "$top" 2>/dev/null || true)" != \
    "$(readlink -f "$destination" 2>/dev/null || true)" ]; then
    if [ -d "$destination" ] &&
      [ -z "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
      rmdir "$destination"
    elif [ -e "$destination" ]; then
      toolchain_die "uninitialized submodule path is not empty: $destination"
      return 1
    fi
    toolchain_clone_managed "$repository" "$destination" "$seed" || return
    if ! git -C "$parent" submodule absorbgitdirs "$path"; then
      toolchain_die "cannot absorb $path Git metadata"
      return 1
    fi
  fi
  if ! git -C "$destination" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    toolchain_die "submodule is not initialized: $destination"
    return 1
  fi
  toolchain_assert_independent_checkout "$destination" || return
  toolchain_assert_remote "$destination" "$repository" || return
  toolchain_fetch_declared_ref "$destination" "$ref" "$revision" || return
  toolchain_assert_clean "$destination" || return
  if ! git -C "$destination" checkout --detach "$revision"; then
    toolchain_die "cannot detach $path at $revision"
    return 1
  fi
  if [ "$(git -C "$destination" rev-parse HEAD)" != "$revision" ]; then
    toolchain_die "$path did not select $revision"
    return 1
  fi
  toolchain_assert_clean "$destination" || return
  toolchain_assert_clean "$parent"
}

toolchain_verify_exact_submodule() {
  local parent="$1" path="$2" repository="$3" destination expected top
  destination="$parent/$path"
  expected="$(toolchain_gitlink "$parent" HEAD "$path")" || return
  top="$(git -C "$destination" rev-parse --show-toplevel 2>/dev/null || true)"
  if [ "$(readlink -f "$top" 2>/dev/null || true)" != \
    "$(readlink -f "$destination" 2>/dev/null || true)" ]; then
    toolchain_die "$path submodule is not initialized: $destination"
    return 1
  fi
  toolchain_assert_remote "$destination" "$repository" || return
  toolchain_expect_equal "$(git -C "$destination" rev-parse HEAD)" \
    "$expected" "$path submodule HEAD mismatch" || return
  toolchain_assert_clean "$destination"
}

toolchain_assert_ancestor() {
  local repo="$1" base="$2" revision="$3" description="$4"
  if ! git -C "$repo" cat-file -e "$base^{commit}" 2>/dev/null; then
    toolchain_die "$description base is missing: $base"
    return 1
  fi
  if ! git -C "$repo" cat-file -e "$revision^{commit}" 2>/dev/null; then
    toolchain_die "$description revision is missing: $revision"
    return 1
  fi
  if ! git -C "$repo" merge-base --is-ancestor "$base" "$revision"; then
    toolchain_die "$description revision does not descend from its base"
    return 1
  fi
}

toolchain_expect_equal() {
  local actual="$1" expected="$2" description="$3"
  if [ "$actual" != "$expected" ]; then
    toolchain_die "$description: expected $expected, found $actual"
    return 1
  fi
}

toolchain_verify_managed_rust() {
  local rust="$1" llvm="$rust/src/llvm-project" value
  toolchain_expect_equal "$(git -C "$rust" rev-parse HEAD)" \
    "$MOTOR_RUST_REV" "managed Rust HEAD mismatch" || return
  toolchain_assert_ancestor "$rust" "$UPSTREAM_RUST_REV" "$MOTOR_RUST_REV" Rust || return
  toolchain_assert_ancestor "$llvm" "$RUST_LLVM_BASE_REV" "$MOTOR_LLVM_REV" LLVM || return
  toolchain_expect_equal \
    "$(toolchain_gitlink "$rust" "$UPSTREAM_RUST_REV" src/llvm-project)" \
    "$RUST_LLVM_BASE_REV" "upstream Rust LLVM gitlink mismatch" || return
  toolchain_expect_equal \
    "$(toolchain_gitlink "$rust" "$MOTOR_RUST_REV" src/llvm-project)" \
    "$MOTOR_LLVM_REV" "Motor Rust LLVM gitlink mismatch" || return
  toolchain_expect_equal \
    "$(toolchain_gitlink "$rust" "$UPSTREAM_RUST_REV" src/tools/cargo)" \
    "$UPSTREAM_CARGO_REV" "upstream Rust Cargo gitlink mismatch" || return
  toolchain_expect_equal \
    "$(toolchain_gitlink "$rust" "$MOTOR_RUST_REV" src/tools/cargo)" \
    "$MOTOR_CARGO_REV" "Motor Rust Cargo gitlink mismatch" || return
  toolchain_expect_equal \
    "$(toolchain_stage0_revision "$rust" "$UPSTREAM_RUST_REV")" \
    "$UPSTREAM_STAGE0_REV" "upstream Stage 0 mismatch" || return
  toolchain_expect_equal \
    "$(toolchain_stage0_revision "$rust" "$MOTOR_RUST_REV")" \
    "$UPSTREAM_STAGE0_REV" "Motor Rust Stage 0 mismatch" || return
  value="$(sha256sum "$rust/Cargo.lock" | awk '{print $1}')"
  toolchain_expect_equal "$value" "$MOTOR_RUST_ROOT_LOCK_SHA256" \
    "Rust root lock hash mismatch" || return
  value="$(sha256sum "$rust/library/Cargo.lock" | awk '{print $1}')"
  toolchain_expect_equal "$value" "$MOTOR_RUST_LIBRARY_LOCK_SHA256" \
    "Rust library lock hash mismatch" || return
  toolchain_assert_clean "$rust" || return
  toolchain_assert_clean "$llvm" || return
  toolchain_assert_clean "$rust/src/tools/cargo" || return
  toolchain_verify_exact_submodule "$rust" library/backtrace \
    "$RUST_BACKTRACE_REPOSITORY" || return
  toolchain_verify_exact_submodule "$rust" src/doc/book \
    "$RUST_BOOK_REPOSITORY" || return
  toolchain_verify_exact_submodule "$rust" src/doc/reference \
    "$RUST_REFERENCE_REPOSITORY"
}
