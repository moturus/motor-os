#!/bin/bash
# Prepare pinned sources on Linux. The native tests themselves stay offline.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
release=0
full=0
for option in "$@"; do
  case "$option" in
    --release) release=1 ;;
    --full) full=1 ;;
    *) echo "usage: $0 [--release] [--full]" >&2; exit 2 ;;
  esac
done
inputs="$ROOT_DIR/build/native-test-inputs"
prepare_home="$inputs/home"
source_tree="$inputs/source"
lorry="$ROOT_DIR/src/bin/lorry/target/release/lorry"
mkdir -p "$prepare_home/.config/lorry" "$source_tree"
printf 'use-cargo-registry = false\n' > "$prepare_home/.config/lorry/lorry.toml"
cat "$ROOT_DIR/img_files/motor-toolchain/user/cfg/lorry.toml" \
  >> "$prepare_home/.config/lorry/lorry.toml"
cat >> "$prepare_home/.config/lorry/lorry.toml" <<EOF

[repositories]
user = "$inputs/vendor"
[cache]
directory = "$inputs/cache"
EOF

cd "$ROOT_DIR"
cargo build --locked --offline --release --manifest-path src/bin/lorry/Cargo.toml
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
RUSTC="$(rustup which rustc)"
export RUSTC

# Exercise the exact crossterm revision selected by Rush, including the fork's
# own development dependencies. Never write into Cargo's checkout.
crossterm_source="$(cargo metadata --locked --offline --format-version 1 \
  --manifest-path src/bin/rush/Cargo.toml |
  jq -er '[.packages[] | select(.name == "crossterm") | .manifest_path] | if length == 1 then .[0] else error("ambiguous crossterm") end')"
crossterm_source="${crossterm_source%/Cargo.toml}"
crossterm_revision="$(git -C "$crossterm_source" rev-parse HEAD)"
crossterm="$ROOT_DIR/build/crossterm-host/source"
if [ ! -f "$crossterm/.prepared-revision" ] ||
    [ "$(cat "$crossterm/.prepared-revision")" != "$crossterm_revision" ]; then
  mkdir -p "${crossterm%/*}"
  staging="$(mktemp -d "${crossterm%/*}/.source.XXXXXX")"
  git -C "$crossterm_source" archive HEAD | tar -xf - -C "$staging"
  cargo fetch --locked --manifest-path "$staging/Cargo.toml"
  printf '%s\n' "$crossterm_revision" > "$staging/.prepared-revision"
  rm -rf "$crossterm"
  mv "$staging" "$crossterm"
fi

# Include unstaged edits and new, nonignored files; omit tracked deletions.
git ls-files --cached --others --exclude-standard -z > "$inputs/candidates"
while IFS= read -r -d '' path; do
  if [ -e "$path" ] || [ -L "$path" ]; then printf '%s\0' "$path"; fi
done < "$inputs/candidates" > "$inputs/files"
tar --null --no-recursion -T "$inputs/files" -cf "$inputs/working-tree.tar"
staging="$(mktemp -d "$inputs/.source.XXXXXX")"
tar -xf "$inputs/working-tree.tar" -C "$staging"
mkdir -p "$staging/build/crossterm-host"
mkdir "$staging/build/crossterm-host/source"
tar -C "$crossterm" --exclude=./target --exclude=./.lorry -cf - . |
  tar -xf - -C "$staging/build/crossterm-host/source"
if [ "$full" = 1 ]; then
  helix="$ROOT_DIR/external-sources/helix"
  [ -f "$helix/Cargo.toml" ] || { echo 'missing pinned Helix checkout' >&2; exit 1; }
  mkdir -p "$staging/external-sources/helix"
  git -C "$helix" archive HEAD | tar -xf - -C "$staging/external-sources/helix"
fi

# Preserve only prepared Git objects when replacing the snapshot. Each fetch
# verifies their provenance against the current lockfile before using them.
if [ -d "$source_tree" ]; then
  while IFS= read -r -d '' git_sources; do
    relative="${git_sources#"$source_tree/"}"
    mkdir -p "$staging/${relative%/*}"
    cp -a "$git_sources" "$staging/${relative%/*}/"
  done < <(find "$source_tree" -type d -path '*/.lorry/vendor/git' -print0 -prune)
fi
rm -r "$source_tree"
mv "$staging" "$source_tree"

"$ROOT_DIR/src/tests/full-native-test.sh" --list > "$inputs/harnesses"
# These Motor-only harnesses belong to the same sys workspace. Fetching a
# workspace takes every locked package, including target-specific dependencies.
printf '%s\n' src/sys/tests/systest src/sys/tools/sysbox src/sys/tests/toolchain \
  src/sys/tests/javy-smoke src/sys/tests/wasmtime-smoke >> "$inputs/harnesses"
[ "$full" != 1 ] || printf '%s\n' external-sources/helix >> "$inputs/harnesses"
: > "$inputs/workspaces"
while read -r crate options; do
  workspace="$(cargo locate-project --workspace --message-format plain \
    --manifest-path "$source_tree/$crate/Cargo.toml")"
  printf '%s\n' "${workspace#"$source_tree/"}"
done < "$inputs/harnesses" | LC_ALL=C sort -u > "$inputs/workspaces"

# Source snapshots change on every run; fetching is needed only when manifests,
# locks or source preparation change. Offline admission verifies all inputs later.
fetch_key="$(cd "$source_tree" && find . -type d \( -name target -o -name .lorry \) -prune -o \
  -type f \( -name Cargo.toml -o -name Cargo.lock -o -path '*/.cargo/config*' \) \
  -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)"
previous_key="$(cat "$inputs/fetch-key" 2>/dev/null || true)"
while IFS= read -r manifest; do
  workspace="${manifest%/Cargo.toml}"
  # Linux runs Cargo as well as Lorry; their dependency stores are separate.
  (cd "$source_tree/$workspace" && cargo fetch --locked)
  if [ "$fetch_key" != "$previous_key" ]; then
    echo "native-test-inputs: fetching locked sources for $workspace"
    env HOME="$prepare_home" "$lorry" fetch --locked \
      --manifest-path "$source_tree/$manifest"
  fi
  git_sources="$source_tree/$workspace/.lorry/vendor/git"
  if [ -d "$git_sources" ]; then
    mkdir -p "$ROOT_DIR/$workspace/.lorry/vendor"
    cp -a "$git_sources" "$ROOT_DIR/$workspace/.lorry/vendor/"
  fi
done < "$inputs/workspaces"
printf '%s\n' "$fetch_key" > "$inputs/fetch-key"
if [ "$full" = 1 ]; then
  tar -C "$source_tree" -cf "$inputs/helix-source.tar" external-sources/helix
fi

if [ "$release" = 1 ]; then
  checkout="$ROOT_DIR/external-sources/quickjs-0.18.0"
  quickjs="$ROOT_DIR/build/assembly/build/quickjs/src"
  [ -f "$quickjs/run-test262.c" ] && [ -d "$checkout/.git" ] || {
    echo 'native-test-inputs: build QuickJS before preparing Test262' >&2; exit 1;
  }
  revision="$(git -C "$checkout" ls-tree HEAD test262 | awk '$2 == "commit" { print $3 }')"
  [ -n "$revision" ] || { echo 'QuickJS pins no Test262 revision' >&2; exit 1; }
  corpus="$ROOT_DIR/external-sources/test262-$revision"
  if [ ! -e "$corpus" ]; then
    git init --quiet "$corpus.part"
    git -C "$corpus.part" fetch --quiet --depth 1 https://github.com/tc39/test262.git "$revision"
    git -C "$corpus.part" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
    mv "$corpus.part" "$corpus"
  fi
  [ "$(git -C "$corpus" rev-parse HEAD)" = "$revision" ] &&
    [ -z "$(git -C "$corpus" status --porcelain)" ] || {
    echo "Test262 checkout differs from $revision" >&2; exit 1;
  }
  (cd "$quickjs" && tar --format=gnu -cf "$inputs/quickjs-source.tar" \
    run-test262.c test262.conf test262_errors.txt ./*.h)
  tar --format=gnu -C "$corpus" --transform 's,^,test262/,' -cf - harness test |
    zstd -q -f -o "$inputs/quickjs-test262.tar.zst"
fi

# Interactive extraction preserves its own execute bits. The guest installer
# uses this list to restore None's execute bits on verified repository sources.
find "$inputs/vendor" -type f -perm /111 -printf '%P\n' | LC_ALL=C sort \
  > "$inputs/vendor-executables"
echo "native-test-inputs: prepared $source_tree and $inputs/vendor"
