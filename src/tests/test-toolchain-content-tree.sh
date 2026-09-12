#!/usr/bin/env bash
# Keep the fast serializer byte-compatible with the bootstrap implementation.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
for helper in lib sources assembly; do . "$ROOT_DIR/src/toolchain-$helper.sh"; done
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
fail() { echo "test-toolchain-content-tree: $*" >&2; exit 1; }
compiler="$(rustup which rustc)"
source="$ROOT_DIR/src/toolchain-content-tree/src/main.rs"
"$compiler" --edition=2021 --test "$source" -o "$temporary/tests"
"$temporary/tests"
"$compiler" --edition=2021 "$source" -o "$temporary/serialize"
mkdir -p "$temporary/tree/empty" "$temporary/tree/sub"
root="$temporary/tree"
printf '\0\377binary\n' > "$root/data"
printf 'executable\n' > "$root/sub/program"
chmod +x "$root/sub/program"
printf 'odd path\n' > "$root/$(printf 'space é\n\377')"
printf 'empty content' > "$root/-option"
: > "$root/empty-file"
ln -s $'missing\n\377' "$root/dangling"
ln -s sub "$root/directory-link"

# Compare the emitted bytes directly, not just their final SHA-256.
: > "$temporary/entries"
: > "$temporary/expected"
while IFS= read -r -d '' path; do
  relative="${path#"$root"/}"
  if [ -L "$path" ]; then
    kind=symlink; mode=120000; content="$temporary/link"
    readlink -n "$path" > "$content"
  else
    kind=file; mode=100644; content="$path"
    if [ -x "$path" ]; then mode=100755; fi
  fi
  printf '%s\0' "$path" "$relative" "$kind" "$mode" >> "$temporary/entries"
  toolchain_serialize_pairs path "$relative" kind "$kind" mode "$mode" >> "$temporary/expected"
  toolchain_emit_file_field content "$content" >> "$temporary/expected"
done < <(find "$root" \( -type f -o -type l \) -print0 | LC_ALL=C sort -zu)
"$temporary/serialize" < "$temporary/entries" > "$temporary/actual"
cmp "$temporary/expected" "$temporary/actual"

legacy_digest() (
  rustup() { return 1; }
  toolchain_content_tree_digest "$@"
)
compare() {
  local fast slow
  fast="$(toolchain_content_tree_digest "$root" "$@")"
  slow="$(legacy_digest "$root" "$@")"
  [ "$fast" = "$slow" ] || fail 'fast and bootstrap digests differ'
}
compare .
compare sub data sub directory-link dangling empty
compare . sub ./sub
compare
original="$(toolchain_content_tree_digest "$root" .)"
printf 'changed' >> "$root/data"
[ "$original" != "$(toolchain_content_tree_digest "$root" .)" ] || fail 'content change missed'
compare .
original="$(toolchain_content_tree_digest "$root" .)"
chmod -x "$root/sub/program"
[ "$original" != "$(toolchain_content_tree_digest "$root" .)" ] || fail 'mode change missed'
compare .

for implementation in toolchain_content_tree_digest legacy_digest; do
  if "$implementation" "$root" missing > /dev/null 2>&1; then fail 'missing input accepted'; fi
  mkfifo "$root/fifo"
  if "$implementation" "$root" . > /dev/null 2>&1; then fail 'FIFO accepted'; fi
  rm "$root/fifo"
  chmod 000 "$root/data"
  if [ ! -r "$root/data" ] && "$implementation" "$root" data > /dev/null 2>&1; then
    fail 'unreadable input accepted'
  fi
  chmod 644 "$root/data"
done
# A selected compiler failure must not silently use the bootstrap path.
if (
  rustup() { printf '%s\n' /bin/false; }
  toolchain_content_tree_digest "$root" .
) > /dev/null 2>&1; then fail 'compiler failure swallowed'; fi

# A changed file type must fail before the helper attempts to read it.
printf '%s\0' "$root/dangling" dangling file 100644 > "$temporary/bad"
if "$temporary/serialize" < "$temporary/bad" > /dev/null 2>&1; then fail 'changed kind accepted'; fi
echo 'test-toolchain-content-tree PASS'
