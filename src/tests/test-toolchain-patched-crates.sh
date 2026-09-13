#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-sources.sh"
. "$ROOT_DIR/src/toolchain-assembly.sh"
. "$ROOT_DIR/src/toolchain-patched-crates.sh"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT
fail() { echo "test-toolchain-patched-crates: $*" >&2; exit 1; }

mkdir -p "$TMP_ROOT/input/demo-1.0.0"
printf '[package]\nname = "demo"\nversion = "1.0.0"\n' > "$TMP_ROOT/input/demo-1.0.0/Cargo.toml"
printf 'upstream\n' > "$TMP_ROOT/input/demo-1.0.0/lib.rs"
printf 'upstream license\n' > "$TMP_ROOT/input/demo-1.0.0/LICENSE"
printf '%s\n' '--- a/lib.rs' '+++ b/lib.rs' '@@ -1 +1 @@' '-upstream' '+motor' > "$TMP_ROOT/motor.patch"
tar -czf "$TMP_ROOT/demo.crate" -C "$TMP_ROOT/input" demo-1.0.0
checksum="$(sha256sum "$TMP_ROOT/demo.crate" | awk '{print $1}')"
prepare() {
	toolchain_prepare_patched_crate "$TMP_ROOT/prepared" demo 1.0.0 "$checksum" \
		"$TMP_ROOT/demo.crate" "$TMP_ROOT/motor.patch"
}
rejected() {
	if prepare > "$TMP_ROOT/output" 2> "$TMP_ROOT/error"; then fail "$1"; fi
}

source="$(prepare)"
[ "$(<"$source/lib.rs")" = motor ] || fail "patch not applied"
cmp "$source/LICENSE" "$TMP_ROOT/input/demo-1.0.0/LICENSE"
[ "$(<"$TMP_ROOT/input/demo-1.0.0/lib.rs")" = upstream ] || fail "upstream changed"
[ "$(prepare)" = "$source" ] || fail "reuse changed the path"
printf 'local edit\n' >> "$source/lib.rs"
rejected "modified tree accepted"
grep -q 'preserving' "$TMP_ROOT/error" || fail "missing preservation diagnostic"
grep -q 'local edit' "$source/lib.rs" || fail "local change overwritten"

# The patch is an identity input, so a different patch gets a different tree.
printf '%s\n' '--- a/lib.rs' '+++ b/lib.rs' '@@ -1 +1 @@' '-upstream' '+motor2' > "$TMP_ROOT/motor.patch"
second="$(prepare)"
[ "$source" != "$second" ] || fail "patch not keyed"
printf 'extra\n' > "$second/untracked"
rejected "extra source file accepted"
rm "$second/untracked"
chmod +x "$second/lib.rs"
rejected "changed executable mode accepted"
chmod -x "$second/lib.rs"
ln -s lib.rs "$second/link"
rejected "extra source symlink accepted"
rm "$second/link"

printf '%s\n' '--- a/lib.rs' '+++ b/lib.rs' '@@ -1 +1 @@' '-wrong context' '+motor' > "$TMP_ROOT/motor.patch"
rejected "mismatched patch accepted"
[ "$(find "$TMP_ROOT/prepared" -maxdepth 1 -name '.prepare.*' | wc -l)" = 0 ] || fail "failed staging leaked"
checksum="$(printf wrong | sha256sum | awk '{print $1}')"
rejected "incorrect checksum accepted"

ln -s /tmp "$TMP_ROOT/input/demo-1.0.0/link"
tar -czf "$TMP_ROOT/demo.crate" -C "$TMP_ROOT/input" demo-1.0.0
checksum="$(sha256sum "$TMP_ROOT/demo.crate" | awk '{print $1}')"
rejected "archive symlink accepted"
grep -q 'link or special file' "$TMP_ROOT/error" || fail "wrong archive rejection"
rm "$TMP_ROOT/input/demo-1.0.0/link"
ln "$TMP_ROOT/input/demo-1.0.0/lib.rs" "$TMP_ROOT/input/demo-1.0.0/hardlink"
tar -czf "$TMP_ROOT/demo.crate" -C "$TMP_ROOT/input" demo-1.0.0
checksum="$(sha256sum "$TMP_ROOT/demo.crate" | awk '{print $1}')"
rejected "archive hardlink accepted"
grep -q 'link or special file' "$TMP_ROOT/error" || fail "wrong hardlink rejection"
rm "$TMP_ROOT/input/demo-1.0.0/hardlink"
tar -czf "$TMP_ROOT/demo.crate" --transform='s@lib.rs@../escape@' \
	-C "$TMP_ROOT/input" demo-1.0.0
checksum="$(sha256sum "$TMP_ROOT/demo.crate" | awk '{print $1}')"
rejected "archive traversal accepted"
grep -q 'noncanonical crate archive path' "$TMP_ROOT/error" || fail "wrong traversal rejection"
printf invalid > "$TMP_ROOT/demo.crate"
checksum="$(sha256sum "$TMP_ROOT/demo.crate" | awk '{print $1}')"
rejected "invalid archive accepted"
echo 'test-toolchain-patched-crates PASS'
