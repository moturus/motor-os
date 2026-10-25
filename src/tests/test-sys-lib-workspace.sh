#!/usr/bin/env bash
# The library workspace the developer image stages for native tests:
# src/build-scripts/sys-lib-workspace.sh assembles it offline from the crates
# the image config stages, locked to src/sys/Cargo.lock's dependency versions.

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
fail() { echo "test-sys-lib-workspace: $*" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$ROOT_DIR/src/build-scripts/sys-lib-workspace.sh" --offline "$work/lib"
for crate in moto-rt moto-sys moto-sdk; do
	[ -f "$work/lib/$crate/Cargo.toml" ] || fail "the workspace lacks $crate"
done
# The manifest and the tokio placeholder are the image's static files.
static="$ROOT_DIR/img_files/motor-os-dev/devtools/src/motor-os/sys/lib"
while read -r file; do
	cmp -s "$static/$file" "$work/lib/$file" || fail "$file is not the image's"
done < <(cd "$static" && find . -type f)
[ -z "$(find "$work/lib" \( -name target -o -name .lorry \) -print)" ] ||
	fail "the workspace contains build outputs"

registry_packages() {
	awk '
		/^\[\[package\]\]/ { name = version = source = "" }
		/^name = / { name = $3 }
		/^version = / { version = $3 }
		/^source = / { source = $3 }
		/^checksum = / && source != "" { print name, version, source, $3 }
	' "$1" | LC_ALL=C sort
}
# src/sys locks tokio from Git, so a crates.io tokio in place of the
# placeholder fails here.
locked="$(registry_packages "$work/lib/Cargo.lock")"
[ -n "$locked" ] || fail "the workspace locks no registry package"
different="$(LC_ALL=C comm -23 <(printf '%s\n' "$locked") \
	<(registry_packages "$ROOT_DIR/src/sys/Cargo.lock"))"
[ -z "$different" ] ||
	fail "the workspace locks packages differently from src/sys/Cargo.lock: $different"

if "$ROOT_DIR/src/build-scripts/sys-lib-workspace.sh" --offline "$work/lib" 2>/dev/null; then
	fail "an existing destination was reused"
fi
echo "test-sys-lib-workspace PASS"
