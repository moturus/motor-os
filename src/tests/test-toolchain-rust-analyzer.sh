#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
for helper in lib sources assembly patched-crates bootstrap runtime rust-analyzer; do
	. "$ROOT_DIR/src/toolchain-$helper.sh"
done
. "$ROOT_DIR/src/patches/crates.sh"
fail() { echo "test-toolchain-rust-analyzer: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
rust="$temporary/rust"
config="$temporary/external state/patches.toml"
url="$temporary/prepared sources/url"
inventory="$temporary/prepared sources/inventory"
mkdir -p "$rust" "$url" "$inventory"
toolchain_generate_rust_analyzer_config "$config" "$rust" "$url" "$inventory"
expected="$(printf '[patch.crates-io]\nurl = { path = "%s" }\ninventory = { path = "%s" }' \
	"$url" "$inventory")"
[ "$(cat "$config")" = "$expected" ] || fail 'config has unexpected fields'
[ "$(stat -c %a "$config")" = 644 ] || fail 'config permissions differ'
toolchain_generate_rust_analyzer_config "$config" "$rust" "$url" "$inventory"
[ "$(cat "$config")" = "$expected" ] || fail 'exact config changed'

# Reject stale state, source-tree writes (also through aliases), and TOML injection.
if toolchain_generate_rust_analyzer_config "$config" "$rust" "$url/changed" \
	"$inventory" 2>/dev/null; then fail 'stale config accepted'; fi
[ "$(cat "$config")" = "$expected" ] || fail 'stale config overwritten'
ln -s "$rust" "$temporary/alias"
for destination in "$rust/.cargo/config.toml" "$temporary/alias/generated.toml"; do
	if toolchain_generate_rust_analyzer_config "$destination" "$rust" "$url" \
		"$inventory" 2>/dev/null; then fail 'source-tree config accepted'; fi
	[ ! -e "$destination" ] || fail 'rejected source-tree config written'
done
ln -s "$config" "$temporary/config-link"
if toolchain_generate_rust_analyzer_config "$temporary/config-link" "$rust" \
	"$url" "$inventory" 2>/dev/null; then fail 'symlink output accepted'; fi
for invalid in relative '/has"quote' '/has\escape' $'/has\nnewline'; do
	if toolchain_render_rust_analyzer_config "$invalid" "$inventory" \
		>/dev/null 2>&1; then fail 'unsafe TOML path accepted'; fi
done

# Offline mode may inspect the cache, but must not attempt network acquisition.
curl() { fail 'offline preparation attempted the network'; }
if toolchain_rust_analyzer_crate "$ROOT_DIR" "$temporary/empty" \
	"$temporary/no-cargo" url false >"$temporary/out" 2>"$temporary/error"; then
	fail 'missing offline archive accepted'
fi
grep -q 'missing offline archive: url' "$temporary/error" || fail 'wrong offline failure'
[ ! -e "$temporary/empty" ] || fail 'offline miss created provisioning state'

# Model the network acquisition with a local archive; no test uses the Internet.
fixture="$temporary/fixture"
mkdir -p "$fixture/url-2.5.8" "$fixture/src/patches"
printf '[package]\nname = "url"\nversion = "2.5.8"\n' > "$fixture/url-2.5.8/Cargo.toml"
printf 'before\n' > "$fixture/url-2.5.8/source"
tar -czf "$fixture/upstream.crate" -C "$fixture" url-2.5.8
printf '%s\n' '--- a/source' '+++ b/source' '@@ -1 +1 @@' '-before' '+after' \
	> "$fixture/src/patches/url-2.5.8-motor.patch"
printf 'after\n' > "$fixture/url-2.5.8/source"
MOTOR_URL_CHECKSUM="$(sha256sum "$fixture/upstream.crate" | awk '{print $1}')"
MOTOR_URL_TREE_SHA256="$(toolchain_content_tree_digest "$fixture/url-2.5.8" .)"
curl() {
	[ "$*" = "--fail --location --proto =https --proto-redir =https https://static.crates.io/crates/url/url-2.5.8.crate -o $9" ] ||
		fail 'unexpected acquisition arguments'
	printf x >> "$fixture/downloads"
	cp "$fixture/upstream.crate" "$9"
}
source="$(toolchain_rust_analyzer_crate "$fixture" "$temporary/acquired" \
	"$temporary/no-cargo" url true)"
[ "$(cat "$source/source")" = after ] || fail 'archive was not patched'
[ "$(cat "$fixture/downloads")" = x ] || fail 'archive was not acquired once'
reused="$(toolchain_rust_analyzer_crate "$fixture" "$temporary/acquired" \
	"$temporary/no-cargo" url false)"
[ "$source" = "$reused" ] || fail 'offline reuse changed the source'
[ "$(cat "$fixture/downloads")" = x ] || fail 'offline reuse downloaded'
MOTOR_URL_TREE_SHA256="$(printf wrong | sha256sum | awk '{print $1}')"
if toolchain_rust_analyzer_crate "$fixture" "$temporary/acquired" \
	"$temporary/no-cargo" url false >/dev/null 2>&1; then
	fail 'incorrect declared tree digest accepted'
fi
[ "$(cat "$source/source")" = after ] || fail 'tree mismatch overwrote the source'
MOTOR_URL_CHECKSUM="$(printf wrong | sha256sum | awk '{print $1}')"
if toolchain_rust_analyzer_crate "$fixture" "$temporary/corrupt" \
	"$temporary/no-cargo" url true >/dev/null 2>&1; then
	fail 'incorrect archive checksum accepted'
fi
[ -z "$(find "$temporary/corrupt" -type f -print -quit)" ] ||
	fail 'unverified download was retained'

echo 'test-toolchain-rust-analyzer PASS'
