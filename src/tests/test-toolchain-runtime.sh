#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-versions.sh"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-runtime.sh"

fail() { echo "test-toolchain-runtime: $*" >&2; exit 1; }

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
rust="$temporary/rust"
local_package="$temporary/local"
mkdir -p "$rust/library" "$local_package/src"
write_lock() {
	printf 'version = 4\n\n[[package]]\nname = "moto-rt"\nversion = "%s"\nsource = "%s"\nchecksum = "%s"\n' \
		"$1" "$2" "$3" > "$rust/library/Cargo.lock"
}
set_local_version() {
	printf '[package]\nname = "moto-rt"\nversion = "%s"\n' "$1" > "$local_package/Cargo.toml"
}
registry=registry+https://github.com/rust-lang/crates.io-index
std_version=0.17.6
std_checksum="$(printf moto-rt | sha256sum | awk '{print $1}')"
write_lock "$std_version" "$registry" "$std_checksum"
compat="$(toolchain_compat_version "$std_version")"

[ "$(toolchain_compat_version 0.17.6)" = 0.17 ] || fail "0.x major version is wrong"
[ "$(toolchain_compat_version 2.3.1)" = 2 ] || fail "major version is wrong"
if toolchain_compat_version seventeen 2>/dev/null; then fail "a non-version was accepted"; fi

# The local runtime may differ from std's below the major version, and its
# content is never compared with the published crate.
for version in "$std_version" "$compat.0" "$compat.999"; do
	set_local_version "$version"
	printf 'local edit %s\n' "$version" > "$local_package/src/lib.rs"
	toolchain_check_moto_rt_compat "$rust" "$local_package" ||
		fail "compatible local moto-rt $version was rejected"
done
[ "$LOCKED_MOTO_RT_VERSION" = "$std_version" ] || fail "std moto-rt version was not recorded"
[ "$LOCKED_MOTO_RT_CHECKSUM" = "$std_checksum" ] || fail "std moto-rt checksum was not recorded"

set_local_version 0.0.1
if toolchain_check_moto_rt_compat "$rust" "$local_package" 2> "$temporary/stderr"; then
	fail "a local moto-rt of another major version was accepted"
fi
grep -q 'differ in their major version' "$temporary/stderr" ||
	fail "the major version mismatch was not named"
set_local_version "$std_version"

# The Rust fork must still take its moto-rt from crates.io.
write_lock "$std_version" git+https://example.com/moto-rt "$std_checksum"
if toolchain_check_moto_rt_compat "$rust" "$local_package" 2>/dev/null; then
	fail "a std moto-rt from outside crates.io was accepted"
fi

echo "test-toolchain-runtime PASS"
