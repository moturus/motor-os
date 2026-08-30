#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-versions.sh"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-bootstrap.sh"

fail() {
	echo "test-toolchain-bootstrap: $*" >&2
	exit 1
}

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
rust_source="$temporary/rust"
mkdir -p "$rust_source"

managed="$temporary/state/managed.toml"
toolchain_generate_bootstrap_config "$managed" "$rust_source" \
	"$temporary/toolchains/managed" "$temporary/sysroot" \
	"$temporary/llvm/bin" "$MOTOR_TOOLCHAIN_ID"

expected_keys='change-id profile host target description submodules extended tools docs optimized-compiler-builtins locked-deps prefix sysconfdir channel omit-git-hash deny-warnings incremental download-ci-llvm targets experimental-targets static-libstdcpp llvm-config cc cxx ar ranlib linker'
actual_keys="$(sed -n 's/^[[:space:]]*\([A-Za-z][A-Za-z0-9_-]*\)[[:space:]]*=.*/\1/p' "$managed" | tr '\n' ' ' | sed 's/ $//')"
[ "$actual_keys" = "$expected_keys" ] ||
	fail "bootstrap schema differs: $actual_keys"

for section in '[build]' '[install]' '[rust]' '[llvm]' \
	'[target.x86_64-unknown-linux-gnu]' '[target.x86_64-unknown-motor]'; do
	grep -Fqx "$section" "$managed" || fail "missing section $section"
done
grep -Fqx 'profile = "library"' "$managed" || fail "wrong profile"
grep -Fqx 'tools = ["cargo", "clippy", "rust-analyzer", "rustdoc", "rustfmt", "src"]' "$managed" ||
	fail "wrong bootstrap tools"
grep -Fqx 'description = "'"$MOTOR_TOOLCHAIN_ID"'"' "$managed" ||
	fail "managed description is missing"
grep -Fqx 'incremental = false' "$managed" ||
	fail "incremental compiler build was enabled"
grep -Fqx 'llvm-config = "'"$temporary/llvm/bin/llvm-config"'"' "$managed" ||
	fail "host rustc does not use the standalone LLVM"

# Existing generated state is reusable only when it is byte-for-byte exact.
before="$(sha256sum "$managed")"
toolchain_generate_bootstrap_config "$managed" "$rust_source" \
	"$temporary/toolchains/managed" "$temporary/sysroot" \
	"$temporary/llvm/bin" "$MOTOR_TOOLCHAIN_ID"
[ "$(sha256sum "$managed")" = "$before" ] || fail "exact config changed"
printf '\n# stale\n' >> "$managed"
stale="$(sha256sum "$managed")"
if toolchain_generate_bootstrap_config "$managed" "$rust_source" \
	"$temporary/toolchains/managed" "$temporary/sysroot" \
	"$temporary/llvm/bin" "$MOTOR_TOOLCHAIN_ID" 2>/dev/null; then
	fail "mismatched existing config was accepted"
fi
[ "$(sha256sum "$managed")" = "$stale" ] || fail "mismatched config was overwritten"

if toolchain_generate_bootstrap_config "$rust_source/generated.toml" \
	"$rust_source" "$temporary/prefix" "$temporary/sysroot" \
	"$temporary/llvm/bin" "$MOTOR_TOOLCHAIN_ID" 2>/dev/null; then
	fail "configuration inside an authoring checkout was accepted"
fi

authoring_description="$MOTOR_TOOLCHAIN_ID+authoring.$(printf authoring | sha256sum | awk '{print $1}')"
authoring="$temporary/state/authoring.toml"
toolchain_generate_bootstrap_config "$authoring" "$rust_source" \
	"$temporary/toolchains/authoring" "$temporary/sysroot" \
	"$temporary/llvm/bin" "$authoring_description"
grep -Fqx 'description = "'"$authoring_description"'"' "$authoring" ||
	fail "authoring description is missing"
[ "$(toolchain_bootstrap_identity_digest "$MOTOR_TOOLCHAIN_ID")" != \
	"$(toolchain_bootstrap_identity_digest "$authoring_description")" ] ||
	fail "source-mode descriptions have the same identity"

wrapper_root="$temporary/wrapper-sysroot"
toolchain_generate_cross_wrappers "$wrapper_root" "$temporary/llvm/bin"
for wrapper in motor-clang motor-clang++ motor-rust-cc; do
	[ -x "$wrapper_root/bin/$wrapper" ] || fail "missing executable $wrapper"
done
grep -Fq -- '--target=x86_64-unknown-motor' "$wrapper_root/bin/motor-clang" ||
	fail "C wrapper lacks the Motor target"
grep -Fq -- '-lmoto_rt_cabi -lc++ -lc++abi -lunwind -lc' \
	"$wrapper_root/bin/motor-rust-cc" || fail "Rust linker wrapper lacks runtimes"
toolchain_generate_cross_wrappers "$wrapper_root" "$temporary/llvm/bin"
printf '\n# stale\n' >> "$wrapper_root/bin/motor-clang"
if toolchain_generate_cross_wrappers \
	"$wrapper_root" "$temporary/llvm/bin" 2>/dev/null; then
	fail "mismatched cross wrapper was accepted"
fi

# Host locations are placeholders in the identity digest.
digest="$(toolchain_bootstrap_identity_digest "$MOTOR_TOOLCHAIN_ID")"
case "$digest" in
	????????????????????????????????????????????????????????????????) ;;
	*) fail "bootstrap digest is not SHA-256: $digest" ;;
esac

echo "test-toolchain-bootstrap PASS"
