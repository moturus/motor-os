#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-versions.sh"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-bootstrap.sh"
. "$ROOT_DIR/src/toolchain-state.sh"

fail() {
	echo "test-toolchain-state: $*" >&2
	exit 1
}

select_managed_identity() {
	MOTOR_SOURCE_MODE=managed
	SELECTED_RUSTUP_TOOLCHAIN_BASE="$MOTOR_RUSTUP_TOOLCHAIN_BASE"
	SELECTED_TOOLCHAIN_DESCRIPTION="$MOTOR_TOOLCHAIN_ID"
	SELECTED_UPSTREAM_RUST_REV="$UPSTREAM_RUST_REV"
	SELECTED_RUST_VERSION="$UPSTREAM_RUST_VERSION"
	SELECTED_STAGE0_REV="$UPSTREAM_STAGE0_REV"
	SELECTED_RUST_LLVM_BASE_REV="$RUST_LLVM_BASE_REV"
	SELECTED_MOTOR_CARGO_VERSION="$MOTOR_CARGO_VERSION"
	SELECTED_MOTOR_CARGO_REV="$MOTOR_CARGO_REV"
	EFFECTIVE_MOTOR_RUST_REV="$MOTOR_RUST_REV"
	EFFECTIVE_MOTOR_LLVM_REV="$MOTOR_LLVM_REV"
	MOTOR_RUST_TREE_STATE=clean
	MOTOR_LLVM_TREE_STATE=clean
	AUTHORING_SOURCE_DIGEST=none
}

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
rust="$temporary/rust"
prefix="$temporary/prefix"
mkdir -p "$rust/library" "$prefix"
printf 'root lock one\n' > "$rust/Cargo.lock"
printf 'library lock one\n' > "$rust/library/Cargo.lock"

select_managed_identity
toolchain_capture_starting_locks "$rust"
toolchain_derive_identity
first_key="$MOTOR_TOOLCHAIN_KEY"
[[ "$MOTOR_RUSTUP_TOOLCHAIN" == "$MOTOR_RUSTUP_TOOLCHAIN_BASE-$first_key" ]] ||
	fail "derived rustup name is not synchronized with the key"
[ "$first_key" = "$(toolchain_key)" ] || fail "dynamic key is not deterministic"

original_assertions="$MOTOR_STANDALONE_LLVM_ASSERTIONS"
MOTOR_STANDALONE_LLVM_ASSERTIONS=ON
toolchain_derive_identity
[ "$MOTOR_TOOLCHAIN_KEY" != "$first_key" ] ||
	fail "standalone LLVM configuration did not re-key dynamic identity"
MOTOR_STANDALONE_LLVM_ASSERTIONS="$original_assertions"
toolchain_derive_identity
[ "$MOTOR_TOOLCHAIN_KEY" = "$first_key" ] ||
	fail "restored standalone LLVM configuration did not restore identity"

# A locally selected source stack cannot collide with the managed tuple even
# when it starts from the same lockfiles.
MOTOR_SOURCE_MODE=authoring
SELECTED_RUSTUP_TOOLCHAIN_BASE="motor-authoring-$UPSTREAM_RUST_VERSION-${UPSTREAM_RUST_REV:0:12}"
AUTHORING_SOURCE_DIGEST="$(printf authoring-tree | sha256sum | awk '{print $1}')"
SELECTED_TOOLCHAIN_DESCRIPTION="$UPSTREAM_RUST_VERSION-motor+authoring.$AUTHORING_SOURCE_DIGEST"
toolchain_derive_identity
[ "$MOTOR_TOOLCHAIN_KEY" != "$first_key" ] || fail "authoring tuple reused managed key"
select_managed_identity
toolchain_derive_identity

printf 'library lock two\n' > "$rust/library/Cargo.lock"
if toolchain_check_postbuild_locks "$rust" "$prefix" 2>/dev/null; then
	fail "a lock rewrite was accepted"
fi
[ -f "$prefix/MOTOR-TOOLCHAIN-REJECTED" ] || fail "rejected prefix has no marker"
grep -q "$START_RUST_LIBRARY_LOCK_SHA256.*$POST_RUST_LIBRARY_LOCK_SHA256" \
	"$prefix/MOTOR-TOOLCHAIN-REJECTED" || fail "rejection omits lock identities"
[ ! -e "$temporary/rustup-link" ] || fail "rejected prefix was linked"

# The next run starts with the new lock and therefore selects a fresh key.
next_prefix="$temporary/next-prefix"
mkdir "$next_prefix"
toolchain_capture_starting_locks "$rust"
toolchain_derive_identity
[ "$MOTOR_TOOLCHAIN_KEY" != "$first_key" ] || fail "rewritten lock did not re-key"
toolchain_check_postbuild_locks "$rust" "$next_prefix" ||
	fail "unchanged post-build locks were rejected"
[ ! -e "$next_prefix/MOTOR-TOOLCHAIN-REJECTED" ] ||
	fail "unchanged prefix was marked rejected"

echo "test-toolchain-state PASS"
