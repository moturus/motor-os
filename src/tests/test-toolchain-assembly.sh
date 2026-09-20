#!/usr/bin/env bash

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
for helper in versions lib sources assembly; do . "$ROOT_DIR/src/toolchain-$helper.sh"; done
fail() { echo "test-toolchain-assembly: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
root="$temporary/motor"; mlibc="$temporary/mlibc"
mkdir -p "$root/src/sys/lib/moto-rt-cabi/src" "$root/src/sys/lib/moto-rt/src" \
	"$root/src/sys/lib/moto-sys/src" "$mlibc"
for repo in "$root" "$mlibc"; do
	git -C "$repo" init -q
	git -C "$repo" config user.email test@example.com
	git -C "$repo" config user.name Test
done
for package in moto-rt moto-rt-cabi moto-sys; do
	version=0.1.0
	printf '[package]\nname = "%s"\nversion = "%s"\n' "$package" "$version" > \
		"$root/src/sys/lib/$package/Cargo.toml"
	printf '%s source\n' "$package" > "$root/src/sys/lib/$package/src/lib.rs"
done
printf '[workspace]\n' > "$root/src/sys/Cargo.toml"
cat > "$root/src/sys/Cargo.lock" <<EOF
version = 4

[[package]]
name = "moto-rt"
version = "0.1.0"

[[package]]
name = "moto-rt-cabi"
version = "0.1.0"

[[package]]
name = "moto-sys"
version = "0.1.0"

[[package]]
name = "unrelated"
version = "1.0.0"
EOF
printf 'mlibc\n' > "$mlibc/source"
git -C "$root" add . && git -C "$root" commit -qm motor
git -C "$mlibc" add . && git -C "$mlibc" commit -qm mlibc

MOTOR_TOOLCHAIN_KEY="$(printf toolchain | sha256sum | awk '{print $1}')"
MOTOR_ASSEMBLY_STATE=clean
export MOTORH="$temporary/output"

toolchain_derive_assembly_identity "$root" "$mlibc"
first_key="$MOTOR_ASSEMBLY_KEY"
toolchain_derive_assembly_identity "$root" "$mlibc"
[ "$MOTOR_ASSEMBLY_KEY" = "$first_key" ] || fail "assembly key is unstable"
# Local runtime versions are no key input: a version bump keeps the assembly.
sed -i 's/version = "0.1.0"/version = "9.9.9"/' "$root/src/sys/lib/moto-sys/Cargo.toml"
git -C "$root" commit -qam 'bump moto-sys'
toolchain_derive_assembly_identity "$root" "$mlibc"
[ "$MOTOR_ASSEMBLY_KEY" = "$first_key" ] || fail "a moto-sys version bump re-keyed the assembly"
original_toolchain_key="$MOTOR_TOOLCHAIN_KEY"
MOTOR_TOOLCHAIN_KEY="$(printf changed-toolchain | sha256sum | awk '{print $1}')"
toolchain_derive_assembly_identity "$root" "$mlibc"
[ "$MOTOR_ASSEMBLY_KEY" != "$first_key" ] ||
	fail "toolchain key did not re-key the assembly"
MOTOR_TOOLCHAIN_KEY="$original_toolchain_key"
toolchain_derive_assembly_identity "$root" "$mlibc"
[ "$MOTOR_ASSEMBLY_KEY" = "$first_key" ] ||
	fail "restored toolchain key did not restore the assembly key"
printf 'unrelated\n' > "$root/README"
toolchain_derive_assembly_identity "$root" "$mlibc"
[ "$MOTOR_ASSEMBLY_KEY" = "$first_key" ] || fail "unrelated source changed assembly"

# No file of this checkout is keyed. A shim edit only marks the producer dirty.
printf 'script edit\n' > "$root/src/build-motor-os.sh"
git -C "$root" add src/build-motor-os.sh
toolchain_derive_assembly_identity "$root" "$mlibc"
[ "$MOTOR_ASSEMBLY_KEY" = "$first_key" ] || fail "build script edit re-keyed assembly"
[ "$MOTOR_ASSEMBLY_STATE" = clean ] || fail "build script edit was marked dirty"
printf 'runtime edit\n' >> "$root/src/sys/lib/moto-rt/src/lib.rs"
toolchain_derive_assembly_identity "$root" "$mlibc"
[ "$MOTOR_ASSEMBLY_KEY" = "$first_key" ] || fail "shim source edit re-keyed assembly"
[ "$MOTOR_ASSEMBLY_STATE" = development-dirty ] || fail "shim source edit was not marked dirty"

# A complete keyed assembly is reusable; partial or changed staging is not.
MOTOR_RUSTUP_TOOLCHAIN=motor-test
MOTOR_SOURCE_MODE=managed
SELECTED_TOOLCHAIN_DESCRIPTION="$MOTOR_TOOLCHAIN_ID"
SELECTED_RUST_VERSION="$UPSTREAM_RUST_VERSION"
SELECTED_UPSTREAM_RUST_REV="$UPSTREAM_RUST_REV"
SELECTED_STAGE0_REV="$UPSTREAM_STAGE0_REV"
SELECTED_RUST_LLVM_BASE_REV="$RUST_LLVM_BASE_REV"
SELECTED_MOTOR_CARGO_VERSION="$MOTOR_CARGO_VERSION"
SELECTED_MOTOR_CARGO_REV="$MOTOR_CARGO_REV"
EFFECTIVE_MOTOR_RUST_REV="$MOTOR_RUST_REV"
EFFECTIVE_MOTOR_LLVM_REV="$MOTOR_LLVM_REV"
MOTOR_RUST_TREE_STATE=clean
MOTOR_LLVM_TREE_STATE=clean
AUTHORING_SOURCE_DIGEST=none
START_RUST_ROOT_LOCK_SHA256="$MOTOR_RUST_ROOT_LOCK_SHA256"
START_RUST_LIBRARY_LOCK_SHA256="$MOTOR_RUST_LIBRARY_LOCK_SHA256"
START_RUST_ANALYZER_LOCK_SHA256="$MOTOR_RUST_ANALYZER_LOCK_SHA256"
RUST_ANALYZER_INPUTS_DIGEST="$(toolchain_rust_analyzer_inputs_digest)"
BOOTSTRAP_CONFIG_DIGEST=test-bootstrap
LOCKED_MOTO_RT_VERSION=0.17.6
LOCKED_MOTO_RT_CHECKSUM="$(printf moto-rt | sha256sum | awk '{print $1}')"
VALIDATED_RUSTC_VERBOSE='rustc test verbose'
VALIDATED_CARGO_VERBOSE='cargo test verbose'
VALIDATED_RUSTFMT_VERSION='rustfmt test version'
VALIDATED_RUST_ANALYZER_VERSION='rust-analyzer test version'
mkdir -p "$ASSEMBLY_SYSROOT/devtools/llvm/lib" \
	"$ASSEMBLY_IMAGE_ROOT/llvm/devtools/llvm/bin" \
	"$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin" \
	"$ASSEMBLY_IMAGE_ROOT/libc/system/cfg/libc"
mkdir -p "$ASSEMBLY_IMAGE_ROOT/rust-analyzer/devtools/rust/bin" \
	"$ASSEMBLY_IMAGE_ROOT/rust-analyzer/devtools/rust/lib/rustlib/src/rust/library/std/src"
printf analyzer > "$ASSEMBLY_IMAGE_ROOT/rust-analyzer/devtools/rust/bin/rust-analyzer"
printf rust-src > "$ASSEMBLY_IMAGE_ROOT/rust-analyzer/devtools/rust/lib/rustlib/src/rust/library/std/src/lib.rs"
printf libc > "$ASSEMBLY_SYSROOT/devtools/llvm/lib/libc.a"
printf cxx > "$ASSEMBLY_SYSROOT/devtools/llvm/lib/libc++.a"
printf shim > "$ASSEMBLY_SYSROOT/devtools/llvm/lib/libmoto_rt_cabi.a"
printf llvm > "$ASSEMBLY_IMAGE_ROOT/llvm/devtools/llvm/bin/llvm"
printf rustc > "$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin/rustc"
printf rustfmt > "$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin/rustfmt"
printf shells > "$ASSEMBLY_IMAGE_ROOT/libc/system/cfg/libc/shells"
mkdir "${ASSEMBLY_ROOT}.building"
toolchain_complete_assembly
for generated in llvm rustc libc rust-analyzer; do
	manifest="$ASSEMBLY_IMAGE_ROOT/$generated/devtools/toolchain/manifest"
	[ -f "$manifest" ] || fail "$generated generated root lacks a manifest"
	cmp -s "$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-MANIFEST" "$manifest" ||
		fail "$generated generated root has the wrong manifest"
done
toolchain_claim_assembly
[ "$TOOLCHAIN_ASSEMBLY_REUSED" = true ] || fail "complete assembly was not reused"
MOTOR_OS_REV=0123456789abcdef0123456789abcdef01234567
toolchain_claim_assembly
[ "$TOOLCHAIN_ASSEMBLY_REUSED" = true ] ||
	fail "unkeyed Motor OS revision prevented assembly reuse"

# Committing the shim sources changes the current state, not the producer's record.
producer_key="$MOTOR_ASSEMBLY_KEY"
producer_manifest_sha256="$(sha256sum "$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-MANIFEST")"
git -C "$root" add . && git -C "$root" commit -qm 'commit shim sources'
MOTOR_ASSEMBLY_STATE=clean
toolchain_derive_assembly_identity "$root" "$mlibc"
[ "$MOTOR_ASSEMBLY_KEY" = "$producer_key" ] || fail "committing inputs re-keyed assembly"
[ "$MOTOR_ASSEMBLY_STATE" = clean ] || fail "committed inputs were not clean"
toolchain_claim_assembly
[ "$TOOLCHAIN_ASSEMBLY_REUSED" = true ] || fail "committed inputs prevented reuse"
[ "$MOTOR_ASSEMBLY_STATE" = clean ] || fail "reuse changed the current source state"
[ "$(sha256sum "$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-MANIFEST")" = "$producer_manifest_sha256" ] ||
	fail "reuse rewrote producer provenance"

manifest="$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-MANIFEST"
cp "$manifest" "$temporary/producer-manifest"
chmod u+w "$manifest"
sed -i 's/^assembly_state=.*/assembly_state=invalid/' "$manifest"
chmod 0444 "$manifest"
if toolchain_claim_assembly 2> "$temporary/invalid-state.log"; then
	fail "invalid producer assembly state was accepted"
fi
grep -q 'invalid producer assembly state' "$temporary/invalid-state.log" ||
	fail "invalid producer assembly state was not diagnosed"
chmod u+w "$manifest"
cp "$temporary/producer-manifest" "$manifest"
chmod 0444 "$manifest"

printf changed >> "$ASSEMBLY_IMAGE_ROOT/llvm/devtools/llvm/bin/llvm"
if toolchain_claim_assembly 2>/dev/null; then
	fail "assembly with changed staging was accepted"
fi
printf llvm > "$ASSEMBLY_IMAGE_ROOT/llvm/devtools/llvm/bin/llvm"
printf changed >> "$ASSEMBLY_IMAGE_ROOT/rust-analyzer/devtools/rust/bin/rust-analyzer"
if toolchain_claim_assembly 2>/dev/null; then fail "changed analyzer was accepted"; fi
printf analyzer > "$ASSEMBLY_IMAGE_ROOT/rust-analyzer/devtools/rust/bin/rust-analyzer"
printf changed >> "$ASSEMBLY_IMAGE_ROOT/rust-analyzer/devtools/rust/lib/rustlib/src/rust/library/std/src/lib.rs"
if toolchain_claim_assembly 2>/dev/null; then fail "changed rust-src was accepted"; fi
printf rust-src > "$ASSEMBLY_IMAGE_ROOT/rust-analyzer/devtools/rust/lib/rustlib/src/rust/library/std/src/lib.rs"
printf changed >> "$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin/rustfmt"
if toolchain_claim_assembly 2>/dev/null; then fail "changed rustfmt was accepted"; fi
printf rustfmt > "$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin/rustfmt"
# Add-on overlays are refreshed in place and are not assembly outputs.
mkdir -p "$ASSEMBLY_IMAGE_ROOT/helix/devtools/helix" "$ASSEMBLY_IMAGE_ROOT/rg/system/bin" \
	"$ASSEMBLY_IMAGE_ROOT/lua/devtools/bin"
printf hx > "$ASSEMBLY_IMAGE_ROOT/helix/devtools/helix/hx"
printf rg > "$ASSEMBLY_IMAGE_ROOT/rg/system/bin/rg"
printf lua > "$ASSEMBLY_IMAGE_ROOT/lua/devtools/bin/lua"
toolchain_claim_assembly
[ "$TOOLCHAIN_ASSEMBLY_REUSED" = true ] || fail "an add-on overlay prevented assembly reuse"
printf changed >> "$ASSEMBLY_IMAGE_ROOT/rg/system/bin/rg"
toolchain_claim_assembly
[ "$TOOLCHAIN_ASSEMBLY_REUSED" = true ] || fail "a rebuilt add-on prevented assembly reuse"
chmod u+w "$ASSEMBLY_IMAGE_ROOT/libc/devtools/toolchain/manifest"
printf changed >> "$ASSEMBLY_IMAGE_ROOT/libc/devtools/toolchain/manifest"
if toolchain_claim_assembly 2>/dev/null; then
	fail "assembly with a changed generated-root manifest was accepted"
fi
cp "$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-MANIFEST" \
	"$ASSEMBLY_IMAGE_ROOT/libc/devtools/toolchain/manifest"
chmod 0444 "$ASSEMBLY_IMAGE_ROOT/libc/devtools/toolchain/manifest"
SELECTED_MOTOR_CARGO_REV=wrong
if toolchain_claim_assembly 2>/dev/null; then
	fail "assembly with a changed Cargo identity was accepted"
fi

echo "test-toolchain-assembly PASS"
