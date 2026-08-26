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
	printf '[package]\nname = "%s"\nversion = "0.1.0"\n' "$package" > \
		"$root/src/sys/lib/$package/Cargo.toml"
	printf '%s source\n' "$package" > "$root/src/sys/lib/$package/src/lib.rs"
done
printf '[workspace]\n' > "$root/src/sys/Cargo.toml"
cat > "$root/src/sys/Cargo.lock" <<'EOF'
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

MOTOR_OS_RUNTIME_INPUTS=(src/sys/Cargo.toml src/sys/lib/moto-rt \
	src/sys/lib/moto-rt-cabi src/sys/lib/moto-sys)
MOTOR_TOOLCHAIN_KEY="$(printf toolchain | sha256sum | awk '{print $1}')"
MOTOR_ASSEMBLY_STATE=clean
export MOTORH="$temporary/output"
fake_cargo="$temporary/cargo"
cat > "$fake_cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'moto-rt-cabi v0.1.0 (/source)' \
  'moto-rt v0.1.0 (/source)' 'moto-sys v0.1.0 (/source)' \
  'moto-rt v0.1.0 (/source) (*)'
EOF
chmod +x "$fake_cargo"

toolchain_derive_assembly_identity "$root" "$mlibc" "$fake_cargo"
first_key="$MOTOR_ASSEMBLY_KEY"; first_tree="$MOTOR_OS_RUNTIME_TREE"
toolchain_derive_assembly_identity "$root" "$mlibc" "$fake_cargo"
[ "$MOTOR_ASSEMBLY_KEY" = "$first_key" ] || fail "assembly key is unstable"
printf 'unrelated\n' > "$root/README"
toolchain_derive_assembly_identity "$root" "$mlibc" "$fake_cargo"
[ "$MOTOR_ASSEMBLY_KEY" = "$first_key" ] || fail "unrelated source changed assembly"

sed -i 's/version = "1.0.0"/version = "2.0.0"/' "$root/src/sys/Cargo.lock"
toolchain_derive_assembly_identity "$root" "$mlibc" "$fake_cargo"
[ "$MOTOR_OS_RUNTIME_TREE" = "$first_tree" ] || fail "unrelated lock entry changed runtime"
[ "$MOTOR_ASSEMBLY_KEY" = "$first_key" ] || fail "unrelated lock entry re-keyed assembly"

printf 'runtime edit\n' >> "$root/src/sys/lib/moto-rt/src/lib.rs"
toolchain_derive_assembly_identity "$root" "$mlibc" "$fake_cargo"
[ "$MOTOR_ASSEMBLY_KEY" != "$first_key" ] || fail "runtime edit did not re-key assembly"
[ "$MOTOR_TOOLCHAIN_KEY" = "$(printf toolchain | sha256sum | awk '{print $1}')" ] ||
	fail "runtime edit changed the toolchain key"
[ "$MOTOR_ASSEMBLY_STATE" = development-dirty ] || fail "runtime edit was not marked dirty"

# A complete keyed assembly is reusable; partial or changed staging is not.
MOTOR_RUSTUP_TOOLCHAIN=motor-test
MOTOR_SOURCE_MODE=managed
EFFECTIVE_MOTOR_RUST_REV="$MOTOR_RUST_REV"
EFFECTIVE_MOTOR_LLVM_REV="$MOTOR_LLVM_REV"
mkdir -p "$ASSEMBLY_SYSROOT/devtools/llvm/lib" \
	"$ASSEMBLY_IMAGE_ROOT/llvm/devtools/llvm/bin" \
	"$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin" \
	"$ASSEMBLY_IMAGE_ROOT/rg/system/bin" \
	"$ASSEMBLY_IMAGE_ROOT/libc/system/cfg/libc"
printf libc > "$ASSEMBLY_SYSROOT/devtools/llvm/lib/libc.a"
printf cxx > "$ASSEMBLY_SYSROOT/devtools/llvm/lib/libc++.a"
printf shim > "$ASSEMBLY_SYSROOT/devtools/llvm/lib/libmoto_rt_cabi.a"
printf llvm > "$ASSEMBLY_IMAGE_ROOT/llvm/devtools/llvm/bin/llvm"
printf rustc > "$ASSEMBLY_IMAGE_ROOT/rustc/devtools/rust/bin/rustc"
printf rg > "$ASSEMBLY_IMAGE_ROOT/rg/system/bin/rg"
printf shells > "$ASSEMBLY_IMAGE_ROOT/libc/system/cfg/libc/shells"
mkdir "${ASSEMBLY_ROOT}.building"
toolchain_complete_assembly
for generated in llvm rustc rg libc; do
	manifest="$ASSEMBLY_IMAGE_ROOT/$generated/devtools/toolchain/manifest"
	[ -f "$manifest" ] || fail "$generated generated root lacks a manifest"
	cmp -s "$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-MANIFEST" "$manifest" ||
		fail "$generated generated root has the wrong manifest"
done
toolchain_claim_assembly
[ "$TOOLCHAIN_ASSEMBLY_REUSED" = true ] || fail "complete assembly was not reused"
printf changed >> "$ASSEMBLY_IMAGE_ROOT/rg/system/bin/rg"
if toolchain_claim_assembly 2>/dev/null; then
	fail "assembly with changed staging was accepted"
fi
printf rg > "$ASSEMBLY_IMAGE_ROOT/rg/system/bin/rg"
chmod u+w "$ASSEMBLY_IMAGE_ROOT/libc/devtools/toolchain/manifest"
printf changed >> "$ASSEMBLY_IMAGE_ROOT/libc/devtools/toolchain/manifest"
if toolchain_claim_assembly 2>/dev/null; then
	fail "assembly with a changed generated-root manifest was accepted"
fi

echo "test-toolchain-assembly PASS"
