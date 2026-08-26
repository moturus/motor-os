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
archive_root="$temporary/archive/moto-rt-$STDLIB_MOTO_RT_VERSION"
cargo_home="$temporary/cargo-home"
mkdir -p "$rust/library" "$local_package/src" "$archive_root/src" \
	"$cargo_home/registry/cache/test-index"
cat > "$rust/library/Cargo.lock" <<EOF
version = 4

[[package]]
name = "moto-rt"
version = "$STDLIB_MOTO_RT_VERSION"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "$STDLIB_MOTO_RT_CHECKSUM"
EOF
cat > "$local_package/Cargo.toml" <<EOF
[package]
name = "moto-rt"
version = "$LOCAL_MOTO_RT_VERSION"
EOF
printf 'runtime source\n' > "$local_package/src/lib.rs"
cp "$local_package/Cargo.toml" "$archive_root/Cargo.toml.orig"
printf 'normalized manifest\n' > "$archive_root/Cargo.toml"
printf 'generated lock\n' > "$archive_root/Cargo.lock"
printf '{}\n' > "$archive_root/.cargo_vcs_info.json"
cp "$local_package/src/lib.rs" "$archive_root/src/lib.rs"
archive="$cargo_home/registry/cache/test-index/moto-rt-$STDLIB_MOTO_RT_VERSION.crate"
tar -czf "$archive" -C "$temporary/archive" "moto-rt-$STDLIB_MOTO_RT_VERSION"
STDLIB_MOTO_RT_CHECKSUM="$(sha256sum "$archive" | awk '{print $1}')"
sed -i 's/^checksum = .*/checksum = "'"$STDLIB_MOTO_RT_CHECKSUM"'"/' \
	"$rust/library/Cargo.lock"

fake_cargo="$temporary/cargo"
cat > "$fake_cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' .cargo_vcs_info.json Cargo.lock Cargo.toml Cargo.toml.orig src/lib.rs
EOF
chmod +x "$fake_cargo"

MOTOR_ASSEMBLY_STATE=clean
toolchain_verify_moto_rt_package "$rust" "$local_package" "$fake_cargo" "$cargo_home"
[ "$MOTO_RT_PACKAGE_COMPARISON" = exact ] || fail "equal packages do not compare exact"

printf 'local edit\n' >> "$local_package/src/lib.rs"
if toolchain_verify_moto_rt_package \
	"$rust" "$local_package" "$fake_cargo" "$cargo_home" 2>/dev/null; then
	fail "clean assembly accepted differing local runtime content"
fi
MOTOR_ASSEMBLY_STATE=development-dirty
toolchain_verify_moto_rt_package \
	"$rust" "$local_package" "$fake_cargo" "$cargo_home" 2>/dev/null
[ "$MOTO_RT_PACKAGE_COMPARISON" = development-dirty ] ||
	fail "dirty package difference was not recorded"

sed -i 's/version = "0.17.5"/version = "0.17.6"/' "$local_package/Cargo.toml"
if toolchain_verify_moto_rt_package \
	"$rust" "$local_package" "$fake_cargo" "$cargo_home" 2>/dev/null; then
	fail "dirty assembly accepted a moto-rt version mismatch"
fi

echo "test-toolchain-runtime PASS"
