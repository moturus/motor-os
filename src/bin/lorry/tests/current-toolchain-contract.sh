#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
repository="$temporary/motor-os"
prefix="$temporary/prefix"
key="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
assembly_key="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
assembly="$temporary/assemblies/$assembly_key"
mkdir -p "$repository/src" "$prefix/bin" "$prefix/lib/rustlib" \
    "$assembly/sysroot/bin" \
    "$assembly/images/rustc/devtools/rust/lib/rustlib/x86_64-unknown-motor" \
    "$temporary/bin"
cp "$ROOT_DIR/src/toolchain-versions.sh" "$repository/src/"
. "$repository/src/toolchain-versions.sh"
toolchain="$MOTOR_RUSTUP_TOOLCHAIN_BASE-$key"
printf '[toolchain]\nchannel = "%s"\n' "$toolchain" > "$repository/rust-toolchain.toml"

fake_tool="$temporary/tool"
cat > "$fake_tool" <<EOF
#!/usr/bin/env bash
case "\$(basename "\$0")" in
cargo)
  printf '%s\n' 'cargo $MOTOR_CARGO_VERSION' 'release: $MOTOR_CARGO_VERSION' \
    "commit-hash: \${BAD_CARGO_REV:-$MOTOR_CARGO_REV}" ;;
rustc)
  if [ "\${1:-}" = --print ]; then
    printf '%s\n' '$prefix'
  else
    printf '%s\n' 'rustc 1.99.0-dev' 'commit-hash: $MOTOR_RUST_REV' \
      'host: x86_64-unknown-linux-gnu' 'release: 1.99.0-dev'
  fi ;;
esac
EOF
chmod +x "$fake_tool"
ln -s "$fake_tool" "$prefix/bin/cargo"
ln -s "$fake_tool" "$prefix/bin/rustc"
cat > "$temporary/bin/rustup" <<EOF
#!/usr/bin/env bash
[ "\$1" = which ] && [ "\$4" = '$toolchain' ] || exit 1
printf '%s/bin/%s\n' '$prefix' "\$2"
EOF
chmod +x "$temporary/bin/rustup"

cat > "$prefix/MOTOR-TOOLCHAIN-MANIFEST" <<EOF
schema=$MOTOR_GENERATED_MANIFEST_SCHEMA
toolchain_key=$key
rustup_toolchain=$toolchain
cargo_rev=$MOTOR_CARGO_REV
effective_rust_rev=$MOTOR_RUST_REV
effective_llvm_rev=$MOTOR_LLVM_REV
EOF
printf '%s\n' "$key" > "$prefix/lib/rustlib/MOTOR-TOOLCHAIN-KEY"
cat > "$assembly/MOTOR-ASSEMBLY-MANIFEST" <<EOF
schema=$MOTOR_GENERATED_MANIFEST_SCHEMA
toolchain_key=$key
assembly_key=$assembly_key
rustup_toolchain=$toolchain
effective_rust_rev=$MOTOR_RUST_REV
effective_llvm_rev=$MOTOR_LLVM_REV
EOF
printf '#!/bin/sh\nexit 0\n' > "$assembly/sysroot/bin/motor-clang"
chmod +x "$assembly/sysroot/bin/motor-clang"

export PATH="$temporary/bin:$PATH"
export LORRY_REPOSITORY_ROOT="$repository"
LORRY_ASSEMBLY_MANIFEST="$assembly/MOTOR-ASSEMBLY-MANIFEST"
. "$SCRIPT_DIR/current-toolchain.sh"
lorry_load_current_toolchain >"$temporary/output" 2>"$temporary/log"
[ "$LORRY_MOTOR_TOOLCHAIN" = "$toolchain" ]
[ "$LORRY_TEST_CARGO" = "$prefix/bin/cargo" ]
[ "$LORRY_MOTOR_LINKER" = "$assembly/sysroot/bin/motor-clang" ]
grep -Fqx "commit-hash: $MOTOR_CARGO_REV" "$temporary/log"

if (BAD_CARGO_REV=wrong LORRY_ASSEMBLY_MANIFEST= lorry_load_current_toolchain) \
        >/dev/null 2>&1; then
    echo "current-toolchain-contract: wrong Cargo revision was accepted" >&2
    exit 1
fi

echo "PASS: exact Motor Cargo and assembly paths come from validated manifests"
