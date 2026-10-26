#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
repository="$temporary/motor-os"
prefix="$temporary/prefix"
toolchain=x86_64-unknown-motor-9.9.9
sysroot="$repository/build/assembly/images/rustc/devtools/rust"
linker="$prefix/lib/rustlib/x86_64-unknown-motor/sysroot/bin/motor-clang"
mkdir -p "$repository" "$prefix/bin" "$(dirname "$linker")" "$temporary/bin"
printf '[toolchain]\nchannel = "%s"\n' "$toolchain" > "$repository/rust-toolchain.toml"

fake_tool="$temporary/tool"
cat > "$fake_tool" <<EOF
#!/usr/bin/env bash
case "\$(basename "\$0")" in
cargo) printf '%s\n' 'cargo 9.9.9-dev' 'release: 9.9.9-dev' ;;
rustc) [ "\$*" = '--print sysroot' ] && printf '%s\n' '$prefix' ;;
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
printf '#!/bin/sh\nexit 0\n' > "$linker"
chmod +x "$linker"

export PATH="$temporary/bin:$PATH"
export LORRY_REPOSITORY_ROOT="$repository"
. "$SCRIPT_DIR/current-toolchain.sh"
if (lorry_load_current_toolchain) >/dev/null 2>&1; then
    echo "current-toolchain-contract: a checkout without an assembly was accepted" >&2
    exit 1
fi
mkdir -p "$sysroot/lib/rustlib/x86_64-unknown-motor"
lorry_load_current_toolchain >"$temporary/output" 2>"$temporary/log"
[ "$LORRY_MOTOR_TOOLCHAIN" = "$toolchain" ]
[ "$LORRY_TEST_CARGO" = "$prefix/bin/cargo" ]
[ "$LORRY_MOTOR_LINKER" = "$linker" ]
[ "$LORRY_MOTOR_SYSROOT" = "$sysroot" ]
grep -Fqx 'release: 9.9.9-dev' "$temporary/log"

echo "PASS: Motor Cargo comes from rustup and the native Rust sysroot from the assembly"
