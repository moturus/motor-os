#!/usr/bin/env bash

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/build-motor-os.sh"
fail() { echo "test-toolchain-helix: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

remote="$temporary/remote"
seed="$temporary/seed"
mkdir -p "$remote" "$seed"
git -C "$remote" init -q --bare
git -C "$seed" init -q
git -C "$seed" config user.email test@example.com
git -C "$seed" config user.name Test
printf fixture > "$seed/source"
git -C "$seed" add source
git -C "$seed" commit -qm fixture
git -C "$seed" branch -M helix-test
git -C "$seed" remote add origin "$remote"
git -C "$seed" push -q origin helix-test

MOTORH="$temporary/motorh"
TOOLCHAIN_SRC_ROOT="$MOTORH/toolchain-src"
HELIX_REPOSITORY="$remote"
HELIX_REF=refs/heads/helix-test
HELIX_REV="$(git -C "$seed" rev-parse HEAD)"
prepare_helix_source
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$HELIX_REV" ] ||
	fail "managed checkout did not select HELIX_REV"
[ -z "$(git -C "$HELIX" status --porcelain)" ] ||
	fail "managed checkout is dirty"

ASSEMBLY_ROOT="$temporary/assembly"
ASSEMBLY_SYSROOT="$ASSEMBLY_ROOT/sysroot"
ASSEMBLY_BUILD_ROOT="$ASSEMBLY_ROOT/build"
ASSEMBLY_IMAGE_ROOT="$ASSEMBLY_ROOT/images"
STANDALONE_LLVM_BIN="$temporary/llvm/bin"
TOOLCHAIN_PREFIX="$temporary/toolchain"
TARGET=x86_64-unknown-motor
activate_exact_assembly_paths
mkdir -p "$HELIX_TARGET_DIR/$TARGET/release" "$HELIX/runtime/queries/rust" \
	"$HELIX/runtime/themes" "$B"
printf binary > "$HELIX_TARGET_DIR/$TARGET/release/hx"
chmod 755 "$HELIX_TARGET_DIR/$TARGET/release/hx"
printf query > "$HELIX/runtime/queries/rust/highlights.scm"
printf theme > "$HELIX/runtime/themes/default.toml"
printf tutor > "$HELIX/runtime/tutor"
mkdir -p "$HELIX/runtime/grammars/sources/rust"
printf source > "$HELIX/runtime/grammars/sources/rust/parser.c"
cat > "$B/llvm-strip" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = -o ]; then cp "$3" "$2"; else exit 1; fi
EOF
chmod +x "$B/llvm-strip"
saved_validator="$(declare -f validate_helix_elf)"
validate_helix_elf() { :; }
stage_helix
[ -x "$HELIX_IMG/devtools/helix/hx" ] || fail "staged hx is not executable"
for component in queries themes tutor; do
	[ -e "$HELIX_IMG/devtools/helix/runtime/$component" ] ||
		fail "runtime component was not staged: $component"
done
[ ! -e "$HELIX_IMG/devtools/helix/runtime/grammars" ] ||
	fail "grammar sources were staged"

eval "$saved_validator"
elf_tools="$temporary/elf-tools"
mkdir -p "$elf_tools"
ln -s "$(command -v readelf)" "$elf_tools/llvm-readelf"
ln -s "$(command -v nm)" "$elf_tools/llvm-nm"
ln -s "$(command -v strip)" "$elf_tools/llvm-strip"
B="$elf_tools"
printf 'int main(void) { return 0; }\n' > "$temporary/static.c"
cc -fPIE -ffreestanding -c "$temporary/static.c" -o "$temporary/static.o"
cc -nostdlib -static-pie -Wl,-e,main "$temporary/static.o" -o "$temporary/static-pie"
validate_helix_elf "$temporary/static-pie"
cc -fPIE -pie "$temporary/static.c" -o "$temporary/dynamic-pie"
if (validate_helix_elf "$temporary/dynamic-pie") 2>/dev/null; then
	fail "ELF validation accepted a dynamic library dependency"
fi
printf '_Thread_local int value; int main(void) { return value; }\n' > \
	"$temporary/tls.c"
cc -fPIE -ffreestanding -c "$temporary/tls.c" -o "$temporary/tls.o"
cc -nostdlib -static-pie -Wl,-e,main "$temporary/tls.o" -o "$temporary/tls-pie"
if (validate_helix_elf "$temporary/tls-pie") 2>/dev/null; then
	fail "ELF validation accepted a TLS segment"
fi

case "$(declare -f build_helix)" in
	*'fetch --locked'*'build --target "$TARGET" --release --locked'*\
*'--offline --no-default-features -p helix-term --bin hx'*) ;;
	*) fail "Helix build is not an explicit fetch followed by an offline locked build" ;;
esac
case "$(declare -f main)" in
	*'toolchain_claim_assembly'*'TOOLCHAIN_ASSEMBLY_REUSED" = false'*\
*'prepare_helix_source'*'build_helix'*'toolchain_complete_assembly'*) ;;
	*) fail "Helix checkout/build is not confined to the assembly producer path" ;;
esac

echo "test-toolchain-helix PASS"
