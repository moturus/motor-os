#!/usr/bin/env bash

# Offline checks of the userspace add-on stage of src/build-motor-os.sh: the
# branch-following checkouts, Helix staging and ELF validation, and the rule
# that each add-on is rebuilt alone and is no part of the assembly.

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/build-motor-os.sh"
fail() { echo "test-build-addons: $*" >&2; exit 1; }
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

# An add-on follows one branch of its fork: no commit is declared anywhere.
MOTORH="$temporary/motorh"
HELIX="$MOTORH/helix"
mkdir -p "$MOTORH"
log() { :; }
skip() { :; }
update_addon_source helix "$HELIX" "$remote" helix-test >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$(git -C "$seed" rev-parse HEAD)" ] ||
	fail "the checkout did not select the branch head"
printf update > "$seed/source"
git -C "$seed" commit -qam update
git -C "$seed" push -q origin helix-test
update_addon_source helix "$HELIX" "$remote" helix-test >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$(git -C "$seed" rev-parse HEAD)" ] ||
	fail "the checkout did not follow its branch"
[ -z "$(git -C "$HELIX" status --porcelain)" ] || fail "the checkout is dirty"
printf local > "$HELIX/source"
if (update_addon_source helix "$HELIX" "$remote" helix-test) >/dev/null 2>&1; then
	fail "a dirty add-on checkout was updated"
fi
git -C "$HELIX" checkout -q -- source

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
# Add-ons are built for new and reused assemblies alike, outside the keyed
# producer path, and before the build checks what make will resolve.
case "$(declare -f main)" in
	*'toolchain_complete_assembly'*'build_addons'*'resolve-toolchain-assembly.sh'*) ;;
	*) fail "add-ons are not built after the assembly is complete" ;;
esac
case "$(declare -f main)" in
	*'TOOLCHAIN_ASSEMBLY_REUSED" = false'*build_helix*'toolchain_complete_assembly'*|\
*'TOOLCHAIN_ASSEMBLY_REUSED" = false'*build_ripgrep*'toolchain_complete_assembly'*|\
*'TOOLCHAIN_ASSEMBLY_REUSED" = false'*build_lua*'toolchain_complete_assembly'*)
		fail "an add-on is still built inside the keyed producer path" ;;
esac
case "$(declare -f build_addons)" in
	*'ensure_addon lua'*'ensure_addon ripgrep'*'ensure_addon helix'*) ;;
	*) fail "Lua, ripgrep, and Helix are not all add-ons" ;;
esac

# A changed source rebuilds that add-on alone; an unchanged one builds nothing.
builds=0
overlay="$ASSEMBLY_IMAGE_ROOT/addon-test"
build_test_addon() {
	builds=$((builds + 1))
	mkdir -p "$overlay/bin"
	printf '%s' "$builds" > "$overlay/bin/tool"
	chmod 755 "$overlay/bin/tool"
}
ensure_addon test source-1 "$overlay" bin/tool build_test_addon
[ "$builds" -eq 1 ] || fail "a missing add-on was not built"
[ "$(cat "$ASSEMBLY_ROOT/ADDON-test")" = source-1 ] || fail "the add-on source was not recorded"
ensure_addon test source-1 "$overlay" bin/tool build_test_addon
[ "$builds" -eq 1 ] || fail "an up-to-date add-on was rebuilt"
ensure_addon test source-2 "$overlay" bin/tool build_test_addon
[ "$builds" -eq 2 ] || fail "a changed source did not rebuild the add-on"
rm -f "$overlay/bin/tool"
ensure_addon test source-2 "$overlay" bin/tool build_test_addon
[ "$builds" -eq 3 ] || fail "a recorded source without its executable was accepted"
build_nothing() { :; }
if (ensure_addon test source-3 "$overlay" bin/tool build_nothing) 2>/dev/null; then
	fail "an add-on build that staged nothing was accepted"
fi

echo "test-build-addons PASS"
