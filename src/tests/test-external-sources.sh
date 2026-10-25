#!/usr/bin/env bash

# Offline checks of the external-source stage of src/build-motor-os.sh: the
# branch-following and revision-pinned checkouts, Helix staging and ELF
# validation, and the rule that every run builds each external source into an
# empty overlay.

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/build-motor-os.sh"
fail() { echo "test-external-sources: $*" >&2; exit 1; }
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

# An external source follows one branch of its fork: no commit is declared anywhere.
EXTERNAL_SOURCES="$temporary/external-sources"
HELIX="$EXTERNAL_SOURCES/helix"
mkdir -p "$EXTERNAL_SOURCES"
log() { :; }
update_external_source helix "$HELIX" "$remote" helix-test >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$(git -C "$seed" rev-parse HEAD)" ] ||
	fail "the checkout did not select the branch head"
printf update > "$seed/source"
git -C "$seed" commit -qam update
git -C "$seed" push -q origin helix-test
update_external_source helix "$HELIX" "$remote" helix-test >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$(git -C "$seed" rev-parse HEAD)" ] ||
	fail "the checkout did not follow its branch"
[ -z "$(git -C "$HELIX" status --porcelain)" ] || fail "the checkout is dirty"
printf local > "$HELIX/source"
if (update_external_source helix "$HELIX" "$remote" helix-test) >/dev/null 2>&1; then
	fail "a dirty external source checkout was updated"
fi
git -C "$HELIX" checkout -q -- source
# The checkouts sit inside the Motor OS checkout: a directory there that is
# not a checkout of its own must not be taken for that one.
outer="$temporary/outer"
git init -q -b helix-test "$outer"
printf '/external-sources/\n' > "$outer/.gitignore"
git -C "$outer" add .gitignore
git -C "$outer" -c user.email=test@example.com -c user.name=Test commit -qm outer
mkdir -p "$outer/external-sources/helix"
if (update_external_source helix "$outer/external-sources/helix" "$remote" helix-test) >/dev/null 2>&1 ||
	[ -e "$outer/.git/FETCH_HEAD" ]; then
	fail "a directory inside another checkout was taken for an external source checkout"
fi

# A pinned external source is built at its declared revision: an older one detaches the
# checkout, a newer one fast-forwards the branch, a revision the branch does not
# reach yet is fetched by its hash, and commits that are not on the remote
# branch are never left behind.
git -C "$remote" config uploadpack.allowReachableSHA1InWant true
first="$(git -C "$seed" rev-parse HEAD~1)"
second="$(git -C "$seed" rev-parse HEAD)"
update_external_source helix "$HELIX" "$remote" helix-test "$first" >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$first" ] ||
	fail "the checkout did not select the declared revision"
[ -z "$(git -C "$HELIX" branch --show-current)" ] ||
	fail "an older declared revision did not detach the checkout"
update_external_source helix "$HELIX" "$remote" helix-test "$second" >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$second" ] ||
	fail "the checkout did not move to the newer declared revision"
git -C "$HELIX" checkout -q helix-test
git -C "$HELIX" reset -q --hard "$first"
update_external_source helix "$HELIX" "$remote" helix-test "$second" >/dev/null 2>&1
[ "$(git -C "$HELIX" branch --show-current)" = helix-test ] &&
	[ "$(git -C "$HELIX" rev-parse HEAD)" = "$second" ] ||
	fail "a newer declared revision did not fast-forward the branch"
printf third > "$seed/source"
git -C "$seed" commit -qam third
third="$(git -C "$seed" rev-parse HEAD)"
if (update_external_source helix "$HELIX" "$remote" helix-test "$third") >/dev/null 2>&1; then
	fail "an unpublished declared revision was accepted"
fi
git -C "$seed" checkout -q -b helix-other
printf fourth > "$seed/source"
git -C "$seed" commit -qam fourth
fourth="$(git -C "$seed" rev-parse HEAD)"
git -C "$seed" push -q origin helix-test helix-other
update_external_source helix "$HELIX" "$remote" helix-test "$fourth" >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$fourth" ] ||
	fail "a declared revision on another branch was not fetched"
update_external_source helix "$HELIX" "$remote" helix-test "$third" >/dev/null 2>&1
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$third" ] || fail "the checkout did not return to the branch head"
git -C "$HELIX" checkout -q -B helix-test "$third"
printf local > "$HELIX/source"
git -C "$HELIX" -c user.email=test@example.com -c user.name=Test commit -qam local
local_head="$(git -C "$HELIX" rev-parse HEAD)"
if (update_external_source helix "$HELIX" "$remote" helix-test "$third") >/dev/null 2>&1; then
	fail "a checkout with local commits was moved to the declared revision"
fi
[ "$(git -C "$HELIX" rev-parse HEAD)" = "$local_head" ] || fail "local commits were left behind"
update_external_source helix "$HELIX" "$remote" helix-test "$local_head" >/dev/null 2>&1 ||
	fail "a pinned local commit was refused"
git -C "$HELIX" reset -q --hard "$third"
case "$(declare -f prepare_external_sources)" in
	*'IFS=: read -r repo branch revision <<< "$spec"'*'"$branch" "$revision"'*) ;;
	*) fail "external sources are not prepared at their declared revisions" ;;
esac
[[ "$MOTOR_JAVY_REV" =~ ^[0-9a-f]{40}$ ]] && [[ "$MOTOR_WASMTIME_REV" =~ ^[0-9a-f]{40}$ ]] ||
	fail "Javy and Wasmtime do not declare full fork revisions"

ASSEMBLY_ROOT="$temporary/assembly"
ASSEMBLY_BUILD_ROOT="$ASSEMBLY_ROOT/build"
ASSEMBLY_IMAGE_ROOT="$ASSEMBLY_ROOT/images"
LLVM_TOOLS="$temporary/llvm/bin"
HELIX_IMG="$ASSEMBLY_IMAGE_ROOT/helix"
HELIX_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/helix"
TARGET=x86_64-unknown-motor
mkdir -p "$HELIX_TARGET_DIR/$TARGET/release" "$HELIX/runtime/queries/rust" \
	"$HELIX/runtime/themes" "$LLVM_TOOLS"
printf binary > "$HELIX_TARGET_DIR/$TARGET/release/hx"
chmod 755 "$HELIX_TARGET_DIR/$TARGET/release/hx"
printf query > "$HELIX/runtime/queries/rust/highlights.scm"
printf theme > "$HELIX/runtime/themes/default.toml"
printf tutor > "$HELIX/runtime/tutor"
mkdir -p "$HELIX/runtime/grammars/sources/rust"
printf source > "$HELIX/runtime/grammars/sources/rust/parser.c"
cat > "$LLVM_TOOLS/llvm-strip" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = -o ]; then cp "$3" "$2"; else exit 1; fi
EOF
chmod +x "$LLVM_TOOLS/llvm-strip"
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
LLVM_TOOLS="$elf_tools"
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
	*'fetch --locked'*'CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$SYSROOT/bin/motor-clang"'*\
*'build --target "$TARGET" --release --locked'*'--offline -p helix-term --bin hx'*) ;;
	*) fail "Helix build is not an explicit fetch followed by an offline locked build" ;;
esac
# The native toolchain is unpacked from its archive before the external sources
# are built, so a bad archive fails the build early; the images take both.
case "$(declare -f main)" in
	*'unpack_native_toolchain'*'build_external_sources'*'build_images'*) ;;
	*) fail "the images are not built after the native toolchain and the external sources" ;;
esac
case "$(declare -f build_external_sources)" in
	*'build_external_source lua'*'build_external_source ripgrep'*'build_external_source helix'*\
*'build_external_source sed'*'build_external_source tar'*) ;;
	*) fail "Lua, ripgrep, Helix, sed, and tar are not all external sources" ;;
esac
# The developer image's library sources take their dependencies from an
# overlay of every package their workspace locks, fetched with Lorry.
case "$(declare -f build_external_sources)" in
	*fetch_sys_lib_deps*) ;;
	*) fail "the dependencies of the staged library sources are not fetched" ;;
esac
case "$(declare -f fetch_sys_lib_deps)" in
	*'src/build-scripts/sys-lib-workspace.sh'*'fetch --locked'*) ;;
	*) fail "the library sources' dependencies are not fetched from their locked workspace" ;;
esac
case "$(declare -f select_external_sources)" in
	*'"sed:$SED_BRANCH"'*) ;;
	*) fail "sed does not follow its fork branch" ;;
esac
case "$(declare -f build_sed)" in
	*'CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1'*'build --target "$TARGET" --release --locked'*\
*'"$SED_IMG/devtools/bin/sed"'*) ;;
	*) fail "sed is not a single-codegen-unit locked release build staged as /devtools/bin/sed" ;;
esac
case "$(declare -f select_external_sources)" in
	*'"motor-os-tar:$MOTOR_OS_TAR_BRANCH"'*) ;;
	*) fail "motor-os-tar does not follow its fork branch" ;;
esac
case "$(declare -f build_tar)" in
	*'build --target "$TARGET" --release --locked'*'for tool in tar zstd'*\
*'"$TAR_IMG/system/bin/$tool"'*) ;;
	*) fail "tar and zstd are not locked release builds staged in /system/bin" ;;
esac

# Every run builds each external source into an empty overlay, and a build
# that stages nothing fails.
builds=0
overlay="$ASSEMBLY_IMAGE_ROOT/external-test"
build_test_source() {
	builds=$((builds + 1))
	mkdir -p "$overlay/bin"
	printf '%s' "$builds" > "$overlay/bin/tool"
	chmod 755 "$overlay/bin/tool"
}
build_external_source test "$overlay" bin/tool build_test_source
: > "$overlay/stale"
build_external_source test "$overlay" bin/tool build_test_source
[ "$builds" -eq 2 ] || fail "an unchanged external source was not built again"
[ ! -e "$overlay/stale" ] || fail "an external source was staged over its previous overlay"
build_nothing() { :; }
if (build_external_source test "$overlay" bin/tool build_nothing) 2>/dev/null; then
	fail "an external source build that staged nothing was accepted"
fi

# Javy and Wasmtime build with the selected toolchain, which their provenance
# records.
case "$(declare -f build_external_sources)" in
	*'build_external_source javy'*'build_external_source wasmtime'*) ;;
	*) fail "Javy/Wasmi and Wasmtime are not both external sources" ;;
esac
javy_root="$temporary/javy"
javy_log="$javy_root/toolchains.log"
mkdir -p "$javy_root/external-sources/javy" "$javy_root/external-sources/wasmtime/motor-runtime"
for tool in javy wasmtime; do
	cat > "$javy_root/external-sources/$tool/motor-build.sh" <<'EOF'
#!/usr/bin/env bash
printf 'build %s %s\n' "$RUSTUP_TOOLCHAIN" "$*" >> "$JAVY_TOOLCHAIN_LOG"
EOF
	chmod +x "$javy_root/external-sources/$tool/motor-build.sh"
done
for selection in first-probe second-probe; do
	(
		export RUSTUP_TOOLCHAIN="$selection" JAVY_TOOLCHAIN_LOG="$javy_log"
		EXTERNAL_SOURCES="$javy_root/external-sources"
		SYSROOT="$javy_root/sysroot"
		ASSEMBLY_BUILD_ROOT="$javy_root/build"
		JAVY_IMG="$javy_root/images/javy" JAVY_TESTS="$javy_root/tests/javy"
		WASMTIME_IMG="$javy_root/images/wasmtime" WASMTIME_TESTS="$javy_root/tests/wasmtime"
		JAVY_PLUGIN_SHA=plugin JAVY_TYPESCRIPT_SHA=typescript
		javy_source_manifest() { echo manifest; }
		wasmtime_source_manifest() { echo manifest; }
		javy_download() { : > "$3"; }
		cargo() { printf 'cargo %s %s %s\n' "$RUSTUP_TOOLCHAIN" "${PWD##*/}" "$*" >> "$JAVY_TOOLCHAIN_LOG"; }
		gzip() { :; }
		tar() { :; }
		install() { :; }
		sha256sum() { cat > /dev/null; }
		build_wasmtime_fixtures() { printf 'fixtures %s\n' "$RUSTUP_TOOLCHAIN" >> "$JAVY_TOOLCHAIN_LOG"; }
		javy_linux_reference() { :; }
		build_javy_test_plugins() { :; }
		build_javy
		build_wasmtime
	) < /dev/null > /dev/null 2>&1 || fail "the Javy or Wasmtime build failed with selection $selection"
done
expected=""
for selection in first-probe second-probe; do
	expected+="cargo $selection javy fetch --locked"$'\n'"build $selection "$'\n'
	expected+="cargo $selection motor-runtime fetch --locked"$'\n'
	expected+="build $selection runtime"$'\n'"fixtures $selection"$'\n'
done
[ "$(cat "$javy_log")"$'\n' = "$expected" ] ||
	fail "Javy and Wasmtime did not fetch and build with the selected toolchain"
# The host Pulley compiler uses the selected toolchain; guest programs use the
# pinned upstream one with wasm32 targets, which the Motor toolchain lacks.
case "$(declare -f build_wasmtime_fixtures)" in
	*'--features compile --bin compile'*'RUSTUP_TOOLCHAIN="$WASM_GUEST_TOOLCHAIN"'*\
*'--target wasm32-wasip2 -p test-programs --features motor'*) ;;
	*) fail "the Wasmtime fixtures are not built with the expected toolchains" ;;
esac
case "$(declare -f build_external_sources)" in
	*'ensure_wasm_guest_toolchain'*'ensure_wasi_sdk'*'build_external_source javy'*\
*'build_external_source wasmtime'*) ;;
	*) fail "the guest toolchain and wasi-sdk are not provided before Javy and Wasmtime" ;;
esac
# javy-smoke's test plugins are guests too, and their QuickJS C code is built
# with the pinned wasi-sdk, checked before it is unpacked.
case "$(declare -f build_javy_test_plugins)" in
	*'RUSTUP_TOOLCHAIN="$WASM_GUEST_TOOLCHAIN" WASI_SDK'*'--target wasm32-wasip1'*\
*'--target wasm32-wasip2'*) ;;
	*) fail "the Javy test plugins are not built with the guest toolchain and wasi-sdk" ;;
esac
case "$(declare -f ensure_wasi_sdk)" in
	*'"$WASI_SDK_SHA"'*'sha256sum -c'*'tar -xzf'*) ;;
	*) fail "wasi-sdk is not checked before it is unpacked" ;;
esac
javy_manifest() (
	RUSTUP_TOOLCHAIN="$1"
	rustc() { printf 'rustc for %s\n' "$RUSTUP_TOOLCHAIN"; }
	JAVY_SOURCES=()
	JAVY_PLUGIN_SHA=plugin
	JAVY_TYPESCRIPT_SHA=typescript
	javy_source_manifest
)
first_manifest="$(javy_manifest first-probe)"
second_manifest="$(javy_manifest second-probe)"
case "$second_manifest" in
	*'toolchain=second-probe'*'rustc=rustc for second-probe'*) ;;
	*) fail "the Javy manifest does not name the selected toolchain" ;;
esac
# The Linux reference digests come from the pinned Linux Javy and the fixtures
# javy-smoke compiles, so the Javy provenance names each.
case "$first_manifest" in
	*'fixtures/hello.js'*"javy-linux=$JAVY_LINUX_SHA"*) ;;
	*) fail "the Javy manifest does not name the Linux reference inputs" ;;
esac
case "$first_manifest" in
	*'plugins/p1/src/lib.rs'*'guest-toolchain=rustc for '"$WASM_GUEST_TOOLCHAIN"*\
*"wasi-sdk=$WASI_SDK_SHA"*) ;;
	*) fail "the Javy manifest does not name the test plugin inputs" ;;
esac

bash "$ROOT_DIR/src/tests/test-wasmtime-fetch.sh"
echo "test-external-sources PASS"
