#!/usr/bin/env bash

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/select-toolchain-assembly.sh"
fail() { echo "test-toolchain-assembly-selection: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

checkout="$temporary/motor"
toolchain_key="$(printf toolchain | sha256sum | awk '{print $1}')"
assembly_key="$(printf assembly | sha256sum | awk '{print $1}')"
runtime_tree="$(printf runtime | sha256sum | awk '{print $1}')"
native_config="$(printf native | sha256sum | awk '{print $1}')"
mkdir -p "$checkout"

selector_initialize_identity() {
	ROOT_DIR="$checkout"
	MOTORH="$temporary"
	ASSEMBLIES_DIR="$temporary/assemblies"
	PIN_ROOT="$checkout/.motor-os/assembly-pins"
	PIN_PATH="$PIN_ROOT/$toolchain_key"
	SELECTED_TOOLCHAIN_KEY="$toolchain_key"
	MOTOR_TOOLCHAIN_KEY="$toolchain_key"
	MOTOR_ASSEMBLY_KEY="$assembly_key"
	MOTOR_OS_RUNTIME_TREE="$runtime_tree"
	MOTOR_MLIBC_TREE_STATE=clean
	STANDALONE_LLVM_CONFIG_DIGEST="$(toolchain_standalone_llvm_config_digest)"
	NATIVE_CONFIGURATION_DIGEST="$native_config"
}

write_assembly() {
	local key="$1" root manifest standalone_llvm_config_digest
	standalone_llvm_config_digest="$(toolchain_standalone_llvm_config_digest)"
	root="$temporary/assemblies/$key"
	mkdir -p "$root/sysroot/devtools/llvm/lib" \
		"$root/images/llvm/devtools/llvm/bin" \
		"$root/images/rustc/devtools/rust/bin" \
		"$root/images/rg/system/bin" \
		"$root/images/libc/system/cfg/libc"
	printf libc > "$root/sysroot/devtools/llvm/lib/libc.a"
	printf cxx > "$root/sysroot/devtools/llvm/lib/libc++.a"
	printf shim > "$root/sysroot/devtools/llvm/lib/libmoto_rt_cabi.a"
	printf llvm > "$root/images/llvm/devtools/llvm/bin/llvm"
	printf rustc > "$root/images/rustc/devtools/rust/bin/rustc"
	printf rg > "$root/images/rg/system/bin/rg"
	printf shells > "$root/images/libc/system/cfg/libc/shells"
	manifest="$root/MOTOR-ASSEMBLY-MANIFEST"
	{
		printf 'schema=%s\n' "$MOTOR_GENERATED_MANIFEST_SCHEMA"
		printf 'toolchain_key=%s\n' "$toolchain_key"
		printf 'assembly_key=%s\n' "$key"
		printf 'standalone_llvm_config_digest=%s\n' \
			"$standalone_llvm_config_digest"
		printf 'source_mode=managed\nassembly_state=clean\n'
		printf 'motor_os_rev=0123456789abcdef0123456789abcdef01234567\n'
		printf 'motor_os_runtime_tree=%s\n' "$runtime_tree"
		printf 'mlibc_rev=%s\nmlibc_tree_state=clean\n' "$MOTOR_MLIBC_REV"
		printf 'local_moto_rt_version=%s\n' "$LOCAL_MOTO_RT_VERSION"
		printf 'native_configuration_digest=%s\n' "$native_config"
		printf 'native_rustc_sha256=%s\n' "$(sha256sum "$root/images/rustc/devtools/rust/bin/rustc" | awk '{print $1}')"
		printf 'native_llvm_sha256=%s\n' "$(sha256sum "$root/images/llvm/devtools/llvm/bin/llvm" | awk '{print $1}')"
		printf 'ripgrep_sha256=%s\n' "$(sha256sum "$root/images/rg/system/bin/rg" | awk '{print $1}')"
		printf 'libc_sha256=%s\n' "$(sha256sum "$root/sysroot/devtools/llvm/lib/libc.a" | awk '{print $1}')"
		printf 'libcxx_sha256=%s\n' "$(sha256sum "$root/sysroot/devtools/llvm/lib/libc++.a" | awk '{print $1}')"
		printf 'moto_rt_cabi_sha256=%s\n' "$(sha256sum "$root/sysroot/devtools/llvm/lib/libmoto_rt_cabi.a" | awk '{print $1}')"
		printf 'libc_config_sha256=%s\n' "$(sha256sum "$root/images/libc/system/cfg/libc/shells" | awk '{print $1}')"
	} > "$manifest"
	chmod 0444 "$manifest"
	local overlay
	for overlay in llvm rustc rg libc; do
		mkdir -p "$root/images/$overlay/devtools/toolchain"
		cp "$manifest" "$root/images/$overlay/devtools/toolchain/manifest"
		chmod 0444 "$root/images/$overlay/devtools/toolchain/manifest"
	done
}

write_assembly "$assembly_key"
resolved="$(selector_main --resolve)"
selector_initialize_identity
[ "$resolved" = "$temporary/assemblies/$assembly_key/images" ] ||
	fail "single assembly was not resolved"
[ -f "$PIN_PATH" ] && [ "$(stat -c %a "$PIN_PATH")" = 600 ] ||
	fail "automatic selection did not create a private pin"
selector_main --show | grep -Fq "$assembly_key  compatible" ||
	fail "show did not describe the pin"

printf changed >> "$temporary/assemblies/$assembly_key/images/rg/system/bin/rg"
if selector_main --resolve >/dev/null 2>&1; then
	fail "modified assembly output was accepted"
fi
printf rg > "$temporary/assemblies/$assembly_key/images/rg/system/bin/rg"

saved_key="$MOTOR_ASSEMBLY_KEY"
MOTOR_ASSEMBLY_KEY="$(printf stale | sha256sum | awk '{print $1}')"
if selector_read_pin "$PIN_PATH" >/dev/null 2>&1; then
	fail "stale pin was accepted"
fi
MOTOR_ASSEMBLY_KEY="$saved_key"

selector_main --clear >/dev/null
other_key="$(printf other | sha256sum | awk '{print $1}')"
write_assembly "$other_key"
if selector_main --resolve </dev/null >/dev/null 2>"$temporary/ambiguous"; then
	fail "noninteractive ambiguity was accepted"
fi
grep -Fq 'multiple assemblies are available' "$temporary/ambiguous" ||
	fail "ambiguity diagnostic omitted the candidates"
if selector_main --pin "$other_key" >/dev/null 2>&1; then
	fail "explicit pin accepted an incompatible assembly"
fi
selector_main --pin "$assembly_key" >/dev/null
[ "$(selector_main --resolve)" = "$temporary/assemblies/$assembly_key/images" ] ||
	fail "explicit pin was not persistent"

selector_main --clear >/dev/null
mv "$temporary/assemblies/$other_key" "$temporary/assemblies/$other_key.rejected"
touch "$temporary/assemblies/$other_key.rejected/MOTOR-ASSEMBLY-REJECTED"
(selector_main --resolve > "$temporary/one") & first=$!
(selector_main --resolve > "$temporary/two") & second=$!
wait "$first"; wait "$second"
cmp -s "$temporary/one" "$temporary/two" ||
	fail "concurrent selectors chose different assemblies"

printf 'malformed\n' > "$PIN_PATH"
if selector_main --resolve >/dev/null 2>&1; then
	fail "malformed pin was accepted"
fi

echo "test-toolchain-assembly-selection PASS"
