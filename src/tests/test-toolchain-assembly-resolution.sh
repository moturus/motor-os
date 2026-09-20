#!/usr/bin/env bash

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/resolve-toolchain-assembly.sh"
fail() { echo "test-toolchain-assembly-resolution: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

# A fake selected toolchain: rustup reports it through a link, as it does for
# a linked prefix, and its stamp carries the toolchain key.
toolchain_key="$(printf toolchain | sha256sum | awk '{print $1}')"
prefix="$temporary/dev/toolchains/motor-test"
mkdir -p "$prefix/lib/rustlib"
printf '%s\n' "$toolchain_key" > "$prefix/lib/rustlib/MOTOR-TOOLCHAIN-KEY"
ln -s "$prefix" "$temporary/linked-toolchain"
rustc() { [ "$*" = '--print sysroot' ] && printf '%s\n' "$temporary/linked-toolchain"; }
toolchain_derive_consumed_assembly_identity "$toolchain_key"
assembly_key="$MOTOR_ASSEMBLY_KEY"
native_config="$NATIVE_CONFIGURATION_DIGEST"

write_assembly() {
	local key="$1" root manifest standalone_llvm_config_digest
	standalone_llvm_config_digest="$(toolchain_standalone_llvm_config_digest)"
	root="$temporary/dev/assemblies/$key"
	mkdir -p "$root/sysroot/devtools/llvm/lib" \
		"$root/images/llvm/devtools/llvm/bin" \
		"$root/images/rustc/devtools/rust/bin" \
		"$root/images/rg/system/bin" \
		"$root/images/libc/system/cfg/libc"
	mkdir -p "$root/images/rust-analyzer/devtools/rust/bin" \
		"$root/images/rust-analyzer/devtools/rust/lib/rustlib/src/rust/library/std/src"
	printf analyzer > "$root/images/rust-analyzer/devtools/rust/bin/rust-analyzer"
	printf rust-src > "$root/images/rust-analyzer/devtools/rust/lib/rustlib/src/rust/library/std/src/lib.rs"
	printf libc > "$root/sysroot/devtools/llvm/lib/libc.a"
	printf cxx > "$root/sysroot/devtools/llvm/lib/libc++.a"
	printf shim > "$root/sysroot/devtools/llvm/lib/libmoto_rt_cabi.a"
	printf llvm > "$root/images/llvm/devtools/llvm/bin/llvm"
	printf rustc > "$root/images/rustc/devtools/rust/bin/rustc"
	printf rustfmt > "$root/images/rustc/devtools/rust/bin/rustfmt"
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
		printf 'mlibc_rev=%s\nmlibc_tree_state=clean\n' "$MOTOR_MLIBC_REV"
		printf 'native_configuration_digest=%s\n' "$native_config"
		printf 'rust_analyzer_inputs_digest=%s\n' "$(toolchain_rust_analyzer_inputs_digest)"
		printf 'native_rust_analyzer_recipe=motor-native-rust-analyzer-v3-std\n'
		toolchain_rust_analyzer_manifest_fields
		printf 'native_rust_analyzer_sha256=%s\n' "$(sha256sum "$root/images/rust-analyzer/devtools/rust/bin/rust-analyzer" | awk '{print $1}')"
		printf 'rust_src_tree_sha256=%s\n' "$(toolchain_content_tree_digest "$root/images/rust-analyzer" devtools/rust/lib/rustlib/src/rust/library)"
		printf 'native_rustc_sha256=%s\n' "$(sha256sum "$root/images/rustc/devtools/rust/bin/rustc" | awk '{print $1}')"
		printf 'native_rustfmt_expected_version_base64=%s\n' "$(printf 'rustfmt test version' | base64 -w0)"
		printf 'native_rustfmt_sha256=%s\n' "$(sha256sum "$root/images/rustc/devtools/rust/bin/rustfmt" | awk '{print $1}')"
		printf 'native_llvm_sha256=%s\n' "$(sha256sum "$root/images/llvm/devtools/llvm/bin/llvm" | awk '{print $1}')"
		printf 'libc_sha256=%s\n' "$(sha256sum "$root/sysroot/devtools/llvm/lib/libc.a" | awk '{print $1}')"
		printf 'libcxx_sha256=%s\n' "$(sha256sum "$root/sysroot/devtools/llvm/lib/libc++.a" | awk '{print $1}')"
		printf 'moto_rt_cabi_sha256=%s\n' "$(sha256sum "$root/sysroot/devtools/llvm/lib/libmoto_rt_cabi.a" | awk '{print $1}')"
		printf 'libc_config_sha256=%s\n' "$(sha256sum "$root/images/libc/system/cfg/libc/shells" | awk '{print $1}')"
	} > "$manifest"
	chmod 0444 "$manifest"
	local overlay
	for overlay in llvm rustc libc rust-analyzer; do
		mkdir -p "$root/images/$overlay/devtools/toolchain"
		cp "$manifest" "$root/images/$overlay/devtools/toolchain/manifest"
		chmod 0444 "$root/images/$overlay/devtools/toolchain/manifest"
	done
}

assembly="$temporary/dev/assemblies/$assembly_key"
if resolver_main --resolve >/dev/null 2>"$temporary/missing"; then
	fail "a missing assembly was resolved"
fi
grep -Fq "$assembly_key" "$temporary/missing" && grep -Fq 'src/build-motor-os.sh' "$temporary/missing" ||
	fail "the missing assembly diagnostic names neither the key nor the producer"

# The assembly lives beside the selected toolchain and needs no selection.
write_assembly "$assembly_key"
write_assembly "$(printf other | sha256sum | awk '{print $1}')"
[ "$(resolver_main --resolve)" = "$assembly/images" ] || fail "the keyed assembly was not resolved"
resolver_main --show | grep -Fq "$assembly_key  managed/clean" ||
	fail "show did not describe the assembly"
[ -z "$(find "$temporary" -name '*pin*')" ] || fail "resolution stored a selection"
for command in --pin --clear --list; do
	if resolver_main "$command" >/dev/null 2>&1; then fail "$command is still accepted"; fi
done

# A rebuilt add-on is no assembly output; a modified toolchain output is.
printf changed >> "$assembly/images/rg/system/bin/rg"
resolver_main --resolve >/dev/null || fail "a rebuilt add-on invalidated the assembly"
printf changed >> "$assembly/images/llvm/devtools/llvm/bin/llvm"
if resolver_main --resolve >/dev/null 2>&1; then
	fail "modified assembly output was accepted"
fi
printf llvm > "$assembly/images/llvm/devtools/llvm/bin/llvm"

mkdir "$assembly.building"
if resolver_main --resolve >/dev/null 2>&1; then fail "an assembly under production was accepted"; fi
rmdir "$assembly.building"
touch "$assembly/MOTOR-ASSEMBLY-REJECTED"
if resolver_main --resolve >/dev/null 2>&1; then fail "a rejected assembly was accepted"; fi
rm "$assembly/MOTOR-ASSEMBLY-REJECTED"

# Another toolchain names another assembly.
printf '%s\n' "$(printf other-toolchain | sha256sum | awk '{print $1}')" > \
	"$prefix/lib/rustlib/MOTOR-TOOLCHAIN-KEY"
if resolver_main --resolve >/dev/null 2>&1; then
	fail "an assembly of another toolchain was resolved"
fi

echo "test-toolchain-assembly-resolution PASS"
