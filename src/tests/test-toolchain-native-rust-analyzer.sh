#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/toolchain-lib.sh"
. "$ROOT_DIR/src/toolchain-native-rust-analyzer.sh"
fail() { echo "test-toolchain-native-rust-analyzer: $*" >&2; exit 1; }
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
export ELF_FIXTURE="$temporary/elf"
mkdir -p "$ELF_FIXTURE"
EFFECTIVE_MOTOR_RUST_REV=0123456789abcdef0123456789abcdef01234567
SELECTED_TOOLCHAIN_DESCRIPTION=test-description
SELECTED_RUST_VERSION=1.99.0
MOTOR_RUST_CHANNEL=dev
VALIDATED_RUST_ANALYZER_VERSION='rust-analyzer 1.99.0-dev (012345678 2026-09-06)'
toolchain_rust_analyzer_release
binary="$temporary/analyzer"
printf '%s\n' "$EFFECTIVE_MOTOR_RUST_REV" "$RUST_ANALYZER_RELEASE" \
	"$SELECTED_TOOLCHAIN_DESCRIPTION" > "$binary"
chmod +x "$binary"
printf '%s\n' 'Class: ELF64' "Data: 2’s complement, little endian" 'Type: DYN' \
	'Machine: Advanced Micro Devices X86-64' 'LOAD 0 0 0 0 0 R E 0' \
	'GNU_STACK 0 0 0 0 0 RW 0' > "$ELF_FIXTURE/headers"
printf '  [12] .init_array INIT_ARRAY 00001200 001200 000010 08 WA 0 0 8\n' \
	> "$ELF_FIXTURE/sections"
for section in .eh_frame_hdr .eh_frame .gcc_except_table; do
	printf '  [13] %s PROGBITS 00002000 002000 000010 00 A 0 0 8\n' "$section" >> "$ELF_FIXTURE/sections"
done
printf '0x19 (INIT_ARRAY) 0x1200\n0x1b (INIT_ARRAYSZ) 16 (bytes)\n' > "$ELF_FIXTURE/dynamic"
printf '0: 0000000000000000 0 NOTYPE LOCAL DEFAULT UND\n' > "$ELF_FIXTURE/symbols"
reader="$temporary/readelf"
printf '%s\n' '#!/usr/bin/env bash' '[ "${READELF_FAIL:-0}" = 0 ] || exit 9' \
	'case "$2" in -h) cat "$ELF_FIXTURE/headers";; -S) cat "$ELF_FIXTURE/sections";;' \
	'-d) cat "$ELF_FIXTURE/dynamic";; --dyn-syms) cat "$ELF_FIXTURE/symbols";; *) exit 3;; esac' \
	> "$reader"
chmod +x "$reader"
toolchain_validate_rust_analyzer_elf "$binary" "$reader"
reject() {
	if toolchain_validate_rust_analyzer_elf "$binary" "$reader" 2>/dev/null; then
		fail "accepted $1"
	fi
}
for header in 'INTERP 0' 'TLS 0' 'LOAD 0 0 0 0 0 RWE 0'; do
	cp "$ELF_FIXTURE/headers" "$temporary/saved"
	printf '%s\n' "$header" >> "$ELF_FIXTURE/headers"
	reject "$header"
	cp "$temporary/saved" "$ELF_FIXTURE/headers"
done
for change in 's/ELF64/ELF32/' 's/Type: DYN/Type: EXEC/' \
	's/X86-64/AArch64/' 's/RW 0/RWE 0/' '/GNU_STACK/d'; do
	cp "$ELF_FIXTURE/headers" "$temporary/saved"
	sed -i "$change" "$ELF_FIXTURE/headers"
	reject "$change"
	cp "$temporary/saved" "$ELF_FIXTURE/headers"
done
for dynamic in '0x1 (NEEDED) library' '0x16 (TEXTREL) 0'; do
	cp "$ELF_FIXTURE/dynamic" "$temporary/saved"
	printf '%s\n' "$dynamic" >> "$ELF_FIXTURE/dynamic"
	reject "$dynamic"
	cp "$temporary/saved" "$ELF_FIXTURE/dynamic"
done
printf '1: 0000000000000000 0 NOTYPE GLOBAL DEFAULT UND missing\n' >> "$ELF_FIXTURE/symbols"
reject 'undefined dynamic symbol'
sed -i '$d' "$ELF_FIXTURE/symbols"
sed -i '/.init_array/s/000010/000000/' "$ELF_FIXTURE/sections"
reject 'empty constructor section'
sed -i '/.init_array/s/000000/000010/' "$ELF_FIXTURE/sections"
for section in .eh_frame_hdr .eh_frame .gcc_except_table; do
	cp "$ELF_FIXTURE/sections" "$temporary/saved"
	sed -i "/ $section /d" "$ELF_FIXTURE/sections"
	reject "missing $section"
	cp "$temporary/saved" "$ELF_FIXTURE/sections"
done
sed -i 's/16 (bytes)/0 (bytes)/' "$ELF_FIXTURE/dynamic"
reject 'empty constructor dynamic entry'
sed -i 's/0 (bytes)/16 (bytes)/' "$ELF_FIXTURE/dynamic"
export READELF_FAIL=1
reject 'reader failure'
unset READELF_FAIL
for identity in "$EFFECTIVE_MOTOR_RUST_REV" "$RUST_ANALYZER_RELEASE" "$SELECTED_TOOLCHAIN_DESCRIPTION"; do
	cp "$binary" "$temporary/saved"
	grep -Fxv "$identity" "$temporary/saved" > "$binary"
	reject "missing identity $identity"
	cp "$temporary/saved" "$binary"
done
toolchain_validate_rust_analyzer_elf "$binary" "$reader"
VALIDATED_RUST_ANALYZER_VERSION='rust-analyzer wrong'
if toolchain_rust_analyzer_release 2>/dev/null; then fail 'host release mismatch accepted'; fi
MOTOR_RUST_CHANNEL=beta
if toolchain_rust_analyzer_release 2>/dev/null; then fail 'unreviewed release channel accepted'; fi
MOTOR_RUST_CHANNEL=dev
VALIDATED_RUST_ANALYZER_VERSION='rust-analyzer 1.99.0-dev (012345678 2026-09-06)'
AUTHORING_SOURCE_DIGEST=none
export TOOLCHAIN_PREFIX="$temporary/prefix" ASSEMBLY_SYSROOT="$temporary/sysroot"
export ASSEMBLY_BUILD_ROOT="$temporary/build" ASSEMBLY_IMAGE_ROOT="$temporary/images"
export STANDALONE_LLVM_BIN="$temporary/llvm" RUST_ANALYZER_CARGO_CONFIG="$temporary/config"
export NATIVE_FIXTURE_BINARY="$binary" NATIVE_BUILD_CALLS="$temporary/calls"
rust="$temporary/rust"
library="$TOOLCHAIN_PREFIX/lib/rustlib/src/rust/library"
mkdir -p "$rust/src/tools/rust-analyzer" "$TOOLCHAIN_PREFIX/bin" \
	"$library/core/src" "$library/std/src" "$STANDALONE_LLVM_BIN"
printf core > "$library/core/src/lib.rs"
printf std > "$library/std/src/lib.rs"
mkdir -p "$library/backtrace/ci"
printf 'set -ex\n' > "$library/backtrace/ci/host-only.sh"
chmod 755 "$library/backtrace/ci/host-only.sh"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
	'[ "$RUSTC" = "$TOOLCHAIN_PREFIX/bin/rustc" ]' \
	'[ "$CARGO_PROFILE_RELEASE_OPT_LEVEL" = s ]' \
	'[ "$CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER" = "$ASSEMBLY_SYSROOT/bin/motor-clang" ]' \
	'[ "$CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS" = "-C link-self-contained=no -C default-linker-libraries=yes" ]' \
	'[ -z "${__CARGO_TESTS_ONLY_SRC_ROOT:-}" ]' \
	'[ "$CFG_RELEASE" = 1.99.0-dev ] && [ "$CFG_RELEASE_CHANNEL" = dev ]' \
	'[[ "$PWD" == */rust/src/tools/rust-analyzer ]]' \
	'[ "$*" = "build --release --locked --offline --target x86_64-unknown-motor -p rust-analyzer --config $RUST_ANALYZER_CARGO_CONFIG --target-dir $ASSEMBLY_BUILD_ROOT/rust-analyzer" ]' \
	'printf "cargo\n" >> "$NATIVE_BUILD_CALLS"' \
	'[ "${BUILD_FAIL:-0}" = 0 ] || exit 7' \
	'output="$ASSEMBLY_BUILD_ROOT/rust-analyzer/x86_64-unknown-motor/release/rust-analyzer"' \
	'mkdir -p "$(dirname "$output")"; cp "$NATIVE_FIXTURE_BINARY" "$output"' \
	> "$TOOLCHAIN_PREFIX/bin/cargo"
printf '%s\n' '#!/usr/bin/env bash' '[ "${STRIP_FAIL:-0}" = 0 ] || exit 8' \
	'[ "$1" = --keep-section=.comment ] && [ "$2" = -o ] || exit 9' \
	'cp "$4" "$3"' > "$STANDALONE_LLVM_BIN/llvm-strip"
chmod +x "$TOOLCHAIN_PREFIX/bin/cargo" "$STANDALONE_LLVM_BIN/llvm-strip"
ln -s "$reader" "$STANDALONE_LLVM_BIN/llvm-readelf"
toolchain_reverify_selected_sources() { printf 'source\n' >> "$NATIVE_BUILD_CALLS"; }
toolchain_reverify_rust_analyzer() { printf 'patch\n' >> "$NATIVE_BUILD_CALLS"; }
toolchain_postbuild_locks_unchanged() { printf 'locks\n' >> "$NATIVE_BUILD_CALLS"; }
toolchain_build_native_rust_analyzer "$rust" "$temporary/cargo" ''
[ "$(paste -sd, "$NATIVE_BUILD_CALLS")" = source,patch,cargo,locks,patch,source ] ||
	fail 'source/lock verification order differs'
staged="$ASSEMBLY_IMAGE_ROOT/rust-analyzer/devtools/rust"
cmp "$binary" "$staged/bin/rust-analyzer" || fail 'staged wrong binary'
cmp "$library/std/src/lib.rs" "$staged/lib/rustlib/src/rust/library/std/src/lib.rs" ||
	fail 'staged wrong rust-src'
cmp "$library/backtrace/ci/host-only.sh" "$staged/lib/rustlib/src/rust/library/backtrace/ci/host-only.sh" ||
	fail 'changed source contents'
[ ! -x "$staged/lib/rustlib/src/rust/library/backtrace/ci/host-only.sh" ] ||
	fail 'staged host source as a guest executable'
[ -x "$library/backtrace/ci/host-only.sh" ] || fail 'changed installed source permissions'
if toolchain_build_native_rust_analyzer "$rust" "$temporary/cargo" '' 2>/dev/null; then
	fail 'existing overlay was overwritten'
fi
for failure in BUILD_FAIL STRIP_FAIL; do
	ASSEMBLY_IMAGE_ROOT="$temporary/$failure"
	export "$failure=1"
	if toolchain_build_native_rust_analyzer "$rust" "$temporary/cargo" '' 2>/dev/null; then
		fail "$failure was ignored"
	fi
	unset "$failure"
	[ ! -e "$ASSEMBLY_IMAGE_ROOT/rust-analyzer" ] || fail 'published failed build'
	if [ -d "$ASSEMBLY_IMAGE_ROOT" ]; then
		[ -z "$(ls -A "$ASSEMBLY_IMAGE_ROOT")" ] || fail 'left temporary overlay'
	fi
done
export NATIVE_LIBRARY_MANIFEST="$rust/library/Cargo.toml"
printf '%s\n' '#!/usr/bin/env bash' 'set -e' '[ "${FETCH_FAIL:-0}" = 0 ] || exit 7' \
	'[ "$RUSTC" = "$TOOLCHAIN_PREFIX/bin/rustc" ]' \
	'[ "$*" = "fetch --locked --manifest-path $NATIVE_LIBRARY_MANIFEST" ]' \
	> "$TOOLCHAIN_PREFIX/bin/cargo"
toolchain_fetch_rust_analyzer_library "$rust" "$TOOLCHAIN_PREFIX"
export FETCH_FAIL=1
if toolchain_fetch_rust_analyzer_library "$rust" "$TOOLCHAIN_PREFIX"; then
	fail 'library source acquisition failure was ignored'
fi
echo 'test-toolchain-native-rust-analyzer PASS'
