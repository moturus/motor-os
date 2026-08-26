#!/usr/bin/env bash
#
# build-motor-os.sh — build the complete Motor OS release environment and the
# base, standard, and development VM images.
#
# This is the single entry point for the exact toolchain pipeline: it provisions
# the host, resolves the declared Rust/LLVM source tuple, builds and validates a
# key-qualified host toolchain, then assembles the matching native development
# toolchain and images.
#
# Run it from a Motor OS checkout; sibling Rust, LLVM, mlibc, ripgrep, sysroot,
# and Lua sources/builds live under $MOTORH (the checkout's parent by default).
#
# Generated image inputs are staged beneath a key-qualified assembly directory.
#
# The tracked img_files directories remain source-only. The standard imager
# consumes the libc and rg roots; the development imager additionally consumes
# the LLVM and rustc roots.
#
# On-image layout (see docs/porting-libc/dirs.md): C/C++ headers + libraries
# live under /devtools/llvm, the clang driver config under /devtools/cfg/llvm,
# mlibc's config files under /system/cfg/libc, and the Rust toolchain at
# /devtools/rust — not the classic /usr and /etc.
#
# Re-running validates and reuses only complete outputs with the same exact key.

set -euo pipefail

log()  { printf '\033[1;34m[build-motor-os]\033[0m %s\n' "$*"; }
skip() { printf '\033[1;32m[build-motor-os]\033[0m (skip) %s\n' "$*"; }
warn() { printf '\033[1;33m[build-motor-os]\033[0m WARNING: %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[build-motor-os]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO"' ERR

usage() {
	cat << 'EOF'
Usage: src/build-motor-os.sh [--source-mode managed]
       src/build-motor-os.sh --source-mode authoring \
         --rust-source /absolute/path/to/rust --authoring-base FULL_COMMIT

Build the complete Motor OS release environment and all three images, including:
  - the exact key-qualified Rust 1.99 Motor toolchain;
  - host cross LLVM/Clang and the mlibc/libc++ sysroot;
  - native Motor OS LLVM/Clang, Lua, and rustc;
  - ripgrep as /system/bin/rg;
  - all standard and dev-image Motor OS binaries;
  - base, standard, and dev images under vm_images/release.

Environment:
  MOTORH  Development root for sibling checkouts and build trees.
          Defaults to the parent of the Motor OS checkout.
  MOTOR_SKIP_HOST_NETWORK_SETUP=1
          Skip build-base.sh's privileged tap/NAT setup after independently
          verifying that host VM networking is already configured.

Managed mode is the default. Authoring mode never fetches, switches, resets,
stashes, cleans, or updates the supplied Rust and LLVM worktrees.

The build is incremental and safe to rerun. It downloads managed sources and packages,
uses sudo for missing Ubuntu packages and host VM setup, and does not start the
VM.
EOF
}

parse_options() {
	SOURCE_MODE=managed
	RUST_SOURCE=
	AUTHORING_BASE=
	while [ "$#" -gt 0 ]; do
		case "$1" in
			-h|--help) usage; return 2 ;;
			--source-mode) [ "$#" -ge 2 ] || die "--source-mode needs a value"; SOURCE_MODE="$2"; shift 2 ;;
			--rust-source) [ "$#" -ge 2 ] || die "--rust-source needs a value"; RUST_SOURCE="$2"; shift 2 ;;
			--authoring-base) [ "$#" -ge 2 ] || die "--authoring-base needs a value"; AUTHORING_BASE="$2"; shift 2 ;;
			*) usage >&2; die "unknown argument: $1" ;;
		esac
	done
	case "$SOURCE_MODE" in
		managed)
			[ -z "$RUST_SOURCE$AUTHORING_BASE" ] ||
				die "managed mode does not accept authoring source options"
			;;
		authoring)
			case "$RUST_SOURCE" in /*) ;; *) die "authoring --rust-source must be absolute" ;; esac
			[[ "$AUTHORING_BASE" =~ ^[0-9a-f]{40}$ ]] ||
				die "authoring --authoring-base must be a full lowercase commit"
			;;
		*) die "unsupported source mode: $SOURCE_MODE" ;;
	esac
}

# --- paths (same scheme as docs/build-llvm.md and docs/build-rustc.md) -------
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
MOTOR="$(cd "$SCRIPT_DIR/.." && pwd)"
[ -e "$MOTOR/.git" ] ||
	die "run this script from its Motor OS checkout; .git is missing at $MOTOR"
. "$SCRIPT_DIR/toolchain-versions.sh"
. "$SCRIPT_DIR/toolchain-lib.sh"
. "$SCRIPT_DIR/toolchain-sources.sh"
. "$SCRIPT_DIR/toolchain-bootstrap.sh"
. "$SCRIPT_DIR/toolchain-state.sh"
. "$SCRIPT_DIR/toolchain-runtime.sh"
. "$SCRIPT_DIR/toolchain-prefix.sh"
. "$SCRIPT_DIR/toolchain-llvm.sh"
. "$SCRIPT_DIR/toolchain-host.sh"
. "$SCRIPT_DIR/toolchain-assembly.sh"
. "$SCRIPT_DIR/toolchain-native.sh"
toolchain_validate_versions || die "invalid src/toolchain-versions.sh"

MOTORH="$(readlink -f "${MOTORH:-$MOTOR/..}")"
export MOTORH
export MOTOR_OS_DIR="$MOTOR"

LLVM="$MOTORH/llvm-project"
MLIBC="$MOTORH/mlibc"
RUST="$MOTORH/rust"
TOOLCHAIN_SRC_ROOT="$MOTORH/toolchain-src"
RIPGREP="$MOTORH/ripgrep"
B="$LLVM/build/bin"                 # the host cross toolchain, built in stage 1
SYSROOT="$MOTORH/motor-sysroot"
CROSS_FILE="$MOTORH/motor.cross-file"
LUA_VER="$MOTOR_LUA_VERSION"
CLANG_MAJOR=""                      # detected after the host toolchain is built

HOST=x86_64-unknown-linux-gnu
TARGET=x86_64-unknown-motor
LLVM_IMG="$MOTOR/img_files/generated/llvm"
RUSTC_IMG="$MOTOR/img_files/generated/rustc"
RG_IMG="$MOTOR/img_files/generated/rg"
LIBC_IMG="$MOTOR/img_files/generated/libc"
MAKE_LOG="$MOTORH/build-motor-os-make.log"

prepare_exact_sources() {
	local source_mode="$1" rust_source="${2:-}" authoring_base="${3:-}"
	MLIBC="$TOOLCHAIN_SRC_ROOT/mlibc"
	toolchain_managed_checkout "$MOTOR_MLIBC_REPOSITORY" "$MOTOR_MLIBC_REF" \
		"$MOTOR_MLIBC_REV" "$MLIBC" "$MOTORH/mlibc" || return

	case "$source_mode" in
		managed)
			RUST="$TOOLCHAIN_SRC_ROOT/rust"
			toolchain_managed_checkout "$MOTOR_RUST_REPOSITORY" "$MOTOR_RUST_REF" \
				"$MOTOR_RUST_REV" "$RUST" "$MOTORH/rust" || return
			toolchain_managed_submodule "$RUST" src/llvm-project \
				"$MOTOR_LLVM_REPOSITORY" "$MOTOR_LLVM_REF" "$MOTOR_LLVM_REV" \
				"$MOTORH/llvm-project" || return
			toolchain_managed_submodule "$RUST" src/tools/cargo \
				"$MOTOR_CARGO_REPOSITORY" "$MOTOR_CARGO_REV" "$MOTOR_CARGO_REV" || return
			local backtrace_rev
			backtrace_rev="$(toolchain_gitlink "$RUST" HEAD library/backtrace)" || return
			toolchain_managed_submodule "$RUST" library/backtrace \
				"$RUST_BACKTRACE_REPOSITORY" "$backtrace_rev" "$backtrace_rev" || return
			toolchain_verify_managed_rust "$RUST" || return
			MOTOR_SOURCE_MODE=managed
			SELECTED_UPSTREAM_RUST_REV="$UPSTREAM_RUST_REV"
			SELECTED_RUST_VERSION="$UPSTREAM_RUST_VERSION"
			SELECTED_STAGE0_REV="$UPSTREAM_STAGE0_REV"
			SELECTED_RUST_LLVM_BASE_REV="$RUST_LLVM_BASE_REV"
			SELECTED_MOTOR_CARGO_VERSION="$MOTOR_CARGO_VERSION"
			SELECTED_MOTOR_CARGO_REV="$MOTOR_CARGO_REV"
			SELECTED_RUSTUP_TOOLCHAIN_BASE="$MOTOR_RUSTUP_TOOLCHAIN_BASE"
			SELECTED_TOOLCHAIN_DESCRIPTION="$MOTOR_TOOLCHAIN_ID"
			EFFECTIVE_MOTOR_RUST_REV="$MOTOR_RUST_REV"
			EFFECTIVE_MOTOR_LLVM_REV="$MOTOR_LLVM_REV"
			MOTOR_RUST_TREE_STATE=clean
			MOTOR_LLVM_TREE_STATE=clean
			AUTHORING_SOURCE_DIGEST=none
			MOTOR_ASSEMBLY_STATE=clean
			;;
		authoring)
			[ -n "$rust_source" ] || die "authoring mode requires --rust-source"
			[ -n "$authoring_base" ] || die "authoring mode requires --authoring-base"
			RUST="$(readlink -f "$rust_source")"
			toolchain_authoring_resolve "$RUST" "$authoring_base" || return
			;;
		*) die "unsupported source mode: $source_mode" ;;
	esac
	LLVM="$RUST/src/llvm-project"
}

activate_exact_assembly_paths() {
	B="$STANDALONE_LLVM_BIN"
	SYSROOT="$ASSEMBLY_SYSROOT"
	CROSS_FILE="$ASSEMBLY_ROOT/motor.cross-file"
	LLVM_IMG="$ASSEMBLY_IMAGE_ROOT/llvm"
	RUSTC_IMG="$ASSEMBLY_IMAGE_ROOT/rustc"
	RG_IMG="$ASSEMBLY_IMAGE_ROOT/rg"
	LIBC_IMG="$ASSEMBLY_IMAGE_ROOT/libc"
	SHIM_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/moto-rt-cabi"
	BUILTINS_BUILD="$ASSEMBLY_BUILD_ROOT/compiler-rt-builtins"
	MLIBC_HEADERS_BUILD="$ASSEMBLY_BUILD_ROOT/mlibc-headers"
	MLIBC_BUILD="$ASSEMBLY_BUILD_ROOT/mlibc"
	CXX_BUILD="$ASSEMBLY_BUILD_ROOT/libcxx"
	NATIVE_LLVM_BUILD="$ASSEMBLY_BUILD_ROOT/native-llvm"
	LUA_BUILD="$ASSEMBLY_BUILD_ROOT/lua"
	RIPGREP_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/ripgrep"
	MOTOR_CARGO="$TOOLCHAIN_PREFIX/bin/cargo"
	RUSTLIB_SRC="$TOOLCHAIN_PREFIX/lib/rustlib/$TARGET/lib"
}

configure_exact_cross_driver() {
	cat > "$B/x86_64-unknown-motor.cfg" <<'EOF'
-fuse-ld=lld
-static-pie
-nostdlib
-Wl,-e,motor_start
-Wl,--pack-dyn-relocs=none
-Wl,-z,noexecstack
EOF
	CLANG_MAJOR="$("$B/clang" --version |
		sed -n 's/.*clang version \([0-9]\{1,\}\).*/\1/p' | head -1)"
	[ -n "$CLANG_MAJOR" ] || die "could not determine clang major version"
}

# On-image directory prefixes (mirrored inside the cross sysroot). Keep these in
# sync with clang/lib/Driver/ToolChains/Motor.cpp and mlibc's MLIBC_SYSCONFDIR.
TOOLS="devtools/llvm"              # headers + libraries
CFG_LLVM="devtools/cfg/llvm"       # clang <triple>.cfg
CFG_LIBC="system/cfg/libc"         # mlibc config files (resolv.conf, ...)

# ============================================================================
# LLVM stage: the Motor OS native LLVM/Clang toolchain, the C/C++ sysroot
# (mlibc + libc++ stack), and Lua, staged into img_files/generated/llvm.
# See docs/build-llvm.md for the prose walkthrough behind each numbered stage.
# ============================================================================

# --- meson (the one extra host package build-base does not install) ----------
ensure_meson() {
	if command -v meson >/dev/null 2>&1; then
		skip "meson already installed"
		return
	fi
	if ! command -v apt-get >/dev/null 2>&1; then
		warn "apt-get not found; install meson manually."
		return
	fi
	log "installing meson"
	sudo apt-get update
	sudo DEBIAN_FRONTEND=noninteractive apt-get -y install meson
}

# --- ancillary source checkout ---------------------------------------------
update_ripgrep_source() {
	local url="https://github.com/moturus/ripgrep.git" branch="master"
	if [ ! -e "$RIPGREP" ]; then
		log "cloning ripgrep ($branch)"
		git clone --branch "$branch" --single-branch "$url" "$RIPGREP"
		return
	fi
	git -C "$RIPGREP" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
		die "$RIPGREP exists but is not a Git checkout"
	[ "$(git -C "$RIPGREP" branch --show-current)" = "$branch" ] ||
		die "ripgrep checkout must be on branch $branch: $RIPGREP"
	[ -z "$(git -C "$RIPGREP" status --porcelain)" ] ||
		die "ripgrep checkout is dirty — preserve its changes and re-run: $RIPGREP"

	log "updating ripgrep ($branch)"
	git -C "$RIPGREP" fetch "$url" "$branch"
	local head remote
	head="$(git -C "$RIPGREP" rev-parse HEAD)"
	remote="$(git -C "$RIPGREP" rev-parse FETCH_HEAD)"
	if [ "$head" = "$remote" ]; then
		skip "ripgrep already current"
		return
	fi
	git -C "$RIPGREP" merge-base --is-ancestor "$head" "$remote" ||
		die "ripgrep checkout has local or diverged commits — update it manually: $RIPGREP"
	git -C "$RIPGREP" merge --ff-only "$remote"
}

# --- stage 2: the C-ABI shim (libmoto_rt_cabi.a) ----------------------------
build_shim() {
	log "stage 2: building the moto-rt-cabi shim"
	local rustlibs=("$RUSTLIB_SRC"/*.rlib) symbol
	for symbol in motor_start memcpy memmove memset memcmp; do
		if "$B/llvm-nm" --defined-only "${rustlibs[@]}" 2>/dev/null |
				awk -v symbol="$symbol" '$2 ~ /^[Tt]$/ && $3 == symbol { found = 1 } END { exit !found }'; then
			die "Motor target libraries define strong $symbol; mixed Rust+C links are unsafe"
		fi
	done
	mkdir -p "$SYSROOT/$TOOLS/lib" "$SYSROOT/$TOOLS/include"
	( cd "$MOTOR/src/sys/lib/moto-rt-cabi" \
		&& CARGO_TARGET_DIR="$SHIM_TARGET_DIR" \
		"$MOTOR_CARGO" build --target x86_64-unknown-motor --release )
	cp "$SHIM_TARGET_DIR/x86_64-unknown-motor/release/libmoto_rt_cabi.a" \
		"$SYSROOT/$TOOLS/lib/"
	for symbol in motor_start memcpy memmove memset memcmp; do
		if "$B/llvm-nm" --defined-only \
				"$SYSROOT/$TOOLS/lib/libmoto_rt_cabi.a" 2>/dev/null |
				awk -v symbol="$symbol" '$2 ~ /^[Tt]$/ && $3 == symbol { found = 1 } END { exit !found }'; then
			die "moto-rt-cabi defines strong $symbol; mixed Rust+C links are unsafe"
		fi
	done
	cp "$MOTOR/src/sys/lib/moto-rt-cabi/moto_rt.h" "$SYSROOT/$TOOLS/include/"
}

# --- stage 3: compiler-rt builtins (emutls excluded) ------------------------
build_builtins() {
	log "stage 3: building compiler-rt builtins"
	# -ffreestanding: the builtins are freestanding, and it keeps clang's
	# resource limits.h/stdint.h from #include_next-ing into the host's glibc
	# headers. The Motor ToolChain adds <sysroot>/devtools/llvm/include, which
	# is empty under the cross sysroot at this stage (mlibc's headers do not
	# exist yet). (The old host cfg used to supply -ffreestanding here.)
	#
	# CMAKE_DISABLE_FIND_PACKAGE_LLVM=ON: the standalone builtins build calls a
	# non-REQUIRED find_package(LLVM) (compiler-rt/.../CompilerRTUtils.cmake,
	# load_llvm_config). With no hint it searches system paths and, on a host
	# that has a distro LLVM -dev package installed (e.g. /usr/lib/llvm-21),
	# loads that package's LLVMExports.cmake — which declares the libLLVM/LTO/
	# Remarks dylibs as `SHARED IMPORTED`. Under CMAKE_SYSTEM_NAME=Generic the
	# platform has no dynamic linking, and newer CMake makes an imported SHARED
	# target a hard error ("... target platform does not support dynamic
	# linking"), aborting the configure. The builtins don't need LLVM at all:
	# disabling the lookup forces compiler-rt's built-in mock-config fallback,
	# which is the same path taken on a host with no system LLVM. (Pointing at
	# the freshly built build tree would not help — its exports carry the same
	# SHARED-imported LTO/Remarks targets.)
	cmake -S "$LLVM/compiler-rt/lib/builtins" -B "$BUILTINS_BUILD" -G Ninja \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_SYSTEM_NAME=Generic \
		-DCMAKE_SYSTEM_PROCESSOR=x86_64 \
		-DCMAKE_C_FLAGS="-ffreestanding" \
		-DCMAKE_C_COMPILER="$B/clang" \
		-DCMAKE_C_COMPILER_TARGET=x86_64-unknown-motor \
		-DCMAKE_ASM_COMPILER="$B/clang" \
		-DCMAKE_ASM_COMPILER_TARGET=x86_64-unknown-motor \
		-DCMAKE_AR="$B/llvm-ar" -DCMAKE_RANLIB="$B/llvm-ranlib" -DCMAKE_NM="$B/llvm-nm" \
		-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
		-DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
		-DCOMPILER_RT_BAREMETAL_BUILD=ON \
		-DCMAKE_DISABLE_FIND_PACKAGE_LLVM=ON
	ninja -C "$BUILTINS_BUILD"

	local builtins
	builtins="$(find "$BUILTINS_BUILD" -name 'libclang_rt.builtins*.a' | head -1)"
	[ -n "$builtins" ] || die "builtins archive not produced"

	# emutls.c must not be present (the shim owns emulated TLS).
	if "$B/llvm-ar" t "$builtins" | grep -q emutls; then
		"$B/llvm-ar" d "$builtins" emutls.c.o
	fi
	if "$B/llvm-nm" "$builtins" 2>/dev/null | grep -q __emutls; then
		warn "__emutls_* still present in builtins — expected it excluded"
	fi

	# Stage a copy in the sysroot and one at the per-target resource-dir path
	# where both mlibc's build and the clang driver look for it.
	cp "$builtins" "$SYSROOT/$TOOLS/lib/libclang_rt.builtins-x86_64.a"
	local rd="$STANDALONE_LLVM_BUILD/lib/clang/$CLANG_MAJOR/lib/x86_64-unknown-motor"
	mkdir -p "$rd"
	cp "$builtins" "$rd/libclang_rt.builtins.a"
}

# --- stage 4: mlibc ---------------------------------------------------------
build_mlibc() {
	log "stage 4: building mlibc"
	# Meson cross file with this machine's absolute paths (kept out of the repos).
	# MLIBC_SYSCONFDIR repoints mlibc's runtime config lookups (resolv.conf,
	# hosts, passwd, ...) from /etc to /system/cfg/libc.
	cat > "$CROSS_FILE" << EOF
[binaries]
c = ['$B/clang', '--target=x86_64-unknown-motor']
cpp = ['$B/clang++', '--target=x86_64-unknown-motor']
ar = '$B/llvm-ar'
strip = '$B/llvm-strip'

[host_machine]
system = 'motor'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'

[built-in options]
c_args = ['-I$SYSROOT/$TOOLS/include', '-D_GNU_SOURCE', '-DMLIBC_SYSCONFDIR="/$CFG_LIBC"']
cpp_args = ['-I$SYSROOT/$TOOLS/include', '-D_GNU_SOURCE', '-DMLIBC_SYSCONFDIR="/$CFG_LIBC"']

[properties]
needs_exe_wrapper = true
EOF
	local cross_hash
	cross_hash="$(sha256sum "$CROSS_FILE" | cut -d ' ' -f 1)"

	( cd "$MLIBC"
		setup_mlibc_build() {
			local build_dir="$1"
			shift
			local stamp="$build_dir/.motor-cross-file.sha256"
			local setup_mode=()
			if [ -f "$build_dir/build.ninja" ]; then
				if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$cross_hash" ]; then
					setup_mode=(--reconfigure)
				else
					die "keyed mlibc build has a mismatched cross-file stamp: $build_dir"
				fi
			fi
			meson setup "${setup_mode[@]}" --cross-file "$CROSS_FILE" \
				--prefix="/$TOOLS" "$@" "$build_dir"
			printf '%s\n' "$cross_hash" > "$stamp"
		}

		# Headers first (validates ABI/meson wiring quickly).
		setup_mlibc_build "$MLIBC_HEADERS_BUILD" -Dheaders_only=true
		DESTDIR="$SYSROOT" ninja -C "$MLIBC_HEADERS_BUILD" install

		# The real static build: libc.a, crt1.o, headers, companion stubs.
		# -Ddebug=false: mlibc's meson.build pins buildtype=debugoptimized
		# (-O2 -g); the flag keeps -O2 and drops only -g. Without it libc.a is
		# 18 MB (59% DWARF) and every mlibc-linked binary carries ~6.6 MB of
		# debug info (see docs/libc_start_redesign.md). .text is byte-identical.
		setup_mlibc_build "$MLIBC_BUILD" -Ddefault_library=static \
			-Dbuild_tests=false -Ddebug=false
		ninja -C "$MLIBC_BUILD"
		DESTDIR="$SYSROOT" ninja -C "$MLIBC_BUILD" install )

	ls "$SYSROOT/$TOOLS/lib/libc.a" "$SYSROOT/$TOOLS/lib/crt1.o" >/dev/null
}

# --- stage 5: the C++ runtime stack (with exceptions) -----------------------
build_cxx_runtimes() {
	log "stage 5: building libunwind + libc++abi + libc++ (exceptions on)"
	cmake -G Ninja -S "$LLVM/runtimes" -B "$CXX_BUILD" \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_COMPILER="$B/clang" -DCMAKE_CXX_COMPILER="$B/clang++" \
		-DCMAKE_C_COMPILER_TARGET=x86_64-unknown-motor \
		-DCMAKE_CXX_COMPILER_TARGET=x86_64-unknown-motor \
		-DCMAKE_SYSTEM_NAME=Generic \
		-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
		-DCMAKE_C_FLAGS="-isystem $SYSROOT/$TOOLS/include -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_LIBUNWIND_USE_DLADDR=0" \
		-DCMAKE_CXX_FLAGS="-isystem $SYSROOT/$TOOLS/include -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_LIBUNWIND_USE_DLADDR=0" \
		-DCMAKE_INSTALL_PREFIX="/$TOOLS" \
		-DLLVM_ENABLE_RUNTIMES="libunwind;libcxxabi;libcxx" \
		-DLLVM_USE_LINKER=lld \
		-DLIBUNWIND_ENABLE_SHARED=OFF -DLIBUNWIND_ENABLE_STATIC=ON \
		-DLIBUNWIND_ENABLE_THREADS=ON \
		-DLIBUNWIND_USE_COMPILER_RT=ON \
		-DLIBUNWIND_INCLUDE_TESTS=OFF \
		-DLIBUNWIND_HAS_PTHREAD_LIB=OFF -DLIBUNWIND_HAS_DL_LIB=OFF \
		-DLIBCXXABI_ENABLE_SHARED=OFF -DLIBCXXABI_ENABLE_STATIC=ON \
		-DLIBCXXABI_ENABLE_EXCEPTIONS=ON \
		-DLIBCXXABI_ENABLE_THREADS=ON \
		-DLIBCXXABI_USE_COMPILER_RT=ON \
		-DLIBCXXABI_USE_LLVM_UNWINDER=ON \
		-DLIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL=OFF \
		-DLIBCXXABI_ENABLE_ASSERTIONS=OFF \
		-DLIBCXXABI_HAS_PTHREAD_LIB=OFF \
		-DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC=ON \
		-DLIBCXX_ENABLE_EXCEPTIONS=ON -DLIBCXX_ENABLE_RTTI=ON \
		-DLIBCXX_ENABLE_THREADS=ON -DLIBCXX_HAS_PTHREAD_API=ON \
		-DLIBCXX_ENABLE_MONOTONIC_CLOCK=ON \
		-DLIBCXX_ENABLE_RANDOM_DEVICE=ON \
		-DLIBCXX_ENABLE_WIDE_CHARACTERS=ON \
		-DLIBCXX_ENABLE_LOCALIZATION=ON \
		-DLIBCXX_ENABLE_FILESYSTEM=ON \
		-DLIBCXX_CXX_ABI=libcxxabi \
		-DLIBCXX_USE_COMPILER_RT=ON \
		-DLIBCXX_HAS_PTHREAD_LIB=OFF -DLIBCXX_HAS_RT_LIB=OFF \
		-DLIBCXX_HAS_ATOMIC_LIB=OFF \
		-DLIBCXX_INCLUDE_BENCHMARKS=OFF -DLIBCXX_INCLUDE_TESTS=OFF
	ninja -C "$CXX_BUILD" unwind cxxabi cxx
	DESTDIR="$SYSROOT" ninja -C "$CXX_BUILD" \
		install-unwind install-cxxabi install-cxx

	ls "$SYSROOT/$TOOLS/lib/libc++.a" "$SYSROOT/$TOOLS/lib/libc++abi.a" \
		"$SYSROOT/$TOOLS/lib/libunwind.a" >/dev/null
}

# --- stage 6: the native LLVM toolchain (the on-image `llvm`) ----------------
build_native_llvm() {
	log "stage 6: building the native (on-image) LLVM toolchain"
	# The STANDARD_LIBRARIES mirror the Motor ToolChain's link group (shim first
	# so its __cxa_thread_atexit wins; -lunwind for the EH runtime). Both the C
	# and C++ groups carry -lc++abi: mlibc is implemented in C++, so even a C link
	# pulls `operator delete`/`new` from libc.a members (this matches the Motor
	# ToolChain's ConstructJob, which adds -lc++abi unconditionally). The
	# assembly key selects a fresh build directory whenever these inputs change,
	# so cached try-compile results cannot cross configurations.
	cmake -S "$LLVM/llvm" -B "$NATIVE_LLVM_BUILD" -G Ninja \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_SYSTEM_NAME=Linux \
		-DCMAKE_C_COMPILER="$B/clang" \
		-DCMAKE_CXX_COMPILER="$B/clang++" \
		-DCMAKE_C_COMPILER_TARGET=x86_64-unknown-motor \
		-DCMAKE_CXX_COMPILER_TARGET=x86_64-unknown-motor \
		-DCMAKE_C_FLAGS="-isystem $SYSROOT/$TOOLS/include -D_GNU_SOURCE -D_DEFAULT_SOURCE" \
		-DCMAKE_CXX_FLAGS="-nostdinc++ -isystem $SYSROOT/$TOOLS/include/c++/v1 -isystem $SYSROOT/$TOOLS/include -D_GNU_SOURCE -D_DEFAULT_SOURCE" \
		-DCMAKE_C_STANDARD_LIBRARIES="$SYSROOT/$TOOLS/lib/crt1.o -Wl,--start-group -lmoto_rt_cabi -lc++abi -lunwind -lc -lclang_rt.builtins-x86_64 -Wl,--end-group" \
		-DCMAKE_CXX_STANDARD_LIBRARIES="$SYSROOT/$TOOLS/lib/crt1.o -Wl,--start-group -lmoto_rt_cabi -lc++ -lc++abi -lunwind -lc -lclang_rt.builtins-x86_64 -Wl,--end-group" \
		-DCMAKE_EXE_LINKER_FLAGS="-L$SYSROOT/$TOOLS/lib" \
		-DCMAKE_TRY_COMPILE_PLATFORM_VARIABLES="CMAKE_C_STANDARD_LIBRARIES;CMAKE_CXX_STANDARD_LIBRARIES" \
		-DLLVM_HOST_TRIPLE=x86_64-unknown-motor \
		-DLLVM_DEFAULT_TARGET_TRIPLE=x86_64-unknown-motor \
		-DLLVM_TARGETS_TO_BUILD=X86 \
		-DLLVM_ENABLE_PROJECTS="clang;lld" \
		-DLLVM_TOOL_LLVM_DRIVER_BUILD=ON \
		-DLLVM_NATIVE_TOOL_DIR="$B" \
		-DLLVM_ENABLE_THREADS=ON \
		-DLLVM_ENABLE_ZLIB=OFF -DLLVM_ENABLE_ZSTD=OFF -DLLVM_ENABLE_LIBXML2=OFF \
		-DLLVM_ENABLE_LIBEDIT=OFF -DLLVM_ENABLE_PLUGINS=OFF \
		-DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF \
		-DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_INCLUDE_DOCS=OFF \
		-DCLANG_ENABLE_STATIC_ANALYZER=OFF \
		-DCLANG_DEFAULT_LINKER=lld -DCLANG_DEFAULT_RTLIB=compiler-rt \
		-DCLANG_DEFAULT_CXX_STDLIB=libc++ \
		-DDEFAULT_SYSROOT= \
		-DCLANG_CONFIG_FILE_SYSTEM_DIR="/$CFG_LLVM"

	ninja -C "$NATIVE_LLVM_BUILD" llvm-driver
}

# --- stage 7: Lua -----------------------------------------------------------
build_lua() {
	log "stage 7: building Lua $LUA_VER"
	( cd "$MOTORH"
		[ -f "lua-$LUA_VER.tar.gz" ] || curl -LO "https://www.lua.org/ftp/lua-$LUA_VER.tar.gz"
		[ -d "lua-$LUA_VER" ] || tar xf "lua-$LUA_VER.tar.gz" )

	( cd "$MOTORH/lua-$LUA_VER/src"
		mkdir -p "$LUA_BUILD"
		local cflags="--target=x86_64-unknown-motor -O2 -isystem $SYSROOT/$TOOLS/include -DLUA_USE_POSIX"
		local f object
		for f in ./*.c; do
			case "$f" in ./lua.c|./luac.c) continue ;; esac
			object="$LUA_BUILD/$(basename "${f%.c}").o"
			# shellcheck disable=SC2086
			"$B/clang" $cflags -c "$f" -o "$object"
		done
		"$B/llvm-ar" rcs "$LUA_BUILD/liblua.a" "$LUA_BUILD"/*.o
		# mlibc is C++ internally (its stdio FILE machinery — cookie_file,
		# memstream, fmemopen — has C++ destructors that call `operator delete`),
		# so even this pure-C program pulls libc++abi/libunwind out of libc.a and
		# must link them. Mirror the C link group the Motor ToolChain emits: the
		# host cfg forces -nostdlib, suppressing that default group, so it is listed
		# explicitly. --start-group resolves the libc <-> libc++abi <-> shim
		# back-references regardless of order.
		# shellcheck disable=SC2086
		"$B/clang" $cflags lua.c "$LUA_BUILD/liblua.a" \
			"$SYSROOT/$TOOLS/lib/crt1.o" \
			-Wl,--start-group \
			"$SYSROOT/$TOOLS/lib/libmoto_rt_cabi.a" \
			"$SYSROOT/$TOOLS/lib/libc++abi.a" \
			"$SYSROOT/$TOOLS/lib/libunwind.a" \
			"$SYSROOT/$TOOLS/lib/libc.a" \
			"$SYSROOT/$TOOLS/lib/libclang_rt.builtins-x86_64.a" \
			-Wl,--end-group -o "$LUA_BUILD/lua" )
}

# --- stage 8: stage the C/C++ toolchain into the image ----------------------
llvm_stage_image() {
	log "stage 8: staging the toolchain, sysroot, and Lua into img_files/generated/llvm"
	local img="$LLVM_IMG"
	[ ! -e "$ASSEMBLY_IMAGE_ROOT" ] ||
		die "assembly image staging root already exists without validated reuse: $ASSEMBLY_IMAGE_ROOT"
	mkdir -p "$img/devtools/bin" "$img/devtools/src" "$img/$TOOLS/bin" "$img/$TOOLS/lib" \
		"$img/$CFG_LLVM" "$LIBC_IMG/$CFG_LIBC"

	# Headers: mlibc + libc++'s c++/v1 in the fresh keyed image root.
	cp -a "$SYSROOT/$TOOLS/include" "$img/$TOOLS/include"

	# Clang's own resource headers (intrinsics, stdarg.h, ...).
	mkdir -p "$img/$TOOLS/lib/clang/$CLANG_MAJOR"
	cp -a "$STANDALONE_LLVM_BUILD/lib/clang/$CLANG_MAJOR/include" \
		"$img/$TOOLS/lib/clang/$CLANG_MAJOR/include"

	# Libraries — strip debug info on the way in.
	local a
	for a in libc libc++ libc++abi libunwind libmoto_rt_cabi \
	         libclang_rt.builtins-x86_64 \
	         libdl libm libpthread librt libresolv libutil libssp libssp_nonshared; do
		"$B/llvm-objcopy" --strip-debug "$SYSROOT/$TOOLS/lib/$a.a" "$img/$TOOLS/lib/$a.a"
	done
	cp "$SYSROOT/$TOOLS/lib/crt1.o" "$img/$TOOLS/lib/"

	# The on-image LLVM multicall lives under /devtools/llvm/bin, mirroring the
	# Rust toolchain at /devtools/rust/bin (build-rustc.md). Its clang config and
	# resource dir are pinned by absolute path (the /devtools/cfg/llvm .cfg + the baked
	# CLANG_CONFIG_FILE_SYSTEM_DIR), and its ld.lld self-dispatch uses the running
	# exe's own path, so the binary works wherever it is placed. Lua is a direct
	# development executable under /devtools/bin.
	"$B/llvm-strip" -o "$img/$TOOLS/bin/llvm" "$NATIVE_LLVM_BUILD/bin/llvm"
	"$B/llvm-strip" -o "$img/devtools/bin/lua" "$LUA_BUILD/lua"

	# /devtools/bin/cc — the C compiler / linker driver: a Rush script (not
	# a compiled binary) over the llvm multicall's clang. rustc's default linker
	# is the bare name `cc`, resolved through the dev image PATH, so a native
	# `rustc hello.rs -o hello` links with no `-C linker=` flag — exactly as rustc
	# uses /usr/bin/cc on Linux. A pure pass-through: the Motor clang ToolChain
	# owns the whole link recipe (crt1.o + the mlibc/libc++ group, incl. libc++abi
	# for C links) and gates it on -nostdlib/-nostartfiles/-nodefaultlibs, so a
	# plain `cc hello.c` gets the full C runtime while rustc's pure-Rust links
	# (which pass -nostartfiles -nodefaultlibs) get nothing forced on them — a
	# pure-Rust hello is ~113 KB, not 8 MB (docs/libc_start_redesign.md). Rust
	# programs that *want* mlibc opt back into the ToolChain recipe with
	# `-C link-self-contained=no -C default-linker-libraries=yes` (build-rustc.md).
	cat > "$img/devtools/bin/cc" << 'EOF'
#!/system/bin/rush
# cc — Motor OS's system C compiler / linker driver. See docs/build-llvm.md.
# A pass-through: clang's Motor ToolChain owns the link recipe and honors
# -nostartfiles/-nodefaultlibs (rustc's pure-Rust links stay mlibc-free).
export TMPDIR=/devtools/tmp
exec /devtools/llvm/bin/llvm clang "$@"
EOF

	# /devtools/bin/c++ — same, in C++ driver mode (adds -lc++ at link).
	# rather than a `clang++` subcommand: the multicall dispatches on the first
	# argument, and `clang++` is not a registered subcommand name.
	cat > "$img/devtools/bin/c++" << 'EOF'
#!/system/bin/rush
# c++ — Motor OS's system C++ compiler / linker driver. See docs/build-llvm.md.
export TMPDIR=/devtools/tmp
exec /devtools/llvm/bin/llvm clang --driver-mode=g++ "$@"
EOF
	chmod +x "$img/devtools/bin/cc" "$img/devtools/bin/c++"

	# The image driver config: only the resource dir needs pinning (the full
	# link/include recipe lives in the Motor ToolChain now). Clang auto-loads it
	# from /devtools/cfg/llvm (CLANG_CONFIG_FILE_SYSTEM_DIR, stage 6).
	cat > "$img/$CFG_LLVM/x86_64-unknown-motor.cfg" << EOF
-resource-dir /$TOOLS/lib/clang/$CLANG_MAJOR
EOF

	# Ship libc's hosts and services databases. sys-io atomically generates
	# resolv.conf from static per-device configuration or active DHCP leases.
	cat > "$LIBC_IMG/$CFG_LIBC/services" << 'EOF'
domain 53/tcp
domain 53/udp
EOF
	cat > "$LIBC_IMG/$CFG_LIBC/hosts" << 'EOF'
127.0.0.1 localhost
::1 localhost
127.0.0.53 motor-dns-test
::1 motor-dns-test
EOF
	cat > "$LIBC_IMG/$CFG_LIBC/shells" << 'EOF'
/system/bin/sh
/system/bin/rush
EOF

	# Sample sources to compile natively in the VM.
	cat > "$img/devtools/src/hello.c" << 'EOF'
#include <stdio.h>

int main(void) {
	printf("Hello from Motor-native clang!\n");
	return 0;
}
EOF
	cat > "$img/devtools/src/hello.cpp" << 'EOF'
#include <iostream>
#include <string>
#include <vector>

int main() {
	std::vector<std::string> words{"Hello", "from", "Motor-native", "clang++!"};
	std::string out;
	for (const auto &w : words) {
		if (!out.empty())
			out += ' ';
		out += w;
	}
	std::cout << out << std::endl;
	return 0;
}
EOF
	cp "$MOTOR/src/sys/tests/native-fstat.c" "$img/devtools/src/native-fstat.c"
	cp "$MOTOR/src/sys/tests/native-temp.c" "$img/devtools/src/native-temp.c"
	cp "$MOTOR/src/sys/tests/native-temp.cpp" "$img/devtools/src/native-temp.cpp"
}

# cc — the C compiler / linker driver rustc uses on the image — is not built
# here: it is a Rush script produced by the LLVM stage (it
# belongs with the C toolchain: it fronts /devtools/llvm/bin/llvm and the
# sysroot libs). rustc's default linker is the bare name `cc`, resolved on PATH
# through the dev image PATH, so a native `rustc hello.rs -o hello` links with no
# `-C linker=` flag, exactly as rustc uses /usr/bin/cc on Linux.

# --- stage rustc + the Rust sysroot into the image ----------------------------
rustc_stage_image() {
	log "staging rustc and the Rust sysroot into img_files/generated/rustc"
	[ ! -e "$RUSTC_IMG" ] ||
		die "Rust image staging already exists without validated reuse: $RUSTC_IMG"
	local rust_img="$RUSTC_IMG/devtools/rust"
	mkdir -p "$RUSTC_IMG/devtools/bin" "$RUSTC_IMG/devtools/src" "$rust_img/bin" \
		"$rust_img/lib/rustlib/$TARGET"

	# The compiler, stripped (~154 MB -> ~98 MB).
	"$B/llvm-strip" -o "$rust_img/bin/rustc" "$RUSTC_MAIN"
	cat > "$RUSTC_IMG/devtools/bin/rustc" << 'EOF'
#!/system/bin/rush
export TMPDIR=/devtools/tmp
exec /devtools/rust/bin/rustc "$@"
EOF
	chmod +x "$RUSTC_IMG/devtools/bin/rustc"
	# A binary that still carries mlibc's operator-delete panic stub would
	# abort at runtime; the stub guard must have taken effect.
	if grep -aq 'operator delete called! delete expressions' "$rust_img/bin/rustc"; then
		die "staged rustc contains mlibc's operator-delete stub — sysroot libc.a is stale (see docs/build-rustc.md pitfalls)"
	fi

	# The Rust sysroot. Copy the whole lib dir: the rlibs carry only metadata
	# *stubs* (bootstrap uses -Zembed-metadata=no) — the .rmeta siblings and
	# self-contained/ must come along or rustc fails with "only metadata stub
	# found for rlib dependency `std`".
	mkdir -p "$rust_img/lib/rustlib/$TARGET/lib"
	cp -r "$RUSTLIB_SRC"/* "$rust_img/lib/rustlib/$TARGET/lib/"
	[ -n "$(ls "$rust_img/lib/rustlib/$TARGET/lib"/*.rmeta 2>/dev/null)" ] || \
		die "no .rmeta files staged — rustc on the image would reject every rlib"

	# (`cc`, the linker driver rustc uses, is a Rush script staged by the
	# LLVM stage — nothing to stage here.)

	# A sample source exercising HashMap, sorting, and thread spawn/join.
	cat > "$RUSTC_IMG/devtools/src/hello.rs" << 'EOF'
use std::collections::HashMap;

fn main() {
    let mut m = HashMap::new();
    for (i, w) in "hello from rustc running natively on motor os".split(' ').enumerate() {
        m.insert(w, i);
    }
    let mut kv: Vec<_> = m.into_iter().collect();
    kv.sort_by_key(|&(_, i)| i);
    let words: Vec<&str> = kv.into_iter().map(|(w, _)| w).collect();
    println!("{}", words.join(" "));
    let t = std::thread::spawn(|| (1..=10u64).product::<u64>());
    println!("10! = {}", t.join().unwrap());
}
EOF

}

# --- build and stage ripgrep -------------------------------------------------
build_ripgrep() {
	log "building ripgrep and staging it as /system/bin/rg"
	( cd "$RIPGREP" && \
		CARGO_TARGET_DIR="$RIPGREP_TARGET_DIR" \
			"$MOTOR_CARGO" build \
				--target "$TARGET" --release --locked )

	local binary="$RIPGREP_TARGET_DIR/$TARGET/release/rg"
	[ -x "$binary" ] || die "ripgrep binary was not produced: $binary"
	[ ! -e "$RG_IMG" ] ||
		die "ripgrep image staging already exists without validated reuse: $RG_IMG"
	mkdir -p "$RG_IMG/system/bin"
	"$B/llvm-strip" -o "$RG_IMG/system/bin/rg" "$binary"
	chmod 755 "$RG_IMG/system/bin/rg"
}

# --- rebuild the OS and all three images -------------------------------------
build_images() {
	log "rebuilding Motor OS and all images (make images BUILD=release)"
	# Keep make's output visible: when a component fails, the compiler diagnostic
	# is the whole diagnosis, and the log alone is easy to overlook.
	( cd "$MOTOR" && \
		make images BUILD=release -j"$(nproc)" ) \
		2>&1 | tee "$MAKE_LOG"
	grep -q 'built the Motor OS base image' "$MAKE_LOG" &&
		grep -q 'built the standard Motor OS image' "$MAKE_LOG" &&
		grep -q 'built the Motor OS dev image' "$MAKE_LOG" ||
		die "make finished without all three imagers running — see $MAKE_LOG"
}

main() {
	local parse_status=0
	parse_options "$@" || parse_status=$?
	[ "$parse_status" -eq 0 ] || {
		[ "$parse_status" -eq 2 ] && return 0
		return "$parse_status"
	}
	log "complete Motor OS build starting"
	log "Motor OS checkout: $MOTOR"
	log "development root:  $MOTORH"

	log "provisioning host packages, rustup, and VM prerequisites"
	local base="$SCRIPT_DIR/build-base.sh"
	[ -x "$base" ] || die "required build stage is not executable: $base"
	MOTOR_BUILD_ORCHESTRATOR=1 "$base"
	[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
	command -v rustup >/dev/null || die "rustup is unavailable after host provisioning"

	log "resolving exact $SOURCE_MODE source tuple"
	prepare_exact_sources "$SOURCE_MODE" "$RUST_SOURCE" "$AUTHORING_BASE"
	log "declared Rust:  $MOTOR_RUST_REV"
	log "effective Rust: $EFFECTIVE_MOTOR_RUST_REV ($MOTOR_RUST_TREE_STATE)"
	log "declared LLVM:  $MOTOR_LLVM_REV"
	log "effective LLVM: $EFFECTIVE_MOTOR_LLVM_REV ($MOTOR_LLVM_TREE_STATE)"
	toolchain_build_selected_host "$RUST" "$AUTHORING_BASE" "$MOTORH/build/toolchain" \
		"$(command -v rustup)" "${CARGO_HOME:-$HOME/.cargo}" \
		"$MOTOR/src/sys/lib/moto-rt"
	log "host toolchain: $MOTOR_RUSTUP_TOOLCHAIN"

	toolchain_derive_assembly_identity "$MOTOR" "$MLIBC" "$TOOLCHAIN_PREFIX/bin/cargo"
	activate_exact_assembly_paths
	toolchain_claim_assembly
	if [ "$TOOLCHAIN_ASSEMBLY_REUSED" = false ]; then
		log "building assembly $MOTOR_ASSEMBLY_KEY"
		toolchain_generate_cross_wrappers "$SYSROOT" "$B"
		configure_exact_cross_driver
		ensure_meson
		build_shim
		build_builtins
		build_mlibc
		build_cxx_runtimes
		build_native_llvm
		build_lua
		llvm_stage_image
		toolchain_build_native_rustc "$RUST" "$AUTHORING_BASE"
		rustc_stage_image
		update_ripgrep_source
		build_ripgrep
		toolchain_complete_assembly
	else
		skip "validated assembly $MOTOR_ASSEMBLY_KEY"
	fi

	# The tracked selector is deliberately added only by the separately gated
	# cutover patch after a clean managed provision and the full core test gate.
	if [ ! -f "$MOTOR/rust-toolchain.toml" ]; then
		log "exact host and native artifacts are ready; root selector cutover remains gated"
		return 0
	fi
	export RUSTUP_TOOLCHAIN="$MOTOR_RUSTUP_TOOLCHAIN"
	export MOTOR_GENERATED_IMAGE_ROOT="$ASSEMBLY_IMAGE_ROOT"
	log "building Motor OS and all images with $MOTOR_RUSTUP_TOOLCHAIN"
	build_images

	local required_outputs=(
		"$LLVM_IMG/devtools/llvm/bin/llvm"
		"$RUSTC_IMG/devtools/rust/bin/rustc"
		"$RG_IMG/system/bin/rg"
		"$MOTOR/vm_images/release/motor-os.qcow2"
		"$MOTOR/vm_images/release/motor-os-dev.qcow2"
	)
	local output
	for output in "${required_outputs[@]}"; do
		[ -f "$output" ] || die "final build output is missing: $output"
	done
	log "base, standard, and dev release images built successfully"
	return 0
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
