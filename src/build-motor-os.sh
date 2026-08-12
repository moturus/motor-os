#!/usr/bin/env bash
#
# build-motor-os.sh — build the complete Motor OS release environment and the
# main VM image.
#
# This is the single entry point for everything past build-base.sh: it runs
# build-base.sh first (host setup + the motor-os-rt-v17 Rust target), then
# builds the Motor LLVM/Clang toolchains and the mlibc/libc++ sysroot, Lua,
# the native Motor rustc, and finally the main image. It absorbs the former
# build-llvm.sh and build-rustc.sh stage scripts; docs/build-llvm.md and
# docs/build-rustc.md remain the prose walkthroughs behind the two stages.
#
# Run it from a Motor OS checkout; sibling Rust, LLVM, mlibc, sysroot, and Lua
# sources/builds live under $MOTORH (the checkout's parent by default).
#
# Generated image inputs are staged under:
#
#   img_files/generated/llvm
#   img_files/generated/rustc
#
# The tracked img_files/motor-os directory remains source-only. The imager
# combines all three roots when it creates the final filesystem.
#
# On-image layout (see docs/porting-libc/dirs.md): C/C++ headers + libraries
# live under /sys/tools/llvm, the clang driver config under /sys/cfg/llvm,
# mlibc's config files under /sys/cfg/libc, and the Rust toolchain at
# /sys/tools/rust — not the classic /usr and /etc.
#
# RE-RUNNING is safe: clones, apt packages, and toolchain setup are detected
# and skipped; the compiles run again (incrementally). A first run is long
# (~2-3 h: three LLVM builds + the compiler crates).

set -euo pipefail

log()  { printf '\033[1;34m[build-motor-os]\033[0m %s\n' "$*"; }
skip() { printf '\033[1;32m[build-motor-os]\033[0m (skip) %s\n' "$*"; }
warn() { printf '\033[1;33m[build-motor-os]\033[0m WARNING: %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[build-motor-os]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO"' ERR

usage() {
	cat << 'EOF'
Usage: src/build-motor-os.sh

Build the complete Motor OS release environment and the main image, including:
  - the moto-rt v17 Motor Rust target toolchain (via build-base.sh);
  - host cross LLVM/Clang and the mlibc/libc++ sysroot;
  - native Motor OS LLVM/Clang, Lua, and rustc;
  - all main-image Motor OS binaries, including /sys/dns-resolver;
  - vm_images/release/motor-os.img and motor-os-base.img.

The dev image (motor-os-dev.img: the main image plus the lorry-built
curl/gears/lorry binaries) is built separately by src/build-dev.sh.

Environment:
  MOTORH  Development root for sibling checkouts and build trees.
          Defaults to the parent of the Motor OS checkout.
  MOTOR_SKIP_HOST_NETWORK_SETUP=1
          Skip build-base.sh's privileged tap/NAT setup after independently
          verifying that host VM networking is already configured.

The build is incremental and safe to rerun. It downloads sources and packages,
uses sudo for missing Ubuntu packages and host VM setup, and does not start the
VM.
EOF
}

if [ "$#" -gt 0 ]; then
	case "$1" in
		-h|--help)
			usage
			exit 0
			;;
		*)
			usage >&2
			die "unknown argument: $1"
			;;
	esac
fi

# --- paths (same scheme as docs/build-llvm.md and docs/build-rustc.md) -------
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
MOTOR="$(cd "$SCRIPT_DIR/.." && pwd)"
[ -e "$MOTOR/.git" ] ||
	die "run this script from its Motor OS checkout; .git is missing at $MOTOR"

MOTORH="$(readlink -f "${MOTORH:-$MOTOR/..}")"
export MOTORH
export MOTOR_OS_DIR="$MOTOR"

LLVM="$MOTORH/llvm-project"
MLIBC="$MOTORH/mlibc"
RUST="$MOTORH/rust"
B="$LLVM/build/bin"                 # the host cross toolchain, built in stage 1
SYSROOT="$MOTORH/motor-sysroot"
CROSS_FILE="$MOTORH/motor.cross-file"
LUA_VER="5.4.8"
CLANG_MAJOR=""                      # detected after the host toolchain is built

HOST=x86_64-unknown-linux-gnu
TARGET=x86_64-unknown-motor
LLVM_IMG="$MOTOR/img_files/generated/llvm"
RUSTC_IMG="$MOTOR/img_files/generated/rustc"
RUSTC_BRANCH=motor-os-rustc

RUSTC_MAIN="$RUST/build/$HOST/stage2-rustc/$TARGET/release/rustc-main"
STAGE2="$RUST/build/$HOST/stage2"
RUSTLIB_SRC="$STAGE2/lib/rustlib/$TARGET/lib"
MAKE_LOG="$MOTORH/build-motor-os-make.log"

# On-image directory prefixes (mirrored inside the cross sysroot). Keep these in
# sync with clang/lib/Driver/ToolChains/Motor.cpp and mlibc's MLIBC_SYSCONFDIR.
TOOLS="sys/tools/llvm"              # headers + libraries
CFG_LLVM="sys/cfg/llvm"            # clang <triple>.cfg
CFG_LIBC="sys/cfg/libc"           # mlibc config files (resolv.conf, ...)

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

# --- clone mlibc + llvm-project, both @ motor-os-rustc ----------------------
clone_repo() {  # url dir branch
	local url="$1" dir="$2" branch="$3"
	if [ -d "$dir/.git" ]; then
		skip "$(basename "$dir") already cloned"
	else
		log "cloning $(basename "$dir") ($branch)"
		git clone "$url" "$dir"
		git -C "$dir" checkout "$branch"
	fi
}
clone_sources() {
	# Everything on one branch, motor-os-rustc, so the rustc stage reuses these
	# same checkouts without switching branches. mlibc motor-os-rustc is a
	# superset of the old `motor` branch (extra lazy-TCB + operator-delete
	# guard, harmless for C/C++). llvm-project motor-os-rustc is the LLVM 23
	# line with the Clang Motor ToolChain; rustc builds its *own* copy of this
	# same LLVM from its submodule (see build-rustc.md), so there is one LLVM
	# repo and version across both builds.
	clone_repo https://github.com/moturus/mlibc.git        "$MLIBC" "$RUSTC_BRANCH"
	clone_repo https://github.com/moturus/llvm-project.git "$LLVM"  "$RUSTC_BRANCH"
}

# --- stage 1: the cross toolchain (host clang/lld/llvm-*) -------------------
build_cross_toolchain() {
	log "stage 1: building the host cross toolchain (clang/lld/llvm-*)"
	cmake -S "$LLVM/llvm" -B "$LLVM/build" -G Ninja \
		-DCMAKE_BUILD_TYPE=Release \
		-DLLVM_ENABLE_ASSERTIONS=ON \
		-DLLVM_ENABLE_PROJECTS="clang;lld" \
		-DLLVM_TARGETS_TO_BUILD=X86 \
		-DLLVM_INCLUDE_TESTS=OFF \
		-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
	ninja -C "$LLVM/build" \
		clang lld llvm-ar llvm-ranlib llvm-nm llvm-readelf llvm-strip llvm-objcopy

	# Host-side auto-loaded config: makes every cross link a raw -static-pie
	# -nostdlib link, so meson's compiler probes and the explicit recipes below
	# succeed. (Distinct from the image cfg written in stage 8.)
	cat > "$B/x86_64-unknown-motor.cfg" << 'EOF'
-fuse-ld=lld
-static-pie
-nostdlib
-Wl,-e,motor_start
-Wl,--pack-dyn-relocs=none
-Wl,-z,noexecstack
EOF

	CLANG_MAJOR="$("$B/clang" --version | sed -n 's/.*clang version \([0-9]\{1,\}\).*/\1/p' | head -1)"
	[ -n "$CLANG_MAJOR" ] || die "could not determine clang major version"
	log "clang major version: $CLANG_MAJOR"
}

# --- stage 2: the C-ABI shim (libmoto_rt_cabi.a) ----------------------------
build_shim() {
	log "stage 2: building the moto-rt-cabi shim"
	mkdir -p "$SYSROOT/$TOOLS/lib" "$SYSROOT/$TOOLS/include"
	( cd "$MOTOR/src/sys/lib/moto-rt-cabi" \
		&& cargo +dev-x86_64-unknown-motor build --target x86_64-unknown-motor --release )
	cp "$MOTOR/src/sys/target/x86_64-unknown-motor/release/libmoto_rt_cabi.a" \
		"$SYSROOT/$TOOLS/lib/"
	cp "$MOTOR/src/sys/lib/moto-rt-cabi/moto_rt.h" "$SYSROOT/$TOOLS/include/"
}

# --- stage 3: compiler-rt builtins (emutls excluded) ------------------------
build_builtins() {
	log "stage 3: building compiler-rt builtins"
	# -ffreestanding: the builtins are freestanding, and it keeps clang's
	# resource limits.h/stdint.h from #include_next-ing into the host's glibc
	# headers. The Motor ToolChain adds <sysroot>/sys/tools/llvm/include, which
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
	cmake -S "$LLVM/compiler-rt/lib/builtins" -B "$LLVM/build-builtins" -G Ninja \
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
	ninja -C "$LLVM/build-builtins"

	local builtins
	builtins="$(find "$LLVM/build-builtins" -name 'libclang_rt.builtins*.a' | head -1)"
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
	local rd="$LLVM/build/lib/clang/$CLANG_MAJOR/lib/x86_64-unknown-motor"
	mkdir -p "$rd"
	cp "$builtins" "$rd/libclang_rt.builtins.a"
}

# --- stage 4: mlibc ---------------------------------------------------------
build_mlibc() {
	log "stage 4: building mlibc"
	# Meson cross file with this machine's absolute paths (kept out of the repos).
	# MLIBC_SYSCONFDIR repoints mlibc's runtime config lookups (resolv.conf,
	# hosts, passwd, ...) from /etc to /sys/cfg/libc.
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

	( cd "$MLIBC"
		# Headers first (validates ABI/meson wiring quickly).
		[ -f build-headers/build.ninja ] || \
			meson setup --cross-file "$CROSS_FILE" --prefix="/$TOOLS" \
				-Dheaders_only=true build-headers
		DESTDIR="$SYSROOT" ninja -C build-headers install

		# The real static build: libc.a, crt1.o, headers, companion stubs.
		# -Ddebug=false: mlibc's meson.build pins buildtype=debugoptimized
		# (-O2 -g); the flag keeps -O2 and drops only -g. Without it libc.a is
		# 18 MB (59% DWARF) and every mlibc-linked binary carries ~6.6 MB of
		# debug info (see docs/libc_start_redesign.md). .text is byte-identical.
		[ -f build/build.ninja ] || \
			meson setup --cross-file "$CROSS_FILE" --prefix="/$TOOLS" \
				-Ddefault_library=static -Dbuild_tests=false -Ddebug=false build
		ninja -C build
		DESTDIR="$SYSROOT" ninja -C build install )

	ls "$SYSROOT/$TOOLS/lib/libc.a" "$SYSROOT/$TOOLS/lib/crt1.o" >/dev/null
}

# --- stage 5: the C++ runtime stack (with exceptions) -----------------------
build_cxx_runtimes() {
	log "stage 5: building libunwind + libc++abi + libc++ (exceptions on)"
	rm -rf "$LLVM/build-motor-cxx"   # stale try_compile results are poison
	cmake -G Ninja -S "$LLVM/runtimes" -B "$LLVM/build-motor-cxx" \
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
	ninja -C "$LLVM/build-motor-cxx" unwind cxxabi cxx
	DESTDIR="$SYSROOT" ninja -C "$LLVM/build-motor-cxx" \
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
	# ToolChain's ConstructJob, which adds -lc++abi unconditionally). Note: if the
	# sysroot's *set* of archives ever changes, `rm -rf build-motor-native` first
	# (the try-compile probe results are cached).
	cmake -S "$LLVM/llvm" -B "$LLVM/build-motor-native" -G Ninja \
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

	# Force the final link so the staged binary reflects the freshly built
	# sysroot archives (CMAKE_*_STANDARD_LIBRARIES are flags, not tracked deps).
	rm -f "$LLVM/build-motor-native/bin/llvm"
	ninja -C "$LLVM/build-motor-native" llvm-driver
}

# --- stage 7: Lua -----------------------------------------------------------
build_lua() {
	log "stage 7: building Lua $LUA_VER"
	( cd "$MOTORH"
		[ -f "lua-$LUA_VER.tar.gz" ] || curl -LO "https://www.lua.org/ftp/lua-$LUA_VER.tar.gz"
		[ -d "lua-$LUA_VER" ] || tar xf "lua-$LUA_VER.tar.gz" )

	( cd "$MOTORH/lua-$LUA_VER/src"
		local cflags="--target=x86_64-unknown-motor -O2 -isystem $SYSROOT/$TOOLS/include -DLUA_USE_POSIX"
		local f
		for f in $(ls ./*.c | grep -v -e 'lua\.c$' -e 'luac\.c$'); do
			# shellcheck disable=SC2086
			"$B/clang" $cflags -c "$f"
		done
		"$B/llvm-ar" rcs liblua.a ./*.o
		# mlibc is C++ internally (its stdio FILE machinery — cookie_file,
		# memstream, fmemopen — has C++ destructors that call `operator delete`),
		# so even this pure-C program pulls libc++abi/libunwind out of libc.a and
		# must link them. Mirror the C link group the Motor ToolChain emits: the
		# host cfg forces -nostdlib, suppressing that default group, so it is listed
		# explicitly. --start-group resolves the libc <-> libc++abi <-> shim
		# back-references regardless of order.
		# shellcheck disable=SC2086
		"$B/clang" $cflags lua.c liblua.a \
			"$SYSROOT/$TOOLS/lib/crt1.o" \
			-Wl,--start-group \
			"$SYSROOT/$TOOLS/lib/libmoto_rt_cabi.a" \
			"$SYSROOT/$TOOLS/lib/libc++abi.a" \
			"$SYSROOT/$TOOLS/lib/libunwind.a" \
			"$SYSROOT/$TOOLS/lib/libc.a" \
			"$SYSROOT/$TOOLS/lib/libclang_rt.builtins-x86_64.a" \
			-Wl,--end-group -o lua )
}

# --- stage 8: stage the C/C++ toolchain into the image ----------------------
llvm_stage_image() {
	log "stage 8: staging the toolchain, sysroot, and Lua into img_files/generated/llvm"
	local img="$LLVM_IMG"
	local legacy="$MOTOR/img_files/motor-os"

	# Migrate worktrees that ran an older version of this script. These paths
	# were generated and untracked; leaving them in the source tree would make
	# the imager see the same destination from two static roots.
	rm -rf "$legacy/sys/tools/llvm" "$legacy/sys/cfg/llvm" \
		"$legacy/sys/cfg/libc"
	rm -f "$legacy/bin/cc" "$legacy/bin/c++" "$legacy/bin/lua"
	rm -rf "$img"
	mkdir -p "$img/bin" "$img/$TOOLS/bin" "$img/$TOOLS/lib" "$img/$TOOLS/src" \
		"$img/$CFG_LLVM" "$img/$CFG_LIBC"

	# Headers: mlibc + libc++'s c++/v1 (rm+copy for a clean, stale-free tree).
	rm -rf "$img/$TOOLS/include"
	cp -a "$SYSROOT/$TOOLS/include" "$img/$TOOLS/include"

	# Clang's own resource headers (intrinsics, stdarg.h, ...).
	rm -rf "$img/$TOOLS/lib/clang/$CLANG_MAJOR/include"
	mkdir -p "$img/$TOOLS/lib/clang/$CLANG_MAJOR"
	cp -a "$LLVM/build/lib/clang/$CLANG_MAJOR/include" \
		"$img/$TOOLS/lib/clang/$CLANG_MAJOR/include"

	# Libraries — strip debug info on the way in.
	local a
	for a in libc libc++ libc++abi libunwind libmoto_rt_cabi \
	         libclang_rt.builtins-x86_64 \
	         libdl libm libpthread librt libresolv libutil libssp libssp_nonshared; do
		"$B/llvm-objcopy" --strip-debug "$SYSROOT/$TOOLS/lib/$a.a" "$img/$TOOLS/lib/$a.a"
	done
	cp "$SYSROOT/$TOOLS/lib/crt1.o" "$img/$TOOLS/lib/"

	# The on-image LLVM multicall lives under /sys/tools/llvm/bin, mirroring the
	# Rust toolchain at /sys/tools/rust/bin (build-rustc.md). Its clang config and
	# resource dir are pinned by absolute path (the /sys/cfg/llvm .cfg + the baked
	# CLANG_CONFIG_FILE_SYSTEM_DIR), and its ld.lld self-dispatch uses the running
	# exe's own path, so the binary works wherever it is placed. Drop any /bin/llvm
	# from earlier layouts. Lua stays in /bin.
	rm -f "$img/bin/llvm"
	"$B/llvm-strip" -o "$img/$TOOLS/bin/llvm" "$LLVM/build-motor-native/bin/llvm"
	"$B/llvm-strip" -o "$img/bin/lua"  "$MOTORH/lua-$LUA_VER/src/lua"

	# /bin/cc — the system C compiler / linker driver: a `#!/bin/rush` script (not
	# a compiled binary) over the llvm multicall's clang. rustc's default linker
	# is the bare name `cc`, resolved on PATH (=/bin on the image), so a native
	# `rustc hello.rs -o hello` links with no `-C linker=` flag — exactly as rustc
	# uses /usr/bin/cc on Linux. A pure pass-through: the Motor clang ToolChain
	# owns the whole link recipe (crt1.o + the mlibc/libc++ group, incl. libc++abi
	# for C links) and gates it on -nostdlib/-nostartfiles/-nodefaultlibs, so a
	# plain `cc hello.c` gets the full C runtime while rustc's pure-Rust links
	# (which pass -nostartfiles -nodefaultlibs) get nothing forced on them — a
	# pure-Rust hello is ~113 KB, not 8 MB (docs/libc_start_redesign.md). Rust
	# programs that *want* mlibc opt back into the ToolChain recipe with
	# `-C link-self-contained=no -C default-linker-libraries=yes` (build-rustc.md).
	cat > "$img/bin/cc" << 'EOF'
#!/bin/rush
# cc — Motor OS's system C compiler / linker driver. See docs/build-llvm.md.
# A pass-through: clang's Motor ToolChain owns the link recipe and honors
# -nostartfiles/-nodefaultlibs (rustc's pure-Rust links stay mlibc-free).
/sys/tools/llvm/bin/llvm clang "$@"
EOF

	# /bin/c++ — same, in C++ driver mode (adds -lc++ at link). --driver-mode
	# rather than a `clang++` subcommand: the multicall dispatches on the first
	# argument, and `clang++` is not a registered subcommand name.
	cat > "$img/bin/c++" << 'EOF'
#!/bin/rush
# c++ — Motor OS's system C++ compiler / linker driver. See docs/build-llvm.md.
/sys/tools/llvm/bin/llvm clang --driver-mode=g++ "$@"
EOF

	# The image driver config: only the resource dir needs pinning (the full
	# link/include recipe lives in the Motor ToolChain now). Clang auto-loads it
	# from /sys/cfg/llvm (CLANG_CONFIG_FILE_SYSTEM_DIR, stage 6).
	cat > "$img/$CFG_LLVM/x86_64-unknown-motor.cfg" << EOF
-resource-dir /$TOOLS/lib/clang/$CLANG_MAJOR
EOF

	# mlibc reads its config from /sys/cfg/libc (MLIBC_SYSCONFDIR). Ship the
	# resolver, hosts, and services databases needed by its generic DNS client.
	cat > "$img/$CFG_LIBC/resolv.conf" << 'EOF'
nameserver 8.8.8.8
EOF
	cat > "$img/$CFG_LIBC/services" << 'EOF'
domain 53/tcp
domain 53/udp
EOF
	cat > "$img/$CFG_LIBC/hosts" << 'EOF'
127.0.0.1 localhost
::1 localhost
127.0.0.53 motor-dns-test
::1 motor-dns-test
EOF

	# Sample sources to compile natively in the VM.
	cat > "$img/$TOOLS/src/hello.c" << 'EOF'
#include <stdio.h>

int main(void) {
	printf("Hello from Motor-native clang!\n");
	return 0;
}
EOF
	cat > "$img/$TOOLS/src/hello.cpp" << 'EOF'
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
	cp "$MOTOR/src/sys/tests/native-fstat.c" "$img/$TOOLS/src/native-fstat.c"
}

# ============================================================================
# rustc stage: a native rustc for Motor OS (rustc + Rust sysroot), staged into
# img_files/generated/rustc. The linker driver rustc uses (/bin/cc) and the
# LLVM multicall it fronts are produced by the LLVM stage above.
#
# The base build leaves the Rust fork on `motor-os-rt-v17`. This stage switches
# it to `motor-os-rustc`, the short compiler-only series based on that branch.
# The LLVM stage already checked out mlibc and llvm-project (LLVM 23) on their
# `motor-os-rustc` branches, so Rust's src/llvm-project submodule is seeded from
# that same llvm-project (same LLVM 23 commit, objects shared). The four
# dependency forks are [patch.crates-io] git URLs cargo fetches — not cloned —
# and moto-rt comes from crates.io. No patches of its own.
#
# NOTE: $MOTORH/rust is also what build-base.sh registered the
# dev-x86_64-unknown-motor toolchain against, and the final make builds every
# Motor OS component with that toolchain. So switching to the compiler branch
# hands the whole Motor OS build over to the fork's compiler and std, and
# everything built with the toolchain beforehand — cargo caches, the clippy
# binaries in stage2 — goes stale. See "This build repurposes the dev
# toolchain" in docs/build-rustc.md, which also holds the pitfall list this
# stage encodes.
# ============================================================================

# --- prerequisites ------------------------------------------------------------
rustc_verify_prereqs() {
	log "verifying the base/LLVM stage outputs the rustc stage needs"
	[ -x "$B/clang" ] || die "host cross clang not found at $B/clang — the LLVM stage did not complete"
	[ -d "$RUST/.git" ] || die "rust checkout not found at $RUST — the base stage did not complete"
	local f
	for f in libc.a crt1.o libc++.a libc++abi.a libunwind.a libmoto_rt_cabi.a; do
		[ -f "$SYSROOT/sys/tools/llvm/lib/$f" ] || \
			die "sysroot incomplete ($f missing) — the LLVM stage did not complete"
	done
	[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
	rustup toolchain list | grep -q '^dev-x86_64-unknown-motor' || \
		die "dev-x86_64-unknown-motor toolchain not registered — the base stage did not complete"
	python3 -c 'import sys, tomllib; assert sys.version_info >= (3, 11)' ||
		die "Stage-2 Lorry seeding requires Python 3.11 or newer"
	[ -x "$MOTOR/src/bin/lorry/bootstrap/install_stage2_seed.py" ] ||
		die "Stage-2 Lorry seed installer is missing or not executable"

	# rustc's default linker is the bare name `cc`, resolved on the image's PATH
	# (=/bin), and that script fronts the llvm multicall. Both are the LLVM
	# stage's staging, and this stage only adds the Rust half on top. Without
	# them the image ships a rustc that cannot link anything, and nothing here
	# would notice — the failure would surface only in the VM, at the end of a
	# 2 h build.
	[ -f "$LLVM_IMG/bin/cc" ] || \
		die "$LLVM_IMG/bin/cc is missing — the LLVM stage stages the linker driver rustc needs"
	[ -f "$LLVM_IMG/sys/tools/llvm/bin/llvm" ] || \
		die "$LLVM_IMG/sys/tools/llvm/bin/llvm is missing — the LLVM stage stages the multicall /bin/cc fronts"

	# The Motor OS checkout must carry the rustc-era runtime fixes (RT.VDSO
	# ChildStdio EOF mapping + O_APPEND, and a 2 GiB data partition).
	grep -q 'E_BAD_HANDLE) => Ok(0)' "$MOTOR/src/sys/lib/rt.vdso/src/stdio.rs" || \
		die "motor-os checkout lacks the ChildStdio EOF fix (rt.vdso/src/stdio.rs) — update the checkout"
	grep -q 'self.metadata(entry_id)?.size' "$MOTOR/src/sys/lib/rt.vdso/src/rt_fs.rs" || \
		die "motor-os checkout lacks the O_APPEND fix (rt.vdso/src/rt_fs.rs) — update the checkout"
	local yaml="$MOTOR/src/imager/motor-os.yaml" size
	size="$(sed -n 's/^data_partition_size_mb: *\([0-9]\{1,\}\).*/\1/p' "$yaml")"
	if [ -z "$size" ] || [ "$size" -lt 2048 ]; then
		die "data_partition_size_mb in $yaml must be >= 2048 — update the checkout"
	fi
}

# The four dependency forks (libc, rust_libloading, stacker, rust-ctrlc) are NOT
# cloned: the rust fork's [patch.crates-io] references them as moturus git URLs,
# so cargo fetches them. moto-rt comes from crates.io. Nothing to do here.

# --- mlibc: only the sysroot's libc.a matters here ----------------------------
check_mlibc() {
	# rustc links against the *sysroot* libc.a / crt1.o that the LLVM stage
	# built from mlibc @ motor-os-rustc — the mlibc source tree itself is not
	# needed by this stage (it can even be deleted after the LLVM stage). The
	# one property that matters is that the installed libc.a carries the
	# operator-delete stub guard, i.e. has NO strong _ZdlPvm (the
	# motor-os-rustc branch guarantees this; the older `motor` branch did not).
	if ! "$B/llvm-nm" "$SYSROOT/sys/tools/llvm/lib/libc.a" 2>/dev/null | grep -q 'T _ZdlPvm'; then
		skip "sysroot libc.a already clean of the delete stubs (mlibc source not needed)"
	elif [ -d "$MLIBC/.git" ]; then
		# Stale libc.a (built from the old `motor` branch) but mlibc is present:
		# switch it to motor-os-rustc if needed and rebuild into the sysroot.
		grep -q '__motor__' "$MLIBC/options/internal/gcc-extra/cxxabi.cpp" || \
			die "mlibc lacks the operator-delete stub guard — put it on branch $RUSTC_BRANCH (see the LLVM stage)"
		log "rebuilding mlibc (sysroot libc.a predates the stub guard)"
		ninja -C "$MLIBC/build"
		( cd "$MLIBC/build" && DESTDIR="$SYSROOT" meson install --no-rebuild >/dev/null )
		"$B/llvm-nm" "$SYSROOT/sys/tools/llvm/lib/libc.a" 2>/dev/null | grep -q 'T _ZdlPvm' && \
			die "strong _ZdlPvm still present in libc.a after rebuild"
	else
		die "sysroot libc.a predates the operator-delete guard and mlibc is not cloned at $MLIBC — re-run the LLVM stage (or clone moturus/mlibc @ $RUSTC_BRANCH and rebuild)"
	fi
	# Keep the on-image copy in sync (LLVM stage 8 staged it).
	if [ -f "$LLVM_IMG/sys/tools/llvm/lib/libc.a" ]; then
		"$B/llvm-objcopy" --strip-debug \
			"$SYSROOT/sys/tools/llvm/lib/libc.a" \
			"$LLVM_IMG/sys/tools/llvm/lib/libc.a"
	fi
}

# --- the rust tree: switch from motor-os-rt-v17 to motor-os-rustc -------------
update_rust() {
	# build-base.sh cloned the Moturus fork and built the target libraries from
	# motor-os-rt-v17. Switch the same checkout to the compiler-only branch.
	if [ "$(git -C "$RUST" branch --show-current)" = "$RUSTC_BRANCH" ]; then
		skip "rust tree already on $RUSTC_BRANCH"
	else
		if [ -n "$(git -C "$RUST" status --porcelain --untracked-files=no)" ]; then
			die "rust tree is dirty — clean it (git stash) and re-run"
		fi
		if git -C "$RUST" show-ref --verify --quiet \
				"refs/heads/$RUSTC_BRANCH"; then
			log "switching rust to local $RUSTC_BRANCH"
			git -C "$RUST" switch -q "$RUSTC_BRANCH"
		else
			log "fetching moturus/rust @ $RUSTC_BRANCH"
			git -C "$RUST" remote add moturus https://github.com/moturus/rust.git \
				2>/dev/null || true
			git -C "$RUST" fetch -q moturus "$RUSTC_BRANCH"
			git -C "$RUST" switch -q -c "$RUSTC_BRANCH" "moturus/$RUSTC_BRANCH"
		fi
	fi

	# Seed rustc's LLVM tree from the checkout the LLVM stage just compiled, and
	# put it on that checkout's exact commit. Do not use `git submodule update`
	# here: the rust fork currently pins an orphaned pre-amend commit. Besides
	# relying on GitHub to retain that unreachable object, submodule's
	# direct-fetch fallback can reject the local reference with "transport
	# 'file' not allowed" on Ubuntu's Git.
	#
	# A direct local clone is safe here because both paths are controlled build
	# inputs under MOTORH. Keep protocol.file.allow scoped to those commands;
	# never weaken the user's global Git policy. --shared preserves the original
	# --reference optimization, and absorbgitdirs restores the normal submodule
	# gitdir layout.
	local rust_llvm="$RUST/src/llvm-project"
	local llvm_commit llvm_url
	llvm_commit="$(git -C "$LLVM" rev-parse HEAD)"
	llvm_url="$(git -C "$RUST" config -f .gitmodules \
		--get submodule.src/llvm-project.url)"
	[ -n "$llvm_url" ] || die "rust fork has no src/llvm-project URL in .gitmodules"

	git -C "$RUST" submodule init src/llvm-project >/dev/null

	# An uninitialized Rust LLVM submodule can still leave an empty directory
	# here. `git -C "$rust_llvm" rev-parse --git-dir` is not a valid
	# initialization test: Git walks up from that directory, finds $RUST/.git,
	# and reports the *superproject* as though it were the submodule. Require a
	# .git entry of its own and verify that Git considers rust_llvm—not RUST—the
	# worktree root.
	local rust_llvm_top=
	if [ -e "$rust_llvm/.git" ]; then
		rust_llvm_top="$(git -C "$rust_llvm" rev-parse --show-toplevel \
			2>/dev/null || true)"
	fi
	if [ "$(readlink -f "$rust_llvm_top" 2>/dev/null || true)" = "$rust_llvm" ]; then
		skip "rust LLVM submodule already initialized"
	else
		if [ -e "$rust_llvm" ] && [ -n "$(ls -A "$rust_llvm" 2>/dev/null)" ]; then
			die "$rust_llvm exists but is not a Git checkout — move it aside and re-run"
		fi
		log "seeding rust LLVM submodule from $LLVM"
		git -c protocol.file.allow=always clone --no-checkout --shared \
			"$LLVM" "$rust_llvm"
		git -C "$RUST" submodule absorbgitdirs src/llvm-project
	fi

	if ! git -C "$rust_llvm" cat-file -e "$llvm_commit^{commit}" 2>/dev/null; then
		log "importing the LLVM stage's commit into the existing rust LLVM submodule"
		git -c protocol.file.allow=always -C "$rust_llvm" \
			fetch -q "$LLVM" "$llvm_commit"
	fi
	git -C "$rust_llvm" checkout -q --detach "$llvm_commit"
	git -C "$rust_llvm" remote set-url origin "$llvm_url" 2>/dev/null || \
		git -C "$rust_llvm" remote add origin "$llvm_url"
	git -C "$RUST" config submodule.src/llvm-project.url "$llvm_url"

	[ "$(git -C "$rust_llvm" rev-parse HEAD)" = "$llvm_commit" ] || \
		die "rust LLVM submodule did not reach the LLVM stage's commit $llvm_commit"
	grep -q 'Motor, // Motor OS' "$RUST/src/llvm-project/llvm/include/llvm/TargetParser/Triple.h" || \
		die "src/llvm-project is not on the Motor triple — is $LLVM on moturus/llvm-project @ $RUSTC_BRANCH?"
	grep -q 'set(LLVM_VERSION_MAJOR 23)' "$RUST/src/llvm-project/cmake/Modules/LLVMVersion.cmake" || \
		die "src/llvm-project is not LLVM 23 — check $LLVM"

	# The [patch.crates-io] deps are moturus git URLs and moto-rt is on
	# crates.io, so there are no local paths to rewrite. Refresh the lock so the
	# git patches + moto-rt >= 0.17.0 resolve (no-op if the fork's lock is
	# already current).
	( cd "$RUST" && cargo update -p libloading -p stacker -p libc -p ctrlc >/dev/null 2>&1 || true )
	( cd "$RUST/library" && cargo update -p moto-rt >/dev/null 2>&1 || true )
}

# --- compiler wrappers + bootstrap.toml ---------------------------------------
write_wrappers() {
	log "writing motor-clang / motor-clang++ / motor-rust-cc wrappers"
	mkdir -p "$SYSROOT/bin"
	local cc
	for cc in clang clang++; do
		cat > "$SYSROOT/bin/motor-$cc" << EOF
#!/bin/sh
# Compiler driver for x86_64-unknown-motor cross builds (cmake/cc-rs use this
# for both compiling and linking). --no-default-config bypasses
# build/bin/x86_64-unknown-motor.cfg (its -nostdlib is for the explicit-link
# recipes in the LLVM stage). The Motor clang driver resolves headers, crt1.o
# and the runtime link group from the sysroot. Rust bootstrap derives an
# x86_64-unknown-none-elf flag from the target's LLVM triple; put Motor's target
# last so clang uses the OS toolchain. _GNU_SOURCE/_DEFAULT_SOURCE: mlibc hides
# realpath & friends under strict-ANSI C++ dialects otherwise.
exec $B/$cc --no-default-config \\
  --sysroot=$SYSROOT -D_GNU_SOURCE -D_DEFAULT_SOURCE \\
  "\$@" --target=x86_64-unknown-motor
EOF
		chmod +x "$SYSROOT/bin/motor-$cc"
	done

	cat > "$SYSROOT/bin/motor-rust-cc" << EOF
#!/bin/sh
# Linker driver for Rust binaries targeting x86_64-unknown-motor that link
# mlibc (the libc crate, or rustc itself with its C++ LLVM). rustc passes
# -nostartfiles/-nodefaultlibs, so the Motor clang driver's automatic
# crt1.o + lib group is suppressed; re-add it after rustc's own inputs.
# crt1.o's strong motor_start overrides std's weak one: mlibc initializes
# the C runtime (TCB, stdio, .init_array) and calls the Rust C main.
SR=$SYSROOT
exec $B/clang --no-default-config \\
  --target=x86_64-unknown-motor --sysroot=\$SR "\$@" \\
  -Wl,--start-group \\
  \$SR/sys/tools/llvm/lib/crt1.o \\
  -lmoto_rt_cabi -lc++ -lc++abi -lunwind -lc -lclang_rt.builtins-x86_64 \\
  -Wl,--end-group
EOF
	chmod +x "$SYSROOT/bin/motor-rust-cc"
}

write_bootstrap_toml() {
	if grep -q 'download-ci-llvm' "$RUST/bootstrap.toml" 2>/dev/null; then
		skip "bootstrap.toml already configured for the rustc port"
		return
	fi
	log "writing rust/bootstrap.toml (backing up the build-base one)"
	[ -f "$RUST/bootstrap.toml" ] && cp "$RUST/bootstrap.toml" "$RUST/bootstrap.toml.pre-rustc"
	cat > "$RUST/bootstrap.toml" << EOF
change-id = "ignore"

profile = "library"

[build]
host = ["$HOST"]
target = ["$HOST", "$TARGET"]
# src/llvm-project is moturus/llvm-project @ motor-os-rustc (LLVM 23), the same
# checkout the LLVM stage builds from; keep bootstrap from resetting it.
submodules = false

[rust]
deny-warnings = false
incremental = true

# --- rustc-on-motor port (see docs/build-rustc.md) ---
# LLVM 23 is built from src/llvm-project for both the build triple and
# x86_64-unknown-motor. X86-only keeps the component lists of the two builds
# identical — rustc_llvm's build.rs queries the *host* llvm-config and rewrites
# host->target paths.
[llvm]
download-ci-llvm = false
targets = "X86"
experimental-targets = ""
static-libstdcpp = false

[target.$TARGET]
cc = "$SYSROOT/bin/motor-clang"
cxx = "$SYSROOT/bin/motor-clang++"
ar = "$B/llvm-ar"
ranlib = "$B/llvm-ranlib"
linker = "$SYSROOT/bin/motor-rust-cc"
EOF
}

# --- build rustc + std --------------------------------------------------------
build_rustc() {
	log "building rustc for $TARGET (first run: ~1.5-2.5 h — two LLVMs + the compiler)"
	# --host is what requests a compiler that *runs on* Motor; --target alone
	# builds nothing new. To force a relink later, delete rustc-main AND the
	# .rustc-stamp next to it (bootstrap trusts the stamp).
	( cd "$RUST" && ./x.py build --stage 2 compiler --host "$TARGET" --target "$TARGET" )
	[ -f "$RUSTC_MAIN" ] || die "rustc-main not produced at $RUSTC_MAIN"
}

build_stds() {
	# ONE x.py INVOCATION, BOTH TARGETS, CLIPPY INCLUDED. This single line is
	# load-bearing in a way that is easy to "tidy" into a broken build, so:
	#
	# Bootstrap's Sysroot step opens with an unconditional
	# `remove_dir_all(build/$HOST/stage2)` ("Removing sysroot ... to avoid
	# caching bugs", src/bootstrap/src/core/build_steps/compile.rs). That is the
	# *dev-x86_64-unknown-motor toolchain directory* — the one the Motor OS
	# make runs on. So every x.py invocation empties the whole stage2 sysroot,
	# bin/ and lib/rustlib/ alike, and re-links only what that invocation
	# builds. The wipe happens once per invocation, so everything named in a
	# single command survives together, while a *later* invocation silently
	# throws away what an earlier one produced:
	#
	#   x.py build library --target A,B   then   x.py build clippy
	#       -> the clippy run wipes the sysroot and puts NO std back. Both
	#          targets lose core+std, and the next `cargo
	#          +dev-x86_64-unknown-motor` — i.e. the whole Motor OS make — dies
	#          with `error[E0463]: can't find crate for core`/`std` ... "target
	#          may not be installed", on whatever dependency it compiles first
	#          (futures-io, futures-sink, ...). It reads as a Motor OS or a
	#          toolchain-registration failure; it is neither, and re-registering
	#          the toolchain cannot help.
	#   x.py build library --target A     then   x.py build library --target B
	#       -> B evicts A's std, same E0463 for A.
	#
	# Naming clippy and library together (exactly what build-base.sh does) makes
	# the whole set survive one wipe, so no ordering can be wrong and nothing has
	# to be copied back afterwards. Do not split this into two commands.
	#
	# clippy must be *rebuilt* here rather than reused: build-base.sh already
	# built it from motor-os-rt-v17, so
	# stage2-tools-bin holds binaries from a *different source tree* by the time
	# update_rust switches to the compiler branch. clippy-driver dynamically
	# loads the hash-suffixed librustc_driver-*.so out of stage2/lib, so a stale
	# pair cannot load (or resolve against) this compiler and the Motor OS build
	# dies in its vdso step (rt.vdso/build.sh runs clippy). Naming clippy here
	# rebuilds it from the compiler branch; it is incremental, and a no-op when current.
	log "building std for both targets + clippy (ONE x.py — each invocation wipes the stage2 sysroot)"
	( cd "$RUST" && ./x.py build --stage 2 clippy library --target "$TARGET,$HOST" )

	# Belt and braces: bootstrap installs the clippy pair into stage2/bin itself,
	# but stage2-tools-bin is the copy that survives a sysroot wipe, so top up
	# from it if a future bootstrap ever stops populating bin/.
	local tb="$RUST/build/$HOST/stage2-tools-bin"
	local b
	for b in cargo-clippy clippy-driver; do
		[ -f "$STAGE2/bin/$b" ] || cp "$tb/$b" "$STAGE2/bin/$b"
	done

	verify_stage2_sysroot
}

# The dev-x86_64-unknown-motor toolchain is exactly build/$HOST/stage2, and the
# Motor OS make compiles every component with it. Check here — while the rust
# tree that produced it is still in hand — that it carries everything that
# build needs, rather than letting a gap surface an hour later as an E0463 deep
# inside a dependency crate.
verify_stage2_sysroot() {
	log "verifying the stage2 sysroot the dev toolchain points at"
	local t
	for t in "$TARGET" "$HOST"; do
		[ -n "$(ls "$STAGE2/lib/rustlib/$t/lib"/libcore-*.rlib 2>/dev/null)" ] || \
			die "no core rlib for $t in $STAGE2 — an x.py build ran after the library build and wiped the sysroot (see the ordering note in build_stds)"
		[ -n "$(ls "$STAGE2/lib/rustlib/$t/lib"/libstd-*.rlib 2>/dev/null)" ] || \
			die "no std rlib for $t in $STAGE2 — an x.py build ran after the library build and wiped the sysroot (see the ordering note in build_stds)"
	done

	# clippy-driver links librustc_driver-<hash>.so out of stage2/lib, so this
	# also proves the pair matches the rustc the Motor OS make is about to use.
	"$STAGE2/bin/clippy-driver" --version >/dev/null || \
		die "clippy-driver does not run against the freshly built rustc — Motor OS's vdso step would fail; see the clippy pitfall in docs/build-rustc.md"

	# The end-to-end check: actually compile something for each target with the
	# very toolchain make will use. This is what catches an E0463 here, in one
	# second, instead of an hour into the make inside some dependency crate.
	local probe
	probe="$(mktemp -d)"
	printf 'pub fn f() -> u32 { 1 }\n' > "$probe/probe.rs"
	for t in "$TARGET" "$HOST"; do
		"$STAGE2/bin/rustc" --edition 2021 --crate-type rlib --target "$t" \
			-o "$probe/probe-$t.rlib" "$probe/probe.rs" || {
				rm -rf "$probe"
				die "the dev toolchain's rustc cannot compile for $t — the stage2 sysroot is incomplete; the make would fail with E0463 (see the ordering note in build_stds)"
			}
	done
	rm -rf "$probe"
	log "stage2 sysroot OK: std for $TARGET and $HOST, clippy matches rustc"
}

# The LLVM stage initially creates the C ABI shim with the bootstrap Motor
# toolchain. Rebuild it after the forked stage2 toolchain is complete so the
# DNS resolver and every later mixed Rust+C link use the final std/moto-rt
# implementation. A fresh target directory avoids cargo accepting artifacts
# fingerprinted by the compiler that the rustc stage just replaced.
rebuild_shim() {
	log "rebuilding moto-rt-cabi with the final Motor Rust toolchain"
	local rustlibs=("$RUSTLIB_SRC"/*.rlib)
	local symbol
	for symbol in motor_start memcpy memmove memset memcmp; do
		if "$B/llvm-nm" --defined-only "${rustlibs[@]}" 2>/dev/null |
				awk -v symbol="$symbol" '$2 ~ /^[Tt]$/ && $3 == symbol { found = 1 } END { exit !found }'; then
			die "final Motor target libraries still define strong $symbol; update the motor-os-rustc toolchain before the strict DNS resolver link"
		fi
	done

	local target_dir="$MOTOR/build/native-toolchain/moto-rt-cabi"
	rm -rf "$target_dir"
	( cd "$MOTOR/src/sys/lib/moto-rt-cabi" \
		&& CARGO_TARGET_DIR="$target_dir" \
			cargo +dev-x86_64-unknown-motor build \
				--target "$TARGET" --release )
	local shim="$target_dir/$TARGET/release/libmoto_rt_cabi.a"
	[ -f "$shim" ] || die "final moto-rt-cabi archive was not produced: $shim"
	for symbol in motor_start memcpy memmove memset memcmp; do
		if "$B/llvm-nm" --defined-only "$shim" 2>/dev/null |
				awk -v symbol="$symbol" '$2 ~ /^[Tt]$/ && $3 == symbol { found = 1 } END { exit !found }'; then
			die "final moto-rt-cabi still defines strong $symbol; the strict DNS resolver link would be unsafe"
		fi
	done
	cp "$shim" "$SYSROOT/sys/tools/llvm/lib/libmoto_rt_cabi.a"

	# The LLVM stage has already staged the C sysroot. Keep that generated image
	# tree synchronized with the final shim before the imager consumes it.
	[ -d "$LLVM_IMG/sys/tools/llvm/lib" ] ||
		die "generated LLVM image tree is missing: $LLVM_IMG"
	"$B/llvm-objcopy" --strip-debug \
		"$shim" "$LLVM_IMG/sys/tools/llvm/lib/libmoto_rt_cabi.a"
}

# cc — the system C compiler / linker driver rustc uses on the image — is not
# built here: it is a `#!/bin/rush` script produced by the LLVM stage (it
# belongs with the C toolchain: it fronts /sys/tools/llvm/bin/llvm and the
# sysroot libs). rustc's default linker is the bare name `cc`, resolved on PATH
# (=/bin on the image), so a native `rustc hello.rs -o hello` links with no
# `-C linker=` flag, exactly as rustc uses /usr/bin/cc on Linux.

# --- stage rustc + the Rust sysroot into the image ----------------------------
rustc_stage_image() {
	log "staging rustc and the Rust sysroot into img_files/generated/rustc"
	# Remove generated files left in the tracked static root by the old
	# workflow; duplicate destinations across static roots are invalid.
	rm -rf "$MOTOR/img_files/motor-os/sys/tools/rust"
	rm -f "$MOTOR/img_files/motor-os/bin/motor-cc"
	rm -rf "$RUSTC_IMG"
	local rust_img="$RUSTC_IMG/sys/tools/rust"
	mkdir -p "$rust_img/bin" "$rust_img/src" \
		"$rust_img/lib/rustlib/$TARGET"

	# The compiler, stripped (~154 MB -> ~98 MB).
	"$B/llvm-strip" -o "$rust_img/bin/rustc" "$RUSTC_MAIN"
	# A binary that still carries mlibc's operator-delete panic stub would
	# abort at runtime; the stub guard must have taken effect.
	if grep -aq 'operator delete called! delete expressions' "$rust_img/bin/rustc"; then
		die "staged rustc contains mlibc's operator-delete stub — sysroot libc.a is stale (see docs/build-rustc.md pitfalls)"
	fi

	# The Rust sysroot. Copy the whole lib dir: the rlibs carry only metadata
	# *stubs* (bootstrap uses -Zembed-metadata=no) — the .rmeta siblings and
	# self-contained/ must come along or rustc fails with "only metadata stub
	# found for rlib dependency `std`".
	rm -rf "$rust_img/lib/rustlib/$TARGET/lib"
	mkdir -p "$rust_img/lib/rustlib/$TARGET/lib"
	cp -r "$RUSTLIB_SRC"/* "$rust_img/lib/rustlib/$TARGET/lib/"
	[ -n "$(ls "$rust_img/lib/rustlib/$TARGET/lib"/*.rmeta 2>/dev/null)" ] || \
		die "no .rmeta files staged — rustc on the image would reject every rlib"

	# (/bin/cc, the linker driver rustc uses, is a rush script staged by the
	# LLVM stage — nothing to stage here.)

	# A sample source exercising HashMap, sorting, and thread spawn/join.
	cat > "$rust_img/src/hello.rs" << 'EOF'
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

	# Seed the reviewed Stage-2 Lorry dependency repository into both the
	# Linux host configuration and the generated image root. Run this after
	# recreating RUSTC_IMG so the image copy survives into the imager.
	"$MOTOR/src/bin/lorry/bootstrap/install_stage2_seed.py"
}

# --- rebuild the OS and the main image ----------------------------------------
build_main_image() {
	# Two builds of the same rust tree produce byte-different compilers with
	# identical `rustc -vV`, which is all cargo fingerprints — every cache
	# built with the previous dev toolchain is silently poisoned (E0463
	# "can't find crate" for random deps). Clear before rebuilding. src/sys/target
	# is the workspace target dir the shim stage builds into with the same dev
	# toolchain, so it is poisoned too.
	log "clearing the Motor OS cargo caches (stale after the rustc rebuild)"
	rm -rf "$MOTOR/build/obj/release" "$MOTOR/src/sys/target"

	log "rebuilding Motor OS + the main image (make main.img BUILD=release)"
	# Keep make's output visible: when a component fails, the compiler diagnostic
	# is the whole diagnosis, and the log alone is easy to overlook.
	( cd "$MOTOR" && \
		make main.img BUILD=release MOTOR_DNS_STRICT_LINK=1 -j"$(nproc)" ) \
		2>&1 | tee "$MAKE_LOG"
	grep -q 'built Motor OS image' "$MAKE_LOG" || \
		die "make finished without the imager running — see $MAKE_LOG"
}

main() {
	log "complete Motor OS build starting"
	log "Motor OS checkout: $MOTOR"
	log "development root:  $MOTORH"

	# A clean checkout cannot build dns-resolver yet: its C bridge needs the
	# mlibc sysroot produced by the LLVM stage. The base stage therefore
	# installs host dependencies and builds the Rust target libraries from
	# motor-os-rt-v17, but skips the base image build.
	log "stage 1/3: host setup and motor-os-rt-v17 Rust target (build-base.sh)"
	local base="$SCRIPT_DIR/build-base.sh"
	[ -x "$base" ] || die "required build stage is not executable: $base"
	MOTOR_SKIP_OS_BUILD=1 "$base"
	# build-base installs rustup in $HOME/.cargo; bring it onto PATH (the
	# subprocess above can't export into us).
	[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

	# Build every C/C++ input, the native LLVM multicall, and Lua, and stage
	# them into the generated LLVM image root. No intermediate image: the rustc
	# stage replaces the bootstrap compiler and performs the definitive build.
	log "stage 2/3: Motor LLVM, mlibc/libc++, native LLVM, and Lua"
	ensure_meson
	clone_sources
	build_cross_toolchain
	build_shim
	build_builtins
	build_mlibc
	build_cxx_runtimes
	build_native_llvm
	build_lua
	llvm_stage_image

	# Build the forked native rustc and both standard libraries, rebuild the C
	# ABI shim with that final toolchain, stage the native Rust toolchain,
	# clear stale Cargo outputs, and run the final make. `make main.img`
	# includes dns-resolver.
	log "stage 3/3: native Motor rustc and the main Motor OS image"
	rustc_verify_prereqs
	check_mlibc
	update_rust
	write_wrappers
	write_bootstrap_toml
	build_rustc
	build_stds
	rebuild_shim
	rustc_stage_image
	build_main_image

	local required_outputs=(
		"$LLVM_IMG/sys/tools/llvm/bin/llvm"
		"$LLVM_IMG/bin/cc"
		"$RUSTC_IMG/sys/tools/rust/bin/rustc"
		"$MOTOR/build/bin/release/dns-resolver"
		"$MOTOR/vm_images/release/motor-os.img"
		"$MOTOR/vm_images/release/motor-os-base.img"
	)
	local output
	for output in "${required_outputs[@]}"; do
		[ -f "$output" ] || die "final build output is missing: $output"
	done

	log "complete release image built successfully"
	log "image: $MOTOR/vm_images/release/motor-os.img"
	log "run:   cd \"$MOTOR/vm_images/release\" && ./run-qemu.sh"
	log "then, at the Motor OS prompt:"
	log "  cc /sys/tools/llvm/src/hello.c -o /sys/tmp/hello && /sys/tmp/hello"
	log "  c++ /sys/tools/llvm/src/hello.cpp -o /sys/tmp/hello2 && /sys/tmp/hello2"
	log "  /sys/tools/rust/bin/rustc /sys/tools/rust/src/hello.rs -o /sys/tmp/hello3 && /sys/tmp/hello3"
}

main "$@"
