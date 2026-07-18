#!/usr/bin/env bash
#
# build-llvm.sh — build the Motor OS native LLVM/Clang toolchain, the C/C++
# sysroot (mlibc + libc++ stack), and Lua, and bake them into the VM image.
#
# This runs build-base.sh first (so a bare machine is fully bootstrapped), then
# performs every step from docs/build-llvm.md, and finally rebuilds the image.
#
# On-image layout (see docs/porting-libc/dirs.md): headers + libraries live
# under /sys/tools/llvm, the clang driver config under /sys/cfg/llvm, and
# mlibc's config files under /sys/cfg/libc — not the classic /usr and /etc.
#
# USAGE
#   Copy this script AND build-base.sh into an empty directory and run:
#
#       ./build-llvm.sh
#
#   That directory becomes $MOTORH. Everything is cloned/built underneath it.
#   These files are kept in the repo at src/ only as the canonical copies to
#   hand out; do not run them from inside a checkout.
#
# RE-RUNNING is safe: clones, apt packages, and toolchain setup are detected and
# skipped; the compiles run again (incrementally). See docs/build-llvm.md for
# the prose walkthrough behind each stage.

set -euo pipefail

# --- logging helpers --------------------------------------------------------
log()  { printf '\033[1;34m[build-llvm]\033[0m %s\n' "$*"; }
skip() { printf '\033[1;32m[build-llvm]\033[0m (skip) %s\n' "$*"; }
warn() { printf '\033[1;33m[build-llvm]\033[0m WARNING: %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[build-llvm]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO"' ERR

# --- paths (same scheme as docs/build-llvm.md) ------------------------------
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
MOTORH="$SCRIPT_DIR"
export MOTORH
MOTOR="$MOTORH/motor-os"
LLVM="$MOTORH/llvm-project"
MLIBC="$MOTORH/mlibc"
B="$LLVM/build/bin"                 # the cross toolchain, built in stage 1
SYSROOT="$MOTORH/motor-sysroot"
CROSS_FILE="$MOTORH/motor.cross-file"
LUA_VER="5.4.8"
CLANG_MAJOR=""                      # detected after the host toolchain is built

# On-image directory prefixes (mirrored inside the cross sysroot). Keep these in
# sync with clang/lib/Driver/ToolChains/Motor.cpp and mlibc's MLIBC_SYSCONFDIR.
TOOLS="sys/tools/llvm"              # headers + libraries
CFG_LLVM="sys/cfg/llvm"            # clang <triple>.cfg
CFG_LIBC="sys/cfg/libc"           # mlibc config files (resolv.conf, ...)

# --- 0. bootstrap the base environment via build-base.sh --------------------
run_build_base() {
	local base="$SCRIPT_DIR/build-base.sh"
	[ -x "$base" ] || die "build-base.sh not found next to this script ($base). Copy both scripts into the same directory."
	log "running build-base.sh (base environment + Motor OS build)"
	"$base"
	# build-base installs rustup in $HOME/.cargo; bring it onto PATH for the
	# cargo invocation in stage 2 (the subprocess above can't export into us).
	[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
}

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
	# Everything on one branch, motor-os-rustc, so build-rustc.sh reuses these
	# same checkouts without switching branches. mlibc motor-os-rustc is a
	# superset of the old `motor` branch (extra lazy-TCB + operator-delete
	# guard, harmless for C/C++). llvm-project motor-os-rustc is the LLVM 23
	# line with the Clang Motor ToolChain; rustc builds its *own* copy of this
	# same LLVM from its submodule (see build-rustc.md), so there is one LLVM
	# repo and version across both builds.
	clone_repo https://github.com/moturus/mlibc.git        "$MLIBC" motor-os-rustc
	clone_repo https://github.com/moturus/llvm-project.git "$LLVM"  motor-os-rustc
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

# --- stage 8: stage everything into the image -------------------------------
stage_image() {
	log "stage 8: staging the toolchain, sysroot, and Lua into img_files"
	local img="$MOTOR/img_files/motor-os"

	# Remove any obsolete /usr + /etc staging from earlier layouts — the
	# toolchain now lives entirely under /sys.
	rm -rf "$img/usr" "$img/etc"

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
}

# --- rebuild the Motor OS image with the new artifacts ----------------------
build_image() {
	log "rebuilding the Motor OS image (make -j\$(nproc) BUILD=release)"
	( cd "$MOTOR" && make -j"$(nproc)" BUILD=release )
}

main() {
	log "Motor OS + LLVM build starting; MOTORH = $MOTORH"
	run_build_base
	ensure_meson
	clone_sources
	build_cross_toolchain
	build_shim
	build_builtins
	build_mlibc
	build_cxx_runtimes
	build_native_llvm
	build_lua
	stage_image
	build_image
	log "done — the image at $MOTOR/vm_images/release now carries clang/lld/llvm, lua, and the C/C++ sysroot."
	log "to run the VM:  cd \"$MOTOR/vm_images/release\" && ./run-qemu.sh"
	log "then, at the Motor OS prompt (the multicall lives at /sys/tools/llvm/bin/llvm):"
	log "  /sys/tools/llvm/bin/llvm clang /sys/tools/llvm/src/hello.c -o /sys/tmp/hello && /sys/tmp/hello"
	log "  cc /sys/tools/llvm/src/hello.c -o /sys/tmp/hello2 && /sys/tmp/hello2   # /bin/cc: same thing, conventional name"
	log "  c++ /sys/tools/llvm/src/hello.cpp -o /sys/tmp/hello3 && /sys/tmp/hello3  # /bin/c++: the C++ counterpart"
}

main "$@"
