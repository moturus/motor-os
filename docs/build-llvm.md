# Building mlibc and llvm for Motor OS

This guide assumes that you can [build and run Motor OS](build.md).

It also assumes that `$MOTORH` env var points to the root of Motor OS
development directory, as described in [build.md](build.md), so that
`$MOTORH/motor-os` contains Motor OS repo from https://github.com/moturus/motor-os.git,
while `$MOTORH/rust` contains Rust sources there were used to build
Rust stdlib for Motor OS. In particular, the `dev-x86_64-unknown-motor`
Rust toolchain registered in [build.md](build.md) is required below to build
the C-ABI shim.

The end result of this guide is a Motor OS VM image that carries a native
`clang`/`lld`/`llvm-*` toolchain (one multicall `llvm` binary), a `lua`
interpreter, and a complete C/C++ sysroot (mlibc headers, `libc.a`, the C++
runtime stack with working exceptions, `crt1.o`, and the compiler runtime) —
so that, booted into the VM, you can compile and run C and C++ programs
natively:

```sh
/sys/tools/llvm/bin/llvm clang   /sys/tools/llvm/src/hello.c   -o /sys/tmp/hello   && /sys/tmp/hello
/sys/tools/llvm/bin/llvm clang++ /sys/tools/llvm/src/hello.cpp -o /sys/tmp/hellopp && /sys/tmp/hellopp
cc /sys/tools/llvm/src/hello.c -o /sys/tmp/hello3 && /sys/tmp/hello3   # /bin/cc: the PATH shortcut
c++ /sys/tools/llvm/src/hello.cpp -o /sys/tmp/hello4 && /sys/tmp/hello4  # /bin/c++: same for C++
```

On the image the toolchain lives under `/sys` — the multicall `llvm` binary at
`/sys/tools/llvm/bin` (mirroring the Rust toolchain's `/sys/tools/rust/bin`, and
invoked by full path just like `rustc`), headers and libraries at
`/sys/tools/llvm`, the clang driver config at `/sys/cfg/llvm`, and mlibc's config
files (`resolv.conf`, ...) at `/sys/cfg/libc`. See
[porting-libc/dirs.md](porting-libc/dirs.md) for the rationale.

For convenience, `/bin/cc` — a `#!/bin/rush` pass-through to `llvm clang` — is
the PATH-accessible system C compiler (`cc hello.c -o hello`), with `/bin/c++`
(`--driver-mode=g++`) as its C++ counterpart. `cc` is also what `rustc` invokes
as its default linker, so native `rustc` needs no `-C linker=` flag; see
[build-rustc.md](build-rustc.md). Both scripts are produced by this guide
(stage 8) because they belong with the C toolchain they front. The clang Motor
ToolChain owns the whole link recipe (crt1.o + the mlibc/libc++ runtime group)
and gates it on `-nostdlib`/`-nostartfiles`/`-nodefaultlibs`, so plain C/C++
links get the full runtime while rustc's pure-Rust links (which pass
`-nostartfiles -nodefaultlibs`) stay mlibc-free — a pure-Rust binary is ~113 KB
(see [libc_start_redesign.md](libc_start_redesign.md)).

## How the pieces fit together

Everything is **cross-built on the Ubuntu host** and then staged into the
image; nothing is compiled on Motor OS itself (self-hosting the *build* is a
separate, distant project). The layers, bottom to top:

```
C/C++ program
  └─ mlibc                       (libc.a, headers, crt1.o)          repo: mlibc @ motor
       └─ libmoto_rt_cabi.a      (C-ABI shim over the RT.VDSO)      repo: motor-os (src/sys/lib/moto-rt-cabi)
  └─ libc++ / libc++abi / libunwind  (C++ runtime + exceptions)     repo: llvm-project @ motor-os-next
  └─ libclang_rt.builtins        (compiler runtime, no emutls)      repo: llvm-project @ motor-os-next
The toolchain that builds all of the above, and also runs on Motor:
  └─ clang + lld + llvm-*        (cross build/, native build-motor-native/) repo: llvm-project @ motor-os-next
```

Build order matters — each stage consumes the sysroot the previous ones filled:

1. **Cross toolchain** — host `clang`/`lld`/`llvm-*` that target `x86_64-unknown-motor`.
2. **The shim** (`libmoto_rt_cabi.a` + `moto_rt.h`).
3. **compiler-rt builtins** (with `emutls` excluded — the shim owns emulated TLS).
4. **mlibc** (`libc.a`, `crt1.o`, headers, empty companion stubs).
5. **C++ runtimes** (`libunwind`, `libc++abi`, `libc++`, exceptions on).
6. **Native LLVM** (the on-image `llvm` multicall binary).
7. **Lua** (a real end-to-end program).
8. **Stage** everything into `img_files/motor-os/` and rebuild the image.

Rough budget: a first build is ~1–2 h of compiling (two full LLVM builds
dominate) and adds ~135 MB to the image.

## Prerequisites and environment

On top of the packages from [build.md](build.md), install meson (the
mlibc build system):

```sh
sudo apt install meson
```

Set the environment used by every stage below (add these to your shell, or
re-`export` them in each new terminal):

```sh
export MOTORH=$HOME/motorh          # same root as build.md
export MOTOR=$MOTORH/motor-os       # the Motor OS repo
export LLVM=$MOTORH/llvm-project
export MLIBC=$MOTORH/mlibc
export B=$LLVM/build/bin            # the cross toolchain, built in stage 1
export SYSROOT=$MOTORH/motor-sysroot
export CLANG_MAJOR=23               # must match `$B/clang --version`; also baked into the image cfg
```

Check out the two repos at the branches that carry the Motor OS support.

mlibc — branch `motor-os-rustc` (the `sysdeps/motor` port and its small generic
hooks, plus the lazy foreign-thread TCB and the `operator delete` stub guard the
native rustc needs — all harmless for a plain C/C++ toolchain, and using the
same branch here means [build-rustc.md](build-rustc.md) never has to switch it):

```sh
cd $MOTORH
git clone https://github.com/moturus/mlibc.git
cd mlibc
git checkout motor-os-rustc
```

llvm — branch `motor-os-rustc` (LLVM 23: the Motor triple, the Clang
driver/ToolChain, and a handful of `lib/Support` portability fixes, on top of
upstream llvm-project). This is the **same** repo, branch, and commit that
rustc builds its own LLVM from (its `src/llvm-project` submodule is pointed
here — see [build-rustc.md](build-rustc.md)), so there is one LLVM version
across both builds:

```sh
cd $MOTORH
git clone https://github.com/moturus/llvm-project.git
cd llvm-project
git checkout motor-os-rustc
```

## Stage 1 — the cross toolchain (host clang/lld/llvm-\*)

Build a host copy of clang + lld + the llvm binutils. This is the compiler that
cross-builds everything else for `x86_64-unknown-motor` (the Motor triple and
its Clang toolchain are already committed on `motor-os-next`).

```sh
cd $LLVM
cmake -S llvm -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_ASSERTIONS=ON \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD=X86 \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++

ninja -C build \
  clang lld llvm-ar llvm-ranlib llvm-nm llvm-readelf llvm-strip llvm-objcopy

# Sanity: confirm the compiler major matches $CLANG_MAJOR above.
$B/clang --version | head -1
```

Clang auto-loads a `<triple>.cfg` from the directory the binary lives in. Create
the **host-side** config so that every cross link this toolchain performs is a
raw `-static-pie -nostdlib` link — the mlibc build's compiler probes and all the
explicit link recipes below depend on this:

```sh
cat > $B/x86_64-unknown-motor.cfg << 'EOF'
-fuse-ld=lld
-static-pie
-nostdlib
-Wl,-e,motor_start
-Wl,--pack-dyn-relocs=none
-Wl,-z,noexecstack
EOF
```

(This is distinct from the *image* config created in stage 8, which drives the
full on-image link recipe. Do not confuse the two.)

## Stage 2 — the C-ABI shim (`libmoto_rt_cabi.a`)

The shim is a Rust staticlib in the Motor OS repo that exposes a flat C ABI over
the RT.VDSO and implements the emulated-TLS runtime (`__emutls_get_address`,
`__cxa_thread_atexit`). It is built with the `dev-x86_64-unknown-motor` Rust
toolchain from [build.md](build.md):

```sh
mkdir -p $SYSROOT/sys/tools/llvm/lib $SYSROOT/sys/tools/llvm/include

cd $MOTOR/src/sys/lib/moto-rt-cabi
cargo +dev-x86_64-unknown-motor build --target x86_64-unknown-motor --release

cp $MOTOR/src/sys/target/x86_64-unknown-motor/release/libmoto_rt_cabi.a \
   $SYSROOT/sys/tools/llvm/lib/
cp $MOTOR/src/sys/lib/moto-rt-cabi/moto_rt.h $SYSROOT/sys/tools/llvm/include/

# Sanity: the key exports are present, exactly once.
$B/llvm-nm $SYSROOT/sys/tools/llvm/lib/libmoto_rt_cabi.a 2>/dev/null | \
  grep -w -e moto_rt_start -e __emutls_get_address -e __cxa_thread_atexit -e memcpy
```

## Stage 3 — compiler-rt builtins (emutls excluded)

The compiler runtime (`__divti3`, `__udivmodti4`, …). `emutls.c` is excluded so
there is exactly one emulated-TLS implementation on the system — the shim's.

```sh
cd $LLVM
cmake -S compiler-rt/lib/builtins -B build-builtins -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
  -DCMAKE_C_FLAGS="-ffreestanding" \
  -DCMAKE_C_COMPILER=$B/clang \
  -DCMAKE_C_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_ASM_COMPILER=$B/clang \
  -DCMAKE_ASM_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_AR=$B/llvm-ar -DCMAKE_RANLIB=$B/llvm-ranlib -DCMAKE_NM=$B/llvm-nm \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
  -DCOMPILER_RT_BAREMETAL_BUILD=ON \
  -DCMAKE_DISABLE_FIND_PACKAGE_LLVM=ON
ninja -C build-builtins

BUILTINS=$(find $LLVM/build-builtins -name 'libclang_rt.builtins*.a' | head -1)

# COMPILER_RT_BAREMETAL_BUILD=ON already omits emutls.c; assert it, and drop it
# if some config drift ever pulls it back in.
$B/llvm-ar t "$BUILTINS" | grep -q emutls && $B/llvm-ar d "$BUILTINS" emutls.c.o
$B/llvm-nm "$BUILTINS" 2>/dev/null | grep __emutls && echo "STILL THERE — BAD" || true

# Stage two copies: one in the sysroot, and one at the per-target resource-dir
# path where both mlibc's build and the clang driver look for it.
cp "$BUILTINS" $SYSROOT/sys/tools/llvm/lib/libclang_rt.builtins-x86_64.a
RD=$LLVM/build/lib/clang/$CLANG_MAJOR/lib/x86_64-unknown-motor
mkdir -p $RD
cp "$BUILTINS" $RD/libclang_rt.builtins.a
```

`-DCMAKE_C_FLAGS="-ffreestanding"` matters: the Motor ToolChain adds
`<sysroot>/sys/tools/llvm/include` to the search path, which is empty under the
cross sysroot at this stage. Without `-ffreestanding` (`__STDC_HOSTED__=0`),
clang's freestanding `limits.h`/`stdint.h` would `#include_next` into the host
glibc headers and fail (`bits/libc-header-start.h` not found) — and `-isystem
$SYSROOT/sys/tools/llvm/include` can't help here because mlibc's headers don't
exist yet at this stage.

`-DCMAKE_DISABLE_FIND_PACKAGE_LLVM=ON` keeps the build reproducible across hosts.
The standalone builtins configure runs a **non-`REQUIRED`** `find_package(LLVM)`
(via `load_llvm_config` in `compiler-rt/cmake/Modules/CompilerRTUtils.cmake`).
With no hint it searches the system paths, so on a machine that happens to have a
distro LLVM `-dev` package installed (say `/usr/lib/llvm-21`) it loads *that*
package's `LLVMExports.cmake`, which declares the `libLLVM`/`LTO`/`Remarks`
dylibs as `SHARED IMPORTED`. Under `CMAKE_SYSTEM_NAME=Generic` the platform has
no dynamic linking, and recent CMake turns an imported `SHARED` target into a
hard error and aborts the configure:

```
CMake Error at /usr/lib/llvm-21/lib/cmake/llvm/LLVMExports.cmake:… (add_library):
  ADD_LIBRARY called with SHARED option but the target platform does not
  support dynamic linking.
```

The builtins don't need LLVM at all — disabling the lookup forces compiler-rt's
built-in mock-config fallback (the same path a host *without* a system LLVM takes
silently). Pointing `find_package` at the freshly built LLVM tree instead does
**not** fix it: that tree's exports carry the same `SHARED IMPORTED` `LTO`/
`Remarks` targets and hit the identical error.

## Stage 4 — mlibc

mlibc is built with meson, cross-compiled by the stage-1 toolchain. Write a
meson cross file that points at that toolchain and the sysroot (kept out of the
repo so both checkouts stay clean):

```sh
cat > $MOTORH/motor.cross-file << EOF
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
# -D_GNU_SOURCE: mlibc's own sources use GNU-guarded declarations. g++ predefines
# it in C++ mode; clang++ does not for non-glibc targets like ours.
# -DMLIBC_SYSCONFDIR: repoints mlibc's runtime config lookups (resolv.conf, hosts,
# passwd, ...) from the default /etc to Motor's /sys/cfg/libc.
c_args = ['-I$SYSROOT/sys/tools/llvm/include', '-D_GNU_SOURCE', '-DMLIBC_SYSCONFDIR="/sys/cfg/libc"']
cpp_args = ['-I$SYSROOT/sys/tools/llvm/include', '-D_GNU_SOURCE', '-DMLIBC_SYSCONFDIR="/sys/cfg/libc"']

[properties]
# The compiler sanity checks link a small static-PIE exe (the host cfg makes it
# -nostdlib, so it succeeds); needs_exe_wrapper stops meson from trying to run it.
needs_exe_wrapper = true
EOF
```

Install the headers first (fast; validates the ABI/meson wiring), then build and
install the static `libc.a` and companion archives:

```sh
cd $MLIBC

# Headers only.
meson setup --cross-file $MOTORH/motor.cross-file --prefix=/sys/tools/llvm \
    -Dheaders_only=true build-headers
DESTDIR=$SYSROOT ninja -C build-headers install

# The real static build: libc.a, crt1.o, all headers, and the empty companion
# stubs (libm/libpthread/libdl/librt/... — everything lives in libc.a on Motor).
# -Ddebug=false: mlibc's own meson.build pins buildtype=debugoptimized (-O2 -g);
# the flag keeps -O2 and drops only -g. Without it libc.a is 18 MB (59% DWARF)
# and every mlibc-linked binary carries ~6.6 MB of debug info — .text is
# byte-identical either way (see libc_start_redesign.md).
meson setup --cross-file $MOTORH/motor.cross-file --prefix=/sys/tools/llvm \
    -Ddefault_library=static -Dbuild_tests=false -Ddebug=false build
ninja -C build
DESTDIR=$SYSROOT ninja -C build install

ls $SYSROOT/sys/tools/llvm/lib/libc.a $SYSROOT/sys/tools/llvm/lib/crt1.o   # both must exist
```

## Stage 5 — the C++ runtime stack (with exceptions)

Cross-build `libunwind`, `libc++abi`, and `libc++` against mlibc, with C++
exceptions and RTTI enabled, and install them into the sysroot.

```sh
cd $LLVM
rm -rf $LLVM/build-motor-cxx   # stale try_compile results are poison

cmake -G Ninja -S $LLVM/runtimes -B $LLVM/build-motor-cxx \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=$B/clang -DCMAKE_CXX_COMPILER=$B/clang++ \
  -DCMAKE_C_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_CXX_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_C_FLAGS="-isystem $SYSROOT/sys/tools/llvm/include -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_LIBUNWIND_USE_DLADDR=0" \
  -DCMAKE_CXX_FLAGS="-isystem $SYSROOT/sys/tools/llvm/include -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_LIBUNWIND_USE_DLADDR=0" \
  -DCMAKE_INSTALL_PREFIX=/sys/tools/llvm \
  -DLLVM_ENABLE_RUNTIMES="libunwind;libcxxabi;libcxx" \
  -DLLVM_USE_LINKER=lld \
  \
  -DLIBUNWIND_ENABLE_SHARED=OFF -DLIBUNWIND_ENABLE_STATIC=ON \
  -DLIBUNWIND_ENABLE_THREADS=ON \
  -DLIBUNWIND_USE_COMPILER_RT=ON \
  -DLIBUNWIND_INCLUDE_TESTS=OFF \
  -DLIBUNWIND_HAS_PTHREAD_LIB=OFF -DLIBUNWIND_HAS_DL_LIB=OFF \
  \
  -DLIBCXXABI_ENABLE_SHARED=OFF -DLIBCXXABI_ENABLE_STATIC=ON \
  -DLIBCXXABI_ENABLE_EXCEPTIONS=ON \
  -DLIBCXXABI_ENABLE_THREADS=ON \
  -DLIBCXXABI_USE_COMPILER_RT=ON \
  -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
  -DLIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL=OFF \
  -DLIBCXXABI_ENABLE_ASSERTIONS=OFF \
  -DLIBCXXABI_HAS_PTHREAD_LIB=OFF \
  \
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

ninja -C $LLVM/build-motor-cxx unwind cxxabi cxx
DESTDIR=$SYSROOT ninja -C $LLVM/build-motor-cxx \
  install-unwind install-cxxabi install-cxx

ls $SYSROOT/sys/tools/llvm/lib/libc++.a $SYSROOT/sys/tools/llvm/lib/libc++abi.a $SYSROOT/sys/tools/llvm/lib/libunwind.a
```

Two non-obvious flags this recipe already encodes:

- `-D_LIBUNWIND_USE_DLADDR=0` — mlibc guards `Dl_info` behind its (disabled)
  glibc option, so libunwind's `dladdr`-based symbolication must be turned off.
- `-D_GNU_SOURCE -D_DEFAULT_SOURCE` — libc++ compiles as `-std=c++26`
  (`__STRICT_ANSI__`), under which mlibc does not imply `_DEFAULT_SOURCE`, so
  `realpath` and friends would go missing without it.

The sysroot at `$SYSROOT` is now a complete C/C++ development root.

## Stage 6 — the native LLVM toolchain (the on-image `llvm`)

Cross-build clang + lld + the llvm binutils again, this time *targeting Motor* —
the output is a single static-PIE multicall `llvm` binary that runs on the image
and dispatches `llvm clang`, `llvm ld.lld`, `llvm ar`, `llvm nm`, etc.

The `CMAKE_*_STANDARD_LIBRARIES` values below complete the driver's own
`-static-pie` link probes; they mirror the link group the Motor ToolChain emits
(shim first so its `__cxa_thread_atexit` wins, `-lunwind` present for the EH
runtime). Both the C and C++ groups carry `-lc++abi`: mlibc is C++ internally, so
even a C link pulls `operator delete`/`new` from `libc.a` members, matching the
ToolChain's `ConstructJob` (which adds `-lc++abi` unconditionally).

```sh
cd $LLVM
cmake -S $LLVM/llvm -B $LLVM/build-motor-native -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=Linux \
  -DCMAKE_C_COMPILER=$B/clang \
  -DCMAKE_CXX_COMPILER=$B/clang++ \
  -DCMAKE_C_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_CXX_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_C_FLAGS="-isystem $SYSROOT/sys/tools/llvm/include -D_GNU_SOURCE -D_DEFAULT_SOURCE" \
  -DCMAKE_CXX_FLAGS="-nostdinc++ -isystem $SYSROOT/sys/tools/llvm/include/c++/v1 -isystem $SYSROOT/sys/tools/llvm/include -D_GNU_SOURCE -D_DEFAULT_SOURCE" \
  -DCMAKE_C_STANDARD_LIBRARIES="$SYSROOT/sys/tools/llvm/lib/crt1.o -Wl,--start-group -lmoto_rt_cabi -lc++abi -lunwind -lc -lclang_rt.builtins-x86_64 -Wl,--end-group" \
  -DCMAKE_CXX_STANDARD_LIBRARIES="$SYSROOT/sys/tools/llvm/lib/crt1.o -Wl,--start-group -lmoto_rt_cabi -lc++ -lc++abi -lunwind -lc -lclang_rt.builtins-x86_64 -Wl,--end-group" \
  -DCMAKE_EXE_LINKER_FLAGS="-L$SYSROOT/sys/tools/llvm/lib" \
  -DCMAKE_TRY_COMPILE_PLATFORM_VARIABLES="CMAKE_C_STANDARD_LIBRARIES;CMAKE_CXX_STANDARD_LIBRARIES" \
  -DLLVM_HOST_TRIPLE=x86_64-unknown-motor \
  -DLLVM_DEFAULT_TARGET_TRIPLE=x86_64-unknown-motor \
  -DLLVM_TARGETS_TO_BUILD=X86 \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TOOL_LLVM_DRIVER_BUILD=ON \
  -DLLVM_NATIVE_TOOL_DIR=$B \
  -DLLVM_ENABLE_THREADS=ON \
  -DLLVM_ENABLE_ZLIB=OFF -DLLVM_ENABLE_ZSTD=OFF -DLLVM_ENABLE_LIBXML2=OFF \
  -DLLVM_ENABLE_LIBEDIT=OFF -DLLVM_ENABLE_PLUGINS=OFF \
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_INCLUDE_DOCS=OFF \
  -DCLANG_ENABLE_STATIC_ANALYZER=OFF \
  -DCLANG_DEFAULT_LINKER=lld -DCLANG_DEFAULT_RTLIB=compiler-rt \
  -DCLANG_DEFAULT_CXX_STDLIB=libc++ \
  -DDEFAULT_SYSROOT= \
  -DCLANG_CONFIG_FILE_SYSTEM_DIR=/sys/cfg/llvm

ninja -C $LLVM/build-motor-native llvm-driver
```

`CMAKE_TRY_COMPILE_PLATFORM_VARIABLES` is load-bearing: without it, the two
`STANDARD_LIBRARIES` values are not forwarded into cmake's `try_compile`
sub-projects, so every `check_symbol_exists` probe links without libc and
silently fails (`getpagesize`, `sysconf`, … all wrongly "not found"). If you
change the sysroot's archive set and reconfigure, wipe `build-motor-native`
first — the wrong probe results are cached.

The result is `$LLVM/build-motor-native/bin/llvm` (unstripped; ~138 MB). Keep
the unstripped copy on the host for symbolizing VM backtraces with `addr2line`;
the image gets a stripped copy (stage 8).

## Stage 7 — Lua

A plain upstream Lua 5.4, cross-compiled against the sysroot — a real,
fork-free program that exercises `setjmp`/`longjmp`, `strtod`, the allocator,
and time/date APIs.

```sh
cd $MOTORH
curl -LO https://www.lua.org/ftp/lua-5.4.8.tar.gz     # or the latest 5.4.x
tar xf lua-5.4.8.tar.gz
cd lua-5.4.8/src

CFLAGS="--target=x86_64-unknown-motor -O2 -isystem $SYSROOT/sys/tools/llvm/include -DLUA_USE_POSIX"

# Everything except the two standalone drivers → liblua.a.
for f in $(ls *.c | grep -v -e '^lua\.c$' -e '^luac\.c$'); do
  $B/clang $CFLAGS -c $f || break
done
$B/llvm-ar rcs liblua.a *.o

# Link the interpreter. mlibc is C++ internally (its stdio FILE machinery —
# cookie_file, memstream, fmemopen — has C++ destructors that call
# `operator delete`), so even this pure-C program pulls libc++abi/libunwind out
# of libc.a and must link them: the same C link group the Motor ToolChain emits
# (suppressed here by the host cfg's -nostdlib, so listed explicitly).
# --start-group resolves the libc <-> libc++abi <-> shim back-references.
$B/clang $CFLAGS lua.c liblua.a $SYSROOT/sys/tools/llvm/lib/crt1.o \
  -Wl,--start-group \
  $SYSROOT/sys/tools/llvm/lib/libmoto_rt_cabi.a \
  $SYSROOT/sys/tools/llvm/lib/libc++abi.a \
  $SYSROOT/sys/tools/llvm/lib/libunwind.a \
  $SYSROOT/sys/tools/llvm/lib/libc.a \
  $SYSROOT/sys/tools/llvm/lib/libclang_rt.builtins-x86_64.a \
  -Wl,--end-group -o lua
```

## Stage 8 — stage everything into the image

`img_files/motor-os/` is a passthrough that maps to the **image root** (the
imager yaml already lists it — never edit that yaml). Headers and libraries land
at `/sys/tools/llvm`, the `llvm` multicall at `/sys/tools/llvm/bin` (mirroring
`/sys/tools/rust/bin`), `lua` and the `cc` script at `/bin`, the clang driver
config at `/sys/cfg/llvm`, and mlibc's config at `/sys/cfg/libc`. (If an earlier
build left a `/usr` or `/etc` tree, or a `/bin/llvm` from the old layout, delete
them: `rm -rf $IMG/usr $IMG/etc $IMG/bin/llvm`.)

```sh
IMG=$MOTOR/img_files/motor-os
rm -rf $IMG/usr $IMG/etc     # obsolete layout, if present
rm -f  $IMG/bin/llvm         # old location — the multicall now lives under /sys
mkdir -p $IMG/bin $IMG/sys/tools/llvm/bin $IMG/sys/cfg/llvm $IMG/sys/cfg/libc \
         $IMG/sys/tools/llvm/lib/clang/$CLANG_MAJOR $IMG/sys/tools/llvm/src

# 1. Headers: mlibc + libc++'s c++/v1.
cp -r $SYSROOT/sys/tools/llvm/include $IMG/sys/tools/llvm/

# 2. Clang's own resource headers (intrinsics, stdarg.h, ...).
cp -r $LLVM/build/lib/clang/$CLANG_MAJOR/include $IMG/sys/tools/llvm/lib/clang/$CLANG_MAJOR/

# 3. Libraries — strip debug info on the way in.
for a in libc libc++ libc++abi libunwind libmoto_rt_cabi \
         libclang_rt.builtins-x86_64 \
         libdl libm libpthread librt libresolv libutil libssp libssp_nonshared; do
  $B/llvm-objcopy --strip-debug $SYSROOT/sys/tools/llvm/lib/$a.a $IMG/sys/tools/llvm/lib/$a.a
done
cp $SYSROOT/sys/tools/llvm/lib/crt1.o $IMG/sys/tools/llvm/lib/

# 4. The on-image LLVM multicall, stripped, at /sys/tools/llvm/bin (like rustc
#    at /sys/tools/rust/bin). Its clang config + resource dir are pinned by
#    absolute path and its ld.lld self-dispatch uses the running exe's own path,
#    so it works wherever it is placed. Lua stays in /bin.
$B/llvm-strip -o $IMG/sys/tools/llvm/bin/llvm $LLVM/build-motor-native/bin/llvm
$B/llvm-strip -o $IMG/bin/lua  $MOTORH/lua-5.4.8/src/lua

# 4b. /bin/cc and /bin/c++ — the PATH-accessible system C / C++ compiler and
#     linker drivers: `#!/bin/rush` pass-throughs over `llvm clang`. rustc's
#     default linker is the bare name `cc`, so native `rustc hello.rs -o hello`
#     links with no `-C linker=` flag (like /usr/bin/cc on Linux). The Motor
#     ToolChain owns the whole link recipe (crt1.o + the mlibc/libc++ group,
#     incl. libc++abi even for C links — mlibc is C++ internally) and gates it
#     on -nostdlib/-nostartfiles/-nodefaultlibs, so `cc hello.c` gets the full
#     C runtime while rustc's pure-Rust links (which pass those flags) get
#     nothing forced on them (~113 KB, not 8 MB — libc_start_redesign.md).
#     Rust programs that want mlibc opt back in with
#     `-C link-self-contained=no -C default-linker-libraries=yes`
#     (build-rustc.md). /bin/c++ uses --driver-mode=g++ rather than a `clang++`
#     subcommand: the multicall dispatches on the first argument, and `clang++`
#     is not a registered subcommand name.
cat > $IMG/bin/cc << 'EOF'
#!/bin/rush
# cc — Motor OS's system C compiler / linker driver. See docs/build-llvm.md.
# A pass-through: clang's Motor ToolChain owns the link recipe and honors
# -nostartfiles/-nodefaultlibs (rustc's pure-Rust links stay mlibc-free).
/sys/tools/llvm/bin/llvm clang "$@"
EOF

cat > $IMG/bin/c++ << 'EOF'
#!/bin/rush
# c++ — Motor OS's system C++ compiler / linker driver. See docs/build-llvm.md.
/sys/tools/llvm/bin/llvm clang --driver-mode=g++ "$@"
EOF

# 5. The image driver config. The full link/include recipe lives in the driver
#    (the Motor ToolChain) now; only the resource dir needs pinning. Clang
#    auto-loads this from /sys/cfg/llvm (CLANG_CONFIG_FILE_SYSTEM_DIR, stage 6).
cat > $IMG/sys/cfg/llvm/x86_64-unknown-motor.cfg << EOF
-resource-dir /sys/tools/llvm/lib/clang/$CLANG_MAJOR
EOF

# 6. mlibc reads its config from /sys/cfg/libc (MLIBC_SYSCONFDIR). Its generic
#    DNS client needs both a nameserver and the domain service entry.
cat > $IMG/sys/cfg/libc/resolv.conf << 'EOF'
nameserver 8.8.8.8
EOF
cat > $IMG/sys/cfg/libc/services << 'EOF'
domain 53/tcp
domain 53/udp
EOF

# 7. A couple of sample sources to compile natively in the VM.
cat > $IMG/sys/tools/llvm/src/hello.c << 'EOF'
#include <stdio.h>

int main(void) {
	printf("Hello from Motor-native clang!\n");
	return 0;
}
EOF
cat > $IMG/sys/tools/llvm/src/hello.cpp << 'EOF'
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
```

Rebuild the image (re-runs the imager; the other components are already built,
so this is quick):

```sh
cd $MOTOR
make img BUILD=release -j$(nproc)
```

## Verify in the VM

Boot the image ([build.md](build.md), `run-qemu.sh`) and, at the Motor OS
prompt, compile and run natively:

```sh
mkdir /sys/tmp                                            # scratch for outputs
/sys/tools/llvm/bin/llvm clang   /sys/tools/llvm/src/hello.c   -o /sys/tmp/hello   && /sys/tmp/hello
/sys/tools/llvm/bin/llvm clang++ /sys/tools/llvm/src/hello.cpp -o /sys/tmp/hellopp && /sys/tmp/hellopp
cc /sys/tools/llvm/src/hello.c -o /sys/tmp/hello3 && /sys/tmp/hello3
lua -e 'print("lua on Motor:", 2^0.5)'
```

Both C and C++ link directly: the Motor clang ToolChain adds `-lc++abi` to the
link group unconditionally (mlibc is C++ internally, so even a C program pulls
`operator delete` from a `libc.a` member — an omission here was the old
`undefined symbol: operator delete` failure). The multicall is invoked by full
path — it is no longer on `PATH` — exactly like `/sys/tools/rust/bin/rustc`;
`cc`, on `/bin`, is the PATH-accessible C front-end and is equivalent to
`/sys/tools/llvm/bin/llvm clang`.

Expected: `Hello from Motor-native clang!` (twice — raw `llvm clang` and `cc`),
`Hello from Motor-native clang++!`, then Lua prints the square root of 2 —
C and C++ (with working exceptions) compiled and linked by the Motor-native
toolchain, plus a real interpreter.

## Where the port lives (for maintainers)

- Motor's mlibc support is on the `motor-os-rustc` branch (a superset of the
  older `motor` branch): `sysdeps/motor/*` plus small generic hooks (a
  `ThreadJoin` sysdep and the `Tcb::sysdepThreadHandle` field, so `pthread_join`
  waits on the kernel thread handle — which is signaled only *after* C++
  `thread_local` destructors run), the lazy foreign-thread TCB, and the
  `operator delete` stub guard (the last two are needed by the native rustc and
  documented in [build-rustc.md](build-rustc.md)). It also routes mlibc's
  hardcoded `/etc` config paths through `MLIBC_SYSCONFDIR`
  (`options/internal/include/mlibc/sysconfdir.hpp`), which the cross-file sets to
  `/sys/cfg/libc`; see [porting-libc/dirs.md](porting-libc/dirs.md).
- Motor's LLVM support is a short series on `motor-os-rustc` (LLVM 23): the
  `x86_64-unknown-motor` triple (emulated-TLS by default), the Clang `Motor`
  ToolChain (static-PIE link recipe, include paths, the `ld.lld` multicall
  fallback), and a few `lib/Support` portability fixes. rustc consumes this
  same branch as its `src/llvm-project` submodule (see build-rustc.md), so the
  toolchain and the compiler share one LLVM. (`motor-os-next` is a legacy alias
  for the same commit.)
- The design rationale and the milestone-by-milestone build history (M0–M10,
  with every pitfall and its fix) are in
  [docs/porting-libc/](porting-libc/porting-libc-by-fable.md).
