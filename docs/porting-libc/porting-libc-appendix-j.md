# Appendix J — M9, step by step

> **Status: complete, including M9b** (2026-07-04) — the full native
> toolchain works on Motor OS: one-command `clang hello.c -o hello` /
> `clang++ hello.cpp -o hello` (driver spawns the linker), plus
> posix_spawn/waitpid/system() and Lua's os.execute (J.10). The VM gate
> loops flushed out ten real platform gaps, all fixed at the right layer
> (J.5 #12–#16, #18–#19, #21–#22) plus eight LLVM patches (#7–#11, #17,
> #20). Next: M10 (exceptions, upstreaming).

> Part of the Motor OS libc porting guide — main: [porting-libc-by-fable.md](porting-libc-by-fable.md); appendices: [A: M0 toolchain](porting-libc-appendix-a.md) · [B: M1 shim](porting-libc-appendix-b.md) · [C: M2 mlibc](porting-libc-appendix-c.md) · [D: M3 stdio+malloc](porting-libc-appendix-d.md) · [E: M4 filesystem](porting-libc-appendix-e.md) · [F: M5 threads+TLS](porting-libc-appendix-f.md) · [G: M6 sockets](porting-libc-appendix-g.md) · [H: M7 poll + real program](porting-libc-appendix-h.md) · [I: M8 C++ stack](porting-libc-appendix-i.md) · [J: M9 native toolchain](porting-libc-appendix-j.md)

M9 is the native toolchain: **clang + lld running ON Motor OS**, cross-built
against our mlibc + libc++ (static, no-EH — the M8 stack), staged on the
image together with a compile-ready sysroot, compiling and linking a C
program natively in the VM. Everything below is verified against the in-tree
llvm-project (clang 23, branch `motor`) and mlibc + our motor sysdeps —
file:line references throughout.

The headline ground-truth results first, because they de-risk the whole
milestone:

1. **LLVM needs no file-backed mmap anywhere on the compile+link path** —
   every use has a tested read()/in-memory fallback (J.2.1), and our mmap
   sysdep already fails cleanly for fd-backed requests.
2. **The gate needs no subprocess spawning** — `clang -c` runs cc1
   in-process (integrated cc1, the default), and `ld.lld` spawns nothing.
   Fork-less Motor is not an obstacle; one-command `clang hello.c -o hello`
   (driver spawns the linker) is the M9b stretch, not the gate.
3. **clang and lld can ship as ONE static multicall binary** (`llvm`,
   via `LLVM_TOOL_LLVM_DRIVER_BUILD=ON`), invoked as `llvm clang …` /
   `llvm ld.lld …` — halving image cost vs. two binaries, and sidestepping
   motor-fs having no hardlinks/symlinks for the busybox-style trick.

---

## J.1 Deliverables

| # | Piece | Where |
|---|---|---|
| 1 | Cross build dir for native tools (clang+lld, X86-only, multicall) | `~/motorh/llvm-project/build-motor-native` |
| 2 | `llvm` multicall binary (static-PIE, stripped) staged | `img_files/motor-os/bin/llvm` |
| 3 | On-image sysroot: mlibc + C++ headers, crt1.o, all archives, clang resource headers | `img_files/motor-os/usr/{include,lib}` |
| 4 | Driver config file for native use | `img_files/motor-os/etc/x86_64-unknown-motor.cfg` |
| 5 | `hello.c` (+ `hello.cpp` secondary) staged as compile fodder | `img_files/motor-os/usr/src/` |
| 6 | LLVM patch #7 (`getMainExecutable` for `__motor__`) | llvm-project branch `motor` |
| 7 | This appendix updated with pitfalls + final sizes | docs |

## J.2 Ground truth (verified in-tree)

### J.2.1 No file-backed mmap needed — fallbacks exist at every use

Motor has anonymous memory only; our sysdep already encodes that
(`sysdeps/motor/generic/sysdeps.cpp:115`):

- `Sysdeps<VmMap>` returns `ENOSYS` unless `MAP_ANONYMOUS && fd == -1` — so
  any `mmap()` of a file **fails cleanly with errno**, never crashes.

LLVM handles that failure by design:

- **Inputs** (`llvm/lib/Support/MemoryBuffer.cpp:515`): `getOpenFileImpl`
  tries mmap only if `shouldUseMmap(...)`; when the map constructor reports
  an error it **falls through to the malloc+read path**. Sources, headers,
  archives, object files — all fine.
- **Linker output** (`llvm/lib/Support/FileOutputBuffer.cpp:140-150`):
  `createOnDiskBuffer` maps the temp output file read-write, and on failure
  — the comment literally says "mmap(2) can fail if the underlying
  filesystem does not support it" — **falls back to
  `createInMemoryBuffer`**, whose `commit()` writes the buffer out with
  ordinary writes + rename.
- Even better, lld **defaults to not mmapping output**:
  `lld/ELF/Driver.cpp:1501` — `mmapOutputFile = hasFlag(OPT_mmap_output_file,
  OPT_no_mmap_output_file, false)`; `Writer.cpp:2840` only adds `F_mmap`
  when asked.

Nothing to do; the platform property and the library design already agree.

### J.2.2 No subprocess needed for the gate

- `clang -c` runs **cc1 in-process** — integrated cc1 has been the default
  since clang 10 (`-fno-integrated-cc1` to opt out; `Driver.cpp` only sets
  `J.InProcess = false` in special cases, e.g. `-ftime-trace` multi-job).
- `ld.lld` is a leaf process — it spawns nothing.
- Subprocesses only enter with the **one-command driver link**
  (`clang hello.c -o hello` → driver executes ld.lld):
  `llvm/lib/Support/Unix/Program.inc:187` uses `posix_spawn` when
  `HAVE_POSIX_SPAWN`, else `fork()+execve`. mlibc *links* `posix_spawn`
  (`options/posix/generic/spawn.cpp`, fork-based), so the configure check
  passes and the build succeeds — but calling it on Motor hits the missing
  `sys_fork` sysdep at runtime. **Gate is therefore two commands**
  (compile, then link); driver-spawned linking is the M9b stretch: add
  `moto_rt_spawn`/`moto_rt_wait` to the shim (Motor natively spawns without
  fork — the shell does it) and give `Program.inc` a `__motor__` path.
  That same stretch unlocks `system()`, `popen()`, and Lua's `os.execute`.

### J.2.3 One multicall binary carries both tools

- `clang/tools/driver/CMakeLists.txt:54` and `lld/tools/lld/CMakeLists.txt:10`
  both declare `GENERATE_DRIVER` — with `LLVM_TOOL_LLVM_DRIVER_BUILD=ON`
  they compile into the single `llvm` binary.
- Dispatch (`llvm/tools/llvm-driver/llvm-driver.cpp`): first by `argv[0]`
  stem, then — key for Motor, which has no symlinks/hardlinks to alias the
  binary — **by subcommand**: `if (Is("llvm") || …) return findTool(Argc-1,
  Argv+1, …)`. So `llvm clang -c x.c` and `llvm ld.lld …` work as-is.

### J.2.4 Cross-compiling LLVM: native tblgen + CMake identity

- Host tablegens already exist from the host build:
  `build/bin/{llvm-tblgen,clang-tblgen,llvm-min-tblgen}` — consumed via
  `LLVM_NATIVE_TOOL_DIR` (`llvm/cmake/modules/TableGen.cmake:193`).
- **`CMAKE_SYSTEM_NAME=Linux`, not `Generic`** (deliberate, unlike the M8
  runtimes build): LLVM proper selects `lib/Support/Unix/*.inc` via
  `LLVM_ON_UNIX`, which follows CMake's `UNIX` — false for `Generic`, and
  there is no third implementation. Setting `Linux` at the *CMake* level is
  safe because the *compiler* level stays honest: the motor triple defines
  no `__linux__`, so source-level Linuxisms (`/proc`, epoll, …) stay
  compiled out, while feature checks (`check_symbol_exists`) actually
  link against mlibc and answer truthfully. Set
  `LLVM_HOST_TRIPLE=x86_64-unknown-motor` explicitly (cache var,
  `llvm/cmake/config-ix.cmake:535` — the inferred default would be wrong
  when cross-compiling).
- **Do NOT set `CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY`** this time
  (again unlike M8 runtimes): LLVM's ~100 `HAVE_*` probes are *link* checks
  and we now have a complete libc to link against — degrading them to
  compile-only would answer some of them wrong (e.g. `HAVE_MALLINFO2`).
  Full try-compile links work since M8 (crt1 + archives via the cfg +
  standard-libraries setting, J.4).

### J.2.5 `getMainExecutable` has no Motor branch — LLVM patch #7

`llvm/lib/Support/Unix/Path.inc:194` is an OS ifdef ladder (`__APPLE__`,
BSDs, `__linux__`/`__managarm__` via `/proc/self/exe`, Solaris, MVS,
`HAVE_DLOPEN`/dladdr) with **no branch our triple hits usefully** — clang
would get an empty string and lose its **resource directory** (the
compiler-owned headers: `stddef.h`, `stdarg.h`, intrinsics), breaking every
compile. Patch #7: add `defined(__motor__)` to the OpenBSD/Haiku branch,
which resolves via `getprogpath(exe_path, argv0)` (argv[0], absolute or
PATH search) — correct on Motor where the shell passes the full
`/bin/llvm`. Belt and braces: the image cfg also pins
`-resource-dir=/usr/lib/clang/23` (J.6), making the answer
argv[0]-independent.

### J.2.6 Stack, signals, CPU count, rlimits — all survivable

- **cc1's heavy work runs on a worker thread with an explicit 8 MB stack**
  (`clang/lib/Frontend/CompilerInstance.cpp:1312`,
  `RunSafelyOnThread(…, DesiredStackSize)`), created via pthreads with
  `pthread_attr_setstacksize` — our M5 `PrepareStack` honors sizes. Motor's
  1 MB main-thread stack is therefore *not* a blocker for compiling.
  `cc1_main.cpp:95` also tries `getrlimit/setrlimit(RLIMIT_STACK)` — check
  at implementation time that mlibc's ENOSYS path there is quiet (expect at
  worst a one-line warning).
- **Signals**: `InitLLVM` installs crash handlers via `sigaction` (M7
  records them; they never fire asynchronously — a crash means the kernel
  kills the process without LLVM's pretty stack trace, acceptable).
  `Signals.inc:266` guards `sigaltstack` behind `HAVE_SIGALTSTACK`; mlibc
  defines the symbol (`options/posix/generic/posix_signal.cpp:111`,
  `sysdep_or_enosys`), so it links and fails softly at runtime.
- **CPU count**: `std::thread::hardware_concurrency` → mlibc
  `sysconf(_SC_NPROCESSORS_ONLN)` → **red banner + fallback 1**
  (`options/posix/generic/unistd.cpp:981`). Consequence: lld runs
  single-threaded and the banner is noisy. Optional nicety (small): a
  `Sysconf` sysdep backed by a new `moto_rt_num_cpus` shim export — decide
  during implementation; not gating.
- **Stub archives** (`libdl.a`, `libpthread.a`, `librt.a`, `libm.a`, …) are
  already installed in the sysroot, so CMake's reflexive `-ldl -lpthread`
  resolve trivially.

### J.2.7 Size and memory budget (measured / estimated)

Measured now: host `clang-23` binary 168 MB and `lld` 94 MB — but that's
all-targets with debug info. The image build is X86-only, `Release`,
stripped, single multicall binary: **estimate 60–110 MB**. Staged sysroot:
`usr/include` 18 MB (12 MB of that is `c++/v1` — stage it; native C++
compiles become possible), `libc.a` 18 MB unstripped (**strip-debug the
staged archives**; expect ~3–5 MB), shim 2.1 MB, libc++ 2.1 MB + abi 0.5 MB,
builtins 0.2 MB, clang resource headers ~3 MB.

**Open questions for the user (please confirm before staging):**
1. Image budget: is **+80–130 MB** on the flash image acceptable?
2. VM RAM: cc1 on hello-sized inputs wants tens of MB, comfortable at
   **≥512 MB** for real files — is the test VM sized for that?

## J.3 Plan of record

1. Apply LLVM patch #7 (`getMainExecutable`, J.2.5).
2. Configure + build `build-motor-native` (J.4): `LLVM_ENABLE_PROJECTS=
   "clang;lld"`, multicall driver ON, X86 only, everything optional OFF.
3. Strip and stage `bin/llvm`; stage the on-image sysroot under
   `img_files/motor-os/usr/` and the cfg under `img_files/motor-os/etc/`
   (J.6). Note this **breaks the "never had /usr on the image" seal** the
   same way M7 added `/etc` — same mechanism, `img_files` passthrough.
4. Gate test in the VM (J.7): two commands + run the output.
5. Record pitfalls (there WILL be a handful of `#ifdef __linux__` /
   configure potholes only the actual build reveals — M8 predicted 2
   locale patches and found 6 total; same expectation here).
6. M9b stretch, separate step: shim spawn/wait + `Program.inc` Motor path →
   one-command `clang hello.c -o hello`, plus `system()`/`os.execute` for
   free.

## J.4 Host build recipe

```sh
LLVM=~/motorh/llvm-project
B=$LLVM/build/bin
SYSROOT=~/motorh/motor-sysroot

cmake -S $LLVM/llvm -B $LLVM/build-motor-native -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=Linux \
  -DCMAKE_C_COMPILER=$B/clang \
  -DCMAKE_CXX_COMPILER=$B/clang++ \
  -DCMAKE_C_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_CXX_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_C_FLAGS="-isystem $SYSROOT/usr/include -D_GNU_SOURCE -D_DEFAULT_SOURCE" \
  -DCMAKE_CXX_FLAGS="-nostdinc++ -isystem $SYSROOT/usr/include/c++/v1 -isystem $SYSROOT/usr/include -D_GNU_SOURCE -D_DEFAULT_SOURCE" \
  -DCMAKE_C_STANDARD_LIBRARIES="$SYSROOT/usr/lib/crt1.o -Wl,--start-group -lc -lmoto_rt_cabi -lclang_rt.builtins-x86_64 -Wl,--end-group" \
  -DCMAKE_CXX_STANDARD_LIBRARIES="$SYSROOT/usr/lib/crt1.o -Wl,--start-group -lc++ -lc++abi -lc -lmoto_rt_cabi -lclang_rt.builtins-x86_64 -Wl,--end-group" \
  -DCMAKE_EXE_LINKER_FLAGS="-L$SYSROOT/usr/lib" \
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
  -DCLANG_CONFIG_FILE_SYSTEM_DIR=/etc

ninja -C $LLVM/build-motor-native llvm-driver
```

Notes, in the order they'll bite:

- The auto-loaded `$B/x86_64-unknown-motor.cfg` (appendix A.5) still
  supplies `-fuse-ld=lld -static-pie -nostdlib -Wl,-e,motor_start …` for
  every link, including CMake's try-compile probes; the
  `CMAKE_*_STANDARD_LIBRARIES` values above complete those links so the
  `HAVE_*` probes answer truthfully (J.2.4).
- **`CMAKE_TRY_COMPILE_PLATFORM_VARIABLES` is load-bearing** (found the
  hard way): `CMAKE_*_STANDARD_LIBRARIES` is NOT forwarded into
  `try_compile` sub-projects by default, so every `check_symbol_exists`
  probe linked without crt1/libc and **failed** — `getpagesize`,
  `getrusage`, `sysconf`, … all wrongly "not found" (symptom: `Process.inc`
  hits `#error Cannot get the page size`; proof in
  `CMakeConfigureLog.yaml`: the probe link line ends `…o -o cmTC_xxx -lm`
  with no libc). Forwarding the two variables fixes the whole class. The
  wrong results are *cached* — wipe the build dir when adding the flag.
- Archive order inside `--start-group` doesn't matter (group scan), but
  the shim **must** stay ahead of `libc++abi` for the usual
  `__cxa_thread_atexit` reason (I.4) — it is, via group semantics.
- `Release`, not `MinSizeRel`: native compile speed in the VM beats ~10%
  binary size; and never `Debug` — a debug clang is ~1.5 GB and unusably
  slow in a VM. The staged binary is a **stripped Release** build; the
  unstripped Release binary stays host-side for `addr2line` against kernel
  backtraces (function-level symbolization from `.symtab`, same as m2–m8).
- `CLANG_ENABLE_ARCMT` is gone (ARCMigrate removed upstream); don't pass it.
- `ninja llvm-driver` builds only the multicall binary and its
  dependencies; expect a full LLVM+clang+lld compile (~30–60 min).
- Strip before staging: `$B/llvm-strip -o /tmp/llvm.stripped
  build-motor-native/bin/llvm` (keep the unstripped one for addr2line
  against VM backtraces — proven invaluable at M8).
- Audit as always: no `PT_TLS`, RELATIVE-only relocs, **and** (M8 Act III
  lesson) key ABI globals not demoted to `.bss`.

### Build log (2026-07-04) — host build complete, staged, awaiting VM gate

Configure passed first-shot after the try-compile-forwarding fix; the build
needed patches #8–#11 (all trivial ifdef/probe fixes, none in code that
runs for our targets except bit.h). Final numbers: `llvm` multicall binary
**138 MB unstripped / 103 MB stripped** (X86-only, Release, no-EH/no-RTTI,
statically linked against mlibc+libc++); staged sysroot **34 MB**
(headers 18 MB + stripped archives + clang resource headers); total image
cost **~137 MB** — at the top of the estimate, as accepted. Audit clean:
static-PIE, entry `motor_start`, **no PT_TLS, 0 non-RELATIVE relocs,
`stdin/stdout/stderr` in `.data`** (the M8 Act III check).

Bonus discovered at link time: the multicall binary carries the whole
LLVM binutils suite, not just clang+lld — `llvm ar/nm/objdump/objcopy/
strip/readelf/addr2line/symbolizer/cxxfilt/size/ranlib/dwp/…` and
`llvm clang++` all dispatch (see `LLVMDriverTools.def` in the build dir).
Motor gets a complete native toolchain, not two tools.

## J.5 Expected patches (running list — fill in as found)

| # | Repo | What | Status |
|---|---|---|---|
| 7 | llvm | `Path.inc getMainExecutable`: `__motor__` → `getprogpath(argv0)` branch — **two hunks**: the use-site ladder AND the `getprogpath` definition guard (`Path.inc:128`) | applied |
| 8 | llvm | `ADT/bit.h` endianness ladder: `__motor__` → `<endian.h>` (mlibc ships the glibc-style header; the unknown-OS fallback wants BSD `<machine/endian.h>`) | applied |
| 9 | llvm | `Path.inc is_local_impl`: `__motor__` → `return true` (no remote filesystems; the fallback wants BSD `statvfs.f_flags & MNT_LOCAL`) | applied |
| 10 | llvm | `cmake/config-ix.cmake`: motor compiler targets take the *probing* header branch instead of the hardcoded assume-Linux set — the predicted Linux-masquerade leak (J.2.4) materialized as `HAVE_SYS_IOCTL_H 1` with no probe; mlibc has no `sys/ioctl.h` (it's in mlibc's glibc option, deliberately not enabled for Motor — no ioctl-able devices) | applied |
| 11 | llvm | `lld/MachO/Driver.cpp` file-preload: `__motor__` joins the `_WIN32` touch-pages branch (the other branch calls `madvise(MADV_WILLNEED)`; mlibc has neither) — MachO port is dead code for us but compiles into the multicall binary | applied |
| 12 | mlibc | motor sysdeps: `Sigaltstack`/`GetRlimit`/`SetRlimit` return quiet ENOSYS, `GetRusage` returns zeroed success — first VM run confirmed J.2.6's prediction was half right: the functions *link* fine, but `sysdep_or_enosys` prints a scary `__ensure_warn` per call, and clang's startup hits sigaltstack + getrlimit **every run**, from two threads at once (interleaved garble on the console). Platform properties deserve implemented-as-ENOSYS sysdeps, not missing ones. GetRusage succeeds with zeros because LLVM's `getRUsageTimes` uses the struct without checking the return | applied |
| 13 | mlibc | motor `Stat` sysdep: `fstat` on a terminal fd synthesizes a character-device stat (`S_IFCHR|0620`) instead of failing — second VM run exited 1 **with no output at all**: clang's `FixupStandardFileDescriptors` (`clang/tools/driver/driver.cpp:249`) fstats fds 0/1/2 and returns a hard, diagnostic-free error if fstat fails with anything ≠ EBADF (`Unix/Process.inc:220`); the EBADF path is no better on Motor (it opens `/dev/null`, which doesn't exist). POSIX software probes std fds constantly — terminal fds must fstat successfully. Known residual: a *piped* std fd (not terminal, not file) would still fail — no pipe detection in the VDSO fd API yet | applied |
| 14 | mlibc | motor sysdeps: `Pread`/`Pwrite` emulated via seek + I/O + seek-back — fourth VM run: clang reads its own config file through `readNativeFileSlice` → `pread`, a syscall nothing in m2–m8 ever exercised (stdio never does positional I/O). The emulation races if two threads do positional I/O on the *same* fd (LLVM opens one fd per file — fine); a real `read_at` in the VDSO/runtime API is a wishlist item | applied |
| 15 | motor-os + mlibc | **Real inode numbers — FileAttr v2** (fifth VM run, the biggest find of the milestone): clang's FileManager identifies files by `(st_dev, st_ino)`; Motor reported `(1, 1)` for everything (a documented M4 landmine), so cc1 treated `stdio.h` as the already-loaded hello.c and compiled the program against itself (`#include nested too deeply`, `main` redefined "in stdio.h" — `cat` showed the real header, acquitting the fs). Fix: `FileAttr` v2 carries the full u128 motor-fs `EntryId` (`{block_no: u64, generation: u64}`); the VDSO fills it at its single `metadata()` conversion point (covers stat, fstat, readdir) and **version-gates all three struct writes** — `FileAttr::new()`/`DirEntry::new()` stamp the caller's ABI version, so v1 binaries (e.g. external Rust-std programs) get the frozen 80/368-byte v1 layouts (mirror structs in `rt_fs.rs`, compile-time size asserts on both sides). mlibc maps `st_dev=1`, `st_ino=block_no+1` (block_no has classic inode semantics: unique among live entries, stable, reused after deletion; +1 keeps root≠0; generation has no stat slot), ttys get `st_dev=2`. `d_ino` filled too. Shim is now v7 (96/384-byte structs in `moto_rt.h`) | applied |
| 16 | mlibc | `Sysconf` sysdep: `_SC_NPROCESSORS_ONLN/_CONF` from the shim's existing `moto_rt_num_cpus`; everything else returns EINVAL, falling through to mlibc's generic per-key defaults. lld's `hardware_concurrency` queries had flooded the link step with mlibc's red fallback banner (and pinned lld to 1 thread); now it's silent and parallel | applied |
| 17 | llvm | **Motor ToolChain include hooks** (`clang/lib/Driver/ToolChains/Motor.{h,cpp}`): `AddClangSystemIncludeArgs` (resource headers + `<sysroot>/usr/include`) and `AddClangCXXStdlibIncludeArgs` (`<sysroot>/usr/include/c++/v1`), Fuchsia-style. Found via the native hello.cpp gate: config-file args precede command-line args, so the cfg's `-isystem /usr/include` outran the command's `-isystem …/c++/v1` — and libc++'s `__mbstate_t.h` resolves via `#include_next <wchar.h>`, which requires the C dir to come AFTER `c++/v1`. Driver-added dirs always follow user `-isystem`s and order C++-before-C, so native `llvm clang++ -c hello.cpp` now needs no include flags at all; the cfg's `-isystem` line is gone. Side benefit: kills the Generic_GCC fallback that leaked host `/usr/include` + `/usr/local/include` into cross compiles. Host cross-compiles can now use `--sysroot=$SYSROOT` instead of explicit `-isystem` pairs (A.5 recipes still work — user flags take precedence) | applied |
| 18 | mlibc | **`PosixSpawn` sysdep tag** + spawn-native paths in `posix_spawn()`/`system()` + real `Waitpid` sysdep (M9b, see J.10) | applied |
| 19 | motor-os | **shim v8**: `moto_rt_spawn`/`moto_rt_waitpid` over `moto_rt::process`, pseudo-pid table (M9b, see J.10) | applied |
| 20 | llvm | **`motor::Linker::ConstructJob`**: full static-PIE link recipe in the toolchain + multicall `ld.lld` subcommand fallback → one-command driver links (M9b, see J.10) | applied |
| 21 | mlibc + img | **`P_tmpdir` → `/sys/tmp`** — the one-command link died with "unable to make temporary file": the driver stages cc1's output in a temp .o, and LLVM's `system_temp_directory` resolves `TMPDIR` → `P_tmpdir` → `/tmp`, which Motor doesn't have. Two-act fix: first patched `P_tmpdir` into mlibc's `stdio.h` — **which didn't work**: mlibc ALREADY defines it in `bits/posix/posix_stdio.h:19` (missed by the first grep), included later, silently shadowing the new define (system headers suppress macro-redefinition warnings; found via `clang -E -dD`). Real fix at the real definition: `posix_stdio.h` now guards on `__motor__`. Verified by `strings` on the staged binary — worth keeping as an audit: a baked-in path constant you can't find in the binary means your #define lost a shadowing war. The image also ships `/sys/tmp` (a README materializes it; manual `mkdir` per boot retired) | applied |
| 22 | motor-os + mlibc | **`system()` went interactive** — the instrumented m9 run was a beauty: markers stopped at t3, "extra" rush prompts appeared, and typing `exit` resumed the test (t5's expected status 7 arrived as the user's exit status 0 — proving spawn/wait/status all work). Root cause: `/bin/sh` on the image is a login **stub script** whose body is `/bin/rush -i /sys/cfg/rush.cfg` — it discards all arguments, so `sh -c "cmd"` launched an interactive shell on the inherited console and `system()` blocked in waitpid until someone typed `exit`. Fix pair: mlibc's spawn-based `system()` targets **`/bin/rush`** directly on `__motor__` (the login stub stays untouched for boot), and rush's `-c` mode now skips the POSIX `--` option terminator that libc passes (`sh -c -- cmd`). Deferred: making `/bin/sh` itself a real argument-forwarding shell entry is a Motor shell-design question | applied |
| — | llvm | unknown `#ifdef __linux__`/configure potholes in `lib/Support` | expect 1–3 more |

## J.6 Image staging layout

**`img_files/motor-os/` maps to the image ROOT, not `/sys`** — learned in
the third VM run: M7's `etc/resolv.conf` already landed at `/etc`, so the
sysroot lives at `/usr` and the cfg at `/etc/x86_64-unknown-motor.cfg`
(`/sys` is Motor's own system tree: cfg, logs, sys-init, tmp, …). The
first staged binary baked in `/sys/usr` + `/sys/etc` and clang reported
`no such file or directory` — fixed by rebaking `DEFAULT_SYSROOT=`
(empty; the cfg drives all paths) and `CLANG_CONFIG_FILE_SYSTEM_DIR=/etc`.
`/sys/tmp` remains the scratch area for outputs.

```
img_files/motor-os/
  bin/llvm                      # multicall clang+lld, stripped, static-PIE
  etc/x86_64-unknown-motor.cfg  # driver config, loaded via CLANG_CONFIG_FILE_SYSTEM_DIR=/etc
  usr/include/...               # mlibc headers + c++/v1 (18 MB)
  usr/lib/crt1.o
  usr/lib/libc.a                # strip-debug'd copies
  usr/lib/libmoto_rt_cabi.a
  usr/lib/libclang_rt.builtins-x86_64.a
  usr/lib/libc++.a  usr/lib/libc++abi.a
  usr/lib/lib{dl,m,pthread,rt,resolv,util,ssp,ssp_nonshared}.a   # empty stubs
  usr/lib/clang/23/include/...  # clang resource headers (~3 MB)
  usr/src/hello.c  usr/src/hello.cpp
```

`/etc/x86_64-unknown-motor.cfg` (the **image** cfg — full recipe, so
that once M9b spawn lands, plain `clang hello.c -o hello` just works; until
then only its compile-side flags matter):

```
-resource-dir /usr/lib/clang/23
-isystem /usr/include
-fuse-ld=lld -static-pie -nostdlib
-Wl,-e,motor_start -Wl,--pack-dyn-relocs=none -Wl,-z,noexecstack
-L/usr/lib
```

(Link libs can't live in a cfg without tripping "unused during compilation"
warnings on `-c`; the gate passes them explicitly, J.7.)

## J.7 Gate test (user runs in VM)

```sh
mkdir /sys/tmp    # fresh boots don't have it (m7/m8 mkdir'd it themselves)
llvm clang -c /usr/src/hello.c -o /sys/tmp/hello.o
llvm ld.lld -m elf_x86_64 -static -pie --no-dynamic-linker -z text \
  -e motor_start --pack-dyn-relocs=none -z noexecstack --eh-frame-hdr \
  /sys/tmp/hello.o /usr/lib/crt1.o \
  --start-group /usr/lib/libc.a /usr/lib/libmoto_rt_cabi.a \
  /usr/lib/libclang_rt.builtins-x86_64.a --end-group \
  -o /sys/tmp/hello
/sys/tmp/hello        # → "Hello from Motor-native clang!"
```

(The linker flag set is exactly what the host driver emits for
`-static-pie` on our triple — captured via `clang -###`.)

Secondary gates, in ascending ambition:
1. `hello.cpp` the same way (add `libc++.a` + `libc++abi.a` before `libc.a`
   in the group; shim before abi).
2. **Self-check**: natively compile `m2.c` (stage it) and run the resulting
   binary's whole suite — the compiler compiled *by* the port validating
   the libc *of* the port.
3. (After M9b spawn) `clang /usr/src/hello.c -o /sys/tmp/hello` in one
   command, and Lua's `os.execute` coming alive.

## J.8 Deliberate gaps (document, defer)

- **One-command driver link / any subprocess** — M9b (shim spawn/wait +
  `Program.inc`); everything else in M9 works without it.
- **Parallel lld** — pends the CPU-count sysdep (J.5); single-threaded lld
  is correct, just slower.
- **`-ftime-report`/`getrusage` fidelity** — zeros are fine.
- **LTO** — untested; nothing known to block ThinLTO except CPU count.
- **Crash prettiness** — no async signals ⇒ no in-process backtrace on
  crash; the kernel's `print_backtrace` + host `addr2line` against the
  unstripped binary is the debug story (M8-proven).
- **Compile perf** — first native compile pulls hundreds of header files
  through sys-io; if it's slow, that's motor-fs/sys-io tuning territory,
  not a toolchain defect. Measure, record, move on.

## J.9 Exit criteria

- [x] `llvm clang -c` + `llvm ld.lld` + run: hello.c end-to-end in the VM
      (2026-07-04; the link step initially drowned the console in mlibc's
      NPROCESSORS fallback banner — fixed by patch #16).
- [x] hello.cpp end-to-end (C++ native compile) — after patch #17, with no
      include flags at all: `llvm clang++ -fno-exceptions -c hello.cpp`.
- [ ] (Optional, ceremonial) Native-compiled `m2` passes its suite in the
      VM — `m2.c` is staged at `/usr/src/m2.c`; compile+link per J.7 and
      run: the ported compiler validating the libc it is built on.
- [x] `llvm` binary audit: no PT_TLS, RELATIVE-only relocs, stdio globals
      in `.data` (M8 Act III check).
- [x] m2–m8 + `lua m7.lua` still pass — NOT a formality in the end: the
      libc gained six new sysdeps and the v2-inode stat/readdir plumbing
      during the VM gate loop, so this sweep validated real changes.
- [x] Record: `llvm` multicall binary **103 MB stripped** (138 MB
      unstripped kept host-side for addr2line); staged sysroot **34 MB**
      (headers 18 MB + stripped archives + resource headers); native
      hello.c compile wall time: not timed (subjectively instant);
      patches: **11 total** (llvm #7–#11 + #17, mlibc/motor #12–#16) vs.
      the "one pre-identified + 1–3 more" estimate — the extra ones were
      all *runtime* libc gaps, which the estimate didn't cover.

## J.10 M9b — process spawning + one-command driver links

> **Status: complete** (2026-07-04) — `m9` passes (posix_spawn / waitpid /
> system, t1–t5), one-command `clang hello.c -o hello` and
> `clang++ hello.cpp -o hello` compile+link+run natively on the image
> (driver-spawned linking via the multicall `ld.lld` subcommand), and Lua's
> `os.execute` works. Two extra potholes on the way: `P_tmpdir`
> (patch #21 — a macro shadowing war) and the `/bin/sh` login stub
> swallowing `-c` (patch #22). m2–m8 + lua keep passing throughout.

Motor spawns processes natively without fork (the shell always has), so
M9b is plumbing, not kernel work — Motor's `moto_rt::process::{spawn,wait}`
API (`proc_spawn`/`proc_wait` in the VDSO vtable) already does everything
POSIX needs:

- **Shim v8** (`moto_rt_spawn` / `moto_rt_waitpid`): children are tracked
  in a pseudo-pid table (pids >= 0x40000000, same pattern as the
  pseudo-socket fds) mapping to Motor's u64 process handles. The child
  inherits stdio (`STDIO_INHERIT`) and cwd. Two Motor properties leak
  through, both documented in `moto_rt.h`: **argv[0] is always the
  resolved executable path** (the VDSO's `run_elf` composes argv as
  `[exe] ++ args` — a spawner cannot lie about argv[0], which kills the
  busybox-symlink trick and motivated the multicall subcommand dispatch),
  and `#!` scripts spawn fine (`run_script` prepends the interpreter).
- **mlibc patch #18 — a `PosixSpawn` sysdep tag** (upstream-worthy for
  fork-less platforms generally: Fuchsia and WASI have the same shape).
  `posix_spawn()` uses the sysdep when implemented instead of musl's
  fork+exec dance; the sysdep gets `have_file_actions`/`have_attr` flags
  and returns ENOSYS for requests it can't honor (Motor: any non-trivial
  file_actions/attrs — no fd redirection control yet, children inherit
  stdio). `system()` gained a spawn-based path (`/bin/sh -c` via
  posix_spawn + waitpid, no SIGINT/SIGQUIT juggling — Motor has no async
  signals to juggle), and `system(NULL)` now answers 1. `waitpid()` is a
  real sysdep: blocking wait on a specific pseudo-pid, WIFEXITED encoding
  `(status & 0xff) << 8`, ECHILD for unknown pids, no
  WNOHANG/process-groups (EINVAL).
- **LLVM patch #20 — `motor::Linker::ConstructJob`** (Fuchsia-style,
  replacing the inherited gnutools linker): owns the full static-PIE
  recipe — `-static -pie --no-dynamic-linker -z text -e motor_start
  --pack-dyn-relocs=none -z noexecstack --eh-frame-hdr`, `crt1.o`,
  `--start-group -lc -lmoto_rt_cabi -lclang_rt.builtins-x86_64
  --end-group` (+ `-lc++ -lc++abi` for the clang++ driver), honoring
  `-nostdlib`/`-nostartfiles`/`-nodefaultlibs` so every explicit recipe
  from appendices A–I keeps working. **Linker discovery**: prefer a real
  `ld.lld` binary if one exists next to the driver (host cross builds);
  otherwise re-invoke the running multicall binary with the `ld.lld`
  subcommand (`/bin/llvm ld.lld …`) — correct on the image because
  argv[0]-dispatch is unavailable (see above) but subcommand dispatch
  isn't.
- **Image cfg shrank to two lines**: `-resource-dir /usr/lib/clang/23`
  (the binary lives in /bin, so the relative default would be
  /lib/clang/23) and `-fno-exceptions` (until M10: no-EH libc++abi has no
  `__gxx_personality_v0`, so exception-enabled C++ wouldn't link). All
  include paths and link flags come from the toolchain now.

Host-side validation (before staging): one-command
`clang --no-default-config --target=x86_64-unknown-motor --sysroot=$SYSROOT
hello.c -o hello` and the clang++ equivalent both compile+link via the
driver-spawned host ld.lld; audits clean (static-PIE, entry motor_start,
no PT_TLS, RELATIVE-only relocs). `--no-default-config` is needed on the
HOST only because the host cfg still carries `-nostdlib` for the
appendix-A.5 explicit recipes; slimming it is deferred until M9/M9b fully
settle.

### J.10.1 VM gate (user runs)

```sh
m9                                    # posix_spawn + waitpid + system tests
clang /usr/src/hello.c -o /sys/tmp/hello && /sys/tmp/hello
clang++ /usr/src/hello.cpp -o /sys/tmp/hellocpp && /sys/tmp/hellocpp
lua -e 'print(os.execute("/bin/echo os.execute works"))'
```

(`clang`/`clang++` here are `llvm clang` / `llvm clang++` — or add tiny
wrapper scripts later.) Regression: m2–m8 + `lua m7.lua` (libc grew the
spawn machinery under everything).

### J.10.2 Deliberate gaps

- `posix_spawn` file_actions/attrs → ENOSYS (no fd redirection control in
  the spawn path yet; needs pipe fds + a dup2-ish story — pends the
  VDSO/pipes investigation).
- `popen()` untouched (fork-based; needs pipes).
- `waitpid(-1)` / process groups / WNOHANG: ECHILD / EINVAL.
- Exit statuses: only the low 8 bits survive (WIFEXITED encoding); Motor's
  full i32 exit codes are truncated like everywhere else in POSIX.
