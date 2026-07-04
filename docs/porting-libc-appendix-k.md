# Appendix K — M10, step by step

> **Status: functionally complete, VM-verified** (2026-07-04) — a final
> regression sweep (hello.c/.cpp, m8, m9) is the only open item.
> M10 gives Motor OS real C++ exceptions: LLVM libunwind
> cross-built for `x86_64-unknown-motor`, libc++abi/libc++ rebuilt with
> EH on, `throw` enabled by default for native `clang++` on the image.
> The research prediction held: **every hard prerequisite already
> existed** — our static-PIE links already carry `PT_PHDR` +
> `PT_GNU_EH_FRAME`, and mlibc's `dl_iterate_phdr` already works in
> static binaries (running at every program start since M2) — so **zero
> mlibc patches and zero libunwind source patches** were needed. One
> LLVM driver patch (#23), one runtimes rebuild, one config override
> (`_LIBUNWIND_USE_DLADDR=0`). Host-side everything is verified (patch
> #23 driver link + `-Wl,-y` shim-wins check, m8 EH-archive relink,
> reloc/PT_TLS audits). **VM gate (2026-07-04): exceptions fully work —
> throw/catch, unwinding, library throws, `dynamic_cast`, cross-thread
> `exception_ptr` all pass.** The gate flushed out two bugs, both fixed:
> t9 was a test bug (over-strict backtrace count vs. clang's tail-call +
> Motor's no-`.eh_frame`-above-`main`), and **t8 exposed a real,
> pre-existing Motor concurrency bug — `pthread_join` returned before the
> C++ `thread_local` destructors ran** — fixed at the mlibc layer by
> routing join through the kernel handle (patch #24, K.5.1). **Both fixes
> confirmed on the VM: `m10` (cross) and native `llvm clang++ m10.cpp`
> both pass, the latter consistently across repeated runs — the race is
> gone.** The native `llvm` was relinked against the patch-#24 libc for a
> coherent image. Upstreaming is scoped separately as **M10b** (K.9).

Read [the master guide](porting-libc-by-fable.md) §5.1 and §6 first.
Appendix I (M8, no-EH C++ stack) is the direct predecessor — K reuses its
build machinery and its hazard list. Appendix J (M9/M9b) defines the native
toolchain this milestone upgrades.

## K.1 Scope & deliverables

In scope (the M10 gate):

1. `libunwind.a` cross-built for Motor, installed in the host sysroot and
   staged on the image (`/usr/lib/libunwind.a`).
2. `libc++abi.a` + `libc++.a` rebuilt with `*_ENABLE_EXCEPTIONS=ON` and
   `LIBCXXABI_USE_LLVM_UNWINDER=ON` (same `build-motor-cxx` tree, wiped and
   reconfigured).
3. LLVM patch #23: `motor::Linker::ConstructJob` adds `-lunwind` to the
   link group — and fixes the group order so the shim's
   `__cxa_thread_atexit` wins over libc++abi's fallback (a latent M9 bug
   found during this research; see K.2.6).
4. Image cfg `/etc/x86_64-unknown-motor.cfg` drops `-fno-exceptions`:
   native `clang++` compiles with exceptions on by default.
5. Gate test `src/tests/libc/m10.cpp` — cross-built to `/bin/m10` AND
   compiled natively on Motor from `/usr/src/m10.cpp`.

Out of scope (deliberate, see K.10): popen/pipes, `posix_spawn`
file_actions, `-funwind-tables` for mlibc itself (backtrace quality, not
correctness), sjlj/EHABI anything, `/bin/sh` redesign. Upstreaming is
M10b — planned in K.9, executed with the user (needs his GitHub identity).

## K.2 Ground truth (verified in-tree, 2026-07-04)

### K.2.1 The binaries and the loader are already EH-ready

`llvm-readelf -l` on the staged `bin/m8` (built at M8, before any M10
work):

```
PHDR           0x000040 ... R    — present (mlibc derives the load base from it)
LOAD           0x000000 ... R    — file offset 0: ELF header + phdrs are mapped
GNU_EH_FRAME   0x04dc6c ... R    — .eh_frame_hdr, from lld --eh-frame-hdr
```

`.eh_frame` + `.eh_frame_hdr` land in the first (read-only) `PT_LOAD`.
`--eh-frame-hdr` has been in every link since M0 (it's in the M9b driver
recipe too, patch #20). Nothing about the kernel, the VDSO loader, or the
linker recipe changes for M10.

### K.2.2 mlibc's `dl_iterate_phdr` already works statically

The unwinder finds `.eh_frame` via `dl_iterate_phdr` (K.2.3). Chain, all
verified in the mlibc tree and in the staged `libc.a` (`llvm-nm` shows
`T __dlapi_iterate_phdr`, `T dl_iterate_phdr`):

- `options/elf/generic/phdr.cpp`: `dl_iterate_phdr` →
  `__dlapi_iterate_phdr` (options/rtld/generic/main.cpp:1083).
- Static-build registration happens in `__dlapi_enter`, which our
  `__mlibc_entry` (sysdeps/motor/generic/entry.cpp) calls at **every**
  program start: under `MLIBC_STATIC_BUILD` it reads the lld-provided
  `__ehdr_start`, computes `phdr_pointer = __ehdr_start + e_phoff`
  (main.cpp:605), and `injectStaticObject` registers the executable.
- `_fetchFromPhdrs` (linker.cpp:517) derives `baseAddress` from
  **PT_PHDR** (`phdr_pointer - phdr->p_vaddr`) — present in our links
  (K.2.1). `dlpi_addr` is therefore the correct PIE load base.
- m8/m9 run this path on every start (an `__ensure(phdr_pointer)` would
  have tripped long ago) — it is battle-tested, just never *queried*.

### K.2.3 libunwind picks the right platform branch untouched

`libunwind/src/config.h`: no `__APPLE__`/`_WIN32`/`__BIONIC__`/baremetal
macro matches `x86_64-unknown-motor`, so the default branch fires:

```c
// Assume an ELF system with a dl_iterate_phdr function.
#define _LIBUNWIND_USE_DL_ITERATE_PHDR 1
#define _LIBUNWIND_SUPPORT_DWARF_UNWIND 1
#define _LIBUNWIND_SUPPORT_DWARF_INDEX 1
```

`AddressSpace.hpp`'s `findUnwindSectionsByPhdr` is generic ELF: scan
`PT_LOAD`s for the target PC, then find `PT_GNU_EH_FRAME`, parse the
binary-search index. Its only libc needs:

- `#include <link.h>` + `ElfW()` — mlibc ships it (options/elf).
- `dl_iterate_phdr` — K.2.2.
- `RWMutex.hpp` → `pthread_rwlock_{rdlock,wrlock,unlock}` +
  `PTHREAD_RWLOCK_INITIALIZER` — all `T` in our `libc.a` (M5 pthreads).
- Register save/restore is pure asm (`UnwindRegistersSave/Restore.S`,
  x86_64 covered); the runtimes build enables ASM language itself.

The Linux-only `_LIBUNWIND_USE_FRAME_HEADER_CACHE` is a CMake opt-in we
leave off. **Expected LLVM source patches for libunwind: zero.**

### K.2.4 The EH flip is archive-only — no header/ABI break

Current libc++'s `__config_site` (checked in the staged sysroot) carries
**no** exceptions macro: header-level EH behavior keys off the per-TU
compiler flag (`-fexceptions` → `__cpp_exceptions`). `LIBCXX_ENABLE_
EXCEPTIONS` / `LIBCXXABI_ENABLE_EXCEPTIONS` only change how the *archives*
are compiled (throw helpers really throw instead of aborting via
`__libcpp_verbose_abort`). Consequences:

- Existing no-EH binaries (m8, the 103MB `llvm`) keep working unchanged.
- Objects compiled `-fno-exceptions` still link against the new archives
  (LLVM itself stays `-fno-exceptions -fno-rtti`; the native toolchain
  does not need a rebuild *for the runtimes' sake* — it needs one only
  for the driver patch, K.5).
- After the flip, library-thrown exceptions (`vector::at`,
  `std::stoi`) work for real — the gate tests exactly that.

### K.2.5 libunwind.a stays a separate archive

`LIBCXXABI_USE_LLVM_UNWINDER=ON` hard-requires `libunwind` in
`LLVM_ENABLE_RUNTIMES` (libcxxabi/CMakeLists.txt:64). The
"merge unwinder objects into libc++abi.a" option
(`LIBCXXABI_STATICALLY_LINK_UNWINDER_IN_STATIC_LIBRARY`) only defaults ON
under `LIBCXXABI_ENABLE_STATIC_UNWINDER=ON`, which we do **not** set:
a separate `/usr/lib/libunwind.a` keeps the explicit recipes honest and
lets plain C use `-fexceptions`/`_Unwind_Backtrace` without dragging in
the C++ ABI library.

### K.2.6 Latent M9 bug: driver group order breaks the shim's `__cxa_thread_atexit`

Appendix I §I.4's plan of record — validated with `-Wl,-y` at M8 — is
that `libmoto_rt_cabi.a` must precede `libc++abi.a` so the **shim's**
VDSO-integrated `__cxa_thread_atexit` (dtor ordering interlocks with
emutls cleanup) wins over libc++abi's pthread-key fallback. The M9b
driver recipe (Motor.cpp) emits:

```
--start-group -lc++ -lc++abi -lc -lmoto_rt_cabi -lclang_rt.builtins-x86_64 --end-group
```

Within a group lld still resolves a lazy symbol from the **first archive
in scan order** that defines it — here `-lc++abi`, the wrong one. Nothing
gated it: hello.cpp has no `thread_local` dtors. Fix rides along in patch
#23: move `-lmoto_rt_cabi` ahead of the C++ libs. m10.cpp adds the gate
(thread_local dtor in a thread, the M5 pattern, now compiled natively).

### K.2.7 Where unwinding stops — and why that's fine

Only frames with `.eh_frame` records can be unwound through. Our C++ TUs
get them automatically once `-fno-exceptions` is dropped (clang emits
unwind tables for EH code). Frames **without** them: mlibc (built without
`-funwind-tables`), crt1's `motor_start`, the shim, thread trampolines.
Phase-1 search hitting such a frame returns `_URC_END_OF_STACK` →
`std::terminate` — which is exactly the correct behavior for an exception
escaping `main` or a thread entry anyway. A throw never needs to *cross*
a libc frame in real code unless a callback throws through qsort-style C
glue (UB-adjacent everywhere; documented gap, K.10). Corollary for the
gate: catch handlers must sit in the same or a calling C++ frame — they
do, in any normal program.

### K.2.8 Size budget

`libunwind.a` is a few hundred KB; EH-enabled `libc++.a`/`libc++abi.a`
grow modestly (currently 2.1M + 544K pre-strip). The rebuilt native
`llvm` binary changes by only the driver patch. **Net image delta:
≈ +1–3 MB.** No user approval needed at this size.

## K.3 Plan of record

1. **Patch #23** (llvm-project, branch motor): Motor.cpp `ConstructJob` —
   group becomes `--start-group -lmoto_rt_cabi [-lc++ -lc++abi if CXX]
   -lunwind -lc -lclang_rt.builtins-x86_64 --end-group` (`-lunwind`
   unconditional: it's an archive, costs nothing when unreferenced, and C
   `-fexceptions` needs it too).
2. Rebuild **host** clang/lld (`ninja -C build`) — the host cross driver
   carries the same Motor.cpp.
   ⚠ Host clang rebuild ⇒ **delete all PCHs in build-motor-native**
   (embedded git hash changes): `find build-motor-native -name '*.pch'
   -delete`.
3. Wipe + reconfigure + rebuild `build-motor-cxx` with the K.4 recipe
   (adds libunwind, flips EH on). `DESTDIR=$SYSROOT ninja install-unwind
   install-cxxabi install-cxx`.
4. Post-install checks (host):
   - `$SYSROOT/usr/lib/libunwind.a` exists; `llvm-nm` shows
     `T _Unwind_RaiseException`, `U pthread_rwlock_wrlock`, `U
     dl_iterate_phdr` and **no** unexpected undefineds (no `getauxval`,
     no `dladdr`).
   - `llvm-nm libc++abi.a | grep __cxa_throw` is `T`;
     `__gxx_personality_v0` is `T`.
   - `__config_site` unchanged vs. K.2.4 expectations.
5. Write `src/tests/libc/m10.cpp` (K.8), cross-build with the K.6 recipe,
   audit (`no PT_TLS`, RELATIVE-only relocs — LSDA/typeinfo pointers land
   as `R_X86_64_RELATIVE` in `.data.rel.ro`), stage as `bin/m10`.
6. Rebuild the native multicall `llvm` (`ninja -C build-motor-native
   llvm`), **verify freshness before staging** (`[ build-motor-native/bin/
   llvm -nt img_files/.../bin/llvm ]` — we staged stale binaries twice at
   M9), strip, stage.
7. Stage: new stripped archives into `img_files/motor-os/usr/lib/`
   (libc++.a, libc++abi.a, **libunwind.a**), cfg without
   `-fno-exceptions`, `m10.cpp` at `usr/src/m10.cpp`, `bin/m10`.
8. User runs the K.8 VM gate. Debug loop as usual (kernel
   `print_backtrace` + host `llvm-addr2line` on unstripped binaries).
9. Mark this appendix complete; update memory; commits when the user asks.

## K.4 Runtimes rebuild recipe

Same skeleton as I.3, three changes marked `# M10`:

```bash
LLVM=/home/posk/motorh/llvm-project
B=$LLVM/build/bin
SYSROOT=/home/posk/motorh/motor-sysroot

rm -rf $LLVM/build-motor-cxx   # stale try_compile results are poison (I.2.5)

cmake -G Ninja -S $LLVM/runtimes -B $LLVM/build-motor-cxx \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=$B/clang -DCMAKE_CXX_COMPILER=$B/clang++ \
  -DCMAKE_C_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_CXX_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_C_FLAGS="-isystem $SYSROOT/usr/include -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_LIBUNWIND_USE_DLADDR=0" \
  -DCMAKE_CXX_FLAGS="-isystem $SYSROOT/usr/include -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_LIBUNWIND_USE_DLADDR=0" \
  -DCMAKE_INSTALL_PREFIX=/usr \
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
```

The recipe above is the **final, working** configure (2026-07-04). Two
fights it already encodes — the naive first attempt hit both, in line
with the I.2.5 hazard list:

- **`error: unknown type name 'Dl_info'`** in AddressSpace.hpp:
  `check_symbol_exists(dladdr)` false-positived (compile-only probe;
  mlibc declares it), but mlibc guards `Dl_info` behind
  `_GNU_SOURCE && __MLIBC_GLIBC_OPTION` — and our mlibc build has the
  glibc option **off**. Fix: `-D_LIBUNWIND_USE_DLADDR=0` (a designed
  `#ifndef` override in AddressSpace.hpp). Cost: `unw_get_proc_name`
  symbolication always fails — irrelevant, our debug loop symbolizes
  host-side via addr2line. Zero source patches held.
- **`no member named 'realpath'`** in libc++ filesystem: libc++ builds
  with `-std=c++26` ⇒ `__STRICT_ANSI__` ⇒ mlibc does **not** imply
  `_DEFAULT_SOURCE`. This bit at M8 too, but the fix
  (`-D_GNU_SOURCE -D_DEFAULT_SOURCE` in the flags) was recorded only in
  I's "deltas from the recipe" pitfall note (I §Build log, line ~295),
  not folded back into the I.3 block. Now folded in here.
- The `*_HAS_PTHREAD_LIB/RT_LIB/ATOMIC_LIB/DL_LIB=OFF` family: probes
  misfire (compile-only), and while the resulting
  `-D_LIBCPP_LINK_*_LIB` defines are mere `#pragma comment(lib)` no-ops
  for static archives, M8 set them OFF and K keeps that.
- `LIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL=OFF` stays forced (I.2.5).
- Do **not** set `LIBUNWIND_IS_BAREMETAL` — it would switch AddressSpace
  to linker-symbol `.eh_frame` bounds and off the (working)
  `dl_iterate_phdr` path.

### Build log (2026-07-04) — host side complete, staged, awaiting VM gate

Everything in K.3 steps 1–7 is done; artifacts staged. Deltas and
findings beyond the recipe fixes already folded into K.4:

- **The native `llvm` link needed the cache updated**: build-motor-native's
  `CMAKE_CXX_STANDARD_LIBRARIES` (an M9-era frozen link line) predates
  libunwind, and the new EH-enabled `libc++abi.a` references `_Unwind_*` —
  the relink failed with undefined `_Unwind_RaiseException` et al. Fix:
  re-run cmake on build-motor-native with the group updated to mirror
  patch #23 (`-lmoto_rt_cabi` first, `-lunwind` added) in both
  `CMAKE_CXX_STANDARD_LIBRARIES` and `CMAKE_C_STANDARD_LIBRARIES`.
  Remember this whenever the sysroot's C++ archives change shape.
- Host-side driver validation without a VM: `clang++ --no-default-config
  --target=x86_64-unknown-motor --sysroot=$SYSROOT m10.cpp -o m10` (the
  `--no-default-config` sidesteps the host cfg's `-nostdlib`, which would
  suppress the driver recipe). Shim wins `__cxa_thread_atexit` per
  `-Wl,-y`; audit clean.
- m8.cpp relinks cleanly `-fno-exceptions` against the EH archives —
  the K.2.4 compat claim holds in both directions.
- Sizes: `libunwind.a` 134 KB; `libc++.a` 2.50 MB / `libc++abi.a` 600 KB
  (from 2.1 MB / 544 KB no-EH); stripped native `llvm` 107.5 MB (was
  103 MB — it statically links the now-EH-enabled libc++). m10 1.2 MB
  stripped. **Actual image delta ≈ +6 MB**, above the K.2.8 guess of
  +1–3 MB; the miss was forgetting that the native toolchain binary
  itself carries libc++.
- Unstripped `m10` kept at `/home/posk/motorh/test-bins/m10-unstripped`
  for the addr2line loop.
- **First VM gate + test fix**: m10 t1–t8 passed on the VM (all EH
  behavior + the patch-#23 `thread_local`-dtor gate); t9 failed
  `backtrace_mid() >= 3`. Root cause (confirmed by `objdump` on the
  Motor binary): the Motor clang (23) tail-calls `return
  backtrace_leaf()` to a `jmp`, erasing the `mid` frame, and Motor has
  no `.eh_frame` above `main` (crt1/`__mlibc_entry`) — so the walk is
  `leaf → main` = 2, not 3. The older host clang didn't tail-call, so
  the host pre-flight passed and hid it. Fix: `disable_tail_calls` on
  `backtrace_mid` (its frame is now a real `call`, verified in the
  disasm) and assert the true invariant `>= 2`. Re-staged; re-run
  pending. Not a Motor defect — t3 unwinds 4 frames via the EH path.

## K.5 Expected patches (running list)

| # | Repo | What | Status |
|---|------|------|--------|
| 23 | llvm-project | Motor.cpp link group: add `-lunwind`; move `-lmoto_rt_cabi` ahead of `-lc++`/`-lc++abi` (K.2.6) | done — verified from the host with `--no-default-config` + `-Wl,-y,__cxa_thread_atexit`: shim wins in a driver link |
| 24 | mlibc | `ThreadJoin` sysdep: `pthread_join` waits on the kernel thread handle (`moto_rt_thread_join`) instead of `didExit`, so it synchronizes-with the C++ thread-exit dtors (K.5.1) | done — fixes the m10 t8 race |

Not patches, but coupled config changes:

- `img_files/motor-os/etc/x86_64-unknown-motor.cfg`: delete the
  `-fno-exceptions` line + its comment block.
- Host cfg (`build/bin/x86_64-unknown-motor.cfg`, appendix A.5 is source
  of truth) never had `-fno-exceptions` — **no change**; the M8-era
  *recipes* passed it per-command, and K.6 simply stops doing that.

Expected mlibc patches: the research said **zero** (K.2.2) — held for the
EH machinery, but the m10 gate flushed out one pre-existing threading bug
(patch #24, K.5.1) that was unrelated to exceptions. Expected libunwind
source patches: **zero** (K.2.3) — held (`-D_LIBUNWIND_USE_DLADDR=0` is
a supported config override, not a patch; see K.4).

### K.5.1 The m10 t8 race — `join()` vs C++ thread-exit destructors (patch #24)

**Symptom.** After the t9 fix, native `llvm clang++ /usr/src/m10.cpp` (no
`-O2`) failed t8 (`tl_dtor_runs == 1`) — but only sometimes: the `-O2`
build passed once then failed the next three runs. Flaky ⇒ a race, not a
codegen issue. (The cross-built `m10`, always `-O2`, happened to win the
race and looked green.)

**Root cause.** t8 spawns a thread that touches a `thread_local` with a
destructor, `join()`s it, then asserts the dtor ran. On Motor the
thread-exit dtors are split across two layers, and they straddle the
join wakeup:

```
mlibc thread_exit (options/internal/generic/threads.cpp):
   run pthread_key (POSIX TSD) dtors          ← before didExit  ✓
   store didExit = 1;  FutexWake(&didExit)     ← WAKES pthread_join
   do_exit → ThreadExit → longjmp → VDSO wrapper returns
      → __rt_thread_fn → on_thread_exiting()   ← C++ __cxa_thread_atexit
                                                  + emutls dtors run HERE  ✗
```

`pthread_join` waited on `didExit`, which mlibc signals *before* the VDSO
runs the C++ `thread_local` destructors. So `join()` could return before
`~TlWatcher` incremented the counter — a violation of the C++ rule that
`join()` synchronizes-with *all* of the thread's exit destructors. The
POSIX-TSD dtors were fine (they run before `didExit`); only the
VDSO-side C++/emutls dtors were late.

**Fix (correct layer = mlibc join).** Motor already has a handle-based
join in moto_rt (`moto_rt_thread_join`, exported by moto-rt-cabi) that
waits on the kernel thread handle — and that handle is signaled at
`SysObj::put(SELF)`, which runs *after* `on_thread_exiting()`. So the
handle wait is exactly the synchronization edge join needs. Wiring:

- `Tcb` gains `uint64_t sysdepThreadHandle` (appended after `guardSize`;
  x86_64 canary/cancelBits offsets are earlier fields, so layout asserts
  hold). The Motor `Clone` sysdep stops leaking the spawn handle blindly
  and stores it there (`__ATOMIC_RELEASE`).
- New `ThreadJoin` sysdep (tag + signature + `MotorSysdepTags`);
  Motor impl = `moto_rt_thread_join(handle)`.
- Generic `thread_join` delegates to `ThreadJoin` when
  `IsImplemented<ThreadJoin>` (mirrors the `PosixSpawn` pattern),
  falling back to the `didExit` loop otherwise. `returnValue` is set
  before `didExit`, so it is already valid when the handle wait returns.

Handle-wait also covers the already-exited case (moto_rt join returns on
a dead handle), and if the thread is dead the dtors have already run
(same `put(SELF)` ordering). The handle stays leaked-until-process-exit
as before; `join` doesn't `put` it. Files: mlibc `tcb.hpp`,
`sysdep-tags.hpp`, `sysdep-signatures.hpp`, `sysdeps/motor/.../sysdeps.hpp`,
`sysdeps/motor/generic/thread.cpp`, `options/internal/generic/threads.cpp`.

This is a real Motor concurrency bug that predates M10 — the patch-#23
`thread_local`-dtor regression test just happened to surface it. Upstream
value: the split-dtor/late-`__cxa_thread_atexit` hazard applies to any
mlibc sysdep that runs C++ thread-exit dtors outside `thread_exit`;
worth raising in the M10b mlibc PR.

## K.6 Cross link recipe (m10 from the host)

I.4 with three deltas: no `-fno-exceptions`, `libunwind.a` after
`libc++abi.a`, and the shim moved before the C++ libs (the I.4 plan of
record, now applied consistently):

```bash
$B/clang++ --target=x86_64-unknown-motor -O2 -std=c++17 \
  -nostdinc++ \
  -isystem $SYSROOT/usr/include/c++/v1 \
  -isystem $SYSROOT/usr/include \
  m10.cpp \
  $SYSROOT/usr/lib/crt1.o \
  $SYSROOT/usr/lib/libmoto_rt_cabi.a \
  $SYSROOT/usr/lib/libc++.a $SYSROOT/usr/lib/libc++abi.a \
  $SYSROOT/usr/lib/libunwind.a \
  $SYSROOT/usr/lib/libc.a \
  $SYSROOT/usr/lib/libclang_rt.builtins-x86_64.a -o m10
```

(Plain archive lists resolve strictly left-to-right; the shim has no
undefined C++ refs so putting it first is safe — verified at M8 with
`-Wl,-y __cxa_thread_atexit`. Repeat that check here.)

Audit before staging, as always: `llvm-readelf -l` → no `PT_TLS`;
`llvm-readelf -r` → `R_X86_64_RELATIVE` only.

## K.7 Image staging

All under `img_files/motor-os/` (maps to image ROOT; never touch the
imager yaml):

| Path on image | Source | Notes |
|---|---|---|
| `/usr/lib/libunwind.a` | build-motor-cxx install | `llvm-objcopy --strip-debug` |
| `/usr/lib/libc++.a`, `/usr/lib/libc++abi.a` | rebuilt, EH-on | strip-debug, replaces M8 archives |
| `/etc/x86_64-unknown-motor.cfg` | edited | `-fno-exceptions` removed |
| `/bin/llvm` | rebuilt build-motor-native, stripped | patch #23; freshness-check before staging |
| `/bin/m10` | K.6 cross build | stripped copy; keep unstripped on host for addr2line |
| `/usr/src/m10.cpp` | src/tests/libc/m10.cpp | native-compile gate input |

Headers under `/usr/include/c++/v1` are re-synced from the sysroot after
the install step (content should be near-identical; `__config_site` must
match K.2.4).

## K.8 Gate test: `src/tests/libc/m10.cpp`

CHECK-style like m8, `-std=c++17`, unbuffered stdout + stderr `MARK`s
(the m9 lesson: this test debugs the machinery underneath itself).
Sections, cheap-to-deep:

1. **throw/catch int** — the minimal personality round-trip.
2. **`std::runtime_error`**: throw, catch by `const std::exception&`,
   check `what()`.
3. **Unwinding runs dtors**: RAII counter through 3 nested frames;
   verify count and order; `std::uncaught_exceptions()` sanity inside a
   dtor.
4. **rethrow** (`throw;`) across a frame + catch-all.
5. **Library throws** (proves the EH-enabled archives, not just the
   compiler): `std::vector::at` → `std::out_of_range`;
   `std::stoi("nope")` → `std::invalid_argument`.
6. **RTTI + EH**: failed `dynamic_cast` on a reference → `std::bad_cast`.
7. **Threads**: throw + catch inside a `std::thread`;
   `std::promise::set_exception` / `future.get()` rethrow on the main
   thread (`std::exception_ptr` crossing threads).
8. **thread_local dtor in a thread** — the K.2.6 regression gate (M5
   pattern, now under the EH runtime; matters for the *native* build,
   which uses the patched driver group order).
9. **`_Unwind_Backtrace` smoke test**: walk ≥ 2 frames from a nested
   call — exercises libunwind directly, not just via EH. (Threshold is
   ≥ 2, not 3: nothing above `main` on Motor carries `.eh_frame`
   (K.2.7), so the reachable count is tight; the helper is
   `disable_tail_calls` so its frame is genuinely exercised. See the VM
   gate log for why 3 was wrong.)

### VM gate (user runs; I never run Motor binaries)

```sh
m10                                     # cross-built, EH archives
llvm clang++ /usr/src/m10.cpp -o /sys/tmp/m10n && /sys/tmp/m10n
                                        # native compile+link+run, EH default-on
llvm clang /usr/src/hello.c -o /sys/tmp/h && /sys/tmp/h    # C regression
llvm clang++ /usr/src/hello.cpp -o /sys/tmp/hpp && /sys/tmp/hpp  # C++ regression
m8 && m9                                # M8/M9 regressions (old binaries, new image)
```

## K.9 M10b — upstreaming campaign (plan only; execute with the user)

Precedent: managarm ships an mlibc-based triple in both trees; reviewers
accept small, well-tested OS ports. Three independent tracks, in
submission order (mlibc first — the LLVM driver patch is more credible
once the libc port is public):

1. **mlibc `sysdeps/motor`** (upstream: github.com/managarm/mlibc, PR).
   Package: sysdeps dir + meson bits + `.github` CI entry (they ask for a
   build-only CI job for new sysdeps). Separable pre-PRs, each tiny and
   arguably useful upstream on its own: the `PosixSpawn` sysdep tag
   (fork-less platforms), the frigg strtofp fix (already in our
   subprojects diff), the `P_tmpdir` `__motor__` guard folds into the
   sysdeps PR.
2. **LLVM triple + driver** (llvm-project, Phabricator-successor flow:
   GitHub PRs). Series: (a) `llvm::Triple::Motor` + `__motor__` define;
   (b) `Motor` ToolChain (Motor.{h,cpp}); (c) the ifdef-ladder patches
   #7–#11 (each self-contained: Path.inc, bit.h, config-ix probing
   branch, MachO madvise guard). Patch #17/#20/#23 fold into (b).
3. **Docs**: a "porting to Motor OS" note in-repo; the appendices stay
   the engineering record.

What only the user can do: open the PRs (identity/DCO), argue timing.
What I can prepare on request: clean branches with squashed, reviewable
commits per track, commit messages, and the mlibc CI yaml.

## K.10 Deliberate gaps (document, defer)

- **No unwind tables in mlibc/shim/crt1**: throw cannot cross a C libc
  frame (callback → qsort-style); `_Unwind_Backtrace` stops at the first
  such frame. Fix if ever needed: rebuild mlibc with `-funwind-tables`
  (wishlist, cheap).
- **`std::bad_alloc` untested**: Motor's allocator prefers to grow;
  forcing OOM in a VM gate is more trouble than the coverage is worth.
- **Forced unwind / pthread_cancel**: no signals, no cancellation — not
  applicable on Motor.
- **popen/pipes, posix_spawn file_actions**: M11 candidates, blocked on
  VDSO pipe support (wishlist).

## K.11 Exit criteria

Host-side (done 2026-07-04):

- [x] `libunwind.a` built, installed (host sysroot + image), **no source
      patches** — only the `_LIBUNWIND_USE_DLADDR=0` config override (K.4).
- [x] libc++/libc++abi rebuilt EH-on; `__config_site` verified unchanged
      (K.2.4); m8.cpp relinks `-fno-exceptions` against the new archives.
- [x] Patch #23 in; `-Wl,-y __cxa_thread_atexit` shows the shim winning
      in a driver link (host, `--no-default-config`).
- [x] `m10` cross-built, audited (no PT_TLS; 2413 relocs, all
      `R_X86_64_RELATIVE`), staged; native `llvm` relinked with libunwind
      and staged (freshness-checked); cfg drops `-fno-exceptions`.
- [x] Image delta measured: **≈ +6 MB** (llvm 103→107.5 MB since it
      statically links the now-EH libc++, + m10 1.2 MB + archive growth).
      Over the K.2.8 guess of +1–3 MB; noted, no approval needed at +6 MB.

On-VM gate (K.8 — user runs; I never run Motor binaries):

- [x] Cross-built `m10`: passes (2026-07-04) — exceptions, unwinding,
      library throws, `dynamic_cast`, cross-thread `exception_ptr`.
- [x] Native `llvm clang++ /usr/src/m10.cpp`: passes consistently across
      repeated runs — exceptions on by default; the t8 join/dtor race is
      gone (patch #24).
- [x] Native `llvm` relinked against the patch-#24 libc.a and re-staged;
      image is coherent (freshness-checked, P_tmpdir + no-PT_TLS verified).
- [ ] hello.c / hello.cpp native regressions + m8/m9 (final sweep).

Follow-up:

- [ ] K.9 upstreaming plan reviewed by the user (execution = M10b).
