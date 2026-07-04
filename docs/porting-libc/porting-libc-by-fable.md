# A C library for Motor OS, then a native Clang/LLVM — recommendation

This document states the recommended plan for porting a C standard library (mlibc) to
Motor OS, then a native Clang/LLVM. Facts below were re-verified against the tree at
`RT_VERSION = 16` (`src/sys/lib/moto-rt/src/lib.rs:110`) and the Rust port in
`/home/posk/motorh/rust`.

Step-by-step implementation (commands, diffs, full code listings, per-milestone status
markers and pitfalls) lives in one appendix file per milestone:

| Appendix | Milestone | File |
|---|---|---|
| A | M0 — toolchain (LLVM target, reloc audit) | [porting-libc-appendix-a.md](porting-libc-appendix-a.md) |
| B | M1 — the C-ABI shim + UTCB `libc_tcb` | [porting-libc-appendix-b.md](porting-libc-appendix-b.md) |
| C | M2 — mlibc bring-up (sysdeps, crt1) | [porting-libc-appendix-c.md](porting-libc-appendix-c.md) |
| D | M3 — stdio + malloc | [porting-libc-appendix-d.md](porting-libc-appendix-d.md) |
| E | M4 — filesystem | [porting-libc-appendix-e.md](porting-libc-appendix-e.md) |
| F | M5 — threads + TLS | [porting-libc-appendix-f.md](porting-libc-appendix-f.md) |
| G | M6 — sockets | [porting-libc-appendix-g.md](porting-libc-appendix-g.md) |
| H | M7 — poll/select, signals-lite, real program (Lua) | [porting-libc-appendix-h.md](porting-libc-appendix-h.md) |
| I | M8 — C++ stack (libc++abi/libc++, no-EH) | [porting-libc-appendix-i.md](porting-libc-appendix-i.md) |

---

## 1. Verdict

**Port mlibc. Do not port picolibc, not even as a stepping stone.**
**Add a real `x86_64-unknown-motor` target to LLVM/Clang at the *start*, not the end.**
**Use `-femulated-tls` everywhere, with `__emutls_get_address` implemented directly over
the VDSO TLS API.**

Why mlibc and not picolibc:

- The end goal — Clang, lld, and libc++ running *on* Motor OS — needs pthreads, a
  POSIX-shaped filesystem API (`dirent`, `stat`, `getcwd`, temp files), `posix_spawn`,
  and enough of `unistd`/`fcntl` to satisfy `llvm/lib/Support`. mlibc has all of this as
  supported option groups; managarm (mlibc's home OS) runs real compilers on it.
- picolibc is newlib for embedded targets: no threads, no `pthread_key_*`, no sockets, no
  `dirent`. Every one of those would have to be written from scratch on top of it — i.e.
  the hard part of the port would be re-implementing what mlibc already ships.
- picolibc's missing pthreads is not just a feature gap, it breaks the TLS story:
  compiler-rt's stock emulated-TLS runtime (`emutls.c`) is built on `pthread_key_create`
  / `pthread_getspecific`. On picolibc there is nothing to back it with.
- The only genuinely reusable artifact of a picolibc detour — the C-ABI shim over the
  RT.VDSO — is libc-agnostic and is needed by the mlibc port anyway. A picolibc "quick
  win" saves nothing.

Why an LLVM target triple first: the alternative is driving "Motor-ness" through flag soup
(`--target=x86_64-unknown-none-elf -femulated-tls -static-pie -nostdlib -e motor_start …`)
that every build system must repeat perfectly. Any translation unit compiled without
`-femulated-tls` is a silent ABI break (native TLS relocations + a `PT_TLS` segment the
loader rejects). A small, local LLVM patch (§4) makes `x86_64-unknown-motor` a real Clang
target whose *defaults* are emulated TLS, static-PIE, and the right link line — the whole
class of "forgot the flag" bugs disappears, and the patch is the seed of the Phase-2
native toolchain work anyway.

---

## 2. Ground truth (verified in-tree)

| Fact | Where |
|---|---|
| `RT_VERSION = 16`; vtable covers alloc/time/futex/proc/tls/thread/fs/net/poll/rand | `moto-rt/src/lib.rs:110-238` |
| Init: loader stores only `vdso_entry`; process must call it with `RT_VERSION` before anything else; C-ABI symbol `motor_runtime_start()` already exists (weak) | `moto-rt/src/lib.rs:256-278` |
| Entry: linker `-e motor_start`; `main(0, null, 0)`; args/env via VDSO, not the stack | `rustc_target/.../base/motor.rs:8`, `rust/library/std/src/sys/pal/motor/mod.rs:14-26` |
| Binaries: static-PIE, `panic=abort`, no dynamic linking, `llvm_target = x86_64-unknown-none-elf` | `x86_64_unknown_motor.rs` |
| Loader applies only `R_AMD64_RELATIVE`; **rejects `PT_TLS`** (`UnsupportedAbi`) | `rt.vdso/src/load.rs:217-260` |
| Kernel owns `%fs` → UTCB; `fs:0x10` = `UTCB.tls`, `fs:0x28` = stack canary; UTCB is a versioned, page-sized, userspace-writable struct with room to grow | `moto-sys/src/shared_mem.rs:87-99` |
| **`UTCB.tls` is owned by the VDSO**: `tls_set/get` store a `BTreeMap` pointer there; `on_thread_exiting()` drains and **frees** it for every VDSO-spawned thread | `rt.vdso/src/rt_tls.rs`, `rt_thread.rs:21` |
| VDSO TLS API is pthread-key-shaped: `create(dtor)/set/get/destroy`, dtors run at thread exit (with reinsertion handling) | `moto-rt/src/tls.rs`, `rt.vdso/src/rt_tls.rs` |
| `moto-rt/src/libc.rs` exports only `mem*`, `__stack_chk_fail`, `__assert_fail` today | `moto-rt/src/libc.rs` |
| Raw anon pages: `SysMem::map/unmap` (`F_READABLE\|F_WRITABLE\|F_LAZY`) below the VDSO | `moto-sys/src/sys_mem.rs` |
| `process::spawn` returns `(handle, stdin, stdout, stderr)` → clean `posix_spawn` mapping; `kill`, `wait`, `try_wait` exist. No fork. | `moto-rt/src/process.rs:207-328` |

---

## 3. The plan, Phase 1: mlibc

The architecture, top to bottom:

```
C/C++ program → mlibc (printf, malloc, pthread_*, socket, …)
                  │
                  ▼
  sysdeps/motor/*.cpp  — sys_open, sys_futex_wait, … (int error codes, 0 = ok)
                  │  extern "C"
                  ▼
  libmoto_rt_cabi.a    — Rust staticlib: C-ABI shim over moto-rt + __emutls_get_address
                  │  RtVdsoVtable fn pointers
                  ▼
  RT.VDSO → moto-sys syscalls → kernel / sys-io
```

### 3.1 The shim: `moto-rt-cabi`

Make it a **sibling staticlib crate** (`crate-type = ["staticlib"]`, target
`x86_64-unknown-motor`), not more code behind moto-rt's `libc` feature: a staticlib
needs its own panic handler and a global allocator (back it with the VDSO
`alloc`/`dealloc` vtable entries), which the rlib-for-std build must not carry.
Contents:

- One flat-C-ABI function per VDSO operation (`moto_rt_open`, `moto_rt_read`, …,
  `moto_rt_vm_map`/`moto_rt_vm_unmap` over raw `SysMem::map/unmap` for mlibc's
  allocator pages). Convention: negative return = `-errorcode`, non-negative = value;
  out-params for compound results. Paired alloc/free helpers for VDSO-allocated buffers
  (args/env/canonicalize) so the two heaps never mix.
- `motor_runtime_start()` already exists — the shim re-exports/uses it and adds a
  `RT_VERSION` assertion.
- **`__emutls_get_address` and `__cxa_thread_atexit`** — see §3.3.
- A hand-written `moto_rt.h`.

Errno translation (moto `ErrorCode` ↔ Linux errno) lives at the sysdep layer — the
`moto_to_errno()` table in `sysdeps/motor/generic/sysdeps.cpp` (Appendix C).

### 3.2 The libc TCB: one new UTCB field (small kernel-ABI addition)

mlibc reaches its per-thread control block (pthread self, errno, cancellation) through a
thread-pointer load. `%fs` base is untouchable and `fs:0x10` is VDSO property (§2), so:

**Add `libc_tcb: u64` to `UserThreadControlBlock`** (`moto-sys/src/shared_mem.rs`),
taking space after the existing fields — the UTCB is a versioned, page-sized struct that
userspace may write; the kernel never reads the new word. Bump `user_version`. Then:

- `sys_tcb_set(p)` → store `p` to `fs:<offset_of(libc_tcb)>`;
- mlibc's `get_current_tcb()` (arch x86_64 header) → one `mov %fs:OFFSET, %rax` — same
  cost as a normal libc, no VDSO call, no conflict with `on_thread_exiting()`.

The obvious alternatives are both worse: reusing `fs:0x10` is a use-after-free (the
VDSO frees that map in `on_thread_exiting()`, and mlibc's TCB must outlive it), and
routing every `errno` read through the VDSO key map (a `BTreeMap` walk) is needless
overhead. The change is ~5 lines in a struct we own.

### 3.3 TLS: `-femulated-tls`, with a native emutls runtime

Decision (user-confirmed): **all C/C++ for Motor is compiled with emulated TLS.** No
`PT_TLS` is ever emitted, `%fs` is never written, the loader is happy. Made a *target
default* by the §4 LLVM patch, not a flag anyone must remember.

Do **not** use compiler-rt's `emutls.c` (pthread-key based, creates libc-bootstrap
ordering hazards). Implement in the shim, in Rust, over the VDSO TLS API — which is
exactly pthread-key-shaped and already runs destructors at thread exit:

- `__emutls_get_address(control)` — clang emits one `__emutls_v.NAME` control struct
  per variable `{size, align, index, default_value}`; the runtime lazily assigns
  indices (atomic), keeps a per-thread growable array under **one** VDSO TLS key, and
  allocates+initializes a variable's storage on first touch (respect `align`). The key's
  destructor frees the array and its slots; `rt_tls`'s exit loop already tolerates
  reinsertion during dtors (`rt_tls.rs:116`).
- `__cxa_thread_atexit(dtor, obj, dso)` — clang uses it for C++ `thread_local`
  destructors under emulated TLS too: keep a per-thread dtor list under a second VDSO
  key whose destructor runs the list LIFO.
- Exclude `emutls.c` when building compiler-rt builtins so there is exactly one
  implementation. Verify the control-struct ABI against the pinned clang version once,
  with a two-thread smoke test.
- `errno` stays in the mlibc TCB (§3.2) — never emutls — so nothing circular exists
  even during early startup. mlibc-internal `thread_local`s compile unchanged.
- `pthread_key_create/…` in mlibc: implement 1:1 over the VDSO key API (dtors included)
  rather than a TCB-side key table; Rust `std` and C then share one TSD mechanism.

Cost: every `_Thread_local` access is a function call. Acceptable; if profiling ever
says otherwise, native-TLS via a kernel/loader change is a contained future project.

### 3.4 mlibc specifics

- **ABI headers: `abis/linux`** (symlink farm, like managarm's demo port). Well-tested
  constants; the sysdep error map targets Linux errno numbers. Note: Rust std reports
  raw moto error codes as its "raw OS errors" (`pal/motor/mod.rs:7-10`) — the two
  worlds' errno namespaces differ; irrelevant in practice, just don't pass numeric
  errno values across the Rust↔C boundary.
- **Meson cross file**: `system = 'motor'`; compilers are the patched clang with
  `--target=x86_64-unknown-motor` (§4). Static `libc.a` only; no `ld.so`, ever
  (`dynamic_linking: false` is a platform property, not a TODO).
- **Option groups**: start `ansi` + `posix`; leave `linux`/`glibc`/`bsd` off. Stub
  unimplemented sysdeps as `ENOSYS` + log through `mlibc::infoLogger()` so real
  requirements surface at runtime, not link time.
- **crt0** (`sysdeps/motor/crt-src/`): entry symbol (link with `-e motor_start` for
  consistency with Rust) does: `motor_runtime_start()`; synthesize argc/argv/envp from
  the shim (VDSO args/env); build the SysV entry-stack block mlibc expects with minimal
  auxv (`AT_PAGESZ=4096`, `AT_RANDOM` ← `fill_random_bytes`, `AT_SECURE=0`, `AT_NULL`);
  call `__mlibc_entry`. No self-relocation — the loader already applied
  `R_X86_64_RELATIVE`. Stack canary is free (`fs:0x28`, kernel-set).
- **Sysdep tables, smoke-test ladder, packaging**: fully specified, with verified
  listings, in Appendices C–E; test binaries are staged via `img_files/motor-os/bin/`.

### 3.5 Known non-goals (document for libc users)

No `fork` (spawn/`posix_spawn` only), no signals delivery (stub `sigaction`; `kill` →
`proc_kill`), no symlinks/hardlinks, no uid/gid, no file-backed `mmap`, termios ≈
`isatty` only. It matters for Phase 2 that **none of these block clang or lld** (§5.3).

---

## 4. The LLVM target patch (do this first, keep it local, upstream later)

A deliberately minimal patch series against the pinned LLVM (pin it next to the Rust
nightly):

1. **Triple**: add `motor` to `llvm/include/llvm/TargetParser/Triple.h` + `Triple.cpp`
   (`x86_64-unknown-motor`), and return `true` from `Triple::hasDefaultEmulatedTLS()`
   for it — the same hook Android/OHOS use. Emulated TLS is now the *default codegen
   model* for the target; `-femulated-tls` disappears from every build recipe.
2. **Clang driver**: `clang/lib/Driver/ToolChains/Motor.{h,cpp}` modeled on the Fuchsia
   toolchain (the best non-Linux, lld-first, static-friendly template): defaults
   static-PIE, `-e motor_start`, integrated-as, `ld.lld`, sysroot layout
   (`crt0.o … -lc -lmoto_rt_cabi -lclang_rt.builtins`), C++ pieces added as they exist.
   A *minimal* version of this class is required from day one — verified at M0: the
   unknown-OS fallback toolchain (`Generic_GCC`) has no native link job and shells out
   to the host `gcc` (which fails, and would be wrong even if it worked), and it
   defaults to non-PIC codegen (`-mrelocation-model static`), which breaks
   `-static-pie` links. Appendix A patch 3 is the ~40-line minimal class (PIC/PIE
   defaults, native `ld.lld` link job); grow it into the full sysroot-aware toolchain
   around M8. An auto-loaded `x86_64-unknown-motor.cfg` supplies the remaining
   defaults through M2.
3. **compiler-rt builtins** for the triple, `emutls.c` excluded (§3.3). Not needed for
   M0's freestanding test; build at M1.

Validate lld-vs-loader once at milestone M0: link a trivial static-PIE with `ld.lld`
and confirm the loader accepts it — the loader handles only `R_AMD64_RELATIVE`, so
check the output has no `DT_RELR` packed relocs, no ifunc/`R_X86_64_IRELATIVE`, no
`PT_TLS`. All are controllable with lld flags in the driver patch; this is the one
place surprises are likely, so burn it down first.

Rust's target keeps compiling via `x86_64-unknown-none-elf` untouched; nothing in the
Rust port changes.

---

## 5. Phase 2: Clang/LLVM running natively on Motor OS

Scope honestly stated: **cross-build LLVM from Linux, run clang/lld/llvm-ar natively on
Motor** to compile and link user programs against the on-image sysroot. Self-hosting the
LLVM *build* (cmake, ninja, python on Motor) is a distant, separate project.

### 5.1 C++ runtime stack (cross-built with the §4 toolchain)

Build order: `libunwind` (optional at first) → `libc++abi` → `libc++`, all static, all
against mlibc. Start with `LIBCXX_ENABLE_EXCEPTIONS=OFF` / `LIBCXXABI_…=OFF` — LLVM
itself compiles `-fno-exceptions -fno-rtti` by default, so the native toolchain doesn't
need EH to *run*. Add the EH-enabled variants later so *user* C++ on Motor can throw
(static-PIE + `.eh_frame` is routine; no loader work needed). Threading:
`LIBCXX_HAS_THREAD_API_PTHREAD` on mlibc's pthreads. C++ `thread_local` dtors already
work via §3.3's `__cxa_thread_atexit`.

### 5.2 `llvm/lib/Support` port

The Unix/*.inc layer mostly compiles against a POSIX-shaped libc. The real gaps, and
their Motor answers:

| Area | Answer |
|---|---|
| `Program.inc` (spawn cc1/lld) | mlibc `posix_spawn` → `moto_rt::process::spawn` (returns handle + stdio fds — clean fit). Also: modern clang runs cc1 in-process by default (`-fintegrated-cc1`), so the hot path doesn't even spawn. |
| `Memory.inc` (RWX for JIT) | not needed for clang/lld; return failure. |
| mmap of input files (`MemoryBuffer`) | let `mmap` fail → LLVM falls back to `read` into malloc'd buffers by design. Output: `FileOutputBuffer` has an in-memory fallback too. |
| `Signals.inc` (crash backtraces) | mlibc `sigaction` stubs accept-and-ignore; wire `abort` to VDSO `log_backtrace` for diagnostics instead. |
| `DynamicLibrary` (plugins) | no `dlopen` on a static-only OS; return failure; build with `LLVM_ENABLE_PLUGINS=OFF`. |

### 5.3 Build & ship

- CMake cross build: `LLVM_ENABLE_PROJECTS="clang;lld"`, `LLVM_TARGETS_TO_BUILD=X86`,
  `LLVM_ENABLE_THREADS=ON` (pthreads exist by then; fall back to `OFF` only if M5
  slips), zlib/zstd/libxml2/terminfo off, tests/benchmarks off, `llvm-ar`/`llvm-nm` via
  `LLVM_TOOLCHAIN_TOOLS`.
- Expect a stripped static clang in the 80–150 MB range; fine for a VM-native OS, but
  budget loader time (millions of `R_X86_64_RELATIVE` relocs applied by
  `rt.vdso/load.rs`) and test with a real binary early — if it's slow, that loader loop
  is optimizable.
- Ship on the image: `clang`, `lld`, `llvm-ar` + a native sysroot (mlibc headers,
  `libc.a`, `crt0.o`, `libmoto_rt_cabi.a`, builtins, libc++ stack) via `imager`.
- Acceptance test: on Motor, `clang hello.c -o hello && ./hello`, then a small C++
  program with `std::thread` + `thread_local`.

---

## 6. Milestones

1. **M0 — toolchain**: §4 LLVM patch; trivial static-PIE from `clang
   --target=x86_64-unknown-motor` + `ld.lld` accepted by the loader (reloc audit).
   Step-by-step: **[Appendix A](porting-libc-appendix-a.md)**.
2. **M1 — shim**: `libmoto_rt_cabi.a` + `moto_rt.h`; `libc_tcb` UTCB field lands.
   Step-by-step: **[Appendix B](porting-libc-appendix-b.md)**.
3. **M2 — crt0 + minimal sysdeps**: exit codes, `write`, argv/env visible in C.
   Step-by-step: **[Appendix C](porting-libc-appendix-c.md)**.
4. **M3 — stdio + malloc**: `printf`, allocator on `moto_rt_vm_map` pages, futex locks.
   Step-by-step: **[Appendix D](porting-libc-appendix-d.md)**.
5. **M4 — filesystem**: open/read/write/stat/dirs/getcwd under `/sys/tmp`.
   Step-by-step: **[Appendix E](porting-libc-appendix-e.md)**.
6. **M5 — threads + TLS**: `pthread_create/join/mutex/cond`; multi-thread
   `_Thread_local` validates the emutls ABI; `__cxa_thread_atexit` dtor test.
   Step-by-step: **[Appendix F](porting-libc-appendix-f.md)**.
7. **M6 — sockets**: TCP/UDP + `getaddrinfo` over `moto-rt::net`.
   Step-by-step: **[Appendix G](porting-libc-appendix-g.md)**.
8. **M7 — real program**: a fork-free Unix utility end-to-end in a VM.
   Step-by-step: **[Appendix H](porting-libc-appendix-h.md)**.
9. **M8 — C++ stack**: libc++abi/libc++ (no-EH) cross-built; C++17 program runs.
   Step-by-step: **[Appendix I](porting-libc-appendix-i.md)**.
10. **M9 — native toolchain**: clang+lld on the image compile hello.c natively.
    Step-by-step: **[Appendix J](porting-libc-appendix-j.md)**.
11. **M10 — polish**: EH-enabled libc++, upstream `sysdeps/motor` to mlibc, upstream
    the LLVM target. Step-by-step: **[Appendix K](porting-libc-appendix-k.md)**.

## 7. Top risks

- **emutls ABI drift** — the control-struct layout is an LLVM implementation detail;
  pin LLVM, re-test on toolchain bumps. **Validated at M5** (2026-07-03): multi-thread
  `_Thread_local` with nonzero initializers behaves correctly across 10+ runs.
- **lld output vs. the loader** — the loader's minimal reloc support is the sharpest
  edge; that's why it's M0, not M9.
- **mlibc internals under a foreign TCB scheme** — patching `get_current_tcb()` and
  `sys_tcb_set` to the `libc_tcb` slot touches arch-internal headers; study managarm's
  x86_64 code paths before estimating.
- **`RT_VERSION` skew** — shim asserts the version at startup (currently 16).
- **Big-binary loading** — relocation and page-in cost for a ~100 MB static clang is
  unmeasured; measure at M9 with the real binary, optimize the loader if needed.
