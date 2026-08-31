# The Motor OS C library and C/C++ runtime

Motor OS ships a complete, fully static C and C++ runtime for
`x86_64-unknown-motor`, built around a port of [mlibc](https://github.com/managarm/mlibc).
It is built, versioned, and validated by the unified toolchain workflow:
[build-llvm.md](build-llvm.md) describes the build graph and image layout,
[toolchain.md](toolchain.md) the versioning and pinning rules. This document
describes the runtime itself: its architecture, the supported surface, its
known limitations, and the on-image conventions.

The port was designed and executed through a step-by-step porting guide
(milestones M0–M10, each with status, pitfalls, and smoke tests m1–m10),
formerly at `docs/porting-libc/`. The guide was removed after completion; see
git history for the walkthroughs. What remains true of its content lives here.

## Architecture

From the application down:

| Layer | Provides |
| --- | --- |
| libc++ / libc++abi / libunwind | full C++ standard library, RTTI, exceptions |
| mlibc (`sysdeps/motor`) | `libc.a`, `crt1.o`, POSIX and ANSI C surface |
| compiler-rt builtins | compiler intrinsics, with `emutls.c.o` removed |
| `moto-rt-cabi` (`libmoto_rt_cabi.a`) | the C-ABI shim over the RT.VDSO |
| RT.VDSO / `moto-rt` | the same process runtime Rust std uses |

The shim (`src/sys/lib/moto-rt-cabi`) is the single bridge between C-world and
the Motor runtime. It owns emulated TLS — `__emutls_get_address` implemented
directly over the VDSO TLS API — and `__cxa_thread_atexit`, which clang emits
calls to under emulated TLS as well. compiler-rt's stock `emutls.c` is removed
from the builtins so the shim is the sole emulated-TLS owner; the kernel
reserves the `libc_tcb` UTCB field for it. Because C and Rust share one
runtime substrate, a C socket, file, or thread is the same kernel/VDSO object
a Rust one is.

Properties that follow, and that every consumer can rely on:

- **Everything is static.** Binaries are static PIEs; there is no dynamic
  linking and no `dlopen`. The loader applies only relative relocations and
  rejects `PT_TLS`, which is why all TLS is emulated (`-femulated-tls` is a
  Motor clang target default) and binaries carry no `.tdata`/`.tbss`.
- **ELF constructors run.** mlibc's `crt1.o` startup executes `.init_array`.
  This is the C-linked entry path; the pure-Rust `motor_start` path does not
  walk constructors, so a Rust program that needs them (e.g. `inventory`-style
  static registration) links through `motor-rust-cc`.
- **Clang owns the link recipe.** Plain `cc`/`c++` invocations receive
  `crt1.o`, mlibc, compiler-rt, and the C++ libraries automatically;
  `-nostdlib` and friends remain meaningful so rustc can produce a pure-Rust
  binary without pulling in mlibc.

## Supported surface

Brought up and gated milestone by milestone during the port, and exercised
today by the assembly validation, the native Lua build, and the full-test
suites:

- **ANSI C**: formatted I/O both directions (including correct `%.17g`
  round-trips), buffered file stdio, `malloc`, `setjmp`/`longjmp`, `abort`
  with `SIGABRT` semantics (status 134).
- **Filesystem**: the `stat` family, `dirent`, `getcwd`/`chdir` and relative
  paths, `openat`, `mkdir`/`mkdirat`, `ftruncate`/`fsync`,
  `access`/`faccessat`, temp files.
- **Processes**: `posix_spawn`, `waitpid`, `system()`. There is **no
  `fork()`**.
- **Threads and TLS**: pthreads (create/join/detach, mutex/cond/rwlock under
  contention, keys with destructors), `_Thread_local` via emulated TLS,
  `__cxa_thread_atexit`.
- **Sockets**: TCP and UDP (connected, peek, timeouts), `getaddrinfo`
  (numeric and hosts-file), nonblocking mode and `fcntl`.
- **poll/select** over sockets and files, including the blocking-listener
  arming path.
- **Signals-lite**: `signal`/`sigaction`/`sigprocmask`/`raise`/`kill(self)`.
  Dispositions are recorded and handlers dispatch synchronously on `raise`;
  Motor has no kernel signals, so **nothing is ever delivered
  asynchronously**. (Terminal Ctrl+C is a separate mechanism — see
  [tui.md](tui.md).)
- **C++**: iostreams, containers, `to_chars`/`from_chars`, RTTI, statics
  guards, `std::thread`, `thread_local` destructors, `<random>`,
  `<filesystem>`, aligned new — with real exceptions via libunwind and
  libc++abi.
- **A native toolchain**: the on-image clang/clang++/lld multicall behind the
  `/devtools/bin/cc` and `c++` launchers compiles and links C and C++ on
  Motor itself. Lua 5.4.8 builds from unmodified sources as the standing
  end-to-end proof.

## Known limitations

- No `fork()`, no `dlopen()`/dynamic linking — both are deliberate platform
  decisions, not gaps.
- Signals are synchronous-only, as above.
- `__cxa_thread_atexit` destructors run at *thread* exit. `main` returning
  can end the process via `proc_exit` without draining the main thread's
  destructor list; the caveat is recorded at the implementation,
  `src/sys/lib/moto-rt-cabi/src/cxa.rs`.
- Executable-permission support is a cross-repository compatibility boundary
  between the fd wrapper, mlibc, and LLVM revisions; never mix components
  across assembly tuples ([build-llvm.md](build-llvm.md), "Source identity").

## On-image layout and configuration

Motor keeps the toolchain and libc out of the classic Unix `/usr` + `/etc`
trees and uses the ownership-based `/devtools` and `/system` trees:

| What | Where |
| --- | --- |
| clang/LLVM headers + libraries | `/devtools/llvm/{include,lib}` |
| clang resource directory | `/devtools/llvm/lib/clang/<N>` |
| clang `<triple>.cfg` | `/devtools/cfg/llvm` |
| C/C++ launchers | `/devtools/bin/{cc,c++}` |
| mlibc runtime configuration | `/system/cfg/libc` |

The standard image carries only the mlibc configuration overlay; the LLVM
tree is development-image-only ([build-llvm.md](build-llvm.md)).

Three of these locations are compiled in, which matters when relocating
anything:

1. the clang driver's Motor toolchain paths (`Motor.cpp`, a single
   `/devtools/llvm` prefix) — baked into both the host cross clang and the
   native multicall;
2. the native driver's config-file directory
   (`-DCLANG_CONFIG_FILE_SYSTEM_DIR=/devtools/cfg/llvm`, a cmake cache
   entry); and
3. mlibc's `MLIBC_SYSCONFDIR`, injected as `"/system/cfg/libc"` through the
   Motor meson cross-file. Every functional config reader in mlibc —
   `resolv.conf`, `hosts`, `protocols`, `passwd`/`group`, `shells`,
   `localtime`, `shadow` — and the `_PATH_*` macros route through it, so libc
   configuration lives at `/system/cfg/libc/resolv.conf`,
   `/system/cfg/libc/hosts`, and so on. Deliberately *not* implemented as a
   path rewrite inside the sysdep `open()`, which would silently capture a
   program's own `/etc` accesses.

## Versioning

mlibc is pinned by `MOTOR_MLIBC_REV` in `src/toolchain-versions.sh`. The
local runtime closure — `moto-rt`, `moto-sys`, `moto-rt-cabi`, and the
workspace inputs that affect their build — enters `MOTOR_ASSEMBLY_KEY`, so a
libc or shim change selects a new assembly rather than mutating an existing
one. The rules and procedures are in [toolchain.md](toolchain.md).
