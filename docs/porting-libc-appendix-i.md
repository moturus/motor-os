# Appendix I — M8, step by step

> **Status: complete** (2026-07-04) — `m8` prints "all tests passed" on Motor
> OS: all ten sections (iostreams incl. `%.17g` goldens, containers,
> to/from_chars, RTTI, statics guard race, `std::thread`, `thread_local`
> dtors, `<random>`, `<filesystem>` incl. `remove_all`, aligned new), then
> `M8: global dtor ran` on stderr and a clean exit; m2–m7 + `lua m7.lua`
> pass against the same rebuilt libc. Cost: six small LLVM patches, one
> VDSO fix (readdir prefetch), and a three-act static-link exit-path saga
> (`__dso_handle`=0, cxa-LIFO inversion, FILE* demoted to dynamic init) —
> all in the Pitfalls of I.7.

> Part of the Motor OS libc porting guide — main: [porting-libc-by-fable.md](porting-libc-by-fable.md); appendices: [A: M0 toolchain](porting-libc-appendix-a.md) · [B: M1 shim](porting-libc-appendix-b.md) · [C: M2 mlibc](porting-libc-appendix-c.md) · [D: M3 stdio+malloc](porting-libc-appendix-d.md) · [E: M4 filesystem](porting-libc-appendix-e.md) · [F: M5 threads+TLS](porting-libc-appendix-f.md) · [G: M6 sockets](porting-libc-appendix-g.md) · [H: M7 poll + real program](porting-libc-appendix-h.md) · [I: M8 C++ stack](porting-libc-appendix-i.md)

M8 is the C++ stack: **libc++abi + libc++ cross-built against our mlibc,
static, no-exceptions (EH-enabled is M10), RTTI on, threads on** — proven by
`m8` (a C++17/20 test suite exercising iostreams, containers, `std::thread`,
`thread_local` objects, RTTI, `<random>`, and optionally `<filesystem>`).
Everything below verified against the in-tree llvm-project (clang 23,
branch `motor`) and mlibc `368a00fa` + our motor sysdeps.

The headline ground-truth result first: **mlibc already provides everything
libc++'s locale layer needs** (I.2.3) — mlibc was built to host libc++ on
managarm, and it shows. The expected friction is not missing libc surface but
CMake cross-compilation ergonomics (I.2.5) and link-order details (I.4).

---

## I.1 Deliverables

| # | Piece | Where |
|---|---|---|
| 1 | Runtimes build dir (`libcxxabi;libcxx`, static, no-EH) | `~/motorh/llvm-project/build-motor-cxx` |
| 2 | Installed into the sysroot: `usr/include/c++/v1`, `usr/lib/libc++.a`, `usr/lib/libc++abi.a` | `$SYSROOT` |
| 3 | A documented `clang++` link recipe for Motor C++ programs | this file, I.4 |
| 4 | `m8.cpp` — C++17/20 suite | `src/tests/libc/` |
| 5 | `m8` staged; m2–m7 + lua still pass | `img_files/motor-os/bin/` |

## I.2 Ground truth (verified in-tree)

### I.2.1 What the compiler defines

`clang --target=x86_64-unknown-motor -dM -E` yields **only `__motor__` and
`__ELF__`** as platform macros — no `__linux__`, no `__unix__`. Consequences,
all verified in libc++ sources:

- libc++'s per-platform dispatches take their **generic/fallback branches**.
  The important one is locale (I.2.2); the rest (chrono → `clock_gettime`,
  new/delete → `malloc`/`aligned_alloc`) are already generic-POSIX shaped.
- Nothing anywhere in libc++/libc++abi knows the OS — which is fine for a
  static, single-config build, and means **no LLVM patches are expected for
  M8** (the target patch from M0 is enough).

### I.2.2 The locale path libc++ will take

`libcxx/include/__locale_dir/locale_base_api.h:110-140` dispatches on
`__APPLE__` / `__FreeBSD__` / `__linux__` / `_LIBCPP_LIBC_PICOLIBC` / … and
lands, for us, in the final `#else`: the **generic POSIX-2008 locale API**
(`newlocale`/`freelocale`/`setlocale`/`uselocale` + `*_l` functions) plus
`bsd_locale_fallbacks.h`, which synthesizes `snprintf_l`/`asprintf_l`-style
helpers by saving/restoring the thread locale with `uselocale`. This is the
path that decides whether `<iostream>`/`<locale>` build at all.

### I.2.3 mlibc has the whole required-symbol list

The required functions are enumerated in a comment block at the top of
`locale_base_api.h:30-105`. Diffed against mlibc (all in the **posix/ansi
options we already build** — the glibc option is *not* needed):

| libc++ needs | mlibc provides (verified grep) |
|---|---|
| `newlocale`/`freelocale`/`uselocale`/`setlocale`, `localeconv` | `options/posix/generic/posix_locale.cpp`, ansi locale |
| `strtof_l`/`strtod_l`/`strtold_l` | `posix_stdlib.cpp:489,497` + `strtold_l` same file |
| `toupper_l`/`tolower_l`, `is*_l`, `isw*_l`, `tow*_l` | ctype/wctype (used since M2) |
| `strcoll_l`/`strxfrm_l`, `wcscoll_l`/`wcsxfrm_l` | `posix_string.cpp` |
| `strftime_l`, `nl_langinfo` | `options/posix/generic/time.cpp` |
| `btowc`/`wctob`, `mbrtowc`, `mbsnrtowcs`/`wcsnrtombs`, `wcrtomb`, `mbrlen`, `mbsrtowcs` | `options/ansi/generic/wchar.cpp` |
| `vasprintf`/`vsnprintf` (for the BSD fallbacks) | `options/ansi/generic/stdio.cpp` |
| `aligned_alloc`, `posix_memalign` (aligned `operator new`) | `options/ansi/generic/stdlib.cpp` |
| `pthread_*` incl. `pthread_once`, keys, rwlock, cond | M5 + `pthread.cpp:701` |
| `clock_gettime(CLOCK_MONOTONIC)` (steady_clock) | `ClockGet` (M2) |
| `getentropy` (`std::random_device`) | `GetEntropy` sysdep (M2) |

Note mlibc's locale *data* is C/POSIX only — `std::locale("de_DE")` will fail
(throw-path → abort under no-EH); programs must stay in the default locale.
That's correct behavior for this image, not a gap to fix.

### I.2.4 libc++ version & knobs

This is a current libc++ (config via `__config_site` `_LIBCPP_HAS_*` 01
macros; `_LIBCPP_LIBC_PICOLIBC`-style custom-libc support exists). The
reference config to crib from is in-tree:
`libcxx/cmake/caches/Armv7M-picolibc.cmake` — a static, `CMAKE_SYSTEM_NAME=
Generic`, `CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY` runtimes build on a
tiny libc. Ours differs by: threads **on**, monotonic clock **on**, random
device **on**, wide chars **on**, exceptions **off** (picolibc's cache has
them on), no libunwind at all.

### I.2.5 Known CMake hazards (plan for them, don't discover them)

- `CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY` is required (we can't link
  executables without our explicit crt1/libs line) — but it makes
  `check_symbol_exists`-style probes **compile-only**, so they can report
  false positives. Any "detected" symbol that mlibc lacks surfaces later as
  an undefined reference when linking `m8` — budget an iteration loop of
  *cmake flag → rebuild → relink m8*.
- The known instance: `__cxa_thread_atexit_impl`. mlibc does **not** export
  it (our `__cxa_thread_atexit` lives in the shim, VDSO-integrated, M5-
  tested). Force `-DLIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL=OFF`; see I.4 for
  the resulting duplicate-definition question.
- Runtimes CMake likes to probe for `-lpthread`/`-lrt`/`-ldl`: everything is
  inside `libc.a` on Motor. Expect to set `LIBCXX_HAS_PTHREAD_LIB=OFF`,
  `LIBCXX_HAS_RT_LIB=OFF` (and friends) if probes misfire.

## I.3 Build recipe

```bash
LLVM=/home/posk/motorh/llvm-project
B=$LLVM/build/bin
SYSROOT=/home/posk/motorh/motor-sysroot

cmake -G Ninja -S $LLVM/runtimes -B $LLVM/build-motor-cxx \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=$B/clang -DCMAKE_CXX_COMPILER=$B/clang++ \
  -DCMAKE_C_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_CXX_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_C_FLAGS="-isystem $SYSROOT/usr/include" \
  -DCMAKE_CXX_FLAGS="-isystem $SYSROOT/usr/include" \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DLLVM_ENABLE_RUNTIMES="libcxxabi;libcxx" \
  -DLLVM_USE_LINKER=lld \
  \
  -DLIBCXXABI_ENABLE_SHARED=OFF -DLIBCXXABI_ENABLE_STATIC=ON \
  -DLIBCXXABI_ENABLE_EXCEPTIONS=OFF \
  -DLIBCXXABI_ENABLE_THREADS=ON \
  -DLIBCXXABI_USE_COMPILER_RT=ON \
  -DLIBCXXABI_USE_LLVM_UNWINDER=OFF \
  -DLIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL=OFF \
  -DLIBCXXABI_ENABLE_ASSERTIONS=OFF \
  \
  -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC=ON \
  -DLIBCXX_ENABLE_EXCEPTIONS=OFF -DLIBCXX_ENABLE_RTTI=ON \
  -DLIBCXX_ENABLE_THREADS=ON -DLIBCXX_HAS_PTHREAD_API=ON \
  -DLIBCXX_ENABLE_MONOTONIC_CLOCK=ON \
  -DLIBCXX_ENABLE_RANDOM_DEVICE=ON \
  -DLIBCXX_ENABLE_WIDE_CHARACTERS=ON \
  -DLIBCXX_ENABLE_LOCALIZATION=ON \
  -DLIBCXX_ENABLE_FILESYSTEM=ON \
  -DLIBCXX_CXX_ABI=libcxxabi \
  -DLIBCXX_USE_COMPILER_RT=ON \
  -DLIBCXX_INCLUDE_BENCHMARKS=OFF -DLIBCXX_INCLUDE_TESTS=OFF

ninja -C $LLVM/build-motor-cxx cxxabi cxx
DESTDIR=$SYSROOT ninja -C $LLVM/build-motor-cxx install-cxxabi install-cxx
```

Fallback ladder if configuration or compilation fights back (drop one at a
time, re-try): `LIBCXX_ENABLE_FILESYSTEM=OFF` → `LIBCXX_ENABLE_WIDE_
CHARACTERS=OFF` → `LIBCXX_ENABLE_LOCALIZATION=OFF` (last resort — loses
`<iostream>`; the milestone can still pass on `printf`-style output, but
record it loudly). Threads/RTTI are not negotiable for M8.

Post-install check: `$SYSROOT/usr/include/c++/v1/__config_site` exists and
has `_LIBCPP_HAS_THREADS 1`, `_LIBCPP_HAS_MONOTONIC_CLOCK 1`; `llvm-nm
$SYSROOT/usr/lib/libc++.a | grep " U "` sample for unexpected undefineds
(e.g. `__cxa_thread_atexit_impl` must NOT appear).

## I.4 Link recipe + symbol-resolution notes

```bash
$B/clang++ --target=x86_64-unknown-motor -O2 -std=c++17 \
  -fno-exceptions -nostdinc++ \
  -isystem $SYSROOT/usr/include/c++/v1 \
  -isystem $SYSROOT/usr/include \
  m8.cpp \
  $SYSROOT/usr/lib/crt1.o \
  $SYSROOT/usr/lib/libc++.a $SYSROOT/usr/lib/libc++abi.a \
  $SYSROOT/usr/lib/libmoto_rt_cabi.a \
  $SYSROOT/usr/lib/libc.a \
  $SYSROOT/usr/lib/libclang_rt.builtins-x86_64.a -o m8
```

- **Order matters**: `libc++.a` → `libc++abi.a` → shim → `libc.a` → builtins.
  Undefined refs flow left to right; the C++ libs resolve their libc needs
  from the later archives.
- **`__cxa_thread_atexit`** is defined twice in this line: the shim's
  (VDSO-integrated, runs dtors inside `on_thread_exiting()`, validated at M5
  with emutls) and libc++abi's fallback (pthread-key based, built because
  `HAS_CXA_THREAD_ATEXIT_IMPL=OFF`). The linker takes the **first archive
  that satisfies the reference**. `thread_local` C++ dtor registration calls
  come from user objects, so resolution order is libc++abi first in the line
  above — if we want the shim's (we do: dtor ordering interlocks with emutls
  cleanup), either (a) move `libmoto_rt_cabi.a` before `libc++abi.a` (safe:
  the shim has no undefined C++ refs), or (b) verify libc++abi's fallback is
  compatible. Decide at implementation with `llvm-nm`; document the outcome
  here. Plan of record: **(a)**.
- `-fno-exceptions` must be on every user TU; a stray `throw` in headers
  compiles into `__libcpp_verbose_abort` (which prints via `fprintf(stderr)`
  and aborts — now survivable output thanks to M7's working `abort()`).
- Audit as always: no `PT_TLS`, 0 non-RELATIVE relocs (C++ statics with
  dynamic initializers must come out as `R_X86_64_RELATIVE`-only; a stray
  copy-reloc or TLS reloc means a config leak — catch it here, not in the
  loader).

## I.5 The gate test: `m8.cpp`

`src/tests/libc/m8.cpp`, CHECK-style like m3–m7, `-std=c++17` (sprinkle
C++20-isms clang defaults tolerate under 17? no — keep pure 17; C++20 can be
a follow-up flag test). Sections, ordered cheap-to-deep:

1. **iostream hello**: `std::cout` / `std::cerr`, `operator<<` for ints,
   doubles (`%.17g`-class formatting through the M7-fixed float machinery!),
   `std::string`, manipulators (`std::hex`, `std::setw`).
2. **Containers/algorithms**: `vector` (incl. 1M-element sort),
   `unordered_map` (hash + rehash), `map`, `string` SSO + heap growth,
   `string_view`, structured bindings, `std::optional`/`variant`/`any`,
   range-for, lambdas, `std::function`.
3. **Strings ↔ numbers**: `std::to_string`, `stoi`/`stod` (valid inputs
   only — error paths throw), `std::from_chars`/`to_chars` (int + double —
   pure libc++ code, no locale).
4. **RTTI**: virtual dispatch, `dynamic_cast` up/down/cross, `typeid().name()`
   (exercises the demangler-adjacent type_info compare).
5. **Static init/teardown**: global object with dynamic initializer +
   destructor writing a flag checked via `atexit` ordering; `static` local
   (thread-safe guard → `__cxa_guard_*` under real threads: two threads race
   a function-local static).
6. **Threads**: `std::thread` ×4 over a `std::mutex`-guarded counter,
   `std::condition_variable` ping-pong with `wait_for` timeout check,
   `std::atomic` fetch_add, `std::call_once`, `std::this_thread::sleep_for`
   (steady_clock elapsed ≥).
7. **`thread_local` C++ objects**: a `thread_local std::string` with
   observable dtor (per-thread counter) — emutls + `__cxa_thread_atexit`
   + M5 dtor machinery under the C++ ABI.
8. **`<random>`**: `std::random_device` (getentropy) seeds `mt19937`;
   distribution sanity (mean of 10k uniform ints within bounds).
9. **`<chrono>`**: steady/system clock round-trips, duration arithmetic.
10. **`<filesystem>`** (only if built): `create_directory` under `/sys/tmp`,
    `ofstream` write / `ifstream` read back, `directory_iterator` finds the
    file, `file_size`, `remove_all`. Expect `symlink`/`chmod`-flavored ops to
    fail with `error_code` — don't test them.
11. **new/delete**: scalar/array, `std::align_val_t` (over-aligned type →
    `aligned_alloc`), `unique_ptr`/`shared_ptr`/`weak_ptr` lifecycle counts.

Print `M8: all tests passed`. No `try`/`catch` anywhere (no-EH build).

## I.6 Deliberate gaps (document, defer)

- **No exceptions** until M10: any library throw-path (`std::stoi` on junk,
  `vector::at` OOB, `std::locale("xx")`) is `verbose_abort` → process death.
  m8 stays on the happy paths.
- **C/POSIX locale only** — mlibc has no locale data; `std::locale`
  construction of named locales dies (by design here).
- **`<filesystem>` partial**: no symlinks/hardlinks/permissions on Motor
  (mlibc ENOSYS) → those ops return `error_code`s; `space()` needs `statvfs`
  (likely ENOSYS); `last_write_time` setter needs `utimensat` (absent).
  Read/create/iterate/remove work (M4 sysdeps).
- **No `<regex>` in m8 v1** — nothing platform-specific in it, but it's the
  single biggest compile-time/code-size item; add later if wanted.
- **PSTL/parallel algorithms, `<print>`, modules** — out of scope.
- **C++20 as a whole** is a stretch goal; the build is `-std=c++17` first.

## I.7 Stage, run, exit criteria

Stage `m8` in `img_files/motor-os/bin/` (no image-side config needed; the
C++ libs are statically linked). User runs in the VM:

- [x] `m8` prints `M8: all tests passed` (several runs; threads + statics
      guard race is scheduling-sensitive). All ten sections including
      filesystem, plus `M8: global dtor ran` on stderr after the pass line
      (the dtor-ordering sentinel) and a clean exit.
- [x] `m8` binary audit was clean (no PT_TLS, RELATIVE-only relocs) — C++
      statics and thread_local didn't smuggle in TLS relocs.
- [x] m2–m7 + `lua m7.lua` still pass (relinked: crt1.o and libc.a both
      changed during the M8 exit-path fixes, so this sweep was load-bearing,
      not a formality).
- [x] Record: final CMake flag deltas from I.3 — see build log below;
      `__cxa_thread_atexit` resolution winner — **the shim** (link order
      puts `libmoto_rt_cabi.a` before `libc++abi.a`; `-Wl,-y` verified);
      libc++.a **2.0 MB** / libc++abi.a **0.54 MB**; m8 binary **8.9 MB**
      (`-O2`, static, RTTI on, no EH).

### Build log (2026-07-03) — implementation complete, host-side

libc++.a (1.9 MB) + libc++abi.a (0.5 MB) built and installed into the
sysroot with **everything on**: threads, monotonic clock, localization,
wide chars, random device, **and filesystem** (no fallback-ladder step was
needed). `__config_site` verified. `m8` links at 9.3 MB, audit clean
(no PT_TLS, 0 non-RELATIVE relocs), staged along with hosted-relinked
m2–m7 + lua. `__cxa_thread_atexit` resolves from the shim
(`-Wl,-y` verified) — plan-of-record (a) held.

Deltas from the I.3 recipe (the final configure adds):
`-D_GNU_SOURCE -D_DEFAULT_SOURCE` in `CMAKE_{C,CXX}_FLAGS` (mlibc guards
`realpath` behind `_DEFAULT_SOURCE`), plus `LIBCXX_HAS_PTHREAD_LIB=OFF`,
`LIBCXX_HAS_RT_LIB=OFF`, `LIBCXX_HAS_ATOMIC_LIB=OFF`,
`LIBCXXABI_HAS_PTHREAD_LIB=OFF` (see pitfall #2).

### Pitfalls found during M8 (fill as they happen)

- **`readdir` cursor dies when the app deletes the entry it just read —
  breaking `remove_all` (and `rm -r`-style code generally)** (VM:
  `remove_all("/sys/tmp/m8-dir") != 2`, followed by a separate crash, below).
  motor-fs's `get_next_entry(id)` validates `id`'s own entry block
  (`motor-fs/src/fs.rs:488`), so a cursor naming an unlinked entry errors
  out — but iterate-delete-advance is exactly what `std::filesystem::
  remove_all`, `rm -r`, and `shutil.rmtree` do. **Motor-side fix in the VDSO**
  (`rt_fs.rs`): `ReadDir` now prefetches the *successor* id before returning
  each entry (`ReadDirCursor::{NotStarted,Next,Done}`), so the cursor never
  references an entry the caller has already seen. Same number of fs round
  trips, just shifted one call earlier. Also fixes Rust
  `std::fs::read_dir`-while-deleting. Entries the caller has *not* yet seen
  can still vanish via concurrent modification — readdir doesn't have to
  survive that (unspecified per POSIX).
- **`__dso_handle` resolved to address 0 — every C++ static destructor ran
  in the wrong exit phase, and mlibc destroyed its own stdio before dtors
  that still print.** The hunt (three VM crashes, four minimal repros, and
  breadcrumbs in mlibc's exit path) is a case study: the crash presented as
  a wild vtable call in `mlibc::abstract_file::write` during `exit()`,
  reproducible with **zero** test sections but *not* with minimal
  iostream-only binaries. Breadcrumbs showed `__mlibc_do_finalize`'s
  early "plain atexit" phase — which mlibc documents as deliberately NOT
  running C++ static dtors, "since that would destroy mlibc's global
  objects including stdout" — executing `stdio_guard::~stdio_guard()` and
  `abstract_file::~abstract_file()`. Root cause: compiler-emitted
  registrations are `__cxa_atexit(dtor, obj, &__dso_handle)`; nothing in
  our link *defines* `__dso_handle` (normally crtbegin.o does, and we don't
  link crtbegin), so **lld synthesized it at the image base — address 0 for
  a static-PIE** — making `&__dso_handle == NULL` and every static dtor a
  "plain atexit" handler. mlibc's own TU dtors then tore down stdio early,
  and the first later dtor that printed (`m8`'s test-harness global dtor
  via `fprintf(stderr)`) wrote through a destroyed FILE. The minis survived
  by luck — no user dtor printed after teardown. Fix: `crt-src/crt1.c` now
  carries the conventional self-referential definition
  (`hidden void *__dso_handle = &__dso_handle;`). Every binary relinked.
  The earlier "stack overflow" readings were garbage-pointer forensics on
  freed-object memory, not real recursion.
  **Act II (same run, after the `__dso_handle` fix):** finalize phases now
  ran in the right order — but the cxa-dtor LIFO *itself* was inverted:
  in a fully static link, init_array follows link order, so the
  executable's TU constructors run *before* mlibc's, and LIFO destruction
  tears down mlibc's static `fd_file` std streams before user dtors that
  still print (mlibc's native habitat is a DSO whose init_array runs first,
  making its dtors last — static linking silently breaks that assumption).
  Fix, glibc-`_IO_cleanup`-shaped and ordering-independent: the three std
  FILE objects are now immortal (no dtor registration), the old
  `stdio_guard` static is gone, and `__mlibc_do_finalize` explicitly
  calls a new `__mlibc_flush_all_files()` after `__dlapi_exit()` — flush
  strictly after every user destructor. Upstream-worthy: any fully-static
  mlibc binary with a printing global dtor has this bug.
  **Act III (the immortalization itself regressed section 1):** the first
  attempt used `frg::eternal<fd_file>` with `FILE *stdout =
  &stdout_file.get()`. `get()` hides a `reinterpret_cast` behind a function
  call, so that initializer is **not a constant expression** — clang moved
  `stdout`/`stdin`/`stderr` from relocation-initialized `.data` into `.bss`
  plus a dynamic initializer in *libc's* TU ctor. Same link-order trap,
  opposite direction: libc++'s iostream init runs before libc's TU ctor
  and captured `stdout == NULL`; the first `std::cout <<` crashed with a
  read at `0xfffffffffffffff8` (member access off a null FILE). Diagnosed
  in seconds from the kernel's `print_backtrace` (well worth keeping
  enabled) + `addr2line`; confirmed by `objdump -t m8 | grep stdout`
  showing the symbols in `.bss`. Final fix: a `union eternal_file
  { mlibc::fd_file file; ... ~eternal_file() {} }` wrapper — the union
  dtor doesn't destroy the member (nothing registered with
  `__cxa_atexit`), and `&stdin_file.file` is a plain address constant, so
  the FILE* globals are back to load-time relocations. Audit rule learned:
  the "0 non-RELATIVE relocs" check does *not* catch a global demoted from
  static to dynamic initialization — check `.bss` migration of ABI globals
  too.
- **`remove_all` returned EINVAL: libc++ chose its `openat`-based
  implementation** — which threads real dirfds through `openat`/`fdopendir`/
  `unlinkat`, none of which Motor has (M4 gap: `Openat` is AT_FDCWD-only,
  no `fdopendir`). That implementation exists to harden against symlink
  races (CVE-2022-21658) — and Motor has no symlinks. LLVM patch #6:
  `__motor__` joins Win32/MVS in `REMOVE_ALL_USE_DIRECTORY_ITERATOR`
  (`src/filesystem/operations.cpp`), selecting the implementation the VDSO
  readdir-prefetch fix supports. Real dirfd support is an M9+ wishlist item.
- **`std::random_device` defaulted to `/dev/urandom` — Motor has no `/dev`**
  (VM: "system_error was thrown in -fno-exceptions mode … failed to open
  /dev/urandom", exit 134 in the `<random>` test). `LIBCXX_ENABLE_RANDOM_
  DEVICE=ON` only enables the *class*; the entropy *source* is chosen in
  `__configuration/platform.h` (arc4random/getentropy/fuchsia/win32, default
  `/dev/urandom`). Two patches: add `__motor__` to the `_LIBCPP_USING_
  GETENTROPY` set, and give `src/random.cpp` a `__has_include(<sys/random.h>)`
  fallback to `<unistd.h>` — the getentropy path unconditionally included
  `sys/random.h`, a Linux-ism mlibc doesn't ship (mlibc declares getentropy
  in its POSIX.1-2024 home, `unistd.h`). Both upstream-shaped.
- **`nanosleep` had no sysdep — first caller ever was
  `std::this_thread::sleep_for`** (VM, first m8 run: mlibc panic
  "Cannot continue without sys_sleep()" in the statics-guard test).
  Seven milestones of C code never called it: m5's waits are futex-based,
  m7's timeouts ride poll deadlines and `SO_RCVTIMEO`, and select-as-sleep
  goes through the poll registry. Added `Sysdeps<Sleep>` over
  `moto_rt_sleep_nanos` (uninterruptible — no signals — so the remaining
  time out-params are always zero). This also makes `sleep(3)`/`usleep`
  work for C programs.

- **The M0 clang config file still said `-ffreestanding` — C++ `main` got
  mangled** (host-side, at first m8 link: `undefined symbol: main … did you
  mean extern "C"?`). `$B/x86_64-unknown-motor.cfg` carried `-ffreestanding`
  from the pre-libc M0 days; in freestanding mode `__STDC_HOSTED__` is 0,
  C++ `main` is an ordinary (mangled) function, and `-fno-builtin` is
  implied — the latter had been quietly costing mem*/printf builtin
  optimizations for *every* Motor binary since M0. Removed from the cfg
  (appendix A.5 updated); runtimes clean-rebuilt hosted; m2–m7 + lua
  relinked hosted. The cfg is a build-dir artifact, not in git — appendix
  A.5 is its source of truth.
- **CMake static-try-compile false positives, as predicted (I.2.5)** —
  configure "found" `clock_gettime in rt` and `pthread` libs; the objects
  then carried `.deplibs` specifiers and lld failed with "unable to find
  library from dependent library specifier: rt/pthread". Fixed with the
  `*_HAS_*_LIB=OFF` quartet above.
- **libc++ platform dispatches needed two one-line LLVM patches** (both
  upstream-shaped, in the motor branch):
  `__locale_dir/locale_base_api.h` — route `__motor__` to
  `support/linux.h` (the generic `#else` pulls in legacy `ibm.h`, whose
  inline `strtod_l` wrappers collide with mlibc's real declarations);
  `__configuration/platform.h` — add `__motor__` to the
  `_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE` set (libc++ builds its own ctype
  table instead of wanting the libc's rune table).
- **`<filesystem>` referenced `::utimes`, which mlibc doesn't have — even
  though it never calls it here.** mlibc defines `UTIME_OMIT`, so libc++
  selects its `utimensat` path (mlibc has `utimensat`, ENOSYS at runtime —
  graceful `error_code`), but the unused `posix_utimes` helper in
  `src/filesystem/time_utils.h` was compiled anyway. Patched: guard the
  helper with `#if !defined(_LIBCPP_USE_UTIMENSAT)` (upstreamable).
