# Appendix C — M2, step by step

> Part of the Motor OS libc porting guide — main: [porting-libc-by-fable.md](porting-libc-by-fable.md); appendices: [A: M0 toolchain](porting-libc-appendix-a.md) · [B: M1 shim](porting-libc-appendix-b.md) · [C: M2 mlibc](porting-libc-appendix-c.md) · [D: M3 stdio+malloc](porting-libc-appendix-d.md) · [E: M4 filesystem](porting-libc-appendix-e.md) · [F: M5 threads+TLS](porting-libc-appendix-f.md) · [G: M6 sockets](porting-libc-appendix-g.md) · [H: M7 poll + real program](porting-libc-appendix-h.md)

> **Status: complete** (2026-07-02) — `m2 foo bar` runs on Motor OS: printf/argv/env/
> malloc output correct, exit codes correct (0 with args, 42 without).

M2 is the mlibc bring-up: a `sysdeps/motor` port compiled as a static `libc.a`, a
Motor `crt1`, and a real C program (`printf`, `malloc`, argv/env, exit codes) running
in a VM. All facts below were verified against the mlibc checkout at
`/home/posk/motorh/mlibc`, commit `368a00fa` (upstream `managarm/mlibc` master) —
**pin that commit** on a `motor` branch.

> **mlibc's sysdep API (as of this pin).** Older descriptions of mlibc use
> `int sys_open(...)`-style free functions; current mlibc replaced those with a
> **templated functor API**: a sysdep
> is a specialization `mlibc::Sysdeps<Tag>::operator()` with the signature fixed by
> `options/internal/include/mlibc/sysdep-signatures.hpp`; the port declares which
> tags it implements in its own `mlibc/sysdeps.hpp`; unimplemented optional sysdeps
> resolve to `NoImpl` and return `ENOSYS` at runtime via `sysdep_or_enosys<>`.
> Mandatory tags are enforced by `static_assert`s in `all-sysdeps.hpp`:
> Exit, FutexWait, FutexWake, Open, Read, Write, Seek, Close, ClockGet, LibcLog,
> LibcPanic, AnonAllocate, AnonFree, VmMap, VmUnmap, TcbSet.
> The reference port to copy is **`sysdeps/demo`** (the mlibc-book port; RISC-V, but
> the structure is exactly what we need).

Environment (extends A.0/B.0):

```bash
export MLIBC=$MOTORH/mlibc
```

Host prerequisites verified: `meson 1.3.2`, `ninja 1.11.1` (mlibc wants C++23 —
fine for our clang). `meson subprojects download` needs **network** once (frigg,
freestnd-c/cxx-hdrs wraps).

### C.1 Shim v2 (motor-os repo): args/env/tid + weak mem*

Five additions to `src/sys/lib/moto-rt-cabi`, then rebuild + restage (B.5) —
args/env, tid, `moto_rt_is_terminal(fd) -> i32` (wraps the VDSO's
`fs_is_terminal`; backs mlibc's `Isatty`), and the weak-mem* change:

**(1) argv/env for crt1** — flat, NULL-terminated arrays allocated once from the
VDSO heap (never freed; process lifetime). In `lib.rs`:

```rust
/// Builds a NULL-terminated char** block (pointers first, then the string
/// bytes, each NUL-terminated) in a single VDSO-heap allocation. Never freed.
fn c_strv(strings: alloc::vec::Vec<alloc::string::String>) -> *mut *mut u8 {
    let n = strings.len();
    let mut bytes = 0usize;
    for s in &strings {
        bytes += s.len() + 1;
    }
    let total = (n + 1) * size_of::<*mut u8>() + bytes;
    let block = moto_rt::alloc::alloc(Layout::from_size_align(total, 8).unwrap());
    assert!(!block.is_null());
    let ptrs = block as *mut *mut u8;
    let mut str_p = unsafe { block.add((n + 1) * size_of::<*mut u8>()) };
    for (i, s) in strings.iter().enumerate() {
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), str_p, s.len());
            *str_p.add(s.len()) = 0;
            *ptrs.add(i) = str_p;
            str_p = str_p.add(s.len() + 1);
        }
    }
    unsafe { *ptrs.add(n) = core::ptr::null_mut() };
    ptrs
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_get_args(argc: *mut i32) -> *mut *mut u8 {
    let args = moto_rt::process::args();
    unsafe { *argc = args.len() as i32 };
    c_strv(args)
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_get_env() -> *mut *mut u8 {
    let mut v = alloc::vec::Vec::new();
    for (k, val) in moto_rt::process::env() {
        v.push(alloc::format!("{k}={val}"));
    }
    c_strv(v)
}
```

**(2) tid** — mlibc's `FutexTid` sysdep (used to cache the TID in the TCB):

```rust
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_tid() -> u64 {
    moto_sys::UserThreadControlBlock::get().self_tid
}
```

**(3) `moto_rt.h`** — add:

```c
char   **moto_rt_get_args(int32_t *argc); /* NULL-terminated; VDSO heap, never free */
char   **moto_rt_get_env(void);           /* NULL-terminated "KEY=VALUE" strings    */
uint64_t moto_rt_tid(void);
```

**(4) mem\* become weak** — `src/sys/lib/moto-rt/src/libc.rs`: add
`#[linkage = "weak"]` to `memcpy`/`memmove`/`memset`/`memcmp` (the file already does
this for `__stack_chk_fail`; `feature(linkage)` is already enabled). Why: mlibc's
`libc.a` ships its own strong `mem*`, and at the final link both archives get object
files loaded — two strong definitions is a link error, strong-over-weak is not. `m1`
(which links without `libc.a`) keeps working off the weak ones. This is the "revisit
at M2" note from B.2, resolved.

Rebuild shim + kernel-side nothing; restage per B.5; re-run `m1` in a VM once (it
must still pass).

### C.2 mlibc: branch, subprojects

```bash
cd $MLIBC
git switch -c motor 368a00fa
meson subprojects download        # network; fetches frigg & freestanding headers
```

### C.3 Register the port and create the `sysdeps/motor` tree

**Root `meson.build`** — extend the OS chain (next to the `demo` branch, ~line 294):

```meson
elif host_machine.system() == 'motor'
	subdir('sysdeps/motor')
```

**Tree layout** (mirrors `sysdeps/demo`):

```
sysdeps/motor/
  meson.build
  include/mlibc/sysdeps.hpp      # tag declarations (C.3b)
  include/abi-bits/*.h           # symlink farm -> abis/linux (like demo's)
  generic/entry.cpp              # byte-for-byte copy of sysdeps/demo/entry.cpp
  generic/sysdeps.cpp            # C.5
  crt-src/crt1.c                 # C.6
```

**abi-bits symlink farm** — same file list as demo, retargeted one level deeper:

```bash
mkdir -p $MLIBC/sysdeps/motor/include/abi-bits
cd $MLIBC/sysdeps/motor/include/abi-bits
for f in $(ls ../../../demo/include/abi-bits); do
    ln -s ../../../../abis/linux/$f $f
done
```

**`sysdeps/motor/meson.build`** — copy `sysdeps/demo/meson.build` verbatim, then
change exactly three things: the `rtld_sources`/`libc_sources` file lists
(`generic/sysdeps.cpp`, plus `generic/entry.cpp` in `libc_sources`; there is no
`syscall.cpp`), and the crt target's input from `crt1.S` to `crt-src/crt1.c` (the
`custom_target` command already runs `c_compiler.cmd_array()`, which works for `.c`).
Keep `sysdep_supported_options = { 'posix': true }` and the whole
`install_headers(...abi-bits...)` block as-is.

**C.3b `include/mlibc/sysdeps.hpp`**:

```cpp
#pragma once

#include <mlibc/sysdep-signatures.hpp>

namespace mlibc {

struct MotorSysdepTags :
	LibcPanic,
	LibcLog,
	Exit,
	TcbSet,
	FutexTid,
	FutexWait,
	FutexWake,
	AnonAllocate,
	AnonFree,
	VmMap,
	VmUnmap,
	Open,
	Read,
	Write,
	Seek,
	Close,
	ClockGet,
	Isatty,
	GetEntropy
{};

template <typename Tag>
using Sysdeps = SysdepOf<MotorSysdepTags, Tag>;

struct SysdepTraits {
	static constexpr bool usesRtNetlink = false;
};

} // namespace mlibc
```

### C.4 The one cross-cutting mlibc patch: the thread pointer

`options/internal/x86_64-include/mlibc/thread.hpp` hardcodes `movq %%fs:0` — the
glibc-style self-pointer Motor cannot provide (the kernel owns `%fs` → UTCB). Gate it
on our target macro (`__motor__`, defined by the A.3 clang patch):

```diff
 inline Tcb *get_current_tcb() {
 	uintptr_t ptr;
+#if defined(__motor__)
+	// Motor OS: the kernel owns %fs (it points at the UTCB); the libc TCB
+	// pointer lives in UTCB.libc_tcb at fs:0x58 (motor-os shared_mem.rs).
+	asm volatile ("movq %%fs:0x58, %0" : "=r"(ptr));
+#else
 	asm volatile ("movq %%fs:0, %0" : "=r"(ptr));
+#endif
 	return reinterpret_cast<Tcb *>(ptr);
 }
```

Related but needing **no** patch: mlibc asserts `Tcb.stackCanary` is at offset 0x28
because the compiler emits `fs:0x28` canary reads — on Motor `fs:0x28` is
`UTCB.stack_guard`, which the **kernel** initializes, so `-fstack-protector` works;
mlibc's own canary field is simply never the one being read. `Sysdeps<TcbSet>` stores
the Tcb pointer via `moto_rt_tcb_set` (C.5), and `interpreterMain` calls it early
with a static `earlyTcb` — exactly the flow our fs:0x58 slot supports.

### C.5 `generic/sysdeps.cpp`

Complete for M2 (signatures copied from `sysdep-signatures.hpp` at the pinned
commit — re-verify on any mlibc bump):

```cpp
#include <abi-bits/errno.h>
#include <abi-bits/fcntl.h>
#include <abi-bits/vm-flags.h>
#include <bits/ensure.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <moto_rt.h>
#include <string.h>
#include <time.h>

namespace {

// moto ErrorCode (moto-rt/src/error.rs) -> Linux errno. Keep in sync.
int moto_to_errno(int64_t e) {
	if (e >= 0)
		return 0;
	switch (-e) {
	case 3:  return EAGAIN;     // NotReady
	case 4:  return ENOSYS;     // NotImplemented
	case 7:  return EINVAL;     // InvalidArgument
	case 8:  return ENOMEM;     // OutOfMemory
	case 9:  return EPERM;      // NotAllowed
	case 10: return ENOENT;     // NotFound
	case 12: return ETIMEDOUT;  // TimedOut
	case 13: return EEXIST;     // AlreadyInUse
	case 14: return EIO;        // UnexpectedEof
	case 15: return EINVAL;     // InvalidFilename
	case 16: return ENOTDIR;    // NotADirectory
	case 17: return EBADF;      // BadHandle
	case 18: return EFBIG;      // FileTooLarge
	case 19: return ENOTCONN;   // NotConnected
	case 20: return ENOSPC;     // StorageFull
	case 21: return EIO;        // InvalidData
	default: return EIO;
	}
}

} // namespace

namespace mlibc {

void Sysdeps<LibcLog>::operator()(const char *msg) {
	moto_rt_log(reinterpret_cast<const uint8_t *>(msg), strlen(msg));
}

void Sysdeps<LibcPanic>::operator()() {
	sysdep<LibcLog>("!!! mlibc panic !!!");
	moto_rt_proc_exit(-1);
}

void Sysdeps<Exit>::operator()(int status) { moto_rt_proc_exit(status); }

int Sysdeps<TcbSet>::operator()(void *pointer) {
	moto_rt_tcb_set(pointer); // UTCB.libc_tcb (fs:0x58); read by get_current_tcb()
	return 0;
}

pid_t Sysdeps<FutexTid>::operator()() { return static_cast<pid_t>(moto_rt_tid()); }

int Sysdeps<FutexWait>::operator()(int *pointer, int expected, const struct timespec *time) {
	uint64_t timeout = UINT64_MAX; // no timeout
	if (time)
		timeout = static_cast<uint64_t>(time->tv_sec) * 1000000000ul
		        + static_cast<uint64_t>(time->tv_nsec);
	int woken = moto_rt_futex_wait(
	    reinterpret_cast<const uint32_t *>(pointer), static_cast<uint32_t>(expected), timeout);
	if (!woken && time)
		return ETIMEDOUT;
	return 0;
}

int Sysdeps<FutexWake>::operator()(int *pointer, bool all) {
	if (all)
		moto_rt_futex_wake_all(reinterpret_cast<const uint32_t *>(pointer));
	else
		moto_rt_futex_wake(reinterpret_cast<const uint32_t *>(pointer));
	return 0;
}

int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
	int64_t r = moto_rt_vm_map(size);
	if (r < 0)
		return moto_to_errno(r);
	*pointer = reinterpret_cast<void *>(r);
	return 0;
}

int Sysdeps<AnonFree>::operator()(void *pointer, size_t) {
	return moto_to_errno(moto_rt_vm_unmap(reinterpret_cast<uint64_t>(pointer)));
}

int Sysdeps<VmMap>::operator()(void *, size_t size, int, int flags, int fd, off_t, void **window) {
	if (!(flags & MAP_ANONYMOUS) || fd != -1)
		return ENOSYS; // no file-backed mmap on Motor (platform property)
	return sysdep<AnonAllocate>(size, window);
}

int Sysdeps<VmUnmap>::operator()(void *pointer, size_t size) {
	return sysdep<AnonFree>(pointer, size);
}

int Sysdeps<Open>::operator()(const char *pathname, int flags, mode_t, int *fd) {
	uint32_t opts = 0;
	switch (flags & O_ACCMODE) {
	case O_RDONLY: opts = MOTO_O_READ; break;
	case O_WRONLY: opts = MOTO_O_WRITE; break;
	case O_RDWR:   opts = MOTO_O_READ | MOTO_O_WRITE; break;
	default:       return EINVAL;
	}
	if (flags & O_APPEND)   opts |= MOTO_O_APPEND;
	if (flags & O_TRUNC)    opts |= MOTO_O_TRUNCATE;
	if (flags & O_CREAT)    opts |= MOTO_O_CREATE;
	if (flags & O_EXCL)     opts |= MOTO_O_CREATE_NEW;
	if (flags & O_NONBLOCK) opts |= MOTO_O_NONBLOCK;
	int64_t r = moto_rt_open(reinterpret_cast<const uint8_t *>(pathname),
	                         strlen(pathname), opts);
	if (r < 0)
		return moto_to_errno(r);
	*fd = static_cast<int>(r);
	return 0;
}

int Sysdeps<Read>::operator()(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	int64_t r = moto_rt_read(fd, reinterpret_cast<uint8_t *>(buf), count);
	if (r < 0)
		return moto_to_errno(r);
	*bytes_read = r;
	return 0;
}

int Sysdeps<Write>::operator()(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
	int64_t r = moto_rt_write(fd, reinterpret_cast<const uint8_t *>(buf), count);
	if (r < 0)
		return moto_to_errno(r);
	*bytes_written = r;
	return 0;
}

int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t *new_offset) {
	uint8_t w;
	switch (whence) {
	case SEEK_SET: w = MOTO_SEEK_SET; break;
	case SEEK_CUR: w = MOTO_SEEK_CUR; break;
	case SEEK_END: w = MOTO_SEEK_END; break;
	default:       return EINVAL;
	}
	int64_t r = moto_rt_seek(fd, offset, w);
	if (r < 0) {
		// The VDSO's seek returns BadHandle (17) for any open fd that is not
		// a regular file (rt.vdso/src/rt_fs.rs downcast) — for the stdio fds,
		// which always exist on Motor, that means "non-seekable stream", which
		// POSIX (and mlibc's fd_file::determine_type) spells ESPIPE.
		if (-r == 17 /* BadHandle */ && fd >= 0 && fd <= 2)
			return ESPIPE;
		return moto_to_errno(r);
	}
	*new_offset = r;
	return 0;
}

int Sysdeps<Close>::operator()(int fd) { return moto_to_errno(moto_rt_close(fd)); }

int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
	uint64_t ns;
	switch (clock) {
	case CLOCK_MONOTONIC: ns = moto_rt_mono_nanos(); break;
	case CLOCK_REALTIME:  ns = moto_rt_real_nanos(); break;
	default:              return EINVAL;
	}
	*secs = static_cast<time_t>(ns / 1000000000ul);
	*nanos = static_cast<long>(ns % 1000000000ul);
	return 0;
}

int Sysdeps<Isatty>::operator()(int fd) {
	// moto_rt_is_terminal wraps the VDSO's fs_is_terminal, which honors the
	// STDIO_IS_TERMINAL env convention for fds 0..2.
	return moto_rt_is_terminal(fd) ? 0 : ENOTTY;
}

int Sysdeps<GetEntropy>::operator()(void *buffer, size_t length) {
	moto_rt_fill_random_bytes(reinterpret_cast<uint8_t *>(buffer), length);
	return 0;
}

} // namespace mlibc
```

### C.6 `crt-src/crt1.c`

The Motor delta from every other port: the loader passes **nothing** — no
argc/argv/auxv on the stack — and the VDSO must be initialized first. Verified
simplification: in static builds, mlibc's `__dlapi_enter` → `interpreterMain`
**derives the program headers from `__ehdr_start` itself** (rtld `main.cpp`), so the
auxv only needs `AT_SECURE`/`AT_RANDOM`/`AT_PAGESZ`. The file is deliberately
self-contained (the crt `custom_target` compiles it with no include paths):

```c
/* Motor OS crt1. Self-contained: compiled without include paths.
 * The entry-stack block below is what mlibc's __dlapi_enter parses:
 *   [argc][argv...][NULL][envp...][NULL][auxv (id,value) pairs][AT_NULL].
 * It lives in motor_start's frame, which never returns — mlibc keeps
 * pointers into it for the process lifetime, which is therefore fine. */
typedef unsigned long uptr;

extern void moto_rt_start(void);
extern char **moto_rt_get_args(int *argc);
extern char **moto_rt_get_env(void);
extern void moto_rt_fill_random_bytes(unsigned char *buf, unsigned long len);

extern void __mlibc_entry(uptr *entry_stack, int (*main_fn)(int, char **, char **));
extern int main(int, char **, char **);

#define AT_NULL   0
#define AT_PAGESZ 6
#define AT_SECURE 23
#define AT_RANDOM 25

void motor_start(void) {
	moto_rt_start(); /* fill the VDSO vtable; must be first */

	int argc = 0;
	char **argv = moto_rt_get_args(&argc);
	char **envp = moto_rt_get_env();
	int envc = 0;
	while (envp[envc])
		envc++;

	static unsigned char random_bytes[16];
	moto_rt_fill_random_bytes(random_bytes, sizeof random_bytes);

	uptr block[1 + (argc + 1) + (envc + 1) + 8];
	uptr *p = block;
	*p++ = (uptr)argc;
	for (int i = 0; i < argc; i++)
		*p++ = (uptr)argv[i];
	*p++ = 0;
	for (int i = 0; i < envc; i++)
		*p++ = (uptr)envp[i];
	*p++ = 0;
	*p++ = AT_PAGESZ; *p++ = 4096;
	*p++ = AT_SECURE; *p++ = 0;
	*p++ = AT_RANDOM; *p++ = (uptr)random_bytes;
	*p++ = AT_NULL;   *p++ = 0;

	__mlibc_entry(block, main);
	__builtin_trap(); /* __mlibc_entry calls exit() */
}
```

`generic/entry.cpp` is demo's file unchanged: `__mlibc_entry` runs
`__dlapi_enter(entry_stack)` (ctors, TCB via `TcbSet`, startup data) then
`exit(main(...))`.

### C.7 Cross file and the two builds

`$MLIBC/ci/motor.cross-file` (absolute paths; `--target` is mandatory — our clang's
default target is the host). Build `llvm-strip` first if missing:
`ninja -C $LLVM_SRC/build llvm-strip`.

```ini
[binaries]
c = ['/home/posk/motorh/llvm-project/build/bin/clang', '--target=x86_64-unknown-motor']
cpp = ['/home/posk/motorh/llvm-project/build/bin/clang++', '--target=x86_64-unknown-motor']
ar = '/home/posk/motorh/llvm-project/build/bin/llvm-ar'
strip = '/home/posk/motorh/llvm-project/build/bin/llvm-strip'

[host_machine]
system = 'motor'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'

[built-in options]
# -D_GNU_SOURCE: mlibc's own sources use GNU-guarded declarations (NSIG,
# AT_EMPTY_PATH, execvpe, strlcpy, ...). g++ predefines _GNU_SOURCE in C++
# mode, which is why gcc-based ports don't notice; clang++ does not for
# non-glibc targets like ours. Verified failure without it.
c_args = ['-I/home/posk/motorh/motor-sysroot/usr/include', '-D_GNU_SOURCE']
cpp_args = ['-I/home/posk/motorh/motor-sysroot/usr/include', '-D_GNU_SOURCE']

[properties]
needs_exe_wrapper = true
```

(The `-I` is for `<moto_rt.h>` in `sysdeps.cpp`. Meson's compiler sanity checks
link a small exe — our auto-loaded `x86_64-unknown-motor.cfg` makes that a
`-static-pie -nostdlib` link, which succeeds; `needs_exe_wrapper` stops meson from
trying to *run* it.)

**Headers-only first** (validates ABI/meson wiring in seconds):

```bash
cd $MLIBC
meson setup --cross-file ci/motor.cross-file --prefix=/usr \
    -Dheaders_only=true build-headers
DESTDIR=$SYSROOT ninja -C build-headers install
ls $SYSROOT/usr/include/stdio.h $SYSROOT/usr/include/abi-bits/errno.h  # both exist
```

**Then the real thing.** One prerequisite (verified failure without it): mlibc's
non-headers build asserts that the compiler runtime exists at clang's **per-target
resource-dir path**, so stage the B.6 builtins archive there under the name clang
reports:

```bash
RD=$LLVM_SRC/build/lib/clang/23/lib/x86_64-unknown-motor   # 23 = clang major
mkdir -p $RD
cp $SYSROOT/usr/lib/libclang_rt.builtins-x86_64.a $RD/libclang_rt.builtins.a
```

(This also lets the clang driver locate builtins on its own later.)

```bash
meson setup --cross-file ci/motor.cross-file --prefix=/usr \
    -Ddefault_library=static -Dbuild_tests=false build
ninja -C build
DESTDIR=$SYSROOT ninja -C build install   # libc.a, crt1.o, all headers
ls $SYSROOT/usr/lib/libc.a $SYSROOT/usr/lib/crt1.o
```

`default_library=static` defines `MLIBC_STATIC_BUILD` and skips `ld.so` — permanent
on Motor, not a shortcut.

### C.8 The M2 test program

`$MOTOR/src/tests/libc/m2.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv, char **envp) {
	printf("M2: hello from mlibc on Motor OS\n");
	printf("M2: argc = %d\n", argc);
	for (int i = 0; i < argc; i++)
		printf("M2: argv[%d] = %s\n", i, argv[i]);
	int envc = 0;
	while (envp[envc])
		envc++;
	printf("M2: %d env vars\n", envc);

	char *p = malloc(1000);
	if (!p)
		return 11;
	strcpy(p, "M2: malloc works");
	puts(p);
	free(p);

	return argc == 3 ? 0 : 42; /* run as `m2 foo bar` to exercise argv */
}
```

Build and audit (link order matters: `libc.a` before the shim — mlibc's strong
`mem*` must beat the shim's weak ones; shim before builtins):

```bash
cd $MOTOR/src/tests/libc
$B/clang --target=x86_64-unknown-motor -O2 -isystem $SYSROOT/usr/include m2.c \
    $SYSROOT/usr/lib/crt1.o \
    $SYSROOT/usr/lib/libc.a \
    $SYSROOT/usr/lib/libmoto_rt_cabi.a \
    $SYSROOT/usr/lib/libclang_rt.builtins-x86_64.a -o m2

$B/llvm-readelf -l m2 | grep -w TLS && echo "PT_TLS — BAD" || echo "no PT_TLS"
$B/llvm-readelf -r m2 | grep R_X86_64 | grep -cv R_X86_64_RELATIVE   # must be 0
```

### C.9 Run on Motor OS + exit criteria

`cp m2 $MOTOR/img_files/motor-os/bin/`, `make img`, boot, then:

```
rush:/$ m2 foo bar
M2: hello from mlibc on Motor OS
M2: argc = 3
M2: argv[0] = m2        (or the full path — record what Motor passes)
M2: argv[1] = foo
M2: argv[2] = bar
M2: <N> env vars
M2: malloc works
```

Exit 0 (silent); run plain `m2` to see the deliberate `exited with status 42`.

- [ ] Shim v2 staged; `m1` still passes in a VM (weak-mem* regression check).
- [ ] mlibc `motor` branch: sysdeps/motor + the `thread.hpp` patch, committed on top
      of pinned `368a00fa`.
- [ ] Headers-only and static builds both succeed; `libc.a` + `crt1.o` in `$SYSROOT`.
- [ ] `m2` audit clean; runs on Motor with correct argv/env/exit codes.
- [ ] Watch the kernel log during `m2` for `sysdep_or_enosys` warnings — that list
      is the to-do input for M3/M4.

Known M2 pitfalls, pre-answered:

- **Duplicate `memcpy` at link** → the C.1(4) weak-linkage change was skipped.
- **`Unimplemented sysdep called!` compile error** → some enabled option group calls
  a `sysdep<Tag>` (not `sysdep_or_enosys`) we don't implement; either add the tag +
  a stub implementation or check whether that option group should be off.
- **Endless `mlibc: fwrite() I/O errors are not handled` and no program output**
  (hit at first M2 run) → mlibc's `fd_file::determine_type` probes streams with
  `Seek(fd, 0, SEEK_CUR)` and requires **ESPIPE** for non-seekable ones; the VDSO
  returns BadHandle for any open non-file fd, which naively maps to EBADF — a hard
  error. Fixed in `Sysdeps<Seek>` (C.5): BadHandle on fds 0–2 → `ESPIPE`.
- **Crash before `main`** → almost certainly TCB: verify the `thread.hpp` patch is
  in and `m1`'s tcb tests still pass (fs:0x58 end-to-end).
- **`frigg` fetch fails** → `meson subprojects download` needs network; vendor the
  subprojects dir if the build machine is offline.
