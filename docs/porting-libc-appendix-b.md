# Appendix B — M1, step by step

> Part of the Motor OS libc porting guide — main: [porting-libc-by-fable.md](porting-libc-by-fable.md); appendices: [A: M0 toolchain](porting-libc-appendix-a.md) · [B: M1 shim](porting-libc-appendix-b.md) · [C: M2 mlibc](porting-libc-appendix-c.md) · [D: M3 stdio+malloc](porting-libc-appendix-d.md) · [E: M4 filesystem](porting-libc-appendix-e.md) · [F: M5 threads+TLS](porting-libc-appendix-f.md)

> **Status: complete** (2026-07-02) — `m1` prints "all tests passed" on Motor OS;
> kernel `libc_tcb` change verified by `full-test.sh`. The emutls control-struct
> ABI is certified against LLVM main @ `6d1ca7202`.

M1 delivers, in dependency order: (1) the `libc_tcb` UTCB field (kernel), (2) the
`moto-rt-cabi` staticlib — the C-ABI shim over the RT.VDSO, including
`__emutls_get_address` and `__cxa_thread_atexit` — plus its hand-written `moto_rt.h`,
(3) compiler-rt builtins for the triple with `emutls.c.o` removed, (4) an `m1.c` smoke
test that exercises all of it (including C `_Thread_local` across two threads) in a VM.

Environment (extends A.0's):

```bash
export SYSROOT=$MOTORH/motor-sysroot     # staging sysroot; created below
```

All shim signatures below were verified against the tree at `RT_VERSION = 16`. Error
convention across the whole shim: **negative return = `-(moto ErrorCode)`** (the raw
Motor error, `moto-rt/src/error.rs` — *not* Linux errno; the errno translation happens
later, in mlibc sysdeps, per the main guide, §3.4). Non-negative = success value.

### B.1 Kernel: the `libc_tcb` UTCB field

Two files, in this repo. `src/sys/lib/moto-sys/src/shared_mem.rs` — append to
`UserThreadControlBlock` (after `name_bytes`, keeping every existing offset stable):

```diff
     pub current_cpu: core::sync::atomic::AtomicU32,
     pub reserved0: [u8; 3],
     pub name_len: u8,
     pub name_bytes: [u8; crate::MAX_THREAD_NAME_LEN],
+
+    /// The C library's thread control block pointer (pthread self).
+    /// Owned by userspace; the kernel only zeroes it at thread start.
+    /// Present iff kernel_version >= 2. Offset: fs:0x58.
+    pub libc_tcb: u64,
 }
+
+// The C library hard-codes this offset in its thread-pointer accessor
+// (e.g. `mov %fs:0x58, %rax`); keep it pinned.
+const _: () =
+    assert!(core::mem::offset_of!(UserThreadControlBlock, libc_tcb) == 0x58);
```

`src/sys/kernel/src/uspace/process.rs`, in `init_user_tcb()` (~line 1188):

```diff
-            user_tcb.kernel_version = 1;
+            user_tcb.kernel_version = 2;
             user_tcb.user_version = 0;
             ...
             user_tcb.name_bytes = [0; 32];
+            user_tcb.libc_tcb = 0;
```

Why this is safe without recompiling userspace: the kernel places the UTCB at
`stack_top - size_of::<UserThreadControlBlock>()` and points `%fs` at it
(`process.rs:1173`), so growing the struct moves the block, not the field offsets —
existing binaries (including the prebuilt Rust std, which never sees this struct)
are unaffected. `kernel_version >= 2` is the userspace feature probe.

Rebuild and verify at ladder level 4 (kernel changed): `make all -j$(nproc) && make
img`, boot, run `/sys/tests/systest`.

### B.2 The shim crate: `src/sys/lib/moto-rt-cabi`

Register it in `src/sys/Cargo.toml` under the `# system libraries` group:

```diff
   "lib/moto-rt",
+  "lib/moto-rt-cabi",
   "lib/moto-stats",
```

`src/sys/lib/moto-rt-cabi/Cargo.toml`:

```toml
[package]
name = "moto-rt-cabi"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["staticlib"]
test = false

[dependencies]
# `libc` feature: compiles moto-rt/src/libc.rs, whose memcpy/memmove/memset/memcmp
# and __stack_chk_fail land in our archive — C code needs them and compiler-rt
# builtins do not provide mem*. Revisit at M2 if mlibc ships its own mem*.
moto-rt  = { path = "../moto-rt", features = ["libc"] }
moto-sys = { path = "../moto-sys" }   # default features = userspace
```

`src/lib.rs` — scaffolding plus the full M1 surface. This is complete, not a sketch;
`mod emutls` / `mod cxa` are in B.3.

> **Implemented in-tree** at `src/sys/lib/moto-rt-cabi/` — the tree is authoritative.
> Deltas vs. the listing below, forced by workspace clippy
> (`clippy::not_unsafe_ptr_arg_deref` is deny-by-default): every pointer-consuming
> export (`moto_rt_log`, `_fill_random_bytes`, `_realloc`, `_dealloc`, `_open`,
> `_read`, `_write`, `_futex_*`, `_tls_set`) is `pub unsafe extern "C"` — the C ABI
> is unchanged; the crate carries `#![allow(clippy::missing_safety_doc)]` (the safety
> contract is moto_rt.h); `PAGE_SIZE` references
> `moto_sys::sys_mem::PAGE_SIZE_SMALL` instead of a literal 4096; and the fs group
> additionally exports `moto_rt_mkdir(path, len) -> i32` — needed because `/sys/tmp`
> does not exist on a fresh image (found at the first M1 run; Rust std's temp-dir
> users `create_dir_all` it on demand too).

```rust
//! moto-rt-cabi: C-ABI surface over the RT.VDSO (via moto-rt), for mlibc & friends.
#![no_std]

extern crate alloc;

mod cxa;
mod emutls;

use core::alloc::Layout;

// ---- Rust runtime scaffolding (staticlib has no host runtime) ----------------

struct VdsoAlloc;
unsafe impl core::alloc::GlobalAlloc for VdsoAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 { moto_rt::alloc::alloc(l) }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 { moto_rt::alloc::alloc_zeroed(l) }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) { unsafe { moto_rt::alloc::dealloc(p, l) } }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        unsafe { moto_rt::alloc::realloc(p, l, n) }
    }
}
#[global_allocator]
static ALLOC: VdsoAlloc = VdsoAlloc;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    moto_rt::error::log_panic(info);
    moto_rt::process::exit(-1)
}

fn err64(e: moto_rt::Error) -> i64 {
    let code: moto_rt::ErrorCode = e.into();
    -(code as i64)
}

fn str_arg<'a>(p: *const u8, len: usize) -> Result<&'a str, i64> {
    let bytes = unsafe { core::slice::from_raw_parts(p, len) };
    core::str::from_utf8(bytes).map_err(|_| -(moto_rt::E_INVALID_ARGUMENT as i64))
}

// ---- init / process / misc ----------------------------------------------------

/// MUST be the first moto_rt_* call in the process (fills in the VDSO vtable).
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_start() { moto_rt::init(); }

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_version() -> u64 { moto_rt::RT_VERSION }

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_proc_exit(code: i32) -> ! { moto_rt::process::exit(code) }

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_log(msg: *const u8, len: usize) {
    if let Ok(s) = str_arg(msg, len) { moto_rt::error::log_to_kernel(s); }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_fill_random_bytes(buf: *mut u8, len: usize) {
    moto_rt::fill_random_bytes(unsafe { core::slice::from_raw_parts_mut(buf, len) });
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_num_cpus() -> usize { moto_rt::num_cpus() }

// ---- heap (VDSO allocator; NOT for mlibc's malloc — that sits on vm_map) ------

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_alloc(size: usize, align: usize) -> *mut u8 {
    moto_rt::alloc::alloc(Layout::from_size_align(size, align).unwrap())
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_alloc_zeroed(size: usize, align: usize) -> *mut u8 {
    moto_rt::alloc::alloc_zeroed(Layout::from_size_align(size, align).unwrap())
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_realloc(p: *mut u8, size: usize, align: usize, new_size: usize) -> *mut u8 {
    unsafe { moto_rt::alloc::realloc(p, Layout::from_size_align(size, align).unwrap(), new_size) }
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_dealloc(p: *mut u8, size: usize, align: usize) {
    unsafe { moto_rt::alloc::dealloc(p, Layout::from_size_align(size, align).unwrap()) }
}

// ---- raw anonymous pages (the one place we go below the VDSO, to moto-sys) ----

const PAGE_SIZE: u64 = 4096; // moto_sys::sys_mem::PAGE_SIZE_SMALL

/// Maps R+W anonymous pages; returns the address, or -(error code).
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_vm_map(num_bytes: usize) -> i64 {
    use moto_sys::SysMem;
    let pages = (num_bytes as u64).div_ceil(PAGE_SIZE).max(1);
    match SysMem::map(
        moto_sys::SysHandle::SELF,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
        u64::MAX, u64::MAX, PAGE_SIZE, pages,
    ) {
        Ok(addr) => addr as i64,
        Err(code) => -(code as i64),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_vm_unmap(addr: u64) -> i32 {
    match moto_sys::SysMem::free(addr) { Ok(()) => 0, Err(code) => -(code as i32) }
}

// ---- fs (M1: the printf/file-io minimum; grows at M2/M4) ----------------------

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_open(path: *const u8, path_len: usize, opts: u32) -> i64 {
    let path = match str_arg(path, path_len) { Ok(s) => s, Err(e) => return e };
    match moto_rt::fs::open(path, opts) { Ok(fd) => fd as i64, Err(e) => err64(e) }
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_read(fd: i32, buf: *mut u8, n: usize) -> i64 {
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, n) };
    match moto_rt::fs::read(fd, buf) { Ok(sz) => sz as i64, Err(e) => err64(e) }
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_write(fd: i32, buf: *const u8, n: usize) -> i64 {
    let buf = unsafe { core::slice::from_raw_parts(buf, n) };
    match moto_rt::fs::write(fd, buf) { Ok(sz) => sz as i64, Err(e) => err64(e) }
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_seek(fd: i32, offset: i64, whence: u8) -> i64 {
    match moto_rt::fs::seek(fd, offset, whence) { Ok(pos) => pos as i64, Err(e) => err64(e) }
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_close(fd: i32) -> i32 {
    match moto_rt::fs::close(fd) { Ok(()) => 0, Err(e) => err64(e) as i32 }
}

// ---- time ----------------------------------------------------------------------

/// Monotonic nanoseconds since boot.
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_mono_nanos() -> u64 {
    moto_rt::time::since_system_start().as_nanos().min(u64::MAX as u128) as u64
}
/// Wall-clock nanoseconds since the UNIX epoch (truncated to u64).
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_real_nanos() -> u64 {
    moto_rt::time::SystemTime::now().as_u128().min(u64::MAX as u128) as u64
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_sleep_nanos(nanos: u64) {
    let deadline = moto_rt::time::Instant::now() + core::time::Duration::from_nanos(nanos);
    moto_rt::thread::sleep_until(deadline);
}

// ---- futex ----------------------------------------------------------------------

/// timeout_nanos == u64::MAX means "no timeout". Returns 1 = woken, 0 = timed out.
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_futex_wait(addr: *const u32, expected: u32, timeout_nanos: u64) -> i32 {
    let futex = unsafe { &*(addr as *const core::sync::atomic::AtomicU32) };
    let timeout = (timeout_nanos != u64::MAX)
        .then(|| core::time::Duration::from_nanos(timeout_nanos));
    moto_rt::futex_wait(futex, expected, timeout) as i32
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_futex_wake(addr: *const u32) -> i32 {
    moto_rt::futex_wake(unsafe { &*(addr as *const core::sync::atomic::AtomicU32) }) as i32
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_futex_wake_all(addr: *const u32) {
    moto_rt::futex_wake_all(unsafe { &*(addr as *const core::sync::atomic::AtomicU32) })
}

// ---- key-based TLS (VDSO) — pthread_key_* maps 1:1 onto this -------------------

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_tls_create(dtor: Option<unsafe extern "C" fn(*mut u8)>) -> usize {
    moto_rt::tls::create(dtor)
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_tls_set(key: usize, value: *mut u8) {
    unsafe { moto_rt::tls::set(key, value) }
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_tls_get(key: usize) -> *mut u8 {
    unsafe { moto_rt::tls::get(key) }
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_tls_destroy(key: usize) {
    unsafe { moto_rt::tls::destroy(key) }
}

// ---- the libc TCB slot (B.1; future mlibc THREAD_SELF = `mov %fs:0x58, %rax`) --

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_tcb_set(val: *mut u8) {
    let utcb = moto_sys::UserThreadControlBlock::get_mut();
    assert!(utcb.kernel_version >= 2, "kernel lacks UTCB.libc_tcb (need kernel_version >= 2)");
    utcb.libc_tcb = val as usize as u64;
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_tcb_get() -> *mut u8 {
    moto_sys::UserThreadControlBlock::get().libc_tcb as usize as *mut u8
}

// ---- threads ---------------------------------------------------------------------

/// Returns the (small, positive) thread handle, or -(error code).
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_thread_spawn(
    thread_fn: extern "C" fn(u64), stack_size: usize, arg: u64,
) -> i64 {
    match moto_rt::thread::spawn(thread_fn, stack_size, arg) {
        Ok(handle) => handle as i64,
        Err(e) => err64(e),
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_thread_join(handle: u64) -> i32 {
    match moto_rt::thread::join(handle) { Ok(()) => 0, Err(e) => err64(e) as i32 }
}
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_thread_yield() { moto_rt::thread::yield_now() }
```

### B.3 `emutls.rs` and `cxa.rs` — the TLS heart of the port

Design recap (main guide, §3.3): one VDSO TLS key holds a per-thread growable slot array; each
`_Thread_local` variable lazily gets a process-wide 1-based index and per-thread
storage. The VDSO runs key destructors at thread exit (`rt.vdso/src/rt_tls.rs`,
tolerating reinsertion), which is what frees the storage and runs C++ dtors. The
control-struct layout must match clang's `__emutls_v.*` lowering
(`llvm/lib/CodeGen/LowerEmuTLS.cpp`): `{ size, align, index, default_value }`, all
pointer-sized. `m1.c` (B.7) is the ABI test.

`src/sys/lib/moto-rt-cabi/src/emutls.rs`:

```rust
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Must match clang's __emutls_v.<name> layout exactly.
#[repr(C)]
pub struct EmutlsControl {
    size: usize,
    align: usize,
    /// 0 = no index assigned yet; written only via atomics (we are the only accessor).
    index: AtomicUsize,
    /// Initial-value template, or null for zero-init.
    default_value: *const u8,
}

static NEXT_INDEX: AtomicUsize = AtomicUsize::new(1);
static EMUTLS_KEY: AtomicUsize = AtomicUsize::new(0); // 0 = key not created yet

type Slots = Vec<Option<(usize /* ptr */, Layout)>>;

unsafe extern "C" fn slots_dtor(p: *mut u8) {
    if p.is_null() { return; }
    let slots = unsafe { Box::from_raw(p as *mut Slots) };
    for (ptr, layout) in slots.iter().flatten() {
        unsafe { alloc::alloc::dealloc(*ptr as *mut u8, *layout) };
    }
}

fn emutls_key() -> usize {
    let k = EMUTLS_KEY.load(Ordering::Acquire);
    if k != 0 { return k; }
    let new_key = moto_rt::tls::create(Some(slots_dtor));
    match EMUTLS_KEY.compare_exchange(0, new_key, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => new_key,
        Err(winner) => { unsafe { moto_rt::tls::destroy(new_key) }; winner }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __emutls_get_address(control: *mut EmutlsControl) -> *mut u8 {
    let control = unsafe { &*control };

    let mut index = control.index.load(Ordering::Acquire);
    if index == 0 {
        let candidate = NEXT_INDEX.fetch_add(1, Ordering::Relaxed);
        index = match control.index.compare_exchange(
            0, candidate, Ordering::AcqRel, Ordering::Acquire,
        ) {
            Ok(_) => candidate,
            Err(winner) => winner, // lost the race; `candidate` becomes an unused gap
        };
    }

    let key = emutls_key();
    let mut slots_ptr = unsafe { moto_rt::tls::get(key) } as *mut Slots;
    if slots_ptr.is_null() {
        slots_ptr = Box::into_raw(Box::new(Slots::new()));
        unsafe { moto_rt::tls::set(key, slots_ptr as *mut u8) };
    }
    let slots = unsafe { &mut *slots_ptr };
    if slots.len() < index {
        slots.resize(index, None);
    }
    let slot = &mut slots[index - 1];
    if slot.is_none() {
        let layout =
            Layout::from_size_align(control.size.max(1), control.align.max(1)).unwrap();
        let p = if control.default_value.is_null() {
            unsafe { alloc::alloc::alloc_zeroed(layout) }
        } else {
            let p = unsafe { alloc::alloc::alloc(layout) };
            unsafe { core::ptr::copy_nonoverlapping(control.default_value, p, control.size) };
            p
        };
        assert!(!p.is_null());
        *slot = Some((p as usize, layout));
    }
    slot.as_ref().unwrap().0 as *mut u8
}
```

`src/sys/lib/moto-rt-cabi/src/cxa.rs` — C++ `thread_local` destructors (clang emits
`__cxa_thread_atexit` calls under emulated TLS too). Same key pattern; the list runs
LIFO via its key destructor at thread exit. A dtor registering another dtor creates a
fresh list, which the VDSO's exit loop picks up on its next iteration:

```rust
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

type CxaDtor = unsafe extern "C" fn(*mut u8);
type DtorList = Vec<(CxaDtor, usize)>;

static CXA_KEY: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn run_dtors(p: *mut u8) {
    if p.is_null() { return; }
    let mut list = unsafe { Box::from_raw(p as *mut DtorList) };
    while let Some((dtor, obj)) = list.pop() {
        unsafe { dtor(obj as *mut u8) };
    }
}

fn cxa_key() -> usize {
    let k = CXA_KEY.load(Ordering::Acquire);
    if k != 0 { return k; }
    let new_key = moto_rt::tls::create(Some(run_dtors));
    match CXA_KEY.compare_exchange(0, new_key, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => new_key,
        Err(winner) => { unsafe { moto_rt::tls::destroy(new_key) }; winner }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_thread_atexit(
    dtor: CxaDtor, obj: *mut u8, _dso_symbol: *mut u8,
) -> i32 {
    let key = cxa_key();
    let mut list_ptr = unsafe { moto_rt::tls::get(key) } as *mut DtorList;
    if list_ptr.is_null() {
        list_ptr = Box::into_raw(Box::new(DtorList::new()));
        unsafe { moto_rt::tls::set(key, list_ptr as *mut u8) };
    }
    unsafe { &mut *list_ptr }.push((dtor, obj as usize));
    0
}
```

Known limitation to carry forward (not an M1 blocker): dtors run on *thread* exit;
`main` returning ends the process via `proc_exit` without unwinding the main thread's
TLS. Revisit when mlibc's `exit()` lands (M2), which should drain the main thread's
keys before `moto_rt_proc_exit`.

### B.4 `moto_rt.h`

Hand-written, staged into `$SYSROOT/usr/include/moto_rt.h`. Complete for the M1
surface:

```c
/* moto_rt.h — C ABI over the Motor OS RT.VDSO (via the moto-rt-cabi staticlib).
 * Error convention: negative return = -(moto error code); these are MOTOR codes
 * (moto-rt/src/error.rs), not POSIX errno. Non-negative = success value. */
#ifndef MOTO_RT_H
#define MOTO_RT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MOTO_RT_VERSION 16u

/* Motor error codes (subset; see moto-rt/src/error.rs). */
#define MOTO_E_OK               0
#define MOTO_E_NOT_READY        3
#define MOTO_E_NOT_IMPLEMENTED  4
#define MOTO_E_INVALID_ARGUMENT 7
#define MOTO_E_OUT_OF_MEMORY    8
#define MOTO_E_NOT_ALLOWED      9
#define MOTO_E_NOT_FOUND        10
#define MOTO_E_TIMED_OUT        12
#define MOTO_E_BAD_HANDLE       17

/* open() flags (moto-rt/src/fs.rs). */
#define MOTO_O_READ       (1u << 0)
#define MOTO_O_WRITE      (1u << 1)
#define MOTO_O_APPEND     (1u << 2)
#define MOTO_O_TRUNCATE   (1u << 3)
#define MOTO_O_CREATE     (1u << 4)
#define MOTO_O_CREATE_NEW (1u << 5)
#define MOTO_O_NONBLOCK   (1u << 6)

/* seek() whence (moto-rt/src/fs.rs). */
#define MOTO_SEEK_SET 0
#define MOTO_SEEK_CUR 1
#define MOTO_SEEK_END 2

/* stdio fds. */
#define MOTO_FD_STDIN  0
#define MOTO_FD_STDOUT 1
#define MOTO_FD_STDERR 2

/* init / process / misc */
void     moto_rt_start(void);              /* MUST be the first call */
uint64_t moto_rt_version(void);            /* == MOTO_RT_VERSION      */
_Noreturn void moto_rt_proc_exit(int32_t code);
void     moto_rt_log(const uint8_t *msg, size_t len);
void     moto_rt_fill_random_bytes(uint8_t *buf, size_t len);
size_t   moto_rt_num_cpus(void);

/* VDSO heap (paired: never mix with another allocator's free) */
void *moto_rt_alloc(size_t size, size_t align);
void *moto_rt_alloc_zeroed(size_t size, size_t align);
void *moto_rt_realloc(void *p, size_t size, size_t align, size_t new_size);
void  moto_rt_dealloc(void *p, size_t size, size_t align);

/* raw anonymous pages (for the libc allocator) */
int64_t moto_rt_vm_map(size_t num_bytes);  /* addr or -err */
int32_t moto_rt_vm_unmap(uint64_t addr);

/* fs */
int64_t moto_rt_open(const uint8_t *path, size_t path_len, uint32_t opts);
int64_t moto_rt_read(int32_t fd, uint8_t *buf, size_t n);
int64_t moto_rt_write(int32_t fd, const uint8_t *buf, size_t n);
int64_t moto_rt_seek(int32_t fd, int64_t offset, uint8_t whence);
int32_t moto_rt_close(int32_t fd);
int32_t moto_rt_mkdir(const uint8_t *path, size_t path_len);
int32_t moto_rt_is_terminal(int32_t fd); /* 1 = tty, 0 = not (or bad fd) */

/* time */
uint64_t moto_rt_mono_nanos(void);         /* monotonic, since boot   */
uint64_t moto_rt_real_nanos(void);         /* wall clock, UNIX epoch  */
void     moto_rt_sleep_nanos(uint64_t nanos);

/* futex (u64 max timeout = infinite); 1 = woken, 0 = timed out */
int32_t moto_rt_futex_wait(const uint32_t *addr, uint32_t expected,
                           uint64_t timeout_nanos);
int32_t moto_rt_futex_wake(const uint32_t *addr);
void    moto_rt_futex_wake_all(const uint32_t *addr);

/* key-based TLS (VDSO); dtors run at thread exit */
size_t moto_rt_tls_create(void (*dtor)(void *));
void   moto_rt_tls_set(size_t key, void *value);
void  *moto_rt_tls_get(size_t key);
void   moto_rt_tls_destroy(size_t key);

/* the libc TCB slot (UTCB.libc_tcb, fs:0x58; needs kernel_version >= 2) */
void  moto_rt_tcb_set(void *tcb);
void *moto_rt_tcb_get(void);

/* threads */
int64_t moto_rt_thread_spawn(void (*thread_fn)(uint64_t), size_t stack_size,
                             uint64_t arg);            /* handle or -err */
int32_t moto_rt_thread_join(uint64_t handle);
void    moto_rt_thread_yield(void);

/* provided for the compiler, not for direct use:
 *   void *__emutls_get_address(void *control);
 *   int __cxa_thread_atexit(void (*dtor)(void *), void *obj, void *dso); */

#ifdef __cplusplus
}
#endif
#endif /* MOTO_RT_H */
```

### B.5 Build the shim and stage the sysroot

```bash
cd $MOTOR/src/sys/lib/moto-rt-cabi
cargo +dev-x86_64-unknown-motor build --target x86_64-unknown-motor --release

mkdir -p $SYSROOT/usr/lib $SYSROOT/usr/include
cp $MOTOR/src/sys/target/x86_64-unknown-motor/release/libmoto_rt_cabi.a $SYSROOT/usr/lib/
cp $MOTOR/src/sys/lib/moto-rt-cabi/moto_rt.h $SYSROOT/usr/include/

# Sanity: the exports are there, exactly once.
$B/llvm-nm $SYSROOT/usr/lib/libmoto_rt_cabi.a 2>/dev/null | grep -w -e moto_rt_start \
    -e __emutls_get_address -e __cxa_thread_atexit -e memcpy
```

(Target objects are PIC by default per the Rust target spec — no extra RUSTFLAGS.
If the final clang link later fails on an undefined Rust-runtime symbol, fix it by
*adding* the missing definition to the shim crate, not by loosening link flags.)

### B.6 compiler-rt builtins (emutls removed)

```bash
cd $LLVM_SRC
cmake -S compiler-rt/lib/builtins -B build-builtins -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
  -DCMAKE_C_COMPILER=$B/clang \
  -DCMAKE_C_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_ASM_COMPILER=$B/clang \
  -DCMAKE_ASM_COMPILER_TARGET=x86_64-unknown-motor \
  -DCMAKE_AR=$B/llvm-ar -DCMAKE_RANLIB=$B/llvm-ranlib -DCMAKE_NM=$B/llvm-nm \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
  -DCOMPILER_RT_BAREMETAL_BUILD=ON
ninja -C build-builtins

BUILTINS=$(find build-builtins -name 'libclang_rt.builtins*.a' | head -1)

# Exactly one __emutls_get_address in the system: compiler-rt's must be absent.
# Under COMPILER_RT_BAREMETAL_BUILD=ON, emutls.c is not built at all (verified);
# if the grep below finds it anyway (config drift), delete the member:
$B/llvm-ar t "$BUILTINS" | grep emutls && $B/llvm-ar d "$BUILTINS" emutls.c.o
$B/llvm-nm "$BUILTINS" 2>/dev/null | grep __emutls && echo "STILL THERE — BAD"

cp "$BUILTINS" $SYSROOT/usr/lib/libclang_rt.builtins-x86_64.a
```

(The `x86_64-unknown-motor.cfg` config file auto-applies to these compiles too —
that's fine and wanted: builtins get `-ffreestanding` and emulated-TLS defaults.)

### B.7 The M1 test program

`m1.c` — exercises every subsystem, most importantly the emutls ABI across two
threads with both a zero-initialized and a template-initialized `_Thread_local`:

```c
#include <stdint.h>
#include "moto_rt.h"

static void out(const char *s) {
    size_t n = 0; while (s[n]) n++;
    moto_rt_write(MOTO_FD_STDOUT, (const uint8_t *)s, n);
}
static _Noreturn void fail(int code, const char *msg) {
    out("M1 FAIL: "); out(msg); out("\n");
    moto_rt_proc_exit(code);
}

static _Thread_local int      tl_init = 7;  /* template-init path */
static _Thread_local long     tl_zero;      /* zero-init path     */
static uint32_t done;                       /* futex              */
static int      thread_err;

static void thread_fn(uint64_t arg) {
    if (arg != 123)               { thread_err = 1; goto wake; }
    if (tl_init != 7)             { thread_err = 2; goto wake; } /* fresh copy */
    if (tl_zero != 0)             { thread_err = 3; goto wake; }
    if (moto_rt_tcb_get() != 0)   { thread_err = 4; goto wake; } /* fresh slot */
    tl_init = 100;
    if (tl_init != 100)           { thread_err = 5; goto wake; }
wake:
    __atomic_store_n(&done, 1, __ATOMIC_RELEASE);
    moto_rt_futex_wake(&done);
}

void motor_start(void) {
    moto_rt_start();                                   /* must be first */
    if (moto_rt_version() != MOTO_RT_VERSION) fail(10, "RT_VERSION mismatch");
    out("M1: shim up\n");

    /* heap */
    uint8_t *p = moto_rt_alloc(64, 16);
    if (!p) fail(11, "alloc");
    for (int i = 0; i < 64; i++) p[i] = (uint8_t)i;
    moto_rt_dealloc(p, 64, 16);

    /* raw pages */
    int64_t addr = moto_rt_vm_map(3 * 4096);
    if (addr <= 0) fail(12, "vm_map");
    ((volatile uint8_t *)addr)[0] = 1;
    ((volatile uint8_t *)addr)[3 * 4096 - 1] = 1;
    if (moto_rt_vm_unmap((uint64_t)addr) != 0) fail(13, "vm_unmap");

    /* key-based TLS */
    size_t key = moto_rt_tls_create(0);
    moto_rt_tls_set(key, (void *)0xabcd);
    if (moto_rt_tls_get(key) != (void *)0xabcd) fail(14, "tls get/set");

    /* libc TCB slot (kernel B.1) */
    int dummy;
    if (moto_rt_tcb_get() != 0) fail(15, "tcb not zero-initialized");
    moto_rt_tcb_set(&dummy);
    if (moto_rt_tcb_get() != &dummy) fail(16, "tcb get/set");

    /* emutls, main thread */
    if (tl_zero != 0 || tl_init != 7) fail(17, "emutls init values");
    tl_init = 10; tl_zero = 5;

    /* emutls + tcb isolation in a second thread */
    int64_t h = moto_rt_thread_spawn(thread_fn, 256 * 1024, 123);
    if (h < 0) fail(18, "thread_spawn");
    while (__atomic_load_n(&done, __ATOMIC_ACQUIRE) == 0)
        moto_rt_futex_wait(&done, 0, UINT64_MAX);
    if (moto_rt_thread_join((uint64_t)h) != 0) fail(19, "thread_join");
    if (thread_err) fail(20 + thread_err, "in-thread check (see thread_err)");
    if (tl_init != 10 || tl_zero != 5) fail(30, "emutls not thread-isolated");

    /* futex timeout + monotonic time + sleep */
    uint64_t t0 = moto_rt_mono_nanos();
    uint32_t never = 0;
    if (moto_rt_futex_wait(&never, 0, 50 * 1000 * 1000) != 0) fail(31, "futex timeout");
    moto_rt_sleep_nanos(10 * 1000 * 1000);
    uint64_t t1 = moto_rt_mono_nanos();
    if (t1 - t0 < 60 * 1000 * 1000) fail(32, "monotonic clock too fast");

    /* fs round-trip under /sys/tmp — which does NOT exist on a fresh image;
     * create it first (ignore -13 AlreadyInUse). The in-tree m1.c also has a
     * fail_err() helper that prints the moto error code in decimal. */
    const char tmpdir[] = "/sys/tmp";
    int32_t mrc = moto_rt_mkdir((const uint8_t *)tmpdir, sizeof tmpdir - 1);
    if (mrc != 0 && mrc != -13) fail(39, "mkdir /sys/tmp");
    const char path[] = "/sys/tmp/m1.txt";
    int64_t fd = moto_rt_open((const uint8_t *)path, sizeof path - 1,
                              MOTO_O_CREATE | MOTO_O_READ | MOTO_O_WRITE);
    if (fd < 0) fail(33, "open");
    if (moto_rt_write((int32_t)fd, (const uint8_t *)"hello", 5) != 5) fail(34, "fwrite");
    if (moto_rt_seek((int32_t)fd, 0, MOTO_SEEK_SET) != 0) fail(35, "seek");
    uint8_t rb[8];
    if (moto_rt_read((int32_t)fd, rb, 8) != 5 || rb[0] != 'h') fail(36, "fread");
    if (moto_rt_close((int32_t)fd) != 0) fail(37, "close");

    /* entropy */
    uint8_t rnd[16] = {0};
    moto_rt_fill_random_bytes(rnd, 16);
    int nz = 0; for (int i = 0; i < 16; i++) nz |= rnd[i];
    if (!nz) fail(38, "entropy all zeros");

    out("M1: all tests passed\n");
    moto_rt_proc_exit(0);
}
```

Build and audit (shim **before** builtins on the link line — both could satisfy
leftover symbols, the shim must win):

```bash
$B/clang --target=x86_64-unknown-motor -O2 -I$SYSROOT/usr/include m1.c \
    $SYSROOT/usr/lib/libmoto_rt_cabi.a \
    $SYSROOT/usr/lib/libclang_rt.builtins-x86_64.a -o m1

$B/llvm-readelf -l m1 | grep -w TLS && echo "PT_TLS PRESENT — emutls broke" || true
$B/llvm-readelf -r m1 | grep -v R_X86_64_RELATIVE | grep R_X86_64 || echo "relocs OK"
```

### B.8 Run it on Motor OS

Same flow as A.8: `cp m1 $MOTOR/img_files/motor-os/bin/`, `make img`, boot, run `m1`.
Expected output:

```
M1: shim up
M1: all tests passed
```

Any failure exits with the distinct code from `fail(...)`, which rush prints as
`[m1] exited with status N`; failures with a moto error attached also print it in
decimal (`fail_err`).

### B.9 M1 exit criteria

- [ ] Kernel `libc_tcb` change in (B.1) landed; full-image build boots; `systest`
      passes (kernel was touched — ladder level 4 is mandatory).
- [ ] `libmoto_rt_cabi.a` + `moto_rt.h` staged in `$SYSROOT`; `llvm-nm` shows
      `moto_rt_start`, `__emutls_get_address`, `__cxa_thread_atexit`, `memcpy`.
- [ ] Builtins archive staged with `emutls.c.o` deleted (B.6 verification).
- [ ] `m1` prints `M1: all tests passed` in the VM — this certifies the emutls
      control-struct ABI against the pinned clang; re-run it on any toolchain bump.
- [ ] Commit: kernel+moto-sys change and the new crate as separate commits
      (`kernel: add UTCB.libc_tcb for the C library`, `moto-rt-cabi: C-ABI shim over
      the RT.VDSO`).
