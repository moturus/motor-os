//! moto-rt-cabi: C-ABI surface over the RT.VDSO (via moto-rt), for mlibc & friends.
//!
//! Error convention: negative return = -(moto ErrorCode) — the raw Motor error
//! (moto-rt/src/error.rs), NOT a POSIX errno; errno translation happens in the
//! libc sysdeps. Non-negative return = success value.
//!
//! See docs/porting-libc-appendix-b.md for the design.
#![no_std]
// The safety contract of every exported function is the C ABI documented in
// moto_rt.h (valid pointer + length, etc.); per-function `# Safety` sections
// would just repeat it.
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

mod cxa;
mod emutls;

use core::alloc::Layout;

// ---- Rust runtime scaffolding (staticlib has no host runtime) ----------------

struct VdsoAlloc;
unsafe impl core::alloc::GlobalAlloc for VdsoAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        moto_rt::alloc::alloc(l)
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        moto_rt::alloc::alloc_zeroed(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { moto_rt::alloc::dealloc(p, l) }
    }
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
pub extern "C" fn moto_rt_start() {
    moto_rt::init();
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_version() -> u64 {
    moto_rt::RT_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_proc_exit(code: i32) -> ! {
    moto_rt::process::exit(code)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_log(msg: *const u8, len: usize) {
    if let Ok(s) = str_arg(msg, len) {
        moto_rt::error::log_to_kernel(s);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_fill_random_bytes(buf: *mut u8, len: usize) {
    moto_rt::fill_random_bytes(unsafe { core::slice::from_raw_parts_mut(buf, len) });
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_num_cpus() -> usize {
    moto_rt::num_cpus()
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_tid() -> u64 {
    moto_sys::UserThreadControlBlock::get().self_tid
}

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

// ---- heap (VDSO allocator; NOT for the libc malloc — that sits on vm_map) ------

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_alloc(size: usize, align: usize) -> *mut u8 {
    moto_rt::alloc::alloc(Layout::from_size_align(size, align).unwrap())
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_alloc_zeroed(size: usize, align: usize) -> *mut u8 {
    moto_rt::alloc::alloc_zeroed(Layout::from_size_align(size, align).unwrap())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_realloc(
    p: *mut u8,
    size: usize,
    align: usize,
    new_size: usize,
) -> *mut u8 {
    unsafe { moto_rt::alloc::realloc(p, Layout::from_size_align(size, align).unwrap(), new_size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_dealloc(p: *mut u8, size: usize, align: usize) {
    unsafe { moto_rt::alloc::dealloc(p, Layout::from_size_align(size, align).unwrap()) }
}

// ---- raw anonymous pages (the one place we go below the VDSO, to moto-sys) ----

const PAGE_SIZE: u64 = moto_sys::sys_mem::PAGE_SIZE_SMALL;

/// Maps R+W anonymous pages; returns the address, or -(error code).
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_vm_map(num_bytes: usize) -> i64 {
    use moto_sys::SysMem;
    let pages = (num_bytes as u64).div_ceil(PAGE_SIZE).max(1);
    match SysMem::map(
        moto_sys::SysHandle::SELF,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
        u64::MAX,
        u64::MAX,
        PAGE_SIZE,
        pages,
    ) {
        Ok(addr) => addr as i64,
        Err(code) => -(code as i64),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_vm_unmap(addr: u64) -> i32 {
    match moto_sys::SysMem::free(addr) {
        Ok(()) => 0,
        Err(code) => -(code as i32),
    }
}

// ---- fs (M1: the printf/file-io minimum; grows at M2/M4) ----------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_open(path: *const u8, path_len: usize, opts: u32) -> i64 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match moto_rt::fs::open(path, opts) {
        Ok(fd) => fd as i64,
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_read(fd: i32, buf: *mut u8, n: usize) -> i64 {
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, n) };
    match moto_rt::fs::read(fd, buf) {
        Ok(sz) => sz as i64,
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_write(fd: i32, buf: *const u8, n: usize) -> i64 {
    let buf = unsafe { core::slice::from_raw_parts(buf, n) };
    match moto_rt::fs::write(fd, buf) {
        Ok(sz) => sz as i64,
        Err(e) => err64(e),
    }
}

/// 1 = terminal, 0 = not a terminal (also 0 for invalid fds).
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_is_terminal(fd: i32) -> i32 {
    moto_rt::fs::is_terminal(fd) as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_mkdir(path: *const u8, path_len: usize) -> i32 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::mkdir(path) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_unlink(path: *const u8, path_len: usize) -> i32 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::unlink(path) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

/// NOTE: in today's VDSO rmdir aliases unlink (rt_fs.rs); we still wrap both
/// so the shim ABI tracks moto-rt's API, not the current implementation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_rmdir(path: *const u8, path_len: usize) -> i32 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::rmdir(path) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_rename(
    old_path: *const u8,
    old_len: usize,
    new_path: *const u8,
    new_len: usize,
) -> i32 {
    let old = match str_arg(old_path, old_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    let new = match str_arg(new_path, new_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::rename(old, new) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

// The C mirrors in moto_rt.h (moto_file_attr_t / moto_dir_entry_t) assume
// these exact sizes; a drift must break the build, not the runtime.
const _: () = assert!(core::mem::size_of::<moto_rt::fs::FileAttr>() == 80);
const _: () = assert!(core::mem::size_of::<moto_rt::fs::DirEntry>() == 368);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_stat(
    path: *const u8,
    path_len: usize,
    attr: *mut moto_rt::fs::FileAttr,
) -> i32 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::stat(path) {
        Ok(a) => {
            unsafe { *attr = a };
            0
        }
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_fstat(fd: i32, attr: *mut moto_rt::fs::FileAttr) -> i32 {
    match moto_rt::fs::get_file_attr(fd) {
        Ok(a) => {
            unsafe { *attr = a };
            0
        }
        Err(e) => err64(e) as i32,
    }
}

/// Returns the full cwd length; copies min(len, capacity) bytes into buf.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_getcwd(buf: *mut u8, capacity: usize) -> i64 {
    match moto_rt::fs::getcwd() {
        Ok(cwd) => {
            let bytes = cwd.as_bytes();
            let n = bytes.len().min(capacity);
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
            bytes.len() as i64
        }
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_chdir(path: *const u8, path_len: usize) -> i32 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e as i32,
    };
    match moto_rt::fs::chdir(path) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_opendir(path: *const u8, path_len: usize) -> i64 {
    let path = match str_arg(path, path_len) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match moto_rt::fs::opendir(path) {
        Ok(fd) => fd as i64,
        Err(e) => err64(e),
    }
}

/// 1 = entry written, 0 = end of directory, negative = -err.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_readdir(fd: i32, dentry: *mut moto_rt::fs::DirEntry) -> i32 {
    match moto_rt::fs::readdir(fd) {
        Ok(Some(e)) => {
            unsafe { *dentry = e };
            1
        }
        Ok(None) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_ftruncate(fd: i32, size: u64) -> i32 {
    match moto_rt::fs::truncate(fd, size) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_fsync(fd: i32) -> i32 {
    match moto_rt::fs::fsync(fd) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_seek(fd: i32, offset: i64, whence: u8) -> i64 {
    match moto_rt::fs::seek(fd, offset, whence) {
        Ok(pos) => pos as i64,
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_close(fd: i32) -> i32 {
    match moto_rt::fs::close(fd) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

// ---- net (moto-rt/src/net.rs; addresses use moto_rt::netc, NOT the Linux ABI) --

// The C mirrors in moto_rt.h (moto_sockaddr_t) assume these exact sizes.
const _: () = assert!(core::mem::size_of::<moto_rt::netc::sockaddr>() == 28);
const _: () = assert!(core::mem::size_of::<moto_rt::netc::sockaddr_in>() == 8);

fn ret0(r: moto_rt::Result<()>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

fn ret_fd(r: moto_rt::Result<moto_rt::RtFd>) -> i64 {
    match r {
        Ok(fd) => fd as i64,
        Err(e) => err64(e),
    }
}

fn ret_bool(r: moto_rt::Result<bool>) -> i32 {
    match r {
        Ok(v) => v as i32,
        Err(e) => err64(e) as i32,
    }
}

fn nanos_to_timo(nanos: u64) -> Option<core::time::Duration> {
    if nanos == u64::MAX {
        None
    } else {
        Some(core::time::Duration::from_nanos(nanos))
    }
}

fn timo_to_nanos(r: moto_rt::Result<Option<core::time::Duration>>) -> i64 {
    match r {
        Ok(None) => i64::MAX, // callers treat MAX as "none"
        Ok(Some(d)) => d.as_nanos().min(i64::MAX as u128) as i64,
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_bind(proto: u8, addr: *const moto_rt::netc::sockaddr) -> i64 {
    ret_fd(moto_rt::net::bind(proto, unsafe { &*addr }))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_listen(fd: i32, backlog: u32) -> i32 {
    ret0(moto_rt::net::listen(fd, backlog))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_accept(fd: i32, peer: *mut moto_rt::netc::sockaddr) -> i64 {
    match moto_rt::net::accept(fd) {
        Ok((fd2, addr)) => {
            unsafe { *peer = addr };
            fd2 as i64
        }
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_tcp_connect(
    addr: *const moto_rt::netc::sockaddr,
    timeout_nanos: u64,
    nonblocking: i32,
) -> i64 {
    let timeout = nanos_to_timo(timeout_nanos).unwrap_or(core::time::Duration::MAX);
    ret_fd(moto_rt::net::tcp_connect(
        unsafe { &*addr },
        timeout,
        nonblocking != 0,
    ))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_udp_connect(
    fd: i32,
    addr: *const moto_rt::netc::sockaddr,
) -> i32 {
    ret0(moto_rt::net::udp_connect(fd, unsafe { &*addr }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_socket_addr(
    fd: i32,
    out: *mut moto_rt::netc::sockaddr,
) -> i32 {
    match moto_rt::net::socket_addr(fd) {
        Ok(addr) => {
            unsafe { *out = addr };
            0
        }
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_peer_addr(fd: i32, out: *mut moto_rt::netc::sockaddr) -> i32 {
    match moto_rt::net::peer_addr(fd) {
        Ok(addr) => {
            unsafe { *out = addr };
            0
        }
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_shutdown(fd: i32, how: u8) -> i32 {
    ret0(moto_rt::net::shutdown(fd, how))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_peek(fd: i32, buf: *mut u8, n: usize) -> i64 {
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, n) };
    match moto_rt::net::peek(fd, buf) {
        Ok(sz) => sz as i64,
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_udp_recv_from(
    fd: i32,
    buf: *mut u8,
    n: usize,
    from: *mut moto_rt::netc::sockaddr,
) -> i64 {
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, n) };
    match moto_rt::net::udp_recv_from(fd, buf) {
        Ok((sz, addr)) => {
            unsafe { *from = addr };
            sz as i64
        }
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_udp_peek_from(
    fd: i32,
    buf: *mut u8,
    n: usize,
    from: *mut moto_rt::netc::sockaddr,
) -> i64 {
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, n) };
    match moto_rt::net::udp_peek_from(fd, buf) {
        Ok((sz, addr)) => {
            unsafe { *from = addr };
            sz as i64
        }
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_net_udp_send_to(
    fd: i32,
    buf: *const u8,
    n: usize,
    to: *const moto_rt::netc::sockaddr,
) -> i64 {
    let buf = unsafe { core::slice::from_raw_parts(buf, n) };
    match moto_rt::net::udp_send_to(fd, buf, unsafe { &*to }) {
        Ok(sz) => sz as i64,
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_set_nonblocking(fd: i32, nonblocking: i32) -> i32 {
    ret0(moto_rt::net::set_nonblocking(fd, nonblocking != 0))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_set_nodelay(fd: i32, v: i32) -> i32 {
    ret0(moto_rt::net::set_nodelay(fd, v != 0))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_nodelay(fd: i32) -> i32 {
    ret_bool(moto_rt::net::nodelay(fd))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_set_ttl(fd: i32, ttl: u32) -> i32 {
    ret0(moto_rt::net::set_ttl(fd, ttl))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_ttl(fd: i32) -> i64 {
    match moto_rt::net::ttl(fd) {
        Ok(v) => v as i64,
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_set_broadcast(fd: i32, v: i32) -> i32 {
    ret0(moto_rt::net::set_udp_broadcast(fd, v != 0))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_broadcast(fd: i32) -> i32 {
    ret_bool(moto_rt::net::udp_broadcast(fd))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_set_read_timeout(fd: i32, nanos: u64) -> i32 {
    ret0(moto_rt::net::set_read_timeout(fd, nanos_to_timo(nanos)))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_set_write_timeout(fd: i32, nanos: u64) -> i32 {
    ret0(moto_rt::net::set_write_timeout(fd, nanos_to_timo(nanos)))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_read_timeout(fd: i32) -> i64 {
    timo_to_nanos(moto_rt::net::read_timeout(fd))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_write_timeout(fd: i32) -> i64 {
    timo_to_nanos(moto_rt::net::write_timeout(fd))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_net_take_error(fd: i32) -> i32 {
    match moto_rt::net::take_error(fd) {
        Ok(None) => 0,
        Ok(Some(e)) => err64(e) as i32,
        Err(e) => err64(e) as i32,
    }
}

// ---- time ----------------------------------------------------------------------

/// Monotonic nanoseconds since boot.
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_mono_nanos() -> u64 {
    moto_rt::time::since_system_start()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

/// Wall-clock nanoseconds since the UNIX epoch (truncated to u64).
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_real_nanos() -> u64 {
    moto_rt::time::SystemTime::now()
        .as_u128()
        .min(u64::MAX as u128) as u64
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_sleep_nanos(nanos: u64) {
    let deadline = moto_rt::time::Instant::now() + core::time::Duration::from_nanos(nanos);
    moto_rt::thread::sleep_until(deadline);
}

// ---- poll (moto-rt/src/poll.rs: the VDSO readiness registry) --------------------

// The C mirror in moto_rt.h (moto_poll_event_t) assumes this exact size.
const _: () = assert!(core::mem::size_of::<moto_rt::poll::Event>() == 16);

/// Returns a registry fd (close with moto_rt_close) or -err.
#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_poll_new() -> i32 {
    ret_fd(moto_rt::poll::new()) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_poll_add(poll_fd: i32, source_fd: i32, token: u64, interests: u64) -> i32 {
    ret0(moto_rt::poll::add(poll_fd, source_fd, token, interests))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_poll_set(poll_fd: i32, source_fd: i32, token: u64, interests: u64) -> i32 {
    ret0(moto_rt::poll::set(poll_fd, source_fd, token, interests))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_poll_del(poll_fd: i32, source_fd: i32) -> i32 {
    ret0(moto_rt::poll::del(poll_fd, source_fd))
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_poll_wake(poll_fd: i32) -> i32 {
    ret0(moto_rt::poll::wake(poll_fd))
}

/// timeout_nanos is relative; u64::MAX = infinite. The deadline must be built
/// here, not in C: Instant's u64 payload is TSC ticks, not nanos.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_poll_wait(
    poll_fd: i32,
    timeout_nanos: u64,
    events: *mut moto_rt::poll::Event,
    events_cap: usize,
) -> i32 {
    let deadline = (timeout_nanos != u64::MAX)
        .then(|| moto_rt::time::Instant::now() + core::time::Duration::from_nanos(timeout_nanos));
    match moto_rt::poll::wait(poll_fd, events, events_cap, deadline) {
        Ok(n) => n as i32,
        Err(e) => err64(e) as i32,
    }
}

// ---- process identity ------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_getpid() -> i64 {
    moto_sys::current_pid() as i64
}

// ---- futex ----------------------------------------------------------------------

/// timeout_nanos == u64::MAX means "no timeout". Returns 1 = woken, 0 = timed out.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_futex_wait(addr: *const u32, expected: u32, timeout_nanos: u64) -> i32 {
    let futex = unsafe { &*(addr as *const core::sync::atomic::AtomicU32) };
    let timeout =
        (timeout_nanos != u64::MAX).then(|| core::time::Duration::from_nanos(timeout_nanos));
    moto_rt::futex_wait(futex, expected, timeout) as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_futex_wake(addr: *const u32) -> i32 {
    moto_rt::futex_wake(unsafe { &*(addr as *const core::sync::atomic::AtomicU32) }) as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_futex_wake_all(addr: *const u32) {
    moto_rt::futex_wake_all(unsafe { &*(addr as *const core::sync::atomic::AtomicU32) })
}

// ---- key-based TLS (VDSO) — pthread_key_* maps 1:1 onto this -------------------

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_tls_create(dtor: Option<unsafe extern "C" fn(*mut u8)>) -> usize {
    moto_rt::tls::create(dtor)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn moto_rt_tls_set(key: usize, value: *mut u8) {
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

// ---- the libc TCB slot (UTCB.libc_tcb, fs:0x58; needs kernel_version >= 2) -----

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_tcb_set(val: *mut u8) {
    let utcb = moto_sys::UserThreadControlBlock::get_mut();
    assert!(
        utcb.kernel_version >= 2,
        "kernel lacks UTCB.libc_tcb (need kernel_version >= 2)"
    );
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
    thread_fn: extern "C" fn(u64),
    stack_size: usize,
    arg: u64,
) -> i64 {
    match moto_rt::thread::spawn(thread_fn, stack_size, arg) {
        Ok(handle) => handle as i64,
        Err(e) => err64(e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_thread_join(handle: u64) -> i32 {
    match moto_rt::thread::join(handle) {
        Ok(()) => 0,
        Err(e) => err64(e) as i32,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn moto_rt_thread_yield() {
    moto_rt::thread::yield_now()
}
