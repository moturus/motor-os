//! POSIX file descriptor helper.
//!
//! Although Motor OS does not use file descriptors internally,
//! a lot of Rust crates assume FDs are available, so to make
//! our lives easier we expose File and Networking APIs in terms
//! of FDs.

use core::any::Any;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use moto_rt::E_BAD_HANDLE;
use moto_rt::E_INVALID_ARGUMENT;
use moto_rt::E_OK;
use moto_rt::ErrorCode;
use moto_rt::RtFd;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_rt::spinlock::SpinLock;

#[derive(Debug)]
pub enum PosixKind {
    ChildProcess,
    ChildStdio,
    File,
    PollRegistry,
    ReadDir,
    SelfStdio,
    TcpListener,
    TcpStream,
    UdpSocket,
}

pub trait PosixFile: Any + Send + Sync {
    fn kind(&self) -> PosixKind;
    fn descriptor_attr(&self, object_id: NonZeroU64) -> Result<moto_rt::fs::FileAttr, ErrorCode>;

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        Err(E_BAD_HANDLE)
    }
    /// Serve the first non-empty buffer, which is what a descriptor kind
    /// without a native vectored path can always do correctly. Kinds that can
    /// do better (regular files, TCP streams) override this; a kind that
    /// cannot read at all still reports `E_BAD_HANDLE` through [`Self::read`].
    /// Filling later buffers would mean a second blocking request after the
    /// first already produced bytes, so it is deliberately not done here.
    unsafe fn read_vectored(&self, bufs: &mut [&mut [u8]]) -> Result<usize, ErrorCode> {
        match bufs.iter_mut().find(|buf| !buf.is_empty()) {
            Some(buf) => self.read(buf),
            None => Ok(0),
        }
    }
    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        Err(E_BAD_HANDLE)
    }
    /// See [`Self::read_vectored`].
    unsafe fn write_vectored(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        match bufs.iter().find(|buf| !buf.is_empty()) {
            Some(buf) => self.write(buf),
            None => Ok(0),
        }
    }
    fn flush(&self) -> Result<(), ErrorCode> {
        Err(E_BAD_HANDLE)
    }
    fn file_lock(&self, _operation: u8) -> Result<(), ErrorCode> {
        Err(E_BAD_HANDLE)
    }

    // rt_fd indicates which FD is closed.
    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        Err(E_BAD_HANDLE)
    }

    /// Whether this object is a terminal endpoint: its peer provides terminal
    /// behavior (docs/tui.md). Immutable metadata on
    /// the object, so duplicated descriptors agree by construction. Only a
    /// process's own stdio can be one; a parent-side `ChildStdio` is the
    /// terminal provider's end, not a terminal.
    fn is_terminal(&self) -> bool {
        false
    }

    /// Whether this file needs [`Self::on_last_close`]. Opting in costs a scan
    /// of the descriptor table per close, so it defaults to off.
    fn wants_last_close(&self) -> bool {
        false
    }

    /// Called when the descriptor being closed was the last one referring to
    /// this file, i.e. when close is observable as releasing the object rather
    /// than one of its `dup`s. For files that must release a shared resource
    /// before close returns and cannot wait for the last reference to die.
    fn on_last_close(&self) {}
    fn set_nonblocking(&self, val: bool) -> Result<(), ErrorCode> {
        Err(moto_rt::E_NOT_IMPLEMENTED)
    }
    // Not pollable by default: fd kinds without readiness semantics (e.g.
    // regular files) must report an error, not kill the process — libc-level
    // poll() treats E_INVALID_ARGUMENT as "always ready", per POSIX rules
    // for regular files.
    fn poll_add(
        &self,
        _r_id: u64,
        _source_fd: RtFd,
        _token: Token,
        _interests: Interests,
    ) -> Result<(), ErrorCode> {
        Err(E_INVALID_ARGUMENT)
    }
    fn poll_set(
        &self,
        _r_id: u64,
        _source_fd: RtFd,
        _token: Token,
        _interests: Interests,
    ) -> Result<(), ErrorCode> {
        Err(E_INVALID_ARGUMENT)
    }
    fn poll_del(&self, _r_id: u64, _source_fd: RtFd) -> Result<(), ErrorCode> {
        Err(E_INVALID_ARGUMENT)
    }
}

pub(crate) fn synthetic_attr(file_type: u8, object_id: NonZeroU64) -> moto_rt::fs::FileAttr {
    let mut attr = moto_rt::fs::FileAttr::new();
    attr.file_type = file_type;
    attr.entry_id = object_id.get() as u128;
    attr
}

pub extern "C" fn posix_read(rt_fd: i32, buf: *mut u8, buf_sz: usize) -> i64 {
    let Some(posix_file) = get_file(rt_fd) else {
        return -(E_BAD_HANDLE as i64);
    };

    let buf = unsafe { core::slice::from_raw_parts_mut(buf, buf_sz) };
    match posix_file.read(buf) {
        Ok(sz) => sz as i64,
        Err(err) => -(err as i64),
    }
}

pub unsafe extern "C" fn posix_read_vectored(rt_fd: i32, packed: *const usize, num: usize) -> i64 {
    let Some(posix_file) = get_file(rt_fd) else {
        return -(E_BAD_HANDLE as i64);
    };

    let packed = unsafe { core::slice::from_raw_parts(packed, num * 2) };
    let mut bufs = Vec::with_capacity(num);
    for idx in 0..num {
        let addr = packed[2 * idx];
        let len = packed[2 * idx + 1];
        let buf = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) };
        bufs.push(buf);
    }

    match unsafe { posix_file.read_vectored(bufs.as_mut_slice()) } {
        Ok(sz) => sz as i64,
        Err(err) => -(err as i64),
    }
}

pub extern "C" fn posix_write(rt_fd: i32, buf: *const u8, buf_sz: usize) -> i64 {
    let Some(posix_file) = get_file(rt_fd) else {
        return -(E_BAD_HANDLE as i64);
    };

    let buf = unsafe { core::slice::from_raw_parts(buf, buf_sz) };
    match posix_file.write(buf) {
        Ok(sz) => sz as i64,
        Err(err) => -(err as i64),
    }
}

pub unsafe extern "C" fn posix_write_vectored(rt_fd: i32, packed: *const usize, num: usize) -> i64 {
    let Some(posix_file) = get_file(rt_fd) else {
        return -(E_BAD_HANDLE as i64);
    };

    let packed = unsafe { core::slice::from_raw_parts(packed, num * 2) };
    let mut bufs = Vec::with_capacity(num);
    for idx in 0..num {
        let addr = packed[2 * idx];
        let len = packed[2 * idx + 1];
        let buf = unsafe { core::slice::from_raw_parts(addr as *const u8, len) };
        bufs.push(buf);
    }

    match unsafe { posix_file.write_vectored(bufs.as_slice()) } {
        Ok(sz) => sz as i64,
        Err(err) => -(err as i64),
    }
}

pub extern "C" fn posix_flush(rt_fd: i32) -> ErrorCode {
    let Some(posix_file) = get_file(rt_fd) else {
        return E_BAD_HANDLE;
    };

    match posix_file.flush() {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn posix_file_lock(rt_fd: RtFd, operation: u8) -> ErrorCode {
    let Some(posix_file) = get_file(rt_fd) else {
        return E_BAD_HANDLE;
    };
    match posix_file.file_lock(operation) {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn posix_close(rt_fd: i32) -> ErrorCode {
    let Some(posix_file) = pop_file(rt_fd) else {
        return E_BAD_HANDLE;
    };

    if posix_file.wants_last_close() && !DESCRIPTORS.is_referenced(&posix_file) {
        posix_file.on_last_close();
    }

    match posix_file.close(rt_fd) {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn posix_duplicate(rt_fd: RtFd) -> RtFd {
    let Some(entry) = get_entry(rt_fd) else {
        return -(E_BAD_HANDLE as RtFd);
    };

    DESCRIPTORS.insert_entry(entry)
}

#[derive(Clone)]
pub(crate) struct DescriptorEntry {
    pub(crate) object: Arc<dyn PosixFile>,
    pub(crate) object_id: NonZeroU64,
}

/// Exposes a way to map RtFd to Arc<T>. The implementation
/// can probably be made faster using unsafe stuff, but that
/// would be premature optimization at the moment.
struct Descriptors {
    descriptors: SpinLock<Vec<Option<DescriptorEntry>>>,
    freelist: SpinLock<Vec<RtFd>>,
    next_object_id: AtomicU64,
}

impl Descriptors {
    const fn new() -> Self {
        Self {
            descriptors: SpinLock::new(Vec::new()),
            freelist: SpinLock::new(Vec::new()),
            next_object_id: AtomicU64::new(1),
        }
    }

    fn get(&self, fd: RtFd) -> Option<DescriptorEntry> {
        self.descriptors
            .lock()
            .get(fd as usize)
            .and_then(Clone::clone)
    }

    fn pop(&self, fd: RtFd) -> Option<DescriptorEntry> {
        let val = {
            let mut descriptors = self.descriptors.lock();
            descriptors.get_mut(fd as usize)?.take()
        };
        if val.is_some() {
            self.freelist.lock().push(fd);
        }
        val
    }

    /// Whether any descriptor still refers to `file`. Used only by files that
    /// opt into [`PosixFile::on_last_close`], so the scan is not on the path
    /// of an ordinary close.
    fn is_referenced(&self, file: &Arc<dyn PosixFile>) -> bool {
        self.descriptors
            .lock()
            .iter()
            .flatten()
            .any(|entry| Arc::ptr_eq(&entry.object, file))
    }

    fn get_free_fd(&self) -> RtFd {
        if let Some(fd) = self.freelist.lock().pop() {
            return fd;
        }

        let res = {
            let mut descriptors = self.descriptors.lock();
            descriptors.push(None);
            descriptors.len() - 1
        };
        assert!(res < (RtFd::MAX as usize));
        res as RtFd
    }

    fn new_object_id(&self) -> NonZeroU64 {
        NonZeroU64::new(self.next_object_id.fetch_add(1, Ordering::Relaxed))
            .expect("descriptor object ID exhausted")
    }

    fn install(&self, entry: DescriptorEntry) -> RtFd {
        let fd = self.get_free_fd();
        let old = self.descriptors.lock()[fd as usize].replace(entry);
        debug_assert!(old.is_none());
        fd
    }

    fn insert<F>(&self, func: F) -> RtFd
    where
        F: FnOnce(RtFd) -> Arc<dyn PosixFile>,
    {
        let fd = self.get_free_fd();
        let entry = DescriptorEntry {
            object: func(fd),
            object_id: self.new_object_id(),
        };
        let old = self.descriptors.lock()[fd as usize].replace(entry);
        debug_assert!(old.is_none());
        fd
    }

    fn insert_entry(&self, entry: DescriptorEntry) -> RtFd {
        self.install(entry)
    }
}

static DESCRIPTORS: Descriptors = Descriptors::new();

pub fn new_file<Constructor>(constructor: Constructor) -> RtFd
where
    Constructor: FnOnce(RtFd) -> Arc<dyn PosixFile>,
{
    DESCRIPTORS.insert(constructor)
}

pub fn push_file(val: Arc<dyn PosixFile>) -> RtFd {
    new_file(|_| val)
}

pub fn get_file(fd: RtFd) -> Option<Arc<dyn PosixFile>> {
    get_entry(fd).map(|entry| entry.object)
}

pub(crate) fn get_entry(fd: RtFd) -> Option<DescriptorEntry> {
    DESCRIPTORS.get(fd)
}

pub fn pop_file(fd: RtFd) -> Option<Arc<dyn PosixFile>> {
    DESCRIPTORS.pop(fd).map(|entry| entry.object)
}
