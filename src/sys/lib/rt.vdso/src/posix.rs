//! POSIX file descriptor helper.
//!
//! Although Motor OS does not use file descriptors internally,
//! a lot of Rust crates assume FDs are available, so to make
//! our lives easier we expose File and Networking APIs in terms
//! of FDs.

use core::any::Any;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU32, Ordering};

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

use crate::runtime::Registration;

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
    /// Copy what a read would return without consuming it, and never wait:
    /// `E_NOT_READY` while the stream is open and empty.
    fn peek(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
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

    /// Files that need [`Self::on_last_close`] count their installed descriptors.
    /// A reference held by a read, write or poll operation does not count.
    fn descriptor_count(&self) -> Option<&AtomicU32> {
        None
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
    fn poll_add(&self, _registration: &Arc<Registration>) -> Result<(), ErrorCode> {
        Err(E_INVALID_ARGUMENT)
    }
    fn poll_set(
        &self,
        _registration: &Arc<Registration>,
        _token: Token,
        _interests: Interests,
    ) -> Result<(), ErrorCode> {
        Err(E_INVALID_ARGUMENT)
    }
    fn poll_del(&self, _registration: &Arc<Registration>) -> Result<(), ErrorCode> {
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
    let Some((posix_file, last)) = DESCRIPTORS.lock().take_for_close(rt_fd) else {
        return E_BAD_HANDLE;
    };

    if last {
        posix_file.on_last_close();
    }

    let result = match posix_file.close(rt_fd) {
        Ok(()) => E_OK,
        Err(err) => err,
    };
    DESCRIPTORS.lock().freelist.push(rt_fd);
    result
}

pub extern "C" fn posix_duplicate(rt_fd: RtFd) -> RtFd {
    let mut table = DESCRIPTORS.lock();
    let Some(entry) = table.entries.get(rt_fd as usize).and_then(Clone::clone) else {
        return -(E_BAD_HANDLE as RtFd);
    };
    table.insert(entry)
}

#[derive(Clone)]
pub(crate) struct DescriptorEntry {
    pub(crate) object: Arc<dyn PosixFile>,
    pub(crate) object_id: NonZeroU64,
}

impl DescriptorEntry {
    fn release_descriptor(&self) -> bool {
        self.object.descriptor_count().is_some_and(|count| {
            let previous = count.fetch_sub(1, Ordering::Relaxed);
            debug_assert!(previous > 0);
            previous == 1
        })
    }
}

struct Descriptors {
    entries: Vec<Option<DescriptorEntry>>,
    freelist: Vec<RtFd>,
    // Exit detaches the entries while other threads can still allocate fds.
    next_fd: RtFd,
    next_object_id: NonZeroU64,
}

impl Descriptors {
    fn insert(&mut self, entry: DescriptorEntry) -> RtFd {
        let fd = self.freelist.pop().unwrap_or_else(|| {
            let fd = self.next_fd;
            self.next_fd = fd.checked_add(1).expect("descriptor number exhausted");
            fd
        });
        if fd as usize >= self.entries.len() {
            self.entries.resize_with(fd as usize + 1, || None);
        }
        if let Some(count) = entry.object.descriptor_count() {
            count.fetch_add(1, Ordering::Relaxed);
        }
        let old = self.entries[fd as usize].replace(entry);
        debug_assert!(old.is_none());
        fd
    }

    // Keep removal and the last-descriptor decision atomic with duplicate.
    // The notification itself can perform I/O and runs outside this lock.
    fn take_for_close(&mut self, fd: RtFd) -> Option<(Arc<dyn PosixFile>, bool)> {
        let entry = self.entries.get_mut(fd as usize)?.take()?;
        let last = entry.release_descriptor();
        Some((entry.object, last))
    }
}

static DESCRIPTORS: SpinLock<Descriptors> = SpinLock::new(Descriptors {
    entries: Vec::new(),
    freelist: Vec::new(),
    next_fd: 0,
    next_object_id: NonZeroU64::MIN,
});

pub fn push_file(object: Arc<dyn PosixFile>) -> RtFd {
    let mut table = DESCRIPTORS.lock();
    let object_id = table.next_object_id;
    table.next_object_id = object_id
        .checked_add(1)
        .expect("descriptor object ID exhausted");
    table.insert(DescriptorEntry { object, object_id })
}

pub fn get_file(fd: RtFd) -> Option<Arc<dyn PosixFile>> {
    get_entry(fd).map(|entry| entry.object)
}

pub(crate) fn get_entry(fd: RtFd) -> Option<DescriptorEntry> {
    DESCRIPTORS.lock().entries.get(fd as usize)?.clone()
}

pub(crate) extern "C" fn closedir(fd: RtFd) -> ErrorCode {
    let mut table = DESCRIPTORS.lock();
    let Some(entry) = table
        .entries
        .get_mut(fd as usize)
        .and_then(|slot| slot.take_if(|entry| matches!(entry.object.kind(), PosixKind::ReadDir)))
    else {
        return E_BAD_HANDLE;
    };
    table.freelist.push(fd);
    drop(table);
    drop(entry);
    E_OK
}

/// Keep all detached objects alive until the last-close notifications finish.
pub(crate) fn notify_process_exit() {
    let entries = core::mem::take(&mut DESCRIPTORS.lock().entries);
    for entry in entries.iter().flatten() {
        if entry.release_descriptor() {
            entry.object.on_last_close();
        }
    }
}
