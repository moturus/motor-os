//! POSIX file descriptor helper.
//!
//! Although Motor OS does not use file descriptors internally,
//! a lot of Rust crates assume FDs are available, so to make
//! our lives easier we expose File and Networking APIs in terms
//! of FDs.

use core::any::Any;

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
    Placeholder,
    PollRegistry,
    ReadDir,
    SelfStdio,
    TcpListener,
    TcpStream,
    UdpSocket,
}

pub trait PosixFile: Any + Send + Sync {
    fn kind(&self) -> PosixKind;

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        Err(E_BAD_HANDLE)
    }
    unsafe fn read_vectored(&self, bufs: &mut [&mut [u8]]) -> Result<usize, ErrorCode> {
        Err(E_BAD_HANDLE)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        Err(E_BAD_HANDLE)
    }
    unsafe fn write_vectored(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        Err(E_BAD_HANDLE)
    }
    fn flush(&self) -> Result<(), ErrorCode> {
        Err(E_BAD_HANDLE)
    }

    // rt_fd indicates which FD is closed.
    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        Err(E_BAD_HANDLE)
    }
    fn set_nonblocking(&self, val: bool) -> Result<(), ErrorCode> {
        Err(moto_rt::E_NOT_IMPLEMENTED)
    }
    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        todo!()
        // Err(E_INVALID_ARGUMENT)
    }
    fn poll_set(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        todo!()
        // Err(E_INVALID_ARGUMENT)
    }
    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        panic!("Unexpected poll_del for {:?}", self.kind())
        // Err(E_INVALID_ARGUMENT)
    }
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

pub extern "C" fn posix_close(rt_fd: i32) -> ErrorCode {
    let Some(posix_file) = pop_file(rt_fd) else {
        return E_BAD_HANDLE;
    };

    match posix_file.close(rt_fd) {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn posix_duplicate(rt_fd: RtFd) -> RtFd {
    let Some(posix_file) = get_file(rt_fd) else {
        return -(E_BAD_HANDLE as RtFd);
    };

    push_file(posix_file)
}

struct Placeholder;
impl PosixFile for Placeholder {
    fn kind(&self) -> PosixKind {
        PosixKind::Placeholder
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        Err(E_BAD_HANDLE)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        Err(E_BAD_HANDLE)
    }

    fn flush(&self) -> Result<(), ErrorCode> {
        Err(E_BAD_HANDLE)
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        Err(E_BAD_HANDLE)
    }
}

/// Exposes a way to map RtFd to Arc<T>. The implementation
/// can probably be made faster using unsafe stuff, but that
/// would be premature optimization at the moment.
struct Descriptors {
    descriptors: SpinLock<Vec<Arc<dyn PosixFile>>>,
    freelist: SpinLock<Vec<RtFd>>,
}

impl Descriptors {
    const fn new() -> Self {
        Self {
            descriptors: SpinLock::new(Vec::new()),
            freelist: SpinLock::new(Vec::new()),
        }
    }

    fn get(&self, fd: RtFd) -> Option<Arc<dyn PosixFile>> {
        let descriptors = self.descriptors.lock();
        if let Some(entry) = descriptors.get(fd as usize) {
            Some(entry.clone())
        } else {
            None
        }
    }

    fn pop(&self, fd: RtFd) -> Option<Arc<dyn PosixFile>> {
        let val = {
            let mut descriptors = self.descriptors.lock();
            if let Some(entry) = descriptors.get_mut(fd as usize) {
                let mut val: Arc<dyn PosixFile> = Arc::new(Placeholder);
                core::mem::swap(&mut val, entry);
                if (val.as_ref() as &dyn Any)
                    .downcast_ref::<Placeholder>()
                    .is_some()
                {
                    None
                } else {
                    Some(val)
                }
            } else {
                return None;
            }
        };
        if val.is_some() {
            self.freelist.lock().push(fd);
        }
        val
    }

    fn get_free_fd(&self) -> RtFd {
        if let Some(fd) = self.freelist.lock().pop() {
            return fd;
        }

        let res = {
            let mut descriptors = self.descriptors.lock();
            descriptors.push(Arc::new(Placeholder));
            descriptors.len() - 1
        };
        assert!(res < (RtFd::MAX as usize));
        res as RtFd
    }

    fn insert<F>(&self, func: F) -> RtFd
    where
        F: FnOnce(RtFd) -> Arc<dyn PosixFile>,
    {
        let fd = self.get_free_fd();
        let mut val = func(fd);
        let mut descriptors = self.descriptors.lock();

        let entry = descriptors.get_mut(fd as usize).unwrap();
        core::mem::swap(&mut val, entry);

        #[cfg(debug_assertions)]
        assert!(
            (val.as_ref() as &dyn Any)
                .downcast_ref::<Placeholder>()
                .is_some()
        );

        fd
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
    DESCRIPTORS.get(fd)
}

pub fn pop_file(fd: RtFd) -> Option<Arc<dyn PosixFile>> {
    DESCRIPTORS.pop(fd)
}
