//! Filesystem RT API.
//!
//! While it would be great to expose something more interesting,
//! Rust's FS PAL is a thin wrapper around POSIX FS API, and a lot
//! of popular third-party crates assume POSIXy FS API, and
//! when Motor OS later adds a libc, or another compatibility
//! layer with another language/system, it will also have to
//! expose a flavor of POSIXy FS API, so we don't try to be too
//! different here and expose a POSIXy FS API.

use crate::error::*;
use crate::ok_or_error;
use crate::to_result;
use crate::RtFd;
use crate::RtVdsoVtable;
use core::sync::atomic::Ordering;

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;

pub const TEMP_DIR: &str = "/sys/tmp";
pub const HANDLE_URL_PREFIX: &str = "handle://";

/// The maximum length of a file/directory absolute path, in bytes.
///
/// Relatively short so that two paths can fit into a page, with some
/// extra fields (for RPC rename request). Although Linux and Windows
/// have longer max path lengths, macOS has 1024, so 1024 should also
/// be enough for Motor OS.
pub const MAX_PATH_LEN: usize = 1024;
/// The maximum length of a file/directory leaf name, in bytes.
pub const MAX_FILENAME_LEN: usize = 256;
/// The maximum length of a single file.
pub const MAX_FILE_LEN: u64 = i64::MAX as u64;

// File types.
pub const FILETYPE_FILE: u8 = 1;
pub const FILETYPE_DIRECTORY: u8 = 2;

// File permissions.
pub const PERM_READ: u64 = 1;
pub const PERM_WRITE: u64 = 2;

// Open options.
pub const O_READ: u32 = 1 << 0;
pub const O_WRITE: u32 = 1 << 1;
pub const O_APPEND: u32 = 1 << 2;
pub const O_TRUNCATE: u32 = 1 << 3;
pub const O_CREATE: u32 = 1 << 4;
pub const O_CREATE_NEW: u32 = 1 << 5;

// When "opening a handle".
pub const O_HANDLE_CHILD: u32 = 1;

// Seek option.
pub const SEEK_SET: u8 = 0;
pub const SEEK_CUR: u8 = 1;
pub const SEEK_END: u8 = 2;

#[repr(C, align(16))]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct FileAttr {
    pub version: u64,
    pub size: u64,
    pub perm: u64,
    pub file_type: u8,
    pub _reserved: [u8; 7],
    pub created: u128,
    pub modified: u128,
    pub accessed: u128,
}

impl FileAttr {
    pub const VERSION: u64 = 1;

    fn new() -> Self {
        Self {
            version: Self::VERSION,
            ..Default::default()
        }
    }
}

/// Returned by readdir().
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub version: u64,
    pub _reserved: u64,
    pub attr: FileAttr,
    pub fname_size: u16, // Filename only, without path/ancestors.
    pub fname: [u8; MAX_FILENAME_LEN],
}

impl DirEntry {
    pub const VERSION: u64 = 1;

    fn new() -> Self {
        Self {
            version: Self::VERSION,
            _reserved: 0,
            attr: FileAttr::new(),
            fname_size: 0,
            fname: [0; MAX_FILENAME_LEN],
        }
    }
}

pub fn is_terminal(rt_fd: RtFd) -> bool {
    let vdso_is_terminal: extern "C" fn(i32) -> i32 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_is_terminal.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    match vdso_is_terminal(rt_fd) {
        0 => false,
        1 => true,
        _ => panic!(),
    }
}

pub fn duplicate(rt_fd: RtFd) -> Result<RtFd, ErrorCode> {
    let vdso_duplicate: extern "C" fn(RtFd) -> RtFd = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_duplicate.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    to_result!(vdso_duplicate(rt_fd))
}

/// Opens a file at `path` with options specified by `opts`.
pub fn open(path: &str, opts: u32) -> Result<RtFd, ErrorCode> {
    let vdso_open: extern "C" fn(*const u8, usize, u32) -> i32 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_open.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    let bytes = path.as_bytes();
    to_result!(vdso_open(bytes.as_ptr(), bytes.len(), opts))
}

pub fn close(rt_fd: RtFd) -> Result<(), ErrorCode> {
    let vdso_close: extern "C" fn(i32) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_close.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_close(rt_fd))
}

pub fn get_file_attr(rt_fd: RtFd) -> Result<FileAttr, ErrorCode> {
    let vdso_get_file_attr: extern "C" fn(i32, *mut FileAttr) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_get_file_attr.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut attr = FileAttr::new();
    match vdso_get_file_attr(rt_fd, &mut attr) {
        E_OK => Ok(attr),
        err => Err(err),
    }
}

pub fn fsync(rt_fd: RtFd) -> Result<(), ErrorCode> {
    let vdso_fsync: extern "C" fn(i32) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_fsync.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_fsync(rt_fd))
}

pub fn datasync(rt_fd: RtFd) -> Result<(), ErrorCode> {
    let vdso_datasync: extern "C" fn(i32) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_datasync.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_datasync(rt_fd))
}

pub fn truncate(rt_fd: RtFd, size: u64) -> Result<(), ErrorCode> {
    let vdso_truncate: extern "C" fn(i32, u64) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_truncate.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_truncate(rt_fd, size))
}

pub fn read(rt_fd: RtFd, buf: &mut [u8]) -> Result<usize, ErrorCode> {
    let vdso_read: extern "C" fn(i32, *mut u8, usize) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_read.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    to_result!(vdso_read(rt_fd, buf.as_mut_ptr(), buf.len()))
}

pub fn read_vectored(rt_fd: RtFd, bufs: &mut [&mut [u8]]) -> Result<usize, ErrorCode> {
    use alloc::vec::Vec;

    let vdso_read_vectored: extern "C" fn(i32, *const usize, usize) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_read_vectored.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    // Pack: a vector of [addr, len].
    let mut packed = Vec::with_capacity(bufs.len() * 2);
    for buf in &*bufs {
        let addr = buf.as_ptr() as usize;
        let len = buf.len();
        packed.push(addr);
        packed.push(len);
    }

    to_result!(vdso_read_vectored(rt_fd, packed.as_ptr(), bufs.len()))
}

pub fn write(rt_fd: RtFd, buf: &[u8]) -> Result<usize, ErrorCode> {
    let vdso_write: extern "C" fn(i32, *const u8, usize) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_write.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    to_result!(vdso_write(rt_fd, buf.as_ptr(), buf.len()))
}

pub fn write_vectored(rt_fd: RtFd, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
    use alloc::vec::Vec;

    let vdso_write_vectored: extern "C" fn(i32, *const usize, usize) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get()
                .fs_write_vectored
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    // Pack: a vector of [addr, len].
    let mut packed = Vec::with_capacity(bufs.len() * 2);
    #[allow(clippy::borrow_deref_ref)]
    for buf in &*bufs {
        let addr = buf.as_ptr() as usize;
        let len = buf.len();
        packed.push(addr);
        packed.push(len);
    }

    to_result!(vdso_write_vectored(rt_fd, packed.as_ptr(), bufs.len()))
}

pub fn flush(rt_fd: RtFd) -> Result<(), ErrorCode> {
    let vdso_flush: extern "C" fn(i32) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_flush.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_flush(rt_fd))
}

pub fn seek(rt_fd: RtFd, offset: i64, whence: u8) -> Result<u64, ErrorCode> {
    let vdso_seek: extern "C" fn(i32, i64, u8) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_seek.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    to_result!(vdso_seek(rt_fd, offset, whence))
}

pub fn mkdir(path: &str) -> Result<(), ErrorCode> {
    let vdso_mkdir: extern "C" fn(*const u8, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_mkdir.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let bytes = path.as_bytes();
    ok_or_error(vdso_mkdir(bytes.as_ptr(), bytes.len()))
}

pub fn unlink(path: &str) -> Result<(), ErrorCode> {
    let vdso_unlink: extern "C" fn(*const u8, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_unlink.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let bytes = path.as_bytes();
    ok_or_error(vdso_unlink(bytes.as_ptr(), bytes.len()))
}

pub fn rename(old: &str, new: &str) -> Result<(), ErrorCode> {
    let vdso_rename: extern "C" fn(*const u8, usize, *const u8, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_rename.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let old = old.as_bytes();
    let new = new.as_bytes();
    ok_or_error(vdso_rename(
        old.as_ptr(),
        old.len(),
        new.as_ptr(),
        new.len(),
    ))
}

pub fn rmdir(path: &str) -> Result<(), ErrorCode> {
    let vdso_rmdir: extern "C" fn(*const u8, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_rmdir.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let bytes = path.as_bytes();
    ok_or_error(vdso_rmdir(bytes.as_ptr(), bytes.len()))
}

pub fn rmdir_all(path: &str) -> Result<(), ErrorCode> {
    let vdso_rmdir_all: extern "C" fn(*const u8, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_rmdir_all.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let bytes = path.as_bytes();
    ok_or_error(vdso_rmdir_all(bytes.as_ptr(), bytes.len()))
}

pub fn set_perm(path: &str, perm: u64) -> Result<(), ErrorCode> {
    let vdso_set_perm: extern "C" fn(*const u8, usize, u64) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_set_perm.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let bytes = path.as_bytes();
    ok_or_error(vdso_set_perm(bytes.as_ptr(), bytes.len(), perm))
}

pub fn set_file_perm(rt_fd: RtFd, perm: u64) -> Result<(), ErrorCode> {
    let vdso_set_file_perm: extern "C" fn(RtFd, u64) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_set_file_perm.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_set_file_perm(rt_fd, perm))
}

pub fn stat(path: &str) -> Result<FileAttr, ErrorCode> {
    let vdso_stat: extern "C" fn(*const u8, usize, *mut FileAttr) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_stat.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    let bytes = path.as_bytes();
    let mut attr = FileAttr::new();

    match vdso_stat(bytes.as_ptr(), bytes.len(), &mut attr) {
        E_OK => Ok(attr),
        err => Err(err),
    }
}

pub fn canonicalize(path: &str) -> Result<alloc::string::String, ErrorCode> {
    let vdso_canonicalize: extern "C" fn(*const u8, usize, *mut u8, *mut usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_canonicalize.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let path = path.as_bytes();
    let mut bytes = [0_u8; MAX_PATH_LEN];
    let mut len = 0_usize;

    use alloc::borrow::ToOwned;
    match vdso_canonicalize(path.as_ptr(), path.len(), bytes.as_mut_ptr(), &mut len) {
        E_OK => Ok(core::str::from_utf8(&bytes[..len]).unwrap().to_owned()),
        err => Err(err),
    }
}

pub fn copy(from: &str, to: &str) -> Result<u64, ErrorCode> {
    let vdso_copy: extern "C" fn(*const u8, usize, *const u8, usize) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_copy.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    let from = from.as_bytes();
    let to = to.as_bytes();
    to_result!(vdso_copy(from.as_ptr(), from.len(), to.as_ptr(), to.len()))
}

pub fn opendir(path: &str) -> Result<RtFd, ErrorCode> {
    let vdso_opendir: extern "C" fn(*const u8, usize) -> i32 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_opendir.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let bytes = path.as_bytes();
    to_result!(vdso_opendir(bytes.as_ptr(), bytes.len()))
}

pub fn closedir(rt_fd: RtFd) -> Result<(), ErrorCode> {
    let vdso_closedir: extern "C" fn(i32) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_closedir.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_closedir(rt_fd))
}

pub fn readdir(rt_fd: RtFd) -> Result<Option<DirEntry>, ErrorCode> {
    let vdso_readdir: extern "C" fn(i32, *mut DirEntry) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_readdir.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut dentry = DirEntry::new();
    match vdso_readdir(rt_fd, &mut dentry) {
        E_OK => Ok(Some(dentry)),
        E_NOT_FOUND => Ok(None),
        err => Err(err),
    }
}

pub fn getcwd() -> Result<alloc::string::String, ErrorCode> {
    let vdso_getcwd: extern "C" fn(*mut u8, *mut usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_getcwd.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut bytes = [0_u8; MAX_PATH_LEN];
    let mut len = 0_usize;

    use alloc::borrow::ToOwned;
    match vdso_getcwd(bytes.as_mut_ptr(), &mut len) {
        E_OK => Ok(core::str::from_utf8(&bytes[..len]).unwrap().to_owned()),
        err => Err(err),
    }
}

pub fn chdir(path: &str) -> Result<(), ErrorCode> {
    let vdso_chdir: extern "C" fn(*const u8, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().fs_chdir.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let bytes = path.as_bytes();
    ok_or_error(vdso_chdir(bytes.as_ptr(), bytes.len()))
}
