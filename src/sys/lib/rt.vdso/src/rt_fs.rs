use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use super::util::mutex::Mutex;
use crate::util::fd::Fd;
use crate::util::fd::DESCRIPTORS;
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::string::ToString;
use moto_rt::error::*;
use moto_rt::fs::*;
use moto_sys_io::rt_fs::*;

pub extern "C" fn open(path_ptr: *const u8, path_size: usize, opts: u32) -> i32 {
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };
    let file = match FsClient::file_open(path, opts) {
        Ok(file) => file,
        Err(err) => return -(err as i32),
    };

    DESCRIPTORS.push(alloc::sync::Arc::new(Fd::File(file)))
}

pub extern "C" fn close(rt_fd: i32) -> ErrorCode {
    let fd = if let Some(fd) = DESCRIPTORS.pop(rt_fd) {
        fd
    } else {
        return E_BAD_HANDLE;
    };

    match fd.as_ref() {
        Fd::File(file) => match FsClient::close_fd(file.fd, CloseFdRequest::F_FILE) {
            Ok(()) => E_OK,
            Err(err) => err,
        },
        _ => panic!("fd {rt_fd} not a file"), // Can't just return an error, as we've popped the fd.
    }
}

pub extern "C" fn get_file_attr(rt_fd: i32, attr: *mut FileAttr) -> ErrorCode {
    let fd = if let Some(fd) = DESCRIPTORS.get(rt_fd) {
        fd
    } else {
        return E_BAD_HANDLE;
    };

    match fd.as_ref() {
        Fd::File(file) => match FsClient::stat(&file.abs_path) {
            Ok(a) => {
                unsafe { *attr = a };
                E_OK
            }
            Err(err) => err,
        },
        _ => return E_BAD_HANDLE,
    }
}

pub extern "C" fn fsync(rt_fd: i32) -> ErrorCode {
    E_OK
}

pub extern "C" fn datasync(rt_fd: i32) -> ErrorCode {
    E_OK
}

pub extern "C" fn truncate(rt_fd: i32, size: u64) -> ErrorCode {
    todo!()
}

pub extern "C" fn read(rt_fd: i32, buf: *mut u8, buf_sz: usize) -> i64 {
    let fd = if let Some(fd) = DESCRIPTORS.get(rt_fd) {
        fd
    } else {
        return -(E_BAD_HANDLE as i64);
    };

    match fd.as_ref() {
        Fd::File(file) => {
            let buf = unsafe { core::slice::from_raw_parts_mut(buf, buf_sz) };
            match FsClient::read(&file, buf) {
                Ok(sz) => sz as i64,
                Err(err) => -(err as i64),
            }
        }
        _ => return -(E_BAD_HANDLE as i64),
    }
}

pub extern "C" fn write(rt_fd: i32, buf: *const u8, buf_sz: usize) -> i64 {
    let fd = if let Some(fd) = DESCRIPTORS.get(rt_fd) {
        fd
    } else {
        return -(E_BAD_HANDLE as i64);
    };

    match fd.as_ref() {
        Fd::File(file) => {
            let buf = unsafe { core::slice::from_raw_parts(buf, buf_sz) };
            match FsClient::write(&file, buf) {
                Ok(sz) => sz as i64,
                Err(err) => -(err as i64),
            }
        }
        _ => return -(E_BAD_HANDLE as i64),
    }
}

pub extern "C" fn flush(_rt_fd: i32) -> ErrorCode {
    E_OK
}

pub extern "C" fn seek(rt_fd: i32, offset: i64, whence: u8) -> i64 {
    let fd = if let Some(fd) = DESCRIPTORS.get(rt_fd) {
        fd
    } else {
        return -(E_BAD_HANDLE as i64);
    };

    match fd.as_ref() {
        Fd::File(file) => match FsClient::seek(&file, offset, whence) {
            Ok(sz) => sz as i64,
            Err(err) => -(err as i64),
        },
        _ => return -(E_BAD_HANDLE as i64),
    }
}

pub extern "C" fn mkdir(path_ptr: *const u8, path_size: usize) -> ErrorCode {
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };
    match FsClient::mkdir(path) {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn unlink(path_ptr: *const u8, path_size: usize) -> ErrorCode {
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };
    match FsClient::unlink(path, F_UNLINK_FILE) {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn rename(
    old_ptr: *const u8,
    old_size: usize,
    new_ptr: *const u8,
    new_size: usize,
) -> ErrorCode {
    todo!()
}

pub extern "C" fn rmdir(path_ptr: *const u8, path_size: usize) -> ErrorCode {
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };
    match FsClient::unlink(path, F_UNLINK_DIR) {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn rmdir_all(path_ptr: *const u8, path_size: usize) -> ErrorCode {
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };
    match FsClient::unlink(path, F_UNLINK_DIR_ALL) {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn set_perm(path_ptr: *const u8, path_size: usize, perm: u64) -> ErrorCode {
    todo!()
}

pub extern "C" fn stat(path_ptr: *const u8, path_size: usize, attr: *mut FileAttr) -> ErrorCode {
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };

    match FsClient::stat(path) {
        Ok(a) => {
            unsafe { *attr = a };
            E_OK
        }
        Err(err) => err,
    }
}

pub extern "C" fn canonicalize(
    in_ptr: *const u8,
    in_size: usize,
    out_ptr: *mut u8,
    out_size: *mut usize,
) -> ErrorCode {
    let path_bytes = unsafe { core::slice::from_raw_parts(in_ptr, in_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };

    let c_path = match CanonicalPath::parse(path) {
        Ok(cp) => cp,
        Err(err) => return err,
    };
    match FsClient::stat(c_path.abs_path.as_str()) {
        Ok(_) => {}
        Err(err) => return err,
    }

    let out_bytes = c_path.abs_path.as_bytes();
    assert!(out_bytes.len() <= moto_rt::fs::MAX_PATH_LEN);
    unsafe {
        core::ptr::copy_nonoverlapping(out_bytes.as_ptr(), out_ptr, out_bytes.len());
        *out_size = out_bytes.len();
    }

    E_OK
}

pub extern "C" fn copy(
    from_ptr: *const u8,
    from_size: usize,
    to_ptr: *const u8,
    to_size: usize,
) -> i64 {
    todo!()
}

pub extern "C" fn opendir(path_ptr: *const u8, path_size: usize) -> i32 {
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };
    let rdr = match FsClient::readdir(path) {
        Ok(rdr) => rdr,
        Err(err) => return -(err as i32),
    };

    DESCRIPTORS.push(alloc::sync::Arc::new(Fd::ReadDir(rdr)))
}

pub extern "C" fn closedir(rt_fd: i32) -> ErrorCode {
    let fd = if let Some(fd) = DESCRIPTORS.pop(rt_fd) {
        fd
    } else {
        return E_BAD_HANDLE;
    };

    let rdr = if let Fd::ReadDir(rdr) = fd.as_ref() {
        rdr
    } else {
        return E_BAD_HANDLE;
    };

    match FsClient::close_fd(rdr.fd, CloseFdRequest::F_READDIR) {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn readdir(rt_fd: i32, dentry: *mut DirEntry) -> ErrorCode {
    let fd = if let Some(fd) = DESCRIPTORS.get(rt_fd) {
        fd
    } else {
        return E_BAD_HANDLE;
    };

    let rdr = if let Fd::ReadDir(rdr) = fd.as_ref() {
        rdr
    } else {
        return E_BAD_HANDLE;
    };

    let de = match FsClient::readdir_next(&rdr) {
        Ok(de) => de,
        Err(err) => return err,
    };

    unsafe { *dentry = de };
    E_OK
}

pub extern "C" fn getcwd(out_ptr: *mut u8, out_size: *mut usize) -> ErrorCode {
    let cwd = match FsClient::getcwd() {
        Ok(cwd) => cwd,
        Err(err) => return err,
    };
    let out_bytes = cwd.as_bytes();
    assert!(out_bytes.len() <= moto_rt::fs::MAX_PATH_LEN);
    unsafe {
        core::ptr::copy_nonoverlapping(out_bytes.as_ptr(), out_ptr, out_bytes.len());
        *out_size = out_bytes.len();
    }

    E_OK
}

pub extern "C" fn chdir(path_ptr: *const u8, path_size: usize) -> ErrorCode {
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };
    match FsClient::chdir(path) {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

// ---------------------- implementation details below ------------------------ //

pub struct ReadDir {
    path: String,
    fd: u64,
}

impl ReadDir {
    fn from(path: String, resp: &ReadDirResponse) -> Result<ReadDir, ErrorCode> {
        Ok(ReadDir { path, fd: resp.fd })
    }
}

pub struct File {
    // We save the file's abs path because sys-io does not provide a way to
    // query file attributes by fd, only by path.
    // TODO: implement get_file_attr by fd, remove abs_path.
    abs_path: String,
    fd: u64,
    pos: AtomicU64, // Atomic because read operations take &File, but change pos.
}

// Given a path str from the user, figure out the absolute path, filename, etc.
#[derive(Clone)]
struct CanonicalPath {
    abs_path: String,
    fname_offset: u16, // The last component.
}

impl CanonicalPath {
    fn _filename(&self) -> &str {
        &self.abs_path.as_str()[(self.fname_offset as usize)..]
    }

    fn normalize(abs_path: &str) -> Result<Self, ErrorCode> {
        if (abs_path.len() == 0) || (abs_path.len() >= MAX_PATH_LEN) {
            return Err(moto_rt::E_INVALID_FILENAME);
        }
        if &abs_path[0..1] != "/" {
            return Err(moto_rt::E_INVALID_FILENAME);
        }

        if abs_path == "/" {
            return Ok(CanonicalPath {
                abs_path: abs_path.to_owned(),
                fname_offset: 1,
            });
        }

        let mut components = alloc::vec![];
        for entry in abs_path.split('/') {
            if entry.is_empty() {
                continue;
            }
            if entry == "." {
                continue;
            }
            if entry.len() != entry.trim().len() {
                return Err(moto_rt::E_INVALID_FILENAME);
            }

            if entry == ".." {
                if components.len() == 0 {
                    return Err(moto_rt::E_INVALID_FILENAME);
                }
                components.pop();
            } else {
                components.push(entry);
            }
        }

        if components.len() == 0 {
            return Ok(CanonicalPath {
                abs_path: "/".to_owned(),
                fname_offset: 1,
            });
        }

        let mut result = String::new();
        for entry in &components {
            result.push('/');
            result.push_str(entry);
        }

        let fname_offset = result.len() - components[components.len() - 1].len();

        Ok(CanonicalPath {
            abs_path: result,
            fname_offset: fname_offset as u16,
        })
    }

    fn parse(path: &str) -> Result<Self, ErrorCode> {
        if (path.len() == 0) || (path.len() >= MAX_PATH_LEN) || (path.len() != path.trim().len()) {
            return Err(moto_rt::E_INVALID_FILENAME);
        }

        if path == "/" {
            return Ok(CanonicalPath {
                abs_path: path.to_owned(),
                fname_offset: 1, // Empty filename.
            });
        }

        if path.trim_end_matches('/').len() != path.len() {
            return Err(moto_rt::E_INVALID_FILENAME);
        }

        if path.starts_with('/') {
            return Self::normalize(path);
        }

        let mut abs_path = {
            match FsClient::getcwd() {
                Ok(cwd) => cwd,
                Err(_) => {
                    // Can't work with rel paths without cwd.
                    return Err(moto_rt::E_INVALID_FILENAME);
                }
            }
        };

        if abs_path != "/" {
            abs_path.push('/');
        }
        abs_path.push_str(path);

        Self::normalize(abs_path.as_str())
    }
}

struct FsClient {
    conn: Mutex<moto_ipc::sync::ClientConnection>,
    cwd: Mutex<String>, // Current Working Directory.
}

static FS_CLIENT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static FS_CLIENT_INITIALIZED: Mutex<bool> = Mutex::new(false);

impl FsClient {
    fn new(url: String) -> Result<(), ErrorCode> {
        use alloc::boxed::Box;

        let mut conn = moto_ipc::sync::ClientConnection::new(moto_ipc::sync::ChannelSize::Small)?;
        if let Err(err) = conn.connect(url.as_str()) {
            moto_sys::SysRay::log("Failed to connect to FS driver.").ok();
            return Err(err.into());
        }

        let fs_client = Box::leak(Box::new(FsClient {
            conn: Mutex::new(conn),
            cwd: Mutex::new(if let Some(cwd) = super::rt_process::EnvRt::get("PWD") {
                cwd
            } else {
                "/".to_owned()
            }), // TODO: get it from PWD env var.
        }));
        assert_eq!(
            0,
            FS_CLIENT.swap(fs_client as *const _ as usize, Ordering::SeqCst)
        );

        Ok(())
    }

    fn get() -> Result<&'static FsClient, ErrorCode> {
        let mut addr = FS_CLIENT.load(Ordering::Relaxed);
        if addr == 0 {
            let mut initialized = FS_CLIENT_INITIALIZED.lock();
            if !*initialized {
                let driver_url = get_fileserver_url()?;
                FsClient::new(driver_url)?;
                *initialized = true;
            }
            addr = FS_CLIENT.load(Ordering::SeqCst);
            assert_ne!(addr, 0);
        }

        unsafe { Ok((addr as *const FsClient).as_ref().unwrap_unchecked()) }
    }

    fn getcwd() -> Result<String, ErrorCode> {
        Ok(Self::get()?.cwd.lock().clone())
    }

    fn chdir(path: &str) -> Result<(), ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let self_ = Self::get()?;

        let cwd = {
            let mut conn = self_.conn.lock();
            let raw_channel = conn.raw_channel();
            unsafe {
                let req = raw_channel.get_mut::<StatRequest>();
                req.header.cmd = CMD_STAT;
                req.header.ver = 0;
                req.header.flags = 0;
                req.parent_fd = 0;

                req.fname_size = c_path.abs_path.as_bytes().len() as u16;
                raw_channel.put_bytes(c_path.abs_path.as_bytes(), req.fname.as_mut_ptr())?;
            }

            conn.do_rpc(None)?;

            let resp = unsafe { raw_channel.get::<StatResponse>() };
            if resp.header.result != 0 {
                return Err(resp.header.result);
            }

            if resp.attr.file_type != moto_rt::fs::FILETYPE_DIRECTORY {
                return Err(moto_rt::E_NOT_A_DIRECTORY);
            }

            c_path.abs_path
        };

        *self_.cwd.lock() = cwd;
        Ok(())
    }

    fn rename(old: &str, new: &str) -> Result<(), ErrorCode> {
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<RenameRequest>();
            let old_path = CanonicalPath::parse(old)?;
            let new_path = CanonicalPath::parse(new)?;

            req.build(
                old_path.abs_path.as_str(),
                new_path.abs_path.as_str(),
                &raw_channel,
            )?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<RenameResponse>() };
        if resp.header.result != 0 {
            return Err(resp.header.result);
        }

        Ok(())
    }

    fn unlink(path: &str, flags: u32) -> Result<(), ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();

        unsafe {
            let req = raw_channel.get_mut::<UnlinkRequest>();
            req.header.cmd = CMD_UNLINK;
            req.header.ver = 0;
            req.header.flags = flags;
            req.parent_fd = 0;

            req.fname_size = c_path.abs_path.as_bytes().len() as u16;
            raw_channel.put_bytes(c_path.abs_path.as_bytes(), req.fname.as_mut_ptr())?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<UnlinkResponse>() };
        if resp.header.result != 0 {
            return Err(resp.header.result);
        }

        Ok(())
    }

    fn file_open(path: &str, opts: u32) -> Result<File, ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();

        unsafe {
            let req = raw_channel.get_mut::<FileOpenRequest>();
            req.header.cmd = CMD_FILE_OPEN;
            req.header.ver = 0;
            req.header.flags = opts;
            req.parent_fd = 0;

            req.fname_size = c_path.abs_path.as_bytes().len() as u16;
            raw_channel.put_bytes(c_path.abs_path.as_bytes(), req.fname.as_mut_ptr())?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<FileOpenResponse>() };
        if resp.header.result != 0 {
            return Err(resp.header.result);
        }

        if resp.fd == 0 {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        Ok(File {
            abs_path: c_path.abs_path,
            fd: resp.fd,
            pos: AtomicU64::new(0),
        })
    }

    fn seek(file: &File, offset: i64, whence: u8) -> Result<u64, ErrorCode> {
        let file_size = {
            let attr = Self::stat(&file.abs_path)?;
            attr.size
        };
        match whence {
            moto_rt::fs::SEEK_CUR => {
                if offset == 0 {
                    return Ok(file.pos.load(Ordering::Relaxed));
                }

                loop {
                    let curr = file.pos.load(Ordering::Relaxed) as i64;
                    let new = curr + offset;
                    if (new > (file_size as i64)) || (new < 0) {
                        return Err(moto_rt::E_INVALID_ARGUMENT);
                    }

                    if file
                        .pos
                        .compare_exchange_weak(
                            curr as u64,
                            new as u64,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        return Ok(new as u64);
                    }
                }
            }
            moto_rt::fs::SEEK_SET => {
                if offset < 0 {
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }
                if (offset as u64) > file_size {
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }
                file.pos.store(offset as u64, Ordering::Relaxed);
                Ok(offset as u64)
            }
            moto_rt::fs::SEEK_END => {
                if (offset < 0) && ((-offset as u64) > file_size) {
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }
                if offset > 0 {
                    moto_sys::SysRay::log("fs.rs: File::seek past end Not Implemented").ok();
                    return Err(moto_rt::E_NOT_IMPLEMENTED);
                }
                let new_pos = file_size - ((-offset) as u64);
                file.pos.store(new_pos, Ordering::Relaxed);
                Ok(new_pos)
            }
            _ => Err(E_INVALID_ARGUMENT),
        }
    }

    fn read(file: &File, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<FileReadRequest>();
            req.header.cmd = CMD_FILE_READ;
            req.header.ver = 0;
            req.fd = file.fd;
            req.offset = file.pos.load(Ordering::Relaxed);
            req.max_bytes = {
                if buf.len() > raw_channel.size() {
                    raw_channel.size()
                } else {
                    buf.len()
                }
            } as u32;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<FileReadResponse>() };
        if resp.header.result != 0 {
            return Err(resp.header.result);
        }

        // resp.size may be BLOCK_SIZE if buf is too small.
        let result_sz = buf.len().min(resp.size as usize);

        unsafe {
            let bytes = raw_channel.get_bytes(resp.data.as_ptr(), result_sz)?;
            core::intrinsics::copy_nonoverlapping(bytes.as_ptr(), buf.as_mut_ptr(), result_sz);
            file.pos.fetch_add(result_sz as u64, Ordering::Relaxed);
            Ok(result_sz)
        }
    }

    fn write(file: &File, buf: &[u8]) -> Result<usize, ErrorCode> {
        if buf.len() == 0 {
            moto_sys::SysRay::log("FS: write request with empty buf").ok();
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<FileWriteRequest>();
            req.header.cmd = CMD_FILE_WRITE;
            req.header.ver = 0;
            req.header.flags = 0;
            req.fd = file.fd;
            req.offset = file.pos.load(Ordering::Relaxed);

            let size =
                (raw_channel.size() - core::mem::size_of::<FileWriteRequest>()).min(buf.len());
            req.size = size as u32;

            raw_channel
                .put_bytes(&buf[0..size], req.data.as_mut_ptr())
                .unwrap();
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<FileWriteResponse>() };
        if resp.header.result != 0 {
            return Err(resp.header.result);
        }

        file.pos.fetch_add(resp.written as u64, Ordering::Relaxed);

        Ok(resp.written as usize)
    }

    fn readdir(path: &str) -> Result<ReadDir, ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<ReadDirRequest>();
            req.header.cmd = CMD_READDIR;
            req.header.ver = 0;
            req.header.flags = 0;
            req.parent_fd = 0;

            req.fname_size = c_path.abs_path.as_bytes().len() as u16;
            raw_channel.put_bytes(c_path.abs_path.as_bytes(), req.fname.as_mut_ptr())?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<ReadDirResponse>() };
        if resp.header.result != 0 {
            return Err(resp.header.result);
        }

        ReadDir::from(c_path.abs_path, &resp)
    }

    fn readdir_next(readdir: &ReadDir) -> Result<DirEntry, ErrorCode> {
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<ReadDirNextRequest>();
            req.header.cmd = CMD_READDIR_NEXT;
            req.header.ver = 0;
            req.header.flags = 0;
            req.readdir_fd = readdir.fd;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<ReadDirNextResponse>() };
        if resp.header.result != 0 {
            return Err(resp.header.result);
        }

        Ok(resp.dir_entry)
    }

    fn close_fd(fd: u64, flags: u32) -> Result<(), ErrorCode> {
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<CloseFdRequest>();
            req.header.cmd = CMD_CLOSE_FD;
            req.header.ver = 0;
            req.header.flags = flags;
            req.fd = fd;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<CloseFdResponse>() };
        if resp.header.result != 0 {
            moto_sys::SysRay::log("close_fd: RPC failed.").ok();
        }

        Ok(())
    }

    fn stat(path: &str) -> Result<FileAttr, ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();

        unsafe {
            let req = raw_channel.get_mut::<StatRequest>();
            req.header.cmd = CMD_STAT;
            req.header.ver = 0;
            req.header.flags = 0;
            req.parent_fd = 0;

            req.fname_size = c_path.abs_path.as_bytes().len() as u16;
            raw_channel.put_bytes(c_path.abs_path.as_bytes(), req.fname.as_mut_ptr())?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<StatResponse>() };
        if resp.header.result != 0 {
            return Err(resp.header.result);
        }

        Ok(resp.attr)
    }

    fn mkdir(path: &str) -> Result<(), ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();

        unsafe {
            let req = raw_channel.get_mut::<MkdirRequest>();
            req.header.cmd = CMD_MKDIR;
            req.header.ver = 0;
            req.header.flags = 0;
            req.parent_fd = 0;

            req.fname_size = c_path.abs_path.as_bytes().len() as u16;
            raw_channel.put_bytes(c_path.abs_path.as_bytes(), req.fname.as_mut_ptr())?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<MkdirResponse>() };
        if resp.header.result != 0 {
            return Err(resp.header.result);
        }

        Ok(())
    }
}

fn get_fileserver_url() -> Result<String, ErrorCode> {
    let mut conn = moto_ipc::sync::ClientConnection::new(moto_ipc::sync::ChannelSize::Small)?;
    conn.connect(FS_URL)?;

    let req = conn.req::<GetServerUrlRequest>();
    req.header.cmd = 1;
    req.header.ver = 0;
    req.header.flags = 0;
    conn.do_rpc(Some(
        moto_rt::time::Instant::now() + core::time::Duration::from_millis(1000),
    ))?;

    let resp = conn.resp::<GetServerUrlResponse>();
    if resp.header.result != 0 || resp.header.ver != 0 {
        moto_sys::SysRay::log("get_fileserver_url() failed.").ok();
        return Err(moto_rt::E_INTERNAL_ERROR);
    }

    Ok(unsafe { resp.url() }?.to_owned())
}
