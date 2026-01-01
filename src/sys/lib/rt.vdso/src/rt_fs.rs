//! Rust's stdlib FS (filesystem) backend.
//!
//! This module bridges Motor OS's "native" FS client in moto-io,
//! which is async and local-thread-only, with the posixy/Linuxy way
//! Rust's stdlib expect FS to behave (FDs, polling, etc.).
use crate::posix::PosixFile;
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Deref;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64};
use core::sync::atomic::{AtomicUsize, Ordering};
use moto_async::AsFuture;
use moto_io::fs::{EntryId, FsClient, ROOT_ID};
use moto_ipc::io_channel;
use moto_rt::Result;
use moto_rt::fs::HANDLE_URL_PREFIX;
use moto_rt::fs::MAX_PATH_LEN;
use moto_sys::SysHandle;
use moto_sys_io::api_fs_legacy;

type IoTask = Box<
    dyn FnOnce(alloc::rc::Rc<moto_io::fs::FsClient>) -> Pin<Box<dyn Future<Output = ()>>> + Send,
>;

// Given a path str from the user, figure out the absolute path, filename, etc.
#[derive(Clone)]
struct CanonicalPath {
    abs_path: String,
    fname_offset: usize, // The last component.
}

impl CanonicalPath {
    fn filename(&self) -> &str {
        &self.abs_path.as_str()[self.fname_offset..]
    }

    fn parent(&self) -> Option<&str> {
        if self.is_root() {
            None
        } else {
            Some(&self.abs_path.as_str()[..self.fname_offset])
        }
    }

    fn is_root(&self) -> bool {
        self.abs_path == "/"
    }

    fn normalize(abs_path: &str) -> Result<Self> {
        if abs_path.is_empty() || (abs_path.len() >= MAX_PATH_LEN) {
            return Err(moto_rt::Error::InvalidFilename);
        }
        if &abs_path[0..1] != "/" {
            return Err(moto_rt::Error::InvalidFilename);
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
                return Err(moto_rt::Error::InvalidFilename);
            }

            if entry == ".." {
                if components.is_empty() {
                    return Err(moto_rt::Error::InvalidFilename);
                }
                components.pop();
            } else {
                components.push(entry);
            }
        }

        if components.is_empty() {
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
            fname_offset,
        })
    }

    fn parse(path: &str) -> Result<Self> {
        if path.is_empty() || (path.len() >= MAX_PATH_LEN) || (path.len() != path.trim().len()) {
            return Err(moto_rt::Error::InvalidFilename);
        }

        if path == "/" {
            return Ok(CanonicalPath {
                abs_path: path.to_owned(),
                fname_offset: 1, // Empty filename.
            });
        }

        if path.trim_end_matches('/').len() != path.len() {
            return Err(moto_rt::Error::InvalidFilename);
        }

        if path.starts_with('/') {
            return Self::normalize(path);
        }

        let mut abs_path = {
            match AsyncFsClient::getcwd() {
                Ok(cwd) => cwd,
                Err(_) => {
                    // Can't work with rel paths without cwd.
                    return Err(moto_rt::Error::InvalidFilename);
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

pub struct AsyncFsClient {
    tasks_tx: moto_async::channel::Sender<IoTask>,
    cwd: moto_rt::mutex::Mutex<String>, // Current Working Directory.
}

static ASYNC_CLIENT: AtomicUsize = AtomicUsize::new(CLIENT_NONE);

const CLIENT_NONE: usize = 0;
const CLIENT_PENDING: usize = 1;
const CLIENT_ERROR: usize = 2;

impl AsyncFsClient {
    pub fn get() -> Result<&'static Self> {
        let addr = ASYNC_CLIENT.load(core::sync::atomic::Ordering::Relaxed);
        if addr == CLIENT_ERROR {
            return Err(moto_rt::Error::NotFound);
        }
        if addr > CLIENT_ERROR {
            return Ok(unsafe { (addr as *const Self).as_ref_unchecked() });
        }

        if addr == CLIENT_NONE {
            // Try to "acquire" the pointer.
            if ASYNC_CLIENT
                .compare_exchange(
                    CLIENT_NONE,
                    CLIENT_PENDING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                // We succeeded in "acquiring" the pointer.
                return Self::create()
                    .inspect_err(|_| ASYNC_CLIENT.store(CLIENT_ERROR, Ordering::Release));
            }
        }

        // Wait for a concurrent initialization.
        loop {
            super::rt_thread::sleep(
                (moto_rt::time::Instant::now() + core::time::Duration::from_micros(20)).as_u64(),
            );

            let addr = ASYNC_CLIENT.load(core::sync::atomic::Ordering::Relaxed);
            if addr > 1 {
                return Ok(unsafe { (addr as *const Self).as_ref_unchecked() });
            }
        }
    }

    extern "C" fn runtime_thread(param: u64) {
        // Safety: safe by construction. See Self::create().
        let boxed = unsafe {
            Box::from_raw(
                param as usize
                    as *mut (
                        moto_async::channel::Receiver<IoTask>,
                        Rc<moto_io::fs::FsClient>,
                    ),
            )
        };
        let (tasks_rx, fs_client) = Box::into_inner(boxed);
        moto_sys::set_current_thread_name("rt_fs::runtime").unwrap();

        moto_async::LocalRuntime::new().block_on(Self::main_runtime_task(tasks_rx, fs_client));
    }

    async fn main_runtime_task(
        mut tasks_rx: moto_async::channel::Receiver<IoTask>,
        fs_client: Rc<moto_io::fs::FsClient>,
    ) {
        loop {
            let io_task = tasks_rx.recv().await.unwrap();
            let result = io_task(fs_client.clone()).await;
        }
    }

    fn create() -> Result<&'static Self> {
        moto_async::LocalRuntime::new().block_on(async move {
            let fs_client = moto_io::fs::FsClient::connect()?;
            let (tasks_tx, tasks_rx) = moto_async::channel(8);

            let this = alloc::boxed::Box::leak(alloc::boxed::Box::new(AsyncFsClient {
                tasks_tx,
                cwd: moto_rt::mutex::Mutex::new(
                    if let Some(cwd) = super::rt_process::EnvRt::get("PWD") {
                        cwd
                    } else {
                        "/".to_owned()
                    },
                ),
            }));

            let addr = this as *mut _ as usize;
            let runtime_thread_param = Box::into_raw(Box::new((tasks_rx, fs_client)));

            let thread_handle = moto_sys::SysCpu::spawn(
                SysHandle::SELF,
                4096 * 16,
                Self::runtime_thread as *const () as usize as u64,
                runtime_thread_param as u64,
            )
            .expect("Error spawning the runtime thread (FS).");

            assert!(
                ASYNC_CLIENT
                    .compare_exchange(CLIENT_PENDING, addr, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            );

            log::debug!("AsyncFsClient created.");

            unsafe { Ok((addr as *const Self).as_ref_unchecked()) }
        })
    }

    fn getcwd() -> Result<String> {
        Ok(Self::get()?.cwd.lock().clone())
    }

    fn chdir(_path: &str) -> Result<()> {
        todo!()
        /*
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

                req.fname_size = c_path.abs_path.len() as u16;
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
        */
    }

    fn file_open(&self, path: &str, opts: u32) -> Result<File> {
        log::debug!("file_open('{path}', {opts:x})");

        if (opts & moto_rt::fs::O_NONBLOCK) != 0 {
            // Not yet.
            return Err(moto_rt::Error::NotImplemented);
        }

        if ((opts & moto_rt::fs::O_TRUNCATE) != 0) && ((opts & moto_rt::fs::O_APPEND) != 0) {
            return Err(moto_rt::Error::InvalidArgument);
        }

        let path = CanonicalPath::parse(path)?;

        let maybe_entry_id = match self.stat_internal(path.clone()) {
            Ok(entry_id) => Some(entry_id),
            Err(moto_rt::Error::NotFound) => None,
            Err(err) => return Err(err),
        };

        let entry_id = match maybe_entry_id {
            Some(entry_id) => {
                if (opts & moto_rt::fs::O_CREATE_NEW) != 0 {
                    return Err(moto_rt::Error::AlreadyInUse);
                }

                log::error!("validate that entry is a file, not a dir");
                if (opts & moto_rt::fs::O_TRUNCATE) != 0 {
                    self.resize(entry_id, 0)?;
                }
                entry_id
            }
            None => {
                if (opts & (moto_rt::fs::O_CREATE_NEW | moto_rt::fs::O_CREATE)) == 0 {
                    return Err(moto_rt::Error::NotFound);
                }
                self.create_internal(&path, moto_io::fs::EntryKind::File)?
            }
        };

        let pos = if (opts & moto_rt::fs::O_APPEND) != 0 {
            todo!()
        } else {
            0
        };

        log::debug!("file_open('{}', {opts:x}) -> {entry_id:x}", path.abs_path);
        Ok(File {
            entry_id,
            pos: AtomicU64::new(pos),
            readable: (opts & moto_rt::fs::O_READ) != 0,
            writable: (opts & moto_rt::fs::O_WRITE) != 0,
            nonblocking: AtomicBool::new(false),
        })
    }

    /// Run `io_task` on the runtime thread.
    fn blocking_run<T, F, Fut>(&self, io_task: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(Rc<FsClient>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
    {
        let (tx_result, rx_result) = moto_async::oneshot();

        let task: IoTask = Box::new(move |fs_client: Rc<FsClient>| {
            let future = io_task(fs_client);

            Box::pin(async move {
                let result = future.await;
                let _ = tx_result.send(result);
            })
        });

        moto_async::LocalRuntime::new().block_on(async {
            let _ = self.tasks_tx.send(task).await;
            rx_result.await.unwrap()
        })
    }

    fn create_internal(
        &self,
        path: &CanonicalPath,
        kind: moto_io::fs::EntryKind,
    ) -> Result<EntryId> {
        if path.is_root() {
            return Err(moto_rt::Error::AlreadyInUse);
        }
        let path = path.clone();

        self.blocking_run(move |fs_client| async move {
            let parent = path.parent().unwrap();
            let Ok(parent_id) = fs_client.stat(parent).await else {
                return Err(moto_rt::Error::NotFound);
            };

            fs_client
                .create_entry(parent_id, kind, path.filename())
                .await
        })
    }

    fn stat_internal(&self, path: CanonicalPath) -> Result<EntryId> {
        if path.is_root() {
            return Ok(ROOT_ID);
        }

        self.blocking_run(move |fs_client| async move { fs_client.stat(&path.abs_path).await })
    }

    fn write(&self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize> {
        let buf_addr = buf.as_ptr() as usize;
        let buf_len = buf.len();

        self.blocking_run(move |fs_client| async move {
            // Safety: The task blocks the caller, keeping the original slice valid.
            let buf = unsafe { core::slice::from_raw_parts(buf_addr as *const u8, buf_len) };
            fs_client.write(file_id, offset, buf).await
        })
    }

    fn read(&self, file_id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let buf_addr = buf.as_mut_ptr() as usize;
        let buf_len = buf.len();

        self.blocking_run(move |fs_client| async move {
            // Safety: The task blocks the caller, keeping the original slice valid.
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_addr as *mut u8, buf_len) };
            fs_client.read(file_id, offset, buf).await
        })
    }

    fn stat(&self, path: &str) -> Result<moto_rt::fs::FileAttr> {
        let path = CanonicalPath::parse(path)?;
        let entry_id = self.stat_internal(path)?;

        self.metadata(entry_id)
    }

    fn metadata(&self, entry_id: EntryId) -> Result<moto_rt::fs::FileAttr> {
        let metadata =
            self.blocking_run(move |fs_client| async move { fs_client.metadata(entry_id).await })?;

        let mut file_attr = moto_rt::fs::FileAttr::new();
        file_attr.size = metadata.size;
        file_attr.perm = moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE;
        file_attr.file_type = match metadata.kind() {
            moto_io::fs::EntryKind::Directory => moto_rt::fs::FILETYPE_DIRECTORY,
            moto_io::fs::EntryKind::File => moto_rt::fs::FILETYPE_FILE,
        };
        file_attr.created = metadata.created.as_nanos();
        file_attr.modified = metadata.modified.as_nanos();
        file_attr.accessed = metadata.accessed.as_nanos();

        Ok(file_attr)
    }

    fn resize(&self, file_id: EntryId, new_size: u64) -> Result<()> {
        self.blocking_run(move |fs_client| async move { fs_client.resize(file_id, new_size).await })
    }
}

struct File {
    entry_id: moto_io::fs::EntryId,
    pos: AtomicU64,
    readable: bool,
    writable: bool,
    nonblocking: AtomicBool,
}

impl PosixFile for File {
    fn kind(&self) -> crate::posix::PosixKind {
        todo!()
    }

    fn write(&self, buf: &[u8]) -> core::result::Result<usize, moto_rt::ErrorCode> {
        if !self.writable {
            return Err(moto_rt::E_NOT_ALLOWED);
        }

        if self.nonblocking.load(Ordering::Acquire) {
            todo!("Implement nonblocking FS ops");
        }

        let pos = self.pos.load(Ordering::Acquire);
        let written = AsyncFsClient::get()
            .expect("Couldn't initialize AsyncFsClient")
            .write(self.entry_id, pos, buf)
            .map_err(|err| err as moto_rt::ErrorCode)?;

        self.pos.store(pos + (written as u64), Ordering::Release);
        Ok(written)
    }

    fn read(&self, buf: &mut [u8]) -> core::result::Result<usize, moto_rt::ErrorCode> {
        if !self.readable {
            return Err(moto_rt::E_NOT_ALLOWED);
        }

        if self.nonblocking.load(Ordering::Acquire) {
            todo!("Implement nonblocking FS ops");
        }

        let pos = self.pos.load(Ordering::Acquire);
        let read = AsyncFsClient::get()
            .expect("Couldn't initialize AsyncFsClient")
            .read(self.entry_id, pos, buf)
            .map_err(|err| err as moto_rt::ErrorCode)?;

        self.pos.store(pos + (read as u64), Ordering::Release);
        Ok(read)
    }
    unsafe fn read_vectored(
        &self,
        bufs: &mut [&mut [u8]],
    ) -> core::result::Result<usize, moto_rt::ErrorCode> {
        todo!()
    }
    unsafe fn write_vectored(
        &self,
        bufs: &[&[u8]],
    ) -> core::result::Result<usize, moto_rt::ErrorCode> {
        todo!()
    }
    fn flush(&self) -> core::result::Result<(), moto_rt::ErrorCode> {
        todo!()
    }

    // rt_fd indicates which FD is closed.
    fn close(&self, rt_fd: moto_rt::RtFd) -> core::result::Result<(), moto_rt::ErrorCode> {
        Ok(())
    }
    fn set_nonblocking(&self, val: bool) -> core::result::Result<(), moto_rt::ErrorCode> {
        Err(moto_rt::E_NOT_IMPLEMENTED)
    }

    /*
    fn poll_add(
        &self,
        r_id: u64,
        source_fd: moto_rt::RtFd,
        token: Token,
        interests: Interests,
    ) -> core::result::Result<(), moto_rt::ErrorCode> {
        todo!()
        // Err(E_INVALID_ARGUMENT)
    }
    fn poll_set(
        &self,
        r_id: u64,
        source_fd: moto_rt::RtFd,
        token: Token,
        interests: Interests,
    ) -> core::result::Result<(), moto_rt::ErrorCode> {
        todo!()
        // Err(E_INVALID_ARGUMENT)
    }
    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> core::result::Result<(), moto_rt::ErrorCode> {
        panic!("Unexpected poll_del for {:?}", self.kind())
        // Err(E_INVALID_ARGUMENT)
    }
    */
}

// ------------------------------------ public API ------------------------------ //

pub fn ok() -> bool {
    AsyncFsClient::get().is_ok()
}

pub extern "C" fn stat(
    path_ptr: *const u8,
    path_size: usize,
    attr: *mut moto_rt::fs::FileAttr,
) -> moto_rt::ErrorCode {
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };

    match AsyncFsClient::get().unwrap().stat(path) {
        Ok(a) => {
            unsafe { *attr = a };
            moto_rt::Error::Ok.into()
        }
        Err(err) => err.into(),
    }
}

pub extern "C" fn open(path_ptr: *const u8, path_size: usize, opts: u32) -> i32 {
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    if (path_bytes.len() > HANDLE_URL_PREFIX.len())
        && (&path_bytes[0..HANDLE_URL_PREFIX.len()] == HANDLE_URL_PREFIX.as_bytes())
    {
        match opts {
            moto_rt::fs::O_HANDLE_CHILD => {
                let Ok(handle_str) = core::str::from_utf8(&path_bytes[HANDLE_URL_PREFIX.len()..])
                else {
                    return -(moto_rt::E_INVALID_ARGUMENT as i32);
                };

                let Ok(handle) = handle_str.parse::<u64>() else {
                    return -(moto_rt::E_INVALID_ARGUMENT as i32);
                };
                return crate::proc_fd::new_child_fd(handle.into());
            }
            _ => return -(moto_rt::E_INVALID_ARGUMENT as i32),
        }
    }
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };
    let file = match AsyncFsClient::get()
        .expect("Couldn't initialize AsyncFsClient")
        .file_open(path, opts)
    {
        Ok(file) => file,
        Err(err) => return -(err as i32),
    };

    crate::posix::push_file(alloc::sync::Arc::new(file))
}

pub extern "C" fn get_file_attr(
    rt_fd: i32,
    attr: *mut moto_rt::fs::FileAttr,
) -> moto_rt::ErrorCode {
    use core::any::Any;

    let Some(posix_file) = crate::posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };
    let Some(file) = (posix_file.as_ref() as &dyn Any).downcast_ref::<File>() else {
        return moto_rt::E_BAD_HANDLE;
    };

    match AsyncFsClient::get().unwrap().metadata(file.entry_id) {
        Ok(a) => {
            unsafe { *attr = a };
            moto_rt::Error::Ok.into()
        }
        Err(err) => err.into(),
    }
}

pub extern "C" fn seek(rt_fd: i32, offset: i64, whence: u8) -> i64 {
    use core::any::Any;

    let Some(posix_file) = crate::posix::get_file(rt_fd) else {
        return -(moto_rt::E_BAD_HANDLE as i64);
    };
    let Some(file) = (posix_file.as_ref() as &dyn Any).downcast_ref::<File>() else {
        return -(moto_rt::E_BAD_HANDLE as i64);
    };

    let file_size = {
        let attr = match AsyncFsClient::get().unwrap().metadata(file.entry_id) {
            Ok(attr) => attr,
            Err(err) => return -(err as u16 as i64),
        };

        if attr.file_type != moto_rt::fs::FILETYPE_FILE {
            return -(moto_rt::Error::InvalidArgument as u16 as i64);
        }
        attr.size
    };
    match whence {
        moto_rt::fs::SEEK_CUR => {
            if offset == 0 {
                return file.pos.load(Ordering::Acquire) as i64;
            }

            loop {
                let curr = file.pos.load(Ordering::Acquire) as i64;
                let new = curr + offset;
                if (new > (file_size as i64)) || (new < 0) {
                    return -(moto_rt::Error::InvalidArgument as u16 as i64);
                }

                if file
                    .pos
                    .compare_exchange_weak(
                        curr as u64,
                        new as u64,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    return new;
                }
            }
        }
        moto_rt::fs::SEEK_SET => {
            if offset < 0 {
                return -(moto_rt::Error::InvalidArgument as u16 as i64);
            }
            if (offset as u64) > file_size {
                return -(moto_rt::Error::InvalidArgument as u16 as i64);
            }
            file.pos.store(offset as u64, Ordering::Release);
            offset
        }
        moto_rt::fs::SEEK_END => {
            if (offset < 0) && ((-offset as u64) > file_size) {
                return -(moto_rt::Error::InvalidArgument as u16 as i64);
            }
            if offset > 0 {
                log::error!("File::seek past end Not Implemented");
                return -(moto_rt::Error::NotImplemented as u16 as i64);
            }
            let new_pos = file_size - ((-offset) as u64);
            file.pos.store(new_pos, Ordering::Release);
            new_pos as i64
        }
        _ => -(moto_rt::Error::InvalidArgument as u16 as i64),
    }
}

pub extern "C" fn truncate(rt_fd: i32, size: u64) -> moto_rt::ErrorCode {
    use core::any::Any;

    let Some(posix_file) = crate::posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };
    let Some(file) = (posix_file.as_ref() as &dyn Any).downcast_ref::<File>() else {
        return moto_rt::E_BAD_HANDLE;
    };

    match AsyncFsClient::get().unwrap().resize(file.entry_id, size) {
        Ok(()) => moto_rt::Error::Ok.into(),
        Err(err) => err.into(),
    }
}
