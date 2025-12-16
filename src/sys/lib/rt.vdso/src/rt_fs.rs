use crate::posix::PosixFile;
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Deref;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::{AtomicUsize, Ordering};
use moto_async::AsFuture;
use moto_io::fs::{EntryId, ROOT_ID};
use moto_ipc::io_channel;
use moto_rt::Error;
use moto_rt::fs::HANDLE_URL_PREFIX;
use moto_rt::fs::MAX_PATH_LEN;
use moto_sys::SysHandle;
use moto_sys_io::api_fs_legacy;

type Result<T> = core::result::Result<T, Error>;

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

    fn normalize(abs_path: &str) -> Result<Self> {
        if abs_path.is_empty() || (abs_path.len() >= MAX_PATH_LEN) {
            return Err(Error::InvalidFilename);
        }
        if &abs_path[0..1] != "/" {
            return Err(Error::InvalidFilename);
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
                return Err(Error::InvalidFilename);
            }

            if entry == ".." {
                if components.is_empty() {
                    return Err(Error::InvalidFilename);
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
            fname_offset: fname_offset as u16,
        })
    }

    fn parse(path: &str) -> Result<Self> {
        if path.is_empty() || (path.len() >= MAX_PATH_LEN) || (path.len() != path.trim().len()) {
            return Err(Error::InvalidFilename);
        }

        if path == "/" {
            return Ok(CanonicalPath {
                abs_path: path.to_owned(),
                fname_offset: 1, // Empty filename.
            });
        }

        if path.trim_end_matches('/').len() != path.len() {
            return Err(Error::InvalidFilename);
        }

        if path.starts_with('/') {
            return Self::normalize(path);
        }

        let mut abs_path = {
            match AsyncFsClient::getcwd() {
                Ok(cwd) => cwd,
                Err(_) => {
                    // Can't work with rel paths without cwd.
                    return Err(Error::InvalidFilename);
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
    io_sender: moto_ipc::io_channel::Sender,
    io_receiver: moto_ipc::io_channel::Receiver,

    client_handle: SysHandle,
    runtime_handle: SysHandle,

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
            return Err(Error::NotFound);
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

    extern "C" fn runtime_thread(self_addr: usize) {
        // Safety: safe by construction. See Self::create().
        let self_: &'static Self = unsafe { (self_addr as *const Self).as_ref().unwrap() };
        moto_sys::set_current_thread_name("rt_fs::runtime").unwrap();

        moto_async::LocalRuntime::new().block_on(self_.runtime_task());
    }

    async fn runtime_task(&'static self) {
        moto_async::LocalRuntime::spawn(self.local_queue_task()).await;
    }

    async fn local_queue_task(&'static self) {
        loop {
            self.runtime_handle.as_future().await;
            todo!()
        }
    }

    fn create() -> Result<&'static Self> {
        moto_async::LocalRuntime::new().block_on(async move {
            let (io_sender, io_receiver) =
                moto_ipc::io_channel::connect(moto_sys_io::api_fs_legacy::FS_URL)?;
            let (client_handle, runtime_handle) =
                moto_sys::SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0).unwrap();

            let this = alloc::boxed::Box::leak(alloc::boxed::Box::new(AsyncFsClient {
                io_sender,
                io_receiver,
                client_handle,
                runtime_handle,
                cwd: moto_rt::mutex::Mutex::new(
                    if let Some(cwd) = super::rt_process::EnvRt::get("PWD") {
                        cwd
                    } else {
                        "/".to_owned()
                    },
                ),
            }));

            let addr = this as *mut _ as usize;

            let thread_handle = moto_sys::SysCpu::spawn(
                SysHandle::SELF,
                4096 * 16,
                Self::runtime_thread as *const () as usize as u64,
                addr as u64,
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

    fn file_open(path: &str, opts: u32) -> Result<File> {
        if opts & moto_rt::fs::O_NONBLOCK != 0 {
            // Not yet.
            return Err(moto_rt::Error::NotImplemented);
        }
        let path = CanonicalPath::parse(path)?.abs_path;
        let entry_id = Self::stat_internal(path.as_str())?;

        todo!()
    }

    fn stat_internal(path: &str) -> Result<EntryId> {
        if path.is_empty() {
            return Err(moto_rt::Error::InvalidArgument);
        }
        if path == "/" {
            return Ok(ROOT_ID);
        }
        if !path.starts_with('/') {
            return Err(moto_rt::Error::InvalidArgument);
        }

        let (left, right) = path.rsplit_once('/').unwrap();
        assert!(!right.is_empty());

        todo!()
        // if left.is_empty() {
        //     return moto_io::fs::FileSystem::
        // }
    }
}

struct File {}

impl PosixFile for File {
    fn kind(&self) -> crate::posix::PosixKind {
        todo!()
    }
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
    todo!()
    /*
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_size) };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };

    match AsyncFsClient::stat(path) {
        Ok(a) => {
            unsafe { *attr = a };
            E_OK
        }
        Err(err) => err,
    }
    */
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
    let file = match AsyncFsClient::file_open(path, opts) {
        Ok(file) => file,
        Err(err) => return -(err as i32),
    };

    crate::posix::push_file(alloc::sync::Arc::new(file))
}
