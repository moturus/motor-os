//! FS driver: basically, runs a thread that receives I/O requests from
//! client processes and routes them to VirtioIO-BLK.

use core::sync::atomic::*;
use moto_ipc::sync::*;
use moto_rt::E_NOT_FOUND;
use moto_sys::{ErrorCode, SysHandle};
use moto_sys_io::api_fs::*;

use super::filesystem::fs;

struct PerConnectionData {
    next_fd: u64,
    readdirs: std::collections::HashMap<u64, Box<dyn super::filesystem::DirectoryIter>>,
    files: std::collections::HashMap<u64, Box<dyn super::filesystem::File>>,
}

impl PerConnectionData {
    fn new() -> Self {
        PerConnectionData {
            next_fd: 1,
            readdirs: std::collections::HashMap::new(),
            files: std::collections::HashMap::new(),
        }
    }

    fn add_readdir(&mut self, ptr: Box<dyn super::filesystem::DirectoryIter>) -> u64 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.readdirs.insert(fd, ptr);
        fd
    }

    fn get_readdir(&mut self, fd: u64) -> Option<&mut Box<dyn super::filesystem::DirectoryIter>> {
        self.readdirs.get_mut(&fd)
    }

    fn remove_readdir(&mut self, fd: u64) {
        self.readdirs.remove(&fd);
    }

    fn add_file(&mut self, ptr: Box<dyn super::filesystem::File>) -> u64 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.files.insert(fd, ptr);
        fd
    }

    fn get_file(&mut self, fd: u64) -> Option<&mut Box<dyn super::filesystem::File>> {
        self.files.get_mut(&fd)
    }

    fn remove_file(&mut self, fd: u64) {
        self.files.remove(&fd);
    }
}

struct Driver {
    ipc_server: LocalServer,
}

impl Driver {
    fn run() -> ! {
        let ipc_server = LocalServer::new(super::DRIVER_URL, ChannelSize::Small, 50, 20)
            .expect(format!("Failed to start listening on {}.", super::DRIVER_URL).as_str());
        let mut driver = Driver { ipc_server };

        // VirtIO interrupts are affined to CPU 0.
        moto_sys::SysCpu::affine_to_cpu(Some(0)).unwrap();

        super::STARTED.store(1, Ordering::Release);
        moto_rt::futex::futex_wake(&super::STARTED);

        loop {
            let Ok(wakers) = driver.ipc_server.wait(SysHandle::NONE, &[]) else {
                continue;
            };

            for waker in &wakers {
                let conn = driver.ipc_server.get_connection(*waker);
                if conn.is_none() {
                    continue;
                }
                let conn = unsafe { conn.unwrap_unchecked() };
                assert!(conn.connected());
                if !conn.have_req() {
                    continue;
                }

                let raw_channel = conn.raw_channel();
                unsafe {
                    let cmd = raw_channel.get::<RequestHeader>().cmd;

                    let result = match cmd {
                        CMD_STAT => Self::on_stat(raw_channel),
                        CMD_FILE_OPEN => Self::on_file_open(conn, raw_channel),
                        CMD_FILE_READ => Self::on_file_read(conn, raw_channel),
                        CMD_FILE_WRITE => Self::on_file_write(conn, raw_channel),
                        CMD_READDIR => Self::on_readdir(conn, raw_channel),
                        CMD_READDIR_NEXT => Self::on_readdir_next(conn, raw_channel),
                        CMD_CLOSE_FD => Self::on_close_fd(conn, raw_channel),
                        CMD_MKDIR => Self::on_mkdir(raw_channel),
                        CMD_UNLINK => Self::on_unlink(raw_channel),
                        CMD_RENAME => Self::on_rename(raw_channel),
                        _ => Err(moto_rt::E_INVALID_ARGUMENT),
                    };

                    if let Err(err) = result {
                        #[cfg(debug_assertions)]
                        if cmd != CMD_STAT && cmd != 0 && cmd != CMD_READDIR_NEXT {
                            // CMD_STAT is often used to probe, so don't spam the log.
                            // CMD_READDIR_NEXT returns E_NOT_FOUND when the loop ends.
                            crate::moto_log!("command {} failed with {:?}", cmd, err);
                        }

                        // #[cfg(debug_assertions)]
                        if cmd == 0 {
                            // This is wrong. But most likeky fixed.
                            static ONCE: std::sync::Once = std::sync::Once::new();
                            ONCE.call_once(|| {
                                crate::moto_log!("{}:{} ZERO", file!(), line!());
                            });
                        }
                        let raw_channel = conn.raw_channel();
                        let resp = raw_channel.get_mut::<ResponseHeader>();
                        resp.result = err;
                    }
                }

                let _ = conn.finish_rpc();
            }
        }
    }

    unsafe fn on_mkdir(raw_channel: RawChannel) -> Result<(), ErrorCode> {
        let req = raw_channel.get::<MkdirRequest>();
        assert_eq!(req.header.cmd, CMD_MKDIR);

        if (req.header.ver != 0) || (req.header.flags != 0) || (req.parent_fd != 0) {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        let fname_bytes = match raw_channel.get_bytes(req.fname.as_ptr(), req.fname_size as usize) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(moto_rt::E_INVALID_FILENAME);
            }
        };

        let fname = match core::str::from_utf8(fname_bytes) {
            Ok(fname) => fname,
            Err(_) => {
                return Err(moto_rt::E_INVALID_FILENAME);
            }
        };

        super::filesystem::fs().mkdir(fname)?;

        let resp = raw_channel.get_mut::<CloseFdResponse>();
        resp.header.result = 0;
        Ok(())
    }

    unsafe fn on_unlink(raw_channel: RawChannel) -> Result<(), ErrorCode> {
        let req = raw_channel.get::<UnlinkRequest>();
        assert_eq!(req.header.cmd, CMD_UNLINK);

        if (req.header.ver != 0) || (req.parent_fd != 0) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let fname_bytes = match raw_channel.get_bytes(req.fname.as_ptr(), req.fname_size as usize) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(moto_rt::E_INVALID_FILENAME);
            }
        };

        let fname = match core::str::from_utf8(fname_bytes) {
            Ok(fname) => fname,
            Err(_) => {
                return Err(moto_rt::E_INVALID_FILENAME);
            }
        };

        match req.header.flags {
            F_UNLINK_FILE => super::filesystem::fs().unlink(fname)?,
            F_UNLINK_DIR => super::filesystem::fs().delete_dir(fname)?,
            F_UNLINK_DIR_ALL => super::filesystem::fs().delete_dir_all(fname)?,
            _ => return Err(moto_rt::E_INVALID_ARGUMENT),
        }

        let resp = raw_channel.get_mut::<UnlinkResponse>();
        resp.header.result = 0;
        Ok(())
    }

    unsafe fn on_rename(raw_channel: RawChannel) -> Result<(), ErrorCode> {
        let req = raw_channel.get::<RenameRequest>();
        assert_eq!(req.header.cmd, CMD_RENAME);

        if (req.header.ver != 0) || (req.parent_fd != 0) || (req.header.flags != 0) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let old = req.old(&raw_channel)?;
        let new = req.new(&raw_channel)?;

        log::debug!("driver: rename: {old} -> {new}");

        super::filesystem::fs().rename(old, new)?;
        let resp = raw_channel.get_mut::<RenameResponse>();
        resp.header.result = 0;
        Ok(())
    }

    unsafe fn on_readdir(
        conn: &mut LocalServerConnection,
        raw_channel: RawChannel,
    ) -> Result<(), ErrorCode> {
        let req = raw_channel.get::<ReadDirRequest>();
        assert_eq!(req.header.cmd, CMD_READDIR);

        if (req.header.ver != 0) || (req.header.flags != 0) || (req.parent_fd != 0) {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        let fname_bytes = match raw_channel.get_bytes(req.fname.as_ptr(), req.fname_size as usize) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(moto_rt::E_INVALID_FILENAME);
            }
        };

        let fname = match core::str::from_utf8(fname_bytes) {
            Ok(fname) => fname,
            Err(_) => {
                return Err(moto_rt::E_INVALID_FILENAME);
            }
        };

        let iter = fs().iter(fname)?;
        let pcon = {
            match conn.extension_mut::<PerConnectionData>() {
                Some(pcon) => pcon,
                None => {
                    let pcon = Box::new(PerConnectionData::new());
                    conn.set_extension(pcon);
                    conn.extension_mut::<PerConnectionData>().unwrap()
                }
            }
        };

        let readdir_fd = pcon.add_readdir(iter);

        let resp = raw_channel.get_mut::<ReadDirResponse>();
        resp.header.result = 0;
        resp.header.ver = 0;
        resp.fd = readdir_fd;

        Ok(())
    }

    unsafe fn on_readdir_next(
        conn: &mut LocalServerConnection,
        raw_channel: RawChannel,
    ) -> Result<(), ErrorCode> {
        let req = raw_channel.get::<ReadDirNextRequest>();
        assert_eq!(req.header.cmd, CMD_READDIR_NEXT);

        if req.header.ver != 0 {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        let pcon = {
            match conn.extension_mut::<PerConnectionData>() {
                Some(pcon) => pcon,
                None => return Err(moto_rt::E_INTERNAL_ERROR),
            }
        };

        let iter = pcon.get_readdir(req.readdir_fd);
        if iter.is_none() {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }
        let iter = iter.unwrap();

        let item = iter.next();

        let resp = raw_channel.get_mut::<ReadDirNextResponse>();
        resp.header.result = 0;
        resp.header.ver = 0;

        if item.is_none() {
            return Err(E_NOT_FOUND);
        }

        let item = item.unwrap_unchecked();
        let (file_type, size) = {
            if item.is_directory() {
                (moto_rt::fs::FILETYPE_DIRECTORY, 0)
            } else {
                (moto_rt::fs::FILETYPE_FILE, item.size()?)
            }
        };
        let attr = moto_rt::fs::FileAttr {
            version: 0,
            perm: 0,
            file_type,
            _reserved: [0; 7],
            size,
            created: 0,
            accessed: 0,
            modified: 0,
        };

        let dir_entry = &mut raw_channel.get_at_mut(&mut resp.dir_entry, 1)?[0];
        dir_entry.version = 0;
        dir_entry._reserved = 0;
        dir_entry.attr = attr;
        dir_entry.fname_size = item.filename().len() as u16;
        assert!((dir_entry.fname_size as usize) <= moto_rt::fs::MAX_FILENAME_LEN);
        raw_channel.put_bytes(item.filename().as_bytes(), dir_entry.fname.as_mut_ptr())?;

        Ok(())
    }

    unsafe fn on_file_open(
        conn: &mut LocalServerConnection,
        raw_channel: RawChannel,
    ) -> Result<(), ErrorCode> {
        let req = raw_channel.get::<FileOpenRequest>();
        assert_eq!(req.header.cmd, CMD_FILE_OPEN);

        if (req.header.ver != 0) || (req.parent_fd != 0) {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        let fname_bytes = match raw_channel.get_bytes(req.fname.as_ptr(), req.fname_size as usize) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(moto_rt::E_INVALID_FILENAME);
            }
        };

        let fname = match core::str::from_utf8(fname_bytes) {
            Ok(fname) => fname,
            Err(_) => {
                return Err(moto_rt::E_INVALID_FILENAME);
            }
        };

        let mut flags = req.header.flags;
        if (flags & moto_rt::fs::O_CREATE_NEW) != 0 {
            fs().create_file(fname)?;
            flags ^= moto_rt::fs::O_CREATE_NEW;
        }

        if flags == (moto_rt::fs::O_CREATE | moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE) {
            fs().unlink(fname).ok();
            fs().create_file(fname)?;
            flags = moto_rt::fs::O_WRITE;
        }

        if flags != moto_rt::fs::O_READ
            && flags != moto_rt::fs::O_WRITE
            && flags != moto_rt::fs::O_APPEND
            && flags != (moto_rt::fs::O_READ | moto_rt::fs::O_WRITE)
        {
            moto_sys::SysRay::log(
                alloc::format!(
                    "on_file_open: flags not supported: 0x{:x}",
                    req.header.flags
                )
                .as_str(),
            )
            .ok();
            return Err(moto_rt::E_NOT_IMPLEMENTED);
        }

        let mut file = fs().open_file(fname)?;
        let pcon = {
            match conn.extension_mut::<PerConnectionData>() {
                Some(pcon) => pcon,
                None => {
                    let pcon = Box::new(PerConnectionData::new());
                    conn.set_extension(pcon);
                    conn.extension_mut::<PerConnectionData>().unwrap()
                }
            }
        };

        let file_sz = file.size()?;
        let fd = pcon.add_file(file);

        let resp = raw_channel.get_mut::<FileOpenResponse>();
        resp.header.result = 0;
        resp.size = file_sz;
        resp.fd = fd;

        Ok(())
    }

    unsafe fn on_file_read(
        conn: &mut LocalServerConnection,
        raw_channel: RawChannel,
    ) -> Result<(), ErrorCode> {
        let req = raw_channel.get::<FileReadRequest>();
        assert_eq!(req.header.cmd, CMD_FILE_READ);

        if req.header.ver != 0 {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        let pcon = {
            match conn.extension_mut::<PerConnectionData>() {
                Some(pcon) => pcon,
                None => return Err(moto_rt::E_INTERNAL_ERROR),
            }
        };

        if let Some(file) = pcon.get_file(req.fd) {
            let resp = raw_channel.get_mut::<FileReadResponse>();
            resp.header.result = 0;

            let buf_size = (req.max_bytes as usize)
                .min(raw_channel.size() - core::mem::size_of::<FileReadResponse>());

            let buf = raw_channel.get_bytes_mut(resp.data.as_mut_ptr(), buf_size)?;
            let bytes_read = file.read_offset(req.offset, buf)?;

            resp.size = bytes_read as u32;

            Ok(())
        } else {
            Err(moto_rt::E_INTERNAL_ERROR)
        }
    }

    unsafe fn on_file_write(
        conn: &mut LocalServerConnection,
        raw_channel: RawChannel,
    ) -> Result<(), ErrorCode> {
        let req = raw_channel.get::<FileWriteRequest>();
        assert_eq!(req.header.cmd, CMD_FILE_WRITE);

        if req.header.ver != 0 {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        if ((req.size as usize) + core::mem::size_of::<FileWriteRequest>()) > raw_channel.size() {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let pcon = {
            match conn.extension_mut::<PerConnectionData>() {
                Some(pcon) => pcon,
                None => return Err(moto_rt::E_INTERNAL_ERROR),
            }
        };

        let p_file = pcon.get_file(req.fd);
        if p_file.is_none() {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        let file = p_file.unwrap();
        let buf = unsafe { core::slice::from_raw_parts(&req.data as *const u8, req.size as usize) };
        let written = file.write_offset(req.offset, buf)?;

        let resp = raw_channel.get_mut::<FileWriteResponse>();
        resp.header.result = 0;
        resp.written = written as u32;

        Ok(())
    }

    unsafe fn on_close_fd(
        conn: &mut LocalServerConnection,
        raw_channel: RawChannel,
    ) -> Result<(), ErrorCode> {
        let req = raw_channel.get::<CloseFdRequest>();
        assert_eq!(req.header.cmd, CMD_CLOSE_FD);

        if req.header.ver != 0 {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        let pcon = {
            match conn.extension_mut::<PerConnectionData>() {
                Some(pcon) => pcon,
                None => return Err(moto_rt::E_INTERNAL_ERROR),
            }
        };

        if req.header.flags == CloseFdRequest::F_READDIR {
            let iter = pcon.get_readdir(req.fd);
            if iter.is_none() {
                return Err(moto_rt::E_INTERNAL_ERROR);
            }

            pcon.remove_readdir(req.fd);
        } else if req.header.flags == CloseFdRequest::F_FILE {
            let file = pcon.get_file(req.fd);
            if file.is_none() {
                return Err(moto_rt::E_INTERNAL_ERROR);
            }

            pcon.remove_file(req.fd);
        } else {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        let resp = raw_channel.get_mut::<CloseFdResponse>();
        resp.header.result = 0;
        Ok(())
    }

    unsafe fn on_stat(raw_channel: RawChannel) -> Result<(), ErrorCode> {
        let req = raw_channel.get::<StatRequest>();
        assert_eq!(req.header.cmd, CMD_STAT);

        if (req.header.ver != 0) || (req.header.flags != 0) || (req.parent_fd != 0) {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        let fname_bytes = match raw_channel.get_bytes(req.fname.as_ptr(), req.fname_size as usize) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(moto_rt::E_INVALID_FILENAME);
            }
        };

        let fname = match core::str::from_utf8(fname_bytes) {
            Ok(fname) => fname,
            Err(_) => {
                return Err(moto_rt::E_INVALID_FILENAME);
            }
        };

        let attr = fs().stat(fname)?;

        let resp = raw_channel.get_mut::<StatResponse>();
        resp.header.result = 0; // Ok.
        resp.fd = 0;
        resp.attr = attr;

        Ok(())
    }
}

pub fn start() {
    std::thread::Builder::new()
        .stack_size(4096 * 256)
        .spawn(Driver::run)
        .unwrap();
}
