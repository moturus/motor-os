//! Spec for client-server filesystem IPC.

use moto_ipc::io_channel;

pub const CMD_MIN: u16 = io_channel::CMD_RESERVED_MAX + 0x100; // 4608 == 0x1200
const _: () = assert!(CMD_MIN > super::api_net::CMD_MAX);

#[derive(Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FsCmd {
    // Read-only commands.
    Stat = CMD_MIN,
    ReadDir,
    ReadDirNext,
    CloseFd,
    FileOpen,
    FileRead,

    // Mutating commands.
    FileWrite,
    Unlink,
    Rename,
    MkDir,

    // Not a command.
    FsCmdMax,
}

pub const CMD_MAX: u16 = FsCmd::FsCmdMax as u16;

impl FsCmd {
    pub const fn try_from(val: u16) -> Result<Self, u16> {
        if val < CMD_MIN {
            return Err(val);
        }
        if val >= CMD_MAX {
            return Err(val);
        }

        Ok(unsafe { core::mem::transmute::<u16, Self>(val) })
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

// -------------- SYNCHRONOUS (obsolete) API.

//
// We use hand-crafted (de)serialization instead of serde because
// hand-crafted means the most efficient (in whatever sense we choose)
// at the cost of developer convenience/productivity; also it is
// unreasonable to expect third-party libraries to make choices/
// tradeoffs that are most beneficial for us.

pub use moto_rt::ErrorCode;

pub const CMD_STAT: u16 = 2;
pub const CMD_READDIR: u16 = 3;
pub const CMD_READDIR_NEXT: u16 = 4;
pub const CMD_CLOSE_FD: u16 = 5;

pub const CMD_MKDIR: u16 = 6;

pub const CMD_FILE_OPEN: u16 = 100;
pub const CMD_FILE_READ: u16 = 101;
pub const CMD_FILE_WRITE: u16 = 102;
pub const CMD_UNLINK: u16 = 103;
pub const CMD_RENAME: u16 = 104;

pub const F_UNLINK_FILE: u32 = 1;
pub const F_UNLINK_DIR: u32 = 2;
pub const F_UNLINK_DIR_ALL: u32 = 3;

pub const FS_URL: &str = "motor-os-fs";

// The first request the client makes to FS_URL, which then
// provides a url of an actual driver to send all other requests to.
#[repr(C, align(8))]
pub struct GetServerUrlRequest {
    pub header: moto_ipc::sync::RequestHeader,
}

#[repr(C, align(8))]
pub struct GetServerUrlResponse {
    pub header: moto_ipc::sync::ResponseHeader,
    pub url_size: u16,
    pub url: [u8; Self::MAX_URL_SIZE],
}

impl GetServerUrlResponse {
    // Something large enough to accommodate all reasonable options,
    // but small enough not to cause overflow.
    const MAX_URL_SIZE: usize = 256;

    /// # Safety
    ///
    /// Assumes self was properly initialized.
    pub unsafe fn url(&self) -> Result<&str, u16> {
        if (self.url_size as usize) > Self::MAX_URL_SIZE {
            return Err(u16::MAX);
        }

        let bytes = core::slice::from_raw_parts(self.url.as_ptr(), self.url_size as usize);
        core::str::from_utf8(bytes).map_err(|_| -> u16 { u16::MAX })
    }
}

#[repr(C, align(8))]
pub struct CloseFdRequest {
    // CMD_CLOSE_FD
    pub header: moto_ipc::sync::RequestHeader,
    pub fd: u64,
}

impl CloseFdRequest {
    pub const F_READDIR: u32 = 1;
    pub const F_FILE: u32 = 2;
}

#[repr(C, align(8))]
pub struct CloseFdResponse {
    pub header: moto_ipc::sync::ResponseHeader,
}

#[repr(C, align(8))]
pub struct StatRequest {
    // CMD_STAT, CMD_READDIR, CMD_MKDIR, CMD_FILE_OPEN, or CMD_UNLINK.
    pub header: moto_ipc::sync::RequestHeader,
    pub parent_fd: u64, // if 0, fname should be absolute.
    pub fname_size: u16,
    pub fname: [u8; moto_rt::fs::MAX_PATH_LEN], // array of bytes with size of fname_size.
}

pub type FileOpenRequest = StatRequest; // Same struct, different command value.

#[repr(C, align(8))]
pub struct FileOpenResponse {
    pub header: moto_ipc::sync::ResponseHeader,
    pub fd: u64,
    pub size: u64,
}

pub type ReadDirRequest = FileOpenRequest; // Same struct, different command value.
pub type ReadDirResponse = FileOpenResponse;

pub type MkdirRequest = StatRequest;
pub type MkdirResponse = CloseFdResponse;

pub type UnlinkRequest = StatRequest;
pub type UnlinkResponse = CloseFdResponse;

#[repr(C, align(16))]
pub struct StatResponse {
    pub header: moto_ipc::sync::ResponseHeader,
    pub fd: u64, // zero if CMD_STAT; non-zero if CMD_FILE_OPEN.
    pub attr: moto_rt::fs::FileAttr,
}

#[repr(C, align(8))]
pub struct ReadDirNextRequest {
    // CMD_READDIR_NEXT.
    pub header: moto_ipc::sync::RequestHeader,
    pub readdir_fd: u64,
}

#[repr(C, align(16))]
pub struct ReadDirNextResponse {
    pub header: moto_ipc::sync::ResponseHeader,
    pub dir_entry: moto_rt::fs::DirEntry,
}

#[allow(unused)]
#[repr(C, align(8))]
pub struct FileReadRequest {
    pub header: moto_ipc::sync::RequestHeader, // CMD_FILE_READ
    pub max_bytes: u32,
    _reserved: u32,
    pub offset: u64,
    pub fd: u64,
}

#[repr(C, align(8))]
pub struct FileReadResponse {
    pub header: moto_ipc::sync::ResponseHeader,
    pub size: u32,
    pub data: [u8; 0],
}

#[allow(unused)]
#[repr(C, align(8))]
pub struct FileWriteRequest {
    pub header: moto_ipc::sync::RequestHeader, // CMD_FILE_WRITE
    pub size: u32,
    _reserved: u32,
    pub offset: u64,
    pub fd: u64,
    pub data: [u8; 0],
}

#[repr(C, align(8))]
pub struct FileWriteResponse {
    pub header: moto_ipc::sync::ResponseHeader,
    pub written: u32,
}

#[repr(C, align(8))]
pub struct RenameRequest {
    pub header: moto_ipc::sync::RequestHeader, // CMD_RENAME
    pub parent_fd: u64,                        // if 0, fname should be absolute.
    pub old_fname_size: u16,
    pub new_fname_size: u16,
    pub old: [u8; moto_rt::fs::MAX_PATH_LEN],
    pub new: [u8; moto_rt::fs::MAX_PATH_LEN],
}

impl RenameRequest {
    pub fn build(
        &mut self,
        old: &str,
        new: &str,
        raw_channel: &moto_ipc::sync::RawChannel,
    ) -> Result<(), ErrorCode> {
        self.header.cmd = CMD_RENAME;
        self.header.ver = 0;
        self.header.flags = 0;
        self.parent_fd = 0;

        self.old_fname_size = old.len() as u16;
        self.new_fname_size = new.len() as u16;
        unsafe {
            raw_channel.put_bytes(old.as_bytes(), self.old.as_mut_ptr())?;
            raw_channel.put_bytes(new.as_bytes(), self.new.as_mut_ptr())?;
        }

        Ok(())
    }

    /// # Safety
    ///
    /// Assumes self was properly initialized.
    pub unsafe fn old<'a>(
        &'a self,
        raw_channel: &'a moto_ipc::sync::RawChannel,
    ) -> Result<&'a str, ErrorCode> {
        let bytes = raw_channel.get_bytes(self.old.as_ptr(), self.old_fname_size as usize)?;
        core::str::from_utf8(bytes).map_err(|_| moto_rt::E_INVALID_ARGUMENT)
    }

    /// # Safety
    ///
    /// Assumes self was properly initialized.
    #[allow(clippy::new_ret_no_self)]
    pub unsafe fn new<'a>(
        &'a self,
        raw_channel: &'a moto_ipc::sync::RawChannel,
    ) -> Result<&'a str, ErrorCode> {
        let bytes = raw_channel.get_bytes(self.new.as_ptr(), self.new_fname_size as usize)?;
        core::str::from_utf8(bytes).map_err(|_| moto_rt::E_INVALID_ARGUMENT)
    }
}

pub type RenameResponse = CloseFdResponse;
