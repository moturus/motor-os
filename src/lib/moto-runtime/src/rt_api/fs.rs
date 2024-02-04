// Spec for client-server filesystem IPC.
//
// We use hand-crafted (de)serialization instead of serde because
// hand-crafted means the most efficient (in whatever sense we choose)
// at the cost of developer convenience/productivity; also it is
// unreasonable to expect third-party libraries to make choices/
// tradeoffs that are most beneficial for us.

pub use moto_sys::ErrorCode;

pub const MAX_PATH: usize = 2048;

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

pub const FILE_TYPE_FILE: u8 = 1;
pub const FILE_TYPE_DIR: u8 = 2;
pub const FILE_TYPE_SYMLINK: u8 = 4;

pub const FILE_PERM_READ: u16 = 1;
pub const FILE_PERM_WRITE: u16 = 2;

pub const F_UNLINK_FILE: u16 = 1;
pub const F_UNLINK_DIR: u16 = 2;
pub const F_UNLINK_DIR_ALL: u16 = 3;

pub const FS_URL: &str = "motor-os-fs";

// The first request the client makes to FS_URL, which then
// provides a url of an actual driver to send all other requests to.
#[repr(C, align(8))]
pub struct GetServerUrlRequest {
    pub command: u16, // 1
    pub version: u16, // 0
    pub flags: u32,   // 0
}

#[repr(C, align(8))]
pub struct GetServerUrlResponse {
    pub result: u16,
    pub version: u16,
    pub url_size: u16,
    pub url: [u8; 0],
}

impl GetServerUrlResponse {
    // Something large enough to accommodate all reasonable options,
    // but small enough not to cause overflow.
    const MAX_URL_SIZE: usize = 256;

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
    pub command: u16, // CMD_CLOSE_FD
    pub version: u16,
    pub flags: u16,
    pub reserved: u16,
    pub fd: u64,
}

impl CloseFdRequest {
    pub const F_READDIR: u16 = 1;
    pub const F_FILE: u16 = 2;
}

#[repr(C, align(8))]
pub struct CloseFdResponse {
    pub result: u16,
}

#[repr(C, align(8))]
pub struct StatRequest {
    pub command: u16, // CMD_STAT, CMD_READDIR, CMD_MKDIR, CMD_FILE_OPEN, or CMD_UNLINK.
    pub version: u16,
    pub flags: u16,
    pub fname_size: u16,
    pub parent_fd: u64, // if 0, fname should be absolute.
    pub fname: [u8; 0], // array of bytes with size of fname_size.
}

pub type FileOpenRequest = StatRequest; // Same struct, different command value.

#[repr(C, align(8))]
pub struct FileOpenResponse {
    pub result: u16, // zero => Ok.
    pub version: u16,
    pub reserved: u32,
    pub fd: u64,
    pub size: u64,
}

pub type ReadDirRequest = FileOpenRequest; // Same struct, different command value.
pub type ReadDirResponse = FileOpenResponse;

pub type MkdirRequest = StatRequest;
pub type MkdirResponse = CloseFdResponse;

pub type UnlinkRequest = StatRequest;
pub type UnlinkResponse = CloseFdResponse;

impl FileOpenRequest {
    // FileOpen flags.
    pub const F_READ: u16 = 1;
    pub const F_WRITE: u16 = 2;
    pub const F_APPEND: u16 = 4;
    pub const F_TRUNCATE: u16 = 8;
    pub const F_CREATE: u16 = 0x10;
    pub const F_CREATE_NEW: u16 = 0x20;
}

#[repr(C, align(8))]
pub struct FileAttrData {
    pub version: u16,
    pub self_size: u16, // The size of this struct.
    pub file_perm: u16, // FILE_PERM_*.
    pub file_type: u8,  // FILE_TYPE_*.
    pub reserved: u8,
    pub size: u64,
    pub created: u64,
    pub accessed: u64,
    pub modified: u64,
}

#[repr(C, align(8))]
pub struct StatResponse {
    pub result: u16, // zero => Ok.
    pub version: u16,
    pub reserved: u32,
    pub fd: u64, // zero if CMD_STAT; non-zero if CMD_FILE_OPEN.
    pub attr: FileAttrData,
}

#[repr(C, align(8))]
pub struct ReadDirNextRequest {
    pub command: u16, // CMD_READDIR_NEXT.
    pub version: u16,
    pub reserved: u32,
    pub readdir_fd: u64,
}

#[repr(C, align(8))]
pub struct DirEntryData {
    pub version: u16,
    pub self_size: u16,
    pub reserved: u32,
    pub attr: FileAttrData,
    pub fd: u64, // Zero is OK.
    pub fname_size: u16,
    pub fname: [u8; 0],
}

#[repr(C, align(8))]
pub struct ReadDirNextResponse {
    pub result: u16, // zero => Ok.
    pub version: u16,
    pub entries: u16,
    pub reserved: u16,
    pub dir_entries: [DirEntryData; 0],
}

#[repr(C, align(8))]
pub struct FileReadRequest {
    pub command: u16, // CMD_FILE_READ
    pub version: u16,
    pub max_bytes: u32,
    pub offset: u64,
    pub fd: u64,
}

#[repr(C, align(8))]
pub struct FileReadResponse {
    pub result: u16, // zero => Ok.
    pub reserved: u16,
    pub size: u32,
    pub data: [u8; 0],
}

#[repr(C, align(8))]
pub struct FileWriteRequest {
    pub command: u16, // CMD_FILE_WRITE
    pub version: u16,
    pub size: u32,
    pub offset: u64,
    pub fd: u64,
    pub data: [u8; 0],
}

#[repr(C, align(8))]
pub struct FileWriteResponse {
    pub result: u16, // zero => Ok.
    pub reserved: u16,
    pub written: u32,
}

#[repr(C, align(8))]
pub struct RenameRequest {
    pub command: u16, // CMD_RENAME
    pub version: u16,
    pub flags: u16,
    pub old_fname_size: u16,
    pub new_fname_size: u16,
    pub parent_fd: u64,  // if 0, fname should be absolute.
    pub fnames: [u8; 0], // array of bytes with size of fname_size.
}

impl RenameRequest {
    pub fn build(
        &mut self,
        old: &str,
        new: &str,
        raw_channel: &moto_ipc::sync::RawChannel,
    ) -> Result<(), ErrorCode> {
        self.command = CMD_RENAME;
        self.version = 0;
        self.flags = 0;
        self.parent_fd = 0;

        self.old_fname_size = old.as_bytes().len() as u16;
        self.new_fname_size = new.as_bytes().len() as u16;
        unsafe {
            raw_channel.put_bytes(old.as_bytes(), &mut self.fnames)?;
            raw_channel.put_bytes(
                new.as_bytes(),
                (((&self.fnames as *const _ as usize) + (self.old_fname_size as usize))
                    as *mut [u8; 0])
                    .as_mut()
                    .unwrap(),
            )?;
        }

        Ok(())
    }

    pub unsafe fn old<'a>(
        &'a self,
        raw_channel: &'a moto_ipc::sync::RawChannel,
    ) -> Result<&'a str, ErrorCode> {
        let bytes = raw_channel.get_bytes(&self.fnames, self.old_fname_size as usize)?;
        core::str::from_utf8(bytes).map_err(|_| ErrorCode::InvalidArgument)
    }

    pub unsafe fn new<'a>(
        &'a self,
        raw_channel: &'a moto_ipc::sync::RawChannel,
    ) -> Result<&'a str, ErrorCode> {
        let bytes = raw_channel.get_bytes(
            (((&self.fnames as *const _ as usize) + (self.old_fname_size as usize))
                as *const [u8; 0])
                .as_ref()
                .unwrap(),
            self.new_fname_size as usize,
        )?;
        core::str::from_utf8(bytes).map_err(|_| ErrorCode::InvalidArgument)
    }
}

pub type RenameResponse = CloseFdResponse;
