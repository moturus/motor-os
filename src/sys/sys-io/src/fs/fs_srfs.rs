use std::time::{SystemTime, UNIX_EPOCH};

use super::filesystem::FileSystem;
use alloc::sync::Arc;
use moto_runtime::rt_api;
use moto_sys::ErrorCode;

const BLOCK_4K: usize = 4096;
const BLOCK_512: usize = 512;

struct FileSystemSrFS {
    inner: srfs::FileSystem,
}

struct File {
    inner: srfs::File,
}

impl super::File for File {
    fn size(&mut self) -> Result<u64, ErrorCode> {
        self.inner.size().map_err(to_error_code)
    }

    fn write_offset(&mut self, offset: u64, buf: &[u8]) -> Result<usize, ErrorCode> {
        self.inner.write_offset(offset, buf).map_err(to_error_code)
    }

    fn read_offset(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.inner.read_offset(offset, buf).map_err(to_error_code)
    }
}

struct DirectoryEntrySrFs {
    inner: srfs::DirEntry,
}

impl super::filesystem::DirectoryEntry for DirectoryEntrySrFs {
    fn is_directory(&self) -> bool {
        self.inner.file_type() == srfs::EntryKind::Directory
    }

    fn filename(&self) -> &str {
        self.inner.file_name()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn path(&self) -> &str {
        self.inner.path()
    }

    fn size(&self) -> Result<u64, ErrorCode> {
        let attr = self.inner.stat().map_err(to_error_code)?;
        Ok(attr.size)
    }
}

struct DirectoryIterSrFs {
    inner: srfs::ReadDir,
}

impl Iterator for DirectoryIterSrFs {
    type Item = Box<dyn super::filesystem::DirectoryEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let inner = self.inner.next()?;
        if inner.is_err() {
            return None;
        }
        Some(Box::new(DirectoryEntrySrFs {
            inner: inner.unwrap(),
        }))
    }
}

impl super::DirectoryIter for DirectoryIterSrFs {}

impl super::filesystem::FileSystem for FileSystemSrFS {
    fn open_file(&'static mut self, path: &str) -> Result<Box<dyn super::File>, ErrorCode> {
        let inner = self.inner.open_file(path).map_err(to_error_code)?;
        Ok(Box::new(File { inner }))
    }

    fn create_file(&'static mut self, path: &str) -> Result<(), ErrorCode> {
        let _ = self.inner.create_file(path).map_err(to_error_code)?;
        Ok(())
    }

    fn iter(&'static mut self, path: &str) -> Result<Box<dyn super::DirectoryIter>, ErrorCode> {
        let inner = self.inner.read_dir(path).map_err(to_error_code)?;
        Ok(Box::new(DirectoryIterSrFs { inner }))
    }

    fn stat(&'static mut self, path: &str) -> Result<rt_api::fs::FileAttrData, ErrorCode> {
        use rt_api::fs::FileAttrData;
        let attr = self.inner.stat(path).map_err(to_error_code)?;

        Ok(FileAttrData {
            version: 1,
            self_size: core::mem::size_of::<FileAttrData>() as u16,
            file_perm: rt_api::fs::FILE_PERM_READ | rt_api::fs::FILE_PERM_WRITE,
            file_type: match attr.kind {
                srfs::EntryKind::Directory => rt_api::fs::FILE_TYPE_DIR,
                srfs::EntryKind::File => rt_api::fs::FILE_TYPE_FILE,
            },
            reserved: 0,
            size: attr.size,
            created: to_moto_timestamp(attr.created),
            accessed: 0,
            modified: to_moto_timestamp(attr.modified),
        })
    }

    fn mkdir(&'static mut self, path: &str) -> Result<(), ErrorCode> {
        self.inner.create_dir(path).map_err(to_error_code)
    }

    fn unlink(&'static mut self, path: &str) -> Result<(), ErrorCode> {
        self.inner.unlink(path).map_err(to_error_code)
    }

    fn delete_dir(&'static mut self, path: &str) -> Result<(), ErrorCode> {
        self.unlink(path)
    }

    fn delete_dir_all(&'static mut self, _path: &str) -> Result<(), ErrorCode> {
        todo!()
    }

    fn rename(&'static mut self, old: &str, new: &str) -> Result<(), ErrorCode> {
        self.inner.rename(old, new).map_err(to_error_code)
    }
}

pub(super) fn init(
    virtio_drive: Arc<dyn moto_virtio::BlockDevice>,
    lba: u64,
    blocks: u64,
) -> Box<dyn FileSystem> {
    assert_eq!(0, blocks & 3); // here blocks are in 512 bytes; we need in 4k.

    let adapter = Box::new(DeviceAdapter {
        virtio_drive,
        blocks4k: blocks >> 2,
        lba_offset: lba << BLOCK_512.ilog2(),
    });

    let inner = srfs::FileSystem::open_device(adapter).unwrap();
    Box::new(FileSystemSrFS { inner })
}

struct DeviceAdapter {
    virtio_drive: Arc<dyn moto_virtio::BlockDevice>,
    blocks4k: u64,
    lba_offset: u64,
}

const VIRTIO_BLOCKS_IN_SRFS_BLOCKS: usize = BLOCK_4K / BLOCK_512; // 8

impl srfs::SyncBlockDevice for DeviceAdapter {
    fn num_blocks(&self) -> u64 {
        self.blocks4k
    }

    fn read_block(&mut self, block_no: u64, buf: &mut [u8]) -> Result<(), srfs::FsError> {
        debug_assert_eq!(0, (buf.as_ptr() as usize) & (BLOCK_4K - 1));
        debug_assert_eq!(BLOCK_4K, buf.len());

        self.virtio_drive
            .read(
                buf,
                self.lba_offset + (block_no << BLOCK_4K.ilog2()),
                VIRTIO_BLOCKS_IN_SRFS_BLOCKS,
            )
            .map_err(|_| srfs::FsError::IoError)
    }

    fn write_block(&mut self, block_no: u64, buf: &[u8]) -> Result<(), srfs::FsError> {
        debug_assert_eq!(0, (buf.as_ptr() as usize) & (BLOCK_4K - 1));
        debug_assert_eq!(BLOCK_4K, buf.len());

        self.virtio_drive
            .write(
                buf,
                self.lba_offset + (block_no << BLOCK_4K.ilog2()),
                VIRTIO_BLOCKS_IN_SRFS_BLOCKS,
            )
            .map_err(|_| srfs::FsError::IoError)
    }
}

fn to_error_code(error: std::io::Error) -> ErrorCode {
    match error.kind() {
        std::io::ErrorKind::NotFound => moto_rt::E_NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => moto_rt::E_NOT_ALLOWED,
        std::io::ErrorKind::AlreadyExists => moto_rt::E_ALREADY_IN_USE,
        std::io::ErrorKind::WouldBlock => todo!(),
        std::io::ErrorKind::InvalidInput => todo!(),
        std::io::ErrorKind::InvalidData => moto_rt::E_UNKNOWN,
        std::io::ErrorKind::TimedOut => todo!(),
        std::io::ErrorKind::WriteZero => todo!(),
        // std::io::ErrorKind::Interrupted => todo!(),
        std::io::ErrorKind::Unsupported => todo!(),
        std::io::ErrorKind::UnexpectedEof => todo!(),
        std::io::ErrorKind::OutOfMemory => moto_rt::E_OUT_OF_MEMORY,
        std::io::ErrorKind::FileTooLarge => moto_rt::E_FILE_TOO_LARGE,
        // std::io::ErrorKind::Other => todo!(),
        _ => moto_rt::E_UNKNOWN,
    }
}

fn to_moto_timestamp(ts: SystemTime) -> u64 {
    let dur = ts.duration_since(UNIX_EPOCH).unwrap();
    dur.as_nanos() as u64
}
