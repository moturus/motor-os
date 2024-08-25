// FileSystem. The API is synchronous because we don't have asynchronous
// FS drivers for now.

use moto_runtime::rt_api;
use moto_sys::ErrorCode;

pub trait File {
    fn size(&mut self) -> Result<u64, ErrorCode>;
    fn write_offset(&mut self, offset: u64, buf: &[u8]) -> Result<usize, ErrorCode>;
    fn read_offset(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, ErrorCode>;
}

#[allow(unused)]
pub trait DirectoryEntry {
    fn is_directory(&self) -> bool;
    fn filename(&self) -> &str; // The filename without ancestors.
    fn path(&self) -> &str; // The full path.
    fn size(&self) -> Result<u64, ErrorCode>;
    fn as_any(&self) -> &dyn std::any::Any;
}

pub trait DirectoryIter: Iterator<Item = Box<dyn DirectoryEntry>> {}

pub trait FileSystem {
    fn open_file(&'static mut self, path: &str) -> Result<Box<dyn File>, ErrorCode>;
    fn create_file(&'static mut self, path: &str) -> Result<(), ErrorCode>;
    fn iter(&'static mut self, path: &str) -> Result<Box<dyn DirectoryIter>, ErrorCode>;
    fn stat(&'static mut self, path: &str) -> Result<rt_api::fs::FileAttrData, ErrorCode>;
    fn mkdir(&'static mut self, path: &str) -> Result<(), ErrorCode>;
    fn unlink(&'static mut self, path: &str) -> Result<(), ErrorCode>;
    fn rename(&'static mut self, old: &str, new: &str) -> Result<(), ErrorCode>;
    fn delete_dir(&'static mut self, path: &str) -> Result<(), ErrorCode>;
    fn delete_dir_all(&'static mut self, path: &str) -> Result<(), ErrorCode>;
}

static mut FS: Option<Box<dyn FileSystem>> = None;

pub fn fs() -> &'static mut Box<dyn FileSystem> {
    unsafe { FS.as_mut().unwrap() }
}

pub fn init() {
    let mut drives = moto_virtio::lsblk();
    if drives.len() == 0 {
        log::error!("No drives found");
        panic!("No drives found");
    }
    if drives.len() % 10 == 1 {
        log::debug!("Found {} virtio drive.", drives.len());
    } else {
        log::debug!("Found {} virtio drives.", drives.len());
    }

    const BLOCK_SIZE: usize = 512;
    let mut block = alloc::vec::Vec::<u8>::with_capacity(BLOCK_SIZE);
    unsafe { block.set_len(BLOCK_SIZE) }; // Safe because we just allocated with the same len.

    let mut fs: Option<Box<dyn FileSystem>> = None;
    for drive in &mut drives {
        if let Ok(()) = drive.read(block.as_mut_slice(), 0, 1) {
            match super::mbr::Mbr::parse(block.as_slice()) {
                Ok(mbr) => {
                    for pte in &mbr.entries {
                        log::trace!("MBR PTE: {:?}", pte);
                        match pte.partition_type {
                            super::mbr::PartitionType::FlatFs => {
                                if fs.is_some() {
                                    log::error!("Found more than one DATA partion.");
                                    panic!();
                                }

                                fs = Some(super::fs_flatfs::init(
                                    drive.clone(),
                                    pte.lba as u64,
                                    pte.sectors as u64,
                                ));
                            }
                            super::mbr::PartitionType::SrFs => {
                                if fs.is_some() {
                                    log::error!("Found more than one DATA partion.");
                                    panic!();
                                }

                                fs = Some(super::fs_srfs::init(
                                    drive.clone(),
                                    pte.lba as u64,
                                    pte.sectors as u64,
                                ));
                            }
                            _ => continue,
                        }
                    }
                }
                Err(err) => {
                    crate::moto_log!("Failed to read MBR: {}", err);
                    log::warn!("Failed to read MBR: {}", err);
                }
            }
        } else {
            crate::moto_log!("Skipping a VirtIO drive due to I/O error.");
            log::warn!("Skipping a VirtIO drive due to I/O error.");
        }
    }

    if fs.is_none() {
        log::error!("Couldn't find a data partion.");
        panic!("Couldn't find a data partition.");
    }

    unsafe {
        core::mem::swap(
            std::ptr::addr_of_mut!(FS).as_mut().unwrap_unchecked(),
            &mut fs,
        )
    };
    assert!(fs.is_none());
}
