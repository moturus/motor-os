use super::filesystem::FileSystem;
use alloc::sync::Arc;
use moto_runtime::rt_api;
use moto_sys::ErrorCode;

const BLOCK_SIZE: u64 = moto_virtio::BLOCK_SIZE as u64;
const PAGE_SIZE_SMALL: u64 = moto_sys::sys_mem::PAGE_SIZE_SMALL;

const _: () = assert!(PAGE_SIZE_SMALL % BLOCK_SIZE == 0);
const _: () = assert!(BLOCK_SIZE <= PAGE_SIZE_SMALL);

struct FileSystemFlatFS {
    root_dir: flatfs::Dir<'static>,
}

#[derive(Clone, Copy)]
struct FileFlatFs {
    bytes: &'static [u8],
}

impl super::File for FileFlatFs {
    fn size(&mut self) -> Result<u64, ErrorCode> {
        Ok(self.bytes.len() as u64)
    }

    fn write_offset(&mut self, _offset: u64, _buf: &[u8]) -> Result<usize, ErrorCode> {
        Err(moto_rt::E_NOT_ALLOWED)
    }

    fn read_offset(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        let offset = offset as usize;
        if offset == self.bytes.len() {
            return Ok(0);
        }
        if offset > self.bytes.len() {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let end = self.bytes.len().min(offset + buf.len());
        unsafe {
            core::intrinsics::copy_nonoverlapping(
                &self.bytes[offset],
                buf.as_mut_ptr(),
                end - offset,
            );
        }

        Ok(end - offset)
    }
}

struct DirectoryEntryFlatFs {
    name: &'static str,
    #[allow(unused)]
    path: String,
    file: Option<FileFlatFs>,
    dir: Option<&'static flatfs::Dir<'static>>,
}

impl super::filesystem::DirectoryEntry for DirectoryEntryFlatFs {
    fn is_directory(&self) -> bool {
        self.dir.is_some()
    }

    fn filename(&self) -> &str {
        self.name
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn size(&self) -> Result<u64, ErrorCode> {
        if let Some(file) = self.file {
            Ok(file.bytes.len() as u64)
        } else {
            panic!("not a file")
        }
    }
}

struct DirectoryIterFlatFs {
    path: String,
    iter_dirs:
        Option<std::collections::btree_map::Iter<'static, &'static str, flatfs::Dir<'static>>>,
    iter_files: Option<std::collections::btree_map::Iter<'static, &'static str, &'static [u8]>>,
}

impl Iterator for DirectoryIterFlatFs {
    type Item = Box<dyn super::filesystem::DirectoryEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(dirs) = &mut self.iter_dirs {
            if let Some((name, dir)) = dirs.next() {
                let mut path = self.path.clone();
                path.push('/');
                path.push_str(name);
                return Some(Box::new(DirectoryEntryFlatFs {
                    name: *name,
                    path,
                    file: None,
                    dir: Some(dir),
                }));
            }
            self.iter_dirs = None;
        }

        if let Some(files) = &mut self.iter_files {
            if let Some((name, file)) = files.next() {
                let mut path = self.path.clone();
                path.push('/');
                path.push_str(name);
                return Some(Box::new(DirectoryEntryFlatFs {
                    name: *name,
                    path,
                    file: Some(FileFlatFs { bytes: *file }),
                    dir: None,
                }));
            }
            self.iter_files = None;
        }

        None
    }
}

impl super::DirectoryIter for DirectoryIterFlatFs {}

impl super::filesystem::FileSystem for FileSystemFlatFS {
    fn open_file(
        &'static mut self,
        path: &str,
    ) -> Result<Box<dyn super::File>, moto_sys::ErrorCode> {
        let paths: Vec<&str> = path
            .split('/')
            .map(|name| name.trim())
            .filter(|name| !name.is_empty())
            .collect();

        if paths.len() == 0 {
            return Err(moto_rt::E_INVALID_FILENAME);
        }

        let mut dir = &self.root_dir;
        for idx in 0..(paths.len() - 1) {
            dir = dir
                .subdirs
                .get(paths[idx])
                .ok_or(moto_rt::E_INVALID_FILENAME)?;
        }

        let file = *dir
            .files
            .get(paths.last().unwrap())
            .ok_or(moto_rt::E_INVALID_FILENAME)?;

        Ok(Box::new(FileFlatFs { bytes: file }))
    }

    fn create_file(&'static mut self, _path: &str) -> Result<(), moto_sys::ErrorCode> {
        Err(moto_rt::E_NOT_ALLOWED)
    }

    fn iter(
        &'static mut self,
        path: &str,
    ) -> Result<Box<dyn super::DirectoryIter>, moto_sys::ErrorCode> {
        if !path.starts_with('/') {
            return Err(moto_rt::E_INVALID_FILENAME);
        }
        let mut dir = &self.root_dir;

        for name in path.split('/') {
            if name.is_empty() {
                continue;
            }

            if let Some(subdir) = dir.subdirs.get(name) {
                dir = subdir;
                continue;
            };

            return Err(moto_rt::E_INVALID_FILENAME);
        }

        Ok(Box::new(DirectoryIterFlatFs {
            path: dir.path.clone(),
            iter_dirs: Some(dir.subdirs.iter()),
            iter_files: Some(dir.files.iter()),
        }))
    }

    fn stat(
        &'static mut self,
        path: &str,
    ) -> Result<moto_runtime::rt_api::fs::FileAttrData, moto_sys::ErrorCode> {
        if !path.starts_with('/') {
            return Err(moto_rt::E_INVALID_FILENAME);
        }
        let mut curr_directory = &self.root_dir;
        let mut file = None;

        for name in path.split('/') {
            if name.is_empty() {
                continue;
            }
            if file.is_some() {
                // Cannot continue after a file has been found.
                return Err(moto_rt::E_INVALID_FILENAME);
            }

            if let Some(subdir) = curr_directory.subdirs.get(name) {
                curr_directory = subdir;
                continue;
            };

            if let Some(f) = curr_directory.files.get(name) {
                file = Some(f);
                break;
            }

            return Err(moto_rt::E_INVALID_FILENAME);
        }

        match file {
            Some(file) => Ok(rt_api::fs::FileAttrData {
                version: 0,
                self_size: core::mem::size_of::<rt_api::fs::FileAttrData>() as u16,
                file_perm: 0,
                file_type: rt_api::fs::FILE_TYPE_FILE,
                reserved: 0,
                size: file.len() as u64,
                created: 0,
                accessed: 0,
                modified: 0,
            }),
            None => Ok(rt_api::fs::FileAttrData {
                version: 0,
                self_size: core::mem::size_of::<rt_api::fs::FileAttrData>() as u16,
                file_perm: rt_api::fs::FILE_PERM_READ,
                file_type: rt_api::fs::FILE_TYPE_DIR,
                reserved: 0,
                size: 0,
                created: 0,
                accessed: 0,
                modified: 0,
            }),
        }
    }

    fn mkdir(&'static mut self, _path: &str) -> Result<(), moto_sys::ErrorCode> {
        Err(moto_rt::E_NOT_ALLOWED)
    }

    fn unlink(&'static mut self, _path: &str) -> Result<(), moto_sys::ErrorCode> {
        Err(moto_rt::E_NOT_ALLOWED)
    }

    fn delete_dir(&'static mut self, _path: &str) -> Result<(), moto_sys::ErrorCode> {
        Err(moto_rt::E_NOT_ALLOWED)
    }

    fn delete_dir_all(&'static mut self, _path: &str) -> Result<(), moto_sys::ErrorCode> {
        Err(moto_rt::E_NOT_ALLOWED)
    }

    fn rename(&'static mut self, _old: &str, _new: &str) -> Result<(), ErrorCode> {
        Err(moto_rt::E_NOT_ALLOWED)
    }
}

pub(super) fn init(
    virtio_drive: Arc<dyn moto_virtio::BlockDevice>,
    lba: u64,
    blocks: u64,
) -> Box<dyn FileSystem> {
    const BLOCKS_PER_PAGE: u64 = PAGE_SIZE_SMALL / BLOCK_SIZE;
    const _: () = assert!(BLOCKS_PER_PAGE.is_power_of_two());
    let num_pages = moto_sys::align_up(blocks, BLOCKS_PER_PAGE) / BLOCKS_PER_PAGE;
    let maybe_addr = moto_sys::SysMem::alloc(PAGE_SIZE_SMALL, num_pages);
    if maybe_addr.is_err() {
        crate::moto_log!("sys-io: failed to allocate {} pages for FlatFS.", num_pages);
        moto_sys::SysCpu::exit(1);
    }

    let buf: &'static mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(
            maybe_addr.unwrap() as usize as *mut u8,
            (num_pages << moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2) as usize,
        )
    };

    virtio_drive
        .read(
            &mut buf[0..((blocks * BLOCK_SIZE) as usize)],
            lba * BLOCK_SIZE,
            blocks as usize,
        )
        .unwrap();

    let root_dir = flatfs::unpack(buf);
    if root_dir.is_err() {
        crate::moto_log!("sys-io: failed unpack FlatFS.");
        moto_sys::SysCpu::exit(1);
    }

    Box::new(FileSystemFlatFS {
        root_dir: root_dir.unwrap(),
    })
}
