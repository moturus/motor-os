use srfs_core::{EntryId, EntryKind, FsError, SyncFileSystem};

use crate::error;
use std::{
    cell::RefCell,
    io::{Error, ErrorKind, Result},
    rc::Rc,
};

pub(crate) struct FileSystemInner {
    fs_core: srfs_core::SyncFileSystem,
    cache: lru::LruCache<String, srfs_core::EntryId>, // path => entry
}

impl FileSystemInner {
    pub(crate) fn fs_core(&mut self) -> &mut srfs_core::SyncFileSystem {
        &mut self.fs_core
    }

    fn create_child_dir(&mut self, parent: EntryId, child: &str) -> Result<EntryId> {
        self.fs_core
            .add_directory(parent, child)
            .map_err(error::to_ioerror)
    }

    fn create_dir(&mut self, path: &str) -> Result<()> {
        let (parent, child) = self.split_parent_child(path)?;

        let result = self.create_child_dir(parent, child)?;
        self.cache.push(path.to_owned(), result);
        Ok(())
    }

    fn create_dir_all(&mut self, path: &str) -> Result<()> {
        if path.is_empty() {
            return Err(ErrorKind::InvalidFilename.into());
        }

        let path = if path.starts_with('/') {
            path.strip_prefix('/').unwrap()
        } else {
            path
        };

        if self.cache.contains(path) {
            return Ok(());
        }

        let ancestors = path.split('/');
        let mut curr_dir = srfs_core::SyncFileSystem::root_dir_id();
        for ancestor in ancestors {
            let entry = self.fs_core.get_directory_entry_by_name(curr_dir, ancestor);
            if let Err(err) = entry {
                if err == FsError::NotFound {
                    curr_dir = self.create_child_dir(curr_dir, ancestor)?;
                    continue;
                } else {
                    return Err(error::to_ioerror(err));
                }
            }

            curr_dir = entry.unwrap().id;
        }

        self.cache.push(path.to_owned(), curr_dir);
        Ok(())
    }

    fn create_file(&mut self, path: &str) -> Result<EntryId> {
        let (parent, child) = self.split_parent_child(path)?;

        self.fs_core
            .add_file(parent, child)
            .map_err(error::to_ioerror)
    }

    fn split_parent_child<'b>(&mut self, path: &'b str) -> Result<(EntryId, &'b str)> {
        let (dir, filename) = if let Some(pair) = path.rsplit_once('/') {
            pair
        } else {
            ("", path)
        };

        let dir = if dir.starts_with('/') {
            dir.strip_prefix('/').unwrap()
        } else {
            dir
        };

        let parent = if dir.is_empty() {
            SyncFileSystem::root_dir_id()
        } else {
            let maybe_dir = self.get_entry(dir)?;
            if maybe_dir.kind() != EntryKind::Directory {
                return Err(Error::from(ErrorKind::InvalidFilename));
            }
            maybe_dir
        };

        Ok((parent, filename))
    }

    fn exists(&mut self, path: &str) -> Result<bool> {
        let entry = self.get_entry(path);
        match entry {
            Ok(_) => Ok(true),
            Err(err) => {
                if err.kind() == ErrorKind::NotFound {
                    Ok(false)
                } else {
                    Err(err)
                }
            }
        }
    }

    fn stat(&mut self, path: &str) -> Result<crate::Attr> {
        let entry = self.get_entry(path)?;
        let raw_attr = self.fs_core.stat(entry).map_err(error::to_ioerror)?;
        Ok(raw_attr.into())
    }

    fn unlink(&mut self, path: &str) -> Result<()> {
        let entry = self.get_entry(path)?;
        if entry.kind() == EntryKind::File {
            // Need to truncate files first.
            self.fs_core
                .set_file_size(entry, 0)
                .map_err(error::to_ioerror)?;
        }
        self.fs_core.remove(entry).map_err(error::to_ioerror)?;
        self.pop_cache(path);
        Ok(())
    }

    fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        log::debug!("rename 0: {old} -> {new}");

        let entry = self.get_entry(old)?;

        let (_, old_child) = self.split_parent_child(old)?;
        let (new_parent, new_child) = self.split_parent_child(new)?;
        let new_child = if new_child.is_empty() {
            old_child
        } else {
            new_child
        };

        log::debug!("rename: {old} -> {new_parent:?} {new_child}");

        self.fs_core
            .move_rename(entry, new_parent, new_child)
            .map_err(error::to_ioerror)?;
        self.pop_cache(old);
        self.cache.push(new.to_owned(), entry);
        Ok(())
    }

    fn pop_cache(&mut self, path: &str) {
        let path = if path.starts_with('/') {
            path.strip_prefix('/').unwrap()
        } else {
            path
        };
        self.cache.pop(path);
    }

    pub(crate) fn get_entry(&mut self, path: &str) -> Result<EntryId> {
        let path = if path.starts_with('/') {
            path.strip_prefix('/').unwrap()
        } else {
            path
        };

        if let Some(entry) = self.cache.get(path) {
            return Ok(*entry);
        }

        let ancestors = path.split('/');
        let mut curr_dir = srfs_core::SyncFileSystem::root_dir_id();
        for ancestor in ancestors {
            if ancestor.is_empty() {
                continue;
            }
            let entry = self.fs_core.get_directory_entry_by_name(curr_dir, ancestor);
            if let Err(err) = entry {
                if err == FsError::NotFound {
                    return Err(Error::from(ErrorKind::NotFound));
                } else {
                    return Err(error::to_ioerror(err));
                }
            }

            curr_dir = entry.unwrap().id;
        }

        self.cache.push(path.to_owned(), curr_dir);
        Ok(curr_dir)
    }
}

pub struct FileSystem {
    inner: Rc<RefCell<FileSystemInner>>,
}

impl FileSystem {
    const CACHE_SIZE: std::num::NonZeroUsize = std::num::NonZeroUsize::new(4096).unwrap();

    pub fn create_volume(path: &std::path::Path, num_blocks: u64) -> Result<()> {
        let mut bd = srfs_core::file_block_device::FileBlockDevice::create(path, num_blocks)?;
        srfs_core::format(&mut bd).map_err(error::to_ioerror)
    }

    pub fn open_volume(path: &std::path::Path) -> Result<Self> {
        let bd = Box::new(srfs_core::file_block_device::FileBlockDevice::open(path)?);
        Self::open_device(bd)
    }

    pub fn open_device(block_device: Box<dyn srfs_core::SyncBlockDevice>) -> Result<Self> {
        let fs = srfs_core::SyncFileSystem::open_fs(block_device).map_err(error::to_ioerror)?;

        Ok(Self {
            inner: Rc::new(RefCell::new(FileSystemInner {
                fs_core: fs,
                cache: lru::LruCache::new(Self::CACHE_SIZE),
            })),
        })
    }

    pub fn create_dir(&mut self, path: &str) -> Result<()> {
        self.inner.borrow_mut().create_dir(path)
    }

    pub fn create_dir_all(&mut self, path: &str) -> Result<()> {
        self.inner.borrow_mut().create_dir_all(path)
    }

    pub fn create_file(&mut self, path: &str) -> Result<crate::File> {
        let file_id = self.inner.borrow_mut().create_file(path)?;
        Ok(crate::File::from(file_id, self.inner.clone()))
    }

    pub fn open_file(&mut self, path: &str) -> Result<crate::File> {
        let file_id = self.inner.borrow_mut().get_entry(path)?;
        if file_id.kind() != EntryKind::File {
            assert_eq!(file_id.kind(), EntryKind::Directory);
            return Err(ErrorKind::IsADirectory.into());
        }

        Ok(crate::File::from(file_id, self.inner.clone()))
    }

    pub fn exists(&mut self, path: &str) -> Result<bool> {
        self.inner.borrow_mut().exists(path)
    }

    pub fn stat(&mut self, path: &str) -> Result<crate::Attr> {
        self.inner.borrow_mut().stat(path)
    }

    pub fn read_dir(&mut self, path: &str) -> Result<crate::ReadDir> {
        crate::readdir::ReadDir::new(path, self.inner.clone())
    }

    pub fn unlink(&mut self, path: &str) -> Result<()> {
        self.inner.borrow_mut().unlink(path)
    }

    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        self.inner.borrow_mut().rename(old, new)
    }
}
