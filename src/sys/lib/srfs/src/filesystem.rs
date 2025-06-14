use camino::{Utf8Path, Utf8PathBuf};
use srfs_core::{EntryId, EntryKind, ROOT_DIR_ID, SyncFileSystem};

use std::{
    cell::RefCell,
    io::{Error, ErrorKind, Result},
    rc::Rc,
};

pub(crate) struct FileSystemInner {
    fs_core: srfs_core::SyncFileSystem,
    cache: lru::LruCache<Utf8PathBuf, srfs_core::EntryId>, // path => entry
}

impl FileSystemInner {
    pub(crate) fn fs_core(&mut self) -> &mut srfs_core::SyncFileSystem {
        &mut self.fs_core
    }

    fn create_child_dir(&mut self, parent: EntryId, child: &str) -> Result<EntryId> {
        self.fs_core.add_directory(parent, child)
    }

    fn create_dir(&mut self, path: &Utf8Path) -> Result<()> {
        assert!(path.is_absolute());
        let (parent, child) = self.split_parent_child(path)?;

        let result = self.create_child_dir(parent, child)?;
        self.cache.push(path.to_owned(), result);
        Ok(())
    }

    fn create_dir_all(&mut self, path: &Utf8Path) -> Result<EntryId> {
        assert!(path.is_absolute());

        if let Ok(entry) = self.get_entry(path) {
            return Ok(entry);
        }

        let parent = path.parent().unwrap();
        let parent_id = self.create_dir_all(parent)?; // Recursion.
        let entry = self.create_child_dir(parent_id, path.file_name().unwrap().into())?;

        self.cache.push(path.to_owned(), entry);
        Ok(entry)
    }

    fn create_file(&mut self, path: &Utf8Path) -> Result<EntryId> {
        assert!(path.is_absolute());
        let (parent, child) = self.split_parent_child(path)?;

        self.fs_core.add_file(parent, child)
    }

    fn split_parent_child<'b>(&mut self, path: &'b Utf8Path) -> Result<(EntryId, &'b str)> {
        let Some(filename) = path.file_name() else {
            return Err(Error::from(ErrorKind::InvalidFilename));
        };

        let dir = if let Some(dir) = path.parent() {
            dir
        } else {
            return Ok((SyncFileSystem::root_dir_id(), filename.into()));
        };

        let maybe_dir = self.get_entry(dir)?;
        if maybe_dir.kind() != EntryKind::Directory {
            return Err(Error::from(ErrorKind::InvalidFilename));
        }

        Ok((maybe_dir, filename.into()))
    }

    fn exists(&mut self, path: &Utf8Path) -> Result<bool> {
        assert!(path.is_absolute());
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

    fn stat(&mut self, path: &Utf8Path) -> Result<crate::Attr> {
        let entry = self.get_entry(path)?;
        let raw_attr = self.fs_core.stat(entry)?;
        Ok(raw_attr.into())
    }

    fn unlink(&mut self, path: &Utf8Path) -> Result<()> {
        let entry = self.get_entry(path)?;
        if entry.kind() == EntryKind::File {
            // Need to truncate files first.
            self.fs_core.set_file_size(entry, 0)?;
        }
        self.fs_core.remove(entry)?;
        self.pop_cache(path);
        Ok(())
    }

    fn rename(&mut self, old: &Utf8Path, new: &Utf8Path) -> Result<()> {
        log::debug!("rename: {old} -> {new}");

        let entry = self.get_entry(old)?;
        let (new_parent, new_child) = self.split_parent_child(new)?;

        self.fs_core.move_rename(entry, new_parent, new_child)?;
        self.pop_cache(old);
        self.cache.push(new.to_owned(), entry);
        Ok(())
    }

    fn pop_cache(&mut self, path: &Utf8Path) {
        self.cache.pop(path);
    }

    pub(crate) fn get_entry(&mut self, path: &Utf8Path) -> Result<EntryId> {
        if path.as_str() == "/" {
            return Ok(ROOT_DIR_ID);
        }

        if let Some(entry) = self.cache.get(path) {
            return Ok(*entry);
        }

        let parent = path.parent().unwrap();
        let parent_id = self.get_entry(parent)?; // Recursion.
        let entry = self
            .fs_core
            .get_directory_entry_by_name(parent_id, path.file_name().unwrap().into())?;
        self.cache.push(path.to_owned(), entry.id);
        Ok(entry.id)
    }
}

pub struct FileSystem {
    inner: Rc<RefCell<FileSystemInner>>,
}

impl FileSystem {
    const CACHE_SIZE: std::num::NonZeroUsize = std::num::NonZeroUsize::new(4096).unwrap();

    pub fn create_volume(path: &std::path::Path, num_blocks: u64) -> Result<()> {
        let mut bd = srfs_core::file_block_device::FileBlockDevice::create(path, num_blocks)?;
        srfs_core::format(&mut bd)
    }

    pub fn open_volume(path: &std::path::Path) -> Result<Self> {
        let bd = Box::new(srfs_core::file_block_device::FileBlockDevice::open(path)?);
        Self::open_device(bd)
    }

    pub fn open_device(block_device: Box<dyn srfs_core::SyncBlockDevice>) -> Result<Self> {
        let fs = srfs_core::SyncFileSystem::open_fs(block_device)?;

        Ok(Self {
            inner: Rc::new(RefCell::new(FileSystemInner {
                fs_core: fs,
                cache: lru::LruCache::new(Self::CACHE_SIZE),
            })),
        })
    }

    pub fn create_dir(&mut self, path: &Utf8Path) -> Result<()> {
        self.inner.borrow_mut().create_dir(path)
    }

    pub fn create_dir_all(&mut self, path: &Utf8Path) -> Result<()> {
        self.inner.borrow_mut().create_dir_all(path).map(|_| ())
    }

    pub fn create_file(&mut self, path: &Utf8Path) -> Result<crate::File> {
        let file_id = self.inner.borrow_mut().create_file(path)?;
        Ok(crate::File::from(file_id, self.inner.clone()))
    }

    pub fn open_file(&mut self, path: &Utf8Path) -> Result<crate::File> {
        let file_id = self.inner.borrow_mut().get_entry(path)?;
        if file_id.kind() != EntryKind::File {
            assert_eq!(file_id.kind(), EntryKind::Directory);
            return Err(ErrorKind::IsADirectory.into());
        }

        Ok(crate::File::from(file_id, self.inner.clone()))
    }

    pub fn exists(&mut self, path: &Utf8Path) -> Result<bool> {
        self.inner.borrow_mut().exists(path)
    }

    pub fn stat(&mut self, path: &Utf8Path) -> Result<crate::Attr> {
        self.inner.borrow_mut().stat(path)
    }

    pub fn read_dir(&mut self, path: &Utf8Path) -> Result<crate::ReadDir> {
        crate::readdir::ReadDir::new(path, self.inner.clone())
    }

    pub fn unlink(&mut self, path: &Utf8Path) -> Result<()> {
        self.inner.borrow_mut().unlink(path)
    }

    pub fn rename(&mut self, old: &Utf8Path, new: &Utf8Path) -> Result<()> {
        self.inner.borrow_mut().rename(old, new)
    }
}
