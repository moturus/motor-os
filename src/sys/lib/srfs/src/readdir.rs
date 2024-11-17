use std::io::{ErrorKind, Result};
use std::{cell::RefCell, rc::Rc};

use srfs_core::{EntryId, EntryKind};

use crate::{error, FileSystemInner};
pub struct DirEntry {
    name: String, // The leaf name.
    path: String, // The full path.
    id: EntryId,
    fs: Rc<RefCell<FileSystemInner>>,
}

impl DirEntry {
    pub fn stat(&self) -> Result<crate::Attr> {
        let raw_attr = self
            .fs
            .borrow_mut()
            .fs_core()
            .stat(self.id)
            .map_err(error::to_ioerror)?;
        Ok(raw_attr.into())
    }

    pub fn file_name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn file_type(&self) -> crate::EntryKind {
        self.id.kind()
    }
}

pub struct ReadDir {
    path: String,
    parent: EntryId,
    cur_pos: u64,
    num_entries: u64,
    fs: Rc<RefCell<FileSystemInner>>,
}

impl ReadDir {
    pub(crate) fn new(path: &str, fs: Rc<RefCell<FileSystemInner>>) -> Result<Self> {
        let parent = fs.borrow_mut().get_entry(path)?;
        if parent.kind() != EntryKind::Directory {
            return Err(ErrorKind::NotADirectory.into());
        }

        let num_entries = fs
            .borrow_mut()
            .fs_core()
            .get_num_entries(parent)
            .map_err(error::to_ioerror)?;

        Ok(Self {
            path: path.to_owned(),
            parent,
            cur_pos: 0,
            num_entries,
            fs,
        })
    }
}

impl Iterator for ReadDir {
    type Item = Result<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur_pos == self.num_entries {
            return None;
        }

        let entry = self
            .fs
            .borrow_mut()
            .fs_core()
            .get_directory_entry(self.parent, self.cur_pos)
            .map_err(error::to_ioerror);
        self.cur_pos += 1;

        match entry {
            Ok(entry) => Some(Ok(DirEntry {
                name: entry.name.clone(),
                path: self.path.clone(),
                id: entry.id,
                fs: self.fs.clone(),
            })),
            Err(err) => Some(Err(err)),
        }
    }
}
