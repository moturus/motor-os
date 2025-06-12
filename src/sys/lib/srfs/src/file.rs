use crate::FileSystemInner;
use srfs_core::EntryId;
use std::io::Result;
use std::{cell::RefCell, rc::Rc};

pub struct File {
    curr_pos: u64,
    id: EntryId,
    fs: Rc<RefCell<FileSystemInner>>,
}

impl File {
    pub(crate) fn from(id: EntryId, fs: Rc<RefCell<FileSystemInner>>) -> Self {
        Self {
            curr_pos: 0,
            id,
            fs,
        }
    }

    pub fn size(&mut self) -> Result<u64> {
        self.fs.borrow_mut().fs_core().get_file_size(self.id)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let written = self
            .fs
            .borrow_mut()
            .fs_core()
            .write(self.id, self.curr_pos, buf)?;
        self.curr_pos += written as u64;
        Ok(written)
    }

    pub fn write_offset(&mut self, offset: u64, buf: &[u8]) -> Result<usize> {
        let written = self.fs.borrow_mut().fs_core().write(self.id, offset, buf)?;
        Ok(written)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = self
            .fs
            .borrow_mut()
            .fs_core()
            .read(self.id, self.curr_pos, buf)?;
        self.curr_pos += read as u64;
        Ok(read)
    }

    pub fn read_offset(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.fs.borrow_mut().fs_core().read(self.id, offset, buf)
    }

    pub fn truncate(&mut self) -> Result<()> {
        todo!()
    }

    pub fn seek(&mut self, pos: std::io::SeekFrom) -> Result<u64> {
        let size = self.size()?;
        let new_pos: u64;
        match pos {
            std::io::SeekFrom::Start(pos) => new_pos = pos,
            std::io::SeekFrom::End(pos) => {
                if pos > 0 {
                    return Err(std::io::ErrorKind::InvalidInput.into());
                }
                let inv = -pos as u64;
                if inv > size {
                    return Err(std::io::ErrorKind::InvalidInput.into());
                }
                new_pos = size - inv;
            }
            std::io::SeekFrom::Current(pos) => {
                if pos >= 0 {
                    new_pos = self.curr_pos + (pos as u64);
                } else {
                    let inv = -pos as u64;
                    new_pos = self.curr_pos + inv;
                }
            }
        }

        if new_pos > size {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        self.curr_pos = new_pos;
        Ok(self.curr_pos)
    }
}
