extern crate std;

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    path::Path,
};

use crate::{FsError, BLOCK_SIZE};

pub struct FileBlockDevice {
    file: File,
    num_blocks: u64,
}

impl FileBlockDevice {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;

        let len = file.metadata()?.len();
        if len & (BLOCK_SIZE - 1) != 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }

        Ok(Self {
            file,
            num_blocks: len >> BLOCK_SIZE.ilog2(),
        })
    }

    pub fn create(path: &Path, num_blocks: u64) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)?;

        file.set_len(num_blocks << BLOCK_SIZE.ilog2())?;

        Ok(Self { file, num_blocks })
    }
}

impl crate::SyncBlockDevice for FileBlockDevice {
    fn num_blocks(&self) -> u64 {
        self.num_blocks
    }

    fn read_block(&mut self, block_no: u64, buf: &mut [u8]) -> Result<(), FsError> {
        if block_no >= self.num_blocks || buf.len() != BLOCK_SIZE as usize {
            return Err(FsError::InvalidArgument);
        }

        if (buf.as_ptr() as usize) & (BLOCK_SIZE as usize - 1) != 0 {
            return Err(FsError::InvalidArgument);
        }

        self.file
            .seek(std::io::SeekFrom::Start(block_no * BLOCK_SIZE))
            .map_err(|_| FsError::IoError)?;

        let read = self.file.read(buf).map_err(|_| FsError::IoError)?;
        if read != BLOCK_SIZE as usize {
            return Err(FsError::InvalidArgument);
        }

        Ok(())
    }

    fn write_block(&mut self, block_no: u64, buf: &[u8]) -> Result<(), FsError> {
        if block_no >= self.num_blocks || buf.len() != BLOCK_SIZE as usize {
            return Err(FsError::InvalidArgument);
        }

        if (buf.as_ptr() as usize) & (BLOCK_SIZE as usize - 1) != 0 {
            return Err(FsError::InvalidArgument);
        }

        self.file
            .seek(std::io::SeekFrom::Start(block_no * BLOCK_SIZE))
            .map_err(|_| FsError::IoError)?;

        let written = self.file.write(buf).map_err(|_| FsError::IoError)?;
        if written != BLOCK_SIZE as usize {
            return Err(FsError::InvalidArgument);
        }

        Ok(())
    }
}
