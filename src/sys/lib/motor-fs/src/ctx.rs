//! Context of an operation.

use crate::{MotorFs, Superblock};
use std::io::Result;

pub(crate) struct Ctx<'a> {
    fs: &'a mut MotorFs,
}

impl<'a> Ctx<'a> {
    pub fn new(fs: &'a mut MotorFs) -> Self {
        Self { fs }
    }

    pub fn block_cache(&mut self) -> &mut async_fs::block_cache::BlockCache {
        self.fs.block_cache()
    }

    pub async fn superblock(&mut self) -> Result<&Superblock> {
        self.fs.superblock().await
    }

    pub async fn superblock_mut(&mut self) -> Result<&mut Superblock> {
        self.fs.superblock_mut().await
    }
}
