//! Motor FS.

use async_fs::block_cache::BlockCache;
use async_fs::{AsyncBlockDevice, FileSystem};
use async_fs::{EntryId, EntryKind};
use std::io::ErrorKind;
use std::io::Result;

use crate::{Ctx, DirEntryBlock, EntryIdInternal, ROOT_DIR_ID, Superblock, validate_filename};

const CACHE_SIZE: usize = 512; // 2MB.

pub struct MotorFs {
    block_cache: async_fs::block_cache::BlockCache,
    error: Result<()>,
}

impl MotorFs {
    pub fn check_err(&self) -> Result<()> {
        match &self.error {
            Ok(_) => Ok(()),
            Err(err) => Err(err.kind().clone().into()),
        }
    }

    pub async fn format(mut dev: Box<dyn AsyncBlockDevice>) -> Result<Self> {
        if dev.num_blocks() <= 2 {
            return Err(ErrorKind::StorageFull.into());
        }
        let (superblock, root_dir) = Superblock::format(dev.num_blocks());

        dev.write_block(0, &superblock).await?;
        dev.write_block(1, &root_dir).await?;

        Ok(Self {
            block_cache: BlockCache::new(dev, CACHE_SIZE).await?,
            error: Ok(()),
        })
    }

    pub fn block_cache(&mut self) -> &mut async_fs::block_cache::BlockCache {
        &mut self.block_cache
    }

    pub(crate) async fn superblock(&mut self) -> Result<&Superblock> {
        let block = self.block_cache.get_block(0).await?;
        Ok(block.block().get_at_offset::<Superblock>(0))
    }

    pub(crate) async fn superblock_mut(&mut self) -> Result<&mut Superblock> {
        let block = self.block_cache.get_block(0).await?;
        Ok(block.block_mut().get_mut_at_offset::<Superblock>(0))
    }
}

impl FileSystem for MotorFs {
    async fn stat(&mut self, parent_id: EntryId, filename: &str) -> Result<Option<EntryId>> {
        // Note: parent is required here, so "/" is always invalid.
        validate_filename(filename)?;

        let id: EntryIdInternal = parent_id.into();
        let parent_block = self.block_cache.pin_block(id.block_no()).await?;
        let parent = parent_block.block().get_at_offset::<DirEntryBlock>(0);
        parent.validate_entry(id)?;

        if parent.kind() != EntryKind::Directory {
            return Err(ErrorKind::NotADirectory.into());
        }

        let hash = parent.hash(filename);

        let mut ctx = Ctx::new(self);

        let Some(mut child_block_no) = parent.first_child_with_hash(&mut ctx, hash).await? else {
            self.block_cache.unpin_block(parent_block);
            return Ok(None);
        };

        loop {
            let child_block = self.block_cache.get_block(child_block_no.as_u64()).await?;
            let child = child_block.block().get_at_offset::<DirEntryBlock>(0);

            let name = child.name()?;
            if name == filename {
                let result = child.entry_id_with_validation(child_block_no)?.into();
                self.block_cache.unpin_block(parent_block);
                return Ok(Some(result));
            }

            if parent.hash(name) != hash {
                break;
            }

            child_block_no = if let Some(id) = child.next_entry_id() {
                id.block_no
            } else {
                break;
            };
        }

        self.block_cache.unpin_block(parent_block);
        Ok(None)
    }

    async fn create_entry(
        &mut self,
        parent_id: EntryId,
        kind: async_fs::EntryKind,
        filename: &str, // Leaf name.
    ) -> Result<EntryId> {
        validate_filename(filename)?;

        let parent_id: EntryIdInternal = parent_id.into();
        let mut parent_block = self.block_cache.pin_block(parent_id.block_no()).await?;
        let parent = parent_block.block().get_at_offset::<DirEntryBlock>(0);
        parent.validate_entry(parent_id)?;

        if parent.kind() != EntryKind::Directory {
            return Err(ErrorKind::NotADirectory.into());
        }

        let hash = parent.hash(filename);

        let mut ctx = Ctx::new(self);

        let Some(mut child_block_no) = parent.first_child_with_hash(&mut ctx, hash).await? else {
            let result = DirEntryBlock::insert(parent_block, &mut ctx, kind, hash, filename).await;
            return result.map(|e| e.into());
        };

        loop {
            let child_block = self.block_cache.get_block(child_block_no.as_u64()).await?;
            let child = child_block.block().get_at_offset::<DirEntryBlock>(0);

            let name = child.name()?;
            if name == filename {
                self.block_cache.unpin_block(parent_block);
                return Err(ErrorKind::AlreadyExists.into());
            }

            if parent.hash(name) != hash {
                todo!("add new entry after child")
            }

            child_block_no = if let Some(id) = child.next_entry_id() {
                id.block_no
            } else {
                todo!("add new entry after child")
            };
        }
    }

    async fn delete_entry(&mut self, entry_id: EntryId) -> Result<()> {
        todo!()
    }

    /// Get the first entry in a directory.
    async fn get_first_entry(&mut self, parent_id: EntryId) -> Result<Option<EntryId>> {
        let id: EntryIdInternal = parent_id.into();
        let parent_block = self.block_cache.pin_block(id.block_no()).await?;
        let parent = parent_block.block().get_at_offset::<DirEntryBlock>(0);
        parent.validate_entry(id)?;

        if parent.kind() != EntryKind::Directory {
            return Err(ErrorKind::NotADirectory.into());
        }

        let mut ctx = Ctx::new(self);

        let Some(child_block_no) = parent.first_child(&mut ctx).await? else {
            self.block_cache.unpin_block(parent_block);
            return Ok(None);
        };

        self.block_cache.unpin_block(parent_block);
        let child_block = self.block_cache.get_block(child_block_no.as_u64()).await?;
        let child = child_block.block().get_at_offset::<DirEntryBlock>(0);
        Ok(Some(child.entry_id_with_validation(child_block_no)?.into()))
    }

    /// Get the next entry in a directory.
    async fn get_next_entry(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        let id: EntryIdInternal = entry_id.into();
        let block = self.block_cache.get_block(id.block_no()).await?;
        let entry = block.block().get_at_offset::<DirEntryBlock>(0);
        entry.validate_entry(id)?;

        Ok(entry.next_entry_id().map(|e| e.into()))
    }

    async fn get_parent(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        let id: EntryIdInternal = entry_id.into();
        if id == ROOT_DIR_ID {
            return Ok(None);
        }

        let block = self.block_cache.get_block(id.block_no()).await?;
        let entry = block.block().get_at_offset::<DirEntryBlock>(0);
        entry.validate_entry(id)?;

        Ok(Some(entry.parent_id().into()))
    }

    async fn name(&mut self, entry_id: EntryId) -> Result<String> {
        let id: EntryIdInternal = entry_id.into();
        let block = self.block_cache.get_block(id.block_no()).await?;
        let entry = block.block().get_at_offset::<DirEntryBlock>(0);
        entry.validate_entry(id)?;

        entry.name().map(|s| s.to_owned())
    }

    async fn metadata(&mut self, entry_id: EntryId) -> Result<async_fs::Metadata> {
        let id: EntryIdInternal = entry_id.into();
        let block = self.block_cache.get_block(id.block_no()).await?;
        let entry = block.block().get_at_offset::<DirEntryBlock>(0);
        entry.validate_entry(id)?;

        Ok(*entry.metadata())
    }

    async fn read(&mut self, file_id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        todo!()
    }

    async fn write(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize> {
        todo!()
    }

    async fn move_rename(
        &mut self,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<EntryId> {
        todo!()
    }

    async fn resize(&mut self, file_id: EntryId, new_size: u64) -> Result<()> {
        todo!()
    }

    async fn empty_blocks(&mut self) -> Result<u64> {
        self.check_err()?;
        Ok(self.superblock().await?.free_blocks())
    }

    async fn flush(&mut self) -> Result<()> {
        self.block_cache.flush().await
    }

    fn num_blocks(&self) -> u64 {
        self.block_cache.device().num_blocks()
    }
}
