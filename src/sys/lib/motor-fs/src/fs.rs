//! Motor FS.
//!
//! Note: it is relatively easy to corrupt the FS by crafting file data blocks
//!       to resemble dir entry or tree blocks, and then issue operations like
//!       insert/delete. This should be fixed at a higher (OS?) level.

use async_fs::block_cache::BlockCache;
use async_fs::{AsyncBlockDevice, BLOCK_SIZE, FileSystem};
use async_fs::{EntryId, EntryKind};
use std::io::ErrorKind;
use std::io::Result;

use crate::{
    DirEntryBlock, EntryIdInternal, ROOT_DIR_ID, Superblock, Txn, dir_entry, validate_filename,
};

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
}

impl FileSystem for MotorFs {
    async fn stat(&mut self, parent_id: EntryId, filename: &str) -> Result<Option<EntryId>> {
        // Note: parent is required here, so "/" is always invalid.
        validate_filename(filename)?;

        let id: EntryIdInternal = parent_id.into();
        let parent_block = self.block_cache.get_block(id.block_no()).await?.clone();
        assert!(!parent_block.is_dirty());
        dir_entry!(parent_block).validate_entry(id)?;

        if dir_entry!(parent_block).kind() != EntryKind::Directory {
            return Err(ErrorKind::NotADirectory.into());
        }

        let hash = dir_entry!(parent_block).hash(filename);

        let mut txn = Txn::new_readonly(self);

        assert!(!parent_block.is_dirty());
        let Some(mut child_block_no) = dir_entry!(parent_block)
            .first_child_with_hash(&mut txn, hash)
            .await?
        else {
            assert!(!parent_block.is_dirty());
            return Ok(None);
        };
        drop(txn);

        loop {
            let child_block = self.block_cache.get_block(child_block_no.as_u64()).await?;

            assert_eq!(
                dir_entry!(parent_block).hash(dir_entry!(child_block).name()?),
                hash
            );

            if dir_entry!(child_block).name()? == filename {
                let result = dir_entry!(child_block)
                    .entry_id_with_validation(child_block_no)?
                    .into();
                return Ok(Some(result));
            }

            child_block_no = if let Some(id) = dir_entry!(child_block).next_entry_id() {
                id.block_no
            } else {
                break;
            };
        }

        Ok(None)
    }

    async fn create_entry(
        &mut self,
        parent_id: EntryId,
        kind: async_fs::EntryKind,
        filename: &str, // Leaf name.
    ) -> Result<EntryId> {
        if self.stat(parent_id, filename).await?.is_some() {
            return Err(ErrorKind::AlreadyExists.into());
        }

        Txn::do_create_entry_txn(self, parent_id.into(), kind, filename)
            .await
            .map(|e| e.into())
    }

    async fn delete_entry(&mut self, entry_id: EntryId) -> Result<()> {
        Txn::do_delete_entry_txn(self, entry_id.into()).await
    }

    async fn move_entry(
        &mut self,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<()> {
        if entry_id == ROOT_DIR_ID.into() {
            return Err(ErrorKind::InvalidInput.into());
        }

        if entry_id == new_parent_id {
            return Err(ErrorKind::InvalidInput.into());
        }

        validate_filename(new_name)?;

        // Check that we are not moving an entry down to its own child,
        // which will create a detached cycle.
        let mut ancestor_id = new_parent_id;
        loop {
            let Some(grandparent_id) = self.get_parent(ancestor_id).await? else {
                assert_eq!(ancestor_id, ROOT_DIR_ID.into());
                break;
            };
            if grandparent_id == entry_id.into() {
                log::debug!("MotorFS::move_entry: cannot move an entry under its own child.");
                return Err(ErrorKind::InvalidInput.into());
            }
            ancestor_id = grandparent_id;
        }

        let old_parent_id = self.get_parent(entry_id).await?.unwrap();

        Txn::do_move_entry_txn(
            self,
            entry_id.into(),
            old_parent_id.into(),
            new_parent_id.into(),
            new_name,
        )
        .await
    }

    /// Get the first entry in a directory.
    async fn get_first_entry(&mut self, _parent_id: EntryId) -> Result<Option<EntryId>> {
        todo!()
        /*
        let id: EntryIdInternal = parent_id.into();
        let parent_block = self.block_cache.pin_block(id.block_no()).await?;
        let parent = parent_block.block().get_at_offset::<DirEntryBlock>(0);
        parent.validate_entry(id)?;

        if parent.kind() != EntryKind::Directory {
            return Err(ErrorKind::NotADirectory.into());
        }

        let mut ctx = Txn::new_readonly(self);

        let Some(child_block_no) = parent.first_child(&mut ctx).await? else {
            self.block_cache.unpin_block(parent_block);
            return Ok(None);
        };

        self.block_cache.unpin_block(parent_block);
        let child_block = self
            .block_cache
            .get_block_mut(child_block_no.as_u64())
            .await?;
        let child = child_block.block().get_at_offset::<DirEntryBlock>(0);
        Ok(Some(child.entry_id_with_validation(child_block_no)?.into()))
        */
    }

    /// Get the next entry in a directory.
    async fn get_next_entry(&mut self, _entry_id: EntryId) -> Result<Option<EntryId>> {
        todo!()
        /*
        let id: EntryIdInternal = entry_id.into();
        let block = self.block_cache.get_block_mut(id.block_no()).await?;
        let entry = block.block().get_at_offset::<DirEntryBlock>(0);
        entry.validate_entry(id)?;

        todo!()
        */
    }

    async fn get_parent(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        let id: EntryIdInternal = entry_id.into();
        if id == ROOT_DIR_ID {
            return Ok(None);
        }

        let block = self.block_cache.get_block(id.block_no()).await?;
        dir_entry!(block).validate_entry(id)?;

        Ok(Some(dir_entry!(block).parent_id().into()))
    }

    async fn name(&mut self, entry_id: EntryId) -> Result<String> {
        let id: EntryIdInternal = entry_id.into();
        let block = self.block_cache.get_block(id.block_no()).await?;
        dir_entry!(block).validate_entry(id)?;

        dir_entry!(block).name().map(|s| s.to_owned())
    }

    async fn metadata(&mut self, entry_id: EntryId) -> Result<async_fs::Metadata> {
        let id: EntryIdInternal = entry_id.into();
        let block = self.block_cache.get_block(id.block_no()).await?;
        dir_entry!(block).validate_entry(id)?;

        Ok(*dir_entry!(block).metadata())
    }

    async fn read(&mut self, file_id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let file_id: EntryIdInternal = file_id.into();
        let entry_block = self.block_cache.get_block(file_id.block_no()).await?;
        dir_entry!(entry_block).validate_entry(file_id)?;

        if dir_entry!(entry_block).kind() != EntryKind::File {
            return Err(ErrorKind::IsADirectory.into());
        }

        let file_size = dir_entry!(entry_block).metadata().size;
        if offset >= file_size {
            return Ok(0);
        }

        let block_start = offset & !(BLOCK_SIZE as u64 - 1);
        if (offset + (buf.len() as u64)) > (block_start + (BLOCK_SIZE as u64)) {
            log::debug!("MotorFs::read() error: cross-block reads are not supported (yet?).");
            return Err(ErrorKind::InvalidInput.into());
        }

        assert!(buf.len() <= BLOCK_SIZE);

        let to_read = if (file_size - offset) >= (BLOCK_SIZE as u64) {
            buf.len()
        } else {
            buf.len().min((file_size - offset) as usize)
        };

        let mut txn = Txn::new_readonly(self);
        let Some(data_block_no) =
            DirEntryBlock::first_data_block_at_offset(&mut txn, file_id, block_start).await?
        else {
            // No data block => "read" zeroes.
            for byte in &mut buf[..to_read] {
                *byte = 0;
            }

            return Ok(to_read);
        };
        drop(txn);

        let data_block = self.block_cache.get_block(data_block_no.as_u64()).await?;
        let offset_within_block = (offset - block_start) as usize;
        buf[..to_read].copy_from_slice(
            &data_block.block().as_bytes()[offset_within_block..(offset_within_block + to_read)],
        );

        Ok(to_read)
    }

    async fn write(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize> {
        Txn::do_write_txn(self, file_id.into(), offset, buf).await
    }

    async fn resize(&mut self, _file_id: EntryId, _new_size: u64) -> Result<()> {
        todo!()
    }

    async fn empty_blocks(&mut self) -> Result<u64> {
        self.check_err()?;
        let sb = self.block_cache.get_block(0).await?;
        Ok(sb.block().get_at_offset::<Superblock>(0).free_blocks())
    }

    async fn flush(&mut self) -> Result<()> {
        self.block_cache.flush().await
    }

    fn num_blocks(&self) -> u64 {
        self.block_cache.device().num_blocks()
    }
}
