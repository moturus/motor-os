use async_fs::AsyncBlockDevice;
use async_fs::Block;
use std::io::{ErrorKind, Result};

use crate::layout::*;
use crate::*;

const CACHE_SIZE: usize = 512; // 2MB.

pub struct SrFs<Dev: AsyncBlockDevice> {
    block_cache: async_fs::block_cache::BlockCache<Dev>,
    error: Result<()>,
}

impl<Dev: AsyncBlockDevice> SrFs<Dev> {
    pub async fn format(mut block_dev: Dev) -> Result<Self> {
        let num_blocks = block_dev.num_blocks();
        if num_blocks < 2 {
            return Err(ErrorKind::InvalidData.into());
        }

        // We use u64::MAX as a marker for None.
        let num_blocks = num_blocks.min(u64::MAX - 1);

        // Write the first block.
        let mut block = Block::new_zeroed();
        let fbh = block.get_mut_at_offset::<SuperblockHeader>(0);
        fbh.magic = crate::MAGIC;
        fbh.version = 1;
        fbh.num_blocks = num_blocks;
        fbh.free_blocks = num_blocks - 2;
        fbh.generation = 1;
        fbh.empty_area_start = 2; // 0 => this; 1 => root dir.
        fbh.set_crc32();
        fbh.validate()?;
        block_dev.write_block(0, &block).await?;

        // Write the root directory.
        block.clear();
        let root_dir = block.get_mut_at_offset::<EntryMetadata>(0);
        *root_dir = EntryMetadata::new(ROOT_DIR_ID, ROOT_DIR_ID);
        root_dir.set_crc32();
        block_dev.write_block(1, &block).await?;

        Ok(Self {
            block_cache: async_fs::block_cache::BlockCache::new(block_dev, CACHE_SIZE).await?,
            error: Ok(()),
        })
    }

    pub async fn open_fs(mut block_dev: Dev) -> Result<Self> {
        let block = Block::from_dev(&mut block_dev, 0).await?;
        let fbh = block.get_at_offset::<SuperblockHeader>(0);

        let num_blocks = fbh.num_blocks;
        if num_blocks < 3 || num_blocks == u64::MAX || num_blocks > block_dev.num_blocks() {
            return Err(ErrorKind::InvalidData.into());
        }

        if fbh.txn_meta_block != 0
            || fbh.txn_data_block != 0
            || fbh.txn_link_block != 0
            || fbh.txn_list_of_links_block != 0
        {
            todo!("roll back or commit the TXN")
        }

        Ok(Self {
            block_cache: async_fs::block_cache::BlockCache::new(block_dev, CACHE_SIZE).await?,
            error: Ok(()),
        })
    }

    fn check_error(&self) -> Result<()> {
        if let Err(err) = &self.error {
            Err(err.kind().into())
        } else {
            Ok(())
        }
    }

    fn make_error(&mut self) -> Result<()> {
        assert!(self.error.is_ok());
        self.error = Err(ErrorKind::InvalidData.into());
        self.check_error()
    }

    async fn find_entry_by_id(
        &mut self,
        parent_id: EntryId,
        entry_id: EntryId,
    ) -> Result<(EntryId, usize /* entry_pos */)> {
        self.find_entry(parent_id, |e| e.id == entry_id).await
    }

    async fn find_entry_by_name(
        &mut self,
        parent_id: EntryId,
        name: &str,
    ) -> Result<(EntryId, usize /* entry_pos */)> {
        self.find_entry(parent_id, |e| {
            if let Ok(s) = core::str::from_utf8(&e.name[0..(e.name_len as usize)]) {
                s == name
            } else {
                false
            }
        })
        .await
    }

    async fn find_entry<F>(
        &mut self,
        parent_id: EntryId,
        pred: F,
    ) -> Result<(EntryId, usize /* entry_pos */)>
    where
        F: Fn(&DirEntry) -> bool,
    {
        self.check_error()?;

        let parent_block = self.block_cache.get_block(parent_id.block_no).await?;
        let meta = parent_block.block().get_at_offset::<EntryMetadata>(0);
        let valid = meta.validate_dir(parent_id);
        if valid.is_err() {
            self.make_error()?;
            unreachable!()
        }

        let num_entries = meta.size;
        if num_entries <= MAX_ENTRIES_IN_META_BLOCK {
            for pos in 0..num_entries {
                let entry = block_get_dir_entry(parent_block.block(), (pos + 1) as usize);
                if pred(entry) {
                    return Ok((entry.id, (pos + 1) as usize));
                }
            }
            return Err(ErrorKind::NotFound.into());
        }

        if num_entries <= MAX_ENTRIES_ONLY_DATA_BLOCKS {
            let num_blocks = num_entries.div_ceil(MAX_ENTRIES_IN_DATA_BLOCK);
            assert!(num_blocks <= MAX_LINKS_IN_META_BLOCK);

            // Copy links out so that we don't have to juggle cached blocks.
            let block_nos = *parent_block.block();

            let mut curr_entry_idx = 0;
            for block_idx in 0..num_blocks {
                let block_no = block_get_datablock_no_in_meta(&block_nos, block_idx);
                let block = self.block_cache.get_block(block_no).await?;

                for pos in 0..MAX_ENTRIES_IN_DATA_BLOCK {
                    let entry = block_get_dir_entry(block.block(), pos as usize);
                    if pred(entry) {
                        return Ok((entry.id, pos as usize));
                    }
                    curr_entry_idx += 1;
                    if curr_entry_idx >= num_entries {
                        break;
                    }
                }
            }
            return Err(ErrorKind::NotFound.into());
        }

        let num_link_blocks = num_entries.div_ceil(MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST);
        assert!(num_link_blocks <= MAX_LINKS_IN_META_BLOCK);
        let num_blocks = num_entries.div_ceil(MAX_ENTRIES_IN_DATA_BLOCK);

        // Copy links out so that we don't have to juggle cached blocks.
        let link_block_nos = *parent_block.block();

        let mut curr_entry_idx = 0;
        let mut curr_block_idx = 0;
        for link_block_idx in 0..num_link_blocks {
            let link_block_no = block_get_datablock_no_in_meta(&link_block_nos, link_block_idx);
            let link_block = self.block_cache.get_block(link_block_no).await?;
            let data_block_nos = *link_block.block();
            for pos_block in 0..512 {
                let data_block_no = block_get_datablock_no_in_link(&data_block_nos, pos_block);
                let block = self.block_cache.get_block(data_block_no).await?;
                for pos in 0..MAX_ENTRIES_IN_DATA_BLOCK {
                    let entry = block_get_dir_entry(block.block(), pos as usize);
                    if pred(entry) {
                        return Ok((entry.id, pos as usize));
                    }
                    curr_entry_idx += 1;
                    if curr_entry_idx >= num_entries {
                        break;
                    }
                }
                curr_block_idx += 1;
                if curr_block_idx >= num_blocks {
                    break;
                }
            }
        }

        Err(ErrorKind::NotFound.into())
    }
}

impl<Dev: AsyncBlockDevice> async_fs::FileSystem for SrFs<Dev> {
    async fn stat(&mut self, parent: async_fs::EntryId, name: &str) -> std::io::Result<EntryId> {
        self.check_error()?;

        let parent_block = self.block_cache.get_block(parent.block_no).await?;
        let meta = parent_block.block().get_at_offset::<EntryMetadata>(0);

        if meta.validate(parent).is_err() {
            self.make_error()?;
            unreachable!()
        }

        let (entry, _) = self.find_entry_by_name(parent, name).await?;
        Ok(entry)
    }

    async fn create_entry(
        &mut self,
        parent: async_fs::EntryId,
        kind: async_fs::EntryKind,
        name: &str, // Leaf name.
    ) -> std::io::Result<async_fs::EntryId> {
        todo!()
    }

    async fn delete_entry(&mut self, entry: async_fs::EntryId) -> std::io::Result<()> {
        todo!()
    }

    async fn list_entries(
        &mut self,
        parent: async_fs::EntryId,
        offset: usize,
        entries: &mut [async_fs::EntryId],
    ) -> std::io::Result<usize> {
        todo!()
    }

    async fn name(&mut self, entry: EntryId) -> std::io::Result<String> {
        if entry == ROOT_DIR_ID {
            return Ok("/".into());
        }

        let block = self.block_cache.get_block(entry.block_no).await?;
        let meta = block.block().get_at_offset::<EntryMetadata>(0);

        if meta.validate(entry).is_err() {
            self.make_error()?;
            unreachable!()
        }

        let parent_id = meta.parent_id;
        let (_, entry_pos) = self.find_entry_by_id(parent_id, entry).await?;
        let parent_block = self.block_cache.get_block(parent_id.block_no).await?;
        let dir_entry = block_get_dir_entry(parent_block.block(), entry_pos);

        let Ok(name) = dir_entry.get_name() else {
            self.make_error()?;
            unreachable!()
        };
        Ok(name.to_owned())
    }

    async fn size(&mut self, entry: async_fs::EntryId) -> std::io::Result<usize> {
        todo!()
    }

    async fn read(
        &mut self,
        entry: async_fs::EntryId,
        offset: u64,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        todo!()
    }

    async fn write(
        &mut self,
        entry: async_fs::EntryId,
        offset: u64,
        buf: &[u8],
    ) -> std::io::Result<usize> {
        todo!()
    }

    async fn rename(
        &mut self,
        entry: async_fs::EntryId,
        new_parent: async_fs::EntryId,
        new_name: &str,
    ) -> std::io::Result<async_fs::EntryId> {
        todo!()
    }

    async fn resize(&mut self, file: async_fs::EntryId, new_size: usize) -> std::io::Result<()> {
        todo!()
    }
}
