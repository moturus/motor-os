use async_fs::AsyncBlockDevice;
use async_fs::Block;
use camino::Utf8Path;
use core::cell::RefCell;
use core::ops::DerefMut;
use std::io::{ErrorKind, Result};
use std::rc::Rc;

use crate::*;

extern crate std;

pub struct SrFs<Dev: AsyncBlockDevice> {
    block_dev: Rc<RefCell<Dev>>,
    error: Result<()>,
}

impl<Dev: AsyncBlockDevice> SrFs<Dev> {
    pub async fn format(block_dev: Rc<RefCell<Dev>>) -> Result<Self> {
        let mut dev = block_dev.borrow_mut();
        let num_blocks = dev.num_blocks();
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
        fbh.validate().map_err(map_fs_error)?;
        dev.write_block(0, &block).await?;

        // Write the root directory.
        let root_dir = block.get_mut_at_offset::<EntryMetadata>(0);
        *root_dir = EntryMetadata::new(ROOT_DIR_ID, ROOT_DIR_ID);
        root_dir.set_crc32();
        dev.write_block(1, &block).await?;

        core::mem::drop(dev);
        Ok(Self {
            block_dev,
            error: Ok(()),
        })
    }

    pub async fn open_fs(block_dev: Rc<RefCell<Dev>>) -> Result<Self> {
        let mut dev = block_dev.borrow_mut();

        let block = Block::from_dev(dev.deref_mut(), 0).await?;
        let fbh = block.get_at_offset::<SuperblockHeader>(0);

        let num_blocks = fbh.num_blocks;
        if num_blocks < 3 || num_blocks == u64::MAX || num_blocks > dev.num_blocks() {
            return Err(ErrorKind::InvalidData.into());
        }

        if fbh.txn_meta_block != 0
            || fbh.txn_data_block != 0
            || fbh.txn_link_block != 0
            || fbh.txn_list_of_links_block != 0
        {
            todo!("roll back or commit the TXN")
        }

        core::mem::drop(dev);
        Ok(Self {
            block_dev,
            error: Ok(()),
        })
    }

    async fn find_entry_by_id(
        &mut self,
        parent_id: EntryId,
        entry_id: EntryId,
    ) -> Result<(u64 /* block_no */, usize /* entry_pos */)> {
        self.find_entry(parent_id, |e| e.id == entry_id).await
    }

    async fn find_entry_by_name(
        &mut self,
        parent_id: EntryId,
        name: &Utf8Path,
    ) -> Result<(u64 /* block_no */, usize /* entry_pos */)> {
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
    ) -> Result<(u64 /* block_no */, usize /* entry_pos */)>
    where
        F: Fn(&DirEntryInternal) -> bool,
    {
        self.error?;
        let mut dev = self.block_dev.borrow_mut();

        let parent_block = Block::from_dev(dev.deref_mut(), parent_id.block_no).await?;
        let meta = unsafe { parent_block.block().get::<EntryMetadata>() };
        let valid = meta.validate_dir(parent_id);
        if valid.is_err() {
            let _ = self.make_error();
            return Err(valid.err().unwrap());
        }

        let num_entries = meta.size;
        if num_entries <= MAX_ENTRIES_IN_META_BLOCK {
            for pos in 0..num_entries {
                let entry = parent_block.block().get_dir_entry((pos + 1) as usize);
                if pred(entry) {
                    return Ok((parent_id.block_no, (pos + 1) as usize));
                }
            }
            return Err(FsError::NotFound);
        }

        if num_entries <= MAX_ENTRIES_ONLY_DATA_BLOCKS {
            let num_blocks = num_entries.div_ceil(MAX_ENTRIES_IN_DATA_BLOCK);
            assert!(num_blocks <= MAX_LINKS_IN_META_BLOCK);

            // Copy links out so that we don't have to juggle cached blocks.
            let block_nos = *parent_block.block();

            let mut curr_entry_idx = 0;
            for block_idx in 0..num_blocks {
                let block_no = block_nos.get_datablock_no_in_meta(block_idx);
                let block = self.blockcache.read(block_no)?;

                for pos in 0..MAX_ENTRIES_IN_DATA_BLOCK {
                    let entry = block.block().get_dir_entry(pos as usize);
                    if pred(entry) {
                        return Ok((block_no, pos as usize));
                    }
                    curr_entry_idx += 1;
                    if curr_entry_idx >= num_entries {
                        break;
                    }
                }
            }
            return Err(FsError::NotFound);
        }

        let num_link_blocks = num_entries.div_ceil(MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST);
        assert!(num_link_blocks <= MAX_LINKS_IN_META_BLOCK);
        let num_blocks = num_entries.div_ceil(MAX_ENTRIES_IN_DATA_BLOCK);

        // Copy links out so that we don't have to juggle cached blocks.
        let link_block_nos = *parent_block.block();

        let mut curr_entry_idx = 0;
        let mut curr_block_idx = 0;
        for link_block_idx in 0..num_link_blocks {
            let link_block_no = link_block_nos.get_datablock_no_in_meta(link_block_idx);
            let link_block = self.blockcache.read(link_block_no)?;
            let data_block_nos = *link_block.block();
            for pos_block in 0..512 {
                let data_block_no = data_block_nos.get_datablock_no_in_link(pos_block);
                let block = self.blockcache.read(data_block_no)?;
                for pos in 0..MAX_ENTRIES_IN_DATA_BLOCK {
                    let entry = block.block().get_dir_entry(pos as usize);
                    if pred(entry) {
                        return Ok((data_block_no, pos as usize));
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
        Err(FsError::NotFound)
    }
}

impl<Dev: AsyncBlockDevice> async_fs::FileSystem for SrFs<Dev> {
    async fn stat(&mut self, full_path: &camino::Utf8Path) -> std::io::Result<async_fs::EntryId> {
        todo!()
    }

    async fn create_entry(
        &mut self,
        parent: async_fs::EntryId,
        kind: async_fs::EntryKind,
        name: &camino::Utf8Path, // Leaf name.
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

    async fn name(&mut self, entry: async_fs::EntryId) -> std::io::Result<camino::Utf8PathBuf> {
        if entry == ROOT_DIR_ID {
            return Ok("/".into());
        }

        let mut dev = self.block_dev.borrow_mut();
        let block = Block::from_dev(dev.deref_mut(), entry.block_no).await?;
        let meta = block.get_at_offset::<EntryMetadata>(0);

        meta.validate(entry).map_err(map_fs_error)?;

        let parent_id = meta.parent_id;
        let (block_no, entry_pos) = self.find_entry_by_id(parent_id, entry).await?;
        let block = Block::from_dev(dev.deref_mut(), block_no).await?;
        let dir_entry = block.block().get_dir_entry(entry_pos);
        Ok(dir_entry.to_owned()?.name)
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
        new_name: &camino::Utf8Path,
    ) -> std::io::Result<async_fs::EntryId> {
        todo!()
    }

    async fn resize(&mut self, file: async_fs::EntryId, new_size: usize) -> std::io::Result<()> {
        todo!()
    }
}
