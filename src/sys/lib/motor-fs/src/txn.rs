//! Each moderately complex FS operation is a transaction.
//!
//! Mutating transactions:
//! - create entry
//! - delete entry
//! - move entry
//! - write to file
//! - set file size

use crate::{BlockNo, DirEntryBlock, EntryIdInternal, MotorFs, ROOT_DIR_ID, Superblock, dir_entry};
use async_fs::{
    BLOCK_SIZE, EntryKind, Timestamp,
    block_cache::{BlockCache, CachedBlock},
};
use std::io::{ErrorKind, Result};

/// Max number of blocks a single transaction may touch.
const TXN_CACHE_SIZE: usize = 12;

/// The transaction object: accumulates "dirty" blocks, then either discards
/// them on error (so no changes to the underlying FS happen) or applies them
/// "atomically", i.e. either all or nothing.
pub struct Txn<'a> {
    fs: &'a mut MotorFs,
    txn_cache: micromap::Map<BlockNo, CachedBlock, TXN_CACHE_SIZE>,
    read_only: bool,
}

impl<'a> Txn<'a> {
    fn block_cache<'b>(&'b mut self) -> &'b mut BlockCache {
        self.fs.block_cache()
    }

    async fn commit<'b>(&'b mut self) -> Result<()> {
        log::warn!("{}:{} do a proper txn", file!(), line!());

        let Txn {
            fs,
            txn_cache,
            read_only: _,
        } = self;

        // For now, just save all dirty blocks.
        for (block_no, block) in txn_cache.drain() {
            assert_eq!(block_no.as_u64(), block.block_no());
            fs.block_cache().push(block);
            fs.block_cache()
                .write_block_if_dirty(block_no.as_u64())
                .await?;
        }

        #[cfg(debug_assertions)]
        self.block_cache().debug_check_clean();

        Ok(())
    }

    pub fn new_readonly(fs: &'a mut MotorFs) -> Self {
        Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: true,
        }
    }
    pub async fn get_block(&'a mut self, block_no: BlockNo) -> std::io::Result<&'a CachedBlock> {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        let this = unsafe {
            let this = self as *mut Self;
            this.as_mut().unwrap_unchecked()
        };

        if let Some(txn_block) = this.txn_cache.get(&block_no) {
            return Ok(txn_block);
        }

        self.block_cache().get_block(block_no.as_u64()).await
    }

    /// Unlike get_block() above, get_txn_block() ensures the block is part of the transaction,
    /// i.e. will be saved in Txn::commit().
    pub async fn get_txn_block<'b>(
        &'b mut self,
        block_no: BlockNo,
    ) -> std::io::Result<&'b mut CachedBlock> {
        assert!(!self.read_only);

        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        let this_1 = unsafe {
            let this = self as *mut Self;
            this.as_mut().unwrap_unchecked()
        };
        let this_2 = unsafe {
            let this = self as *mut Self;
            this.as_mut().unwrap_unchecked()
        };

        if let Some(txn_block) = this_1.txn_cache.get_mut(&block_no) {
            return Ok(txn_block);
        }

        let block = self.block_cache().get_block(block_no.as_u64()).await?;
        this_2.txn_cache.insert(block_no, block.clone());

        // Recursion.
        let Some(txn_block) = this_2.txn_cache.get_mut(&block_no) else {
            panic!();
        };

        Ok(txn_block)
    }

    pub fn get_empty_block_mut<'b>(&'b mut self, block_no: BlockNo) -> &'b mut CachedBlock {
        assert!(!self.read_only);

        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        let this_1 = unsafe {
            let this = self as *mut Self;
            this.as_mut().unwrap_unchecked()
        };
        let this_2 = unsafe {
            let this = self as *mut Self;
            this.as_mut().unwrap_unchecked()
        };

        if let Some(txn_block) = this_1.txn_cache.get_mut(&block_no) {
            txn_block.block_mut().clear();
            return txn_block;
        }

        let block = self.block_cache().get_empty_block(block_no.as_u64());
        this_2.txn_cache.insert(block_no, block.clone());

        // Recursion.
        let Some(txn_block) = this_2.txn_cache.get_mut(&block_no) else {
            panic!();
        };

        txn_block
    }

    pub async fn do_create_entry_txn(
        fs: &'a mut MotorFs,
        parent_id: EntryIdInternal,
        kind: EntryKind,
        filename: &'a str,
    ) -> Result<EntryIdInternal> {
        let mut txn = Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        let parent_id: EntryIdInternal = parent_id.into();
        let hash = {
            // TODO: remove unsafe when NLL Problem #3 is solved.
            // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
            let this_txn = unsafe {
                let this = &mut txn as *mut Self;
                this.as_mut().unwrap_unchecked()
            };
            let parent_block = this_txn.get_block(parent_id.block_no).await?;
            dir_entry!(parent_block).validate_entry(parent_id)?;

            if dir_entry!(parent_block).kind() != EntryKind::Directory {
                return Err(ErrorKind::NotADirectory.into());
            }

            dir_entry!(parent_block).hash(filename)
        };

        let entry_id = Superblock::allocate_block(&mut txn).await?;
        DirEntryBlock::init_child_entry(&mut txn, parent_id, entry_id, kind, filename);
        DirEntryBlock::link_child_block(&mut txn, parent_id.block_no, entry_id.block_no, hash)
            .await?;
        DirEntryBlock::increment_dir_size(&mut txn, parent_id).await?;
        txn.commit().await?;
        Ok(entry_id)
    }

    pub async fn do_delete_entry_txn(fs: &'a mut MotorFs, entry_id: EntryIdInternal) -> Result<()> {
        let entry_id: EntryIdInternal = entry_id.into();
        if entry_id == ROOT_DIR_ID {
            return Err(ErrorKind::InvalidInput.into());
        }

        let mut txn = Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        let parent_id = {
            // TODO: remove unsafe when NLL Problem #3 is solved.
            // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
            let this_txn = unsafe {
                let this = &mut txn as *mut Self;
                this.as_mut().unwrap_unchecked()
            };
            let entry_block = this_txn.get_block(entry_id.block_no).await?;
            dir_entry!(entry_block).validate_entry(entry_id)?;
            if dir_entry!(entry_block).metadata().size > 0 {
                return match dir_entry!(entry_block).kind() {
                    EntryKind::Directory => Err(ErrorKind::DirectoryNotEmpty.into()),
                    EntryKind::File => {
                        log::error!("TODO: implement deleting non-empty files.");
                        Err(ErrorKind::FileTooLarge.into())
                    }
                };
            }

            dir_entry!(entry_block).parent_id()
        };
        DirEntryBlock::delete_entry(&mut txn, parent_id, entry_id).await?;
        txn.commit().await
    }

    pub async fn do_write_txn(
        fs: &'a mut MotorFs,
        file_id: EntryIdInternal,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize> {
        // For now, cross-block writes are not supported.

        // Block "hash" is the offset of the start of the block.
        let block_start = offset & !(BLOCK_SIZE as u64 - 1);
        if (offset + (buf.len() as u64)) > (block_start + (BLOCK_SIZE as u64)) {
            log::debug!("MotorFs::write() error: cross-block writes are not supported (yet?).");
            return Err(ErrorKind::InvalidInput.into());
        }

        let file_id: EntryIdInternal = file_id.into();
        let block = fs.block_cache().get_block(file_id.block_no()).await?;
        dir_entry!(block).validate_entry(file_id)?;
        if dir_entry!(block).metadata().kind() != EntryKind::File {
            return Err(ErrorKind::IsADirectory.into());
        }

        let prev_file_size = dir_entry!(block).metadata().size;
        let new_file_size = offset + (buf.len() as u64);

        let mut txn = Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        // Step 1: find or insert the data block.
        let data_block_no = match DirEntryBlock::first_data_block_at_offset(
            &mut txn,
            file_id,
            block_start,
        )
        .await?
        {
            Some(block_no) => block_no,
            None => DirEntryBlock::insert_data_block(&mut txn, file_id, block_start).await?,
        };

        // Step 2: update the data lock.
        let data_block = txn.get_txn_block(data_block_no).await?;
        data_block.block_mut().as_bytes_mut()
            [(offset - block_start) as usize..(new_file_size - block_start) as usize]
            .copy_from_slice(buf);

        // Step 3: update the file size & modified.
        {
            let entry_block = txn.get_txn_block(file_id.block_no).await?;
            let mut entry_ref = entry_block.block_mut();
            DirEntryBlock::from_block_mut(&mut *entry_ref)
                .metadata_mut()
                .modified = Timestamp::now();
            if prev_file_size < new_file_size {
                DirEntryBlock::from_block_mut(&mut *entry_ref).set_file_size(new_file_size);
            }
        }

        txn.commit().await?;

        Ok(buf.len())
    }
}
