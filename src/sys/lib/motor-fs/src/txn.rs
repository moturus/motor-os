//! Each moderately complex FS operation is a transaction.
//!
//! Mutating transactions:
//! - create entry
//! - delete entry
//! - move entry
//! - write to file
//! - set file size

use crate::{BlockNo, DirEntryBlock, EntryIdInternal, MotorFs, Superblock, dir_entry};
use async_fs::{
    BLOCK_SIZE, EntryKind, FileSystem, Timestamp,
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

impl<'a> Drop for Txn<'a> {
    fn drop(&mut self) {
        let Txn {
            fs,
            txn_cache,
            read_only,
        } = self;

        if *read_only {
            assert!(txn_cache.is_empty());
            return;
        }

        for (block_no, block) in txn_cache.drain() {
            assert_eq!(block_no.as_u64(), block.block_no());
            fs.block_cache().discard(block);
        }

        #[cfg(debug_assertions)]
        self.block_cache().debug_check_clean();
    }
}

impl<'a> Txn<'a> {
    fn block_cache<'b>(&'b mut self) -> &'b mut BlockCache {
        self.fs.block_cache()
    }

    async fn commit<'b>(&'b mut self) -> Result<()> {
        log::trace!("{}:{} do a proper txn", file!(), line!());

        let Txn {
            fs,
            txn_cache,
            read_only,
        } = self;

        assert!(!*read_only);

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

    pub async fn get_block<'b>(
        &'b mut self,
        block_no: BlockNo,
    ) -> std::io::Result<&'b CachedBlock> {
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
        log::trace!(
            "{}:{} - create entry: {parent_id:?} {kind:?} {filename}",
            file!(),
            line!()
        );
        let mut txn = Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        let this_txn = unsafe {
            let this = &mut txn as *mut Self;
            this.as_mut().unwrap_unchecked()
        };
        let hash = DirEntryBlock::get_hash(this_txn, parent_id, filename).await?;

        let entry_id = Superblock::allocate_block(&mut txn).await?;
        DirEntryBlock::init_child_entry(&mut txn, parent_id, entry_id, kind, filename);
        DirEntryBlock::link_child_block(&mut txn, parent_id.block_no, entry_id.block_no, hash)
            .await?;
        DirEntryBlock::increment_dir_size(&mut txn, parent_id).await?;
        txn.commit().await?;
        Ok(entry_id)
    }

    pub async fn do_delete_entry_txn(fs: &'a mut MotorFs, entry_id: EntryIdInternal) -> Result<()> {
        log::trace!("{}:{} - delete entry: {entry_id:?}", file!(), line!());

        let mut txn = Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        DirEntryBlock::delete_entry(&mut txn, entry_id).await?;
        txn.commit().await
    }

    pub async fn do_move_entry_txn(
        fs: &'a mut MotorFs,
        entry_id: EntryIdInternal,
        old_parent_id: EntryIdInternal,
        new_parent_id: EntryIdInternal,
        new_name: &str,
    ) -> Result<()> {
        // Renaming is an atomic FS operation (both in Linux, Windows, and Rust).
        // If the target exists, it is deleted.
        log::trace!(
            "{}:{} - move entry: {old_parent_id:?} {new_parent_id:?} {new_name}",
            file!(),
            line!()
        );
        let mut txn = Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        // Delete the target entry, if present (and not empty).
        if let Some(target) = txn.fs.stat(new_parent_id.into(), new_name).await? {
            let target_id: EntryIdInternal = target.into();
            if target_id == entry_id {
                return Err(ErrorKind::InvalidInput.into());
            }
            log::debug!("move_entry: deleting target {target_id:?}");
            DirEntryBlock::delete_entry(&mut txn, target_id).await?;
        }

        // Unlink + re-link the entry record.
        {
            DirEntryBlock::unlink_entry(&mut txn, old_parent_id, entry_id, false).await?;
            // TODO: remove unsafe when NLL Problem #3 is solved.
            // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
            let this_txn = unsafe {
                let this = &mut txn as *mut Self;
                this.as_mut().unwrap_unchecked()
            };
            let hash = DirEntryBlock::get_hash(this_txn, new_parent_id, new_name).await?;
            DirEntryBlock::link_child_block(
                &mut txn,
                new_parent_id.block_no,
                entry_id.block_no,
                hash,
            )
            .await?;
            DirEntryBlock::increment_dir_size(&mut txn, new_parent_id).await?;
        }

        // Finally, update the entry record itself.
        {
            let entry_block = txn.get_txn_block(entry_id.block_no).await?;
            let entry_ref = &mut *entry_block.block_mut();

            DirEntryBlock::from_block_mut(entry_ref)
                .set_name(new_name)
                .unwrap(); // new_name has been validated => unwrap().
            DirEntryBlock::from_block_mut(entry_ref).set_parent_id(new_parent_id);
            DirEntryBlock::from_block_mut(entry_ref).set_parent_id(new_parent_id);
            DirEntryBlock::from_block_mut(entry_ref)
                .metadata_mut()
                .modified = Timestamp::now();
        }

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

        let block_key = dir_entry!(block).hash_u64(block_start);

        let prev_file_size = dir_entry!(block).metadata().size;
        let new_file_size = offset + (buf.len() as u64);

        let mut txn = Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        // Step 1: find or insert the data block.
        let data_block_no =
            match DirEntryBlock::data_block_at_key(&mut txn, file_id, block_key).await? {
                Some(block_no) => block_no,
                None => DirEntryBlock::insert_data_block(&mut txn, file_id, block_key).await?,
            };

        log::debug!(
            "write({:?}, {offset}, ...) - block no: {} block key: {block_key}",
            u128::from(file_id),
            data_block_no.as_u64()
        );

        // Step 2: update the data lock.
        let data_block = txn.get_txn_block(data_block_no).await?;
        data_block.block_mut().as_bytes_mut()
            [(offset - block_start) as usize..(new_file_size - block_start) as usize]
            .copy_from_slice(buf);

        // Step 3: update the file size & modified.
        DirEntryBlock::set_file_size_in_entry(&mut txn, file_id, prev_file_size.max(new_file_size))
            .await?;

        txn.commit().await?;

        Ok(buf.len())
    }

    pub async fn do_resize_txn(
        fs: &'a mut MotorFs,
        file_id: EntryIdInternal,
        new_size: u64,
    ) -> Result<()> {
        let block = fs
            .block_cache()
            .get_block(file_id.block_no())
            .await?
            .clone();
        dir_entry!(block).validate_entry(file_id)?;
        if dir_entry!(block).metadata().kind() != EntryKind::File {
            return Err(ErrorKind::IsADirectory.into());
        }

        let prev_size = dir_entry!(block).metadata().size;
        if new_size == prev_size {
            return Ok(());
        }
        let last_block_start = prev_size & !(BLOCK_SIZE as u64 - 1);
        let last_block_key = dir_entry!(block).hash_u64(last_block_start);

        let mut txn = Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        // The trivial case: just bump the size var.
        DirEntryBlock::set_file_size_in_entry(&mut txn, file_id, new_size).await?;
        if new_size > prev_size {
            return txn.commit().await;
        }

        // Three cases:
        // (a) truncation within the last data block, nothing to deallocate
        //     - zero out the truncated bytes
        // (b) a single (the last one) data block to deallocate
        //     - deallocate the last block
        //     - zero out truncated bytes on the new last block, if needed
        // (c) many blocks to deallocate
        //     - unlink the last data block
        //     - convert the unlinked (last) block to a TreeNodeBlock
        //     - transfer the remaining extra blocks from the file
        //       to the new TreeNodeBlock
        //     - zero out truncated bytes on the new last block, if needed

        if last_block_start < new_size {
            // Case (a): no data blocks to drop.
            let Some(data_block_no) =
                DirEntryBlock::data_block_at_key(&mut txn, file_id, last_block_key).await?
            else {
                // Nothing to see here.
                return txn.commit().await;
            };

            // Zero out truncated bytes.
            let new_end = (new_size - last_block_start) as usize;
            let old_end = (prev_size - last_block_start) as usize;
            let data_block = txn.get_txn_block(data_block_no).await?;
            data_block.block_mut().as_bytes_mut()[new_end..old_end].fill(0);

            return txn.commit().await;
        }

        if (new_size + (BLOCK_SIZE as u64)) > last_block_start {
            // Case (b): only the last block needs dropping.
            if let Some(data_block_no) =
                DirEntryBlock::data_block_at_key(&mut txn, file_id, last_block_key).await?
            {
                DirEntryBlock::unlink_child_block(
                    &mut txn,
                    file_id.block_no,
                    data_block_no,
                    last_block_key,
                )
                .await?;

                DirEntryBlock::decrement_blocks_in_use(&mut txn, file_id).await?;

                Superblock::free_single_block(&mut txn, data_block_no).await?;
            };

            // Zero out truncated bytes in the new last block.
            let last_block_start = new_size & !(BLOCK_SIZE as u64 - 1);
            let last_block_key =
                DirEntryBlock::get_hash_u64(&mut txn, file_id, last_block_start).await?;
            let Some(data_block_no) =
                DirEntryBlock::data_block_at_key(&mut txn, file_id, last_block_key).await?
            else {
                // Nothing to see here.
                return txn.commit().await;
            };

            // Zero out truncated bytes.
            let new_end = (new_size - last_block_start) as usize;
            let data_block = txn.get_txn_block(data_block_no).await?;
            data_block.block_mut().as_bytes_mut()[new_end..].fill(0);

            return txn.commit().await;
        }

        todo!("do the complicated dance");
    }
}
