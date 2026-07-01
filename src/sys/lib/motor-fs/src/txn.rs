//! Each moderately complex FS operation is a transaction.
//!
//! Mutating transactions:
//! - create entry
//! - delete entry
//! - move entry
//! - write to file
//! - set file size
//!
//! How transactions work:
//! - all transactions have a counter;
//! - there there are two write-ahead areas to write ahead transactions
//! - each transaction has a transaction header: basically block #0 (superblock)
//!   with the current transaction ID with the list of blocks modified by this
//!   transaction
//! - on commit block #0 with the transaction header is written to the transaction
//!   area; then the remaining dirty blocks are written after it
//! - at this point the transaction returns, with an async flusher
//!   flushing the blocks into their normal places
//! - this async flusher is different from the async flusher the block cache
//!   uses to track completions

use crate::{
    BlockNo, DirEntryBlock, EntryIdInternal, INLINE_CAPACITY, INLINE_DATA_OFFSET,
    MAX_BLOCKS_IN_TXN, MotorFs, Superblock, dir_entry,
};
use async_fs::{
    AsyncBlockDevice, BLOCK_SIZE, EntryKind, FileSystem, Timestamp,
    block_cache::{BlockCache, CachedBlock},
};
use std::io::{ErrorKind, Result};

/// Max number of blocks a single transaction may touch.
const TXN_CACHE_SIZE: usize = 16;

#[cfg(test)]
thread_local! {
    /// Test hook: caps how many `truncate_right_txn` levels
    /// [`Txn::do_large_truncate`] runs before bailing out early, simulating a
    /// crash partway through a large truncation. `usize::MAX` (the default)
    /// means "run to completion".
    pub(crate) static TRUNCATE_MAX_STEPS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(usize::MAX) };
}

/// The transaction object: accumulates "dirty" blocks, then either discards
/// them on error (so no changes to the underlying FS happen) or applies them
/// "atomically", i.e. either all or nothing.
pub struct Txn<'a, BD: AsyncBlockDevice + 'static> {
    fs: &'a mut MotorFs<BD>,
    txn_cache: micromap::Map<BlockNo, CachedBlock, TXN_CACHE_SIZE>,
    read_only: bool,
}

impl<'a, BD: AsyncBlockDevice + 'static> Drop for Txn<'a, BD> {
    fn drop(&mut self) {
        for (block_no, block) in self.txn_cache.drain() {
            assert_eq!(block_no.as_u64(), block.block_no());
            if block.is_dirty() {
                assert!(!self.read_only);
                log::warn!("Dirty block {} on txn drop.", block_no.as_u64());
                block.discard_dirty();
            }
        }

        #[cfg(debug_assertions)]
        self.block_cache().debug_check_clean();
    }
}

impl<'a, BD: AsyncBlockDevice + 'static> Txn<'a, BD> {
    fn block_cache(&mut self) -> &mut BlockCache<BD> {
        self.fs.block_cache()
    }

    async fn commit(mut self) -> Result<()> {
        log::trace!("{}:{} do a proper txn", file!(), line!());

        let Txn {
            ref mut fs,
            ref mut txn_cache,
            read_only,
        } = self;

        assert!(!read_only);

        let mut txn_blocks: [Option<(BlockNo, CachedBlock)>; MAX_BLOCKS_IN_TXN] =
            [const { None }; MAX_BLOCKS_IN_TXN];
        let mut next_idx = 0;

        // Collect dirty blocks.
        for (block_no, block) in txn_cache.drain() {
            debug_assert_eq!(block_no.as_u64(), block.block_no());
            if block.is_dirty() {
                txn_blocks[next_idx] = Some((block_no, block));
                next_idx += 1;
            }
        }

        fs.log_txn(txn_blocks).await
    }

    pub fn new_readonly(fs: &'a mut MotorFs<BD>) -> Self {
        Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: true,
        }
    }

    /// Unlike get_block() above, get_txn_block() ensures the block is part of the transaction,
    /// i.e. will be saved in Txn::commit().
    pub async fn get_block(&mut self, block_no: BlockNo) -> std::io::Result<CachedBlock> {
        if let Some(block) = self.txn_cache.get(&block_no) {
            return Ok(block.clone());
        }

        let block = self.block_cache().get_block(block_no.as_u64()).await?;
        self.txn_cache.insert(block_no, block.clone());

        Ok(block)
    }

    /// Reads a block via the underlying block cache *without* registering it in
    /// the transaction. Use only for read-only tree walks where the block is
    /// not modified: tracked reads accumulate in `txn_cache`, which is bounded,
    /// so a walk that may visit many nodes must not use [`Self::get_block`].
    pub async fn get_block_untracked(&mut self, block_no: BlockNo) -> std::io::Result<CachedBlock> {
        self.block_cache().get_block(block_no.as_u64()).await
    }

    pub fn get_empty_block_mut(&mut self, block_no: BlockNo) -> CachedBlock {
        assert!(!self.read_only);

        if let Some(txn_block) = self.txn_cache.get_mut(&block_no) {
            txn_block.block_mut().clear();
            return txn_block.clone();
        }

        let block = self.block_cache().get_empty_block(block_no.as_u64());
        self.txn_cache.insert(block_no, block.clone());

        block
    }

    pub async fn do_create_entry_txn(
        fs: &'a mut MotorFs<BD>,
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

        let hash = DirEntryBlock::get_hash(&mut txn, parent_id, filename).await?;

        let entry_id = Superblock::allocate_block(&mut txn).await?;
        DirEntryBlock::init_child_entry(&mut txn, parent_id, entry_id, kind, filename);
        DirEntryBlock::link_child_block(&mut txn, parent_id.block_no, entry_id.block_no, hash)
            .await?;
        DirEntryBlock::increment_dir_size(&mut txn, parent_id).await?;
        txn.commit().await?;
        Ok(entry_id)
    }

    pub async fn do_delete_entry_txn(
        fs: &'a mut MotorFs<BD>,
        entry_id: EntryIdInternal,
    ) -> Result<()> {
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
        fs: &'a mut MotorFs<BD>,
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
        if let Some((target, _)) = txn.fs.stat(async_fs::Role::System, new_parent_id.into(), new_name).await? {
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
            let hash = DirEntryBlock::get_hash(&mut txn, new_parent_id, new_name).await?;
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
            let mut entry_block = txn.get_block(entry_id.block_no).await?;
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
        fs: &'a mut MotorFs<BD>,
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

        let block = fs.block_cache().get_block(file_id.block_no()).await?;
        dir_entry!(block).validate_entry(file_id)?;
        if dir_entry!(block).metadata().kind() != EntryKind::File {
            return Err(ErrorKind::IsADirectory.into());
        }
        let prev_file_size = dir_entry!(block).metadata().size;
        drop(block);

        let block_key = block_start / (BLOCK_SIZE as u64);
        let new_file_size = offset + (buf.len() as u64);
        let final_size = prev_file_size.max(new_file_size);

        let mut txn = Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        // Inline path: the file fits in its entry block both before and after the
        // write, so the data lives in the entry block, not a tree.
        if final_size <= INLINE_CAPACITY {
            {
                let mut entry_block = txn.get_block(file_id.block_no).await?;
                let mut entry_ref = entry_block.block_mut();
                let bytes = entry_ref.as_bytes_mut();
                // A write starting past the current end leaves a hole; zero it.
                if offset > prev_file_size {
                    bytes[INLINE_DATA_OFFSET + prev_file_size as usize
                        ..INLINE_DATA_OFFSET + offset as usize]
                        .fill(0);
                }
                bytes[INLINE_DATA_OFFSET + offset as usize
                    ..INLINE_DATA_OFFSET + new_file_size as usize]
                    .copy_from_slice(buf);
            }
            DirEntryBlock::set_file_size_in_entry(&mut txn, file_id.block_no, final_size).await?;
            txn.commit().await?;
            return Ok(buf.len());
        }

        // Tree path. If the file is currently inline, migrate it to a tree first.
        if prev_file_size <= INLINE_CAPACITY {
            DirEntryBlock::convert_inline_to_tree(&mut txn, file_id, prev_file_size).await?;
        }

        // Step 1: find or insert the data block.
        let data_block_no =
            match DirEntryBlock::data_block_at_key(&mut txn, file_id.block_no, block_key).await? {
                Some(block_no) => block_no,
                None => DirEntryBlock::insert_data_block(&mut txn, file_id, block_key).await?,
            };

        // Step 2: update the data block.
        let mut data_block = txn.get_block(data_block_no).await?;
        data_block.block_mut().as_bytes_mut()
            [(offset - block_start) as usize..(new_file_size - block_start) as usize]
            .copy_from_slice(buf);

        // Step 3: update the file size & modified.
        DirEntryBlock::set_file_size_in_entry(&mut txn, file_id.block_no, final_size).await?;

        txn.commit().await?;

        Ok(buf.len())
    }

    pub async fn do_resize_txn(
        fs: &'a mut MotorFs<BD>,
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
        drop(block);
        if new_size == prev_size {
            return Ok(());
        }

        // Storage is size-based: a file is inline iff its size is <=
        // INLINE_CAPACITY. A resize must keep that invariant, migrating between
        // inline and tree storage as the size crosses the cutoff.
        match (prev_size <= INLINE_CAPACITY, new_size <= INLINE_CAPACITY) {
            (true, true) => Self::resize_inline(fs, file_id, prev_size, new_size).await,
            (true, false) => Self::grow_inline_to_tree(fs, file_id, prev_size, new_size).await,
            (false, true) => Self::shrink_tree_to_inline(fs, file_id, prev_size, new_size).await,
            (false, false) => Self::resize_tree(fs, file_id, prev_size, new_size).await,
        }
    }

    /// Resizes a file that stays inline (both sizes <= INLINE_CAPACITY): only the
    /// entry block changes. Bytes that leave the file (shrink) or become a newly
    /// exposed hole (grow) are zeroed, then the size is recorded.
    async fn resize_inline(
        fs: &mut MotorFs<BD>,
        file_id: EntryIdInternal,
        prev_size: u64,
        new_size: u64,
    ) -> Result<()> {
        let mut txn = Txn {
            fs: &mut *fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };
        {
            let mut entry_block = txn.get_block(file_id.block_no).await?;
            let mut entry_ref = entry_block.block_mut();
            let bytes = entry_ref.as_bytes_mut();
            let lo = prev_size.min(new_size) as usize;
            let hi = prev_size.max(new_size) as usize;
            bytes[INLINE_DATA_OFFSET + lo..INLINE_DATA_OFFSET + hi].fill(0);
        }
        DirEntryBlock::set_file_size_in_entry(&mut txn, file_id.block_no, new_size).await?;
        txn.commit().await
    }

    /// Grows a file from inline storage past INLINE_CAPACITY: migrates the inline
    /// bytes into a tree, then records the larger (sparse) size.
    async fn grow_inline_to_tree(
        fs: &mut MotorFs<BD>,
        file_id: EntryIdInternal,
        prev_size: u64,
        new_size: u64,
    ) -> Result<()> {
        let mut txn = Txn {
            fs: &mut *fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };
        DirEntryBlock::convert_inline_to_tree(&mut txn, file_id, prev_size).await?;
        DirEntryBlock::set_file_size_in_entry(&mut txn, file_id.block_no, new_size).await?;
        txn.commit().await
    }

    /// Shrinks a file from tree storage down to inline (`new_size <=
    /// INLINE_CAPACITY < prev_size`). The surviving bytes `[0, new_size)` stay
    /// reachable at every committed step:
    ///
    /// - Phase 1 reduces the tree to a single data block (key 0) via the ordinary
    ///   truncation, with the recorded size held at `BLOCK_SIZE` -- still above
    ///   `INLINE_CAPACITY`, so the size-based invariant holds at every commit and
    ///   a crash leaves a valid (larger) tree file, never lost data.
    /// - Phase 2 atomically collapses that single block into inline storage.
    async fn shrink_tree_to_inline(
        fs: &mut MotorFs<BD>,
        file_id: EntryIdInternal,
        prev_size: u64,
        new_size: u64,
    ) -> Result<()> {
        // Truncate-to-empty is special: the ordinary truncation chops every child
        // of the root in a single transaction (cut == 0), flipping the entry
        // straight from a populated tree to an empty (size 0, hence inline) file.
        // No intermediate committed state has size <= cap with a populated tree,
        // and it walks nothing -- so do it directly.
        if new_size == 0 {
            return Self::resize_tree(fs, file_id, prev_size, 0).await;
        }

        // Phase 1: drop everything above the first data block, if there is more
        // than one block. The intermediate size (BLOCK_SIZE) stays above the
        // cutoff, so the file remains a valid tree at the commit boundary and a
        // crash leaves the surviving bytes [0, new_size) intact.
        if prev_size > BLOCK_SIZE as u64 {
            Self::resize_tree(fs, file_id, prev_size, BLOCK_SIZE as u64).await?;
        }
        // Phase 2: atomic collapse to inline.
        Self::collapse_to_inline(fs, file_id, new_size).await
    }

    /// Atomically collapses a file spanning at most one data block (key 0) into
    /// inline storage of `new_size` bytes. It reads the surviving `[0, new_size)`
    /// bytes, frees the whole (small) sub-tree, and rewrites the entry inline --
    /// all in one transaction, so a crash leaves the file either fully tree (old
    /// size) or fully inline (`new_size`), never torn.
    async fn collapse_to_inline(
        fs: &mut MotorFs<BD>,
        file_id: EntryIdInternal,
        new_size: u64,
    ) -> Result<()> {
        let mut txn = Txn {
            fs: &mut *fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        // The surviving bytes: data block key 0, or zeros if it is a hole.
        let mut data = vec![0u8; new_size as usize];
        if let Some(block0) =
            DirEntryBlock::data_block_at_key(&mut txn, file_id.block_no, 0).await?
        {
            let block = txn.get_block(block0).await?;
            data.copy_from_slice(&block.block().as_bytes()[..new_size as usize]);
        }

        // Every block below the root (the thin spine plus data block 0). The file
        // spans at most one data block here, so this is at most a few blocks.
        let mut to_free: Vec<BlockNo> = Vec::new();
        crate::bplus_tree::RootNode::collect_blocks_below(&mut txn, file_id.block_no, &mut to_free)
            .await?;
        let freed_count = to_free.len() as u64;
        debug_assert!(
            freed_count < MAX_BLOCKS_IN_TXN as u64,
            "collapse_to_inline: sub-tree too large: {freed_count}"
        );

        // Rewrite the entry as inline: clear the data region and lay down the
        // surviving bytes (the old tree root lived in this region).
        {
            let mut entry_block = txn.get_block(file_id.block_no).await?;
            let mut entry_ref = entry_block.block_mut();
            let bytes = entry_ref.as_bytes_mut();
            bytes[INLINE_DATA_OFFSET..].fill(0);
            bytes[INLINE_DATA_OFFSET..INLINE_DATA_OFFSET + new_size as usize]
                .copy_from_slice(&data);
        }
        // The file now occupies just its entry block.
        DirEntryBlock::set_file_size_in_entry(&mut txn, file_id.block_no, new_size).await?;
        if freed_count > 0 {
            DirEntryBlock::decrement_blocks_in_use(&mut txn, file_id.block_no, freed_count).await?;
        }

        // Free the now-detached sub-tree blocks.
        for block_no in to_free {
            Superblock::free_single_block(&mut txn, block_no).await?;
        }

        txn.commit().await
    }

    /// Resizes a file that stays in B+ tree storage. Both the old and new sizes
    /// are above `INLINE_CAPACITY` (or `new_size == BLOCK_SIZE`, the intermediate
    /// used by [`Self::shrink_tree_to_inline`]), so the file is and remains a tree.
    async fn resize_tree(
        fs: &mut MotorFs<BD>,
        file_id: EntryIdInternal,
        prev_size: u64,
        new_size: u64,
    ) -> Result<()> {
        let last_block_start = prev_size & !(BLOCK_SIZE as u64 - 1);
        let last_block_key = last_block_start / (BLOCK_SIZE as u64);

        // Case (c): a truncation that drops more than one data block (i.e. the
        // last surviving block starts at least a full block below the old last
        // block). The tree may be up to four levels deep and a single txn may
        // only touch a bounded number of blocks, so this is done across several
        // transactions and is handled separately, before the single-txn cases.
        if new_size < prev_size && (new_size + (BLOCK_SIZE as u64)) <= last_block_start {
            return Self::do_large_truncate(fs, file_id, new_size).await;
        }

        let mut txn = Txn {
            fs: &mut *fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        DirEntryBlock::set_file_size_in_entry(&mut txn, file_id.block_no, new_size).await?;

        // The trivial case: just bump the size var.
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
        //     - handled by do_large_truncate above

        if last_block_start < new_size {
            // Case (a): no data blocks to drop.
            let Some(data_block_no) =
                DirEntryBlock::data_block_at_key(&mut txn, file_id.block_no, last_block_key)
                    .await?
            else {
                // Nothing to see here.
                return txn.commit().await;
            };

            // Zero out truncated bytes.
            let new_end = (new_size - last_block_start) as usize;
            let old_end = (prev_size - last_block_start) as usize;
            let mut data_block = txn.get_block(data_block_no).await?;
            data_block.block_mut().as_bytes_mut()[new_end..old_end].fill(0);

            return txn.commit().await;
        }

        if (new_size + (BLOCK_SIZE as u64)) > last_block_start {
            // Case (b): only the last block needs dropping.
            if let Some(data_block_no) =
                DirEntryBlock::data_block_at_key(&mut txn, file_id.block_no, last_block_key).await?
            {
                DirEntryBlock::unlink_child_block(
                    &mut txn,
                    file_id.block_no,
                    data_block_no,
                    last_block_key,
                )
                .await?;

                DirEntryBlock::decrement_blocks_in_use(&mut txn, file_id.block_no, 1).await?;
                Superblock::free_single_block(&mut txn, data_block_no).await?;
            };

            // Zero out truncated bytes in the new last block.
            let last_block_start = new_size & !(BLOCK_SIZE as u64 - 1);
            let last_block_key = last_block_start / (BLOCK_SIZE as u64);
            let Some(data_block_no) =
                DirEntryBlock::data_block_at_key(&mut txn, file_id.block_no, last_block_key)
                    .await?
            else {
                // Nothing to see here.
                return txn.commit().await;
            };

            // Zero out truncated bytes.
            let new_end = (new_size - last_block_start) as usize;
            let mut data_block = txn.get_block(data_block_no).await?;
            data_block.block_mut().as_bytes_mut()[new_end..].fill(0);

            return txn.commit().await;
        }

        // Every shrink case that reaches here was handled above, and case (c)
        // returned early, so this point is unreachable.
        log::error!("resize_tree: unexpected fall-through");
        Err(ErrorKind::InvalidInput.into())
    }

    /// Handles a truncation that drops more than one data block (resize case (c)).
    ///
    /// The B+ tree is at most four levels deep, and a single transaction may only
    /// touch a bounded number of blocks, so the right-most stale branches are
    /// chopped off one tree level per transaction, walking from the root down to
    /// the data (leaf) level.
    ///
    /// The recorded file size is *not* set to `new_size` up front: instead each
    /// chopping transaction lowers it in step with the branches it removes (see
    /// `truncate_right`), and the exact `new_size` is pinned at the very end.
    /// This keeps the recorded size from ever sitting below the file's surviving
    /// extent at a committed step, so a crash mid-truncation can never leave
    /// stale data blocks reachable above EOF (which would otherwise resurface,
    /// un-zeroed, when the file is later grown again).
    async fn do_large_truncate(
        fs: &mut MotorFs<BD>,
        file_id: EntryIdInternal,
        new_size: u64,
    ) -> Result<()> {
        // Every block whose key is at or above this holds only data above new_size.
        let first_stale_key = new_size.div_ceil(BLOCK_SIZE as u64);

        // Seed the root's subtree total from the file's maintained block count:
        // every block the file occupies except the entry block itself sits below
        // the root node. This lets truncate_right count chopped blocks by
        // subtraction instead of walking the whole chopped-off forest.
        let blocks_below_root = {
            let entry_block = fs.block_cache().get_block(file_id.block_no()).await?;
            let total = DirEntryBlock::from_block(&entry_block.block()).blocks_in_use();
            total - 1
        };

        // Chop the right-most stale branches level by level, root first. The tree
        // is at most four levels deep, so at most four iterations are needed; the
        // last one chops off data blocks, completing the resize.
        let mut node_block_no = file_id.block_no;
        let mut is_root = true;
        let mut subtree_total = Some(blocks_below_root);
        for _step in 0..4 {
            #[cfg(test)]
            if _step >= TRUNCATE_MAX_STEPS.with(|c| c.get()) {
                // Test hook: bail out as if the machine crashed mid-truncation.
                return Ok(());
            }
            match Self::truncate_right_txn(
                &mut *fs,
                file_id.block_no,
                node_block_no,
                is_root,
                first_stale_key,
                subtree_total,
            )
            .await?
            {
                Some((child, child_total)) => {
                    node_block_no = child;
                    is_root = false;
                    subtree_total = child_total;
                }
                None => break,
            }
        }

        // Final transaction: pin the recorded size to exactly new_size and, if
        // new_size is not block-aligned, zero out the stale tail of the last
        // surviving data block. The size is set unconditionally here (not only in
        // the unaligned case) so that the aligned and sparse paths also land on
        // exactly new_size regardless of how far the per-level shrinking above
        // got.
        let mut txn = Txn {
            fs: &mut *fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };
        DirEntryBlock::set_file_size_in_entry(&mut txn, file_id.block_no, new_size).await?;
        if new_size & (BLOCK_SIZE as u64 - 1) != 0 {
            let last_block_start = new_size & !(BLOCK_SIZE as u64 - 1);
            let last_block_key = last_block_start / (BLOCK_SIZE as u64);

            if let Some(data_block_no) =
                DirEntryBlock::data_block_at_key(&mut txn, file_id.block_no, last_block_key).await?
            {
                let new_end = (new_size - last_block_start) as usize;
                let mut data_block = txn.get_block(data_block_no).await?;
                data_block.block_mut().as_bytes_mut()[new_end..].fill(0);
            }
        }
        txn.commit().await
    }

    /// Chops off the right-most stale branches at a single tree level, in one
    /// transaction. `subtree_total` is the number of blocks below `node_block_no`,
    /// when known (see [`crate::bplus_tree::Node::truncate_right`]). Returns the
    /// next node to process (the right-most surviving child) and its own subtree
    /// total, or `None` once the data (leaf) level has been reached.
    async fn truncate_right_txn(
        fs: &mut MotorFs<BD>,
        file_block_no: BlockNo,
        node_block_no: BlockNo,
        is_root: bool,
        first_stale_key: u64,
        subtree_total: Option<u64>,
    ) -> Result<Option<(BlockNo, Option<u64>)>> {
        let mut txn = Txn {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        let next = if is_root {
            crate::bplus_tree::RootNode::truncate_right(
                &mut txn,
                node_block_no,
                file_block_no,
                first_stale_key,
                subtree_total,
            )
            .await?
        } else {
            crate::bplus_tree::NonRootNode::truncate_right(
                &mut txn,
                node_block_no,
                file_block_no,
                first_stale_key,
                subtree_total,
            )
            .await?
        };

        txn.commit().await?;
        Ok(next)
    }

    #[cfg(test)]
    pub async fn test_remove_block_txn(
        fs: &'a mut MotorFs<BD>,
        file_id: EntryIdInternal,
        offset: u64,
    ) -> Result<()> {
        assert_eq!(0, offset & (BLOCK_SIZE as u64 - 1));

        let block_key = offset / (BLOCK_SIZE as u64);

        let mut txn = Self {
            fs,
            txn_cache: micromap::Map::new(),
            read_only: false,
        };

        // let data_block_no = DirEntryBlock::data_block_at_key(&mut txn, file_id.block_no, block_key)
        //     .await?
        //     .expect(format!("data block at {block_key} not found").as_str());

        let Some(data_block_no) =
            DirEntryBlock::data_block_at_key(&mut txn, file_id.block_no, block_key).await?
        else {
            log::error!("\n\n data block for key {block_key} not found!\n\n");
            crate::bplus_tree::RootNode::test_log_tree(&mut txn, file_id.block_no).await?;
            panic!("\n\n");
        };
        let sb_block = txn.get_block(BlockNo::from_u64(0)).await?;
        let free_blocks_prev = sb_block
            .block()
            .get_at_offset::<Superblock>(0)
            .free_blocks();

        DirEntryBlock::unlink_child_block(&mut txn, file_id.block_no, data_block_no, block_key)
            .await?;

        let free_blocks_now = sb_block
            .block()
            .get_at_offset::<Superblock>(0)
            .free_blocks();

        DirEntryBlock::decrement_blocks_in_use(
            &mut txn,
            file_id.block_no,
            free_blocks_now - free_blocks_prev + 1,
        )
        .await?;

        Superblock::free_single_block(&mut txn, data_block_no).await?;

        // log::debug!("removed block {block_key}");
        // crate::bplus_tree::RootNode::test_log_tree(&mut txn, file_id.block_no).await?;

        txn.commit().await
    }
}
