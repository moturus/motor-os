// Filesystem. The API is biased for convenience, which in practical terms
// means that there is a single mutable object representing the filesystem,
// and the rest are immutable clone-able and copy-able that do not borrow.
// This makes dealing with the borrow checker trivial.

use core::ptr::copy_nonoverlapping;
use std::io::ErrorKind;

use async_fs::{BLOCK_SIZE, Block};

use crate::block_cache::BlockCache;

use super::*;

pub(crate) fn format(block_device: &mut dyn SyncBlockDevice) -> Result<()> {
    let num_blocks = block_device.num_blocks();
    if num_blocks < 2 {
        return Err(ErrorKind::InvalidInput.into());
    }

    // We use u64::MAX as a marker for None.
    let num_blocks = num_blocks.min(u64::MAX - 1);

    // Write the first block.
    let mut block = Block::new_zeroed();
    let fbh = block.get_mut_at_offset::<SuperblockHeader>(0);
    fbh.magic = MAGIC;
    fbh.version = 1;
    fbh.num_blocks = num_blocks;
    fbh.free_blocks = num_blocks - 2;
    fbh.generation = 1;
    fbh.empty_area_start = 2; // 0 => this; 1 => root dir.
    fbh.set_crc32();
    fbh.validate()?;

    block_device.write_block(0, block.as_bytes())?;

    // Write the root directory.
    let root_dir = block.get_mut_at_offset::<EntryMetadata>(0);
    *root_dir = EntryMetadata::new(ROOT_DIR_ID, ROOT_DIR_ID);
    root_dir.set_crc32();

    block_device.write_block(1, block.as_bytes())?;

    Ok(())
}

#[derive(Debug)]
enum BlockType {
    Metadata,
    Data,
    Links,
    ListOfLinks,
}

pub struct SyncFileSystem {
    blockcache: BlockCache,
    num_blocks: u64,
    error: Result<()>, // If set, the FS is corrupted and cannot be used.
}

impl SyncFileSystem {
    pub const fn root_dir_id() -> EntryId {
        ROOT_DIR_ID
    }

    pub fn num_blocks(&self) -> u64 {
        self.num_blocks
    }

    fn superblock_header(&mut self) -> &SuperblockHeader {
        self.blockcache
            .read(0)
            .unwrap()
            .block()
            .get_at_offset::<SuperblockHeader>(0)
    }

    pub fn empty_blocks(&mut self) -> u64 {
        self.superblock_header().free_blocks
    }

    pub fn open_fs(mut block_device: Box<dyn SyncBlockDevice>) -> Result<Self> {
        let mut block = Block::new_zeroed();
        block_device.read_block(0, block.as_bytes_mut())?;
        let fbh = block.get_at_offset::<SuperblockHeader>(0);
        fbh.validate()?;

        let num_blocks = fbh.num_blocks;
        if num_blocks < 3 || num_blocks == u64::MAX || num_blocks > block_device.num_blocks() {
            return Err(ErrorKind::InvalidInput.into());
        }

        if fbh.txn_meta_block != 0
            || fbh.txn_data_block != 0
            || fbh.txn_link_block != 0
            || fbh.txn_list_of_links_block != 0
        {
            todo!("roll back or commit the TXN")
        }

        Ok(Self {
            num_blocks,
            blockcache: BlockCache::new(block_device),
            error: Ok(()),
        })
    }

    /// Create a new file.
    pub fn add_file(&mut self, parent_id: EntryId, name: &str) -> Result<EntryId> {
        self.add_directory_entry(parent_id, name, true)
    }

    /// Create a new directory.
    pub fn add_directory(&mut self, parent_id: EntryId, name: &str) -> Result<EntryId> {
        self.add_directory_entry(parent_id, name, false)
    }

    fn check_error(&self) -> Result<()> {
        if let Err(err) = &self.error {
            Err(err.kind().into())
        } else {
            Ok(())
        }
    }

    fn validate_new_entry(&mut self, parent_id: EntryId, name: &str) -> Result<()> {
        self.check_error()?;

        validate_filename(name)?;
        if parent_id.block_no >= self.num_blocks || parent_id.block_no < 1 {
            return Err(ErrorKind::InvalidInput.into());
        }
        if self.find_entry_by_name(parent_id, name).is_ok() {
            return Err(ErrorKind::AlreadyExists.into());
        }

        let parent_block = self.blockcache.read(parent_id.block_no)?;
        let meta = parent_block.block().get_at_offset::<EntryMetadata>(0);
        meta.validate_dir(parent_id)?;
        if meta.size == MAX_DIR_ENTRIES {
            return Err(ErrorKind::FileTooLarge.into());
        }

        Ok(())
    }

    // Must be inside a transaction. Inner => no need to poison self.
    fn add_directory_entry_inner(
        &mut self,
        parent_id: EntryId,
        child_id: EntryId,
        child_name: &str,
    ) -> Result<()> {
        // let sbh = self.superblock.header();
        // assert_ne!(TXN_TYPE_NONE, sbh.txn_type);
        let parent_block = self.blockcache.get(parent_id.block_no);
        let meta = parent_block.block().get_at_offset::<EntryMetadata>(0);
        let prev_size = meta.size;

        // Update the parent dir.
        if prev_size < MAX_ENTRIES_IN_META_BLOCK {
            // Stick the new block entry into the meta block.
            let parent_block = self.blockcache.get_mut(parent_id.block_no);
            let meta = parent_block
                .block_mut()
                .get_mut_at_offset::<EntryMetadata>(0);
            meta.size += 1;
            meta.set_crc32();

            block_set_dir_entry(
                parent_block.block_mut(),
                (prev_size + 1) as usize,
                child_id,
                child_name,
            );
            self.blockcache.write(parent_id.block_no)?;
        } else if prev_size < MAX_ENTRIES_ONLY_DATA_BLOCKS {
            let need_new_block = prev_size == MAX_ENTRIES_IN_META_BLOCK
                || prev_size.is_multiple_of(MAX_ENTRIES_IN_DATA_BLOCK);
            if need_new_block {
                // Allocate a new data block.
                let data_block_no = self.allocate_txn_block(BlockType::Data)?;

                // Write the new data block.
                if prev_size == MAX_ENTRIES_IN_META_BLOCK {
                    let source_block_addr =
                        self.blockcache.get(parent_id.block_no).block() as *const Block as usize;
                    let data_block = self.blockcache.get_block_uninit(data_block_no);
                    for idx in 0..(MAX_ENTRIES_IN_META_BLOCK as usize) {
                        let source_block =
                            unsafe { (source_block_addr as *const Block).as_ref().unwrap() };

                        *block_get_dir_entry_mut(data_block.block_mut(), idx) =
                            *block_get_dir_entry(source_block, idx + 1);
                    }

                    block_set_dir_entry(
                        data_block.block_mut(),
                        MAX_ENTRIES_IN_META_BLOCK as usize,
                        child_id,
                        child_name,
                    );
                } else {
                    let data_block = self.blockcache.get_block_uninit(data_block_no);
                    block_set_dir_entry(data_block.block_mut(), 0, child_id, child_name);
                }
                self.blockcache.write(data_block_no)?;

                // Update the parent.
                let parent_block = self.blockcache.get_mut(parent_id.block_no);
                let meta = parent_block
                    .block_mut()
                    .get_mut_at_offset::<EntryMetadata>(0);
                meta.size += 1;
                meta.set_crc32();

                block_set_datablock_no_in_meta(
                    parent_block.block_mut(),
                    prev_size / MAX_ENTRIES_IN_DATA_BLOCK,
                    data_block_no,
                );
                self.blockcache.write(parent_id.block_no)?;
            } else {
                // Update an existing data block.
                let data_block_idx = prev_size / MAX_ENTRIES_IN_DATA_BLOCK;
                let parent_block = self.blockcache.get(parent_id.block_no);
                let data_block_no =
                    block_get_datablock_no_in_meta(parent_block.block(), data_block_idx);
                let data_block = self.blockcache.read_mut(data_block_no)?;
                block_set_dir_entry(
                    data_block.block_mut(),
                    (prev_size % MAX_ENTRIES_IN_DATA_BLOCK) as usize,
                    child_id,
                    child_name,
                );
                self.blockcache.write(data_block_no)?;
                self.plus_one(parent_id.block_no)?;
            }
        } else {
            let need_new_data_block = prev_size.is_multiple_of(MAX_ENTRIES_IN_DATA_BLOCK);
            let need_new_list_block = prev_size == MAX_ENTRIES_ONLY_DATA_BLOCKS
                || prev_size.is_multiple_of(MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST);

            if need_new_data_block {
                // Allocate a new data block.
                let data_block_no = self.allocate_txn_block(BlockType::Data)?;
                let data_block = self.blockcache.get_block_uninit(data_block_no);
                block_set_dir_entry(data_block.block_mut(), 0, child_id, child_name);
                self.blockcache.write(data_block_no)?;

                if need_new_list_block {
                    let link_block_no = self.allocate_txn_block(BlockType::Links)?;
                    if prev_size == MAX_ENTRIES_ONLY_DATA_BLOCKS {
                        let source_block_addr = self.blockcache.get(parent_id.block_no).block()
                            as *const Block
                            as usize;
                        let link_block = self.blockcache.get_block_uninit(link_block_no);
                        for idx in 0..MAX_LINKS_IN_META_BLOCK {
                            let source_block =
                                unsafe { (source_block_addr as *const Block).as_ref().unwrap() };

                            block_set_datablock_no_in_link(
                                link_block.block_mut(),
                                idx,
                                block_get_datablock_no_in_meta(source_block, idx),
                            );
                        }

                        block_set_datablock_no_in_link(
                            link_block.block_mut(),
                            MAX_LINKS_IN_META_BLOCK,
                            data_block_no,
                        );
                    } else {
                        let link_block = self.blockcache.get_block_uninit(link_block_no);
                        block_set_datablock_no_in_link(link_block.block_mut(), 0, data_block_no);
                    }
                    self.blockcache.write(link_block_no)?;
                    // Update the parent.
                    let parent_block = self.blockcache.get_mut(parent_id.block_no);
                    let meta = parent_block
                        .block_mut()
                        .get_mut_at_offset::<EntryMetadata>(0);
                    meta.size += 1;
                    meta.set_crc32();
                    block_set_datablock_no_in_meta(
                        parent_block.block_mut(),
                        prev_size / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST,
                        link_block_no,
                    );
                    self.blockcache.write(parent_id.block_no)?;
                } else {
                    // Update the link block.
                    let link_block_idx = prev_size / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST;
                    let parent_block = self.blockcache.get(parent_id.block_no);
                    let link_block_no =
                        block_get_datablock_no_in_meta(parent_block.block(), link_block_idx);
                    let link_block = self.blockcache.read_mut(link_block_no)?;
                    let data_block_idx = (prev_size % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST)
                        / MAX_ENTRIES_IN_DATA_BLOCK;
                    block_set_datablock_no_in_link(
                        link_block.block_mut(),
                        data_block_idx,
                        data_block_no,
                    );
                    self.blockcache.write(link_block_no)?;
                    self.plus_one(parent_id.block_no)?;
                }
            } else {
                // Update an existing data block.
                let link_block_idx = prev_size / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST;
                let parent_block = self.blockcache.get(parent_id.block_no);
                let link_block_no =
                    block_get_datablock_no_in_meta(parent_block.block(), link_block_idx);
                let link_block = self.blockcache.read(link_block_no)?;
                let data_block_idx = (prev_size % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST)
                    / MAX_ENTRIES_IN_DATA_BLOCK;
                let data_block_no =
                    block_get_datablock_no_in_link(link_block.block(), data_block_idx);

                let data_block = self.blockcache.read_mut(data_block_no)?;
                block_set_dir_entry(
                    data_block.block_mut(),
                    (prev_size % MAX_ENTRIES_IN_DATA_BLOCK) as usize,
                    child_id,
                    child_name,
                );
                self.blockcache.write(data_block_no)?;
                self.plus_one(parent_id.block_no)?;
            }
        }

        Ok(())
    }

    fn add_directory_entry(
        &mut self,
        parent_id: EntryId,
        name: &str,
        is_file: bool,
    ) -> Result<EntryId> {
        self.check_error()?;
        self.validate_new_entry(parent_id, name)?;

        // Steps:
        // - get a free block
        // - write the new EntryMetadata into it; (crash here: whatever)
        // - mark the block as busy in the parent dir; (crash here: check the parent dir upon bootup)
        // - add the block to the parent dir; (crash here: check the parent dir upon bootup)
        // - commit: clear the busy block.

        // Get a new generation (no save).
        let block = self.blockcache.get_mut(0);
        let sbh = block.block_mut().get_mut_at_offset::<SuperblockHeader>(0);

        let mut generation = sbh.generation + 1;
        if is_file && ((generation & 1) == 1) {
            generation += 1; // Files must have EVEN generations.
        }
        if (!is_file) && ((generation & 1) == 0) {
            generation += 1; // Directories must have ODD generations.
        }

        sbh.generation = generation;
        self.start_txn(TXN_TYPE_ADD_NODE, parent_id)?;

        // Get a new block.
        let block_no = self.allocate_txn_block(BlockType::Metadata)?;

        // Write the new block.
        let new_id = EntryId::new(block_no, generation);
        let meta_block = self.blockcache.get_block_uninit(block_no);
        let meta = meta_block.block_mut().get_mut_at_offset::<EntryMetadata>(0);
        *meta = EntryMetadata::new(new_id, parent_id);
        meta.size = 0;
        meta.set_crc32();
        self.blockcache.write(block_no)?;

        self.add_directory_entry_inner(parent_id, new_id, name)
            .inspect_err(|_| {
                let _ = self.make_error();
            })?;

        // Commit.
        self.commit_txn()?;
        Ok(new_id)
    }

    /// Get a specific directory entry (child).
    pub fn get_directory_entry(&mut self, parent: EntryId, pos: u64) -> Result<DirEntry> {
        self.check_error()?;
        let parent_block = self.blockcache.read(parent.block_no)?;
        let meta = parent_block.block().get_at_offset::<EntryMetadata>(0);
        meta.validate_dir(parent)?;
        let num_entries = meta.size;

        if pos >= meta.size {
            return Err(ErrorKind::NotFound.into());
        }

        if num_entries <= MAX_ENTRIES_IN_META_BLOCK {
            return Ok(*block_get_dir_entry(
                parent_block.block(),
                (pos + 1) as usize,
            ));
        }

        if num_entries <= MAX_ENTRIES_ONLY_DATA_BLOCKS {
            let data_block_idx = pos / MAX_ENTRIES_IN_DATA_BLOCK;
            let data_block_no =
                block_get_datablock_no_in_meta(parent_block.block(), data_block_idx);
            return Ok(*block_get_dir_entry(
                self.blockcache.read(data_block_no)?.block(),
                (pos % MAX_ENTRIES_IN_DATA_BLOCK) as usize,
            ));
        }

        let link_block_idx = pos / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST;
        let link_block_no = block_get_datablock_no_in_meta(parent_block.block(), link_block_idx);

        let link_block = self.blockcache.read(link_block_no)?;
        let data_block_idx =
            (pos % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST) / MAX_ENTRIES_IN_DATA_BLOCK;
        let data_block_no = block_get_datablock_no_in_link(link_block.block(), data_block_idx);

        Ok(*block_get_dir_entry(
            self.blockcache.read(data_block_no)?.block(),
            (pos % MAX_ENTRIES_IN_DATA_BLOCK) as usize,
        ))
    }

    pub fn get_directory_entry_by_name(&mut self, parent: EntryId, name: &str) -> Result<DirEntry> {
        self.check_error()?;
        let (block_no, entry_pos) = self.find_entry_by_name(parent, name)?;
        let block = self.blockcache.read(block_no).unwrap();
        Ok(*block_get_dir_entry(block.block(), entry_pos))
    }

    /// Get the number of directory entries (children).
    pub fn get_num_entries(&mut self, dir: EntryId) -> Result<u64> {
        self.check_error()?;
        let block = self.blockcache.read(dir.block_no)?;
        let meta = block.block().get_at_offset::<EntryMetadata>(0);
        meta.validate_dir(dir)?;

        Ok(meta.size)
    }

    /// Get file size.
    pub fn get_file_size(&mut self, file: EntryId) -> Result<u64> {
        self.check_error()?;
        let block = self.blockcache.read(file.block_no)?;
        let meta = block.block().get_at_offset::<EntryMetadata>(0);
        meta.validate_file(file)?;

        Ok(meta.size)
    }

    pub fn stat(&mut self, entry: EntryId) -> Result<Attr> {
        self.check_error()?;
        let block = self.blockcache.read(entry.block_no)?;
        let meta = block.block().get_at_offset::<EntryMetadata>(0);
        meta.validate(entry)?;

        Ok(meta.into())
    }

    pub fn set_file_size(&mut self, file_id: EntryId, new_size: u64) -> Result<()> {
        self.check_error()?;

        // Go block by block, from the end.
        loop {
            let metadata_block = self.blockcache.read(file_id.block_no)?;
            let meta = metadata_block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate_file(file_id)?;
            let prev_size = meta.size;
            if new_size > prev_size {
                return Err(ErrorKind::InvalidInput.into());
            }
            if new_size == prev_size {
                return Ok(());
            }

            let mid_size = (prev_size - 1) & !(BLOCK_SIZE as u64 - 1);
            debug_assert!(mid_size < prev_size);
            debug_assert!((prev_size - mid_size) <= BLOCK_SIZE as u64);
            debug_assert_eq!(0, mid_size & (BLOCK_SIZE as u64 - 1));

            // A special case.
            let mid_size = if prev_size > MAX_BYTES_IN_META_BLOCK
                && prev_size <= BLOCK_SIZE as u64
                && new_size <= MAX_BYTES_IN_META_BLOCK
            {
                new_size
            } else {
                mid_size
            };

            if (new_size > mid_size && new_size > MAX_BYTES_IN_META_BLOCK)
                || prev_size <= MAX_BYTES_IN_META_BLOCK
            {
                // No block/layout changes.
                let metadata_block = self.blockcache.get_mut(file_id.block_no);
                let meta = metadata_block
                    .block_mut()
                    .get_mut_at_offset::<EntryMetadata>(0);
                meta.size = new_size;
                meta.set_crc32();
                self.blockcache.write(file_id.block_no)?;
                return Ok(());
            }

            // Need to remove the last data block and, potentially, link blocks.
            if prev_size <= MAX_BYTES_ONLY_DATA_BLOCKS {
                // Files smaller than ~2M.
                let block_idx = mid_size >> BLOCK_SIZE.ilog2();

                let meta_block = self.blockcache.get(file_id.block_no);
                let data_block_no = block_get_datablock_no_in_meta(meta_block.block(), block_idx);

                // TODO: we probably don't need a TXN here: will save a couple of block writes?
                self.start_txn(TXN_TYPE_REMOVE_BYTES, file_id)?;
                let superblock = self.blockcache.get_mut(0);
                let sbh = superblock
                    .block_mut()
                    .get_mut_at_offset::<SuperblockHeader>(0);
                sbh.txn_data_block = data_block_no;
                self.save_superblock()?;

                let metadata_block = self.blockcache.get_mut(file_id.block_no);
                let meta = metadata_block
                    .block_mut()
                    .get_mut_at_offset::<EntryMetadata>(0);
                meta.size = mid_size;
                meta.set_crc32();
                self.blockcache.write(file_id.block_no)?;

                if (mid_size <= MAX_BYTES_IN_META_BLOCK) && (mid_size > 0) {
                    let data = *self.blockcache.read(data_block_no)?.block();
                    unsafe {
                        let metadata_block = self.blockcache.get_mut(file_id.block_no);
                        copy_nonoverlapping(
                            data.as_bytes().as_ptr(),
                            block_get_data_bytes_in_meta_mut(metadata_block.block_mut())
                                .as_mut_ptr(),
                            MAX_BYTES_IN_META_BLOCK as usize,
                        );
                    }
                    self.blockcache.write(file_id.block_no)?;
                }

                self.free_txn_block(BlockType::Data)?;
                self.commit_txn()?;
                continue;
            }

            if prev_size <= MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS {
                // Files smaller than ~1G.
                let link_block_idx = mid_size >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
                let meta_block = self.blockcache.get(file_id.block_no);
                let link_block_no =
                    block_get_datablock_no_in_meta(meta_block.block(), link_block_idx);

                let link_block = self.blockcache.read(link_block_no)?;
                let data_block_idx =
                    (mid_size & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1)) >> BLOCK_SIZE.ilog2();
                let data_block_no =
                    block_get_datablock_no_in_link(link_block.block(), data_block_idx);

                let need_to_free_link_block =
                    (data_block_idx == 0) || (mid_size == MAX_BYTES_ONLY_DATA_BLOCKS);

                self.start_txn(TXN_TYPE_REMOVE_BYTES, file_id)?;

                let superblock = self.blockcache.get_mut(0);
                let sbh = superblock
                    .block_mut()
                    .get_mut_at_offset::<SuperblockHeader>(0);
                sbh.txn_data_block = data_block_no;
                if need_to_free_link_block {
                    sbh.txn_link_block = link_block_no;
                }
                self.save_superblock()?;

                let metadata_block = self.blockcache.get_mut(file_id.block_no);
                let meta = metadata_block
                    .block_mut()
                    .get_mut_at_offset::<EntryMetadata>(0);
                meta.size = mid_size;
                meta.set_crc32();
                self.blockcache.write(file_id.block_no)?;

                if mid_size == MAX_BYTES_ONLY_DATA_BLOCKS {
                    let links = *self.blockcache.get(link_block_no).block();
                    let metadata_block = self.blockcache.get_mut(file_id.block_no);
                    for idx in 0..MAX_LINKS_IN_META_BLOCK {
                        block_set_datablock_no_in_meta(
                            metadata_block.block_mut(),
                            idx,
                            block_get_datablock_no_in_link(&links, idx),
                        );
                    }
                    self.blockcache.write(file_id.block_no)?;
                }

                self.free_txn_block(BlockType::Data)?;
                if need_to_free_link_block {
                    self.free_txn_block(BlockType::Links)?;
                }
                self.commit_txn()?;
                continue;
            }

            // Large files.
            let list_of_links_block_idx =
                mid_size >> BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST.ilog2();
            let meta_block = self.blockcache.get(file_id.block_no);
            let list_of_links_block_no =
                block_get_datablock_no_in_meta(meta_block.block(), list_of_links_block_idx);

            let link_block_idx = (mid_size & (BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST - 1))
                >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
            let list_of_links_block = self.blockcache.read(list_of_links_block_no)?;
            let link_block_no =
                block_get_datablock_no_in_link(list_of_links_block.block(), link_block_idx);

            let link_block = self.blockcache.read(link_block_no)?;
            let data_block_idx =
                (mid_size & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1)) >> BLOCK_SIZE.ilog2();
            let data_block_no = block_get_datablock_no_in_link(link_block.block(), data_block_idx);

            let need_to_free_link_block = data_block_idx == 0;
            let need_to_free_list_of_links_block = need_to_free_link_block
                && ((link_block_idx == 0) || (mid_size == MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS));

            self.start_txn(TXN_TYPE_REMOVE_BYTES, file_id)?;
            let superblock = self.blockcache.get_mut(0);
            let sbh = superblock
                .block_mut()
                .get_mut_at_offset::<SuperblockHeader>(0);
            sbh.txn_data_block = data_block_no;
            if need_to_free_link_block {
                sbh.txn_link_block = link_block_no;
            }
            if need_to_free_list_of_links_block {
                sbh.txn_list_of_links_block = list_of_links_block_no;
            }
            self.save_superblock()?;

            let metadata_block = self.blockcache.get_mut(file_id.block_no);
            let meta = metadata_block
                .block_mut()
                .get_mut_at_offset::<EntryMetadata>(0);
            meta.size = mid_size;
            meta.set_crc32();
            self.blockcache.write(file_id.block_no)?;

            if mid_size == MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS {
                let list_of_links = *self.blockcache.get(list_of_links_block_no).block();
                let metadata_block = self.blockcache.get_mut(file_id.block_no);
                for idx in 0..MAX_LINKS_IN_META_BLOCK {
                    block_set_datablock_no_in_meta(
                        metadata_block.block_mut(),
                        idx,
                        block_get_datablock_no_in_link(&list_of_links, idx),
                    );
                }
                self.blockcache.write(file_id.block_no)?;
            }

            self.free_txn_block(BlockType::Data)?;
            if need_to_free_link_block {
                self.free_txn_block(BlockType::Links)?;
            }
            if need_to_free_list_of_links_block {
                self.free_txn_block(BlockType::ListOfLinks)?;
            }
            self.commit_txn()?;
            continue;
        }
    }

    pub fn get_parent(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        if entry_id == ROOT_DIR_ID {
            return Ok(None);
        }

        let block = self.blockcache.read(entry_id.block_no)?;
        let meta = block.block().get_at_offset::<EntryMetadata>(0);
        meta.validate(entry_id)?;

        Ok(Some(meta.parent_id))
    }

    pub fn get_name(&mut self, entry_id: EntryId) -> Result<String> {
        if entry_id == ROOT_DIR_ID {
            return Ok("/".into());
        }

        let block = self.blockcache.read(entry_id.block_no)?;
        let meta = block.block().get_at_offset::<EntryMetadata>(0);

        meta.validate(entry_id)?;

        let parent_id = meta.parent_id;
        let (block_no, entry_pos) = self.find_entry_by_id(parent_id, entry_id)?;
        let block = self.blockcache.get(block_no);
        let dir_entry = block_get_dir_entry(block.block(), entry_pos);
        dir_entry.get_name().map(|n| n.into())
    }

    pub fn move_rename(
        &mut self,
        entry_id: EntryId,
        new_parent: EntryId,
        new_name: &str,
    ) -> Result<()> {
        self.check_error()?;
        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate(entry_id).unwrap();
            let block = self.blockcache.read(new_parent.block_no)?;
            let meta = block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate(new_parent).unwrap();
        }
        self.validate_new_entry(new_parent, new_name)?;
        if entry_id.block_no == ROOT_DIR_ID.block_no {
            return Err(ErrorKind::InvalidInput.into());
        }
        let block = self.blockcache.read(entry_id.block_no)?;
        let meta = block.block().get_at_offset::<EntryMetadata>(0);
        meta.validate(entry_id)?;
        let old_parent = meta.parent_id;

        if old_parent == new_parent {
            let (block_no, entry_pos) = self.find_entry_by_id(old_parent, entry_id)?;
            let block = self.blockcache.get_mut(block_no);
            block_get_dir_entry_mut(block.block_mut(), entry_pos).set_name(new_name);
            self.blockcache.write(block_no)?;
            return Ok(());
        }

        self.start_txn(TXN_TYPE_MOVE, old_parent)?;
        let superblock = self.blockcache.get_mut(0);
        let sbh = superblock
            .block_mut()
            .get_mut_at_offset::<SuperblockHeader>(0);
        sbh.txn_meta_block = entry_id.block_no;
        self.save_superblock()?;

        let block = self.blockcache.get_mut(entry_id.block_no);
        let meta = block.block_mut().get_mut_at_offset::<EntryMetadata>(0);
        meta.parent_id = new_parent;
        meta.set_crc32();
        self.blockcache.write(entry_id.block_no)?;

        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate(entry_id).unwrap();
        }

        // Move to the new parent.
        self.add_directory_entry_inner(new_parent, entry_id, new_name)
            .inspect_err(|_| {
                let _ = self.make_error();
            })?;

        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate(entry_id).unwrap();
            let block = self.blockcache.read(old_parent.block_no)?;
            let meta = block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate(old_parent).unwrap();
            let block = self.blockcache.read(new_parent.block_no)?;
            let meta = block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate(new_parent).unwrap();
        }

        // Clear newly added blocks, if any (can find them from the meta block).
        let superblock = self.blockcache.get_mut(0);
        let sbh = superblock
            .block_mut()
            .get_mut_at_offset::<SuperblockHeader>(0);
        sbh.txn_data_block = 0;
        sbh.txn_link_block = 0;
        sbh.txn_list_of_links_block = 0;

        // #[cfg(debug_assertions)]
        // {
        //     let block = self.blockcache.read(entry_id.block_no)?;
        //     let meta = block.block().get_at_offset::<EntryMetadata>(0);
        //     meta.validate(entry_id).unwrap();
        // }

        if let Err(_err) = self.remove_directory_entry_inner(old_parent, entry_id) {
            return self.make_error();
        }
        let superblock = self.blockcache.get_mut(0);
        let sbh = superblock
            .block_mut()
            .get_mut_at_offset::<SuperblockHeader>(0);
        let txn_data_block = sbh.txn_data_block;
        if sbh.txn_link_block != 0 {
            self.free_txn_block(BlockType::Links)?;
        }
        if txn_data_block != 0 {
            self.free_txn_block(BlockType::Data)?;
        }

        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate(entry_id).unwrap();
            let block = self.blockcache.read(old_parent.block_no)?;
            let meta = block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate(old_parent).unwrap();
            let block = self.blockcache.read(new_parent.block_no)?;
            let meta = block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate(new_parent).unwrap();
        }

        self.commit_txn()?;
        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = block.block().get_at_offset::<EntryMetadata>(0);
            meta.validate(entry_id).unwrap();
        }

        Ok(())
    }

    pub fn remove(&mut self, entry_id: EntryId) -> Result<()> {
        self.check_error()?;
        if entry_id.block_no == ROOT_DIR_ID.block_no {
            return Err(ErrorKind::InvalidInput.into());
        }
        let block = self.blockcache.read(entry_id.block_no)?;
        let meta = block.block().get_at_offset::<EntryMetadata>(0);
        meta.validate(entry_id)?;
        if meta.size > 0 {
            // Cannot delete a non-empty directory or a file with data.
            // First clean the directory or truncate the file.
            #[cfg(debug_assertions)]
            log::debug!("srfs-core: remove failed: non-empty entry");
            return Err(ErrorKind::DirectoryNotEmpty.into());
        }
        let parent_id = meta.parent_id;

        // Pre-commit: mark the block we are removing as dirty.
        self.start_txn(TXN_TYPE_REMOVE_NODE, parent_id)?;
        let superblock = self.blockcache.get_mut(0);
        let sbh = superblock
            .block_mut()
            .get_mut_at_offset::<SuperblockHeader>(0);
        assert_eq!(0, sbh.txn_meta_block);
        sbh.txn_meta_block = entry_id.block_no;

        self.remove_directory_entry_inner(parent_id, entry_id)
            .inspect_err(|_| {
                let _ = self.make_error();
            })?;

        // Commit.
        let superblock = self.blockcache.get_mut(0);
        let sbh = superblock
            .block_mut()
            .get_mut_at_offset::<SuperblockHeader>(0);
        let txn_data_block = sbh.txn_data_block;
        if sbh.txn_link_block != 0 {
            self.free_txn_block(BlockType::Links)?;
        }
        if txn_data_block != 0 {
            self.free_txn_block(BlockType::Data)?;
        }
        self.free_txn_block(BlockType::Metadata)?;
        self.commit_txn()
    }

    // Must be inside a transaction. Inner => no need to poison self.
    fn remove_directory_entry_inner(&mut self, parent_id: EntryId, child: EntryId) -> Result<()> {
        // let sbh = self.superblock.header();
        // assert_ne!(TXN_TYPE_NONE, sbh.txn_type);

        // Need to put the last entry into the place occupied by this entry.
        let (entry_block_no, entry_pos) = self.find_entry_by_id(parent_id, child)?;

        // Need to read instead of get because the find above may flush the cache.
        let parent_block = self.blockcache.read(parent_id.block_no)?;
        let parent_meta = parent_block.block().get_at_offset::<EntryMetadata>(0);
        parent_meta.validate_dir(parent_id)?;
        let num_entries = parent_meta.size;
        if num_entries <= MAX_ENTRIES_IN_META_BLOCK {
            assert_eq!(entry_block_no, parent_id.block_no);
            // Only the parent_block needs changing.
            if (entry_pos as u64) < num_entries {
                let parent_block = self.blockcache.get_mut(parent_id.block_no);
                let last_entry = *block_get_dir_entry(parent_block.block(), num_entries as usize);
                *block_get_dir_entry_mut(parent_block.block_mut(), entry_pos) = last_entry;
            }
        } else if num_entries <= MAX_ENTRIES_ONLY_DATA_BLOCKS {
            let last_entry_block_idx = (num_entries - 1) / MAX_ENTRIES_IN_DATA_BLOCK;
            let last_entry_block_no =
                block_get_datablock_no_in_meta(parent_block.block(), last_entry_block_idx);
            let last_entry_idx = ((num_entries - 1) % MAX_ENTRIES_IN_DATA_BLOCK) as usize;

            if (entry_block_no, entry_pos) != (last_entry_block_no, last_entry_idx) {
                let last_entry_block = self.blockcache.read(last_entry_block_no)?;
                let last_entry = *block_get_dir_entry(last_entry_block.block(), last_entry_idx);
                let entry_block = self.blockcache.read_mut(entry_block_no)?;
                *block_get_dir_entry_mut(entry_block.block_mut(), entry_pos) = last_entry;
                self.blockcache.write(entry_block_no)?;
            }

            if last_entry_idx == 0 {
                // We need to free last_entry_block.
                let superblock = self.blockcache.get_mut(0);
                let sbh = superblock
                    .block_mut()
                    .get_mut_at_offset::<SuperblockHeader>(0);
                assert_eq!(0, sbh.txn_data_block);
                sbh.txn_data_block = last_entry_block_no;
                self.save_superblock()?; // TODO: do we need this?
            }

            if num_entries == (MAX_ENTRIES_IN_META_BLOCK + 1) {
                // Move all entries into the parent meta block.
                let entry_block = *self.blockcache.get(entry_block_no).block();
                let parent_block = self.blockcache.get_mut(parent_id.block_no);
                for idx in 0..(MAX_ENTRIES_IN_META_BLOCK as usize) {
                    *block_get_dir_entry_mut(parent_block.block_mut(), idx + 1) =
                        *block_get_dir_entry(&entry_block, idx);
                }
                // Note: parent_block is not saved here, will be saved below.

                // Free the last block.
                let superblock = self.blockcache.get_mut(0);
                let sbh = superblock
                    .block_mut()
                    .get_mut_at_offset::<SuperblockHeader>(0);
                assert_eq!(0, sbh.txn_data_block);
                sbh.txn_data_block = last_entry_block_no;
                self.save_superblock()?; // TODO: do we need this?
            }
        } else {
            let last_link_block_no = block_get_datablock_no_in_meta(
                parent_block.block(),
                (num_entries - 1) / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST,
            );

            let last_link_block = self.blockcache.read(last_link_block_no)?;
            let last_entry_block_idx = ((num_entries - 1)
                % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST)
                / MAX_ENTRIES_IN_DATA_BLOCK;
            let last_entry_block_no =
                block_get_datablock_no_in_link(last_link_block.block(), last_entry_block_idx);
            let last_entry_idx = ((num_entries - 1) % MAX_ENTRIES_IN_DATA_BLOCK) as usize;

            if (entry_block_no, entry_pos) != (last_entry_block_no, last_entry_idx) {
                let last_entry_block = self.blockcache.read(last_entry_block_no)?;
                let last_entry = *block_get_dir_entry(last_entry_block.block(), last_entry_idx);
                let entry_block = self.blockcache.read_mut(entry_block_no)?;
                *block_get_dir_entry_mut(entry_block.block_mut(), entry_pos) = last_entry;
                self.blockcache.write(entry_block_no)?;
            }

            if last_entry_idx == 0 {
                // We need to free last_entry_block.
                let superblock = self.blockcache.get_mut(0);
                let sbh = superblock
                    .block_mut()
                    .get_mut_at_offset::<SuperblockHeader>(0);
                assert_eq!(0, sbh.txn_data_block);
                sbh.txn_data_block = last_entry_block_no;
                self.save_superblock()?; // TODO: do we need this?
            }

            if num_entries == (MAX_ENTRIES_ONLY_DATA_BLOCKS + 1) {
                // Move all links into the parent meta block.
                let link_block = self.blockcache.get(last_link_block_no);
                let links: Block = *link_block.block();
                let parent_block = self.blockcache.get_mut(parent_id.block_no);
                for idx in 0..MAX_LINKS_IN_META_BLOCK {
                    block_set_datablock_no_in_meta(
                        parent_block.block_mut(),
                        idx,
                        block_get_datablock_no_in_link(&links, idx),
                    );
                }
                // Note: parent_block is not saved here, will be saved below.

                // Free the link block.
                let superblock = self.blockcache.get_mut(0);
                let sbh = superblock
                    .block_mut()
                    .get_mut_at_offset::<SuperblockHeader>(0);
                assert_eq!(0, sbh.txn_link_block);
                sbh.txn_link_block = last_link_block_no;
                self.save_superblock()?; // TODO: do we need this?
            }

            if (num_entries % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST) == 1 {
                // Free the link block.
                let superblock = self.blockcache.get_mut(0);
                let sbh = superblock
                    .block_mut()
                    .get_mut_at_offset::<SuperblockHeader>(0);
                assert_eq!(0, sbh.txn_link_block);
                sbh.txn_link_block = last_link_block_no;
                self.save_superblock()?; // TODO: do we need this?
            }
        }

        let parent_block = self.blockcache.get_mut(parent_id.block_no);
        let parent_meta = parent_block
            .block_mut()
            .get_mut_at_offset::<EntryMetadata>(0);
        parent_meta.size -= 1;
        parent_meta.set_crc32();
        self.blockcache.write(parent_id.block_no)?;

        Ok(())
    }

    /// Write buf to file at offset. At most 4096 bytes will be written.
    ///
    /// A write may succeed with the resulting usize less than buf.len; this usually
    /// happens when the write would otherwise cross a block boundary. Just do another
    /// write for the remaining bytes then.
    pub fn write(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize> {
        self.check_error()?;
        if file_id.kind() != EntryKind::File {
            return Err(ErrorKind::InvalidInput.into());
        }
        let meta_block = self.blockcache.read(file_id.block_no)?;
        let meta = meta_block.block().get_at_offset::<EntryMetadata>(0);
        meta.validate_file(file_id)?;
        let prev_size = meta.size;
        if offset > prev_size {
            return Err(ErrorKind::InvalidInput.into());
        }
        let new_end = if offset == prev_size {
            offset + (buf.len() as u64)
        } else {
            prev_size.min(offset + (buf.len() as u64))
        };
        let new_size = prev_size.max(new_end);
        if new_size <= MAX_BYTES_IN_META_BLOCK {
            // Only the main/metadata block.
            let meta_block = self.blockcache.get_mut(file_id.block_no);
            let meta = meta_block.block_mut().get_mut_at_offset::<EntryMetadata>(0);

            meta.size = new_size;
            meta.set_crc32();
            unsafe {
                copy_nonoverlapping(
                    buf.as_ptr(),
                    (block_get_data_bytes_in_meta_mut(meta_block.block_mut()).as_mut_ptr() as usize
                        + (offset as usize)) as *mut u8,
                    (new_end - offset) as usize,
                );
            }
            self.blockcache.write(file_id.block_no).inspect_err(|_| {
                let _ = self.make_error();
            })?;
            return Ok((new_end - offset) as usize);
        }

        if new_size == prev_size {
            self.update_file(file_id, offset, buf)
        } else {
            self.append(file_id, offset, buf)
        }
    }

    pub fn read(&mut self, file_id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.check_error()?;
        if file_id.kind() != EntryKind::File {
            return Err(ErrorKind::InvalidInput.into());
        }
        let meta_block = self.blockcache.read(file_id.block_no)?;
        let meta = meta_block.block().get_at_offset::<EntryMetadata>(0);
        meta.validate_file(file_id)?;
        let file_size = meta.size;
        if offset >= file_size {
            return Ok(0);
        }
        let end = file_size.min(offset + (buf.len() as u64));
        if file_size <= MAX_BYTES_IN_META_BLOCK {
            // We are still in the main block.
            unsafe {
                copy_nonoverlapping(
                    (block_get_data_bytes_in_meta(meta_block.block()).as_ptr() as usize
                        + (offset as usize)) as *const u8,
                    buf.as_mut_ptr(),
                    (end - offset) as usize,
                );
            }
            return Ok((end - offset) as usize);
        }

        let data_block_no = self.find_data_block(file_id, offset)?;
        let block_end = align_up(offset + 1, BLOCK_SIZE as u64);
        let new_end = end.min(block_end);
        let data_block = self.blockcache.read(data_block_no)?;
        unsafe {
            copy_nonoverlapping(
                (data_block.block().as_bytes().as_ptr() as usize
                    + (offset as usize & (BLOCK_SIZE - 1))) as *const u8,
                buf.as_mut_ptr(),
                (new_end - offset) as usize,
            );
        }
        Ok((new_end - offset) as usize)
    }

    fn append(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize> {
        self.check_error()?;
        // We may potentially need to allocate three new blocks:
        // - a new data block
        // - a new 1st level (leaf) blocklist block
        // - a new 2nd level blocklist block
        let meta_block = self.blockcache.get(file_id.block_no);
        let meta = meta_block.block().get_at_offset::<EntryMetadata>(0);
        let prev_size = meta.size;
        assert_eq!(prev_size, offset);
        let new_size =
            if align_up(prev_size + 1, BLOCK_SIZE as u64) >= prev_size + (buf.len() as u64) {
                prev_size + (buf.len() as u64)
            } else {
                align_up(prev_size + 1, BLOCK_SIZE as u64)
            };

        // Special case 1: going from data in meta block to a separate data block.
        if prev_size <= MAX_BYTES_IN_META_BLOCK {
            assert!(new_size > MAX_BYTES_IN_META_BLOCK); // The caller handles in-meta writes.

            // Cache the address of the bytes, to fool the borrow checker.
            let prev_bytes_start =
                block_get_data_bytes_in_meta(meta_block.block()).as_ptr() as usize;

            // Start the txn.
            self.start_txn(TXN_TYPE_ADD_BYTES, file_id)?;
            let data_block_no = self.allocate_txn_block(BlockType::Data)?;

            // Copy bytes.
            let data_block = self.blockcache.get_block_uninit(data_block_no);
            unsafe {
                // Copy existing bytes.
                copy_nonoverlapping(
                    prev_bytes_start as *const u8,
                    data_block.block_mut().as_bytes_mut().as_mut_ptr(),
                    prev_size as usize,
                );
                // Copy new bytes.
                copy_nonoverlapping(
                    buf.as_ptr(),
                    (data_block.block_mut().as_bytes_mut().as_ptr() as usize + (prev_size as usize))
                        as *mut u8,
                    (new_size - prev_size) as usize,
                );
            }
            self.blockcache.write(data_block_no).inspect_err(|_| {
                let _ = self.make_error();
            })?;

            // Update the meta.
            let meta_block = self.blockcache.get_mut(file_id.block_no);
            block_set_datablock_no_in_meta(meta_block.block_mut(), 0, data_block_no);
            let meta = meta_block.block_mut().get_mut_at_offset::<EntryMetadata>(0);
            meta.size = new_size;
            meta.set_crc32();
            self.blockcache.write(file_id.block_no).inspect_err(|_| {
                let _ = self.make_error();
            })?;

            // Commit the txn.
            self.commit_txn()?;
            return Ok((new_size - prev_size) as usize);
        }

        if align_up(prev_size, BLOCK_SIZE as u64) >= new_size {
            // The write goes to an existing data block - no TXN is necessary.
            let data_block_no = self.find_data_block(file_id, prev_size - 1)?;

            // Copy bytes.
            let data_block = self.blockcache.read_mut(data_block_no)?;
            unsafe {
                copy_nonoverlapping(
                    buf.as_ptr(),
                    (data_block.block_mut().as_bytes_mut().as_mut_ptr() as usize
                        + (offset as usize & (BLOCK_SIZE - 1))) as *mut u8,
                    (new_size - prev_size) as usize,
                );
            }
            self.blockcache.write(data_block_no)?;

            // Update meta.
            let meta_block = self.blockcache.get_mut(file_id.block_no);
            let meta = meta_block.block_mut().get_mut_at_offset::<EntryMetadata>(0);
            meta.size = new_size;
            meta.set_crc32();
            self.blockcache.write(file_id.block_no)?;

            return Ok((new_size - prev_size) as usize);
        }

        // Append a new block.
        self.start_txn(TXN_TYPE_ADD_BYTES, file_id)?;
        let data_block_no = self.allocate_txn_block(BlockType::Data)?;

        // Copy bytes.
        let data_block = self.blockcache.get_block_uninit(data_block_no);
        debug_assert_eq!(0, offset as usize & (BLOCK_SIZE - 1));
        unsafe {
            copy_nonoverlapping(
                buf.as_ptr(),
                data_block.block_mut().as_bytes_mut().as_mut_ptr(),
                (new_size - prev_size) as usize,
            );
        }
        self.blockcache.write(data_block_no).inspect_err(|_| {
            let _ = self.make_error();
        })?;

        if new_size <= MAX_BYTES_ONLY_DATA_BLOCKS {
            // Update the meta.
            let meta_block = self.blockcache.get_mut(file_id.block_no);
            block_set_datablock_no_in_meta(
                meta_block.block_mut(),
                prev_size >> BLOCK_SIZE.ilog2(),
                data_block_no,
            );
        } else if new_size <= MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS {
            // Files of size between ~2M and ~1G.
            let need_new_link_block = prev_size
                .is_multiple_of(BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST)
                || (prev_size == MAX_BYTES_ONLY_DATA_BLOCKS);

            if need_new_link_block {
                let link_block_no =
                    self.allocate_txn_block(BlockType::Links).inspect_err(|_| {
                        let _ = self.make_error();
                    })?;

                let (link_block, data_block_idx) = if prev_size == MAX_BYTES_ONLY_DATA_BLOCKS {
                    let meta_block = *self.blockcache.get(file_id.block_no).block();
                    let bytes = block_get_data_bytes_in_meta(&meta_block);
                    let link_block = self.blockcache.get_block_uninit(link_block_no);

                    unsafe {
                        copy_nonoverlapping(
                            bytes.as_ptr(),
                            link_block.block_mut().as_bytes_mut().as_mut_ptr(),
                            bytes.len(),
                        );
                    }

                    (link_block, MAX_LINKS_IN_META_BLOCK)
                } else {
                    (self.blockcache.get_block_uninit(link_block_no), 0)
                };

                block_set_datablock_no_in_link(
                    link_block.block_mut(),
                    data_block_idx,
                    data_block_no,
                );
                self.blockcache.write(link_block_no).inspect_err(|_| {
                    let _ = self.make_error();
                })?;

                let link_block_idx = prev_size >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
                let meta_block = self.blockcache.get_mut(file_id.block_no);
                block_set_datablock_no_in_meta(
                    meta_block.block_mut(),
                    link_block_idx,
                    link_block_no,
                );
            } else {
                let link_block_idx = prev_size >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
                let link_block_no = block_get_datablock_no_in_meta(
                    self.blockcache.get(file_id.block_no).block(),
                    link_block_idx,
                );
                let link_block = self.blockcache.read_mut(link_block_no);
                if let Err(err) = link_block {
                    let _ = self.make_error();
                    return Err(err);
                }
                let data_block_idx = (prev_size & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1))
                    >> BLOCK_SIZE.ilog2();
                block_set_datablock_no_in_link(
                    link_block.unwrap().block_mut(),
                    data_block_idx,
                    data_block_no,
                );
                self.blockcache.write(link_block_no).inspect_err(|_| {
                    let _ = self.make_error();
                })?;
            }
        } else {
            // ~1G+ files here.
            let need_new_list_of_links_block = prev_size
                .is_multiple_of(BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST)
                || (prev_size == MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS);

            if need_new_list_of_links_block {
                // Always a new link block here.
                let link_block_no =
                    self.allocate_txn_block(BlockType::Links).inspect_err(|_| {
                        let _ = self.make_error();
                    })?;
                let link_block = self.blockcache.get_block_uninit(link_block_no);

                block_set_datablock_no_in_link(link_block.block_mut(), 0, data_block_no);
                self.blockcache.write(link_block_no).inspect_err(|_| {
                    let _ = self.make_error();
                })?;

                let list_of_links_block_no = self
                    .allocate_txn_block(BlockType::ListOfLinks)
                    .inspect_err(|_| {
                        let _ = self.make_error();
                    })?;
                let (list_of_links_block, link_block_idx) =
                    if prev_size == MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS {
                        let meta_block = *self.blockcache.get(file_id.block_no).block();
                        let bytes = block_get_data_bytes_in_meta(&meta_block);
                        let list_of_links_block =
                            self.blockcache.get_block_uninit(list_of_links_block_no);

                        unsafe {
                            copy_nonoverlapping(
                                bytes.as_ptr(),
                                list_of_links_block.block_mut().as_bytes_mut().as_mut_ptr(),
                                bytes.len(),
                            );
                        }

                        (list_of_links_block, MAX_LINKS_IN_META_BLOCK)
                    } else {
                        (self.blockcache.get_block_uninit(list_of_links_block_no), 0)
                    };

                block_set_datablock_no_in_link(
                    list_of_links_block.block_mut(),
                    link_block_idx,
                    link_block_no,
                );
                self.blockcache
                    .write(list_of_links_block_no)
                    .inspect_err(|_| {
                        let _ = self.make_error();
                    })?;

                let list_of_links_block_idx =
                    prev_size >> BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST.ilog2();
                let meta_block = self.blockcache.get_mut(file_id.block_no);
                block_set_datablock_no_in_meta(
                    meta_block.block_mut(),
                    list_of_links_block_idx,
                    list_of_links_block_no,
                );
            } else {
                let list_of_links_block_idx =
                    prev_size >> BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST.ilog2();
                let list_of_links_block_no = block_get_datablock_no_in_meta(
                    self.blockcache.get(file_id.block_no).block(),
                    list_of_links_block_idx,
                );
                // Cache the block.
                if let Err(err) = self.blockcache.read(list_of_links_block_no) {
                    let _ = self.make_error();
                    return Err(err);
                }

                let need_new_link_block =
                    prev_size.is_multiple_of(BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST);
                let link_block_idx = (prev_size & (BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST - 1))
                    >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();

                if need_new_link_block {
                    let link_block_no =
                        self.allocate_txn_block(BlockType::Links).inspect_err(|_| {
                            let _ = self.make_error();
                        })?;
                    let link_block = self.blockcache.get_block_uninit(link_block_no);

                    block_set_datablock_no_in_link(link_block.block_mut(), 0, data_block_no);
                    self.blockcache.write(link_block_no).inspect_err(|_| {
                        let _ = self.make_error();
                    })?;

                    let list_of_links_block = self.blockcache.get_mut(list_of_links_block_no);
                    block_set_datablock_no_in_link(
                        list_of_links_block.block_mut(),
                        link_block_idx,
                        link_block_no,
                    );
                    self.blockcache
                        .write(list_of_links_block_no)
                        .inspect_err(|_| {
                            let _ = self.make_error();
                        })?;
                } else {
                    let link_block_no = block_get_datablock_no_in_link(
                        self.blockcache.get(list_of_links_block_no).block(),
                        link_block_idx,
                    );
                    let link_block = self.blockcache.read_mut(link_block_no);
                    if let Err(err) = link_block {
                        let _ = self.make_error();
                        return Err(err);
                    }
                    let data_block_idx = (prev_size & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1))
                        >> BLOCK_SIZE.ilog2();
                    block_set_datablock_no_in_link(
                        link_block.unwrap().block_mut(),
                        data_block_idx,
                        data_block_no,
                    );
                    self.blockcache.write(link_block_no).inspect_err(|_| {
                        let _ = self.make_error();
                    })?;
                }
            }
        }

        // Commit the txn.
        let meta_block = self.blockcache.get_mut(file_id.block_no);
        let meta = meta_block.block_mut().get_mut_at_offset::<EntryMetadata>(0);
        meta.size = new_size;
        meta.set_crc32();
        self.blockcache.write(file_id.block_no).inspect_err(|_| {
            let _ = self.make_error();
        })?;

        self.commit_txn()?;
        Ok((new_size - prev_size) as usize)
    }

    fn update_file(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize> {
        let data_block_no = self.find_data_block(file_id, offset)?;
        let block_end = align_up(offset + 1, BLOCK_SIZE as u64);
        let new_end = (offset + (buf.len() as u64)).min(block_end);
        let data_block = self.blockcache.read_mut(data_block_no)?;
        unsafe {
            copy_nonoverlapping(
                buf.as_ptr(),
                (data_block.block_mut().as_bytes_mut().as_ptr() as usize
                    + (offset as usize & (BLOCK_SIZE - 1))) as *mut u8,
                (new_end - offset) as usize,
            );
        }
        self.blockcache.write(data_block_no)?;
        Ok((new_end - offset) as usize)
    }

    fn find_data_block(&mut self, file_id: EntryId, offset: u64) -> Result<u64> {
        let meta_block = self.blockcache.get(file_id.block_no);
        let meta = meta_block.block().get_at_offset::<EntryMetadata>(0);
        let file_size = meta.size;
        debug_assert!(file_size > MAX_BYTES_IN_META_BLOCK);
        debug_assert!(offset < file_size);

        if file_size <= MAX_BYTES_ONLY_DATA_BLOCKS {
            // Files smaller than ~2M.
            let block_idx = offset >> BLOCK_SIZE.ilog2();

            let meta_block = self.blockcache.get(file_id.block_no);
            return Ok(block_get_datablock_no_in_meta(
                meta_block.block(),
                block_idx,
            ));
        }

        if file_size <= MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS {
            // Files smaller than ~1G.
            let link_block_idx = offset >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
            let meta_block = self.blockcache.get(file_id.block_no);
            let link_block_no = block_get_datablock_no_in_meta(meta_block.block(), link_block_idx);

            let link_block = self.blockcache.read(link_block_no)?;
            let data_block_idx =
                (offset & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1)) >> BLOCK_SIZE.ilog2();
            return Ok(block_get_datablock_no_in_link(
                link_block.block(),
                data_block_idx,
            ));
        }

        // Files larger than ~1G.
        let list_of_links_block_idx = offset >> BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST.ilog2();
        let meta_block = self.blockcache.get(file_id.block_no);
        let list_of_links_block_no =
            block_get_datablock_no_in_meta(meta_block.block(), list_of_links_block_idx);

        let list_of_links_block = self.blockcache.read(list_of_links_block_no)?;
        let link_block_idx = (offset & (BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST - 1))
            >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
        let link_block_no =
            block_get_datablock_no_in_link(list_of_links_block.block(), link_block_idx);

        let link_block = self.blockcache.read(link_block_no)?;
        let data_block_idx =
            (offset & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1)) >> BLOCK_SIZE.ilog2();
        Ok(block_get_datablock_no_in_link(
            link_block.block(),
            data_block_idx,
        ))
    }

    fn find_entry_by_id(
        &mut self,
        parent_id: EntryId,
        entry_id: EntryId,
    ) -> Result<(u64 /* block_no */, usize /* entry_pos */)> {
        self.find_entry(parent_id, |e| e.id == entry_id)
    }

    fn find_entry_by_name(
        &mut self,
        parent_id: EntryId,
        name: &str,
    ) -> Result<(u64 /* block_no */, usize /* entry_pos */)> {
        self.find_entry(parent_id, |e| {
            if let Ok(s) = core::str::from_utf8(&e.name[0..(e.name_len as usize)]) {
                s == name
            } else {
                false
            }
        })
    }

    fn find_entry<F>(
        &mut self,
        parent_id: EntryId,
        pred: F,
    ) -> Result<(u64 /* block_no */, usize /* entry_pos */)>
    where
        F: Fn(&DirEntry) -> bool,
    {
        self.check_error()?;
        let parent_block = self.blockcache.read(parent_id.block_no)?;
        let meta = parent_block.block().get_at_offset::<EntryMetadata>(0);
        let valid = meta.validate_dir(parent_id);
        if valid.is_err() {
            let _ = self.make_error();
            return Err(valid.err().unwrap());
        }

        let num_entries = meta.size;
        if num_entries <= MAX_ENTRIES_IN_META_BLOCK {
            for pos in 0..num_entries {
                let entry = block_get_dir_entry(parent_block.block(), (pos + 1) as usize);
                if pred(entry) {
                    return Ok((parent_id.block_no, (pos + 1) as usize));
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
                let block = self.blockcache.read(block_no)?;

                for pos in 0..MAX_ENTRIES_IN_DATA_BLOCK {
                    let entry = block_get_dir_entry(block.block(), pos as usize);
                    if pred(entry) {
                        return Ok((block_no, pos as usize));
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
            let link_block = self.blockcache.read(link_block_no)?;
            let data_block_nos = *link_block.block();
            for pos_block in 0..512 {
                let data_block_no = block_get_datablock_no_in_link(&data_block_nos, pos_block);
                let block = self.blockcache.read(data_block_no)?;
                for pos in 0..MAX_ENTRIES_IN_DATA_BLOCK {
                    let entry = block_get_dir_entry(block.block(), pos as usize);
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
        Err(ErrorKind::NotFound.into())
    }

    fn make_error(&mut self) -> Result<()> {
        assert!(self.error.is_ok());
        self.error = Err(ErrorKind::InvalidData.into());
        self.check_error()
    }

    fn save_superblock(&mut self) -> Result<()> {
        assert!(self.error.is_ok());
        let superblock = self.blockcache.get_mut(0);
        let sbh = superblock
            .block_mut()
            .get_mut_at_offset::<SuperblockHeader>(0);
        sbh.set_crc32();
        self.blockcache.write(0).inspect_err(|_| {
            let _ = self.make_error();
        })
    }

    fn plus_one(&mut self, block_no: u64) -> Result<()> {
        let block = self.blockcache.get_mut(block_no);
        let meta = block.block_mut().get_mut_at_offset::<EntryMetadata>(0);
        meta.size += 1;
        meta.set_crc32();
        self.blockcache.write(block_no).inspect_err(|_| {
            let _ = self.make_error();
        })
    }

    // Get a free block to use.
    fn allocate_txn_block(&mut self, block_type: BlockType) -> Result<u64> {
        let superblock = self.blockcache.get_mut(0);
        let mut sbh = superblock
            .block_mut()
            .get_mut_at_offset::<SuperblockHeader>(0);
        assert_ne!(0, sbh.txn_blocks_owner);
        if sbh.free_blocks == 0 {
            return Err(ErrorKind::StorageFull.into());
        }

        #[cfg(debug_assertions)]
        match block_type {
            BlockType::Metadata => debug_assert_eq!(0, sbh.txn_meta_block),
            BlockType::Data => debug_assert_eq!(0, sbh.txn_data_block),
            BlockType::Links => debug_assert_eq!(0, sbh.txn_link_block),
            BlockType::ListOfLinks => debug_assert_eq!(0, sbh.txn_list_of_links_block),
        }

        let new_block_no = if sbh.freelist_head == 0 {
            // The freelist is empty: get the block from the empty area.
            let new_block_no = sbh.empty_area_start;
            sbh.empty_area_start += 1;
            new_block_no
        } else {
            // Get the block from the freelist.
            let new_block_no = sbh.freelist_head;
            let block = self.blockcache.read(new_block_no)?;
            let freelist_head = *block.block().get_at_offset::<u64>(0);
            let superblock = self.blockcache.get_mut(0);
            sbh = superblock
                .block_mut()
                .get_mut_at_offset::<SuperblockHeader>(0);
            sbh.freelist_head = freelist_head;
            if sbh.freelist_head >= sbh.num_blocks {
                log::error!("FS corrupted: bad freelist (1)");
                self.make_error()?;
                unreachable!()
            }
            new_block_no
        };

        assert_ne!(new_block_no, 0);
        if new_block_no >= sbh.num_blocks {
            log::error!("FS corrupted: bad freelist (2)");
            self.make_error()?;
            unreachable!()
        }
        sbh.free_blocks -= 1;
        match block_type {
            BlockType::Metadata => sbh.txn_meta_block = new_block_no,
            BlockType::Data => sbh.txn_data_block = new_block_no,
            BlockType::Links => sbh.txn_link_block = new_block_no,
            BlockType::ListOfLinks => sbh.txn_list_of_links_block = new_block_no,
        }
        self.save_superblock()?;

        Ok(new_block_no)
    }

    fn free_txn_block(&mut self, block_type: BlockType) -> Result<()> {
        let superblock = self.blockcache.get_mut(0);
        let mut sbh = superblock
            .block_mut()
            .get_mut_at_offset::<SuperblockHeader>(0);
        let block_no = match block_type {
            BlockType::Metadata => sbh.txn_meta_block,
            BlockType::Data => sbh.txn_data_block,
            BlockType::Links => sbh.txn_link_block,
            BlockType::ListOfLinks => sbh.txn_list_of_links_block,
        };
        assert_ne!(0, block_no);
        if sbh.empty_area_start == (block_no + 1) {
            sbh.empty_area_start -= 1;
        } else {
            let prev_head = sbh.freelist_head;
            let block = self.blockcache.get_block_uninit(block_no);
            *block.block_mut().get_mut_at_offset::<u64>(0) = prev_head;
            self.blockcache.write(block_no)?;
            let superblock = self.blockcache.get_mut(0);
            sbh = superblock
                .block_mut()
                .get_mut_at_offset::<SuperblockHeader>(0);
        }

        match block_type {
            BlockType::Metadata => sbh.txn_meta_block = 0,
            BlockType::Data => sbh.txn_data_block = 0,
            BlockType::Links => sbh.txn_link_block = 0,
            BlockType::ListOfLinks => sbh.txn_list_of_links_block = 0,
        }
        sbh.free_blocks += 1;
        self.save_superblock()
    }

    fn start_txn(&mut self, txn_type: u32, owner: EntryId) -> Result<()> {
        let superblock = self.blockcache.get_mut(0);
        let sbh = superblock
            .block_mut()
            .get_mut_at_offset::<SuperblockHeader>(0);
        assert_eq!(TXN_TYPE_NONE, sbh.txn_type);
        assert_eq!(0, sbh.txn_blocks_owner);
        assert_eq!(0, sbh.txn_meta_block);
        assert_eq!(0, sbh.txn_data_block);
        assert_eq!(0, sbh.txn_link_block);
        assert_eq!(0, sbh.txn_list_of_links_block);
        sbh.txn_blocks_owner = owner.block_no;
        sbh.txn_type = txn_type;

        self.save_superblock()
    }

    fn commit_txn(&mut self) -> Result<()> {
        let superblock = self.blockcache.get_mut(0);
        let sbh = superblock
            .block_mut()
            .get_mut_at_offset::<SuperblockHeader>(0);
        sbh.txn_meta_block = 0;
        sbh.txn_data_block = 0;
        sbh.txn_link_block = 0;
        sbh.txn_list_of_links_block = 0;
        sbh.txn_blocks_owner = 0;
        sbh.txn_type = TXN_TYPE_NONE;
        self.save_superblock()
    }
}
