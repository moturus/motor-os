// Filesystem. The API is biased for convenience, which in practical terms
// means that there is a single mutable object representing the filesystem,
// and the rest are immutable clone-able and copy-able that do not borrow.
// This makes dealing with the borrow checker trivial.

use core::ptr::copy_nonoverlapping;

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::String;

use crate::block_cache::BlockCache;

use super::*;

pub(crate) fn format(block_device: &mut dyn SyncBlockDevice) -> Result<(), FsError> {
    let num_blocks = block_device.num_blocks();
    if num_blocks < 2 {
        return Err(FsError::InvalidArgument);
    }

    // We use u64::MAX as a marker for None.
    let num_blocks = num_blocks.min(u64::MAX - 1);

    // Write the first block.
    let mut block = Block::new_zeroed();
    unsafe {
        let fbh = block.get_mut::<SuperblockHeader>();
        fbh.magic = MAGIC;
        fbh.version = 1;
        fbh.num_blocks = num_blocks;
        fbh.free_blocks = num_blocks - 2;
        fbh.generation = 1;
        fbh.empty_area_start = 2; // 0 => this; 1 => root dir.
        fbh.set_crc32();
        fbh.validate()?;
    }
    block_device.write_block(0, block.as_bytes())?;

    // Write the root directory.
    unsafe {
        let root_dir = block.get_mut::<EntryMetadata>();
        *root_dir = EntryMetadata::new(ROOT_DIR_ID, ROOT_DIR_ID);
        root_dir.set_crc32();
    }
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
    superblock: Superblock,
    blockcache: BlockCache,
    num_blocks: u64,
    error: Result<(), FsError>, // If set, the FS is corrupted and cannot be used.
}

impl SyncFileSystem {
    pub const fn root_dir_id() -> EntryId {
        ROOT_DIR_ID
    }

    pub fn num_blocks(&self) -> u64 {
        self.num_blocks
    }

    pub fn empty_blocks(&self) -> u64 {
        self.superblock.header().free_blocks
    }

    pub fn open_fs(mut block_device: Box<dyn SyncBlockDevice>) -> Result<Self, FsError> {
        let mut block = Box::new(Block::new_uninit());
        block_device.read_block(0, block.as_bytes_mut())?;
        let superblock = Superblock::from(block)?;

        let num_blocks = superblock.header().num_blocks;
        if num_blocks < 3 || num_blocks == u64::MAX || num_blocks > block_device.num_blocks() {
            return Err(FsError::InvalidArgument);
        }

        let fbh = superblock.header();
        if fbh.txn_meta_block != 0
            || fbh.txn_data_block != 0
            || fbh.txn_link_block != 0
            || fbh.txn_list_of_links_block != 0
        {
            todo!("roll back or commit the TXN")
        }

        Ok(Self {
            num_blocks,
            superblock,
            blockcache: BlockCache::new(block_device),
            error: Ok(()),
        })
    }

    /// Create a new file.
    pub fn add_file(&mut self, parent_id: EntryId, name: &str) -> Result<EntryId, FsError> {
        self.add_directory_entry(parent_id, name, true)
    }

    /// Create a new directory.
    pub fn add_directory(&mut self, parent_id: EntryId, name: &str) -> Result<EntryId, FsError> {
        self.add_directory_entry(parent_id, name, false)
    }

    // Returns parent size.
    fn validate_new_entry(&mut self, parent_id: EntryId, name: &str) -> Result<(), FsError> {
        self.error?;
        validate_filename(name)?;
        if parent_id.block_no >= self.num_blocks || parent_id.block_no < 1 {
            return Err(FsError::InvalidArgument);
        }
        if self.find_entry_by_name(parent_id, name).is_ok() {
            return Err(FsError::AlreadyExists);
        }

        let parent_block = self.blockcache.read(parent_id.block_no)?;
        let meta = unsafe { parent_block.block().get::<EntryMetadata>() };
        meta.validate_dir(parent_id)?;
        if meta.size == MAX_DIR_ENTRIES {
            return Err(FsError::TooLarge);
        }

        Ok(())
    }

    // Must be inside a transaction. Inner => no need to poison self.
    fn add_directory_entry_inner(
        &mut self,
        parent_id: EntryId,
        child_id: EntryId,
        child_name: &str,
    ) -> Result<(), FsError> {
        let sbh = self.superblock.header();
        assert_ne!(TXN_TYPE_NONE, sbh.txn_type);
        let parent_block = self.blockcache.get(parent_id.block_no);
        let meta = unsafe { parent_block.block().get::<EntryMetadata>() };
        let prev_size = meta.size;

        // Update the parent dir.
        if prev_size < MAX_ENTRIES_IN_META_BLOCK as u64 {
            // Stick the new block entry into the meta block.
            let parent_block = self.blockcache.get_mut(parent_id.block_no);
            let meta = unsafe { parent_block.block_mut().get_mut::<EntryMetadata>() };
            meta.size += 1;
            meta.set_crc32();
            parent_block
                .block_mut()
                .set_dir_entry((prev_size + 1) as usize, child_id, child_name);
            self.blockcache.write(parent_id.block_no)?;
        } else if prev_size < MAX_ENTRIES_ONLY_DATA_BLOCKS {
            let need_new_block = prev_size == MAX_ENTRIES_IN_META_BLOCK
                || (prev_size % MAX_ENTRIES_IN_DATA_BLOCK == 0);
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

                        *data_block.block_mut().get_dir_entry_mut(idx) =
                            *source_block.get_dir_entry(idx + 1);
                    }

                    data_block.block_mut().set_dir_entry(
                        MAX_ENTRIES_IN_META_BLOCK as usize,
                        child_id,
                        child_name,
                    );
                } else {
                    let data_block = self.blockcache.get_block_uninit(data_block_no);
                    data_block
                        .block_mut()
                        .set_dir_entry(0, child_id, child_name);
                }
                self.blockcache.write(data_block_no)?;

                // Update the parent.
                let parent_block = self.blockcache.get_mut(parent_id.block_no);
                let meta = unsafe { parent_block.block_mut().get_mut::<EntryMetadata>() };
                meta.size += 1;
                meta.set_crc32();
                parent_block
                    .block_mut()
                    .set_datablock_no_in_meta(prev_size / MAX_ENTRIES_IN_DATA_BLOCK, data_block_no);
                self.blockcache.write(parent_id.block_no)?;
            } else {
                // Update an existing data block.
                let data_block_idx = prev_size / MAX_ENTRIES_IN_DATA_BLOCK;
                let parent_block = self.blockcache.get(parent_id.block_no);
                let data_block_no = parent_block
                    .block()
                    .get_datablock_no_in_meta(data_block_idx);
                let data_block = self.blockcache.read_mut(data_block_no)?;
                data_block.block_mut().set_dir_entry(
                    (prev_size % MAX_ENTRIES_IN_DATA_BLOCK) as usize,
                    child_id,
                    child_name,
                );
                self.blockcache.write(data_block_no)?;
                self.plus_one(parent_id.block_no)?;
            }
        } else {
            let need_new_data_block = prev_size % MAX_ENTRIES_IN_DATA_BLOCK == 0;
            let need_new_list_block = prev_size == MAX_ENTRIES_ONLY_DATA_BLOCKS
                || (prev_size % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST == 0);

            if need_new_data_block {
                // Allocate a new data block.
                let data_block_no = self.allocate_txn_block(BlockType::Data)?;
                let data_block = self.blockcache.get_block_uninit(data_block_no);
                data_block
                    .block_mut()
                    .set_dir_entry(0, child_id, child_name);
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

                            link_block.block_mut().set_datablock_no_in_link(
                                idx,
                                source_block.get_datablock_no_in_meta(idx),
                            );
                        }

                        link_block
                            .block_mut()
                            .set_datablock_no_in_link(MAX_LINKS_IN_META_BLOCK, data_block_no);
                    } else {
                        let link_block = self.blockcache.get_block_uninit(link_block_no);
                        link_block
                            .block_mut()
                            .set_datablock_no_in_link(0, data_block_no);
                    }
                    self.blockcache.write(link_block_no)?;
                    // Update the parent.
                    let parent_block = self.blockcache.get_mut(parent_id.block_no);
                    let meta = unsafe { parent_block.block_mut().get_mut::<EntryMetadata>() };
                    meta.size += 1;
                    meta.set_crc32();
                    parent_block.block_mut().set_datablock_no_in_meta(
                        prev_size / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST,
                        link_block_no,
                    );
                    self.blockcache.write(parent_id.block_no)?;
                } else {
                    // Update the link block.
                    let link_block_idx = prev_size / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST;
                    let parent_block = self.blockcache.get(parent_id.block_no);
                    let link_block_no = parent_block
                        .block()
                        .get_datablock_no_in_meta(link_block_idx);
                    let link_block = self.blockcache.read_mut(link_block_no)?;
                    let data_block_idx = (prev_size % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST)
                        / MAX_ENTRIES_IN_DATA_BLOCK;
                    link_block
                        .block_mut()
                        .set_datablock_no_in_link(data_block_idx, data_block_no);
                    self.blockcache.write(link_block_no)?;
                    self.plus_one(parent_id.block_no)?;
                }
            } else {
                // Update an existing data block.
                let link_block_idx = prev_size / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST;
                let parent_block = self.blockcache.get(parent_id.block_no);
                let link_block_no = parent_block
                    .block()
                    .get_datablock_no_in_meta(link_block_idx);
                let link_block = self.blockcache.read(link_block_no)?;
                let data_block_idx = (prev_size % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST)
                    / MAX_ENTRIES_IN_DATA_BLOCK;
                let data_block_no = link_block.block().get_datablock_no_in_link(data_block_idx);

                let data_block = self.blockcache.read_mut(data_block_no)?;
                data_block.block_mut().set_dir_entry(
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
    ) -> Result<EntryId, FsError> {
        self.error?;
        self.validate_new_entry(parent_id, name)?;

        // Steps:
        // - get a free block
        // - write the new EntryMetadata into it; (crash here: whatever)
        // - mark the block as busy in the parent dir; (crash here: check the parent dir upon bootup)
        // - add the block to the parent dir; (crash here: check the parent dir upon bootup)
        // - commit: clear the busy block.

        // Get a new generation (no save).
        let mut generation = self.superblock.header().generation + 1;
        if is_file && ((generation & 1) == 1) {
            generation += 1; // Files must have EVEN generations.
        }
        if (!is_file) && ((generation & 1) == 0) {
            generation += 1; // Directories must have ODD generations.
        }

        let sbh = self.superblock.header_mut();
        sbh.generation = generation;
        self.start_txn(TXN_TYPE_ADD_NODE, parent_id)?;

        // Get a new block.
        let block_no = self.allocate_txn_block(BlockType::Metadata)?;

        // Write the new block.
        let new_id = EntryId::new(block_no, generation);
        let meta_block = self.blockcache.get_block_uninit(block_no);
        let meta = unsafe { meta_block.block_mut().get_mut::<EntryMetadata>() };
        *meta = EntryMetadata::new(new_id, parent_id);
        meta.size = 0;
        meta.set_crc32();
        self.blockcache.write(block_no)?;

        self.add_directory_entry_inner(parent_id, new_id, name)
            .map_err(|e| {
                let _ = self.make_error();
                e
            })?;

        // Commit.
        self.commit_txn()?;
        Ok(new_id)
    }

    /// Get a specific directory entry (child).
    pub fn get_directory_entry(&mut self, parent: EntryId, pos: u64) -> Result<DirEntry, FsError> {
        self.error?;
        let parent_block = self.blockcache.read(parent.block_no)?;
        let meta = unsafe { parent_block.block().get::<EntryMetadata>() };
        meta.validate_dir(parent)?;
        let num_entries = meta.size;

        if pos as u64 >= meta.size {
            return Err(FsError::NotFound);
        }

        if num_entries <= MAX_ENTRIES_IN_META_BLOCK {
            return parent_block
                .block()
                .get_dir_entry((pos + 1) as usize)
                .to_owned();
        }

        if num_entries <= MAX_ENTRIES_ONLY_DATA_BLOCKS {
            let data_block_idx = pos / MAX_ENTRIES_IN_DATA_BLOCK;
            let data_block_no = parent_block
                .block()
                .get_datablock_no_in_meta(data_block_idx);
            return self
                .blockcache
                .read(data_block_no)?
                .block()
                .get_dir_entry((pos % MAX_ENTRIES_IN_DATA_BLOCK) as usize)
                .to_owned();
        }

        let link_block_idx = pos / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST;
        let link_block_no = parent_block
            .block()
            .get_datablock_no_in_meta(link_block_idx);

        let link_block = self.blockcache.read(link_block_no)?;
        let data_block_idx =
            (pos % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST) / MAX_ENTRIES_IN_DATA_BLOCK;
        let data_block_no = link_block.block().get_datablock_no_in_link(data_block_idx);

        return self
            .blockcache
            .read(data_block_no)?
            .block()
            .get_dir_entry((pos % MAX_ENTRIES_IN_DATA_BLOCK) as usize)
            .to_owned();
    }

    pub fn get_directory_entry_by_name(
        &mut self,
        parent: EntryId,
        name: &str,
    ) -> Result<DirEntry, FsError> {
        self.error?;
        let (block_no, entry_pos) = self.find_entry_by_name(parent, name)?;
        let block = self.blockcache.read(block_no).unwrap();
        Ok(block.block().get_dir_entry(entry_pos).to_owned()?)
    }

    /// Get the number of directory entries (children).
    pub fn get_num_entries(&mut self, dir: EntryId) -> Result<u64, FsError> {
        self.error?;
        let block = self.blockcache.read(dir.block_no)?;
        let meta = unsafe { block.block().get::<EntryMetadata>() };
        meta.validate_dir(dir)?;

        Ok(meta.size as u64)
    }

    /// Get file size.
    pub fn get_file_size(&mut self, file: EntryId) -> Result<u64, FsError> {
        self.error?;
        let block = self.blockcache.read(file.block_no)?;
        let meta = unsafe { block.block().get::<EntryMetadata>() };
        meta.validate_file(file)?;

        Ok(meta.size)
    }

    pub fn stat(&mut self, entry: EntryId) -> Result<Attr, FsError> {
        self.error?;
        let block = self.blockcache.read(entry.block_no)?;
        let meta = unsafe { block.block().get::<EntryMetadata>() };
        meta.validate(entry)?;

        Ok(meta.into())
    }

    pub fn set_file_size(&mut self, file_id: EntryId, new_size: u64) -> Result<(), FsError> {
        self.error?;

        // Go block by block, from the end.
        loop {
            let metadata_block = self.blockcache.read(file_id.block_no)?;
            let meta = unsafe { metadata_block.block().get::<EntryMetadata>() };
            meta.validate_file(file_id)?;
            let prev_size = meta.size;
            if new_size > prev_size {
                return Err(FsError::InvalidArgument);
            }
            if new_size == prev_size {
                return Ok(());
            }

            let mid_size = (prev_size - 1) & !(BLOCK_SIZE - 1);
            debug_assert!(mid_size < prev_size);
            debug_assert!((prev_size - mid_size) <= BLOCK_SIZE);
            debug_assert_eq!(0, mid_size & (BLOCK_SIZE - 1));

            // A special case.
            let mid_size = if prev_size > MAX_BYTES_IN_META_BLOCK
                && prev_size <= BLOCK_SIZE
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
                let meta = unsafe { metadata_block.block_mut().get_mut::<EntryMetadata>() };
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
                let data_block_no = meta_block.block().get_datablock_no_in_meta(block_idx);

                // TODO: we probably don't need a TXN here: will save a couple of block writes?
                self.start_txn(TXN_TYPE_REMOVE_BYTES, file_id)?;
                self.superblock.header_mut().txn_data_block = data_block_no;
                self.save_superblock()?;

                let metadata_block = self.blockcache.get_mut(file_id.block_no);
                let meta = unsafe { metadata_block.block_mut().get_mut::<EntryMetadata>() };
                meta.size = mid_size;
                meta.set_crc32();
                self.blockcache.write(file_id.block_no)?;

                if (mid_size <= MAX_BYTES_IN_META_BLOCK) && (mid_size > 0) {
                    let data = *self.blockcache.read(data_block_no)?.block();
                    unsafe {
                        let metadata_block = self.blockcache.get_mut(file_id.block_no);
                        copy_nonoverlapping(
                            data.as_bytes().as_ptr(),
                            metadata_block
                                .block_mut()
                                .as_data_bytes_in_meta_mut()
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
                let link_block_no = meta_block.block().get_datablock_no_in_meta(link_block_idx);

                let link_block = self.blockcache.read(link_block_no)?;
                let data_block_idx =
                    (mid_size & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1)) >> BLOCK_SIZE.ilog2();
                let data_block_no = link_block.block().get_datablock_no_in_link(data_block_idx);

                let need_to_free_link_block =
                    (data_block_idx == 0) || (mid_size == MAX_BYTES_ONLY_DATA_BLOCKS);

                self.start_txn(TXN_TYPE_REMOVE_BYTES, file_id)?;
                self.superblock.header_mut().txn_data_block = data_block_no;
                if need_to_free_link_block {
                    self.superblock.header_mut().txn_link_block = link_block_no;
                }
                self.save_superblock()?;

                let metadata_block = self.blockcache.get_mut(file_id.block_no);
                let meta = unsafe { metadata_block.block_mut().get_mut::<EntryMetadata>() };
                meta.size = mid_size;
                meta.set_crc32();
                self.blockcache.write(file_id.block_no)?;

                if mid_size == MAX_BYTES_ONLY_DATA_BLOCKS {
                    let links = *self.blockcache.get(link_block_no).block();
                    let metadata_block = self.blockcache.get_mut(file_id.block_no);
                    for idx in 0..MAX_LINKS_IN_META_BLOCK {
                        metadata_block
                            .block_mut()
                            .set_datablock_no_in_meta(idx, links.get_datablock_no_in_link(idx));
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
            let list_of_links_block_no = meta_block
                .block()
                .get_datablock_no_in_meta(list_of_links_block_idx);

            let link_block_idx = (mid_size & (BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST - 1))
                >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
            let list_of_links_block = self.blockcache.read(list_of_links_block_no)?;
            let link_block_no = list_of_links_block
                .block()
                .get_datablock_no_in_link(link_block_idx);

            let link_block = self.blockcache.read(link_block_no)?;
            let data_block_idx =
                (mid_size & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1)) >> BLOCK_SIZE.ilog2();
            let data_block_no = link_block.block().get_datablock_no_in_link(data_block_idx);

            let need_to_free_link_block = data_block_idx == 0;
            let need_to_free_list_of_links_block = need_to_free_link_block
                && ((link_block_idx == 0) || (mid_size == MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS));

            self.start_txn(TXN_TYPE_REMOVE_BYTES, file_id)?;
            self.superblock.header_mut().txn_data_block = data_block_no;
            if need_to_free_link_block {
                self.superblock.header_mut().txn_link_block = link_block_no;
            }
            if need_to_free_list_of_links_block {
                self.superblock.header_mut().txn_list_of_links_block = list_of_links_block_no;
            }
            self.save_superblock()?;

            let metadata_block = self.blockcache.get_mut(file_id.block_no);
            let meta = unsafe { metadata_block.block_mut().get_mut::<EntryMetadata>() };
            meta.size = mid_size;
            meta.set_crc32();
            self.blockcache.write(file_id.block_no)?;

            if mid_size == MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS {
                let list_of_links = *self.blockcache.get(list_of_links_block_no).block();
                let metadata_block = self.blockcache.get_mut(file_id.block_no);
                for idx in 0..MAX_LINKS_IN_META_BLOCK {
                    metadata_block
                        .block_mut()
                        .set_datablock_no_in_meta(idx, list_of_links.get_datablock_no_in_link(idx));
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

    pub fn get_parent(&mut self, entry_id: EntryId) -> Result<Option<EntryId>, FsError> {
        if entry_id == ROOT_DIR_ID {
            return Ok(None);
        }

        let block = self.blockcache.read(entry_id.block_no)?;
        let meta = unsafe { block.block().get::<EntryMetadata>() };
        meta.validate(entry_id)?;

        Ok(Some(meta.parent_id))
    }

    pub fn get_name(&mut self, entry_id: EntryId) -> Result<String, FsError> {
        if entry_id == ROOT_DIR_ID {
            return Ok("/".to_owned());
        }

        let block = self.blockcache.read(entry_id.block_no)?;
        let meta = unsafe { block.block().get::<EntryMetadata>() };

        meta.validate(entry_id)?;

        let parent_id = meta.parent_id;
        let (block_no, entry_pos) = self.find_entry_by_id(parent_id, entry_id)?;
        let block = self.blockcache.get(block_no);
        let dir_entry = block.block().get_dir_entry(entry_pos);
        Ok(dir_entry.to_owned()?.name)
    }

    pub fn move_rename(
        &mut self,
        entry_id: EntryId,
        new_parent: EntryId,
        new_name: &str,
    ) -> Result<(), FsError> {
        self.error?;
        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(entry_id).unwrap();
            let block = self.blockcache.read(new_parent.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(new_parent).unwrap();
        }
        self.validate_new_entry(new_parent, new_name)?;
        if entry_id.block_no == ROOT_DIR_ID.block_no {
            return Err(FsError::InvalidArgument);
        }
        let block = self.blockcache.read(entry_id.block_no)?;
        let meta = unsafe { block.block().get::<EntryMetadata>() };
        meta.validate(entry_id)?;
        let old_parent = meta.parent_id;

        if old_parent == new_parent {
            let (block_no, entry_pos) = self.find_entry_by_id(old_parent, entry_id)?;
            let block = self.blockcache.get_mut(block_no);
            block
                .block_mut()
                .get_dir_entry_mut(entry_pos)
                .set_name(new_name);
            self.blockcache.write(block_no)?;
            return Ok(());
        }

        self.start_txn(TXN_TYPE_MOVE, old_parent)?;
        self.superblock.header_mut().txn_meta_block = entry_id.block_no;
        self.save_superblock()?;

        let block = self.blockcache.get_mut(entry_id.block_no);
        let meta = unsafe { block.block_mut().get_mut::<EntryMetadata>() };
        meta.parent_id = new_parent;
        meta.set_crc32();
        self.blockcache.write(entry_id.block_no)?;

        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(entry_id).unwrap();
        }

        // Move to the new parent.
        self.add_directory_entry_inner(new_parent, entry_id, new_name)
            .map_err(|e| {
                let _ = self.make_error();
                e
            })?;

        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(entry_id).unwrap();
            let block = self.blockcache.read(old_parent.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(old_parent).unwrap();
            let block = self.blockcache.read(new_parent.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(new_parent).unwrap();
        }

        // Clear newly added blocks, if any (can find them from the meta block).
        let sbh = self.superblock.header_mut();
        sbh.txn_data_block = 0;
        sbh.txn_link_block = 0;
        sbh.txn_list_of_links_block = 0;

        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(entry_id).unwrap();
        }

        self.remove_directory_entry_inner(old_parent, entry_id)
            .map_err(|e| {
                let _ = self.make_error();
                e
            })?;
        if self.superblock.header().txn_link_block != 0 {
            self.free_txn_block(BlockType::Links)?;
        }
        if self.superblock.header().txn_data_block != 0 {
            self.free_txn_block(BlockType::Data)?;
        }

        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(entry_id).unwrap();
            let block = self.blockcache.read(old_parent.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(old_parent).unwrap();
            let block = self.blockcache.read(new_parent.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(new_parent).unwrap();
        }

        self.commit_txn()?;
        #[cfg(debug_assertions)]
        {
            let block = self.blockcache.read(entry_id.block_no)?;
            let meta = unsafe { block.block().get::<EntryMetadata>() };
            meta.validate(entry_id).unwrap();
        }

        Ok(())
    }

    pub fn remove(&mut self, entry_id: EntryId) -> Result<(), FsError> {
        self.error?;
        if entry_id.block_no == ROOT_DIR_ID.block_no {
            return Err(FsError::InvalidArgument);
        }
        let block = self.blockcache.read(entry_id.block_no)?;
        let meta = unsafe { block.block().get::<EntryMetadata>() };
        meta.validate(entry_id)?;
        if meta.size > 0 {
            // Cannot delete a non-empty directory or a file with data.
            // First clean the directory or truncate the file.
            #[cfg(debug_assertions)]
            log::debug!("srfs-core: remove failed: non-empty entry");
            return Err(FsError::TooLarge);
        }
        let parent_id = meta.parent_id;

        // Pre-commit: mark the block we are removing as dirty.
        self.start_txn(TXN_TYPE_REMOVE_NODE, parent_id)?;
        let fbh = self.superblock.header_mut();
        assert_eq!(0, fbh.txn_meta_block);
        fbh.txn_meta_block = entry_id.block_no;

        self.remove_directory_entry_inner(parent_id, entry_id)
            .map_err(|e| {
                let _ = self.make_error();
                e
            })?;

        // Commit.
        if self.superblock.header().txn_link_block != 0 {
            self.free_txn_block(BlockType::Links)?;
        }
        if self.superblock.header().txn_data_block != 0 {
            self.free_txn_block(BlockType::Data)?;
        }
        self.free_txn_block(BlockType::Metadata)?;
        self.commit_txn()
    }

    // Must be inside a transaction. Inner => no need to poison self.
    fn remove_directory_entry_inner(
        &mut self,
        parent_id: EntryId,
        child: EntryId,
    ) -> Result<(), FsError> {
        let sbh = self.superblock.header();
        assert_ne!(TXN_TYPE_NONE, sbh.txn_type);

        // Need to put the last entry into the place occupied by this entry.
        let (entry_block_no, entry_pos) = self.find_entry_by_id(parent_id, child)?;

        // Need to read instead of get because the find above may flush the cache.
        let parent_block = self.blockcache.read(parent_id.block_no)?;
        let parent_meta = unsafe { parent_block.block().get::<EntryMetadata>() };
        parent_meta.validate_dir(parent_id)?;
        let num_entries = parent_meta.size;
        if num_entries <= MAX_ENTRIES_IN_META_BLOCK {
            assert_eq!(entry_block_no, parent_id.block_no);
            // Only the parent_block needs changing.
            if (entry_pos as u64) < num_entries {
                let parent_block = self.blockcache.get_mut(parent_id.block_no);
                let last_entry = *parent_block.block().get_dir_entry(num_entries as usize);
                *parent_block.block_mut().get_dir_entry_mut(entry_pos) = last_entry;
            }
        } else if num_entries <= MAX_ENTRIES_ONLY_DATA_BLOCKS {
            let last_entry_block_idx = (num_entries - 1) / MAX_ENTRIES_IN_DATA_BLOCK;
            let last_entry_block_no = parent_block
                .block()
                .get_datablock_no_in_meta(last_entry_block_idx);
            let last_entry_idx = ((num_entries - 1) % MAX_ENTRIES_IN_DATA_BLOCK) as usize;

            if (entry_block_no, entry_pos) != (last_entry_block_no, last_entry_idx) {
                let last_entry_block = self.blockcache.read(last_entry_block_no)?;
                let last_entry = *last_entry_block.block().get_dir_entry(last_entry_idx);
                let entry_block = self.blockcache.read_mut(entry_block_no)?;
                *entry_block.block_mut().get_dir_entry_mut(entry_pos) = last_entry;
                self.blockcache.write(entry_block_no)?;
            }

            if last_entry_idx == 0 {
                // We need to free last_entry_block.
                let fbh = self.superblock.header_mut();
                assert_eq!(0, fbh.txn_data_block);
                fbh.txn_data_block = last_entry_block_no;
                self.save_superblock()?; // TODO: do we need this?
            }

            if num_entries == (MAX_ENTRIES_IN_META_BLOCK + 1) {
                // Move all entries into the parent meta block.
                let entry_block = *self.blockcache.get(entry_block_no).block();
                let parent_block = self.blockcache.get_mut(parent_id.block_no);
                for idx in 0..(MAX_ENTRIES_IN_META_BLOCK as usize) {
                    *parent_block.block_mut().get_dir_entry_mut(idx + 1) =
                        *entry_block.get_dir_entry(idx);
                }
                // Note: parent_block is not saved here, will be saved below.

                // Free the last block.
                let fbh = self.superblock.header_mut();
                assert_eq!(0, fbh.txn_data_block);
                fbh.txn_data_block = last_entry_block_no;
                self.save_superblock()?; // TODO: do we need this?
            }
        } else {
            let last_link_block_no = parent_block.block().get_datablock_no_in_meta(
                (num_entries - 1) / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST,
            );

            let last_link_block = self.blockcache.read(last_link_block_no)?;
            let last_entry_block_idx = ((num_entries - 1)
                % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST)
                / MAX_ENTRIES_IN_DATA_BLOCK;
            let last_entry_block_no = last_link_block
                .block()
                .get_datablock_no_in_link(last_entry_block_idx);
            let last_entry_idx = ((num_entries - 1) % MAX_ENTRIES_IN_DATA_BLOCK) as usize;

            if (entry_block_no, entry_pos) != (last_entry_block_no, last_entry_idx) {
                let last_entry_block = self.blockcache.read(last_entry_block_no)?;
                let last_entry = *last_entry_block.block().get_dir_entry(last_entry_idx);
                let entry_block = self.blockcache.read_mut(entry_block_no)?;
                *entry_block.block_mut().get_dir_entry_mut(entry_pos) = last_entry;
                self.blockcache.write(entry_block_no)?;
            }

            if last_entry_idx == 0 {
                // We need to free last_entry_block.
                let fbh = self.superblock.header_mut();
                assert_eq!(0, fbh.txn_data_block);
                fbh.txn_data_block = last_entry_block_no;
                self.save_superblock()?; // TODO: do we need this?
            }

            if num_entries == (MAX_ENTRIES_ONLY_DATA_BLOCKS + 1) {
                // Move all links into the parent meta block.
                let link_block = self.blockcache.get(last_link_block_no);
                let links: Block = *link_block.block();
                let parent_block = self.blockcache.get_mut(parent_id.block_no);
                for idx in 0..MAX_LINKS_IN_META_BLOCK {
                    parent_block
                        .block_mut()
                        .set_datablock_no_in_meta(idx, links.get_datablock_no_in_link(idx));
                }
                // Note: parent_block is not saved here, will be saved below.

                // Free the link block.
                let fbh = self.superblock.header_mut();
                assert_eq!(0, fbh.txn_link_block);
                fbh.txn_link_block = last_link_block_no;
                self.save_superblock()?; // TODO: do we need this?
            }

            if (num_entries % MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST) == 1 {
                // Free the link block.
                let fbh = self.superblock.header_mut();
                assert_eq!(0, fbh.txn_link_block);
                fbh.txn_link_block = last_link_block_no;
                self.save_superblock()?; // TODO: do we need this?
            }
        }

        let parent_block = self.blockcache.get_mut(parent_id.block_no);
        let parent_meta = unsafe { parent_block.block_mut().get_mut::<EntryMetadata>() };
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
    pub fn write(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        self.error?;
        if file_id.kind() != EntryKind::File {
            return Err(FsError::InvalidArgument);
        }
        let meta_block = self.blockcache.read(file_id.block_no)?;
        let meta = unsafe { meta_block.block().get::<EntryMetadata>() };
        meta.validate_file(file_id)?;
        let prev_size = meta.size;
        if offset > prev_size {
            return Err(FsError::InvalidArgument);
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
            let meta = unsafe { meta_block.block_mut().get_mut::<EntryMetadata>() };

            meta.size = new_size;
            meta.set_crc32();
            unsafe {
                copy_nonoverlapping(
                    buf.as_ptr(),
                    (meta_block
                        .block_mut()
                        .as_data_bytes_in_meta_mut()
                        .as_mut_ptr() as usize
                        + (offset as usize)) as *mut u8,
                    (new_end - offset) as usize,
                );
            }
            self.blockcache.write(file_id.block_no).map_err(|e| {
                let _ = self.make_error();
                e
            })?;
            return Ok((new_end - offset) as usize);
        }

        if new_size == prev_size {
            return self.update_file(file_id, offset, buf);
        } else {
            return self.append(file_id, offset, buf);
        }
    }

    pub fn read(
        &mut self,
        file_id: EntryId,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, FsError> {
        self.error?;
        if file_id.kind() != EntryKind::File {
            return Err(FsError::InvalidArgument);
        }
        let meta_block = self.blockcache.read(file_id.block_no)?;
        let meta = unsafe { meta_block.block().get::<EntryMetadata>() };
        meta.validate_file(file_id)?;
        let file_size = meta.size;
        if offset >= file_size {
            return Ok(0);
        }
        let end = file_size.min(offset + (buf.len() as u64));
        if file_size <= (MAX_BYTES_IN_META_BLOCK as u64) {
            // We are still in the main block.
            unsafe {
                copy_nonoverlapping(
                    (meta_block.block().as_data_bytes_in_meta().as_ptr() as usize
                        + (offset as usize)) as *const u8,
                    buf.as_mut_ptr(),
                    (end - offset) as usize,
                );
            }
            return Ok((end - offset) as usize);
        }

        let data_block_no = self.find_data_block(file_id, offset)?;
        let block_end = align_up(offset + 1, BLOCK_SIZE);
        let new_end = (offset + (buf.len() as u64)).min(block_end);
        let data_block = self.blockcache.read(data_block_no)?;
        unsafe {
            copy_nonoverlapping(
                (data_block.block().as_bytes().as_ptr() as usize
                    + ((offset & (BLOCK_SIZE - 1)) as usize)) as *const u8,
                buf.as_mut_ptr(),
                (new_end - offset) as usize,
            );
        }
        return Ok((new_end - offset) as usize);
    }

    fn append(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        self.error?;
        // We may potentially need to allocate three new blocks:
        // - a new data block
        // - a new 1st level (leaf) blocklist block
        // - a new 2nd level blocklist block
        let meta_block = self.blockcache.get(file_id.block_no);
        let meta = unsafe { meta_block.block().get::<EntryMetadata>() };
        let prev_size = meta.size;
        assert_eq!(prev_size, offset);
        let new_size = if align_up(prev_size + 1, BLOCK_SIZE) >= prev_size + (buf.len() as u64) {
            prev_size + (buf.len() as u64)
        } else {
            align_up(prev_size + 1, BLOCK_SIZE)
        };

        // Special case 1: going from data in meta block to a separate data block.
        if prev_size <= MAX_BYTES_IN_META_BLOCK {
            assert!(new_size > MAX_BYTES_IN_META_BLOCK); // The caller handles in-meta writes.

            // Cache the address of the bytes, to fool the borrow checker.
            let prev_bytes_start = meta_block.block().as_data_bytes_in_meta().as_ptr() as usize;

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
            self.blockcache.write(data_block_no).map_err(|e| {
                let _ = self.make_error();
                e
            })?;

            // Update the meta.
            let meta_block = self.blockcache.get_mut(file_id.block_no);
            meta_block
                .block_mut()
                .set_datablock_no_in_meta(0, data_block_no);
            let meta = unsafe { meta_block.block_mut().get_mut::<EntryMetadata>() };
            meta.size = new_size;
            meta.set_crc32();
            self.blockcache.write(file_id.block_no).map_err(|e| {
                let _ = self.make_error();
                e
            })?;

            // Commit the txn.
            self.commit_txn()?;
            return Ok((new_size - prev_size) as usize);
        }

        if align_up(prev_size, BLOCK_SIZE) >= new_size {
            // The write goes to an existing data block - no TXN is necessary.
            let data_block_no = self.find_data_block(file_id, prev_size - 1)?;

            // Copy bytes.
            let data_block = self.blockcache.read_mut(data_block_no)?;
            unsafe {
                copy_nonoverlapping(
                    buf.as_ptr(),
                    (data_block.block_mut().as_bytes_mut().as_mut_ptr() as usize
                        + (offset & (BLOCK_SIZE - 1)) as usize) as *mut u8,
                    (new_size - prev_size) as usize,
                );
            }
            self.blockcache.write(data_block_no)?;

            // Update meta.
            let meta_block = self.blockcache.get_mut(file_id.block_no);
            let meta = unsafe { meta_block.block_mut().get_mut::<EntryMetadata>() };
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
        debug_assert_eq!(0, offset & (BLOCK_SIZE - 1));
        unsafe {
            copy_nonoverlapping(
                buf.as_ptr(),
                data_block.block_mut().as_bytes_mut().as_mut_ptr(),
                (new_size - prev_size) as usize,
            );
        }
        self.blockcache.write(data_block_no).map_err(|e| {
            let _ = self.make_error();
            e
        })?;

        if new_size <= MAX_BYTES_ONLY_DATA_BLOCKS {
            // Update the meta.
            let meta_block = self.blockcache.get_mut(file_id.block_no);
            meta_block
                .block_mut()
                .set_datablock_no_in_meta(prev_size >> BLOCK_SIZE.ilog2(), data_block_no);
        } else if new_size <= MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS {
            // Files of size between ~2M and ~1G.
            let need_new_link_block = (prev_size % BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST == 0)
                || (prev_size == MAX_BYTES_ONLY_DATA_BLOCKS);

            if need_new_link_block {
                let link_block_no = self.allocate_txn_block(BlockType::Links).map_err(|e| {
                    let _ = self.make_error();
                    e
                })?;

                let (link_block, data_block_idx) = if prev_size == MAX_BYTES_ONLY_DATA_BLOCKS {
                    let meta_block = *self.blockcache.get(file_id.block_no).block();
                    let bytes = meta_block.as_data_bytes_in_meta();
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

                link_block
                    .block_mut()
                    .set_datablock_no_in_link(data_block_idx, data_block_no);
                self.blockcache.write(link_block_no).map_err(|e| {
                    let _ = self.make_error();
                    e
                })?;

                let link_block_idx = prev_size >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
                let meta_block = self.blockcache.get_mut(file_id.block_no);
                meta_block
                    .block_mut()
                    .set_datablock_no_in_meta(link_block_idx, link_block_no);
            } else {
                let link_block_idx = prev_size >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
                let link_block_no = self
                    .blockcache
                    .get(file_id.block_no)
                    .block()
                    .get_datablock_no_in_meta(link_block_idx);
                let link_block = self.blockcache.read_mut(link_block_no);
                if let Err(err) = link_block {
                    let _ = self.make_error();
                    return Err(err);
                }
                let data_block_idx = (prev_size & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1))
                    >> BLOCK_SIZE.ilog2();
                link_block
                    .unwrap()
                    .block_mut()
                    .set_datablock_no_in_link(data_block_idx, data_block_no);
                self.blockcache.write(link_block_no).map_err(|e| {
                    let _ = self.make_error();
                    e
                })?;
            }
        } else {
            // ~1G+ files here.
            let need_new_list_of_links_block =
                (prev_size % BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST == 0)
                    || (prev_size == MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS);

            if need_new_list_of_links_block {
                // Always a new link block here.
                let link_block_no = self.allocate_txn_block(BlockType::Links).map_err(|e| {
                    let _ = self.make_error();
                    e
                })?;
                let link_block = self.blockcache.get_block_uninit(link_block_no);

                link_block
                    .block_mut()
                    .set_datablock_no_in_link(0, data_block_no);
                self.blockcache.write(link_block_no).map_err(|e| {
                    let _ = self.make_error();
                    e
                })?;

                let list_of_links_block_no = self
                    .allocate_txn_block(BlockType::ListOfLinks)
                    .map_err(|e| {
                        let _ = self.make_error();
                        e
                    })?;
                let (list_of_links_block, link_block_idx) =
                    if prev_size == MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS {
                        let meta_block = *self.blockcache.get(file_id.block_no).block();
                        let bytes = meta_block.as_data_bytes_in_meta();
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

                list_of_links_block
                    .block_mut()
                    .set_datablock_no_in_link(link_block_idx, link_block_no);
                self.blockcache.write(list_of_links_block_no).map_err(|e| {
                    let _ = self.make_error();
                    e
                })?;

                let list_of_links_block_idx =
                    prev_size >> BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST.ilog2();
                let meta_block = self.blockcache.get_mut(file_id.block_no);
                meta_block
                    .block_mut()
                    .set_datablock_no_in_meta(list_of_links_block_idx, list_of_links_block_no);
            } else {
                let list_of_links_block_idx =
                    prev_size >> BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST.ilog2();
                let list_of_links_block_no = self
                    .blockcache
                    .get(file_id.block_no)
                    .block()
                    .get_datablock_no_in_meta(list_of_links_block_idx);
                // Cache the block.
                if let Err(err) = self.blockcache.read(list_of_links_block_no) {
                    let _ = self.make_error();
                    return Err(err);
                }

                let need_new_link_block = prev_size % BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST == 0;
                let link_block_idx = (prev_size & (BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST - 1))
                    >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();

                if need_new_link_block {
                    let link_block_no = self.allocate_txn_block(BlockType::Links).map_err(|e| {
                        let _ = self.make_error();
                        e
                    })?;
                    let link_block = self.blockcache.get_block_uninit(link_block_no);

                    link_block
                        .block_mut()
                        .set_datablock_no_in_link(0, data_block_no);
                    self.blockcache.write(link_block_no).map_err(|e| {
                        let _ = self.make_error();
                        e
                    })?;

                    let list_of_links_block = self.blockcache.get_mut(list_of_links_block_no);
                    list_of_links_block
                        .block_mut()
                        .set_datablock_no_in_link(link_block_idx, link_block_no);
                    self.blockcache.write(list_of_links_block_no).map_err(|e| {
                        let _ = self.make_error();
                        e
                    })?;
                } else {
                    let link_block_no = self
                        .blockcache
                        .get(list_of_links_block_no)
                        .block()
                        .get_datablock_no_in_link(link_block_idx);
                    let link_block = self.blockcache.read_mut(link_block_no);
                    if let Err(err) = link_block {
                        let _ = self.make_error();
                        return Err(err);
                    }
                    let data_block_idx = (prev_size & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1))
                        >> BLOCK_SIZE.ilog2();
                    link_block
                        .unwrap()
                        .block_mut()
                        .set_datablock_no_in_link(data_block_idx, data_block_no);
                    self.blockcache.write(link_block_no).map_err(|e| {
                        let _ = self.make_error();
                        e
                    })?;
                }
            }
        }

        // Commit the txn.
        let meta_block = self.blockcache.get_mut(file_id.block_no);
        let meta = unsafe { meta_block.block_mut().get_mut::<EntryMetadata>() };
        meta.size = new_size;
        meta.set_crc32();
        self.blockcache.write(file_id.block_no).map_err(|e| {
            let _ = self.make_error();
            e
        })?;

        self.commit_txn()?;
        return Ok((new_size - prev_size) as usize);
    }

    fn update_file(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let data_block_no = self.find_data_block(file_id, offset)?;
        let block_end = align_up(offset + 1, BLOCK_SIZE);
        let new_end = (offset + (buf.len() as u64)).min(block_end);
        let data_block = self.blockcache.read_mut(data_block_no)?;
        unsafe {
            copy_nonoverlapping(
                buf.as_ptr(),
                (data_block.block_mut().as_bytes_mut().as_ptr() as usize
                    + ((offset & (BLOCK_SIZE - 1)) as usize)) as *mut u8,
                (new_end - offset) as usize,
            );
        }
        self.blockcache.write(data_block_no)?;
        return Ok((new_end - offset) as usize);
    }

    fn find_data_block(&mut self, file_id: EntryId, offset: u64) -> Result<u64, FsError> {
        let meta_block = self.blockcache.get(file_id.block_no);
        let meta = unsafe { meta_block.block().get::<EntryMetadata>() };
        let file_size = meta.size;
        debug_assert!(file_size > MAX_BYTES_IN_META_BLOCK);
        debug_assert!(offset < file_size);

        if file_size <= MAX_BYTES_ONLY_DATA_BLOCKS {
            // Files smaller than ~2M.
            let block_idx = offset >> BLOCK_SIZE.ilog2();

            let meta_block = self.blockcache.get(file_id.block_no);
            return Ok(meta_block.block().get_datablock_no_in_meta(block_idx));
        }

        if file_size <= MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS {
            // Files smaller than ~1G.
            let link_block_idx = offset >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
            let meta_block = self.blockcache.get(file_id.block_no);
            let link_block_no = meta_block.block().get_datablock_no_in_meta(link_block_idx);

            let link_block = self.blockcache.read(link_block_no)?;
            let data_block_idx =
                (offset & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1)) >> BLOCK_SIZE.ilog2();
            return Ok(link_block.block().get_datablock_no_in_link(data_block_idx));
        }

        // Files larger than ~1G.
        let list_of_links_block_idx = offset >> BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST.ilog2();
        let meta_block = self.blockcache.get(file_id.block_no);
        let list_of_links_block_no = meta_block
            .block()
            .get_datablock_no_in_meta(list_of_links_block_idx);

        let list_of_links_block = self.blockcache.read(list_of_links_block_no)?;
        let link_block_idx = (offset & (BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST - 1))
            >> BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST.ilog2();
        let link_block_no = list_of_links_block
            .block()
            .get_datablock_no_in_link(link_block_idx);

        let link_block = self.blockcache.read(link_block_no)?;
        let data_block_idx =
            (offset & (BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1)) >> BLOCK_SIZE.ilog2();
        return Ok(link_block.block().get_datablock_no_in_link(data_block_idx));
    }

    fn find_entry_by_id(
        &mut self,
        parent_id: EntryId,
        entry_id: EntryId,
    ) -> Result<(u64 /* block_no */, usize /* entry_pos */), FsError> {
        self.find_entry(parent_id, |e| e.id == entry_id)
    }

    fn find_entry_by_name(
        &mut self,
        parent_id: EntryId,
        name: &str,
    ) -> Result<(u64 /* block_no */, usize /* entry_pos */), FsError> {
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
    ) -> Result<(u64 /* block_no */, usize /* entry_pos */), FsError>
    where
        F: Fn(&DirEntryInternal) -> bool,
    {
        self.error?;
        let parent_block = self.blockcache.read(parent_id.block_no)?;
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
            let num_blocks =
                (num_entries + MAX_ENTRIES_IN_DATA_BLOCK - 1) / MAX_ENTRIES_IN_DATA_BLOCK;
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

        let num_link_blocks = (num_entries + MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST - 1)
            / MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST;
        assert!(num_link_blocks <= MAX_LINKS_IN_META_BLOCK);
        let num_blocks = (num_entries + MAX_ENTRIES_IN_DATA_BLOCK - 1) / MAX_ENTRIES_IN_DATA_BLOCK;

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
        return Err(FsError::NotFound);
    }

    fn make_error(&mut self) -> Result<(), FsError> {
        assert!(self.error.is_ok());
        self.error = Err(FsError::ValidationFailed);
        return self.error;
    }

    fn save_superblock(&mut self) -> Result<(), FsError> {
        assert!(self.error.is_ok());
        self.superblock.header_mut().set_crc32();
        self.blockcache
            .write_uncached_block(0, self.superblock.block())
            .map_err(|e| {
                let _ = self.make_error();
                e
            })
    }

    fn plus_one(&mut self, block_no: u64) -> Result<(), FsError> {
        let block = self.blockcache.get_mut(block_no);
        let meta = unsafe { block.block_mut().get_mut::<EntryMetadata>() };
        meta.size += 1;
        meta.set_crc32();
        self.blockcache.write(block_no).map_err(|e| {
            let _ = self.make_error(); // We cannot recover from this.
            e
        })
    }

    // Get a free block to use.
    fn allocate_txn_block(&mut self, block_type: BlockType) -> Result<u64, FsError> {
        let fbh = self.superblock.header_mut();
        assert_ne!(0, fbh.txn_blocks_owner);
        if fbh.free_blocks == 0 {
            return Err(FsError::FsFull);
        }

        #[cfg(debug_assertions)]
        match block_type {
            BlockType::Metadata => debug_assert_eq!(0, fbh.txn_meta_block),
            BlockType::Data => debug_assert_eq!(0, fbh.txn_data_block),
            BlockType::Links => debug_assert_eq!(0, fbh.txn_link_block),
            BlockType::ListOfLinks => debug_assert_eq!(0, fbh.txn_list_of_links_block),
        }

        let new_block_no = if fbh.freelist_head == 0 {
            // The freelist is empty: get the block from the empty area.
            let new_block_no = fbh.empty_area_start;
            fbh.empty_area_start += 1;
            new_block_no
        } else {
            // Get the block from the freelist.
            let new_block_no = fbh.freelist_head;
            let block = self.blockcache.read(new_block_no)?;
            fbh.freelist_head = *unsafe { block.block().get::<u64>() };
            if fbh.freelist_head >= fbh.num_blocks {
                log::error!("FS corrupted: bad freelist (1)");
                self.make_error()?;
                unreachable!()
            }
            new_block_no
        };

        assert_ne!(new_block_no, 0);
        if new_block_no >= fbh.num_blocks {
            log::error!("FS corrupted: bad freelist (2)");
            self.make_error()?;
            unreachable!()
        }
        fbh.free_blocks -= 1;
        match block_type {
            BlockType::Metadata => fbh.txn_meta_block = new_block_no,
            BlockType::Data => fbh.txn_data_block = new_block_no,
            BlockType::Links => fbh.txn_link_block = new_block_no,
            BlockType::ListOfLinks => fbh.txn_list_of_links_block = new_block_no,
        }
        self.save_superblock()?;

        Ok(new_block_no)
    }

    fn free_txn_block(&mut self, block_type: BlockType) -> Result<(), FsError> {
        let sbh = self.superblock.header_mut();
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
            unsafe { *block.block_mut().get_mut::<u64>() = prev_head };
            self.blockcache.write(block_no)?;
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

    fn start_txn(&mut self, txn_type: u32, owner: EntryId) -> Result<(), FsError> {
        let sbh = self.superblock.header_mut();
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

    fn commit_txn(&mut self) -> Result<(), FsError> {
        let sbh = self.superblock.header_mut();
        sbh.txn_meta_block = 0;
        sbh.txn_data_block = 0;
        sbh.txn_link_block = 0;
        sbh.txn_list_of_links_block = 0;
        sbh.txn_blocks_owner = 0;
        sbh.txn_type = TXN_TYPE_NONE;
        self.save_superblock()
    }
}
