//! Motor FS "on disk" layout.
//!
//! All names are UTF-8.
//!
//! Only files and directories are supported (no links).
//!
//! Once a directory entry (a file or a directory) is created,
//! it will keep its ID (block_no + generation) until it is deleted,
//! i.e. moves and renames preserve EntryId.
//!
//! Key facts:
//! - block #0 is superblock.
//! - block #1 is the root directory ("/").
//! - only blocks that contain file data/bytes are purely data blocks,
//!   all other blocks have BlockHeader.

use std::io::ErrorKind;

pub use async_fs::BLOCK_SIZE;
use async_fs::Block;
pub use async_fs::EntryId;
pub use async_fs::EntryKind;
use async_fs::Metadata;
use async_fs::Timestamp;
use async_fs::block_cache::CachedBlock;
use std::io::Result;

use crate::Ctx;
use crate::bplus_tree;

pub const MAX_FILENAME_LEN: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockNo(u64);

impl BlockNo {
    pub fn null() -> Self {
        Self(0)
    }

    pub fn is_null(&self) -> bool {
        self.0 == 0
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// EntryId uniquely identifies a file or a directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(16))]
pub(crate) struct EntryIdInternal {
    /// The number of the block the Entry physically resides on.
    /// Never changes, but can be re-used.
    pub block_no: BlockNo,
    /// A unique number, to prevent ABA issues.
    /// Never changes and is never re-used.
    pub generation: u64,
}

const _: () = assert!(16 == size_of::<EntryIdInternal>());
const _: () = assert!(size_of::<EntryId>() == size_of::<EntryIdInternal>());

impl From<EntryId> for EntryIdInternal {
    fn from(value: EntryId) -> Self {
        unsafe { core::mem::transmute(value) }
    }
}

impl From<EntryIdInternal> for EntryId {
    fn from(value: EntryIdInternal) -> Self {
        unsafe { core::mem::transmute(value) }
    }
}

impl EntryIdInternal {
    pub fn new(block_no: BlockNo, generation: u64) -> Self {
        Self {
            block_no,
            generation,
        }
    }

    pub fn block_no(&self) -> u64 {
        self.block_no.0
    }
}

pub const ROOT_DIR_ID: EntryIdInternal = EntryIdInternal {
    block_no: BlockNo(1),
    generation: 1,
};

/// Just a random number.
pub(crate) const MAGIC: u64 = 0x0c51_a0bb_b108_3d15;

/// Superblock (block #0).
#[repr(C)]
pub(crate) struct Superblock {
    magic: u64,         // MAGIC.
    version: u64,       // 1 at the moment.
    num_blocks: u64,    // Num blocks (may be less than what the device has).
    free_blocks: u64,   // The number of unused blocks.
    generation: u64,    // Auto-incrementing. Used in EntityId.
    freelist_head: u64, // The head of the block freelist.
    empty_area_start: u64, // All blocks after this one are unused.

                        // txn_meta_block: u64,          // A meta block currently being worked on.
                        // txn_data_block: u64,          // A file data block currently being worked on.
                        // txn_link_block: u64,          // A directory list block or file data block list.
                        // txn_list_of_links_block: u64, // A file list-of-lists block currently being worked on.
                        // txn_blocks_owner: u64,        // The "owner" of the txn blocks to check upon bootup.
                        // txn_type: u32,                // TXN_TYPE_***.
                        // crc32: u32, // CRC32 of this data structure.
}
const _: () = assert!(core::mem::size_of::<Superblock>() < BLOCK_SIZE);
unsafe impl plain::Plain for Superblock {}

impl Superblock {
    /// Returns the superblock and the root dir.
    pub fn format(num_blocks: u64) -> (Block, Block) {
        assert!(num_blocks > 2);

        let mut block_0 = Block::new_zeroed();
        let sb = block_0.get_mut_at_offset::<Self>(0);
        *sb = Self {
            magic: MAGIC,
            version: 1,
            num_blocks,
            free_blocks: num_blocks - 2,
            empty_area_start: 2,
            generation: 1,
            freelist_head: 0,
        };

        let mut block_1 = Block::new_zeroed();
        let root_dir = block_1.get_mut_at_offset::<DirEntryBlock>(0);

        root_dir.block_header.block_type = BlockType::DirEntry;
        root_dir.block_header.in_use = 1;
        root_dir.block_header.blocks_in_use = 1;

        root_dir.entry_id = ROOT_DIR_ID;

        // set_name() calls validate_name() which will fail on "/", so we do it manually.
        root_dir.name_bytes[0] = b'/';
        root_dir.name_len = 1;

        root_dir.hash_seed = std::random::random();

        let ts = Timestamp::now();
        root_dir.metadata.created = ts;
        root_dir.metadata.modified = ts;
        root_dir.metadata.set_kind(EntryKind::Directory);

        root_dir
            .btree_root
            .init_new_root(BlockNo(1), BlockNo::null());

        (block_0, block_1)
    }

    pub fn free_blocks(&self) -> u64 {
        self.free_blocks
    }

    pub async fn allocate_block(&mut self, ctx: &mut Ctx<'_>) -> Result<EntryIdInternal> {
        if self.free_blocks == 0 {
            return Err(ErrorKind::StorageFull.into());
        }

        if self.freelist_head == 0 {
            if self.empty_area_start != (self.num_blocks - self.free_blocks) {
                log::error!(
                    "Corrupted free block accounting: num_blocks: {}, free blocks: {}, empty_area_start: {}.",
                    self.num_blocks,
                    self.free_blocks,
                    self.empty_area_start
                );
                return Err(ErrorKind::InvalidData.into());
            }
            self.free_blocks -= 1;
            self.empty_area_start += 1;
            self.generation += 1;
            return Ok(EntryIdInternal::new(
                BlockNo(self.empty_area_start - 1),
                self.generation,
            ));
        }

        todo!()
    }

    pub async fn free_block(&mut self, ctx: &mut Ctx<'_>, block_no: BlockNo) -> Result<()> {
        if block_no.as_u64() == (self.empty_area_start - 1) {
            self.free_blocks += 1;
            self.empty_area_start -= 1;
            return Ok(());
        }

        todo!()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum BlockType {
    FileEntry = 1, // Also B+ tree root node.
    DirEntry = 2,  // Also B+ tree root node.
    TreeNode = 3,  // B+ tree node.
    _FileDataBlock = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChildType {
    TreeNode,
    Entry,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct BlockHeader {
    block_type: BlockType,
    in_use: u8, // 1 => true, 0 => false; _ => block corrupted.
    _padding_1: [u8; 6],

    // The number of blocks, including this block and tree nodes, the entity is using.
    blocks_in_use: u64,
}

const _: () = assert!(16 == core::mem::size_of::<BlockHeader>());
unsafe impl plain::Plain for BlockHeader {}

/// Directory Entry (file or directory) Header.
#[repr(C, align(4096))]
pub(crate) struct DirEntryBlock {
    block_header: BlockHeader,
    entry_id: EntryIdInternal,  // offset 16.
    parent_id: EntryIdInternal, // offset 32.

    // When several entries hash names to the same value, they form an SLL.
    next_entry_id: EntryIdInternal, // offset 48.

    metadata: Metadata, // offset 64.

    name_bytes: [u8; MAX_FILENAME_LEN], // offset 192.
    name_len: u8,

    // We use Cityhash64 to hash entry names; each directory has a random hash seed.
    hash_seed: u64, // offset 432.

    btree_root: bplus_tree::Node<DIR_ENTRY_BTREE_ORDER>,
}

unsafe impl plain::Plain for DirEntryBlock {}

pub(crate) const DIR_ENTRY_BTREE_ORDER: usize = 226;
pub(crate) const BTREE_ROOT_OFFSET: usize = 456;

const _: () = assert!(BLOCK_SIZE == core::mem::size_of::<DirEntryBlock>());
const _: () = assert!(BTREE_ROOT_OFFSET == core::mem::offset_of!(DirEntryBlock, btree_root));

pub(crate) const BTREE_NODE_ORDER: usize = 253;
pub(crate) const BTREE_NODE_OFFSET: usize = 24;

#[repr(C, align(4096))]
pub(crate) struct TreeNodeBlock {
    block_header: BlockHeader, // 16 bytes
    _padding: [u8; 8],

    btree_node: bplus_tree::Node<BTREE_NODE_ORDER>, // offset BTREE_NODE_OFFSET.
}

const _: () = assert!(BLOCK_SIZE == core::mem::size_of::<TreeNodeBlock>());
const _: () = assert!(BTREE_NODE_OFFSET == core::mem::offset_of!(TreeNodeBlock, btree_node));

unsafe impl plain::Plain for TreeNodeBlock {}

impl DirEntryBlock {
    pub fn from_block(block: &Block) -> &Self {
        block.get_at_offset(0)
    }

    pub fn from_block_mut(block: &mut Block) -> &mut Self {
        block.get_mut_at_offset(0)
    }

    pub async fn format_root_dir(&mut self) {
        todo!()
    }

    pub fn kind(&self) -> EntryKind {
        match self.block_header.block_type {
            BlockType::FileEntry => EntryKind::File,
            BlockType::DirEntry => EntryKind::Directory,
            _ => panic!("Dir entries must be pre-validated."),
        }
    }

    pub fn next_entry_id(&self) -> Option<EntryIdInternal> {
        if self.next_entry_id.block_no.is_null() {
            None
        } else {
            Some(self.next_entry_id)
        }
    }

    pub fn in_use(&self) -> Result<bool> {
        let in_use = self.block_header.in_use;
        match in_use {
            0 => Ok(false),
            1 => Ok(true),
            _ => {
                log::error!("Corrupt dir entry {:?}: in_use: {in_use}", self.entry_id);
                Err(ErrorKind::InvalidData.into())
            }
        }
    }

    pub fn entry_id_with_validation(&self, block_no: BlockNo) -> Result<EntryIdInternal> {
        let entry_id = self.entry_id;
        if entry_id.block_no != block_no {
            log::error!("Corrupt dir entry: block no {block_no:?} does not match {entry_id:?}.");
            return Err(ErrorKind::InvalidData.into());
        }
        if self.block_header.in_use != 1 {
            log::error!("Corrupt dir entry {:?}: not in use.", self.entry_id);
            return Err(ErrorKind::InvalidData.into());
        }

        self.validate_entry(entry_id)?;
        Ok(entry_id)
    }

    #[cfg(all(test, debug_assertions))]
    pub(crate) fn hash_debug(filename: &str) -> u64 {
        // To test hash collisions, in debug tests we keep the first bytes as hash.
        let mut hash = 0_u64;
        for idx in 0..8.min(filename.len()) {
            let byte = filename.as_bytes()[idx];
            hash |= (byte as u64) << (idx * 8);
        }

        hash
    }

    pub fn hash(&self, filename: &str) -> u64 {
        assert_eq!(self.kind(), EntryKind::Directory);

        #[cfg(all(test, debug_assertions))]
        return Self::hash_debug(filename);

        #[cfg(not(all(test, debug_assertions)))]
        crate::city_hash::city_hash64_with_seed(filename.as_bytes(), self.hash_seed)
    }

    pub fn validate_entry(&self, entry_id: EntryIdInternal) -> Result<()> {
        if !self.in_use()? {
            // This can be a user error, so we don't log an error.
            return Err(ErrorKind::InvalidInput.into());
        }

        if self.entry_id != entry_id {
            log::error!("Corrupt dir entry: {:?} != {entry_id:?}", self.entry_id);
            return Err(ErrorKind::InvalidData.into());
        }

        if self.btree_root.this() != entry_id.block_no {
            log::error!(
                "Corrupt dir entry: BTree Root BlockNo {:?} != {:?}",
                self.btree_root.this(),
                self.entry_id.block_no
            );
            return Err(ErrorKind::InvalidData.into());
        }

        match self.block_header.block_type {
            BlockType::FileEntry | BlockType::DirEntry => {}
            block_type => {
                log::error!(
                    "Corrupt dir entry {:?}: block_type: {block_type:?}",
                    self.entry_id
                );
                return Err(ErrorKind::InvalidInput.into());
            }
        }

        let _ = self.metadata.try_kind()?;

        Ok(())
    }

    pub async fn first_child(&self, ctx: &mut Ctx<'_>) -> Result<Option<BlockNo>> {
        assert_eq!(self.kind(), EntryKind::Directory);

        self.btree_root.first_child(ctx).await
    }

    pub async fn first_child_with_hash(
        &self,
        ctx: &mut Ctx<'_>,
        hash: u64,
    ) -> Result<Option<BlockNo>> {
        assert_eq!(self.kind(), EntryKind::Directory);
        self.btree_root.first_child_with_key(ctx, hash).await
    }

    pub async fn first_block_at_offset(
        &self,
        ctx: &mut Ctx<'_>,
        block_offset: u64,
    ) -> Result<Option<BlockNo>> {
        assert_eq!(self.kind(), EntryKind::File);
        self.btree_root
            .first_child_with_key(ctx, block_offset)
            .await
    }

    pub fn parent_id(&self) -> EntryIdInternal {
        self.parent_id
    }

    pub fn name(&self) -> Result<&str> {
        let name_len = self.name_len as usize;
        if name_len > self.name_bytes.len() {
            log::error!(
                "Corrupt dir entry {:?}: name_len: {name_len}",
                self.entry_id
            );
            return Err(ErrorKind::InvalidData.into());
        }
        let name_slice = &self.name_bytes[0..name_len];
        str::from_utf8(name_slice).map_err(|e| {
            log::error!("Corrupt dir entry {:?}: utf8 error: {e:?}", self.entry_id);
            ErrorKind::InvalidData.into()
        })
    }

    pub fn set_name(&mut self, filename: &str) -> Result<()> {
        validate_filename(filename)?;

        self.name_bytes[..filename.len()].clone_from_slice(filename.as_bytes());
        self.name_len = filename.len() as u8;

        Ok(())
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub async fn insert_child_entry(
        mut parent_block: CachedBlock,
        ctx: &mut Ctx<'_>,
        kind: async_fs::EntryKind,
        hash: u64,
        filename: &str,
    ) -> Result<EntryIdInternal> {
        let parent = parent_block
            .block_mut()
            .get_mut_at_offset::<DirEntryBlock>(0);
        assert_eq!(hash, parent.hash(filename));
        assert_eq!(parent.kind(), EntryKind::Directory);
        let parent_id = parent.entry_id;
        assert_eq!(parent.btree_root.this(), parent_id.block_no);

        // Step 1: allocate a block for the new child. Makes sb_block dirty.
        let mut sb_block = ctx.block_cache().pin_block(0).await?;
        let sb = sb_block.block_mut().get_mut_at_offset::<Superblock>(0);
        let entry_id = sb.allocate_block(ctx).await?;

        // Step 2: initialize the child entry block. Makes child_block dirty.
        let mut child_block = ctx.block_cache().pin_empty_block(entry_id.block_no());
        parent.init_child_entry(child_block.block_mut(), entry_id, kind, filename);

        // Step 3: insert a link to the child block into self.btree_root.
        //         Makes one or more tree nodes dirty (or even allocates new tree node blocks).
        let changed_tree_blocks = parent
            .btree_root
            .insert_link(ctx, hash, entry_id.block_no)
            .await
            .inspect_err(|err| todo!())?;

        parent.metadata.size += 1;
        parent.metadata.modified = Timestamp::now();

        // Step 4: start txn.
        log::warn!("DirEntryBlock::insert(): implement txn.");

        // Step 5: save changes.
        // TODO: batch write blocks when implemented.
        for block_no in changed_tree_blocks {
            if block_no == parent_id.block_no {
                continue;
            }
            ctx.block_cache()
                .write_block(block_no.as_u64())
                .await
                .inspect_err(|_err| todo!())?;
        }

        ctx.block_cache().unpin_block(child_block);
        ctx.block_cache()
            .write_block(entry_id.block_no())
            .await
            .inspect_err(|_err| todo!())?;

        ctx.block_cache().unpin_block(parent_block);
        ctx.block_cache()
            .write_block(parent_id.block_no())
            .await
            .inspect_err(|_err| todo!())?;

        ctx.block_cache().unpin_block(sb_block);
        ctx.block_cache()
            .write_block(0)
            .await
            .inspect_err(|_err| todo!())?;

        // Step 6: commit txn.

        Ok(entry_id)
    }

    pub async fn insert_data_block(
        mut entry_block: CachedBlock,
        ctx: &mut Ctx<'_>,
        block_offset: u64,
    ) -> Result<BlockNo> {
        let entry = entry_block
            .block_mut()
            .get_mut_at_offset::<DirEntryBlock>(0);
        assert_eq!(entry.kind(), EntryKind::File);
        let entry_id = entry.entry_id;
        assert_eq!(entry.btree_root.this(), entry_id.block_no);

        // Step 1: allocate a new data block. Makes sb_block dirty.
        let mut sb_block = ctx.block_cache().pin_block(0).await?;
        let sb = sb_block.block_mut().get_mut_at_offset::<Superblock>(0);
        let data_block_id = sb.allocate_block(ctx).await?;
        log::debug!(
            "Allocated new data block {}",
            data_block_id.block_no.as_u64()
        );

        // Step 2: initialize the new data block.
        let data_block = ctx.block_cache().pin_empty_block(data_block_id.block_no());

        // Step 3: insert a link to the child block into self.btree_root.
        //         Makes one or more tree nodes dirty (or even allocates new tree node blocks).
        let changed_tree_blocks = entry
            .btree_root
            .insert_link(ctx, block_offset, data_block_id.block_no)
            .await
            .inspect_err(|err| todo!())?;

        entry.metadata.modified = Timestamp::now();

        // Step 4: start txn.
        log::warn!("DirEntryBlock::insert_data_block(): implement txn.");

        // Step 5: save changes.
        // TODO: batch write blocks when implemented.
        for block_no in changed_tree_blocks {
            if block_no == entry_id.block_no {
                continue;
            }
            ctx.block_cache()
                .write_block(block_no.as_u64())
                .await
                .inspect_err(|_err| todo!())?;
        }

        ctx.block_cache().unpin_block(data_block);
        ctx.block_cache()
            .write_block(data_block_id.block_no())
            .await
            .inspect_err(|_err| todo!())?;

        ctx.block_cache().unpin_block(entry_block);
        ctx.block_cache()
            .write_block(entry_id.block_no())
            .await
            .inspect_err(|_err| todo!())?;

        ctx.block_cache().unpin_block(sb_block);
        ctx.block_cache()
            .write_block(0)
            .await
            .inspect_err(|_err| todo!())?;

        // Step 6: commit txn.

        Ok(data_block_id.block_no)
    }

    pub fn set_file_size(&mut self, new_size: u64) {
        assert_eq!(self.kind(), EntryKind::File);
        self.metadata.size = new_size;
    }

    pub fn init_child_entry<'a>(
        &self,
        child_block: &'a mut Block,
        child_entry_id: EntryIdInternal,
        kind: async_fs::EntryKind,
        filename: &str,
    ) -> &'a mut Self {
        let child = child_block.get_mut_at_offset::<DirEntryBlock>(0);

        child.block_header.block_type = match kind {
            EntryKind::Directory => BlockType::DirEntry,
            EntryKind::File => BlockType::FileEntry,
        };

        child.block_header.in_use = 1;
        child.block_header.blocks_in_use = 1;

        child.entry_id = child_entry_id;
        child.set_name(filename).unwrap();

        child.metadata.set_kind(kind);
        child.parent_id = self.entry_id;

        if kind == EntryKind::Directory {
            child.hash_seed = std::random::random();
        }

        let ts = Timestamp::now();
        child.metadata.created = ts;
        child.metadata.modified = ts;

        child
            .btree_root
            .init_new_root(child_entry_id.block_no, self.entry_id.block_no);

        child
    }

    pub async fn delete_entry(
        mut parent_block: CachedBlock,
        ctx: &mut Ctx<'_>,
        entry_id: EntryIdInternal,
    ) -> Result<()> {
        let parent = parent_block
            .block_mut()
            .get_mut_at_offset::<DirEntryBlock>(0);
        let parent_id = parent.entry_id;
        assert_eq!(parent.btree_root.this(), parent_id.block_no);

        // Get the entry hash, to give it to B+ tree.
        let hash = {
            // entry_block should be cached.
            let entry_block = ctx
                .block_cache()
                .get_block(entry_id.block_no())
                .await
                .inspect_err(|err| todo!())?;
            let entry = DirEntryBlock::from_block(entry_block.block());
            assert_eq!(entry.parent_id, parent_id); // The caller must ensure this.
            if entry.next_entry_id().is_some() {
                todo!("delete the entry from the list.");
            }
            let name = entry.name()?;
            parent.hash(name)
        };

        let Some(list_head_block_no) = parent.first_child_with_hash(ctx, hash).await? else {
            parent_block.forget();
            log::error!("Invalid hash for entry {entry_id:?}.");
            return Err(ErrorKind::InvalidData.into());
        };

        if list_head_block_no != entry_id.block_no {
            todo!("delete the entry from the list.");
        }

        // Step 1: delete the link.
        let changed_tree_blocks = parent
            .btree_root
            .delete_link(ctx, hash, entry_id.block_no)
            .await
            .inspect_err(|err| todo!())?;

        // Step 2: update the parent metadata.
        parent.metadata.size -= 1;
        parent.metadata.modified = Timestamp::now();

        // Step 3: mark the entry as deleted.
        let mut entry_block = ctx.block_cache().pin_block(entry_id.block_no()).await?;
        let entry = DirEntryBlock::from_block_mut(entry_block.block_mut());
        assert_eq!(0, entry.metadata.size); // TODO: implement deleting non-empty files.
        entry.block_header.in_use = 0;

        // Step 4: free the entry block. Makes sb_block dirty.
        let mut sb_block = ctx
            .block_cache()
            .pin_block(0)
            .await
            .inspect_err(|err| todo!())?;
        let sb = sb_block.block_mut().get_mut_at_offset::<Superblock>(0);
        sb.free_block(ctx, entry_id.block_no)
            .await
            .inspect_err(|err| todo!())?;

        // Step 5: Start txn.
        log::warn!("DirEntryBlock::delete(): implement txn.");

        // Step 6: save changes.
        // TODO: batch write blocks when implemented.
        for block_no in changed_tree_blocks {
            if block_no == parent_id.block_no {
                continue;
            }
            ctx.block_cache()
                .write_block(block_no.as_u64())
                .await
                .inspect_err(|_err| todo!())?;
        }
        ctx.block_cache().unpin_block(parent_block);
        ctx.block_cache()
            .write_block(parent_id.block_no())
            .await
            .inspect_err(|_err| todo!())?;

        ctx.block_cache().unpin_block(entry_block);
        ctx.block_cache()
            .write_block(entry_id.block_no())
            .await
            .inspect_err(|_err| todo!())?;

        ctx.block_cache().unpin_block(sb_block);
        ctx.block_cache()
            .write_block(0)
            .await
            .inspect_err(|_err| todo!())?;

        // Step 6: commit txn.

        Ok(())
    }
}

impl TreeNodeBlock {
    pub fn block_type(&self) -> BlockType {
        self.block_header.block_type
    }

    pub async fn first_child(&self, ctx: &mut Ctx<'_>) -> Result<Option<BlockNo>> {
        assert_eq!(self.block_type(), BlockType::TreeNode);

        // Recursion in an async fn requires boxing: rustc --explain E0733.
        Box::pin(self.btree_node.first_child(ctx)).await
    }
}

pub fn validate_filename(filename: &str) -> Result<()> {
    // if filename == "/" {
    //     return Ok(());
    // }

    if filename.len() > MAX_FILENAME_LEN || filename.contains('/') || filename.starts_with("..") {
        return Err(ErrorKind::InvalidFilename.into());
    }

    if filename.trim().len() != filename.len() {
        return Err(ErrorKind::InvalidFilename.into());
    }

    Ok(())
}
