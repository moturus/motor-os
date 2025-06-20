use super::*;
use async_fs::BLOCK_SIZE;
use async_fs::Block;
/// Various data structures as they are on the permanent storage.
///
/// EntryMetadata is the same for files and directories.
///
/// Directories:
/// - if the number of entries is at most MAX_ENTRIES_IN_META_BLOCK (14), then only the
///   metadata block contains entries;
/// - if the number of entries is at most MAX_ENTRIES_ONLY_DATA_BLOCKS (7440), then the
///   metadata block lists data blocks;
/// - if the number of entries is more than MAX_ENTRIES_ONLY_DATA_BLOCKS, but less than
///   MAX_DIR_ENTRIES (65536), the metadata block lists block lists, which in turn list
///   data blocks with entries.
/// - TODO: the number of directory entries is limited to 64k because to find an entry
///   by its name currently requires a linear search; we should add a hashmap to speed
///   things up.
///
/// Files:
/// - if file size is at most MAX_BYTES_IN_META_BLOCK, then the metadata block has the bytes
///   immediately after EntryMetadata;
/// - otherwise all file data are in data blocks;
///   - if the file size is no more than MAX_BYTES_ONLY_DATA_BLOCKS (~2M), the metadata block
///     lists data blocks;
///   - if the file size is no more than MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS (~1G), the metadata
///     block lists the first level block list blocks;
///   - if the file size is no more than MAX_BYTES_LIST_OF_LISTS_BLOCKS (~500G), the metadata
///     block lists second-level list-of-list blocks, which list the first level block list
///     blocks which list data blocks;
///   - file sizes above that are currently not supported, but it will be easy to continue with
///     the same approach.
use core::ptr::copy_nonoverlapping;
use crc::CRC_32_ISO_HDLC;
use std::io::ErrorKind;
use std::io::Result;

const CRC32: crc::Crc<u32> = crc::Crc::<u32>::new(&CRC_32_ISO_HDLC);
const CRC32_VERIFY: u32 = 0x2144DF1C;

pub(crate) fn crc32_hash(bytes: &[u8]) -> u32 {
    let mut digest = CRC32.digest();
    digest.update(bytes);
    digest.finalize()
}

pub(crate) fn crc32_verify(bytes: &[u8]) -> Result<()> {
    if CRC32_VERIFY == crc32_hash(bytes) {
        Ok(())
    } else {
        Err(ErrorKind::InvalidData.into())
    }
}

pub use async_fs::EntryKind;

/// EntryId uniquely identifies a file or a directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct EntryId {
    /// The number of the block the Entry physically resides on.
    /// Never changes, but can be re-used.
    pub block_no: u64,
    /// A unique number, to prevent ABA issues. Odd => dir, even => file.
    /// Never changes and is never re-used.
    pub generation: u64,
}

pub const ROOT_DIR_ID: EntryId = EntryId {
    block_no: 1,
    generation: 1,
};

impl EntryId {
    pub fn new(block_no: u64, generation: u64) -> Self {
        Self {
            block_no,
            generation,
        }
    }

    pub fn kind(&self) -> EntryKind {
        if (self.generation & 1) == 1 {
            EntryKind::Directory
        } else {
            EntryKind::File
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Timestamp {
    pub secs: u64,
    pub ns: u32,
    _pad: u32,
}

impl Timestamp {
    pub fn now() -> Self {
        {
            let ts = std::time::UNIX_EPOCH.elapsed().unwrap();

            Self {
                secs: ts.as_secs(),
                ns: ts.subsec_nanos(),
                _pad: 0,
            }
        }
    }

    pub const fn zero() -> Self {
        Self {
            secs: 0,
            ns: 0,
            _pad: 0,
        }
    }
}

impl From<Timestamp> for std::time::SystemTime {
    fn from(ts: Timestamp) -> Self {
        let dur = std::time::Duration::new(ts.secs, ts.ns);
        std::time::SystemTime::checked_add(&std::time::UNIX_EPOCH, dur).unwrap()
    }
}

// An entry in a directory.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DirEntry {
    pub id: EntryId,
    pub name: [u8; 255], // UTF-8.
    pub name_len: u8,
}

const _: () = assert!(core::mem::size_of::<DirEntry>() == 272);

unsafe impl plain::Plain for DirEntry {}

impl std::fmt::Debug for DirEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirEntryInternal")
            .field("id", &self.id)
            .field("name", &self.get_name().unwrap())
            .finish()
    }
}

impl DirEntry {
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        assert!(bytes.len() <= 255);

        unsafe { copy_nonoverlapping(bytes.as_ptr(), self.name.as_mut_ptr(), bytes.len()) };
        self.name_len = bytes.len() as u8;
    }

    pub fn get_name(&self) -> Result<&str> {
        let name_str = str::from_utf8(&self.name[0..(self.name_len as usize)])
            .map_err(|_| std::io::Error::from(ErrorKind::InvalidData))?;
        Ok(name_str)
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(crate) struct EntryMetadata {
    pub id: EntryId,
    pub parent_id: EntryId,
    pub size: u64, // File size in bytes, or the number of directory entries.
    pub created: Timestamp,
    pub modified: Timestamp,
    pub accessed: Timestamp, // Usually not tracked.
    pub user_data: [u64; 4], // Whatever, e.g. permissions, uid/gid, etc.
    pub _reserved_2: u32,
    pub crc32: u32, // CRC32 of this data structure.
}

unsafe impl plain::Plain for EntryMetadata {}

const _: () = assert!(core::mem::size_of::<EntryMetadata>() == 128);
const _: () = assert!(core::mem::size_of::<EntryMetadata>() < BLOCK_SIZE);

// In the metadata block, we put dir entries at the same place as in data blocks, leaving
// the space at the beginning of the block to be used by EntryMetadata.
const _: () = assert!(core::mem::size_of::<EntryMetadata>() <= core::mem::size_of::<DirEntry>());

// Max entries in data block (leaf directory lists).
pub(crate) const MAX_ENTRIES_IN_DATA_BLOCK: u64 =
    (BLOCK_SIZE / core::mem::size_of::<DirEntry>()) as u64;
const _: () = assert!(MAX_ENTRIES_IN_DATA_BLOCK == 15);

// Directories with entries <= MAX_ENTRIES_IN_SELF_BLOCK occupy a single block.
pub(crate) const MAX_ENTRIES_IN_META_BLOCK: u64 = MAX_ENTRIES_IN_DATA_BLOCK - 1;
const _: () = assert!(MAX_ENTRIES_IN_META_BLOCK == 14);

// The max number of directory entries without separate block lists.
pub(crate) const MAX_ENTRIES_ONLY_DATA_BLOCKS: u64 =
    MAX_LINKS_IN_META_BLOCK * MAX_ENTRIES_IN_DATA_BLOCK;
const _: () = assert!(MAX_ENTRIES_ONLY_DATA_BLOCKS == 7440);

pub(crate) const MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST: u64 =
    MAX_ENTRIES_IN_DATA_BLOCK * 512;
const _: () = assert!(MAX_ENTRIES_COVERED_BY_FIRST_LEVEL_BLOCKLIST == 7680);

// Files with size <= MAX_BYTES_IN_SELF_BLOCK occupy a single block.
pub(crate) const MAX_BYTES_IN_META_BLOCK: u64 =
    (BLOCK_SIZE - core::mem::size_of::<EntryMetadata>()) as u64;
const _: () = assert!(MAX_BYTES_IN_META_BLOCK == 3968);

// The max number of blocks referenced in the meta block of a file.
pub(crate) const MAX_LINKS_IN_META_BLOCK: u64 = MAX_BYTES_IN_META_BLOCK / 8;
const _: () = assert!(MAX_LINKS_IN_META_BLOCK == 496);

// The max size of a file without separate block list blocks.
pub(crate) const MAX_BYTES_ONLY_DATA_BLOCKS: u64 = MAX_LINKS_IN_META_BLOCK * (BLOCK_SIZE as u64);
const _: () = assert!(MAX_BYTES_ONLY_DATA_BLOCKS == 2_031_616);

pub(crate) const BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST: u64 = (BLOCK_SIZE * BLOCK_SIZE / 8) as u64;
const _: () = assert!(BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST == 4096 * 512); // 2M.

// The max size of a file without separate list-of-list blocks.
pub(crate) const MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS: u64 =
    MAX_LINKS_IN_META_BLOCK * BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST;
const _: () = assert!(MAX_BYTES_SINGLE_LEVEL_LIST_BLOCKS == 1_040_187_392); // ~1G.

pub(crate) const BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST: u64 =
    BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST * 512;
const _: () = assert!(BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST == 1024 * 1024 * 1024); // 1G.

// The max size of a file with list-of-list blocks.
pub(crate) const MAX_BYTES_LIST_OF_LISTS_BLOCKS: u64 =
    MAX_LINKS_IN_META_BLOCK * BYTES_COVERED_BY_SECOND_LEVEL_BLOCKLIST;
const _: () = assert!(MAX_BYTES_LIST_OF_LISTS_BLOCKS == 532_575_944_704); // ~500G.

impl EntryMetadata {
    pub fn new(id: EntryId, parent_id: EntryId) -> Self {
        let now = Timestamp::now();
        Self {
            id,
            parent_id,
            size: 0,
            created: now,
            modified: now,
            accessed: Timestamp::zero(),
            user_data: [0; 4],
            _reserved_2: 0,
            crc32: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as usize as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    pub fn set_crc32(&mut self) {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                self as *const _ as usize as *const u8,
                core::mem::size_of::<Self>() - 4,
            )
        };
        let crc32 = crc32_hash(bytes);
        self.crc32 = crc32;
    }

    fn validate_basic(&self, id: EntryId) -> Result<()> {
        if self.id != id {
            return Err(ErrorKind::InvalidData.into());
        }
        crc32_verify(self.as_bytes())
    }

    pub fn validate(&self, id: EntryId) -> Result<()> {
        match id.kind() {
            EntryKind::Directory => self.validate_dir(id),
            EntryKind::File => self.validate_file(id),
        }
    }

    pub fn validate_dir(&self, id: EntryId) -> Result<()> {
        self.validate_basic(id)?;
        if self.id.kind() != EntryKind::Directory {
            return Err(ErrorKind::InvalidData.into());
        }
        if self.size > MAX_DIR_ENTRIES {
            return Err(ErrorKind::InvalidData.into());
        }

        Ok(())
    }

    pub fn validate_file(&self, id: EntryId) -> Result<()> {
        self.validate_basic(id)?;
        if self.id.kind() != EntryKind::File {
            return Err(ErrorKind::InvalidData.into());
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Attr {
    pub id: EntryId,
    pub size: u64, // File size in bytes, or the number of directory entries.
    pub created: Timestamp,
    pub modified: Timestamp,
    pub accessed: Timestamp, // Usually not tracked.
    pub user_data: [u64; 4], // Whatever, e.g. permissions, uid/gid, etc.
}

impl From<&EntryMetadata> for Attr {
    fn from(meta: &EntryMetadata) -> Self {
        Self {
            id: meta.id,
            size: meta.size,
            created: meta.created,
            modified: meta.modified,
            accessed: meta.accessed,
            user_data: meta.user_data,
        }
    }
}

pub(crate) const MAGIC: u64 = 0x0c51_a0bb_b108_3d14; // Just a random number.

// The type of transaction type in process.
pub(crate) const TXN_TYPE_NONE: u32 = 0;
pub(crate) const TXN_TYPE_ADD_NODE: u32 = 1;
pub(crate) const TXN_TYPE_ADD_BYTES: u32 = 2;
pub(crate) const TXN_TYPE_REMOVE_NODE: u32 = 3;
pub(crate) const TXN_TYPE_REMOVE_BYTES: u32 = 4;
pub(crate) const TXN_TYPE_MOVE: u32 = 5;

// The partition:
// - the first block
// - root_dir block
// - either Entry blocks, data blocks, or empty blocks

// The first block header. Duplicated at [0..) and [2048..) of the first block
// of the partition.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct SuperblockHeader {
    pub magic: u64,                   // MAGIC.
    pub version: u64,                 // 1 at the moment.
    pub num_blocks: u64,              // Num blocks (may be less than what the device has).
    pub free_blocks: u64,             // The number of unused blocks.
    pub generation: u64,              // Auto-incrementing. Used in EntityId.
    pub freelist_head: u64,           // The head of the block freelist.
    pub empty_area_start: u64,        // All blocks after this one are unused.
    pub txn_meta_block: u64,          // A meta block currently being worked on.
    pub txn_data_block: u64,          // A file data block currently being worked on.
    pub txn_link_block: u64,          // A directory list block or file data block list.
    pub txn_list_of_links_block: u64, // A file list-of-lists block currently being worked on.
    pub txn_blocks_owner: u64,        // The "owner" of the txn blocks to check upon bootup.
    pub txn_type: u32,                // TXN_TYPE_***.
    pub crc32: u32,                   // CRC32 of this data structure.
}

unsafe impl plain::Plain for SuperblockHeader {}

impl SuperblockHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as usize as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    pub fn set_crc32(&mut self) {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                self as *const _ as usize as *const u8,
                core::mem::size_of::<Self>() - 4,
            )
        };
        let crc32 = crc32_hash(bytes);
        self.crc32 = crc32;
    }

    pub fn validate(&self) -> Result<()> {
        crc32_verify(self.as_bytes())?;
        if self.version != 1 {
            return Err(ErrorKind::Unsupported.into());
        }
        if self.magic == MAGIC {
            Ok(())
        } else {
            Err(ErrorKind::InvalidData.into())
        }
    }
}

pub(crate) fn validate_filename(name: &str) -> Result<()> {
    if name.len() > 255 || name.contains('/') || name == "." || name == ".." {
        return Err(ErrorKind::InvalidFilename.into());
    }

    Ok(())
}

pub(crate) fn align_up(what: u64, how: u64) -> u64 {
    debug_assert!(how.is_power_of_two());
    (what + how - 1) & !(how - 1)
}

pub(crate) fn block_get_dir_entry(block: &Block, pos: usize) -> &DirEntry {
    assert!(pos as u64 <= MAX_ENTRIES_IN_DATA_BLOCK);
    let offset = pos * core::mem::size_of::<DirEntry>();
    block.get_at_offset::<DirEntry>(offset)
}

pub(crate) fn block_set_dir_entry(block: &mut Block, pos: usize, id: EntryId, name: &str) {
    let entry = block_get_dir_entry_mut(block, pos);
    entry.id = id;
    entry.set_name(name);
}

pub(crate) fn block_get_dir_entry_mut(block: &mut Block, pos: usize) -> &mut DirEntry {
    assert!(pos <= MAX_ENTRIES_IN_DATA_BLOCK as usize);
    let offset = pos * core::mem::size_of::<DirEntry>();
    block.get_mut_at_offset(offset)
}

pub(crate) fn block_set_datablock_no_in_meta(
    block: &mut Block,
    data_block_idx: u64,
    block_no: u64,
) {
    assert!(data_block_idx <= MAX_LINKS_IN_META_BLOCK);
    let offset = core::mem::size_of::<EntryMetadata>() + ((data_block_idx as usize) << 3);
    assert!(offset < BLOCK_SIZE);
    *block.get_mut_at_offset(offset) = block_no;
}

pub(crate) fn block_get_datablock_no_in_meta(block: &Block, data_block_idx: u64) -> u64 {
    assert!(data_block_idx <= MAX_LINKS_IN_META_BLOCK);
    let offset = core::mem::size_of::<EntryMetadata>() + ((data_block_idx as usize) << 3);
    debug_assert!(offset < BLOCK_SIZE);
    *block.get_at_offset(offset)
}

pub(crate) fn block_get_datablock_no_in_link(block: &Block, data_block_idx: u64) -> u64 {
    assert!(data_block_idx < 512);
    let offset = (data_block_idx as usize) << 3;
    *block.get_at_offset(offset)
}

pub(crate) fn block_set_datablock_no_in_link(
    block: &mut Block,
    data_block_idx: u64,
    block_no: u64,
) {
    assert!(data_block_idx < 512);
    let offset = (data_block_idx as usize) << 3;
    *block.get_mut_at_offset(offset) = block_no;
}

pub(crate) fn block_get_data_bytes_in_meta_mut(block: &mut Block) -> &mut [u8] {
    const OFFSET: usize = core::mem::size_of::<EntryMetadata>();
    const LEN: usize = BLOCK_SIZE - OFFSET;
    unsafe {
        core::slice::from_raw_parts_mut(
            (((block as *mut _ as usize) + OFFSET) as *mut u8)
                .as_mut()
                .unwrap_unchecked(),
            LEN,
        )
    }
}

pub(crate) fn block_get_data_bytes_in_meta(block: &Block) -> &[u8] {
    unsafe {
        core::slice::from_raw_parts(
            (((block as *const _ as usize) + core::mem::size_of::<EntryMetadata>()) as *const u8)
                .as_ref()
                .unwrap_unchecked(),
            BLOCK_SIZE - core::mem::size_of::<EntryMetadata>(),
        )
    }
}
