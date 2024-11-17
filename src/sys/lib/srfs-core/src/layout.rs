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

#[cfg(feature = "std")]
extern crate std;

use super::*;

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::String;

use crc::CRC_32_ISO_HDLC;

const CRC32: crc::Crc<u32> = crc::Crc::<u32>::new(&CRC_32_ISO_HDLC);
const CRC32_VERIFY: u32 = 0x2144DF1C;

pub(crate) fn crc32_hash(bytes: &[u8]) -> u32 {
    let mut digest = CRC32.digest();
    digest.update(bytes);
    digest.finalize()
}

pub(crate) fn crc32_verify(bytes: &[u8]) -> Result<(), FsError> {
    if CRC32_VERIFY == crc32_hash(bytes) {
        Ok(())
    } else {
        Err(FsError::ValidationFailed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct EntryId {
    /// The number of the block the Entry physically resides on.
    /// Never changes, but can be re-used.
    pub(crate) block_no: u64,
    /// A unique number, to prevent ABA issues. Odd => dir, even => file.
    /// Never changes and is never re-used.
    pub(crate) generation: u64,
}

pub const ROOT_DIR_ID: EntryId = EntryId {
    block_no: 1,
    generation: 1,
};

impl EntryId {
    pub(crate) fn new(block_no: u64, generation: u64) -> Self {
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
            #![cfg(feature = "std")]
            let ts = std::time::UNIX_EPOCH.elapsed().unwrap();

            Self {
                secs: ts.as_secs(),
                ns: ts.subsec_nanos(),
                _pad: 0,
            }
        }
        {
            #![cfg(not(feature = "std"))]
            Self {
                secs: 0,
                ns: 0,
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

#[cfg(feature = "std")]
impl From<Timestamp> for std::time::SystemTime {
    fn from(ts: Timestamp) -> Self {
        let dur = std::time::Duration::new(ts.secs, ts.ns);
        std::time::SystemTime::checked_add(&std::time::UNIX_EPOCH, dur).unwrap()
    }
}

// An entry in a directory.
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct DirEntryInternal {
    pub id: EntryId,
    pub name: [u8; 255], // UTF-8.
    pub name_len: u8,
}

const _: () = assert!(core::mem::size_of::<DirEntryInternal>() == 272);

impl DirEntryInternal {
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        assert!(bytes.len() <= 255);

        unsafe { copy_nonoverlapping(bytes.as_ptr(), self.name.as_mut_ptr(), bytes.len()) };
        self.name_len = bytes.len() as u8;
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_owned(&self) -> Result<DirEntry, FsError> {
        Ok(DirEntry {
            id: self.id,
            name: core::str::from_utf8(&self.name[0..(self.name_len as usize)])
                .map_err(|_| FsError::Utf8Error)?
                .to_owned(),
        })
    }
}

#[derive(Debug)]
pub struct DirEntry {
    pub id: EntryId,
    pub name: String,
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

const _: () = assert!(core::mem::size_of::<EntryMetadata>() == 128);
const _: () = assert!(core::mem::size_of::<EntryMetadata>() < (BLOCK_SIZE as usize));

// In the metadata block, we put dir entries at the same place as in data blocks, leaving
// the space at the beginning of the block to be used by EntryMetadata.
const _: () =
    assert!(core::mem::size_of::<EntryMetadata>() <= core::mem::size_of::<DirEntryInternal>());

// Max entries in data block (leaf directory lists).
pub(crate) const MAX_ENTRIES_IN_DATA_BLOCK: u64 =
    BLOCK_SIZE / (core::mem::size_of::<DirEntryInternal>() as u64);
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
    BLOCK_SIZE - (core::mem::size_of::<EntryMetadata>() as u64);
const _: () = assert!(MAX_BYTES_IN_META_BLOCK == 3968);

// The max number of blocks referenced in the meta block of a file.
pub(crate) const MAX_LINKS_IN_META_BLOCK: u64 = MAX_BYTES_IN_META_BLOCK / 8;
const _: () = assert!(MAX_LINKS_IN_META_BLOCK == 496);

// The max size of a file without separate block list blocks.
pub(crate) const MAX_BYTES_ONLY_DATA_BLOCKS: u64 = MAX_LINKS_IN_META_BLOCK * BLOCK_SIZE;
const _: () = assert!(MAX_BYTES_ONLY_DATA_BLOCKS == 2_031_616);

pub(crate) const BYTES_COVERED_BY_FIRST_LEVEL_BLOCKLIST: u64 = BLOCK_SIZE * BLOCK_SIZE / 8;
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

    fn validate_basic(&self, id: EntryId) -> Result<(), FsError> {
        crc32_verify(self.as_bytes())?;
        if self.id != id {
            return Err(FsError::ValidationFailed);
        }
        Ok(())
    }

    pub fn validate(&self, id: EntryId) -> Result<(), FsError> {
        match id.kind() {
            EntryKind::Directory => self.validate_dir(id),
            EntryKind::File => self.validate_file(id),
        }
    }

    pub fn validate_dir(&self, id: EntryId) -> Result<(), FsError> {
        self.validate_basic(id)?;
        if self.id.kind() != EntryKind::Directory {
            return Err(FsError::ValidationFailed);
        }
        if self.size > MAX_DIR_ENTRIES {
            return Err(FsError::ValidationFailed);
        }

        Ok(())
    }

    pub fn validate_file(&self, id: EntryId) -> Result<(), FsError> {
        self.validate_basic(id)?;
        if self.id.kind() != EntryKind::File {
            return Err(FsError::ValidationFailed);
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

    pub fn validate(&self) -> Result<(), FsError> {
        crc32_verify(self.as_bytes())?;
        if self.version != 1 {
            return Err(FsError::UnsupportedVersion);
        }
        if self.magic == MAGIC {
            Ok(())
        } else {
            Err(FsError::ValidationFailed)
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C, align(4096))]
pub(crate) struct Block {
    bytes: [u8; 4096],
}

const _: () = assert!(core::mem::size_of::<Block>() as u64 == BLOCK_SIZE);

impl Block {
    pub const fn new_zeroed() -> Self {
        Self { bytes: [0; 4096] }
    }

    pub unsafe fn get<T>(&self) -> &T {
        debug_assert!(core::mem::size_of::<T>() as u64 <= BLOCK_SIZE);

        (self.bytes.as_ptr() as usize as *const T)
            .as_ref()
            .unwrap_unchecked()
    }

    pub unsafe fn get_mut<T>(&mut self) -> &mut T {
        debug_assert!(core::mem::size_of::<T>() as u64 <= BLOCK_SIZE);

        (self.bytes.as_ptr() as usize as *mut T)
            .as_mut()
            .unwrap_unchecked()
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (self as *const _ as usize as *const u8)
                    .as_ref()
                    .unwrap_unchecked(),
                BLOCK_SIZE as usize,
            )
        }
    }

    pub fn as_data_bytes_in_meta(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (((self as *const _ as usize) + core::mem::size_of::<EntryMetadata>())
                    as *const u8)
                    .as_ref()
                    .unwrap_unchecked(),
                BLOCK_SIZE as usize - core::mem::size_of::<EntryMetadata>(),
            )
        }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                (self as *mut _ as usize as *mut u8)
                    .as_mut()
                    .unwrap_unchecked(),
                BLOCK_SIZE as usize,
            )
        }
    }

    pub fn as_data_bytes_in_meta_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                (((self as *mut _ as usize) + core::mem::size_of::<EntryMetadata>()) as *mut u8)
                    .as_mut()
                    .unwrap_unchecked(),
                BLOCK_SIZE as usize - core::mem::size_of::<EntryMetadata>(),
            )
        }
    }

    pub fn set_dir_entry(&mut self, pos: usize, id: EntryId, name: &str) {
        let entry = self.get_dir_entry_mut(pos);
        entry.id = id;
        entry.set_name(name);
    }

    pub fn get_dir_entry(&self, pos: usize) -> &DirEntryInternal {
        assert!(pos as u64 <= MAX_ENTRIES_IN_DATA_BLOCK);
        let offset = pos * core::mem::size_of::<DirEntryInternal>();
        unsafe {
            ((self.bytes.as_ptr() as usize + offset) as *const DirEntryInternal)
                .as_ref()
                .unwrap_unchecked()
        }
    }

    pub fn get_dir_entry_mut(&mut self, pos: usize) -> &mut DirEntryInternal {
        assert!(pos <= MAX_ENTRIES_IN_DATA_BLOCK as usize);
        let offset = pos * core::mem::size_of::<DirEntryInternal>();
        unsafe {
            ((self.bytes.as_ptr() as usize + offset) as *mut DirEntryInternal)
                .as_mut()
                .unwrap_unchecked()
        }
    }

    pub fn get_datablock_no_in_meta(&self, data_block_idx: u64) -> u64 {
        assert!(data_block_idx <= MAX_LINKS_IN_META_BLOCK);
        let offset = core::mem::size_of::<EntryMetadata>() + ((data_block_idx as usize) << 3);
        debug_assert!(offset < BLOCK_SIZE as usize);
        unsafe { *((self.bytes.as_ptr() as usize + offset) as *const u64) }
    }

    pub fn set_datablock_no_in_meta(&mut self, data_block_idx: u64, block_no: u64) {
        assert!(data_block_idx <= MAX_LINKS_IN_META_BLOCK);
        let offset = core::mem::size_of::<EntryMetadata>() + ((data_block_idx as usize) << 3);
        assert!(offset < BLOCK_SIZE as usize);
        unsafe {
            *((self.bytes.as_ptr() as usize + offset) as *mut u64) = block_no;
        }
    }

    pub fn get_datablock_no_in_link(&self, data_block_idx: u64) -> u64 {
        assert!(data_block_idx < 512);
        let offset = (data_block_idx as usize) << 3;
        unsafe { *((self.bytes.as_ptr() as usize + offset) as *const u64) }
    }

    pub fn set_datablock_no_in_link(&mut self, data_block_idx: u64, block_no: u64) {
        assert!(data_block_idx < 512);
        let offset = (data_block_idx as usize) << 3;
        unsafe {
            *((self.bytes.as_ptr() as usize + offset) as *mut u64) = block_no;
        }
    }
}

pub(crate) struct Superblock {
    block: Box<Block>,
}

impl Superblock {
    pub fn from(block: Box<Block>) -> Result<Self, FsError> {
        unsafe {
            let fbh = block.get::<SuperblockHeader>();
            fbh.validate()?;
        }

        Ok(Self { block })
    }

    pub fn header(&self) -> &SuperblockHeader {
        unsafe { self.block.get::<SuperblockHeader>() }
    }

    pub fn header_mut(&mut self) -> &mut SuperblockHeader {
        unsafe { self.block.get_mut::<SuperblockHeader>() }
    }

    pub fn ___as_bytes(&self) -> &[u8] {
        self.block.as_bytes()
    }

    pub fn block(&self) -> &Block {
        &self.block
    }
}

pub(crate) fn validate_filename(name: &str) -> Result<(), FsError> {
    if name.as_bytes().len() > 255 || name.contains('/') || name == "." || name == ".." {
        return Err(FsError::InvalidArgument);
    }

    Ok(())
}

pub(crate) fn align_up(what: u64, how: u64) -> u64 {
    debug_assert!(how.is_power_of_two());
    (what + how - 1) & !(how - 1)
}
