use std::io::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    File,
}

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

/// Filesystem trait.
pub trait FileSystem {
    /// Find a file or directory by its full path.
    async fn stat(&mut self, parent_id: EntryId, filename: &str) -> Result<EntryId>;

    /// Create a file or directory.
    async fn create_entry(
        &mut self,
        parent_id: EntryId,
        kind: EntryKind,
        name: &str, // Leaf name.
    ) -> Result<EntryId>;

    /// Delete the file or directory.
    async fn delete_entry(&mut self, entry_id: EntryId) -> Result<()>;

    /// Get a specific entry.
    async fn get_entry_by_pos(&mut self, parent_id: EntryId, pos: usize) -> Result<EntryId>;

    /// Get the parent of the entry.
    async fn get_parent(&mut self, entry_id: EntryId) -> Result<Option<EntryId>>;

    /// Filename of the entry, without parent directories.
    async fn name(&mut self, entry_id: EntryId) -> Result<String>;

    /// The size of the file in bytes, or the number of children in the directory.
    async fn size(&mut self, entry_id: EntryId) -> Result<u64>;

    /// Read bytes from a file.
    async fn read(&mut self, file_id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Write bytes to a file.
    async fn write(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize>;

    /// Rename and/or move the file or directory.
    /// Returns the new ID of the entry.
    async fn move_rename(
        &mut self,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<EntryId>;

    /// Resize the file.
    async fn resize(&mut self, file_id: EntryId, new_size: u64) -> Result<()>;

    async fn empty_blocks(&mut self) -> Result<u64>;

    async fn flush(&mut self) -> Result<()>;
}
