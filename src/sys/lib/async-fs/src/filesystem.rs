use camino::{Utf8Path, Utf8PathBuf};
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
    async fn stat(&mut self, full_path: &Utf8Path) -> Result<EntryId>;

    /// Create a file or directory.
    async fn create_entry(
        &mut self,
        parent: EntryId,
        kind: EntryKind,
        name: &Utf8Path, // Leaf name.
    ) -> Result<EntryId>;

    /// Delete the file or directory.
    async fn delete_entry(&mut self, entry: EntryId) -> Result<()>;

    /// List directory entries.
    async fn list_entries(
        &mut self,
        parent: EntryId,
        offset: usize,
        entries: &mut [EntryId],
    ) -> Result<usize>;

    /// Filename of the entry, without parent directories.
    async fn name(&mut self, entry: EntryId) -> Result<Utf8PathBuf>;

    /// The size of the file in bytes, or the number of children in the directory.
    async fn size(&mut self, entry: EntryId) -> Result<usize>;

    /// Read bytes from a file.
    async fn read(&mut self, entry: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Write bytes to a file.
    async fn write(&mut self, entry: EntryId, offset: u64, buf: &[u8]) -> Result<usize>;

    /// Rename and/or move the file or directory.
    /// Returns the new ID of the entry.
    async fn rename(
        &mut self,
        entry: EntryId,
        new_parent: EntryId,
        new_name: &Utf8Path,
    ) -> Result<EntryId>;

    /// Resize the file.
    async fn resize(&mut self, file: EntryId, new_size: usize) -> Result<()>;
}
