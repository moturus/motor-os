use std::io::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    File,
}

pub type EntryId = u128;

#[derive(Clone, Copy, Debug)]
#[repr(C, align(8))]
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

impl From<std::time::SystemTime> for Timestamp {
    fn from(value: std::time::SystemTime) -> Self {
        let dur = value
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO);

        Timestamp {
            secs: dur.as_secs(),
            ns: dur.subsec_nanos(),
            _pad: 0,
        }
    }
}

/// Directory Entry Metadata.
#[derive(Clone, Copy, Debug)]
#[repr(C, align(8))]
pub struct Metadata {
    pub created: Timestamp,
    pub modified: Timestamp,
    pub accessed: Timestamp,
    pub size: u64,                 // File size or the number of directory entries.
    pub user_extensions: [u8; 72], // Permissions, ACL, whatever.
}

const _: () = assert!(128 == core::mem::size_of::<Metadata>());

/// Filesystem trait.
pub trait FileSystem {
    /// Find a file or directory by its full path.
    async fn stat(&mut self, parent_id: EntryId, filename: &str) -> Result<Option<EntryId>>;

    /// Create a file or directory.
    async fn create_entry(
        &mut self,
        parent_id: EntryId,
        kind: EntryKind,
        name: &str, // Leaf name.
    ) -> Result<EntryId>;

    /// Delete the file or directory.
    async fn delete_entry(&mut self, entry_id: EntryId) -> Result<()>;

    /// Get the first entry in a directory.
    async fn get_first_entry(&mut self, parent_id: EntryId) -> Result<Option<EntryId>>;

    /// Get the next entry in a directory.
    async fn get_next_entry(&mut self, entry_id: EntryId) -> Result<Option<EntryId>>;

    /// Get the parent of the entry.
    async fn get_parent(&mut self, entry_id: EntryId) -> Result<Option<EntryId>>;

    /// Filename of the entry, without parent directories.
    async fn name(&mut self, entry_id: EntryId) -> Result<String>;

    /// The metadata of the directory entry.
    async fn metadata(&mut self, entry_id: EntryId) -> Result<Metadata>;

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

    /// The total number of blocks in the FS.
    fn num_blocks(&self) -> u64;

    async fn empty_blocks(&mut self) -> Result<u64>;

    async fn flush(&mut self) -> Result<()>;
}
