use async_trait::async_trait;
use bytemuck::Pod;

#[cfg(feature = "std")]
pub type Result<T> = std::io::Result<T>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, moto_rt::Error>;

#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Directory = 1,
    File = 2,
}

impl TryFrom<u8> for EntryKind {
    #[cfg(feature = "std")]
    type Error = std::io::Error;

    #[cfg(not(feature = "std"))]
    type Error = moto_rt::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(EntryKind::Directory),
            2 => Ok(EntryKind::File),
            x => {
                log::error!("Corrupted EntryKind: {x}.");

                #[cfg(feature = "std")]
                {
                    Err(std::io::ErrorKind::InvalidData.into())
                }

                #[cfg(not(feature = "std"))]
                {
                    Err(moto_rt::Error::InvalidData)
                }
            }
        }
    }
}

pub type EntryId = u128;
pub const ROOT_ID: EntryId = 0;

#[derive(Clone, Copy, Debug, Pod)]
#[repr(C, align(4))]
pub struct Timestamp {
    secs: [u8; 8],  // le bytes u64
    nanos: [u8; 4], // le bytes u32
}

unsafe impl bytemuck::Zeroable for Timestamp {}

impl Timestamp {
    #[cfg(feature = "std")]
    pub fn now() -> Self {
        {
            let ts = std::time::UNIX_EPOCH.elapsed().unwrap();

            Self {
                secs: ts.as_secs().to_le_bytes(),
                nanos: ts.subsec_nanos().to_le_bytes(),
            }
        }
    }

    pub const fn zero() -> Self {
        Self {
            secs: [0; 8],
            nanos: [0; 4],
        }
    }

    pub fn as_nanos(&self) -> u128 {
        let secs = u64::from_le_bytes(self.secs);
        let nanos = u32::from_le_bytes(self.nanos);
        (secs as u128) * 1_000_000_000 + (nanos as u128)
    }
}

#[cfg(feature = "std")]
impl From<Timestamp> for std::time::SystemTime {
    fn from(ts: Timestamp) -> Self {
        let dur =
            std::time::Duration::new(u64::from_le_bytes(ts.secs), u32::from_le_bytes(ts.nanos));
        std::time::SystemTime::checked_add(&std::time::UNIX_EPOCH, dur).unwrap()
    }
}

#[cfg(feature = "std")]
impl From<std::time::SystemTime> for Timestamp {
    fn from(value: std::time::SystemTime) -> Self {
        let dur = value
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO);

        Timestamp {
            secs: dur.as_secs().to_le_bytes(),
            nanos: dur.subsec_nanos().to_le_bytes(),
        }
    }
}

/// Directory Entry Metadata.
#[derive(Clone, Copy, Debug, Pod)]
#[repr(C, align(8))]
pub struct Metadata {
    pub size: u64, // File size or the number of directory entries.
    pub created: Timestamp,
    pub modified: Timestamp,
    pub accessed: Timestamp,
    kind: u8, // Must use u8, as using EntryKind leads to ub if not properly initialized.
    _reserved: [u8; 11],
    pub user_extensions: [u8; 72], // Permissions, ACL, whatever.
}

unsafe impl bytemuck::Zeroable for Metadata {}

const _: () = assert!(128 == core::mem::size_of::<Metadata>());

impl Metadata {
    pub fn kind(&self) -> EntryKind {
        self.kind.try_into().unwrap()
    }

    pub fn set_kind(&mut self, kind: EntryKind) {
        self.kind = match kind {
            EntryKind::Directory => 1,
            EntryKind::File => 2,
        };
    }

    pub fn try_kind(&self) -> Result<EntryKind> {
        self.kind.try_into()
    }

    pub fn zeroed() -> Self {
        Self {
            size: 0,
            created: Timestamp::zero(),
            modified: Timestamp::zero(),
            accessed: Timestamp::zero(),
            kind: 0,
            _reserved: [0; 11],
            user_extensions: [0; 72],
        }
    }
}

/// Filesystem trait.
#[async_trait(?Send)]
pub trait FileSystem {
    /// Find a file or directory by its full path.
    async fn stat(
        &mut self,
        parent_id: EntryId,
        filename: &str,
    ) -> Result<Option<(EntryId, EntryKind)>>;

    /// Create a file or directory.
    async fn create_entry(
        &mut self,
        parent_id: EntryId,
        kind: EntryKind,
        name: &str, // Leaf name.
    ) -> Result<EntryId>;

    /// Delete the file or directory.
    async fn delete_entry(&mut self, entry_id: EntryId) -> Result<()>;

    /// Rename and/or move the file or directory.
    async fn move_entry(
        &mut self,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<()>;

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
    /// Note that cross-block reads may not be supported.
    async fn read(&mut self, file_id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Write bytes to a file.
    /// Note that cross-block writes may not be supported.
    async fn write(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize>;

    /// Resize the file.
    async fn resize(&mut self, file_id: EntryId, new_size: u64) -> Result<()>;

    /// The total number of blocks in the FS.
    fn num_blocks(&self) -> u64;

    async fn empty_blocks(&mut self) -> Result<u64>;

    async fn flush(&mut self) -> Result<()>;
}
