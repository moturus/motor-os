use async_trait::async_trait;
use bytemuck::Pod;

#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use crate::Result;

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

/// Privilege role for permission checks: System > Interactive > None. The
/// discriminant is both the privilege rank and the per-role permissions array
/// index (see PERMISSIONS_DESIGN.md).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    None = 0,
    Interactive = 1,
    System = 2,
}

/// Per-role permission value. `r` gates `w` and `x` (if reading is not allowed,
/// neither writing nor execution is). Zero == `Rwx`, so a zeroed entry is fully
/// permissive. The value space is a lattice, not a chain (`Rx` and `Rw` are
/// incomparable). See PERMISSIONS_DESIGN.md.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessPermissions {
    Rwx = 0, // zero => full access (legacy/format default)
    Rx = 1,
    Rw = 2,
    R = 3,
    None = 4,
}

impl AccessPermissions {
    /// (read, write, execute)
    pub fn triple(self) -> (bool, bool, bool) {
        match self {
            AccessPermissions::Rwx => (true, true, true),
            AccessPermissions::Rx => (true, false, true),
            AccessPermissions::Rw => (true, true, false),
            AccessPermissions::R => (true, false, false),
            AccessPermissions::None => (false, false, false),
        }
    }

    pub fn can_read(self) -> bool {
        self.triple().0
    }

    pub fn can_write(self) -> bool {
        self.triple().1
    }

    pub fn can_execute(self) -> bool {
        self.triple().2
    }

    /// True iff `target`'s permission set is a subset of `self`'s, i.e. `self`
    /// may be *narrowed* to `target` without granting anything new. Rejects e.g.
    /// `Rx -> Rw` (would drop x and add w).
    pub fn can_narrow_to(self, target: AccessPermissions) -> bool {
        let (sr, sw, sx) = self.triple();
        let (tr, tw, tx) = target.triple();
        (!tr || sr) && (!tw || sw) && (!tx || sx)
    }

    /// Per-bit intersection of two permissions. ANDing two r-gated values keeps
    /// the r-gate, so the result is always a valid `Access`. Used to clamp lower
    /// roles when a higher role is narrowed (cross-role cascade).
    pub fn meet(self, other: AccessPermissions) -> AccessPermissions {
        let (ar, aw, ax) = self.triple();
        let (br, bw, bx) = other.triple();
        Self::from_triple(ar && br, aw && bw, ax && bx)
    }

    /// Build an `Access` from an r-gated `(r, w, x)` triple. Only ever fed gated
    /// triples (raw disk bytes go through `try_from`).
    fn from_triple(r: bool, w: bool, x: bool) -> AccessPermissions {
        match (r, w, x) {
            (true, true, true) => AccessPermissions::Rwx,
            (true, false, true) => AccessPermissions::Rx,
            (true, true, false) => AccessPermissions::Rw,
            (true, false, false) => AccessPermissions::R,
            _ => AccessPermissions::None,
        }
    }
}

impl TryFrom<u8> for AccessPermissions {
    #[cfg(feature = "std")]
    type Error = std::io::Error;

    #[cfg(not(feature = "std"))]
    type Error = moto_rt::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(AccessPermissions::Rwx),
            1 => Ok(AccessPermissions::Rx),
            2 => Ok(AccessPermissions::Rw),
            3 => Ok(AccessPermissions::R),
            4 => Ok(AccessPermissions::None),
            x => {
                log::error!("Corrupted Access: {x}.");

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

/// May a caller acting as `caller` change role `target`'s permission from `old`
/// to `new`? Governs **authority only**; cross-role monotonicity is a separate
/// constraint applied by the FS (cap + cascade). See PERMISSIONS_DESIGN.md.
///   - target strictly below caller : any change (widen or narrow)
///   - target == caller (own byte)  : narrow only
///   - target strictly above caller : forbidden
pub fn may_set(caller: Role, target: Role, old: AccessPermissions, new: AccessPermissions) -> bool {
    use core::cmp::Ordering::*;
    match (caller as u8).cmp(&(target as u8)) {
        Greater => true,
        Equal => old.can_narrow_to(new),
        Less => false,
    }
}

/// True iff `perms` (indexed by `Role`) satisfies cross-role monotonicity:
/// `perms[None] ⊆ perms[Interactive] ⊆ perms[System]`. Used to validate the
/// initial permissions passed to `create_entry`.
pub fn perms_monotonic(perms: [AccessPermissions; 3]) -> bool {
    perms[Role::System as usize].can_narrow_to(perms[Role::Interactive as usize])
        && perms[Role::Interactive as usize].can_narrow_to(perms[Role::None as usize])
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
    // Per-role permissions: one `Access` byte per `Role`, indexed by the role's
    // discriminant (perms[0]=None, perms[1]=Interactive, perms[2]=System). Zero
    // == `Access::Rwx`, so a zeroed entry is fully permissive. Kept as raw bytes
    // (not `[Access; 3]`) because `Access` has invalid bit patterns and so is
    // not `Pod`; decode via `access()`. See PERMISSIONS_DESIGN.md.
    perms: [u8; 3],
    _reserved: [u8; 8],
    pub user_extensions: [u8; 72], // Reserved for a future ACL/xattr record.
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
            perms: [0; 3],
            _reserved: [0; 8],
            user_extensions: [0; 72],
        }
    }

    /// Decoded permission for `role`. Errors only on a corrupt on-disk byte.
    pub fn access(&self, role: Role) -> Result<AccessPermissions> {
        AccessPermissions::try_from(self.perms[role as usize])
    }

    /// Overwrite the raw permission byte for `role`. The caller is responsible
    /// for authorization (`may_set`) and for maintaining cross-role
    /// monotonicity; this is the unchecked setter used by the txn layer.
    pub fn set_access(&mut self, role: Role, access: AccessPermissions) {
        self.perms[role as usize] = access as u8;
    }

    /// Overwrite all three per-role permission bytes at once (indexed by
    /// `Role`). Used when initializing a new entry.
    pub fn set_perms(&mut self, perms: [AccessPermissions; 3]) {
        self.set_access(Role::None, perms[Role::None as usize]);
        self.set_access(Role::Interactive, perms[Role::Interactive as usize]);
        self.set_access(Role::System, perms[Role::System as usize]);
    }
}

/// Filesystem trait.
#[async_trait(?Send)]
pub trait FileSystem {
    /// Find a file or directory by its full path.
    async fn stat(
        &mut self,
        role: Role,
        parent_id: EntryId,
        filename: &str,
    ) -> Result<Option<(EntryId, EntryKind)>>;

    /// Create a file or directory with the given initial per-role permissions
    /// (indexed by `Role`). `[Access::Rwx; 3]` is the fully-permissive default.
    async fn create_entry(
        &mut self,
        role: Role,
        parent_id: EntryId,
        kind: EntryKind,
        name: &str, // Leaf name.
        perms: [AccessPermissions; 3],
    ) -> Result<EntryId>;

    /// Change one role's permission on an entry, acting as `caller`. Enforces
    /// authority and cross-role monotonicity (see PERMISSIONS_DESIGN.md);
    /// returns `PermissionDenied` if not allowed.
    async fn set_permissions(
        &mut self,
        caller: Role,
        entry_id: EntryId,
        target: Role,
        access: AccessPermissions,
    ) -> Result<()>;

    /// Delete the file or directory.
    async fn delete_entry(&mut self, role: Role, entry_id: EntryId) -> Result<()>;

    /// Rename and/or move the file or directory.
    async fn move_entry(
        &mut self,
        role: Role,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<()>;

    /// Get the first entry in a directory.
    async fn get_first_entry(&mut self, role: Role, parent_id: EntryId) -> Result<Option<EntryId>>;

    /// Get the next entry in a directory.
    async fn get_next_entry(&mut self, role: Role, entry_id: EntryId) -> Result<Option<EntryId>>;

    /// Get the parent of the entry.
    async fn get_parent(&mut self, role: Role, entry_id: EntryId) -> Result<Option<EntryId>>;

    /// Filename of the entry, without parent directories.
    async fn name(&mut self, role: Role, entry_id: EntryId) -> Result<String>;

    /// The metadata of the directory entry.
    async fn metadata(&mut self, role: Role, entry_id: EntryId) -> Result<Metadata>;

    /// Read bytes from a file.
    /// Note that cross-block reads may not be supported.
    async fn read(
        &mut self,
        role: Role,
        file_id: EntryId,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize>;

    /// Write bytes to a file.
    /// Note that cross-block writes may not be supported.
    async fn write(
        &mut self,
        role: Role,
        file_id: EntryId,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize>;

    /// Resize the file.
    async fn resize(&mut self, role: Role, file_id: EntryId, new_size: u64) -> Result<()>;

    /// The total number of blocks in the FS.
    fn num_blocks(&self) -> u64;

    async fn empty_blocks(&mut self) -> Result<u64>;

    /// Copies bytes from one file to another.
    async fn copy_file_range(
        &mut self,
        role: Role,
        from: EntryId,
        from_offset: u64,
        to: EntryId,
        to_offset: u64,
        size: u64,
    ) -> Result<u64>;

    /// Flush all in-memory blocks to the underlying block device.
    async fn flush(&mut self) -> Result<()>;
}
