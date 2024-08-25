use bitflags::bitflags;
use std::time::SystemTime;

pub use srfs_core::EntryKind;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Permissions: u64 {
        const READABLE = 1;
        const WRITABLE = 2;
        const EXECUTABLE = 4;
    }
}

#[derive(Clone, Copy)]
pub struct Attr {
    pub created: SystemTime,
    pub modified: SystemTime,
    pub size: u64,
    pub kind: EntryKind,
    pub permissions: Permissions,
}

impl From<srfs_core::Attr> for Attr {
    fn from(raw_attr: srfs_core::Attr) -> Self {
        Self {
            created: raw_attr.created.into(),
            modified: raw_attr.modified.into(),
            size: raw_attr.size,
            kind: raw_attr.id.kind(),
            permissions: Permissions::all(),
        }
    }
}
