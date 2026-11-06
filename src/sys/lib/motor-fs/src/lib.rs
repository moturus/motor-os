//! Motor FS.
//!
//! Motor Filesystem is work-in-progress. It is designed for use in
//! virtual machines and thus has certain assumptions that simplify its
//! design vs traditional filesystems that are designed to run on real
//! hardware.
//!
//! More specifically:
//! - Block writes are assumed to be atomic;
//! - No "on disk" data corruption is assumed or protected against;
//! - Only resistance to "power off" is built-in.
#![feature(random)]

#[cfg(all(feature = "image-admin", target_os = "motor"))]
compile_error!("motor-fs feature `image-admin` is only available on Linux hosts");

mod bplus_tree;
mod city_hash;
mod fs;
mod layout;
mod txn;
mod txn_log;

pub(crate) use layout::*;
pub(crate) use txn::*;

pub use fs::*;
pub use layout::{ROOT_DIR_ID, has_superblock_magic};

/// Superblock, root, journal and at least one allocatable filesystem block.
pub const MIN_BLOCKS: u64 = layout::RESERVED_BLOCKS as u64 + 1;

#[cfg(test)]
mod tests;
