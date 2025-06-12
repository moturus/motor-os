//! Simple Rust File System
//!
//! A simple filesystem impremented in Rust.
//!
//! This crate is a work-in-progress. It contains synchronous
//! high-level API, similar to std::fs::* in Rust, and uses
//! crate srfs-core internally. For use with \[std\].
//!
//! All basic filesystem features are implemented (see ```struct FileSystem```),
//! with provisions for extensions.
//!
//! At the moment only synchronous interface is provided.
//!
//! TODO:
//!
//! * crash recovery
//! * timestamps
//! * async API
//!
//! Contributions are welcome.

#![feature(io_error_more)]

extern crate alloc;

pub use srfs_core::BLOCK_SIZE;
pub use srfs_core::MAX_DIR_ENTRIES;
pub use srfs_core::MAX_FILE_SIZE;
pub use srfs_core::PARTITION_ID;
pub use srfs_core::SyncBlockDevice;

mod attr;
mod file;
mod filesystem;
mod readdir;

pub use attr::*;
pub use file::*;
pub use filesystem::*;
pub use readdir::*;
