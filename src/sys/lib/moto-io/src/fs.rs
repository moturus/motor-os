//! Asynchronous file operations.
//!
//! This module contains utility methods for working with the file system
//! asynchronously. This includes reading/writing to files, and working with
//! directories. Key differences from a standard async fs API (e.g. tokio):
//!    (a) moto-io API is no-std
//!    (b) moto-io API is somewhat simpler than that of Tokio, which in some
//!        areas appears to be too complex/over-engineered
//!    (c) moto-io API is "local" (current thread only)
#![allow(unused)]
extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
pub use async_fs::{EntryId, EntryKind, Metadata, ROOT_ID, Result};
use async_trait::async_trait;

pub struct FileSystem {}

#[async_trait(?Send)]
impl async_fs::FileSystem for FileSystem {
    /// Find a file or directory by its full path.
    async fn stat(&mut self, parent_id: EntryId, filename: &str) -> Result<Option<EntryId>> {
        todo!()
    }

    /// Create a file or directory.
    async fn create_entry(
        &mut self,
        parent_id: EntryId,
        kind: EntryKind,
        name: &str, // Leaf name.
    ) -> Result<EntryId> {
        todo!()
    }

    /// Delete the file or directory.
    async fn delete_entry(&mut self, entry_id: EntryId) -> Result<()> {
        todo!()
    }

    /// Rename and/or move the file or directory.
    async fn move_entry(
        &mut self,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<()> {
        todo!()
    }

    /// Get the first entry in a directory.
    async fn get_first_entry(&mut self, parent_id: EntryId) -> Result<Option<EntryId>> {
        todo!()
    }

    /// Get the next entry in a directory.
    async fn get_next_entry(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        todo!()
    }

    /// Get the parent of the entry.
    async fn get_parent(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        todo!()
    }

    /// Filename of the entry, without parent directories.
    async fn name(&mut self, entry_id: EntryId) -> Result<String> {
        todo!()
    }

    /// The metadata of the directory entry.
    async fn metadata(&mut self, entry_id: EntryId) -> Result<Metadata> {
        todo!()
    }

    /// Read bytes from a file.
    /// Note that cross-block reads may not be supported.
    async fn read(&mut self, file_id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        todo!()
    }

    /// Write bytes to a file.
    /// Note that cross-block writes may not be supported.
    async fn write(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize> {
        todo!()
    }

    /// Resize the file.
    async fn resize(&mut self, file_id: EntryId, new_size: u64) -> Result<()> {
        todo!()
    }

    /// The total number of blocks in the FS.
    fn num_blocks(&self) -> u64 {
        todo!()
    }

    async fn empty_blocks(&mut self) -> Result<u64> {
        todo!()
    }

    async fn flush(&mut self) -> Result<()> {
        todo!()
    }
}
