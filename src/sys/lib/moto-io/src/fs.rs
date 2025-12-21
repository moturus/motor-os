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
use alloc::collections::btree_map::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use async_trait::async_trait;
use core::{
    cell::{Cell, RefCell},
    task::{LocalWaker, Poll},
};
use moto_ipc::io_channel::Msg;
use moto_rt::Error;
use moto_sys_io::api_fs;

pub use async_fs::{EntryId, EntryKind, Metadata, ROOT_ID, Result};

pub struct FsClient {
    io_sender: moto_ipc::io_channel::Sender,
    io_receiver: moto_ipc::io_channel::Receiver,

    // Because FsClient is single-threaded, we use Cell<>, not AtomicU64.
    request_counter: Cell<u64>,

    responses: RefCell<BTreeMap<u64, ResponseWaiter>>,
}

enum ResponseWaiter {
    Waker(LocalWaker),
    Msg(Msg),
}

pub struct ResponseFuture {
    request_id: u64,
    fs_client: Rc<FsClient>,
}

impl Future for ResponseFuture {
    type Output = Result<Msg>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let mut responses = self.fs_client.responses.borrow_mut();
        match responses.entry(self.request_id) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(ResponseWaiter::Waker(cx.local_waker().clone()));
                Poll::Pending
            }
            alloc::collections::btree_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                ResponseWaiter::Waker(local_waker) => {
                    *local_waker = cx.local_waker().clone();
                    Poll::Pending
                }
                ResponseWaiter::Msg(msg) => Poll::Ready(Ok(*msg)),
            },
        }
    }
}

impl FsClient {
    fn new_request_id(&self) -> u64 {
        self.request_counter.update(|id| id + 1);
        self.request_counter.get()
    }

    async fn send_recv(self: Rc<Self>, msg: Msg) -> Result<Msg> {
        self.io_sender.send(msg).await?;
        ResponseFuture {
            request_id: msg.id,
            fs_client: self,
        }
        .await
    }

    pub fn connect() -> Result<Rc<Self>> {
        let (io_sender, io_receiver) = moto_ipc::io_channel::connect(moto_sys_io::api_fs::FS_URL)?;
        Ok(Rc::new(Self {
            io_sender,
            io_receiver,
            request_counter: Cell::new(0),
            responses: Default::default(),
        }))
    }

    /// Find a file or directory by its full path.
    pub async fn stat(self: &Rc<Self>, path: &str) -> Result<EntryId> {
        if path.len() > moto_rt::fs::MAX_PATH_LEN || path.is_empty() {
            return Err(moto_rt::Error::InvalidArgument);
        }
        if path == "/" {
            return Ok(ROOT_ID);
        }

        if !path.starts_with('/') {
            return Err(moto_rt::Error::InvalidArgument);
        }

        let mut current = ROOT_ID;
        for entry in path.split('/') {
            if entry.is_empty() {
                continue;
            }

            let current = self.stat_one(current, entry).await?;
        }

        Ok(current)
    }

    async fn stat_one(self: &Rc<Self>, parent_id: EntryId, fname: &str) -> Result<EntryId> {
        moto_rt::error::log_to_kernel("stat one");
        let io_page = self.io_sender.alloc_page(u64::MAX).await?;
        let mut msg = api_fs::stat_msg_encode(parent_id, fname, io_page);
        msg.id = self.new_request_id();

        let _self = self.clone();
        let response = moto_async::LocalRuntime::spawn(_self.send_recv(msg)).await;

        todo!("{fname}")
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
