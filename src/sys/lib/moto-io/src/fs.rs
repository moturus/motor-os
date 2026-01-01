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
use alloc::rc::Weak;
use alloc::string::String;
use async_trait::async_trait;
use core::pin::Pin;
use core::{
    cell::{Cell, RefCell},
    task::{LocalWaker, Poll},
};
use moto_ipc::io_channel::Msg;
use moto_rt::Result;
use moto_sys_io::api_fs;

use async_fs::BLOCK_SIZE;
pub use async_fs::{EntryId, EntryKind, Metadata, ROOT_ID};

pub struct FsClient {
    io_sender: moto_ipc::io_channel::Sender,
    io_receiver: RefCell<moto_ipc::io_channel::Receiver>,

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
    fs_client: Weak<FsClient>,
}

impl Future for ResponseFuture {
    type Output = Result<Msg>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let Some(fs_client) = self.fs_client.upgrade() else {
            return Poll::Ready(Err(moto_rt::Error::NotConnected));
        };

        let mut responses = fs_client.responses.borrow_mut();
        match responses.entry(self.request_id) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(ResponseWaiter::Waker(cx.local_waker().clone()));
            }
            alloc::collections::btree_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                ResponseWaiter::Waker(local_waker) => {
                    *local_waker = cx.local_waker().clone();
                }
                ResponseWaiter::Msg(msg) => {
                    let msg = *msg;
                    let _ = entry.remove_entry();
                    return Poll::Ready(Ok(msg));
                }
            },
        }
        core::mem::drop(responses);

        let result = loop {
            match fs_client.io_receiver.borrow_mut().poll_recv(cx) {
                Poll::Ready(Err(err)) => {
                    break Err(err);
                }
                Poll::Ready(Ok(msg)) => {
                    if msg.id == self.request_id {
                        break Ok(msg);
                    } else {
                        let mut responses = fs_client.responses.borrow_mut();
                        match responses.entry(msg.id) {
                            alloc::collections::btree_map::Entry::Vacant(entry) => {
                                entry.insert_entry(ResponseWaiter::Msg(msg));
                            }
                            alloc::collections::btree_map::Entry::Occupied(mut entry) => {
                                match entry.get_mut() {
                                    ResponseWaiter::Waker(local_waker) => {
                                        let mut val = ResponseWaiter::Msg(msg);
                                        core::mem::swap(&mut val, entry.get_mut());
                                        let ResponseWaiter::Waker(waker) = val else {
                                            panic!();
                                        };
                                        waker.wake();
                                        continue;
                                    }
                                    ResponseWaiter::Msg(msg) => todo!(),
                                }
                            }
                        }
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
        };

        fs_client.responses.borrow_mut().remove(&self.request_id);
        Poll::Ready(result)
    }
}

impl FsClient {
    fn new_request_id(&self) -> u64 {
        self.request_counter.update(|id| id + 1);
        self.request_counter.get()
    }

    async fn send_recv(self: Rc<Self>, msg: Msg) -> Result<Msg> {
        self.clone().send(msg).await?;
        self.recv(msg.id).await
    }

    async fn send(self: Rc<Self>, msg: Msg) -> Result<()> {
        self.io_sender.send(msg).await
    }

    async fn recv(self: Rc<Self>, msg_id: u64) -> Result<Msg> {
        ResponseFuture {
            request_id: msg_id,
            fs_client: Rc::downgrade(&self),
        }
        .await
    }

    pub fn connect() -> Result<Rc<Self>> {
        let (io_sender, io_receiver) = moto_ipc::io_channel::connect(moto_sys_io::api_fs::FS_URL)?;
        Ok(Rc::new(Self {
            io_sender,
            io_receiver: RefCell::new(io_receiver),
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

            current = self.stat_one(current, entry).await?;
        }

        Ok(current)
    }

    async fn stat_one(self: &Rc<Self>, parent_id: EntryId, fname: &str) -> Result<EntryId> {
        log::debug!("stat_one({parent_id:x}, '{fname}')");
        let io_page = self.io_sender.alloc_page(u64::MAX).await?;
        let mut msg = api_fs::stat_msg_encode(parent_id, fname, io_page);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        let entry_id = api_fs::stat_resp_decode(resp)?;
        log::debug!("stat_one({parent_id:x}, '{fname}') => {entry_id:x}");
        Ok(entry_id)
    }

    /// Create a file or directory.
    pub async fn create_entry(
        self: &Rc<Self>,
        parent_id: EntryId,
        kind: EntryKind,
        name: &str, // Leaf name.
    ) -> Result<EntryId> {
        log::debug!("create_entry({parent_id:x}, {kind:?}, '{name}')");
        let io_page = self.io_sender.alloc_page(u64::MAX).await?;
        let mut msg = api_fs::create_entry_msg_encode(
            parent_id,
            kind == EntryKind::Directory, /* is_dir */
            name,
            io_page,
        );
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        let entry_id = api_fs::create_entry_resp_decode(resp)?;
        log::debug!("created entry {entry_id:x}");
        Ok(entry_id)
    }

    /// Write bytes to a file.
    /// Note that cross-block writes may not be supported.
    pub async fn write(
        self: &Rc<Self>,
        file_id: EntryId,
        offset: u64,
        mut buf: &[u8],
    ) -> Result<usize> {
        log::debug!(
            "write({file_id:x}): offset: 0x{offset:x}, len: {}",
            buf.len()
        );

        let mut written = 0_usize;
        let mut step_offset = offset;
        loop {
            // `buf` can be large; we split it into 4k chunks; we send them
            // in batches of BATCH_SIZE and then wait for completions.
            const BATCH_SIZE: usize = 16;

            let mut batch_ids = [0_u64; BATCH_SIZE];
            let mut batch_idx = 0;
            loop {
                let step_len = ((BLOCK_SIZE as u64) - (step_offset & (BLOCK_SIZE as u64 - 1)))
                    .min(buf.len() as u64);
                debug_assert!(step_len < u16::MAX as u64);

                let io_page = self.io_sender.alloc_page(u64::MAX).await?;
                io_page.bytes_mut()[0..step_len as usize]
                    .clone_from_slice(&buf[0..(step_len as usize)]);

                let mut msg =
                    api_fs::write_msg_encode(file_id, step_offset, step_len as u16, io_page);
                let msg_id = self.new_request_id();
                msg.id = msg_id;
                if let Err(err) = self.clone().send(msg).await {
                    todo!()
                }

                written += (step_len as usize);
                step_offset += step_len;
                buf = &buf[(step_len as usize)..];

                batch_ids[batch_idx] = msg_id;
                batch_idx += 1;
                if batch_idx >= BATCH_SIZE {
                    break;
                }

                if buf.is_empty() {
                    break;
                }
            }

            for id in batch_ids {
                if id == 0 {
                    break;
                }
                if let Err(err) = self.clone().recv(id).await {
                    todo!()
                }
            }

            if buf.is_empty() {
                break;
            }
        }

        log::debug!("wrote {written} bytes to {file_id:x}) at offset: 0x{offset:x}");
        Ok(written)
    }

    /// Read bytes from a file.
    /// Note that cross-block reads may not be supported.
    pub async fn read(
        self: &Rc<Self>,
        file_id: EntryId,
        offset: u64,
        mut buf: &mut [u8],
    ) -> Result<usize> {
        log::debug!(
            "read({file_id:x}): offset: 0x{offset:x}, len: {}",
            buf.len()
        );

        let mut to_be_read = 0_usize;
        let mut actual_read = 0_usize;
        let mut step_offset = offset;
        let mut remaining_len = buf.len();
        let mut error = None;
        loop {
            // `buf` can be large; we split it into 4k chunks; we send them
            // in batches of BATCH_SIZE and then wait for completions.
            const BATCH_SIZE: usize = 16;

            let mut batch_ids = [0_u64; BATCH_SIZE];
            let mut batch_idx = 0;
            loop {
                let step_len = ((BLOCK_SIZE as u64) - (step_offset & (BLOCK_SIZE as u64 - 1)))
                    .min(remaining_len as u64);
                debug_assert!(step_len < u16::MAX as u64);

                let mut msg = api_fs::read_msg_encode(file_id, step_offset, step_len as u16);
                let msg_id = self.new_request_id();
                msg.id = msg_id;
                if let Err(err) = self.clone().send(msg).await {
                    todo!()
                }

                to_be_read += (step_len as usize);
                step_offset += step_len;
                remaining_len -= (step_len as usize);

                batch_ids[batch_idx] = msg_id;
                batch_idx += 1;
                if batch_idx >= BATCH_SIZE {
                    break;
                }

                if remaining_len == 0 {
                    break;
                }
            }

            for id in batch_ids {
                if id == 0 {
                    break;
                }
                match self.clone().recv(id).await {
                    Ok(msg) => match api_fs::read_resp_decode(msg, &self.io_receiver.borrow()) {
                        Ok((len, io_page)) => {
                            assert!(len as usize <= buf.len());
                            buf[..(len as usize)]
                                .clone_from_slice(&io_page.bytes()[..(len as usize)]);
                            buf = &mut buf[..(len as usize)];
                            actual_read += len as usize;
                        }
                        Err(err) => {
                            error = Some(err);
                            break;
                        }
                    },
                    Err(err) => {
                        error = Some(err);
                        break;
                    }
                }
            }

            if remaining_len == 0 {
                break;
            }
        }

        log::debug!("done reading {actual_read} bytes from {file_id:x}) at offset: 0x{offset:x}");
        if actual_read > 0 {
            Ok(actual_read)
        } else if let Some(err) = error {
            if err == moto_rt::Error::UnexpectedEof {
                Ok(0)
            } else {
                Err(err)
            }
        } else {
            Ok(0)
        }
    }

    /// The metadata of the directory entry.
    pub async fn metadata(self: &Rc<Self>, entry_id: EntryId) -> Result<Metadata> {
        log::debug!("metadata({entry_id:x})");
        let mut msg = api_fs::metadata_msg_encode(entry_id);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        let metadata = api_fs::metadata_resp_decode(resp, &self.io_receiver.borrow())?;
        log::debug!(
            "metadata({entry_id:x}) => {:?} sz: {}",
            metadata.kind(),
            metadata.size
        );
        Ok(metadata)
    }

    /// Resize the file.
    pub async fn resize(self: &Rc<Self>, file_id: EntryId, new_size: u64) -> Result<()> {
        log::debug!("resize({file_id:x}, {new_size})");
        let mut msg = api_fs::resize_msg_encode(file_id, new_size);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        resp.status()
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
