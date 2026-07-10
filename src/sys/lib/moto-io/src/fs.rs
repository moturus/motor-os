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
    pub async fn stat(self: &Rc<Self>, path: &str) -> Result<(EntryId, EntryKind)> {
        if path.len() > moto_rt::fs::MAX_PATH_LEN || path.is_empty() {
            return Err(moto_rt::Error::InvalidArgument);
        }
        if path == "/" {
            return Ok((ROOT_ID, EntryKind::Directory));
        }

        if !path.starts_with('/') {
            return Err(moto_rt::Error::InvalidArgument);
        }

        let (mut entry_id, mut entry_kind) = (ROOT_ID, EntryKind::Directory);
        for entry_name in path.split('/') {
            if entry_name.is_empty() {
                continue;
            }

            if entry_kind != EntryKind::Directory {
                return Err(moto_rt::Error::NotFound);
            }

            (entry_id, entry_kind) = self.stat_one(entry_id, entry_name).await?;
        }

        Ok((entry_id, entry_kind))
    }

    async fn stat_one(
        self: &Rc<Self>,
        parent_id: EntryId,
        fname: &str,
    ) -> Result<(EntryId, EntryKind)> {
        let io_page = self.io_sender.alloc_page(u64::MAX).await?;
        let mut msg = api_fs::stat_msg_encode(parent_id, fname, io_page);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        api_fs::stat_resp_decode(resp)
    }

    /// Create a file or directory.
    pub async fn create_entry(
        self: &Rc<Self>,
        parent_id: EntryId,
        kind: EntryKind,
        name: &str, // Leaf name.
    ) -> Result<EntryId> {
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
        Ok(entry_id)
    }

    /// Write bytes to a file.
    pub async fn write(
        self: &Rc<Self>,
        file_id: EntryId,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize> {
        // Multi-block writes: each request carries up to WRITE_MAX_PAGES
        // io_pages of data (32K); see api_fs::write_multi_msg_encode.
        // A request whose data fits the first (boundary-limited) chunk uses
        // the classic single-page format. WINDOW requests in flight bound
        // transient page usage to WINDOW * WRITE_MAX_PAGES = 32 of the
        // channel's 64 client pages, leaving slack for concurrent
        // stat/create requests.
        const WINDOW: usize = 4;

        let mut buf_running = buf;

        let mut written = 0_usize;
        let mut send_offset = offset;
        let mut error = None;
        let mut short_write = false;

        while error.is_none() && !short_write && !buf_running.is_empty() {
            // (msg id, request len, multi format) of the in-flight batch.
            let mut batch = [(0_u64, 0_u32, false); WINDOW];
            let mut batch_idx = 0;
            while batch_idx < WINDOW && !buf_running.is_empty() {
                // The first chunk runs to a page boundary, so the request
                // spans at most WRITE_MAX_PAGES pages and no chunk crosses
                // an FS block boundary.
                let first_chunk =
                    ((BLOCK_SIZE as u64) - (send_offset & (BLOCK_SIZE as u64 - 1))) as usize;
                let req_len = buf_running
                    .len()
                    .min(first_chunk + (api_fs::WRITE_MAX_PAGES - 1) * BLOCK_SIZE)
                    as u32;
                debug_assert!(req_len as usize <= api_fs::WRITE_MAX_BYTES);
                let multi = req_len as usize > first_chunk;

                // Allocate and fill the data pages: page i holds chunk i.
                // On any failure the pages collected so far drop, freeing
                // them.
                let mut pages = alloc::vec::Vec::new();
                let mut filled = 0_usize;
                for chunk in api_fs::io_chunks(send_offset, req_len) {
                    match self.io_sender.alloc_page(u64::MAX).await {
                        Ok(io_page) => {
                            io_page.bytes_mut()[..chunk]
                                .clone_from_slice(&buf_running[filled..(filled + chunk)]);
                            filled += chunk;
                            pages.push(io_page);
                        }
                        Err(err) => {
                            error = Some(err);
                            break;
                        }
                    }
                }
                if error.is_some() {
                    break;
                }

                let mut msg = if multi {
                    api_fs::write_multi_msg_encode(file_id, send_offset, req_len, pages)
                } else {
                    api_fs::write_msg_encode(
                        file_id,
                        send_offset,
                        req_len as u16,
                        pages.pop().unwrap(),
                    )
                };
                let msg_id = self.new_request_id();
                msg.id = msg_id;
                if let Err(err) = self.clone().send(msg).await {
                    error = Some(err);
                    break;
                }

                batch[batch_idx] = (msg_id, req_len, multi);
                batch_idx += 1;
                send_offset += req_len as u64;
                buf_running = &buf_running[(req_len as usize)..];
            }

            // Always receive the response of every sent message, even after
            // an error: abandoned responses would leak in self.responses
            // forever. Responses are processed in send order, so `written`
            // counts a contiguous prefix; after an error or a short write,
            // later responses are drained but not counted (like any
            // pipelined write, file content past the reported prefix is
            // unspecified after a failure).
            for &(msg_id, req_len, multi) in batch.iter().take(batch_idx) {
                let resp = match self.clone().recv(msg_id).await {
                    Ok(resp) => resp,
                    Err(err) => {
                        if error.is_none() {
                            error = Some(err);
                        }
                        continue;
                    }
                };
                if error.is_some() || short_write {
                    continue;
                }

                // The response format follows the request format we chose:
                // the classic response is status-only (a full write).
                let done = if multi {
                    api_fs::write_multi_resp_decode(resp)
                } else {
                    resp.status().map(|_| req_len)
                };
                match done {
                    Ok(n) if n > req_len => error = Some(moto_rt::Error::InvalidData),
                    Ok(n) => {
                        written += n as usize;
                        if n < req_len {
                            short_write = true;
                        }
                    }
                    Err(err) => error = Some(err),
                }
            }
        }

        if written > 0 {
            Ok(written)
        } else if let Some(err) = error {
            Err(err)
        } else {
            Ok(0)
        }
    }

    /// Read bytes from a file.
    /// Note that cross-block reads may not be supported.
    pub async fn read(
        self: &Rc<Self>,
        file_id: EntryId,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        // Multi-block reads: each request asks for up to READ_MAX_PAGES
        // io_pages of data (48K) and gets one multi-page response (or the
        // classic single-page response when the request fits one page).
        // WINDOW requests in flight bound transient page usage to
        // WINDOW * READ_MAX_PAGES = 48 of the channel's 64 server pages,
        // leaving slack for concurrent stat/metadata responses.
        const WINDOW: usize = 4;

        let mut buf_running = buf;

        let mut actual_read = 0_usize;
        let mut send_offset = offset;
        let mut remaining_len = buf_running.len();
        let mut error = None;
        let mut eof = false;

        while error.is_none() && !eof && remaining_len > 0 {
            // (msg id, request offset, request len) of the in-flight batch.
            let mut batch = [(0_u64, 0_u64, 0_u32); WINDOW];
            let mut batch_idx = 0;
            while batch_idx < WINDOW && remaining_len > 0 {
                // The first chunk runs to a page boundary, so the whole
                // request spans at most READ_MAX_PAGES pages.
                let first_chunk =
                    ((BLOCK_SIZE as u64) - (send_offset & (BLOCK_SIZE as u64 - 1))) as usize;
                let req_len = remaining_len
                    .min(first_chunk + (api_fs::READ_MAX_PAGES - 1) * BLOCK_SIZE)
                    as u32;
                debug_assert!(req_len as usize <= api_fs::READ_MAX_BYTES);

                let mut msg = api_fs::read_msg_encode(file_id, send_offset, req_len as u16);
                let msg_id = self.new_request_id();
                msg.id = msg_id;
                if let Err(err) = self.clone().send(msg).await {
                    error = Some(err);
                    break;
                }

                batch[batch_idx] = (msg_id, send_offset, req_len);
                batch_idx += 1;
                send_offset += req_len as u64;
                remaining_len -= req_len as usize;
            }

            // Always receive the response of every sent message, even after an
            // error: abandoned responses would leak in self.responses forever,
            // together with their io_pages (the pool is finite). After an
            // error - or after a short (EOF) response - later responses are
            // drained but their data is discarded: `actual_read` must stay a
            // contiguous prefix of `buf`.
            for &(msg_id, req_offset, req_len) in batch.iter().take(batch_idx) {
                let resp = match self.clone().recv(msg_id).await {
                    Ok(resp) => resp,
                    Err(err) => {
                        if error.is_none() {
                            error = Some(err);
                        }
                        continue;
                    }
                };

                // The response format follows the request length we chose:
                // one page carries it => single-page format.
                let decoded = if req_len as usize <= BLOCK_SIZE {
                    api_fs::read_resp_decode(resp, &self.io_receiver.borrow())
                        .map(|(len, io_page)| (len as u32, alloc::vec![io_page]))
                } else {
                    api_fs::read_multi_resp_decode(resp, &self.io_receiver.borrow())
                };
                // Pages freed on drop, so error/discard paths below leak nothing.
                let (total, pages) = match decoded {
                    Ok(decoded) => decoded,
                    Err(err) => {
                        if error.is_none() {
                            error = Some(err);
                        }
                        continue;
                    }
                };

                if error.is_some() || eof {
                    continue;
                }

                // Reassemble: page i holds chunk i; chunk sizes derive from
                // (request offset, total) on both sides.
                let mut copied = 0_usize;
                let mut valid = total <= req_len;
                if valid {
                    for (io_page, chunk) in
                        pages.iter().zip(api_fs::io_chunks(req_offset, total))
                    {
                        buf_running[copied..(copied + chunk)]
                            .clone_from_slice(&io_page.bytes()[..chunk]);
                        copied += chunk;
                    }
                    // Fewer pages than chunks => a malformed response.
                    valid = copied == total as usize;
                }
                if !valid {
                    error = Some(moto_rt::Error::InvalidData);
                    continue;
                }

                actual_read += copied;
                buf_running = &mut buf_running[copied..];
                if copied < req_len as usize {
                    eof = true;
                }
            }
        }

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

    /// Copy up to `size` bytes from file `from` to file `to`, both at `offset`.
    /// Returns the number of bytes actually copied, which may be less than
    /// `size` if the end of the source file is reached.
    pub async fn copy_file_range(
        self: &Rc<Self>,
        from: EntryId,
        to: EntryId,
        offset: u64,
        size: u64,
    ) -> Result<u64> {
        let mut msg = api_fs::copy_file_range_req_encode(from, to, offset, size);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        api_fs::copy_file_range_resp_decode(resp)
    }

    /// The metadata of the directory entry.
    pub async fn metadata(self: &Rc<Self>, entry_id: EntryId) -> Result<Metadata> {
        let mut msg = api_fs::metadata_msg_encode(entry_id);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        let metadata = api_fs::metadata_resp_decode(resp, &self.io_receiver.borrow())?;
        Ok(metadata)
    }

    /// Resize the file.
    pub async fn resize(self: &Rc<Self>, file_id: EntryId, new_size: u64) -> Result<()> {
        let mut msg = api_fs::resize_msg_encode(file_id, new_size);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        resp.status()
    }

    /// Delete the file or directory.
    pub async fn delete_entry(self: &Rc<Self>, entry_id: EntryId) -> Result<()> {
        let mut msg = api_fs::delete_entry_msg_encode(entry_id);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        resp.status()
    }

    pub async fn flush(self: &Rc<Self>) -> Result<()> {
        let mut msg = api_fs::flush_msg_encode();
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        resp.status()
    }

    /// Rename and/or move the file or directory.
    pub async fn move_entry(
        self: &Rc<Self>,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<()> {
        let io_page = self.io_sender.alloc_page(u64::MAX).await?;
        let mut msg = api_fs::move_entry_req_encode(entry_id, new_parent_id, new_name, io_page);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        resp.status()
    }

    /// Get the first entry in a directory.
    pub async fn get_first_entry(self: &Rc<Self>, parent_id: EntryId) -> Result<Option<EntryId>> {
        let mut msg = api_fs::get_first_entry_req_encode(parent_id);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        api_fs::get_first_entry_resp_decode(resp)
    }

    /// Get the next entry in a directory.
    pub async fn get_next_entry(self: &Rc<Self>, entry_id: EntryId) -> Result<Option<EntryId>> {
        let mut msg = api_fs::get_next_entry_req_encode(entry_id);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        api_fs::get_next_entry_resp_decode(resp)
    }

    /// Get the parent of the entry.
    async fn get_parent(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        todo!()
    }

    /// Filename of the entry, without parent directories.
    pub async fn name(self: &Rc<Self>, entry_id: EntryId) -> Result<String> {
        let mut msg = api_fs::get_name_req_encode(entry_id);
        msg.id = self.new_request_id();

        let resp = self.clone().send_recv(msg).await?;
        api_fs::get_name_resp_decode(resp, &self.io_receiver.borrow())
    }

    /// The total number of blocks in the FS.
    fn num_blocks(&self) -> u64 {
        todo!()
    }

    async fn empty_blocks(&mut self) -> Result<u64> {
        todo!()
    }
}
