use async_fs::EntryId;
use moto_ipc::io_channel::{IoPage, Msg, PAGE_SIZE, Sender};
use moto_rt::Result;
use moto_rt::fs::MAX_PATH_LEN;

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const FS_URL: &str = "sys-io-fs";
pub const CMD_STAT: u16 = 1;
pub const CMD_CREATE_FILE: u16 = 2;
pub const CMD_CREATE_DIR: u16 = 3;
pub const CMD_WRITE: u16 = 4;
pub const CMD_READ: u16 = 5;
pub const CMD_METADATA: u16 = 6;
pub const CMD_RESIZE: u16 = 7;
pub const CMD_DELETE_ENTRY: u16 = 8;
pub const CMD_FLUSH: u16 = 9;
pub const CMD_GET_FIRST_ENTRY: u16 = 10;
pub const CMD_GET_NEXT_ENTRY: u16 = 11;
pub const CMD_GET_NAME: u16 = 12;
pub const CMD_MOVE_ENTRY: u16 = 13;
pub const CMD_COPY_FILE_RANGE: u16 = 14;
pub const CMD_FILE_LOCK: u16 = 15;
pub const CMD_SET_PERMISSIONS: u16 = 16;

pub fn file_lock_msg_encode(entry_id: EntryId, open_id: u64, operation: u8) -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_FILE_LOCK;
    msg.payload.set_arg_128(entry_id);
    msg.handle = open_id;
    msg.payload.args_8_mut()[16] = operation;
    msg
}

pub fn file_lock_msg_decode(msg: Msg) -> Result<(EntryId, u64, u8)> {
    Ok((msg.payload.arg_128(), msg.handle, msg.payload.args_8()[16]))
}

pub fn stat_msg_encode(parent_id: u128, fname: &str, io_page: IoPage) -> Msg {
    assert!(fname.len() <= MAX_PATH_LEN);

    let mut msg = Msg::new();
    msg.command = CMD_STAT;

    msg.payload.set_arg_128(parent_id);
    let fname_len: u16 = fname.len() as u16;

    let bytes = io_page.bytes_mut();
    bytes[0..2].clone_from_slice(&fname_len.to_ne_bytes());
    bytes[2..(2 + fname.len())].clone_from_slice(fname.as_bytes());

    msg.payload.shared_pages_mut()[11] = IoPage::into_u16(io_page);
    msg
}

pub fn stat_msg_decode(msg: Msg, sender: &Sender) -> Result<(u128, String)> {
    let parent_id = msg.payload.arg_128();
    let io_page_idx = msg.payload.shared_pages()[11];
    let io_page = sender.get_page(io_page_idx)?;

    let bytes = io_page.bytes();
    let fname_len: usize = u16::from_ne_bytes(bytes[0..2].try_into().unwrap()) as usize;
    if fname_len > MAX_PATH_LEN {
        log::warn!("stat_msg_decode: bad fname len {fname_len}");
        return Err(moto_rt::Error::InvalidFilename);
    }

    let fname_vec = bytes[2..(2 + fname_len)].to_vec();
    let fname = String::from_utf8(fname_vec).map_err(|err| {
        log::warn!("stat_msg_decode: utf8 err: {err:?}");
        moto_rt::Error::InvalidFilename
    })?;

    Ok((parent_id, fname))
}

pub fn stat_resp_encode(req: Msg, entry_id: u128, entry_kind: async_fs::EntryKind) -> Msg {
    let mut resp = Msg::new();
    resp.id = req.id;
    resp.handle = req.handle;

    resp.command = CMD_STAT;
    resp.status = moto_rt::Error::Ok.into();

    resp.payload.set_arg_128(entry_id);
    resp.payload.args_8_mut()[23] = entry_kind as u8;
    resp
}

pub fn stat_resp_decode(msg: Msg) -> Result<(u128, async_fs::EntryKind)> {
    msg.status()?;
    Ok((
        msg.payload.arg_128(),
        msg.payload.args_8()[23]
            .try_into()
            .map_err(|_| moto_rt::Error::InternalError)?,
    ))
}

pub fn create_entry_msg_encode(parent_id: u128, is_dir: bool, name: &str, io_page: IoPage) -> Msg {
    let mut msg = stat_msg_encode(parent_id, name, io_page);
    msg.command = if is_dir {
        CMD_CREATE_DIR
    } else {
        CMD_CREATE_FILE
    };
    msg
}

pub fn create_entry_msg_decode(msg: Msg, sender: &Sender) -> Result<(u128, String)> {
    stat_msg_decode(msg, sender)
}

pub fn create_entry_resp_decode(msg: Msg) -> Result<u128> {
    msg.status().map(|_| msg.payload.arg_128())
}

pub fn empty_resp_encode(msg_id: u64, status: Result<()>) -> Msg {
    let mut resp = Msg::new();
    resp.id = msg_id;

    resp.status = match status {
        Ok(()) => moto_rt::Error::Ok.into(),
        Err(err) => err.into(),
    };

    resp
}

pub fn write_msg_encode(file_id: u128, offset: u64, len: u16, io_page: IoPage) -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_WRITE;

    msg.payload.set_arg_128(file_id); // This takes 16 bytes.
    msg.handle = offset;
    msg.payload.args_16_mut()[10] = len;
    msg.payload.shared_pages_mut()[11] = IoPage::into_u16(io_page);

    msg
}

pub fn write_msg_decode(msg: Msg, sender: &Sender) -> Result<(u128, u64, u16, IoPage)> {
    let file_id = msg.payload.arg_128();
    let io_page_idx = msg.payload.shared_pages()[11];
    let io_page = sender.get_page(io_page_idx)?;

    let offset = msg.handle;
    let len = msg.payload.args_16()[10];

    Ok((file_id, offset, len, io_page))
}

/// Multi-block writes, mirroring multi-block reads: a CMD_WRITE request whose
/// data spans more than one io_page carries up to [`WRITE_MAX_PAGES`] pages
/// in `payload.shared_pages[0..8]`, holding chunks in [`io_chunks`] order.
/// To make room, the file id moves to the long handle and the offset to
/// `payload.args_64()[2]`; the total length travels in `Msg::flags` — a
/// classic single-page write leaves `flags` zero, which is how the server
/// tells the request formats apart. The response returns the number of bytes
/// actually written in `Msg::flags`; a short count means a later chunk
/// failed after earlier ones were written.
pub const WRITE_MAX_PAGES: usize = 8;
pub const WRITE_MAX_BYTES: usize = WRITE_MAX_PAGES * PAGE_SIZE; // 32K.

pub fn write_multi_msg_encode(file_id: u128, offset: u64, len: u32, pages: Vec<IoPage>) -> Msg {
    debug_assert!(len > 0 && len as usize <= WRITE_MAX_BYTES);
    debug_assert_eq!(pages.len(), io_chunks(offset, len).count());

    let mut msg = Msg::new();
    msg.command = CMD_WRITE;
    msg.set_long_handle(file_id);
    msg.flags = len;
    msg.payload.args_64_mut()[2] = offset;
    for (idx, page) in pages.into_iter().enumerate() {
        msg.payload.shared_pages_mut()[idx] = IoPage::into_u16(page);
    }

    msg
}

/// Decode a multi-page write request: (file_id, offset, len, data pages).
/// Page i holds chunk i of `io_chunks(offset, len)`.
pub fn write_multi_msg_decode(msg: Msg, sender: &Sender) -> Result<(u128, u64, u32, Vec<IoPage>)> {
    let file_id = msg.get_long_handle();
    let offset = msg.payload.args_64()[2];
    let len = msg.flags;

    // (offset, len) come from an untrusted client; bound them before
    // recovering pages. The byte bound alone does not bound the page count:
    // an unaligned WRITE_MAX_BYTES write would span one page too many.
    if len == 0 || len as usize > WRITE_MAX_BYTES {
        return Err(moto_rt::Error::InvalidArgument);
    }
    let num_pages = io_chunks(offset, len).count();
    if num_pages > WRITE_MAX_PAGES {
        return Err(moto_rt::Error::InvalidArgument);
    }

    let mut pages = Vec::with_capacity(num_pages);
    for idx in 0..num_pages {
        // Note: pages already recovered are dropped (freed) if a later
        // get_page fails; see read_multi_resp_decode.
        pages.push(sender.get_page(msg.payload.shared_pages()[idx])?);
    }

    Ok((file_id, offset, len, pages))
}

pub fn write_multi_resp_encode(msg_id: u64, written: u32) -> Msg {
    let mut msg = Msg::new();
    msg.id = msg_id;
    msg.command = CMD_WRITE;
    msg.status = moto_rt::Error::Ok.into();
    msg.flags = written;

    msg
}

/// Decode a multi-page write response: the number of bytes written.
pub fn write_multi_resp_decode(msg: Msg) -> Result<u32> {
    msg.status()?;
    Ok(msg.flags)
}

/// Multi-block reads: a CMD_READ request whose `len` spans more than one
/// io_page is answered with a *multi-page* response carrying up to
/// [`READ_MAX_PAGES`] pages in `payload.shared_pages` (its full capacity).
/// A request with `len <= PAGE_SIZE` gets the classic single-page response;
/// the requester picked `len`, so it always knows which response format to
/// expect. This amortizes the fixed per-message cost (decode, page alloc,
/// locking, response send + wake) over up to 48K instead of 4K.
pub const READ_MAX_PAGES: usize = 12;
pub const READ_MAX_BYTES: usize = READ_MAX_PAGES * PAGE_SIZE; // 48K.

/// A multi-page read response packs the total length and the page count
/// into `Msg::flags`: pages hold chunks of deterministic sizes (see
/// [`io_chunks`]), so nothing else needs to travel.
const READ_RESP_LEN_MASK: u32 = (1 << 20) - 1;
const READ_RESP_PAGES_SHIFT: u32 = 20;
const _: () = assert!(READ_MAX_BYTES as u32 <= READ_RESP_LEN_MASK);

/// The per-page chunk sizes of a read or write at `offset` for `len` bytes:
/// the first chunk runs to the next io_page boundary, each following chunk is
/// a whole page (the last possibly partial). Both sides derive the same
/// split, so only (offset, len) travel on the wire.
pub fn io_chunks(offset: u64, len: u32) -> impl Iterator<Item = usize> {
    let mut chunk_offset = offset;
    let mut remaining = len as usize;
    core::iter::from_fn(move || {
        if remaining == 0 {
            return None;
        }
        let step = (PAGE_SIZE - (chunk_offset as usize % PAGE_SIZE)).min(remaining);
        chunk_offset += step as u64;
        remaining -= step;
        Some(step)
    })
}

/// Encode a multi-page read response. `total_len` is the number of bytes
/// actually read; `pages` hold its chunks in [`io_chunks`] order.
pub fn read_multi_resp_encode(msg_id: u64, total_len: u32, pages: Vec<IoPage>) -> Msg {
    debug_assert!(pages.len() <= READ_MAX_PAGES);
    debug_assert!(total_len as usize <= READ_MAX_BYTES);

    let mut msg = Msg::new();
    msg.id = msg_id;
    msg.command = CMD_READ;
    msg.status = moto_rt::Error::Ok.into();
    msg.flags = total_len | ((pages.len() as u32) << READ_RESP_PAGES_SHIFT);
    for (idx, page) in pages.into_iter().enumerate() {
        msg.payload.shared_pages_mut()[idx] = IoPage::into_u16(page);
    }

    msg
}

/// Decode a multi-page read response: (total bytes read, that data's pages).
pub fn read_multi_resp_decode(msg: Msg, receiver: &Sender) -> Result<(u32, Vec<IoPage>)> {
    msg.status()?;

    let total_len = msg.flags & READ_RESP_LEN_MASK;
    let num_pages = (msg.flags >> READ_RESP_PAGES_SHIFT) as usize;
    if num_pages > READ_MAX_PAGES || total_len as usize > READ_MAX_BYTES {
        return Err(moto_rt::Error::InvalidData);
    }

    let mut pages = Vec::with_capacity(num_pages);
    for idx in 0..num_pages {
        // Note: pages already recovered are dropped (freed) if a later
        // get_page fails; the failed message's remaining pages leak, but a
        // bad page index means channel corruption, matching the single-page
        // decode's behavior.
        pages.push(receiver.get_page(msg.payload.shared_pages()[idx])?);
    }

    Ok((total_len, pages))
}

pub fn read_msg_encode(file_id: u128, offset: u64, len: u16) -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_READ;

    msg.payload.set_arg_128(file_id); // This takes 16 bytes.
    msg.handle = offset;
    msg.payload.args_16_mut()[10] = len;

    msg
}

pub fn read_msg_decode(msg: Msg) -> (u128, u64, u16) {
    let file_id = msg.payload.arg_128();
    let offset = msg.handle;
    let len = msg.payload.args_16()[10];

    (file_id, offset, len)
}

pub fn read_resp_encode(msg_id: u64, len: u16, io_page: IoPage) -> Msg {
    let mut msg = Msg::new();
    msg.id = msg_id;
    msg.command = CMD_READ;
    msg.status = moto_rt::Error::Ok.into();

    msg.payload.args_16_mut()[10] = len;
    msg.payload.shared_pages_mut()[11] = IoPage::into_u16(io_page);

    msg
}

pub fn read_resp_decode(msg: Msg, receiver: &Sender) -> Result<(u16, IoPage)> {
    msg.status()?;

    let io_page_idx = msg.payload.shared_pages()[11];
    let io_page = receiver.get_page(io_page_idx)?;
    let len = msg.payload.args_16()[10];

    Ok((len, io_page))
}

pub fn metadata_msg_encode(entry_id: u128) -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_METADATA;
    msg.payload.set_arg_128(entry_id); // This takes 16 bytes.

    msg
}

pub fn metadata_msg_decode(msg: Msg) -> u128 {
    msg.payload.arg_128()
}

pub fn metadata_resp_encode(msg_id: u64, metadata: async_fs::Metadata, io_page: IoPage) -> Msg {
    // Safety: see metadata_resp_decode below.
    unsafe {
        core::ptr::copy_nonoverlapping(
            &metadata as *const _ as usize as *const u8,
            io_page.bytes_mut().as_mut_ptr(),
            size_of::<async_fs::Metadata>(),
        );
    }

    let mut msg = Msg::new();
    msg.id = msg_id;
    msg.command = CMD_METADATA;
    msg.status = moto_rt::Error::Ok.into();
    msg.payload.shared_pages_mut()[11] = IoPage::into_u16(io_page);

    msg
}

pub fn metadata_resp_decode(msg: Msg, receiver: &Sender) -> Result<async_fs::Metadata> {
    msg.status()?;

    let io_page_idx = msg.payload.shared_pages()[11];
    let io_page = receiver.get_page(io_page_idx)?;

    let mut metadata = async_fs::Metadata::zeroed();
    // Safety: see metadata_resp_encode above.
    unsafe {
        core::ptr::copy_nonoverlapping(
            io_page.bytes().as_ptr(),
            (&mut metadata) as *mut _ as usize as *mut u8,
            size_of::<async_fs::Metadata>(),
        );
    }

    Ok(metadata)
}

pub fn set_permissions_msg_encode(entry_id: EntryId, access: async_fs::AccessPermissions) -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_SET_PERMISSIONS;
    msg.payload.set_arg_128(entry_id);
    msg.payload.args_8_mut()[23] = access as u8;
    msg
}

pub fn set_permissions_msg_decode(msg: Msg) -> (EntryId, u8) {
    (msg.payload.arg_128(), msg.payload.args_8()[23])
}

pub fn resize_msg_encode(file_id: u128, new_size: u64) -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_RESIZE;
    msg.payload.set_arg_128(file_id); // This takes 16 bytes.
    msg.payload.args_64_mut()[2] = new_size;

    msg
}

pub fn resize_msg_decode(msg: Msg) -> (u128, u64) {
    (msg.payload.arg_128(), msg.payload.args_64()[2])
}

pub fn delete_entry_msg_encode(entry_id: u128) -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_DELETE_ENTRY;
    msg.payload.set_arg_128(entry_id); // This takes 16 bytes.

    msg
}

pub fn delete_entry_msg_decode(msg: Msg) -> u128 {
    msg.payload.arg_128()
}

pub fn flush_msg_encode() -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_FLUSH;

    msg
}

pub fn get_first_entry_req_encode(parent_id: EntryId) -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_GET_FIRST_ENTRY;
    msg.payload.set_arg_128(parent_id); // This takes 16 bytes.

    msg
}

pub fn get_first_entry_req_decode(msg: Msg) -> u128 {
    msg.payload.arg_128()
}

pub fn get_first_entry_resp_encode(req: Msg, entry_id: Option<EntryId>) -> Msg {
    let mut resp = Msg::new();
    resp.id = req.id;
    resp.handle = req.handle;

    resp.command = CMD_GET_FIRST_ENTRY;
    resp.status = moto_rt::Error::Ok.into();

    resp.payload.set_arg_128(entry_id.unwrap_or(0));
    resp
}

pub fn get_first_entry_resp_decode(resp: Msg) -> Result<Option<EntryId>> {
    resp.status()?;
    let entry_id = resp.payload.arg_128();
    Ok(if entry_id == 0 { None } else { Some(entry_id) })
}

pub fn get_next_entry_req_encode(entry_id: EntryId) -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_GET_NEXT_ENTRY;
    msg.payload.set_arg_128(entry_id); // This takes 16 bytes.

    msg
}

pub fn get_next_entry_req_decode(msg: Msg) -> u128 {
    msg.payload.arg_128()
}

pub fn get_next_entry_resp_encode(req: Msg, entry_id: Option<EntryId>) -> Msg {
    let mut resp = Msg::new();
    resp.id = req.id;
    resp.handle = req.handle;

    resp.command = CMD_GET_NEXT_ENTRY;
    resp.status = moto_rt::Error::Ok.into();

    resp.payload.set_arg_128(entry_id.unwrap_or(0));
    resp
}

pub fn get_next_entry_resp_decode(resp: Msg) -> Result<Option<EntryId>> {
    resp.status()?;
    let entry_id = resp.payload.arg_128();
    Ok(if entry_id == 0 { None } else { Some(entry_id) })
}

pub fn get_name_req_encode(entry_id: EntryId) -> Msg {
    let mut msg = Msg::new();
    msg.command = CMD_GET_NAME;
    msg.payload.set_arg_128(entry_id); // This takes 16 bytes.

    msg
}

pub fn get_name_req_decode(msg: Msg) -> u128 {
    msg.payload.arg_128()
}

pub fn get_name_resp_encode(msg_id: u64, name: &str, io_page: IoPage) -> Msg {
    let mut msg = Msg::new();
    msg.id = msg_id;
    msg.command = CMD_GET_NAME;
    msg.status = moto_rt::Error::Ok.into();

    io_page.bytes_mut()[..name.len()].clone_from_slice(name.as_bytes());
    msg.payload.args_16_mut()[10] = name.len() as u16;
    msg.payload.shared_pages_mut()[11] = IoPage::into_u16(io_page);

    msg
}

pub fn get_name_resp_decode(msg: Msg, receiver: &Sender) -> Result<String> {
    msg.status()?;

    let io_page_idx = msg.payload.shared_pages()[11];
    let io_page = receiver.get_page(io_page_idx)?;
    let len = msg.payload.args_16()[10];
    let name = &io_page.bytes()[..(len as usize)];
    let name = str::from_utf8(name).map_err(|_| moto_rt::Error::InvalidData)?;

    use alloc::borrow::ToOwned;
    Ok(name.to_owned())
}

pub fn move_entry_req_encode(
    entry_id: EntryId,
    new_parent_id: EntryId,
    new_name: &str,
    io_page: IoPage,
) -> Msg {
    assert!(new_name.len() <= moto_rt::fs::MAX_FILENAME_LEN);

    let mut msg = Msg::new();
    msg.command = CMD_MOVE_ENTRY;

    msg.set_long_handle(entry_id);
    msg.payload.set_arg_128(new_parent_id);
    let fname_len: u16 = new_name.len() as u16;

    let bytes = io_page.bytes_mut();
    bytes[0..2].clone_from_slice(&fname_len.to_ne_bytes());
    bytes[2..(2 + new_name.len())].clone_from_slice(new_name.as_bytes());

    msg.payload.shared_pages_mut()[11] = IoPage::into_u16(io_page);
    msg
}

/// Returns entry_id, new_parent_id, new_name.
pub fn move_entry_req_decode(msg: Msg, sender: &Sender) -> Result<(u128, u128, String)> {
    let entry_id = msg.get_long_handle();
    let new_parent_id = msg.payload.arg_128();
    let io_page_idx = msg.payload.shared_pages()[11];
    let io_page = sender.get_page(io_page_idx)?;

    let bytes = io_page.bytes();
    let fname_len: usize = u16::from_ne_bytes(bytes[0..2].try_into().unwrap()) as usize;
    if fname_len > moto_rt::fs::MAX_FILENAME_LEN {
        log::warn!("move_entry_req_decode: bad fname len {fname_len}");
        return Err(moto_rt::Error::InvalidFilename);
    }

    let fname_vec = bytes[2..(2 + fname_len)].to_vec();
    let fname = String::from_utf8(fname_vec).map_err(|err| {
        log::warn!("move_entry_req_decode: utf8 err: {err:?}");
        moto_rt::Error::InvalidFilename
    })?;

    Ok((entry_id, new_parent_id, fname))
}

/// Copies `size` bytes from file `from` at `offset` to file `to` at `offset`.
pub fn copy_file_range_req_encode(from: EntryId, to: EntryId, offset: u64, size: u64) -> Msg {
    debug_assert!(size <= u32::MAX as u64);

    let mut msg = Msg::new();
    msg.command = CMD_COPY_FILE_RANGE;

    msg.set_long_handle(from);
    msg.payload.set_arg_128(to);
    msg.payload.args_64_mut()[2] = offset;
    msg.flags = size as u32;

    msg
}

/// Returns (from, to, offset, size).
pub fn copy_file_range_req_decode(msg: Msg) -> (u128, u128, u64, u64) {
    let from = msg.get_long_handle();
    let to = msg.payload.arg_128();
    let offset = msg.payload.args_64()[2];
    let size = msg.flags as u64;

    (from, to, offset, size)
}

pub fn copy_file_range_resp_encode(msg_id: u64, copied: u64) -> Msg {
    let mut msg = Msg::new();
    msg.id = msg_id;
    msg.command = CMD_COPY_FILE_RANGE;
    msg.status = moto_rt::Error::Ok.into();

    msg.payload.args_64_mut()[0] = copied;
    msg
}

pub fn copy_file_range_resp_decode(msg: Msg) -> Result<u64> {
    msg.status()?;
    Ok(msg.payload.args_64()[0])
}
