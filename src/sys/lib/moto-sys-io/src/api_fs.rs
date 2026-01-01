use moto_ipc::io_channel::{IoPage, Msg, Receiver, Sender};
use moto_rt::Result;
use moto_rt::fs::MAX_PATH_LEN;

extern crate alloc;

use alloc::string::String;

pub const FS_URL: &str = "sys-io-fs";
pub const CMD_STAT: u16 = 1;
pub const CMD_CREATE_FILE: u16 = 2;
pub const CMD_CREATE_DIR: u16 = 3;
pub const CMD_WRITE: u16 = 4;
pub const CMD_READ: u16 = 5;
pub const CMD_METADATA: u16 = 6;
pub const CMD_RESIZE: u16 = 7;

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

pub fn create_entry_msg_encode(parent_id: u128, is_dir: bool, name: &str, io_page: IoPage) -> Msg {
    let mut msg = stat_msg_encode(parent_id, name, io_page);
    msg.command = if is_dir {
        CMD_CREATE_DIR
    } else {
        CMD_CREATE_FILE
    };
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

pub fn create_entry_msg_decode(msg: Msg, sender: &Sender) -> Result<(u128, String)> {
    stat_msg_decode(msg, sender)
}

pub fn stat_resp_encode(req: Msg, entry_id: u128) -> Msg {
    let mut resp = Msg::new();
    resp.id = req.id;
    resp.handle = req.handle;
    resp.wake_handle = req.handle;

    resp.command = CMD_STAT;
    resp.status = moto_rt::Error::Ok.into();

    resp.payload.set_arg_128(entry_id);
    resp
}

pub fn stat_resp_decode(msg: Msg) -> Result<u128> {
    msg.status().map(|_| msg.payload.arg_128())
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

pub fn read_resp_decode(msg: Msg, receiver: &Receiver) -> Result<(u16, IoPage)> {
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

pub fn metadata_resp_decode(msg: Msg, receiver: &Receiver) -> Result<async_fs::Metadata> {
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
