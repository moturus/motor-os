use moto_ipc::io_channel::{IoPage, Msg, Sender};
use moto_rt::Result;
use moto_rt::fs::MAX_PATH_LEN;

extern crate alloc;

use alloc::string::String;

pub const FS_URL: &str = "sys-io-fs";
pub const CMD_STAT: u16 = 1;
pub const CMD_CREATE_FILE: u16 = 2;
pub const CMD_CREATE_DIR: u16 = 3;

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
    assert_eq!(msg.command, CMD_STAT);
    if msg.status() != moto_rt::E_OK {
        return Err(msg.status().into());
    }
    // if let Err(err) = msg.status() {
    //     return Err(err);
    // }

    Ok(msg.payload.arg_128())
}

pub fn create_entry_resp_decode(msg: Msg) -> Result<u128> {
    if msg.status() != moto_rt::E_OK {
        return Err(msg.status().into());
    }
    // if let Err(err) = msg.status() {
    //     return Err(err);
    // }

    Ok(msg.payload.arg_128())
}

pub fn empty_resp_encode(req: Msg, status: Result<()>) -> Msg {
    let mut resp = Msg::new();
    resp.id = req.id;
    resp.handle = req.handle;
    resp.wake_handle = req.handle;

    resp.command = req.command;
    resp.status = match status {
        Ok(()) => moto_rt::Error::Ok.into(),
        Err(err) => err.into(),
    };

    resp
}
