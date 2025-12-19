use moto_ipc::io_channel::{IoPage, Msg};
use moto_rt::fs::MAX_PATH_LEN;

pub const FS_URL: &str = "sys-io-fs";
pub const CMD_STAT: u16 = 2;

pub fn stat_msg(parent_id: u128, fname: &str, io_page: IoPage) -> Msg {
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
