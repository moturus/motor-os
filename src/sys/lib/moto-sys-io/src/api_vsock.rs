//! Virtio-vsock discovery IPC.
//!
//! The request has zero handle, flags, and payload. The response echoes the
//! request and reports discovery through its native status code; no socket or
//! transport resource is reserved.

use moto_ipc::io_channel;

use crate::api_net::NetCmd;

pub fn availability_request() -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::VsockAvailability as u16;
    msg
}

pub fn availability_response(msg: &io_channel::Msg) -> Result<(), moto_rt::Error> {
    msg.status()
}
