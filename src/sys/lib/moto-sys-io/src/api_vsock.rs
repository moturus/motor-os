//! Virtio-vsock control IPC. Stream data-page messages are defined separately.

use moto_ipc::io_channel;

use crate::api_net::{self, NetCmd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VsockAddr {
    pub cid: u32,
    pub port: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectRequest {
    pub peer: VsockAddr,
    pub subchannel_mask: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectResponse {
    pub handle: u64,
    pub local: VsockAddr,
}

pub fn availability_request() -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::VsockAvailability as u16;
    msg
}

pub fn availability_response(msg: &io_channel::Msg) -> Result<(), moto_rt::Error> {
    msg.status()
}

/// Build a connect request. The peer occupies payload bytes 0..8, bytes
/// 8..23 are reserved as zero, and byte 23 carries the shared-channel index.
pub fn connect_request(peer: VsockAddr, subchannel_idx: u8) -> moto_rt::Result<io_channel::Msg> {
    if !valid_peer(peer) || subchannel_idx >= api_net::IO_SUBCHANNELS {
        return Err(moto_rt::Error::InvalidArgument);
    }
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::VsockStreamConnect as u16;
    msg.payload.args_32_mut()[0] = peer.cid;
    msg.payload.args_32_mut()[1] = peer.port;
    msg.payload.args_8_mut()[23] = subchannel_idx;
    Ok(msg)
}

pub fn decode_connect_request(msg: &io_channel::Msg) -> moto_rt::Result<ConnectRequest> {
    let peer = VsockAddr {
        cid: msg.payload.args_32()[0],
        port: msg.payload.args_32()[1],
    };
    let subchannel_idx = msg.payload.args_8()[23];
    if msg.command != NetCmd::VsockStreamConnect as u16
        || msg.handle != 0
        || msg.flags != 0
        || !msg.payload.args_8()[8..23].iter().all(|byte| *byte == 0)
        || !valid_peer(peer)
        || subchannel_idx >= api_net::IO_SUBCHANNELS
    {
        return Err(moto_rt::Error::InvalidArgument);
    }
    Ok(ConnectRequest {
        peer,
        subchannel_mask: api_net::io_subchannel_mask(subchannel_idx),
    })
}

/// Encode a successful response while preserving the request ID, wake handle,
/// and command. Flags and payload fields not carrying the local address clear.
pub fn encode_connect_response(
    request: &io_channel::Msg,
    handle: u64,
    local: VsockAddr,
) -> moto_rt::Result<io_channel::Msg> {
    if request.command != NetCmd::VsockStreamConnect as u16 || handle == 0 || !valid_local(local) {
        return Err(moto_rt::Error::InvalidArgument);
    }
    let mut response = io_channel::Msg::new();
    response.id = request.id;
    response.wake_handle = request.wake_handle;
    response.command = request.command;
    response.handle = handle;
    response.status = moto_rt::E_OK;
    response.payload.args_32_mut()[0] = local.cid;
    response.payload.args_32_mut()[1] = local.port;
    Ok(response)
}

/// Decode a successful response whose flags and reserved payload bytes are
/// zero. Native error status is returned before success-only fields are read.
pub fn decode_connect_response(msg: &io_channel::Msg) -> moto_rt::Result<ConnectResponse> {
    if msg.command != NetCmd::VsockStreamConnect as u16 {
        return Err(moto_rt::Error::InvalidData);
    }
    msg.status()?;
    let local = VsockAddr {
        cid: msg.payload.args_32()[0],
        port: msg.payload.args_32()[1],
    };
    if msg.handle == 0
        || msg.flags != 0
        || !msg.payload.args_8()[8..].iter().all(|byte| *byte == 0)
        || !valid_local(local)
    {
        return Err(moto_rt::Error::InvalidData);
    }
    Ok(ConnectResponse {
        handle: msg.handle,
        local,
    })
}

fn valid_peer(addr: VsockAddr) -> bool {
    addr.cid >= 2 && addr.cid != u32::MAX && valid_port(addr.port)
}

fn valid_local(addr: VsockAddr) -> bool {
    addr.cid >= 3 && addr.cid != u32::MAX && valid_port(addr.port)
}

fn valid_port(port: u32) -> bool {
    port != 0 && port != u32::MAX
}
