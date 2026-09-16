//! Virtio-vsock control IPC. Stream data-page messages are defined separately.

use moto_ipc::io_channel;

use crate::api_net::{self, NetCmd};

extern crate alloc;

pub const SHUTDOWN_RECEIVE: u32 = 1;
pub const SHUTDOWN_SEND: u32 = 2;
const SHUTDOWN_BOTH: u32 = SHUTDOWN_RECEIVE | SHUTDOWN_SEND;

pub const STATE_READ_CLOSED: u32 = 1;
pub const STATE_WRITE_CLOSED: u32 = 2;
pub const STATE_TERMINAL: u32 = 4;
const STATE_ALL: u32 = STATE_READ_CLOSED | STATE_WRITE_CLOSED | STATE_TERMINAL;

/// Vsock deliberately reuses the established stream page layout and bounds.
pub const STREAM_TX_MAX_PAGES: usize = api_net::TCP_TX_MAX_PAGES;
pub const STREAM_TX_MAX_BYTES: usize = api_net::TCP_TX_MAX_BYTES;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerBindResponse {
    pub handle: u64,
    pub local: VsockAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptRequest {
    pub subchannel_mask: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptResponse {
    pub handle: u64,
    pub local: VsockAddr,
    pub peer: VsockAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamStateChange {
    pub handle: u64,
    pub flags: u32,
    pub cause: Option<moto_rt::Error>,
}

/// Build a discovery request with zero handle, flags, and payload. Its echoed
/// native status reports availability without reserving a socket or transport.
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

/// Build a combined bind/listen request. The requested u32 port occupies
/// payload bytes 0..4; zero asks sys-io for an ephemeral port. The fixed
/// backlog is server-owned, and the remaining payload bytes are zero.
pub fn listener_bind_request(port: u32) -> moto_rt::Result<io_channel::Msg> {
    if port == u32::MAX {
        return Err(moto_rt::Error::InvalidArgument);
    }
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::VsockListenerBind as u16;
    msg.payload.args_32_mut()[0] = port;
    Ok(msg)
}

pub fn decode_listener_bind_request(msg: &io_channel::Msg) -> moto_rt::Result<u32> {
    let port = msg.payload.args_32()[0];
    if msg.command != NetCmd::VsockListenerBind as u16
        || msg.handle != 0
        || msg.flags != 0
        || port == u32::MAX
        || !msg.payload.args_8()[4..].iter().all(|byte| *byte == 0)
    {
        return Err(moto_rt::Error::InvalidArgument);
    }
    Ok(port)
}

/// Encode a successful bind response while preserving request identity. The
/// server-selected local CID and nonzero port occupy payload bytes 0..8;
/// flags and the remaining payload bytes are zero.
pub fn encode_listener_bind_response(
    request: &io_channel::Msg,
    handle: u64,
    local: VsockAddr,
) -> moto_rt::Result<io_channel::Msg> {
    if request.command != NetCmd::VsockListenerBind as u16 || handle == 0 || !valid_local(local) {
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

pub fn decode_listener_bind_response(
    msg: &io_channel::Msg,
) -> moto_rt::Result<ListenerBindResponse> {
    if msg.command != NetCmd::VsockListenerBind as u16 {
        return Err(moto_rt::Error::InvalidData);
    }
    msg.status()?;
    let local = VsockAddr {
        cid: msg.payload.args_32()[0],
        port: msg.payload.args_32()[1],
    };
    if msg.handle == 0
        || msg.flags != 0
        || !valid_local(local)
        || !msg.payload.args_8()[8..].iter().all(|byte| *byte == 0)
    {
        return Err(moto_rt::Error::InvalidData);
    }
    Ok(ListenerBindResponse {
        handle: msg.handle,
        local,
    })
}

/// Build one accept request for a listener handle. Payload byte 23 carries
/// the shared-channel index; every other payload byte and flags are zero.
/// Unknown or stale listener handles are resolved by the server.
pub fn listener_accept_request(
    handle: u64,
    subchannel_idx: u8,
) -> moto_rt::Result<io_channel::Msg> {
    if subchannel_idx >= api_net::IO_SUBCHANNELS {
        return Err(moto_rt::Error::InvalidArgument);
    }
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::VsockListenerAccept as u16;
    msg.handle = handle;
    msg.payload.args_8_mut()[23] = subchannel_idx;
    Ok(msg)
}

pub fn decode_listener_accept_request(msg: &io_channel::Msg) -> moto_rt::Result<AcceptRequest> {
    let subchannel_idx = msg.payload.args_8()[23];
    if msg.command != NetCmd::VsockListenerAccept as u16
        || msg.flags != 0
        || !msg.payload.args_8()[..23].iter().all(|byte| *byte == 0)
        || subchannel_idx >= api_net::IO_SUBCHANNELS
    {
        return Err(moto_rt::Error::InvalidArgument);
    }
    Ok(AcceptRequest {
        subchannel_mask: api_net::io_subchannel_mask(subchannel_idx),
    })
}

/// Encode a successful accept response while preserving request identity.
/// The new stream handle is in `handle`; payload bytes 0..16 contain fixed-
/// width local CID/port followed by peer CID/port, and bytes 16..24 are zero.
pub fn encode_listener_accept_response(
    request: &io_channel::Msg,
    handle: u64,
    local: VsockAddr,
    peer: VsockAddr,
) -> moto_rt::Result<io_channel::Msg> {
    if request.command != NetCmd::VsockListenerAccept as u16
        || handle == 0
        || !valid_local(local)
        || !valid_peer(peer)
    {
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
    response.payload.args_32_mut()[2] = peer.cid;
    response.payload.args_32_mut()[3] = peer.port;
    Ok(response)
}

pub fn decode_listener_accept_response(msg: &io_channel::Msg) -> moto_rt::Result<AcceptResponse> {
    if msg.command != NetCmd::VsockListenerAccept as u16 {
        return Err(moto_rt::Error::InvalidData);
    }
    msg.status()?;
    let local = VsockAddr {
        cid: msg.payload.args_32()[0],
        port: msg.payload.args_32()[1],
    };
    let peer = VsockAddr {
        cid: msg.payload.args_32()[2],
        port: msg.payload.args_32()[3],
    };
    if msg.handle == 0
        || msg.flags != 0
        || !valid_local(local)
        || !valid_peer(peer)
        || !msg.payload.args_8()[16..].iter().all(|byte| *byte == 0)
    {
        return Err(moto_rt::Error::InvalidData);
    }
    Ok(AcceptResponse {
        handle: msg.handle,
        local,
        peer,
    })
}

/// Build a handle-only listener drop request. Handle validity is server-owned.
/// With a nonzero request ID, sys-io echoes E_OK only after authoritative
/// local removal. ID zero is fire-and-forget. That response is not peer
/// cleanup acknowledgement and does not free ports retained by child tuples.
pub fn listener_drop_request(handle: u64) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::VsockListenerDrop as u16;
    msg.handle = handle;
    msg
}

pub fn decode_listener_drop_request(msg: &io_channel::Msg) -> moto_rt::Result<()> {
    if msg.command != NetCmd::VsockListenerDrop as u16
        || msg.flags != 0
        || !payload_is_zero(&msg.payload)
    {
        return Err(moto_rt::Error::InvalidArgument);
    }
    Ok(())
}

/// Build a shutdown control with a nonzero RECEIVE/SEND subset and zero
/// payload. The server resolves unknown or stale handles.
pub fn shutdown_request(handle: u64, flags: u32) -> moto_rt::Result<io_channel::Msg> {
    if flags == 0 || flags & !SHUTDOWN_BOTH != 0 {
        return Err(moto_rt::Error::InvalidArgument);
    }
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::VsockStreamShutdown as u16;
    msg.handle = handle;
    msg.flags = flags;
    Ok(msg)
}

pub fn decode_shutdown_request(msg: &io_channel::Msg) -> moto_rt::Result<u32> {
    if msg.command != NetCmd::VsockStreamShutdown as u16
        || msg.flags == 0
        || msg.flags & !SHUTDOWN_BOTH != 0
        || !payload_is_zero(&msg.payload)
    {
        return Err(moto_rt::Error::InvalidArgument);
    }
    Ok(msg.flags)
}

/// Build a handle-only close request. Handle validity is server-owned.
pub fn close_request(handle: u64) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::VsockStreamClose as u16;
    msg.handle = handle;
    msg
}

pub fn decode_close_request(msg: &io_channel::Msg) -> moto_rt::Result<()> {
    if msg.command != NetCmd::VsockStreamClose as u16
        || msg.flags != 0
        || !payload_is_zero(&msg.payload)
    {
        return Err(moto_rt::Error::InvalidArgument);
    }
    Ok(())
}

/// Build an E_OK notification with cumulative local state in `flags`, a native
/// terminal cause in `args_32[0]`, and zero remaining payload. A zero cause
/// denotes either a nonterminal update or an orderly terminal state.
/// TERMINAL stops writes but is not an RX barrier: validated data may follow.
/// READ_CLOSED is ordered after the last RX page in the client's FIFO; readers
/// drain preceding data before reporting the retained terminal cause or EOF.
pub fn state_changed(
    handle: u64,
    flags: u32,
    cause: Option<moto_rt::Error>,
) -> moto_rt::Result<io_channel::Msg> {
    if flags & !STATE_ALL != 0
        || cause.is_some() && flags & STATE_TERMINAL == 0
        || !matches!(
            cause,
            None | Some(moto_rt::Error::ConnectionReset | moto_rt::Error::InternalError)
        )
    {
        return Err(moto_rt::Error::InvalidArgument);
    }
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::EvtVsockStreamStateChanged as u16;
    msg.handle = handle;
    msg.flags = flags;
    msg.status = moto_rt::E_OK;
    msg.payload.args_32_mut()[0] = cause.map_or(0, |cause| cause as u32);
    Ok(msg)
}

pub fn decode_state_changed(msg: &io_channel::Msg) -> moto_rt::Result<StreamStateChange> {
    if msg.command != NetCmd::EvtVsockStreamStateChanged as u16 {
        return Err(moto_rt::Error::InvalidData);
    }
    msg.status()?;
    if msg.flags & !STATE_ALL != 0 || !msg.payload.args_8()[4..].iter().all(|byte| *byte == 0) {
        return Err(moto_rt::Error::InvalidData);
    }
    let cause = match msg.payload.args_32()[0] {
        0 => None,
        value if value == moto_rt::E_CONNECTION_RESET as u32 => {
            Some(moto_rt::Error::ConnectionReset)
        }
        value if value == moto_rt::E_INTERNAL_ERROR as u32 => Some(moto_rt::Error::InternalError),
        _ => return Err(moto_rt::Error::InvalidData),
    };
    if cause.is_some() && msg.flags & STATE_TERMINAL == 0 {
        return Err(moto_rt::Error::InvalidData);
    }
    Ok(StreamStateChange {
        handle: msg.handle,
        flags: msg.flags,
        cause,
    })
}

pub fn stream_tx_msg(
    handle: u64,
    io_page: io_channel::IoPage,
    sz: usize,
    timestamp: u64,
) -> io_channel::Msg {
    api_net::stream_page_msg(NetCmd::VsockStreamTx, handle, io_page, sz, timestamp)
}

pub fn stream_tx_multi_msg(
    handle: u64,
    pages: &[u16],
    total_len: u32,
    timestamp: u64,
) -> io_channel::Msg {
    api_net::stream_tx_multi_msg(NetCmd::VsockStreamTx, handle, pages, total_len, timestamp)
}

pub fn stream_tx_multi_decode(
    msg: &io_channel::Msg,
    sender: &io_channel::Sender,
) -> moto_rt::Result<(alloc::vec::Vec<io_channel::IoPage>, u32)> {
    if msg.command != NetCmd::VsockStreamTx as u16 {
        return Err(moto_rt::Error::InvalidArgument);
    }
    api_net::stream_tx_multi_decode(msg, sender)
}

pub fn stream_rx_msg(
    handle: u64,
    io_page: io_channel::IoPage,
    sz: usize,
    rx_seq: u64,
) -> io_channel::Msg {
    api_net::stream_page_msg(NetCmd::VsockStreamRx, handle, io_page, sz, rx_seq)
}

// This is syntactic validation only. sys-io decides which non-host CIDs the
// current transport supports and returns NotImplemented for unsupported ones.
fn valid_peer(addr: VsockAddr) -> bool {
    addr.cid >= 2 && addr.cid != u32::MAX && valid_port(addr.port)
}

fn valid_local(addr: VsockAddr) -> bool {
    addr.cid >= 3 && addr.cid != u32::MAX && valid_port(addr.port)
}

fn valid_port(port: u32) -> bool {
    port != 0 && port != u32::MAX
}

fn payload_is_zero(payload: &io_channel::Payload) -> bool {
    payload.args_64() == &[0; 3]
}
