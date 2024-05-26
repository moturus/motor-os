// Spec for client-server Networking IPC.

use core::net::IpAddr;
use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
use core::net::SocketAddr;
use moto_ipc::io_channel;
use moto_sys::ErrorCode;

pub const CMD_MIN: u16 = io_channel::CMD_RESERVED_MAX;

pub const CMD_TCP_LISTENER_BIND: u16 = CMD_MIN + 0;
pub const CMD_TCP_LISTENER_ACCEPT: u16 = CMD_MIN + 1;
pub const CMD_TCP_LISTENER_SET_OPTION: u16 = CMD_MIN + 2;
pub const CMD_TCP_LISTENER_GET_OPTION: u16 = CMD_MIN + 3;
pub const CMD_TCP_LISTENER_DROP: u16 = CMD_MIN + 4;

pub const CMD_TCP_STREAM_CONNECT: u16 = CMD_MIN + 5;
pub const CMD_TCP_STREAM_TX: u16 = CMD_MIN + 6;
pub const CMD_TCP_STREAM_RX: u16 = CMD_MIN + 7;
pub const CMD_TCP_STREAM_RX_ACK: u16 = CMD_MIN + 8;
pub const CMD_TCP_STREAM_SET_OPTION: u16 = CMD_MIN + 9;
pub const CMD_TCP_STREAM_GET_OPTION: u16 = CMD_MIN + 10;
pub const CMD_TCP_STREAM_CLOSE: u16 = CMD_MIN + 11;

pub const CMD_MAX: u16 = CMD_TCP_STREAM_CLOSE;

pub const EVT_TCP_STREAM_STATE_CHANGED: u16 = CMD_MIN;

pub const TCP_OPTION_SHUT_RD: u64 = 1 << 0;
pub const TCP_OPTION_SHUT_WR: u64 = 1 << 1;
pub const TCP_OPTION_NODELAY: u64 = 1 << 2;
pub const TCP_OPTION_TTL: u64 = 1 << 3;

pub const TCP_RX_MAX_INFLIGHT: u64 = 8;

/// Each IO Channel in moto_ipc::io_channel has 64 pages (for the server and for the client).
/// Using the full channel per socket is wasteful, so channels are split into subchannels.
/// A channel can be split into 2^0, 2^1, 2^2, ... 2^6 subchannels (technically, we
/// don't need a full power-of-two number of subchannels, as io_channel accepts a 64 bit
/// mask for the subchannel, so we can have a 1-page-wide channel, a 31-page-wide channel,
/// and a 32-page-wide channel, and maybe later we will do that, but for now we
/// hard-code the number of equal sized subchannels in IO_SUBCHANNELS).
///
/// Eight subchannels (8 pages in-flight) are not much worse re: throughput vs four
/// (16 pages in-flight), based on benchmarks.
pub const IO_SUBCHANNELS: usize = 8;

pub const fn io_subchannel_mask(io_channel_idx: usize) -> u64 {
    debug_assert!(io_channel_idx < IO_SUBCHANNELS);

    const IO_SUBCHANNEL_WIDTH: u8 = 8;
    const IO_SUBCHANNEL_MASK: u64 = 0xFF;
    const _A1: () = assert!((IO_SUBCHANNEL_WIDTH as usize) * IO_SUBCHANNELS == 64);
    const _A2: () = assert!(IO_SUBCHANNEL_MASK == ((1 << IO_SUBCHANNEL_WIDTH) - 1));

    IO_SUBCHANNEL_MASK << ((io_channel_idx as u64) * (IO_SUBCHANNEL_WIDTH as u64))
}

const _A1: () = assert!(io_subchannel_mask(0) == 0xFF);
const _A2: () = assert!(io_subchannel_mask(1) == 0xFF00);
const _A3: () = assert!(io_subchannel_mask(2) == 0xFF_0000);
const _A4: () = assert!(io_subchannel_mask(7) == 0xFF00_0000_0000_0000);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum TcpState {
    Closed = 0,
    Listening = 1,
    PendingAccept = 2,
    Connecting = 3,
    ReadWrite = 4,
    ReadOnly = 5,
    WriteOnly = 6,
    _Max = 7,
}

impl TryFrom<u32> for TcpState {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value < (Self::_Max as u32) {
            Ok(unsafe { core::mem::transmute(value) })
        } else {
            Err(())
        }
    }
}

impl Into<u32> for TcpState {
    fn into(self) -> u32 {
        self as u32
    }
}

impl TcpState {
    pub fn can_read(&self) -> bool {
        *self == TcpState::ReadWrite || *self == TcpState::ReadOnly
    }

    pub fn can_write(&self) -> bool {
        *self == TcpState::ReadWrite || *self == TcpState::WriteOnly
    }
}

pub fn bind_tcp_listener_request(addr: &SocketAddr) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = CMD_TCP_LISTENER_BIND;
    put_socket_addr(&mut msg.payload, addr);

    msg
}

pub fn accept_tcp_listener_request(handle: u64, subchannel_mask: u64) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = CMD_TCP_LISTENER_ACCEPT;
    msg.handle = handle;
    msg.payload.args_64_mut()[0] = subchannel_mask;

    msg
}

pub fn tcp_stream_connect_request(addr: &SocketAddr, subchannel_mask: u64) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = CMD_TCP_STREAM_CONNECT;
    msg.payload.args_64_mut()[0] = subchannel_mask;
    msg.payload.args_32_mut()[5] = 0; // timeout
    put_socket_addr(&mut msg.payload, addr);

    msg
}

pub fn tcp_stream_connect_timeout_request(
    addr: &SocketAddr,
    subchannel_mask: u64,
    timeout: moto_sys::time::Instant,
) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = CMD_TCP_STREAM_CONNECT;

    // We have only 32 bits for timeout. ~10ms granularity is fine.
    let timeout = timeout.as_u64() >> 27;
    assert!(timeout < (u32::MAX) as u64);
    msg.payload.args_64_mut()[0] = subchannel_mask;
    msg.payload.args_32_mut()[5] = timeout as u32;
    put_socket_addr(&mut msg.payload, addr);

    msg
}

pub fn tcp_stream_connect_timeout(msg: &io_channel::Msg) -> Option<moto_sys::time::Instant> {
    let mut timeout = msg.payload.args_32()[5];
    timeout &= u32::MAX - 1;
    if timeout == 0 {
        return None;
    }
    let timeout = (timeout as u64) << 27;
    Some(moto_sys::time::Instant::from_u64(timeout))
}

pub fn tcp_stream_tx_msg(
    handle: u64,
    io_page: io_channel::IoPage,
    sz: usize,
    timestamp: u64,
) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = CMD_TCP_STREAM_TX;
    msg.handle = handle;
    msg.payload.shared_pages_mut()[0] = io_channel::IoPage::into_u16(io_page);
    msg.payload.args_64_mut()[1] = sz as u64;
    msg.payload.args_64_mut()[2] = timestamp;

    msg
}

pub fn tcp_stream_rx_msg(
    handle: u64,
    io_page: io_channel::IoPage,
    sz: usize,
    rx_seq: u64,
) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = CMD_TCP_STREAM_RX;
    msg.handle = handle;
    msg.payload.shared_pages_mut()[0] = io_channel::IoPage::into_u16(io_page);
    msg.payload.args_64_mut()[1] = sz as u64;
    msg.payload.args_64_mut()[2] = rx_seq;

    msg
}

pub fn get_socket_addr(payload: &io_channel::Payload) -> Result<SocketAddr, ErrorCode> {
    match payload.args_32()[5] & 1 {
        0 => {
            let ip = Ipv4Addr::from(payload.args_32()[0]);
            let port = payload.args_16()[2];
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        1 => {
            let octets: [u8; 16] = payload.args_8()[0..16].try_into().unwrap();
            let ip = Ipv6Addr::from(octets);
            let port = payload.args_16()[9];
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => unreachable!(),
    }
}

pub fn put_socket_addr(payload: &mut io_channel::Payload, addr: &SocketAddr) {
    match addr.ip() {
        IpAddr::V4(addr_v4) => {
            payload.args_32_mut()[0] = addr_v4.into();
            payload.args_16_mut()[2] = addr.port();
            payload.args_32_mut()[5] &= u32::MAX - 1;
        }
        IpAddr::V6(addr_v6) => {
            payload.args_8_mut()[0..16].clone_from_slice(&addr_v6.octets());
            payload.args_16_mut()[9] = addr.port();
            payload.args_32_mut()[5] |= 1;
        }
    }
}
