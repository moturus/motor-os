// Spec for client-server Networking IPC.

use core::net::IpAddr;
use core::net::Ipv6Addr;
use core::net::SocketAddr;
use moto_ipc::io_channel;

pub const CMD_MIN: u16 = io_channel::CMD_RESERVED_MAX; // 4352 == 0x1100

#[derive(Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NetCmd {
    TcpListenerBind = CMD_MIN,
    TcpListenerAccept,
    TcpListenerSetOption,
    TcpListenerGetOption,
    TcpListenerDrop,
    TcpStreamConnect,
    TcpStreamTx,
    TcpStreamRx,
    TcpStreamRxAck,
    TcpStreamSetOption,
    TcpStreamGetOption,
    TcpStreamClose,
    EvtTcpStreamStateChanged,
    UdpSocketBind,
    UdpSocketTxRx,
    UdpSocketTxRxAck,
    UdpSocketDrop,
    NetCmdMax,
}

pub const CMD_MAX: u16 = NetCmd::NetCmdMax as u16;

impl NetCmd {
    pub const fn try_from(val: u16) -> Result<Self, u16> {
        if val < CMD_MIN {
            return Err(val);
        }
        if val >= CMD_MAX {
            return Err(val);
        }

        Ok(unsafe { core::mem::transmute::<u16, Self>(val) })
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn is_udp(&self) -> bool {
        matches!(
            self,
            NetCmd::UdpSocketBind
                | NetCmd::UdpSocketTxRx
                | NetCmd::UdpSocketTxRxAck
                | NetCmd::UdpSocketDrop
        )
    }
}

pub const TCP_OPTION_SHUT_RD: u64 = 1 << 0;
pub const TCP_OPTION_SHUT_WR: u64 = 1 << 1;
pub const TCP_OPTION_NODELAY: u64 = 1 << 2;
pub const TCP_OPTION_TTL: u64 = 1 << 3;

pub const TCP_RX_MAX_INFLIGHT: u64 = 8;

/// The number of subchannels per channel.
///
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
pub const IO_SUBCHANNELS: u8 = 8;

pub const fn io_subchannel_mask(io_channel_idx: u8) -> u64 {
    debug_assert!(io_channel_idx < IO_SUBCHANNELS);

    const IO_SUBCHANNEL_WIDTH: u8 = 8;
    const IO_SUBCHANNEL_MASK: u64 = 0xFF;
    const _A1: () = assert!((IO_SUBCHANNEL_WIDTH as usize) * (IO_SUBCHANNELS as usize) == 64);
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

impl Default for TcpState {
    fn default() -> Self {
        Self::Closed
    }
}

impl TryFrom<u32> for TcpState {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value < (Self::_Max as u32) {
            Ok(unsafe { core::mem::transmute::<u32, TcpState>(value) })
        } else {
            Err(())
        }
    }
}

impl From<TcpState> for u32 {
    fn from(val: TcpState) -> u32 {
        val as u32
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

/// Prepare CMD_TCP_LISTENER_BIND IO message.
///
/// `num_listeners` indicate the number of
/// outstanding listening sockets to create: each incoming connection consumes one
/// socket, and a new listener is created. But if several incoming connections happen
/// at once, they can consume all outstanding listeners so that new incoming connections
/// are rejected until new listeners are created, thus having several outstanding listeners
/// reduces the chance that an incoming connection is rejected because there are no
/// outstanding listeners due to a spike in incoming connections.
/// `num_listeners` can be no more than 32.
pub fn bind_tcp_listener_request(addr: &SocketAddr, num_listeners: Option<u8>) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::TcpListenerBind as u16;
    msg.flags = num_listeners.unwrap_or(0) as u32;
    put_socket_addr(&mut msg.payload, addr);

    msg
}

pub fn accept_tcp_listener_request(handle: u64, subchannel_mask: u64) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::TcpListenerAccept as u16;
    msg.handle = handle;
    msg.payload.args_64_mut()[0] = subchannel_mask;

    msg
}

pub fn tcp_stream_connect_request(addr: &SocketAddr, subchannel_idx: u8) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::TcpStreamConnect as u16;
    msg.payload.args_8_mut()[23] = subchannel_idx;
    put_socket_addr(&mut msg.payload, addr);
    msg.flags = u32::MAX; // Timeout.

    msg
}

pub fn tcp_stream_connect_timeout_request(
    addr: &SocketAddr,
    subchannel_idx: u8,
    timeout: moto_rt::time::Instant,
) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::TcpStreamConnect as u16;
    msg.payload.args_8_mut()[23] = subchannel_idx;
    put_socket_addr(&mut msg.payload, addr);

    // We have only 32 bits for timeout. ~10ms granularity is fine.
    let timeout_64: u64 = timeout.as_u64() >> 27;
    msg.flags = if timeout_64 > (u32::MAX as u64) {
        u32::MAX
    } else {
        timeout_64 as u32
    };

    msg
}

pub fn tcp_stream_connect_timeout(msg: &io_channel::Msg) -> Option<moto_rt::time::Instant> {
    let timeout = msg.flags;
    if timeout == u32::MAX {
        return None;
    }
    let timeout = (timeout as u64) << 27;
    Some(moto_rt::time::Instant::from_u64(timeout))
}

pub fn tcp_stream_tx_msg(
    handle: u64,
    io_page: io_channel::IoPage,
    sz: usize,
    timestamp: u64,
) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::TcpStreamTx as u16;
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
    msg.command = NetCmd::TcpStreamRx as u16;
    msg.handle = handle;
    msg.payload.shared_pages_mut()[0] = io_channel::IoPage::into_u16(io_page);
    msg.payload.args_64_mut()[1] = sz as u64;
    msg.payload.args_64_mut()[2] = rx_seq;

    msg
}

pub fn udp_socket_tx_rx_msg(
    handle: u64,
    io_page: io_channel::IoPage,
    fragment_id: u16,
    sz: u16,
    addr: &SocketAddr,
) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::UdpSocketTxRx as u16;
    msg.handle = handle;
    put_socket_addr(&mut msg.payload, addr); // uses [0..=8]
    msg.payload.args_16_mut()[9] = fragment_id;
    msg.payload.args_16_mut()[10] = sz;
    msg.payload.shared_pages_mut()[11] = io_channel::IoPage::into_u16(io_page);

    msg
}

pub fn udp_socket_tx_rx_empty_msg(handle: u64, addr: &SocketAddr) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::UdpSocketTxRx as u16;
    msg.handle = handle;
    put_socket_addr(&mut msg.payload, addr); // uses [0..=8]

    msg
}

pub fn get_socket_addr(payload: &io_channel::Payload) -> SocketAddr {
    let octets: [u8; 16] = payload.args_8()[0..16].try_into().unwrap();
    let ipv6 = Ipv6Addr::from(octets);
    let port = payload.args_16()[8];
    if let Some(ipv4) = ipv6.to_ipv4_mapped() {
        SocketAddr::new(IpAddr::V4(ipv4), port)
    } else {
        SocketAddr::new(IpAddr::V6(ipv6), port)
    }
}

// Uses the first 18 bytes (= 9 u16).
pub fn put_socket_addr(payload: &mut io_channel::Payload, addr: &SocketAddr) {
    let ipv6 = match addr.ip() {
        IpAddr::V4(ipv4_addr) => ipv4_addr.to_ipv6_mapped(),
        IpAddr::V6(ipv6_addr) => ipv6_addr,
    };
    payload.args_8_mut()[0..16].clone_from_slice(&ipv6.octets());
    payload.args_16_mut()[8] = addr.port();
}

#[test]
fn test_get_put_socket_addr() {
    let mut payload = io_channel::Payload::new_zeroed();

    let addr_in = "[ff:ff:ff::ff:ff:ff]:1234".parse().unwrap();
    put_socket_addr(&mut payload, &addr_in);
    let addr_out = get_socket_addr(&payload);
    assert_eq!(addr_in, addr_out);
}

pub fn bind_udp_socket_request(addr: &SocketAddr, subchannel_idx: u8) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::UdpSocketBind as u16;
    msg.payload.args_8_mut()[23] = subchannel_idx;
    put_socket_addr(&mut msg.payload, addr);

    msg
}
