//! Spec for client-server Networking IPC.

use core::net::IpAddr;
use core::net::Ipv6Addr;
use core::net::SocketAddr;
use moto_ipc::io_channel;

extern crate alloc;

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
    IcmpEcho,
    UdpSocketBindForRemote,
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
                | NetCmd::UdpSocketBindForRemote
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
pub const TCP_OPTION_LINGER: u64 = 1 << 4;

pub const ICMP_ECHO_MAX_TIMEOUT_MS: u32 = 60_000;
pub const ICMP_ECHO_MAX_DATA_LEN: u16 = 65_507;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpEchoRequest {
    pub destination: IpAddr,
    pub sequence: u16,
    pub data_len: u16,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpEchoResponse {
    pub source: IpAddr,
    pub rtt_ns: u64,
}

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
/// Four subchannels of 16 pages (64KB in flight per socket). This was 8
/// subchannels of 8 pages until 2026-07-11 ("not much worse than 4×16" per
/// old benchmarks) — but with 128KB socket buffers and late-binding TX the
/// 8-page pool measurably bound: the RX pump found the subchannel empty on
/// 12.5% of page allocs (16.5K stalls/s at ~540 MiB/s), each stall setting
/// the page-wait bits and turning every page free during it into a client
/// wake syscall (~130K/s). Cost of 4×16: at most 4 sockets per channel.
pub const IO_SUBCHANNELS: u8 = 4;

pub const fn io_subchannel_mask(io_channel_idx: u8) -> u64 {
    debug_assert!(io_channel_idx < IO_SUBCHANNELS);

    const IO_SUBCHANNEL_WIDTH: u8 = 64 / IO_SUBCHANNELS;
    const IO_SUBCHANNEL_MASK: u64 = (1_u64 << IO_SUBCHANNEL_WIDTH) - 1;
    const _A1: () = assert!((IO_SUBCHANNEL_WIDTH as usize) * (IO_SUBCHANNELS as usize) == 64);

    IO_SUBCHANNEL_MASK << ((io_channel_idx as u64) * (IO_SUBCHANNEL_WIDTH as u64))
}

const _A1: () = assert!(io_subchannel_mask(0) == 0xFFFF);
const _A2: () = assert!(io_subchannel_mask(1) == 0xFFFF_0000);
const _A3: () = assert!(io_subchannel_mask(2) == 0xFFFF_0000_0000);
const _A4: () = assert!(io_subchannel_mask(3) == 0xFFFF_0000_0000_0000);

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum TcpState {
    #[default]
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

/// Multi-page TX, mirroring the FS multi-block writes: a TcpStreamTx message
/// whose data spans more than one io_page carries up to [`TCP_TX_MAX_PAGES`]
/// pages in `payload.shared_pages()[0..8]`, each full except possibly the
/// last (so per-page lengths need no wire space); the total length travels
/// in `Msg::flags` — a classic single-page Tx ([`tcp_stream_tx_msg`]) leaves
/// `flags` zero, which is how the server tells the formats apart. The
/// timestamp moves to `payload.args_64()[2]` (the page ids occupy the rest).
/// Fire-and-forget, like the single-page form.
pub const TCP_TX_MAX_PAGES: usize = 8;
pub const TCP_TX_MAX_BYTES: usize = TCP_TX_MAX_PAGES * io_channel::PAGE_SIZE;

/// Encode a multi-page TX message. `pages` are the io_page ids (from
/// [`io_channel::IoPage::into_u16`]), full except possibly the last.
pub fn tcp_stream_tx_multi_msg(
    handle: u64,
    pages: &[u16],
    total_len: u32,
    timestamp: u64,
) -> io_channel::Msg {
    debug_assert!(total_len > 0 && (total_len as usize) <= TCP_TX_MAX_BYTES);
    debug_assert_eq!(
        pages.len(),
        (total_len as usize).div_ceil(io_channel::PAGE_SIZE)
    );

    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::TcpStreamTx as u16;
    msg.handle = handle;
    msg.flags = total_len;
    msg.payload.shared_pages_mut()[..pages.len()].copy_from_slice(pages);
    msg.payload.args_64_mut()[2] = timestamp;

    msg
}

/// Decode a multi-page TX request (`msg.flags != 0`): the data pages and the
/// total length. Page i holds bytes `[i * PAGE_SIZE..]` of the payload.
pub fn tcp_stream_tx_multi_decode(
    msg: &io_channel::Msg,
    sender: &io_channel::Sender,
) -> moto_rt::Result<(alloc::vec::Vec<io_channel::IoPage>, u32)> {
    let total_len = msg.flags;

    // The length comes from an untrusted client; bound it before recovering
    // pages.
    if total_len == 0 || total_len as usize > TCP_TX_MAX_BYTES {
        return Err(moto_rt::Error::InvalidArgument);
    }

    let num_pages = (total_len as usize).div_ceil(io_channel::PAGE_SIZE);
    let mut pages = alloc::vec::Vec::with_capacity(num_pages);
    let mut seen: u64 = 0; // Client page ids are < CHANNEL_PAGE_COUNT (64).
    for idx in 0..num_pages {
        let page_id = msg.payload.shared_pages()[idx];
        // Reject a duplicate id within one request before recovering it: two
        // IoPages over one page would double-free it on drop. Dedup must run
        // before get_client_page_checked -- building the second IoPage first
        // and dropping it clears the shared bit while the first copy still
        // lives in `pages`, reintroducing the double-free we guard against.
        let bit = 1u64 << (page_id as u64 & 63);
        if (seen & bit) != 0 {
            return Err(moto_rt::Error::InvalidArgument);
        }
        seen |= bit;
        // A flags/pages count mismatch makes this index point past the slots
        // the client actually filled (an unfilled slot reads as id 0, whose
        // in-use bit is clear), so get_client_page_checked rejects it here
        // rather than us freeing a page the client never allocated. Pages
        // recovered so far are freed when `pages` drops on this early return.
        pages.push(sender.get_client_page_checked(page_id)?);
    }

    Ok((pages, total_len))
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

// Note: there is deliberately no multi-page RX mirroring the multi-page TX
// above. It was implemented and A/B-measured (2026-07-11): no throughput
// difference. Unlike client->server messages, which each cost sys-io a task
// spawn + dispatch, server->client messages are nearly free on both sides,
// so there is nothing to amortize.

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

pub fn get_ip_addr(payload: &io_channel::Payload) -> IpAddr {
    let octets: [u8; 16] = payload.args_8()[0..16].try_into().unwrap();
    let ipv6 = Ipv6Addr::from(octets);
    if let Some(ipv4) = ipv6.to_ipv4_mapped() {
        IpAddr::V4(ipv4)
    } else {
        IpAddr::V6(ipv6)
    }
}

pub fn put_ip_addr(payload: &mut io_channel::Payload, addr: &IpAddr) {
    let ipv6 = match addr {
        IpAddr::V4(ipv4_addr) => ipv4_addr.to_ipv6_mapped(),
        IpAddr::V6(ipv6_addr) => *ipv6_addr,
    };
    payload.args_8_mut()[0..16].copy_from_slice(&ipv6.octets());
}

pub fn get_socket_addr(payload: &io_channel::Payload) -> SocketAddr {
    let port = payload.args_16()[8];
    SocketAddr::new(get_ip_addr(payload), port)
}

// Uses the first 18 bytes (= 9 u16).
pub fn put_socket_addr(payload: &mut io_channel::Payload, addr: &SocketAddr) {
    put_ip_addr(payload, &addr.ip());
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

pub fn icmp_echo_request(
    destination: IpAddr,
    sequence: u16,
    data_len: u16,
    timeout: core::time::Duration,
) -> moto_rt::Result<io_channel::Msg> {
    if timeout > core::time::Duration::from_millis(ICMP_ECHO_MAX_TIMEOUT_MS as u64) {
        return Err(moto_rt::Error::InvalidArgument);
    }
    let timeout_ms = timeout.as_millis();
    if timeout_ms == 0 || timeout_ms > ICMP_ECHO_MAX_TIMEOUT_MS as u128 {
        return Err(moto_rt::Error::InvalidArgument);
    }
    if data_len > ICMP_ECHO_MAX_DATA_LEN || destination.is_unspecified() {
        return Err(moto_rt::Error::InvalidArgument);
    }

    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::IcmpEcho as u16;
    msg.flags = timeout_ms as u32;
    put_ip_addr(&mut msg.payload, &destination);
    msg.payload.args_16_mut()[8] = sequence;
    msg.payload.args_16_mut()[9] = data_len;
    Ok(msg)
}

pub fn decode_icmp_echo_request(msg: &io_channel::Msg) -> moto_rt::Result<IcmpEchoRequest> {
    if msg.command != NetCmd::IcmpEcho as u16
        || msg.id == 0
        || msg.flags == 0
        || msg.flags > ICMP_ECHO_MAX_TIMEOUT_MS
    {
        return Err(moto_rt::Error::InvalidArgument);
    }

    let destination = get_ip_addr(&msg.payload);
    let data_len = msg.payload.args_16()[9];
    if destination.is_unspecified() || data_len > ICMP_ECHO_MAX_DATA_LEN {
        return Err(moto_rt::Error::InvalidArgument);
    }

    Ok(IcmpEchoRequest {
        destination,
        sequence: msg.payload.args_16()[8],
        data_len,
        timeout_ms: msg.flags,
    })
}

pub fn encode_icmp_echo_response(
    mut msg: io_channel::Msg,
    source: IpAddr,
    rtt: core::time::Duration,
) -> io_channel::Msg {
    debug_assert_eq!(msg.command, NetCmd::IcmpEcho as u16);
    put_ip_addr(&mut msg.payload, &source);
    msg.payload.args_64_mut()[2] = rtt.as_nanos().min(u64::MAX as u128) as u64;
    msg.status = moto_rt::E_OK;
    msg
}

pub fn decode_icmp_echo_response(msg: &io_channel::Msg) -> moto_rt::Result<IcmpEchoResponse> {
    if msg.command != NetCmd::IcmpEcho as u16 || msg.id == 0 {
        return Err(moto_rt::Error::InvalidData);
    }
    msg.status()?;

    let source = get_ip_addr(&msg.payload);
    if source.is_unspecified() {
        return Err(moto_rt::Error::InvalidData);
    }

    Ok(IcmpEchoResponse {
        source,
        rtt_ns: msg.payload.args_64()[2],
    })
}

#[test]
fn test_get_put_ip_addr() {
    let mut payload = io_channel::Payload::new_zeroed();

    for addr_in in ["192.0.2.7", "2001:db8::7"] {
        let addr_in: IpAddr = addr_in.parse().unwrap();
        put_ip_addr(&mut payload, &addr_in);
        assert_eq!(addr_in, get_ip_addr(&payload));
    }
}

#[test]
fn test_icmp_echo_codec() {
    let destination: IpAddr = "2001:db8::7".parse().unwrap();
    let mut msg =
        icmp_echo_request(destination, 42, 56, core::time::Duration::from_millis(1500)).unwrap();
    msg.id = 9;

    assert_eq!(
        decode_icmp_echo_request(&msg).unwrap(),
        IcmpEchoRequest {
            destination,
            sequence: 42,
            data_len: 56,
            timeout_ms: 1500,
        }
    );

    let source: IpAddr = "2001:db8::8".parse().unwrap();
    let msg = encode_icmp_echo_response(msg, source, core::time::Duration::from_nanos(123_456));
    assert_eq!(
        decode_icmp_echo_response(&msg).unwrap(),
        IcmpEchoResponse {
            source,
            rtt_ns: 123_456,
        }
    );
}

#[test]
fn test_icmp_echo_rejects_bad_bounds() {
    assert!(matches!(
        icmp_echo_request(
            "192.0.2.1".parse().unwrap(),
            0,
            0,
            core::time::Duration::ZERO,
        ),
        Err(moto_rt::Error::InvalidArgument)
    ));
    assert!(matches!(
        icmp_echo_request(
            "0.0.0.0".parse().unwrap(),
            0,
            0,
            core::time::Duration::from_secs(1),
        ),
        Err(moto_rt::Error::InvalidArgument)
    ));
    assert!(matches!(
        icmp_echo_request(
            "192.0.2.1".parse().unwrap(),
            0,
            0,
            core::time::Duration::from_millis(ICMP_ECHO_MAX_TIMEOUT_MS as u64)
                + core::time::Duration::from_nanos(1),
        ),
        Err(moto_rt::Error::InvalidArgument)
    ));
}

#[test]
fn test_icmp_echo_error_response() {
    let mut msg = icmp_echo_request(
        "192.0.2.1".parse().unwrap(),
        1,
        8,
        core::time::Duration::from_secs(1),
    )
    .unwrap();
    msg.id = 1;
    msg.status = moto_rt::E_TIMED_OUT;

    assert!(matches!(
        decode_icmp_echo_response(&msg),
        Err(moto_rt::Error::TimedOut)
    ));
}

pub fn bind_udp_socket_request(addr: &SocketAddr, subchannel_idx: u8) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::UdpSocketBind as u16;
    msg.payload.args_8_mut()[23] = subchannel_idx;
    put_socket_addr(&mut msg.payload, addr);

    msg
}

pub fn bind_udp_socket_for_remote_request(
    remote_addr: &SocketAddr,
    subchannel_idx: u8,
) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = NetCmd::UdpSocketBindForRemote as u16;
    msg.payload.args_8_mut()[23] = subchannel_idx;
    put_socket_addr(&mut msg.payload, remote_addr);

    msg
}

#[test]
fn test_bind_udp_socket_for_remote_request() {
    let remote_addr = "[2001:db8::1]:53".parse().unwrap();
    let msg = bind_udp_socket_for_remote_request(&remote_addr, 3);

    assert_eq!(msg.command, NetCmd::UdpSocketBindForRemote as u16);
    assert_eq!(get_socket_addr(&msg.payload), remote_addr);
    assert_eq!(msg.payload.args_8()[23], 3);
    assert!(NetCmd::UdpSocketBindForRemote.is_udp());
}
