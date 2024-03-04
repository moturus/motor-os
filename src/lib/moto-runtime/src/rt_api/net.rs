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
pub const CMD_TCP_STREAM_WRITE: u16 = CMD_MIN + 6;
pub const CMD_TCP_STREAM_READ: u16 = CMD_MIN + 7;
pub const CMD_TCP_STREAM_PEEK: u16 = CMD_MIN + 8;
pub const CMD_TCP_STREAM_SET_OPTION: u16 = CMD_MIN + 9;
pub const CMD_TCP_STREAM_GET_OPTION: u16 = CMD_MIN + 10;
pub const CMD_TCP_STREAM_DROP: u16 = CMD_MIN + 11;

pub const CMD_MAX: u16 = CMD_MIN + 11;

pub const TCP_OPTION_SHUT_RD: u64 = 1 << 0;
pub const TCP_OPTION_SHUT_WR: u64 = 1 << 1;
pub const TCP_OPTION_READ_TIMEOUT: u64 = 1 << 2;
pub const TCP_OPTION_WRITE_TIMEOUT: u64 = 1 << 3;
pub const TCP_OPTION_NODELAY: u64 = 1 << 4;
pub const TCP_OPTION_TTL: u64 = 1 << 5;
pub const TCP_OPTION_NONBLOCKING: u64 = 1 << 6;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TcpState {
    Connecting,
    ReadWrite,
    ReadOnly,
    WriteOnly,
    Closed,
}

impl TcpState {
    pub fn can_read(&self) -> bool {
        *self == TcpState::ReadWrite || *self == TcpState::ReadOnly
    }

    pub fn can_write(&self) -> bool {
        *self == TcpState::ReadWrite || *self == TcpState::WriteOnly
    }
}

pub fn bind_tcp_listener_request(addr: &SocketAddr) -> io_channel::QueueEntry {
    let mut qe = io_channel::QueueEntry::new();
    qe.command = CMD_TCP_LISTENER_BIND;
    put_socket_addr(&mut qe.payload, addr);

    qe
}

pub fn accept_tcp_listener_request(handle: u64) -> io_channel::QueueEntry {
    let mut qe = io_channel::QueueEntry::new();
    qe.command = CMD_TCP_LISTENER_ACCEPT;
    qe.handle = handle;

    qe
}

pub fn tcp_stream_connect_request(addr: &SocketAddr) -> io_channel::QueueEntry {
    let mut qe = io_channel::QueueEntry::new();
    qe.command = CMD_TCP_STREAM_CONNECT;
    qe.payload.args_32_mut()[5] = 0; // timeout
    put_socket_addr(&mut qe.payload, addr);

    qe
}

pub fn tcp_stream_connect_timeout_request(
    addr: &SocketAddr,
    timeout: moto_sys::time::Instant,
) -> io_channel::QueueEntry {
    let mut qe = io_channel::QueueEntry::new();
    qe.command = CMD_TCP_STREAM_CONNECT;

    // We have only 32 bits for timeout. ~10ms granularity is fine.
    let timeout = timeout.as_u64() >> 27;
    assert!(timeout < (u32::MAX) as u64);
    qe.payload.args_32_mut()[5] = timeout as u32;
    put_socket_addr(&mut qe.payload, addr);

    qe
}

pub fn tcp_stream_connect_timeout(qe: &io_channel::QueueEntry) -> Option<moto_sys::time::Instant> {
    let mut timeout = qe.payload.args_32()[5];
    timeout &= u32::MAX - 1;
    if timeout == 0 {
        return None;
    }
    let timeout = (timeout as u64) << 27;
    Some(moto_sys::time::Instant::from_u64(timeout))
}

pub fn tcp_stream_write_request(
    handle: u64,
    io_buffer: io_channel::IoBuffer,
    sz: usize,
    timestamp: u64,
) -> io_channel::QueueEntry {
    let mut qe = io_channel::QueueEntry::new();
    qe.command = CMD_TCP_STREAM_WRITE;
    qe.handle = handle;
    qe.payload.buffers_mut()[0] = io_buffer;
    qe.payload.args_64_mut()[1] = sz as u64;
    qe.payload.args_64_mut()[2] = timestamp;

    qe
}

pub fn tcp_stream_read_request(
    handle: u64,
    io_buffer: io_channel::IoBuffer,
    sz: usize,
    timestamp: u64,
) -> io_channel::QueueEntry {
    let mut qe = io_channel::QueueEntry::new();
    qe.command = CMD_TCP_STREAM_READ;
    qe.handle = handle;
    qe.payload.buffers_mut()[0] = io_buffer;
    qe.payload.args_64_mut()[1] = sz as u64;
    qe.payload.args_64_mut()[2] = timestamp;

    qe
}

pub fn tcp_stream_peek_request(
    handle: u64,
    io_buffer: io_channel::IoBuffer,
    sz: usize,
    timestamp: u64,
) -> io_channel::QueueEntry {
    let mut qe = io_channel::QueueEntry::new();
    qe.command = CMD_TCP_STREAM_PEEK;
    qe.handle = handle;
    qe.payload.buffers_mut()[0] = io_buffer;
    qe.payload.args_64_mut()[1] = sz as u64;
    qe.payload.args_64_mut()[2] = timestamp;

    qe
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
