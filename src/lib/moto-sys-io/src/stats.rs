use core::slice;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use moto_ipc::sync::RequestHeader;
use moto_ipc::sync::ResponseHeader;
use moto_sys::ErrorCode;

pub const URL_IO_STATS: &str = "sys-io-stats-service";

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpSocketStatsV1 {
    pub id: u64,
    pub device_id: u64,
    pub pid: u64,             // Owner's process ID.
    pub local_addr: [u8; 16], // If IPv4, IPv4 -> IPv6 mapping will be used.
    pub local_port: u16,
    pub remote_addr: [u8; 16], // All zeroes if not known.
    pub remote_port: u16,      // Zero if not known.

    pub tcp_state: moto_runtime::rt_api::net::TcpState,
    pub smoltcp_state: smoltcp::socket::tcp::State,
}

impl Default for TcpSocketStatsV1 {
    fn default() -> Self {
        Self {
            id: 0,
            device_id: u64::MAX,
            pid: 0,
            local_addr: [0; 16],
            local_port: 0,
            remote_addr: [0; 16],
            remote_port: 0,
            tcp_state: moto_runtime::rt_api::net::TcpState::Closed,
            smoltcp_state: smoltcp::socket::tcp::State::Closed,
        }
    }
}

impl core::fmt::Debug for TcpSocketStatsV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TCP: pid: {} dev: {} id: {} local_addr: {:?} remote_addr: {:?} state: {:?} ({:?})",
            self.pid,
            self.device_id,
            self.id,
            self.local_addr(),
            self.remote_addr(),
            self.tcp_state,
            self.smoltcp_state
        )
    }
}

impl TcpSocketStatsV1 {
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        Self::octets_to_addr(&self.local_addr, self.local_port)
    }

    pub fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        Self::octets_to_addr(&self.remote_addr, self.remote_port)
    }

    fn octets_to_addr(octets: &[u8; 16], port: u16) -> Option<std::net::SocketAddr> {
        if port == 0 {
            return None;
        }
        if *octets == [0u8; 16] {
            return None;
        }
        if octets[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255] {
            Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]),
                port,
            )))
        } else {
            Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::from(*octets),
                port,
                0,
                0,
            )))
        }
    }
}

pub const CMD_TCP_STATS: u16 = 1000;

pub struct IoStatsService {
    conn: moto_ipc::sync::ClientConnection,
}

impl IoStatsService {
    pub fn connect() -> Result<Self, ErrorCode> {
        let mut conn = moto_ipc::sync::ClientConnection::new(moto_ipc::sync::ChannelSize::Small)?;
        conn.connect(URL_IO_STATS)?;
        Ok(Self { conn })
    }

    /// Get existing TCP socket info for sockets with IDs >= start_id.
    /// Sockets are returned in order of their IDs, so start_id can be used for "paging".
    pub fn get_tcp_socket_stats(
        &mut self,
        start_id: u64,
    ) -> Result<&[TcpSocketStatsV1], ErrorCode> {
        let req = self.conn.req::<GetTcpSocketStatsRequest>();
        req.header.cmd = CMD_TCP_STATS;
        req.header.ver = 0;
        req.header.flags = 0;
        req.start_id = start_id;

        self.conn.do_rpc(None)?;

        self.conn
            .resp::<GetTcpSocketStatsResponse<1>>()
            .socket_stats()
    }
}

#[repr(C)]
pub struct GetTcpSocketStatsRequest {
    pub header: RequestHeader,
    pub start_id: u64,
}

#[repr(C)]
pub struct GetTcpSocketStatsResponse<const N: usize> {
    pub header: ResponseHeader,
    pub num_results: u64,
    pub socket_stats: [TcpSocketStatsV1; N],
}

pub const MAX_TCP_SOCKET_STATS: usize = 56;

const _SZ: () = assert!(
    size_of::<GetTcpSocketStatsResponse<MAX_TCP_SOCKET_STATS>>()
        <= moto_sys::sys_mem::PAGE_SIZE_SMALL as usize
);

impl<const N: usize> GetTcpSocketStatsResponse<N> {
    const _SZ: () = assert!(size_of::<Self>() <= moto_sys::sys_mem::PAGE_SIZE_SMALL as usize);

    pub fn socket_stats(&self) -> Result<&[TcpSocketStatsV1], ErrorCode> {
        let res = ErrorCode::from(self.header.result);
        if res.is_err() {
            return Err(res);
        }

        let start_addr = &self.socket_stats as *const _ as usize;
        let len = (self.num_results as usize) * size_of::<TcpSocketStatsV1>();

        if start_addr + len
            > (self as *const _ as usize) + (moto_sys::sys_mem::PAGE_SIZE_SMALL as usize)
        {
            return Err(ErrorCode::InternalError);
        }

        unsafe {
            Ok(slice::from_raw_parts(
                start_addr as *const TcpSocketStatsV1,
                self.num_results as usize,
            ))
        }
    }
}
