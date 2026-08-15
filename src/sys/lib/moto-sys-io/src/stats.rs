extern crate std;

use core::slice;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use moto_ipc::sync::RequestHeader;
use moto_ipc::sync::ResponseHeader;
use moto_rt::ErrorCode;

pub const URL_IO_STATS: &str = "sys-io-stats-service";

/// TCP protocol state reported over the sys-io stats interface.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TcpProtocolState {
    #[default]
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
}

const _: () = {
    assert!(size_of::<TcpProtocolState>() == 1);
    assert!(align_of::<TcpProtocolState>() == 1);
};

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

    pub tcp_state: crate::api_net::TcpState,
    pub protocol_state: TcpProtocolState,
}

const _: () = {
    assert!(size_of::<TcpSocketStatsV1>() == 72);
    assert!(align_of::<TcpSocketStatsV1>() == 8);
    assert!(core::mem::offset_of!(TcpSocketStatsV1, tcp_state) == 60);
    assert!(core::mem::offset_of!(TcpSocketStatsV1, protocol_state) == 64);
};

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
            tcp_state: crate::api_net::TcpState::Closed,
            protocol_state: TcpProtocolState::Closed,
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
            self.protocol_state
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

/// Run sys-io's in-process self-tests. Debug builds only: a release sys-io has
/// no self-tests compiled in and answers this with `E_INVALID_ARGUMENT`.
pub const CMD_SELF_TEST: u16 = 1001;

/// The longest failure message [`SelfTestResponse`] carries back.
pub const MAX_SELF_TEST_FAILURE_LEN: usize = 512;

#[repr(C)]
pub struct SelfTestRequest {
    pub header: RequestHeader,
}

#[repr(C)]
pub struct SelfTestResponse {
    pub header: ResponseHeader,
    pub tests_run: u32,
    pub failures: u32,
    /// Bytes of `first_failure` in use; zero when nothing failed.
    pub failure_len: u32,
    pub first_failure: [u8; MAX_SELF_TEST_FAILURE_LEN],
}

const _: () = assert!(size_of::<SelfTestResponse>() <= moto_sys::sys_mem::PAGE_SIZE_SMALL as usize);

/// What a self-test run produced.
pub struct SelfTestOutcome {
    pub tests_run: u32,
    pub failures: u32,
    /// The first failure, as "test name: message". Empty when none failed.
    pub first_failure: std::string::String,
}

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

    /// Run sys-io's self-tests in the running sys-io and collect the result.
    /// Debug builds only, on both sides of this call.
    #[cfg(debug_assertions)]
    pub fn run_self_tests(&mut self) -> Result<SelfTestOutcome, ErrorCode> {
        let req = self.conn.req::<SelfTestRequest>();
        req.header.cmd = CMD_SELF_TEST;
        req.header.ver = 0;
        req.header.flags = 0;

        self.conn.do_rpc(None)?;

        let resp = self.conn.resp::<SelfTestResponse>();
        if resp.header.result != moto_rt::E_OK {
            return Err(resp.header.result);
        }

        let len = (resp.failure_len as usize).min(MAX_SELF_TEST_FAILURE_LEN);
        Ok(SelfTestOutcome {
            tests_run: resp.tests_run,
            failures: resp.failures,
            first_failure: std::string::String::from_utf8_lossy(&resp.first_failure[..len])
                .into_owned(),
        })
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
        let res = self.header.result;
        if res != moto_rt::E_OK {
            return Err(res);
        }

        let start_addr = &self.socket_stats as *const _ as usize;
        let len = (self.num_results as usize) * size_of::<TcpSocketStatsV1>();

        if start_addr + len
            > (self as *const _ as usize) + (moto_sys::sys_mem::PAGE_SIZE_SMALL as usize)
        {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }

        unsafe {
            Ok(slice::from_raw_parts(
                start_addr as *const TcpSocketStatsV1,
                self.num_results as usize,
            ))
        }
    }
}
