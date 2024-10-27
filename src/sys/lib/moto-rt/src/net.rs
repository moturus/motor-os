use super::netc;
use crate::ErrorCode;
use crate::RtFd;
use core::time::Duration;

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;

pub const SHUTDOWN_READ: u8 = 1;
pub const SHUTDOWN_WRITE: u8 = 2;

pub const PROTO_TCP: u8 = 1;
pub const PROTO_UDP: u8 = 2;

pub fn bind(_proto: u8, _addr: &netc::sockaddr) -> Result<RtFd, ErrorCode> {
    todo!()
}

pub fn accept(_rt_fd: RtFd) -> Result<(RtFd, netc::sockaddr), ErrorCode> {
    todo!()
}

pub fn tcp_connect(_addr: &netc::sockaddr, _timeout: Duration) -> Result<RtFd, ErrorCode> {
    todo!()
}

pub fn udp_connect(_addr: &netc::sockaddr) -> Result<(), ErrorCode> {
    todo!()
}

pub fn socket_addr(_rt_fd: RtFd) -> Result<netc::sockaddr, ErrorCode> {
    todo!()
}

pub fn peer_addr(_rt_fd: RtFd) -> Result<netc::sockaddr, ErrorCode> {
    todo!()
}

pub fn set_ttl(_rt_fd: RtFd, _ttl: u32) -> Result<(), ErrorCode> {
    todo!()
}

pub fn ttl(_rt_fd: RtFd) -> Result<u32, ErrorCode> {
    todo!()
}

pub fn set_only_v6(_rt_fd: RtFd, _only_v6: bool) -> Result<(), ErrorCode> {
    todo!()
}

pub fn only_v6(_rt_fd: RtFd) -> Result<bool, ErrorCode> {
    todo!()
}

pub fn take_error(_rt_fd: RtFd) -> Result<ErrorCode, ErrorCode> {
    // getsockopt
    Err(crate::E_NOT_IMPLEMENTED)
}

pub fn set_nonblocking(_rt_fd: RtFd, _nonblocking: bool) -> Result<(), ErrorCode> {
    todo!()
}

pub fn peek(_rt_fd: RtFd, _buf: &mut [u8]) -> Result<usize, ErrorCode> {
    todo!()
}

pub fn set_read_timeout(_rt_fd: RtFd, _timeout: Option<Duration>) -> Result<(), ErrorCode> {
    todo!()
}

pub fn read_timeout(_rt_fd: RtFd) -> Result<Option<Duration>, ErrorCode> {
    todo!()
}

pub fn set_write_timeout(_rt_fd: RtFd, _timeout: Option<Duration>) -> Result<(), ErrorCode> {
    todo!()
}

pub fn write_timeout(_rt_fd: RtFd) -> Result<Option<Duration>, ErrorCode> {
    todo!()
}

pub fn shutdown(_rt_fd: RtFd, _shutdown: u8) -> Result<(), ErrorCode> {
    todo!()
}

pub fn set_linger(_rt_fd: RtFd, _timeout: Option<Duration>) -> Result<(), ErrorCode> {
    todo!()
}

pub fn linger(_rt_fd: RtFd) -> Result<Option<Duration>, ErrorCode> {
    todo!()
}

pub fn set_nodelay(_rt_fd: RtFd, _nodelay: bool) -> Result<(), ErrorCode> {
    todo!()
}

pub fn nodelay(_rt_fd: RtFd) -> Result<bool, ErrorCode> {
    todo!()
}

pub fn set_udp_broadcast(_rt_fd: RtFd, _broadcast: bool) -> Result<(), ErrorCode> {
    todo!()
}

pub fn udp_broadcast(_rt_fd: RtFd) -> Result<bool, ErrorCode> {
    todo!()
}

pub fn udp_recv_from(_rt_fd: RtFd, _buf: &mut [u8]) -> Result<(usize, netc::sockaddr), ErrorCode> {
    todo!()
}

pub fn udp_peek_from(_rt_fd: RtFd, _buf: &mut [u8]) -> Result<(usize, netc::sockaddr), ErrorCode> {
    todo!()
}

pub fn udp_send_to(_rt_fd: RtFd, _buf: &[u8], _addr: &netc::sockaddr) -> Result<usize, ErrorCode> {
    todo!()
}

pub fn set_udp_multicast_loop_v4(_rt_fd: RtFd, _val: bool) -> Result<(), ErrorCode> {
    todo!()
}

pub fn udp_multicast_loop_v4(_rt_fd: RtFd) -> Result<bool, ErrorCode> {
    todo!()
}

pub fn set_udp_multicast_ttl_v4(_rt_fd: RtFd, _val: u32) -> Result<(), ErrorCode> {
    todo!()
}

pub fn udp_multicast_ttl_v4(_rt_fd: RtFd) -> Result<u32, ErrorCode> {
    todo!()
}

pub fn set_udp_multicast_loop_v6(_rt_fd: RtFd, _val: bool) -> Result<(), ErrorCode> {
    todo!()
}

pub fn udp_multicast_loop_v6(_rt_fd: RtFd) -> Result<bool, ErrorCode> {
    todo!()
}

pub fn join_udp_multicast_v4(
    _rt_fd: RtFd,
    _addr: &netc::in_addr,
    _iface: &netc::in_addr,
) -> Result<(), ErrorCode> {
    todo!()
}

pub fn leave_udp_multicast_v4(
    _rt_fd: RtFd,
    _addr: &netc::in_addr,
    _iface: &netc::in_addr,
) -> Result<(), ErrorCode> {
    todo!()
}

pub fn join_udp_multicast_v6(
    _rt_fd: RtFd,
    _addr: &netc::in6_addr,
    _iface: u32,
) -> Result<(), ErrorCode> {
    todo!()
}

pub fn leave_udp_multicast_v6(
    _rt_fd: RtFd,
    _addr: &netc::in6_addr,
    _iface: u32,
) -> Result<(), ErrorCode> {
    todo!()
}

pub fn lookup_host(
    host: &str,
    port: u16,
) -> Result<(u16, alloc::collections::VecDeque<netc::sockaddr>), ErrorCode> {
    use core::net::Ipv4Addr;
    use core::net::SocketAddrV4;
    use core::str::FromStr;

    // TODO: move to vdso.
    let addr = if host == "localhost" {
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)
    } else if let Ok(addr_v4) = Ipv4Addr::from_str(host) {
        SocketAddrV4::new(addr_v4, port)
    } else {
        #[cfg(debug_assertions)]
        crate::moto_log!(
            "LookupHost::try_from: {}:{}: DNS lookup not implemented",
            host,
            port
        );
        return Err(crate::E_NOT_IMPLEMENTED);
    };

    let addr = netc::sockaddr { v4: addr.into() };
    let mut vecdec = alloc::collections::VecDeque::new();
    vecdec.push_back(addr);
    Ok((port, vecdec))
}
