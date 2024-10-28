use super::netc;
use crate::ok_or_error;
use crate::to_result;
use crate::ErrorCode;
use crate::RtFd;
use crate::RtVdsoVtableV1;
use core::sync::atomic::Ordering;
use core::time::Duration;

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;

pub const SHUTDOWN_READ: u8 = 1;
pub const SHUTDOWN_WRITE: u8 = 2;

pub const PROTO_TCP: u8 = 1;
pub const PROTO_UDP: u8 = 2;

pub fn bind(proto: u8, addr: &netc::sockaddr) -> Result<RtFd, ErrorCode> {
    let vdso_bind: extern "C" fn(u8, *const netc::sockaddr) -> RtFd = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().net_bind.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    to_result!(vdso_bind(proto, addr))
}

pub fn accept(_rt_fd: RtFd) -> Result<(RtFd, netc::sockaddr), ErrorCode> {
    todo!()
}

pub fn tcp_connect(addr: &netc::sockaddr, timeout: Duration) -> Result<RtFd, ErrorCode> {
    let vdso_tcp_connect: extern "C" fn(*const netc::sockaddr, u64) -> RtFd = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get()
                .net_tcp_connect
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let timeout = match timeout.as_nanos() {
        x if x >= (u64::MAX as u128) => u64::MAX,
        x => x as u64,
    };
    to_result!(vdso_tcp_connect(addr, timeout))
}

pub fn udp_connect(addr: &netc::sockaddr) -> Result<(), ErrorCode> {
    let vdso_udp_connect: extern "C" fn(*const netc::sockaddr) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get()
                .net_udp_connect
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_udp_connect(addr))
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
    let vdso_lookup: extern "C" fn(
        /* host_bytes */ *const u8,
        /* host_bytes_sz */ usize,
        /* port */ u16,
        /* result_addr */ *mut usize,
        /* result_len */ *mut usize,
    ) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().dns_lookup.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut result_addr: usize = 0;
    let mut result_num: usize = 0;

    let res = vdso_lookup(
        host.as_bytes().as_ptr(),
        host.len(),
        port,
        &mut result_addr,
        &mut result_num,
    );
    if res != crate::E_OK {
        return Err(res);
    }

    let addresses: &[netc::sockaddr] =
        unsafe { core::slice::from_raw_parts(result_addr as *const netc::sockaddr, result_num) };

    let mut vecdec = alloc::collections::VecDeque::new();
    for addr in addresses {
        vecdec.push_back(*addr);
    }

    let layout = core::alloc::Layout::from_size_align(
        core::mem::size_of::<netc::sockaddr>() * result_num,
        16,
    )
    .unwrap();
    unsafe { crate::alloc::dealloc(result_addr as *mut u8, layout) };

    Ok((port, vecdec))
}
