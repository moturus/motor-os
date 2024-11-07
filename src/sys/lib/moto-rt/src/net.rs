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

pub const SO_RCVTIMEO: u64 = 1;
pub const SO_SNDTIMEO: u64 = 2;
pub const SO_SHUTDOWN: u64 = 3;
pub const SO_NODELAY: u64 = 4;
pub const SO_TTL: u64 = 5;

fn setsockopt(rt_fd: RtFd, opt: u64, ptr: usize, len: usize) -> Result<(), ErrorCode> {
    let vdso_setsockopt: extern "C" fn(RtFd, u64, usize, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().net_setsockopt.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_setsockopt(rt_fd, opt, ptr, len))
}

fn getsockopt(rt_fd: RtFd, opt: u64, ptr: usize, len: usize) -> Result<(), ErrorCode> {
    let vdso_getsockopt: extern "C" fn(RtFd, u64, usize, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().net_getsockopt.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_getsockopt(rt_fd, opt, ptr, len))
}

pub fn bind(proto: u8, addr: &netc::sockaddr) -> Result<RtFd, ErrorCode> {
    let vdso_bind: extern "C" fn(u8, *const netc::sockaddr) -> RtFd = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().net_bind.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    to_result!(vdso_bind(proto, addr))
}

pub fn accept(rt_fd: RtFd) -> Result<(RtFd, netc::sockaddr), ErrorCode> {
    let vdso_accept: extern "C" fn(RtFd, *mut netc::sockaddr) -> RtFd = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().net_accept.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut addr: netc::sockaddr = unsafe { core::mem::zeroed() };
    let res = vdso_accept(rt_fd, &mut addr);
    if res < 0 {
        return Err(-res as ErrorCode);
    }

    Ok((res, addr))
}

pub fn tcp_connect(addr: &netc::sockaddr, timeout: Duration) -> Result<RtFd, ErrorCode> {
    let vdso_tcp_connect: extern "C" fn(*const netc::sockaddr, u64) -> RtFd = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get()
                .net_tcp_connect
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let timeout = timeout.as_nanos().try_into().unwrap_or(u64::MAX);
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

pub fn set_ttl(rt_fd: RtFd, ttl: u32) -> Result<(), ErrorCode> {
    setsockopt(rt_fd, SO_TTL, &ttl as *const _ as usize, 4)
}

pub fn ttl(rt_fd: RtFd) -> Result<u32, ErrorCode> {
    let mut ttl = 0_u32;
    getsockopt(rt_fd, SO_TTL, &mut ttl as *mut _ as usize, 4)?;
    Ok(ttl)
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

pub fn set_read_timeout(rt_fd: RtFd, timeout: Option<Duration>) -> Result<(), ErrorCode> {
    let timeout: u64 = match timeout {
        Some(dur) => dur.as_nanos().try_into().unwrap_or(u64::MAX),
        None => u64::MAX,
    };

    if timeout == 0 {
        return Err(crate::E_INVALID_ARGUMENT);
    }

    setsockopt(
        rt_fd,
        SO_RCVTIMEO,
        &timeout as *const _ as usize,
        core::mem::size_of::<u64>(),
    )
}

pub fn read_timeout(rt_fd: RtFd) -> Result<Option<Duration>, ErrorCode> {
    let mut timeout_ns = 0_u64;

    getsockopt(
        rt_fd,
        SO_RCVTIMEO,
        &mut timeout_ns as *mut _ as usize,
        core::mem::size_of::<u64>(),
    )?;

    if timeout_ns == u64::MAX {
        Ok(None)
    } else {
        Ok(Some(Duration::from_nanos(timeout_ns)))
    }
}

pub fn set_write_timeout(rt_fd: RtFd, timeout: Option<Duration>) -> Result<(), ErrorCode> {
    let timeout: u64 = match timeout {
        Some(dur) => dur.as_nanos().try_into().unwrap_or(u64::MAX),
        None => u64::MAX,
    };

    setsockopt(
        rt_fd,
        SO_SNDTIMEO,
        &timeout as *const _ as usize,
        core::mem::size_of::<u64>(),
    )
}

pub fn write_timeout(rt_fd: RtFd) -> Result<Option<Duration>, ErrorCode> {
    let mut timeout_ns = 0_u64;

    getsockopt(
        rt_fd,
        SO_SNDTIMEO,
        &mut timeout_ns as *mut _ as usize,
        core::mem::size_of::<u64>(),
    )?;

    if timeout_ns == u64::MAX {
        Ok(None)
    } else {
        Ok(Some(Duration::from_nanos(timeout_ns)))
    }
}

pub fn shutdown(rt_fd: RtFd, shutdown: u8) -> Result<(), ErrorCode> {
    if 0 != ((shutdown & !SHUTDOWN_READ) & !SHUTDOWN_WRITE) {
        return Err(crate::E_INVALID_ARGUMENT);
    }

    setsockopt(rt_fd, SO_SHUTDOWN, &shutdown as *const _ as usize, 1)
}

pub fn set_linger(_rt_fd: RtFd, _timeout: Option<Duration>) -> Result<(), ErrorCode> {
    todo!()
}

pub fn linger(_rt_fd: RtFd) -> Result<Option<Duration>, ErrorCode> {
    todo!()
}

pub fn set_nodelay(rt_fd: RtFd, nodelay: bool) -> Result<(), ErrorCode> {
    let nodelay = if nodelay { 1 } else { 0 };
    setsockopt(rt_fd, SO_NODELAY, &nodelay as *const _ as usize, 1)
}

pub fn nodelay(rt_fd: RtFd) -> Result<bool, ErrorCode> {
    let mut nodelay = 0_u8;
    getsockopt(rt_fd, SO_NODELAY, &mut nodelay as *mut _ as usize, 1)?;
    match nodelay {
        0 => Ok(false),
        1 => Ok(true),
        _ => panic!("bad nodelay {nodelay}"),
    }
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
