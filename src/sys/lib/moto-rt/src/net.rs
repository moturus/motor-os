use super::netc;
use crate::ok_or_error;
use crate::to_result;
use crate::ErrorCode;
use crate::RtFd;
use crate::RtVdsoVtable;
use core::sync::atomic::Ordering;
use core::time::Duration;

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;

// In theory, max UDP payload over IPv4 is
// 65507 = 65535 - 20 (IP header) - 8 (UDP header).
//
// But in practice smoltcp refuses to fragment UDP datagrams
// larger than 65493 bytes, so our practical MAX UDP payload is
// this weird number.
//
// Some argue that it does not make sense to fragment UDP
// datagrams, and so UDP payload should be 1472, or less.
// While smoltcp may well be susceptible to DDOS fragmentation
// atacks in this case, and so we may have to eventually
// disable UDP packet (de)fragmentation, for now we try
// to do our best and allow large UDP payloads.
pub const MAX_UDP_PAYLOAD: usize = 65493;

pub const SHUTDOWN_READ: u8 = 1;
pub const SHUTDOWN_WRITE: u8 = 2;

pub const PROTO_TCP: u8 = 1;
pub const PROTO_UDP: u8 = 2;

pub const SO_RCVTIMEO: u64 = 1;
pub const SO_SNDTIMEO: u64 = 2;
pub const SO_SHUTDOWN: u64 = 3;
pub const SO_NODELAY: u64 = 4;
pub const SO_TTL: u64 = 5;
pub const SO_NONBLOCKING: u64 = 6;
pub const SO_ERROR: u64 = 7;
pub const SO_ONLY_IPV6: u64 = 8;
pub const SO_LINGER: u64 = 9;
pub const SO_BROADCAST: u64 = 10;
pub const SO_MULTICAST_LOOP_V4: u64 = 11;
pub const SO_MULTICAST_LOOP_V6: u64 = 12;
pub const SO_MULTICAST_TTL_V4: u64 = 13;

fn setsockopt(rt_fd: RtFd, opt: u64, ptr: usize, len: usize) -> Result<(), ErrorCode> {
    let vdso_setsockopt: extern "C" fn(RtFd, u64, usize, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_setsockopt.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_setsockopt(rt_fd, opt, ptr, len))
}

fn getsockopt(rt_fd: RtFd, opt: u64, ptr: usize, len: usize) -> Result<(), ErrorCode> {
    let vdso_getsockopt: extern "C" fn(RtFd, u64, usize, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_getsockopt.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_getsockopt(rt_fd, opt, ptr, len))
}

fn setsockopt_bool(rt_fd: RtFd, val: bool, opt: u64) -> Result<(), ErrorCode> {
    let val: u8 = if val { 1 } else { 0 };
    setsockopt(rt_fd, opt, &val as *const _ as usize, 1)
}

fn getsockopt_bool(rt_fd: RtFd, opt: u64) -> Result<bool, ErrorCode> {
    let mut val = 0_u8;
    getsockopt(rt_fd, opt, &mut val as *mut _ as usize, 1)?;
    match val {
        0 => Ok(false),
        1 => Ok(true),
        _ => panic!("bad bool opt val {val} for opt {opt}"),
    }
}

pub fn bind(proto: u8, addr: &netc::sockaddr) -> Result<RtFd, ErrorCode> {
    let vdso_bind: extern "C" fn(u8, *const netc::sockaddr) -> RtFd = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_bind.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    to_result!(vdso_bind(proto, addr))
}

pub fn listen(rt_fd: RtFd, max_backlog: u32) -> Result<(), ErrorCode> {
    let vdso_listen: extern "C" fn(RtFd, u32) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_listen.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_listen(rt_fd, max_backlog))
}

pub fn accept(rt_fd: RtFd) -> Result<(RtFd, netc::sockaddr), ErrorCode> {
    let vdso_accept: extern "C" fn(RtFd, *mut netc::sockaddr) -> RtFd = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_accept.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut addr: netc::sockaddr = unsafe { core::mem::zeroed() };
    let res = vdso_accept(rt_fd, &mut addr);
    if res < 0 {
        return Err(-res as ErrorCode);
    }

    Ok((res, addr))
}

/// Create a TCP stream by connecting to a remote addr.
pub fn tcp_connect(
    addr: &netc::sockaddr,
    timeout: Duration,
    nonblocking: bool,
) -> Result<RtFd, ErrorCode> {
    let vdso_tcp_connect: extern "C" fn(*const netc::sockaddr, u64, bool) -> RtFd = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_tcp_connect.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let timeout = timeout.as_nanos().try_into().unwrap_or(u64::MAX);
    to_result!(vdso_tcp_connect(addr, timeout, nonblocking))
}

pub fn udp_connect(rt_fd: RtFd, addr: &netc::sockaddr) -> Result<(), ErrorCode> {
    let vdso_udp_connect: extern "C" fn(RtFd, *const netc::sockaddr) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_udp_connect.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_udp_connect(rt_fd, addr))
}

pub fn socket_addr(rt_fd: RtFd) -> Result<netc::sockaddr, ErrorCode> {
    let vdso_socket_addr: extern "C" fn(RtFd, *mut netc::sockaddr) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_socket_addr.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut addr: netc::sockaddr = unsafe { core::mem::zeroed() };
    let res = vdso_socket_addr(rt_fd, &mut addr);
    if res != crate::E_OK {
        return Err(res as ErrorCode);
    }

    Ok(addr)
}

pub fn peer_addr(rt_fd: RtFd) -> Result<netc::sockaddr, ErrorCode> {
    let vdso_peer_addr: extern "C" fn(RtFd, *mut netc::sockaddr) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_peer_addr.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut addr: netc::sockaddr = unsafe { core::mem::zeroed() };
    let res = vdso_peer_addr(rt_fd, &mut addr);
    if res != crate::E_OK {
        return Err(res as ErrorCode);
    }

    Ok(addr)
}

pub fn set_ttl(rt_fd: RtFd, ttl: u32) -> Result<(), ErrorCode> {
    setsockopt(rt_fd, SO_TTL, &ttl as *const _ as usize, 4)
}

pub fn ttl(rt_fd: RtFd) -> Result<u32, ErrorCode> {
    let mut ttl = 0_u32;
    getsockopt(rt_fd, SO_TTL, &mut ttl as *mut _ as usize, 4)?;
    Ok(ttl)
}

pub fn set_only_v6(rt_fd: RtFd, only_v6: bool) -> Result<(), ErrorCode> {
    setsockopt_bool(rt_fd, only_v6, SO_ONLY_IPV6)
}

pub fn only_v6(rt_fd: RtFd) -> Result<bool, ErrorCode> {
    getsockopt_bool(rt_fd, SO_ONLY_IPV6)
}

pub fn take_error(rt_fd: RtFd) -> Result<ErrorCode, ErrorCode> {
    let mut error = 0_u16;
    getsockopt(rt_fd, SO_ERROR, &mut error as *mut _ as usize, 2)?;
    Ok(error as ErrorCode)
}

pub fn set_nonblocking(rt_fd: RtFd, nonblocking: bool) -> Result<(), ErrorCode> {
    setsockopt_bool(rt_fd, nonblocking, SO_NONBLOCKING)
}

pub fn peek(rt_fd: RtFd, buf: &mut [u8]) -> Result<usize, ErrorCode> {
    let vdso_peek: extern "C" fn(i32, *mut u8, usize) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_peek.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    to_result!(vdso_peek(rt_fd, buf.as_mut_ptr(), buf.len()))
}

pub fn set_read_timeout(rt_fd: RtFd, timeout: Option<Duration>) -> Result<(), ErrorCode> {
    let timeout: u64 = match timeout {
        Some(dur) => dur.as_nanos().try_into().unwrap_or(u64::MAX),
        None => u64::MAX,
    };

    if timeout == 0 {
        // See TcpStream::set_read_timeout() doc in Rust stdlib.
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

    if timeout == 0 {
        // See TcpStream::set_write_timeout() doc in Rust stdlib.
        return Err(crate::E_INVALID_ARGUMENT);
    }

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

const MAX_LINGER_MS: u64 = 60_000; // 60 sec.
pub fn set_linger(rt_fd: RtFd, timeout: Option<Duration>) -> Result<(), ErrorCode> {
    let linger_millis: u64 = if let Some(timo) = timeout {
        let millis = timo.as_millis();
        if millis > (MAX_LINGER_MS as u128) {
            MAX_LINGER_MS
        } else {
            millis as u64
        }
    } else {
        u64::MAX
    };
    setsockopt(rt_fd, SO_LINGER, &linger_millis as *const u64 as usize, 8)
}

pub fn linger(rt_fd: RtFd) -> Result<Option<Duration>, ErrorCode> {
    let mut linger_millis = 0_u64;
    getsockopt(rt_fd, SO_LINGER, &mut linger_millis as *mut _ as usize, 8)?;
    match linger_millis {
        val if val <= MAX_LINGER_MS => Ok(Some(Duration::from_millis(val))),
        u64::MAX => Ok(None),
        _ => panic!("bad linger {linger_millis}"),
    }
}

pub fn set_nodelay(rt_fd: RtFd, nodelay: bool) -> Result<(), ErrorCode> {
    setsockopt_bool(rt_fd, nodelay, SO_NODELAY)
}

pub fn nodelay(rt_fd: RtFd) -> Result<bool, ErrorCode> {
    getsockopt_bool(rt_fd, SO_NODELAY)
}

pub fn set_udp_broadcast(rt_fd: RtFd, val: bool) -> Result<(), ErrorCode> {
    setsockopt_bool(rt_fd, val, SO_BROADCAST)
}

pub fn udp_broadcast(rt_fd: RtFd) -> Result<bool, ErrorCode> {
    getsockopt_bool(rt_fd, SO_BROADCAST)
}

pub fn udp_recv_from(rt_fd: RtFd, buf: &mut [u8]) -> Result<(usize, netc::sockaddr), ErrorCode> {
    let mut addr: netc::sockaddr = unsafe { core::mem::zeroed() };

    let vdso_udp_recv_from: extern "C" fn(i32, *mut u8, usize, *mut netc::sockaddr) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get()
                .net_udp_recv_from
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let res = vdso_udp_recv_from(rt_fd, buf.as_mut_ptr(), buf.len(), &mut addr as *mut _);
    if res < 0 {
        Err((-res) as ErrorCode)
    } else {
        Ok(((res as usize), addr))
    }
}

pub fn udp_peek_from(rt_fd: RtFd, buf: &mut [u8]) -> Result<(usize, netc::sockaddr), ErrorCode> {
    let mut addr: netc::sockaddr = unsafe { core::mem::zeroed() };

    let vdso_udp_peek_from: extern "C" fn(i32, *mut u8, usize, *mut netc::sockaddr) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get()
                .net_udp_peek_from
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let res = vdso_udp_peek_from(rt_fd, buf.as_mut_ptr(), buf.len(), &mut addr as *mut _);
    if res < 0 {
        Err((-res) as ErrorCode)
    } else {
        Ok(((res as usize), addr))
    }
}

pub fn udp_send_to(rt_fd: RtFd, buf: &[u8], addr: &netc::sockaddr) -> Result<usize, ErrorCode> {
    let vdso_udp_send_to: extern "C" fn(i32, *const u8, usize, *const netc::sockaddr) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().net_udp_send_to.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    to_result!(vdso_udp_send_to(
        rt_fd,
        buf.as_ptr(),
        buf.len(),
        addr as *const _
    ))
}

pub fn set_udp_multicast_loop_v4(rt_fd: RtFd, val: bool) -> Result<(), ErrorCode> {
    setsockopt_bool(rt_fd, val, SO_MULTICAST_LOOP_V4)
}

pub fn udp_multicast_loop_v4(rt_fd: RtFd) -> Result<bool, ErrorCode> {
    getsockopt_bool(rt_fd, SO_MULTICAST_LOOP_V4)
}

pub fn set_udp_multicast_ttl_v4(rt_fd: RtFd, val: u32) -> Result<(), ErrorCode> {
    setsockopt(rt_fd, SO_MULTICAST_TTL_V4, &val as *const _ as usize, 4)
}

pub fn udp_multicast_ttl_v4(rt_fd: RtFd) -> Result<u32, ErrorCode> {
    let mut ttl = 0_u32;
    getsockopt(rt_fd, SO_MULTICAST_TTL_V4, &mut ttl as *mut _ as usize, 4)?;
    Ok(ttl)
}

pub fn set_udp_multicast_loop_v6(rt_fd: RtFd, val: bool) -> Result<(), ErrorCode> {
    setsockopt_bool(rt_fd, val, SO_MULTICAST_LOOP_V6)
}

pub fn udp_multicast_loop_v6(rt_fd: RtFd) -> Result<bool, ErrorCode> {
    getsockopt_bool(rt_fd, SO_MULTICAST_LOOP_V6)
}

pub const JOIN_MULTICAST_OP: u64 = 1;
pub const LEAVE_MULTICAST_OP: u64 = 2;

pub fn join_udp_multicast_v4(
    rt_fd: RtFd,
    addr: &netc::in_addr,
    iface: &netc::in_addr,
) -> Result<(), ErrorCode> {
    let vdso_multicast_op_v4: extern "C" fn(
        i32,
        u64,
        *const netc::in_addr,
        *const netc::in_addr,
    ) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get()
                .net_udp_multicast_op_v4
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_multicast_op_v4(
        rt_fd,
        JOIN_MULTICAST_OP,
        addr as *const _,
        iface as *const _,
    ))
}

pub fn leave_udp_multicast_v4(
    rt_fd: RtFd,
    addr: &netc::in_addr,
    iface: &netc::in_addr,
) -> Result<(), ErrorCode> {
    let vdso_multicast_op_v4: extern "C" fn(
        i32,
        u64,
        *const netc::in_addr,
        *const netc::in_addr,
    ) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get()
                .net_udp_multicast_op_v4
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_multicast_op_v4(
        rt_fd,
        LEAVE_MULTICAST_OP,
        addr as *const _,
        iface as *const _,
    ))
}

pub fn join_udp_multicast_v6(
    rt_fd: RtFd,
    addr: &netc::in6_addr,
    iface: u32,
) -> Result<(), ErrorCode> {
    let vdso_multicast_op_v6: extern "C" fn(i32, u64, *const netc::in6_addr, u32) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get()
                .net_udp_multicast_op_v6
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_multicast_op_v6(
        rt_fd,
        JOIN_MULTICAST_OP,
        addr as *const _,
        iface,
    ))
}

pub fn leave_udp_multicast_v6(
    rt_fd: RtFd,
    addr: &netc::in6_addr,
    iface: u32,
) -> Result<(), ErrorCode> {
    let vdso_multicast_op_v6: extern "C" fn(i32, u64, *const netc::in6_addr, u32) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get()
                .net_udp_multicast_op_v6
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_multicast_op_v6(
        rt_fd,
        LEAVE_MULTICAST_OP,
        addr as *const _,
        iface,
    ))
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
            RtVdsoVtable::get().dns_lookup.load(Ordering::Relaxed) as usize as *const (),
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
