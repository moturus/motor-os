//! The vdso net veneer: the C-ABI shims std/mio call through (bind, listen,
//! accept, connect, the socket options, DNS), plus the netdev-gated internal
//! helper. Everything here is caller-thread glue over the socket state
//! machines in rt_tcp/rt_udp and the channel runtime in [`super::channel`];
//! it is what stays in the vdso when those move to moto-io.

use crate::posix;
use crate::posix::PosixFile;
use alloc::vec::Vec;
use core::any::Any;
use core::time::Duration;
use moto_rt::RtFd;
use moto_rt::netc;
use moto_sys::ErrorCode;

use super::rt_tcp::TcpStream;
use super::rt_udp::UdpSocket;

pub unsafe extern "C" fn dns_lookup(
    host_bytes: *const u8,
    host_bytes_sz: usize,
    port: u16,
    result_addr: *mut usize,
    result_len: *mut usize,
) -> ErrorCode {
    use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use core::str::FromStr;
    use moto_dns::{AddressFamily, ClientError, Status};
    use moto_rt::netc;

    fn error_code(error: ClientError) -> ErrorCode {
        match error {
            ClientError::InvalidName => moto_rt::E_INVALID_ARGUMENT,
            ClientError::ServiceUnavailable => moto_rt::E_NOT_CONNECTED,
            ClientError::TimedOut => moto_rt::E_TIMED_OUT,
            ClientError::Transport(error) => error,
            ClientError::Protocol(_) => moto_rt::E_INVALID_DATA,
            ClientError::Resolver(status) => match status {
                Status::NotFound => moto_rt::E_NOT_FOUND,
                Status::TemporaryFailure | Status::Busy => moto_rt::E_NOT_READY,
                Status::OutOfMemory => moto_rt::E_OUT_OF_MEMORY,
                Status::TimedOut => moto_rt::E_TIMED_OUT,
                Status::System | Status::ResolverFailure => moto_rt::E_INTERNAL_ERROR,
                Status::Ok | Status::UnsupportedFamily | Status::InvalidRequest => {
                    moto_rt::E_INVALID_DATA
                }
            },
        }
    }

    if result_addr.is_null() || result_len.is_null() {
        return moto_rt::E_INVALID_ARGUMENT;
    }
    unsafe {
        *result_addr = 0;
        *result_len = 0;
    }
    if host_bytes.is_null()
        || host_bytes_sz == 0
        || host_bytes_sz > moto_dns::MAX_NAME_LEN
    {
        return moto_rt::E_INVALID_ARGUMENT;
    }

    let host_bytes = unsafe { core::slice::from_raw_parts(host_bytes, host_bytes_sz) };
    if host_bytes.contains(&0) {
        return moto_rt::E_INVALID_ARGUMENT;
    }
    let Ok(host) = core::str::from_utf8(host_bytes) else {
        return moto_rt::E_INVALID_ARGUMENT;
    };

    let mut addresses = Vec::<netc::sockaddr>::new();
    if host == "localhost" {
        addresses.push(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).into());
    } else if let Ok(addr_v4) = Ipv4Addr::from_str(host) {
        addresses.push(SocketAddr::V4(SocketAddrV4::new(addr_v4, port)).into());
    } else if let Ok(addr_v6) = Ipv6Addr::from_str(host) {
        addresses.push(SocketAddr::V6(SocketAddrV6::new(addr_v6, port, 0, 0)).into());
    } else {
        let mut client = match moto_dns::Client::connect() {
            Ok(client) => client,
            Err(error) => return error_code(error),
        };
        let lookup = match client.lookup(host, AddressFamily::Any) {
            Ok(lookup) => lookup,
            Err(error) => return error_code(error),
        };
        if lookup.truncated {
            log::warn!(
                "dns_lookup: resolver truncated the result for {}:{} to {} addresses",
                host,
                port,
                lookup.addresses.len()
            );
        }

        addresses.reserve(lookup.addresses.len());
        for address in lookup.addresses {
            let socket_addr = match address.address_family() {
                Ok(AddressFamily::V4) => SocketAddr::new(
                    Ipv4Addr::new(
                        address.bytes[0],
                        address.bytes[1],
                        address.bytes[2],
                        address.bytes[3],
                    )
                    .into(),
                    port,
                ),
                Ok(AddressFamily::V6) => {
                    SocketAddr::new(Ipv6Addr::from(address.bytes).into(), port)
                }
                Ok(AddressFamily::Any) | Err(_) => return moto_rt::E_INVALID_DATA,
            };
            addresses.push(socket_addr.into());
        }
    }

    let allocation_size = core::mem::size_of_val(addresses.as_slice());
    let res_addr = unsafe { crate::rt_alloc::alloc(allocation_size as u64, 16) };
    if res_addr == 0 {
        return moto_rt::E_OUT_OF_MEMORY;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            addresses.as_ptr(),
            res_addr as usize as *mut netc::sockaddr,
            addresses.len(),
        );
        *result_addr = res_addr as usize;
        *result_len = addresses.len();
    }
    moto_rt::E_OK
}

pub extern "C" fn bind(proto: u8, addr: *const netc::sockaddr) -> RtFd {
    if proto == moto_rt::net::PROTO_UDP {
        let addr = unsafe { (*addr).into() };
        let udp_socket = match super::rt_udp::UdpSocket::bind(&addr) {
            Ok(x) => x,
            Err(err) => return -(err as RtFd),
        };
        posix::push_file(udp_socket)
    } else if proto == moto_rt::net::PROTO_UDP_FOR_REMOTE {
        let addr = unsafe { (*addr).into() };
        let udp_socket = match super::rt_udp::UdpSocket::bind_for_remote(&addr) {
            Ok(socket) => socket,
            Err(err) => return -(err as RtFd),
        };
        posix::push_file(udp_socket)
    } else if proto == moto_rt::net::PROTO_TCP {
        let addr = unsafe { (*addr).into() };
        let listener = match super::rt_tcp::TcpListener::bind(&addr) {
            Ok(x) => x,
            Err(err) => return -(err as RtFd),
        };
        posix::push_file(listener)
    } else {
        -(moto_rt::E_NOT_IMPLEMENTED as RtFd)
    }
}

pub extern "C" fn listen(rt_fd: RtFd, max_backlog: u32) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };
    let Some(listener) =
        (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_tcp::TcpListener>()
    else {
        return moto_rt::E_BAD_HANDLE;
    };

    match listener.listen(max_backlog) {
        Ok(()) => moto_rt::E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn accept(rt_fd: RtFd, peer_addr: *mut netc::sockaddr) -> RtFd {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return -(moto_rt::E_BAD_HANDLE as RtFd);
    };
    let Some(listener) =
        (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_tcp::TcpListener>()
    else {
        return -(moto_rt::E_BAD_HANDLE as RtFd);
    };

    let (stream, addr) = match listener.accept() {
        Ok(x) => x,
        Err(err) => return -(err as RtFd),
    };
    let stream = posix::push_file(stream);
    unsafe {
        *peer_addr = addr.into();
    }
    stream
}

pub extern "C" fn tcp_connect(
    addr: *const netc::sockaddr,
    timeout_ns: u64,
    nonblocking: bool,
) -> RtFd {
    let addr = unsafe { (*addr).into() };
    let timeout = if timeout_ns == u64::MAX {
        None
    } else {
        Some(Duration::from_nanos(timeout_ns))
    };
    let stream = match TcpStream::connect(&addr, timeout, nonblocking) {
        Ok(x) => x,
        Err(err) => return -(err as RtFd),
    };
    posix::push_file(stream)
}

pub unsafe extern "C" fn setsockopt(rt_fd: RtFd, option: u64, ptr: usize, len: usize) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };

    unsafe {
        if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpStream>() {
            tcp_stream.setsockopt(option, ptr, len)
        } else if let Some(tcp_listener) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_tcp::TcpListener>()
        {
            tcp_listener.setsockopt(option, ptr, len)
        } else if let Some(udp_socket) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_udp::UdpSocket>()
        {
            udp_socket.setsockopt(option, ptr, len)
        } else if option == moto_rt::net::SO_NONBLOCKING {
            assert_eq!(len, 1);
            let nonblocking = *(ptr as *const u8);
            if nonblocking > 1 {
                return moto_rt::E_INVALID_ARGUMENT;
            }

            match posix_file.set_nonblocking(nonblocking == 1) {
                Ok(_) => moto_rt::E_OK,
                Err(err) => err,
            }
        } else {
            moto_rt::E_BAD_HANDLE
        }
    }
}

pub unsafe extern "C" fn getsockopt(rt_fd: RtFd, option: u64, ptr: usize, len: usize) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };

    unsafe {
        if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpStream>() {
            tcp_stream.getsockopt(option, ptr, len)
        } else if let Some(tcp_listener) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_tcp::TcpListener>()
        {
            tcp_listener.getsockopt(option, ptr, len)
        } else if let Some(udp_socket) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_udp::UdpSocket>()
        {
            udp_socket.getsockopt(option, ptr, len)
        } else {
            moto_rt::E_BAD_HANDLE
        }
    }
}

pub extern "C" fn peek(rt_fd: i32, buf: *mut u8, buf_sz: usize) -> i64 {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return -(moto_rt::E_BAD_HANDLE as i64);
    };

    let buf = unsafe { core::slice::from_raw_parts_mut(buf, buf_sz) };

    if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpStream>() {
        match tcp_stream.peek(buf) {
            Ok(sz) => return sz as i64,
            Err(err) => return -(err as i64),
        }
    }

    if let Some(udp_socket) = (posix_file.as_ref() as &dyn Any).downcast_ref::<UdpSocket>() {
        match udp_socket.peek(buf) {
            Ok(sz) => return sz as i64,
            Err(err) => return -(err as i64),
        }
    }

    -(moto_rt::E_BAD_HANDLE as i64)
}

pub unsafe extern "C" fn socket_addr(rt_fd: RtFd, addr: *mut netc::sockaddr) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };

    unsafe {
        if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpStream>() {
            if let Some(socket_addr) = tcp_stream.socket_addr() {
                *addr = (socket_addr).into();
                return moto_rt::E_OK;
            }
            return moto_rt::E_INVALID_ARGUMENT;
        };
        if let Some(udp_socket) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_udp::UdpSocket>()
        {
            *addr = (*udp_socket.local_addr()).into();
            return moto_rt::E_OK;
        };
        if let Some(tcp_listener) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_tcp::TcpListener>()
        {
            *addr = (*tcp_listener.socket_addr()).into();
            return moto_rt::E_OK;
        };
    }

    moto_rt::E_BAD_HANDLE
}

pub unsafe extern "C" fn peer_addr(rt_fd: RtFd, addr: *mut netc::sockaddr) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };

    unsafe {
        if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpStream>() {
            match tcp_stream.peer_addr() {
                Ok(peer_addr) => {
                    *addr = peer_addr.into();
                    return moto_rt::E_OK;
                }
                Err(err) => return err,
            }
        }
        if let Some(udp_socket) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_udp::UdpSocket>()
        {
            match udp_socket.peer_addr() {
                Some(peer_addr) => {
                    *addr = peer_addr.into();
                    return moto_rt::E_OK;
                }
                None => return moto_rt::E_NOT_CONNECTED,
            }
        };
    }

    moto_rt::E_BAD_HANDLE
}

pub unsafe extern "C" fn udp_recv_from(
    rt_fd: RtFd,
    buf: *mut u8,
    buf_sz: usize,
    addr: *mut netc::sockaddr,
) -> i64 {
    unsafe { udp_recv_or_peek_from(rt_fd, buf, buf_sz, addr, false) }
}

pub unsafe extern "C" fn udp_peek_from(
    rt_fd: RtFd,
    buf: *mut u8,
    buf_sz: usize,
    addr: *mut netc::sockaddr,
) -> i64 {
    unsafe { udp_recv_or_peek_from(rt_fd, buf, buf_sz, addr, true) }
}

unsafe fn udp_recv_or_peek_from(
    rt_fd: RtFd,
    buf: *mut u8,
    buf_sz: usize,
    addr: *mut netc::sockaddr,
    peek: bool,
) -> i64 {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return -(moto_rt::E_BAD_HANDLE as i64);
    };
    let Some(udp_socket) =
        (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_udp::UdpSocket>()
    else {
        return -(moto_rt::E_BAD_HANDLE as i64);
    };

    let buf = unsafe { core::slice::from_raw_parts_mut(buf, buf_sz) };
    match udp_socket.recv_or_peek_from(buf, peek) {
        Ok((sz, from)) => {
            unsafe { *addr = from.into() };
            sz as i64
        }
        Err(err) => -(err as i64),
    }
}

pub unsafe extern "C" fn udp_send_to(
    rt_fd: RtFd,
    buf: *const u8,
    buf_sz: usize,
    addr: *const netc::sockaddr,
) -> i64 {
    let addr = unsafe { (*addr).into() };
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return -(moto_rt::E_BAD_HANDLE as i64);
    };
    let Some(udp_socket) =
        (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_udp::UdpSocket>()
    else {
        return -(moto_rt::E_BAD_HANDLE as i64);
    };

    let buf = unsafe { core::slice::from_raw_parts(buf, buf_sz) };
    match udp_socket.send_to(buf, &addr) {
        Ok(sz) => sz as i64,
        Err(err) => -(err as i64),
    }
}

pub unsafe extern "C" fn udp_connect(rt_fd: RtFd, addr: *const netc::sockaddr) -> ErrorCode {
    let addr = unsafe { (*addr).into() };
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };
    let Some(udp_socket) =
        (posix_file.as_ref() as &dyn Any).downcast_ref::<super::rt_udp::UdpSocket>()
    else {
        return moto_rt::E_BAD_HANDLE;
    };

    udp_socket.connect(&addr);
    moto_rt::E_OK
}

#[allow(unused)]
pub fn vdso_internal_helper(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    match a1 {
        #[cfg(feature = "netdev")]
        0 => {
            // Give stage-E teardown a moment to settle before the leak check;
            // the wait is a veneer (caller-thread) concern, kept out of the
            // moving channel layer.
            crate::rt_thread::sleep(
                (moto_rt::time::Instant::now() + core::time::Duration::from_millis(500)).as_u64(),
            );
            super::channel::assert_runtime_empty();
        }
        _ => panic!("Unrecognized option {a1}"),
    }

    0
}
