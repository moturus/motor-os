//! The vdso net veneer: the C-ABI shims std/mio call through (bind, listen,
//! accept, connect, the socket options, DNS), plus the netdev-gated internal
//! helper. Everything here is caller-thread glue over the moto-io net stack
//! (`moto_io::net::{tcp, udp, channel}`); it installs the concrete
//! `EventSourceManaged` listener and downcasts posix files from the FD table
//! back to the `Rt*` wrapper that owns each descriptor.

use crate::posix;
use crate::posix::PosixFile;
use crate::runtime::EventSourceManaged;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::time::Duration;
use moto_rt::RtFd;
use moto_rt::netc;
use moto_sys::ErrorCode;

use crate::net::rt_tcp::RtTcpListener;
use crate::net::rt_tcp::RtTcpStream;
use crate::net::rt_udp::RtUdpSocket;
use moto_io::net::tcp::TcpStream;

/// Build the poll-registry event source a socket emits its readiness through.
/// The vdso owns this choice (the concrete `EventSourceManaged` is a vdso
/// type); the socket state machine only ever sees it as an opaque
/// `Arc<dyn NetEventListener>`, so it names no vdso type. A TCP listener
/// never becomes writable, but a mio test expects a successful WRITABLE
/// interest registration, so the mask includes WRITABLE for every socket:
/// https://github.com/tokio-rs/mio/blob/9a9d691891d5f7d91c7493b65d0b80726699faa8/tests/poll.rs#L56
///
/// Returns the concrete source, not the trait object: a wrapper keeps it to
/// register interests through, and passes a clone down as the listener.
fn new_event_source() -> Arc<EventSourceManaged> {
    Arc::new(EventSourceManaged::new(
        moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_WRITABLE,
    ))
}

/// Reserve one socket slot from the vDSO pool, blocking the caller thread
/// (vdso streams, UDP sockets, and listeners all live on pool-owned
/// channels). Blocking on provisioning matches the deleted compatibility
/// pool -- it created channels under its global lock -- but the connect
/// retries now sleep on the channel's
/// own runtime thread instead of the caller's.
fn reserve_slot() -> Result<moto_io::net::Reservation, ErrorCode> {
    moto_async::block_on_sync(crate::net::pool::NET_POOL.reserve()).map_err(ErrorCode::from)
}

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
    if host_bytes.is_null() || host_bytes_sz == 0 || host_bytes_sz > moto_dns::MAX_NAME_LEN {
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
        let reservation = match reserve_slot() {
            Ok(r) => r,
            Err(err) => return -(err as RtFd),
        };
        let events = new_event_source();
        let udp_socket = match moto_async::block_on_sync(
            moto_io::net::udp::UdpSocket::bind_reserved(reservation, &addr, Some(events.clone())),
        ) {
            Ok(x) => x,
            Err(err) => return -(err as RtFd),
        };
        posix::push_file(RtUdpSocket::new(udp_socket, events))
    } else if proto == moto_rt::net::PROTO_UDP_FOR_REMOTE {
        let addr = unsafe { (*addr).into() };
        let reservation = match reserve_slot() {
            Ok(r) => r,
            Err(err) => return -(err as RtFd),
        };
        let events = new_event_source();
        let udp_socket =
            match moto_async::block_on_sync(moto_io::net::udp::UdpSocket::bind_for_remote_reserved(
                reservation,
                &addr,
                Some(events.clone()),
            )) {
                Ok(socket) => socket,
                Err(err) => return -(err as RtFd),
            };
        posix::push_file(RtUdpSocket::new(udp_socket, events))
    } else if proto == moto_rt::net::PROTO_TCP {
        let addr = unsafe { (*addr).into() };
        let reservation = match reserve_slot() {
            Ok(r) => r,
            Err(err) => return -(err as RtFd),
        };
        let events = new_event_source();
        let observer = crate::net::rt_tcp::ListenerEvents::new(events.clone());
        let listener =
            match moto_async::block_on_sync(moto_io::net::tcp::TcpListener::bind_reserved(
                reservation,
                &addr,
                Some(observer.clone()),
                None,
            )) {
                Ok(x) => x,
                Err(err) => return -(err as RtFd),
            };
        // The pump needs the bound listener; the observer needed to exist
        // first. No completion can beat `set_pump`: completions follow
        // donations, and donations follow the pump.
        let pump = crate::net::accept_pump::AcceptPump::new(
            &crate::net::pool::NET_POOL,
            Arc::downgrade(&listener),
        );
        observer.set_pump(pump.clone());
        {
            let pump = pump.clone();
            crate::io_runtime::spawn(move || pump.run());
        }
        posix::push_file(RtTcpListener::new(listener, events, pump))
    } else {
        -(moto_rt::E_NOT_IMPLEMENTED as RtFd)
    }
}

pub extern "C" fn listen(rt_fd: RtFd, max_backlog: u32) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };
    let Some(listener) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtTcpListener>() else {
        return moto_rt::E_BAD_HANDLE;
    };

    listener.listen(max_backlog)
}

pub extern "C" fn accept(rt_fd: RtFd, peer_addr: *mut netc::sockaddr) -> RtFd {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return -(moto_rt::E_BAD_HANDLE as RtFd);
    };
    let Some(listener) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtTcpListener>() else {
        return -(moto_rt::E_BAD_HANDLE as RtFd);
    };

    // Blocking is the vdso's job: a native user awaits `accept()` on its
    // own executor. O_NONBLOCK takes the try path, and the accepted stream
    // inherits the flag -- a deliberate, decided divergence from
    // std-on-Linux (where an accepted socket starts blocking regardless of
    // the listener): Motor has no accept4(SOCK_NONBLOCK), so mio marks only
    // the listener and relies on inheritance to get nonblocking streams
    // back. Both descriptors' flags are the wrappers', so this whole copy
    // is a veneer concern.
    let nonblocking = listener.is_nonblocking();
    let accepted = if nonblocking {
        listener.inner().try_accept_observed(&new_event_source)
    } else {
        // A blocking accept donates its own slot -- the pool path posted a
        // request per parked caller, and a host-owned listener with no
        // donation outstanding parks its callers forever (decision 2).
        match reserve_slot() {
            Ok(reservation) => listener.inner().post_accept(reservation),
            Err(err) => return -(err as RtFd),
        }
        moto_async::block_on_sync(listener.inner().accept_observed(&new_event_source))
    };
    // A returned accept -- either variant, either outcome -- may have
    // consumed a queued connection or a donation; let the pump recompute.
    listener.pump().poke();
    let (stream, events, addr) = match accepted {
        Ok(x) => x,
        Err(err) => return -(err as RtFd),
    };
    let stream = posix::push_file(RtTcpStream::new(stream, events, nonblocking));
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
    // The blocking wait is the vdso's; a native user awaits `connect()`.
    // Both variants reserve first: a nonblocking connect defers the TCP
    // handshake, not the channel slot the stream lives on.
    let reservation = match reserve_slot() {
        Ok(r) => r,
        Err(err) => return -(err as RtFd),
    };
    let events = new_event_source();
    let connected = if nonblocking {
        TcpStream::connect_nonblocking_reserved(reservation, &addr, timeout, Some(events.clone()))
    } else {
        moto_async::block_on_sync(TcpStream::connect_reserved(
            reservation,
            &addr,
            timeout,
            Some(events.clone()),
            None,
        ))
    };
    let stream = match connected {
        Ok(x) => x,
        Err(err) => return -(err as RtFd),
    };
    posix::push_file(RtTcpStream::new(stream, events, nonblocking))
}

pub unsafe extern "C" fn setsockopt(rt_fd: RtFd, option: u64, ptr: usize, len: usize) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };

    unsafe {
        // The native option calls are futures; `ptr` outlives them because
        // this bridge drives each one to completion before returning.
        if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtTcpStream>() {
            tcp_stream.setsockopt(option, ptr, len)
        } else if let Some(tcp_listener) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<RtTcpListener>()
        {
            tcp_listener.setsockopt(option, ptr, len)
        } else if let Some(udp_socket) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<RtUdpSocket>()
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
        if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtTcpStream>() {
            tcp_stream.getsockopt(option, ptr, len)
        } else if let Some(tcp_listener) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<RtTcpListener>()
        {
            tcp_listener.getsockopt(option, ptr, len)
        } else if let Some(udp_socket) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<RtUdpSocket>()
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

    if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtTcpStream>() {
        match crate::net::blocking::tcp_peek(tcp_stream, buf) {
            Ok(sz) => return sz as i64,
            Err(err) => return -(err as i64),
        }
    }

    if let Some(udp_socket) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtUdpSocket>() {
        match crate::net::blocking::udp_recv(udp_socket, buf, true) {
            Ok((sz, _)) => return sz as i64,
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
        if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtTcpStream>() {
            if let Some(socket_addr) = tcp_stream.inner().socket_addr() {
                *addr = (socket_addr).into();
                return moto_rt::E_OK;
            }
            return moto_rt::E_INVALID_ARGUMENT;
        };
        if let Some(udp_socket) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtUdpSocket>() {
            *addr = (*udp_socket.inner().local_addr()).into();
            return moto_rt::E_OK;
        };
        if let Some(tcp_listener) =
            (posix_file.as_ref() as &dyn Any).downcast_ref::<RtTcpListener>()
        {
            *addr = (*tcp_listener.inner().socket_addr()).into();
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
        if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtTcpStream>() {
            match tcp_stream.inner().peer_addr() {
                Ok(peer_addr) => {
                    *addr = peer_addr.into();
                    return moto_rt::E_OK;
                }
                Err(err) => return err,
            }
        }
        if let Some(udp_socket) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtUdpSocket>() {
            match udp_socket.inner().peer_addr() {
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
    let Some(udp_socket) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtUdpSocket>() else {
        return -(moto_rt::E_BAD_HANDLE as i64);
    };

    let buf = unsafe { core::slice::from_raw_parts_mut(buf, buf_sz) };
    match crate::net::blocking::udp_recv(udp_socket, buf, peek) {
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
    let Some(udp_socket) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtUdpSocket>() else {
        return -(moto_rt::E_BAD_HANDLE as i64);
    };

    let buf = unsafe { core::slice::from_raw_parts(buf, buf_sz) };
    match crate::net::blocking::udp_send(udp_socket, buf, &addr) {
        Ok(sz) => sz as i64,
        Err(err) => -(err as i64),
    }
}

pub unsafe extern "C" fn udp_connect(rt_fd: RtFd, addr: *const netc::sockaddr) -> ErrorCode {
    let addr = unsafe { (*addr).into() };
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return moto_rt::E_BAD_HANDLE;
    };
    let Some(udp_socket) = (posix_file.as_ref() as &dyn Any).downcast_ref::<RtUdpSocket>() else {
        return moto_rt::E_BAD_HANDLE;
    };

    udp_socket.inner().connect(&addr);
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
            moto_io::net::channel::assert_runtime_empty();
            crate::net::pool::NET_POOL.assert_empty();
        }
        #[cfg(feature = "netdev")]
        1 => return crate::net::pool::NET_POOL.client_count() as u64,
        #[cfg(feature = "netdev")]
        2 => moto_io::net::channel::poison_connect_for_test(a2 != 0),
        _ => panic!("Unrecognized option {a1}"),
    }

    0
}
