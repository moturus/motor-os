use crate::posix;
use crate::posix::PosixFile;
use crate::runtime::EventSourceManaged;
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::any::Any;
use core::net::SocketAddr;
use core::sync::atomic::*;
use core::time::Duration;
use crossbeam::utils::CachePadded;
use moto_ipc::io_channel;
use moto_rt::RtFd;
use moto_rt::moto_log;
use moto_rt::mutex::Mutex;
use moto_rt::netc;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_rt::time::Instant;
use moto_sys::ErrorCode;
use moto_sys::SysHandle;
use moto_sys_io::api_net;
use moto_sys_io::api_net::IO_SUBCHANNELS;
use moto_sys_io::api_net::TcpState;

use super::rt_tcp::TcpListener;
use super::rt_tcp::TcpStream;
use super::rt_udp::UdpSocket;

pub unsafe extern "C" fn dns_lookup(
    host_bytes: *const u8,
    host_bytes_sz: usize,
    port: u16,
    result_addr: *mut usize,
    result_len: *mut usize,
) -> ErrorCode {
    use core::net::Ipv4Addr;
    use core::net::SocketAddrV4;
    use core::str::FromStr;
    use moto_rt::netc;

    unsafe {
        let host: &str = core::str::from_raw_parts(host_bytes, host_bytes_sz);

        let addr = if host == "localhost" {
            SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)
        } else if let Ok(addr_v4) = Ipv4Addr::from_str(host) {
            SocketAddrV4::new(addr_v4, port)
        } else {
            crate::moto_log!("dns_lookup: {}:{}: not implemented", host, port);
            return moto_rt::E_NOT_IMPLEMENTED;
        };

        let res_addr = crate::rt_alloc::alloc(core::mem::size_of::<netc::sockaddr>() as u64, 16);
        let result: &mut [netc::sockaddr] =
            core::slice::from_raw_parts_mut(res_addr as usize as *mut netc::sockaddr, 1);

        let addr = netc::sockaddr { v4: addr.into() };
        result[0] = addr;
        *result_addr = res_addr as usize;
        *result_len = 1;
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
        0 => NET.lock().assert_empty(),
        _ => panic!("Unrecognized option {a1}"),
    }

    0
}

// -------------------------------- implementation details ------------------------------ //

// Note: we have an IO thread per net channel instead of a single IO thread:
// - simpler/easier to code here: no need to "schedule" between channels
// - will scale better in the future when the driver side is also multithreaded
// - the usually assumed negatives are not necessarily as bad in Motor OS
//   as in e.g. Linux:
//   - threads are "lighter", i.e. they consume less memory
//   - thread scheduling is potentially better, as Motor OS is designed
//     for the cloud use case vs a general purpose thingy, whatever that is,
//     that Linux targets.
//
// Note: there are several fence(SeqCst) below that appear unneeded. However,
//       without them (at least some of them; all permutations haven't been tested)
//       weird things happens that are not happening with them, related to
//       memory on stack. Maybe there is a bug in _this_ code that these fences
//       hide, or maybe the compiler is too aggressive (the compiler is not
//       aware of cross-process shared memory, for example). Anyway, the code
//       below is somewhat fragile and probably has to be refactored (again)
//       for performance and robustness.
//
// Note: some or all of the above may be outdated.

pub trait ResponseHandler {
    fn on_response(&self, resp: io_channel::Msg);
}

static NET: Mutex<NetRuntime> = Mutex::new(NetRuntime {
    full_channels: BTreeMap::new(),
    channels: BTreeMap::new(),

    #[cfg(feature = "netdev")]
    num_tcp_listeners: AtomicU64::new(0),
    #[cfg(feature = "netdev")]
    num_tcp_streams: AtomicU64::new(0),
    #[cfg(feature = "netdev")]
    num_udp_sockets: AtomicU64::new(0),
});

pub fn stats_tcp_listener_created() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_listeners.fetch_add(1, Ordering::Relaxed);
}

pub fn stats_tcp_listener_dropped() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_listeners.fetch_sub(1, Ordering::Relaxed);
}

pub fn stats_tcp_stream_created() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_streams.fetch_add(1, Ordering::Relaxed);
}

pub fn stats_tcp_stream_dropped() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_streams.fetch_sub(1, Ordering::Relaxed);
}

pub fn stats_udp_socket_created() {
    #[cfg(feature = "netdev")]
    NET.lock().num_udp_sockets.fetch_add(1, Ordering::Relaxed);
}

pub fn stats_udp_socket_dropped() {
    #[cfg(feature = "netdev")]
    NET.lock().num_udp_sockets.fetch_sub(1, Ordering::Relaxed);
}

struct NetRuntime {
    // Channels at capacity. We need sets, but this is rustc-dep-of-std, and our options are limited.
    full_channels: BTreeMap<u64, Arc<NetChannel>>,
    // Channels that can accommodate more sockets.
    channels: BTreeMap<u64, Arc<NetChannel>>,

    #[cfg(feature = "netdev")]
    num_tcp_listeners: AtomicU64,
    #[cfg(feature = "netdev")]
    num_tcp_streams: AtomicU64,
    #[cfg(feature = "netdev")]
    num_udp_sockets: AtomicU64,
}

impl NetRuntime {
    #[cfg(feature = "netdev")]
    fn assert_empty(&self) {
        crate::rt_thread::sleep(
            (moto_rt::time::Instant::now() + core::time::Duration::from_millis(500)).as_u64(),
        );
        assert_eq!(0, self.num_tcp_listeners.load(Ordering::Acquire));
        assert_eq!(0, self.num_tcp_streams.load(Ordering::Acquire));
        assert!(self.full_channels.is_empty());
        for channel in self.channels.values() {
            channel.assert_empty();
        }
    }

    fn reserve_channel(&mut self) -> ChannelReservation {
        if let Some(entry) = self.channels.first_entry() {
            let channel = entry.get().clone();
            let reservations = 1 + channel.reservations.fetch_add(1, Ordering::Relaxed);
            if reservations == IO_SUBCHANNELS {
                self.channels.remove(&channel.id());
                self.full_channels.insert(channel.id(), channel.clone());
            }

            ChannelReservation {
                channel,
                subchannel_idx: None,
            }
        } else {
            let channel = NetChannel::new();
            channel.reservations.fetch_add(1, Ordering::Relaxed);
            self.channels.insert(channel.id(), channel.clone());
            ChannelReservation {
                channel,
                subchannel_idx: None,
            }
        }
    }

    fn release_channel_reservation(&mut self, channel: &NetChannel) {
        channel.reservations.fetch_sub(1, Ordering::Relaxed);
        if let Some(channel) = self.full_channels.remove(&channel.id()) {
            // TODO: maybe clear empty channels?
            self.channels.insert(channel.id(), channel);
        }

        // moto_log!("{}:{} drop empty channels", file!(), line!());
    }
}

/// A communication channel between the current process and sys-io.
///
/// Each channel has a dedicated io_thread.
///
/// Each ~socket~ has a dedicated "subchannel", so that sockets don't interfere
/// with each other.
pub struct NetChannel {
    conn: io_channel::ClientConnection,
    reservations: AtomicU8,

    subchannels_in_use: Vec<AtomicBool>,

    // TODO: we will only have at most IO_SUBCHANNELS streams per connection. Maybe
    //       we should get rid of spinlocks below and have simple vectors?
    //
    // We use weak references to TcpStream below because ultimately the user
    // owns tcp streams, and we want to clear things away when the user drops them.
    tcp_streams: Mutex<BTreeMap<u64, Weak<TcpStream>>>,
    tcp_listeners: Mutex<BTreeMap<u64, Weak<TcpListener>>>,
    udp_sockets: Mutex<BTreeMap<u64, Weak<UdpSocket>>>,

    next_msg_id: CachePadded<AtomicU64>, // A counter.

    // This is a multi-producer, single-consumer queue.
    send_queue: crossbeam_queue::ArrayQueue<io_channel::Msg>,

    // Threads waiting to add their msg to send_queue.
    send_waiters: Mutex<VecDeque<u64>>,

    // Streams waiting for "can write" notification.
    write_waiters: Mutex<VecDeque<Weak<TcpStream>>>,

    // Threads waiting for specific resp_id: map resp_id => (thread handle, resp).
    legacy_resp_waiters: Mutex<BTreeMap<u64, (SysHandle, Option<io_channel::Msg>)>>,
    response_handlers: Mutex<BTreeMap<u64, Weak<dyn ResponseHandler + Send + Sync>>>,

    io_thread_join_handle: AtomicU64,
    io_thread_wake_handle: AtomicU64,

    io_thread_running: CachePadded<AtomicBool>,
    io_thread_wake_requested: CachePadded<AtomicBool>,
    exiting: CachePadded<AtomicBool>,
}

impl Drop for NetChannel {
    fn drop(&mut self) {
        self.exiting.store(true, Ordering::Release);
        self.assert_empty();
        todo!("wait for the IO thread to finish")
    }
}

impl NetChannel {
    fn id(&self) -> u64 {
        self.conn.server_handle().into()
    }

    fn assert_empty(&self) {
        assert_eq!(0, self.reservations.load(Ordering::Relaxed));
        self.conn.assert_empty();

        for sub in &self.subchannels_in_use {
            assert!(!sub.load(Ordering::Relaxed));
        }
    }

    fn io_thread(&self) -> ! {
        let mut maybe_msg = None;
        loop {
            self.io_thread_running.store(true, Ordering::Release);
            let mut should_sleep = self.io_thread_poll_messages();
            let (sleep, msg) = self.io_thread_send_messages(maybe_msg);
            maybe_msg = msg;
            should_sleep &= sleep;

            if !self.send_queue.is_full() {
                // Take waiters because maybe_can_write() may push into write_waiters.
                let mut waiters = VecDeque::new();
                core::mem::swap(&mut waiters, &mut *self.write_waiters.lock());
                for waiter in waiters {
                    if let Some(waiter) = waiter.upgrade() {
                        waiter.maybe_can_write();
                    }
                }
            } else {
                self.wake_driver();
            }

            if should_sleep {
                assert!(maybe_msg.is_none());

                // We do the complicated dance with two atomics and send waiters below
                // because we don't want to syscall wake in every maybe_wake_io_thread().
                if self.io_thread_wake_requested.swap(false, Ordering::SeqCst) {
                    continue;
                }
                self.io_thread_running.store(false, Ordering::Release);
                if self.io_thread_wake_requested.swap(false, Ordering::SeqCst) {
                    continue;
                }
                let waiter = { self.send_waiters.lock().pop_front() };
                if let Some(waiter) = waiter {
                    self.io_thread_running.store(true, Ordering::Release);
                    let _ = moto_sys::SysCpu::wake(SysHandle::from(waiter));
                    continue;
                }
                if self.io_thread_wake_requested.swap(false, Ordering::SeqCst) {
                    continue;
                }

                self.wake_driver(); // TODO: be smarter.

                let _ = moto_sys::SysCpu::wait(
                    &mut [self.conn.server_handle()],
                    SysHandle::NONE,
                    SysHandle::NONE,
                    None,
                );
            }
        }
    }

    // Poll messages, if any. Returns true if the IO thread may sleep.
    fn io_thread_poll_messages(&self) -> bool {
        let mut received_messages = 0;

        while let Ok(msg) = self.conn.recv() {
            fence(Ordering::SeqCst);
            received_messages += 1;

            #[cfg(debug_assertions)]
            crate::moto_log!(
                "{}:{} got msg {}:0x{:x}:{}",
                file!(),
                line!(),
                msg.id,
                msg.handle,
                msg.command
            );

            let cmd = api_net::NetCmd::try_from(msg.command).unwrap();

            let wait_handle: SysHandle = if msg.id == 0 {
                if cmd.is_udp() {
                    self.on_udp_msg(msg);
                    continue;
                }

                // This is an incoming packet, or similar, without a dedicated waiter.
                let stream_handle = msg.handle;
                let stream = {
                    let mut tcp_streams = self.tcp_streams.lock();
                    if let Some(stream) = tcp_streams.get_mut(&stream_handle) {
                        stream.upgrade()
                    } else {
                        // No stream for the packet. But it is possible that there is a pending
                        // accept for the stream, so we must not just drop the packet in
                        // on_orphan_message() below. And we should check the pending accept queues
                        // while holding the tcp streams lock, otherwise we could race with
                        // the accept converting into a stream...
                        let mut tcp_listeners = self.tcp_listeners.lock();
                        for listener in tcp_listeners.values() {
                            if let Some(listener) = listener.upgrade()
                                && listener.add_to_pending_queue(msg)
                            {
                                continue;
                            }
                        }
                        None
                    }
                };
                if let Some(stream) = stream {
                    // Note: we must hold the lock while processing the message, otherwise the wait handle might get updated
                    //       and we will lose the wakeup. Sad story, don't ask...
                    stream.process_incoming_msg(msg)
                } else {
                    self.on_orphan_message(msg);
                    SysHandle::NONE
                }
            } else {
                // These are synchronous req/resp messages.
                let mut resp_waiters = self.legacy_resp_waiters.lock();
                if let Some((handle, resp)) = resp_waiters.get_mut(&msg.id) {
                    *resp = Some(msg);
                    *handle
                } else {
                    core::mem::drop(resp_waiters);
                    let Some(resp_handler) = self.response_handlers.lock().remove(&msg.id) else {
                        panic!("unexpected msg");
                    };
                    if let Some(handler) = resp_handler.upgrade() {
                        handler.on_response(msg);
                    }
                    SysHandle::NONE
                }
            };

            if wait_handle != SysHandle::NONE
                && wait_handle.as_u64() != moto_sys::UserThreadControlBlock::get().self_handle
            {
                let _ = moto_sys::SysCpu::wake(wait_handle);
            }

            if received_messages > 32 {
                return false;
            }
        }

        true
    }

    fn on_udp_msg(&self, msg: io_channel::Msg) {
        assert_eq!(0, msg.id); // UDP is now always async.

        let socket: Option<Arc<UdpSocket>> = self
            .udp_sockets
            .lock()
            .get_mut(&msg.handle)
            .and_then(|s| s.upgrade());

        if let Some(udp_socket) = socket {
            udp_socket.process_incoming_msg(msg);
        } else {
            self.on_orphan_message(msg);
        }
    }

    // Attempts to send some messages. Returns true if the io thread may sleep.
    fn io_thread_send_messages(
        &self,
        msg: Option<io_channel::Msg>,
    ) -> (bool, Option<io_channel::Msg>) {
        let mut sent_messages = 0;
        if let Some(msg) = msg {
            fence(Ordering::SeqCst);
            if let Err(err) = self.conn.send(msg) {
                assert_eq!(err, moto_rt::Error::NotReady);
                self.wake_driver();
                return (false, Some(msg));
            }
            sent_messages += 1;
        }

        while let Some(msg) = self.send_queue.pop() {
            fence(Ordering::SeqCst);
            if let Err(err) = self.conn.send(msg) {
                assert_eq!(err, moto_rt::Error::NotReady);
                self.wake_driver();
                return (false, Some(msg));
            }

            sent_messages += 1;
            if sent_messages > 32 {
                self.wake_driver();
                return (false, None);
            }
        }

        if sent_messages > 0 {
            self.wake_driver();
        }
        (true, None)
    }

    pub fn add_write_waiter(&self, stream: &TcpStream) {
        self.write_waiters.lock().push_back(stream.weak());
    }

    pub fn maybe_wake_io_thread(&self) {
        self.io_thread_wake_requested.store(true, Ordering::Release);
        if self.io_thread_running.load(Ordering::SeqCst) {
            return;
        }

        let _ = moto_sys::SysCpu::wake(self.io_thread_wake_handle.load(Ordering::Relaxed).into());
    }

    extern "C" fn io_thread_init(self_addr: usize) {
        // We extract a raw reference from Arc<Self> so that refcounting works and Self::drop()
        // gets triggered.
        let self_: &'static Self = unsafe {
            let self_arc = Arc::from_raw(self_addr as *const Self);
            let self_ptr = Arc::as_ptr(&self_arc);
            &*self_ptr
        };

        self_.io_thread_wake_handle.store(
            moto_sys::UserThreadControlBlock::get().self_handle,
            Ordering::Release,
        );

        moto_sys::set_current_thread_name("rt_net::io_thread").unwrap();

        self_.io_thread();
    }

    fn new() -> Arc<Self> {
        let mut subchannels_in_use = Vec::with_capacity(IO_SUBCHANNELS as usize);
        for _ in 0..IO_SUBCHANNELS {
            subchannels_in_use.push(AtomicBool::new(false));
        }

        let self_ = Arc::new(NetChannel {
            conn: io_channel::ClientConnection::connect("sys-io").unwrap(),
            subchannels_in_use,
            tcp_streams: Mutex::new(BTreeMap::new()),
            tcp_listeners: Mutex::new(BTreeMap::new()),
            udp_sockets: Mutex::new(BTreeMap::new()),
            reservations: AtomicU8::new(0),
            next_msg_id: CachePadded::new(AtomicU64::new(1)),
            send_queue: crossbeam_queue::ArrayQueue::new(io_channel::CHANNEL_PAGE_COUNT),
            send_waiters: Mutex::new(VecDeque::new()),
            write_waiters: Mutex::new(VecDeque::new()),
            legacy_resp_waiters: Mutex::new(BTreeMap::new()),
            response_handlers: Mutex::new(BTreeMap::new()),
            io_thread_join_handle: AtomicU64::new(SysHandle::NONE.into()),
            io_thread_wake_handle: AtomicU64::new(SysHandle::NONE.into()),
            io_thread_running: CachePadded::new(AtomicBool::new(false)),
            io_thread_wake_requested: CachePadded::new(AtomicBool::new(false)),
            exiting: CachePadded::new(AtomicBool::new(false)),
        });

        let self_ptr = Arc::into_raw(self_.clone());
        let thread_handle = moto_sys::SysCpu::spawn(
            SysHandle::SELF,
            4096 * 16,
            Self::io_thread_init as *const () as usize as u64,
            self_ptr as usize as u64,
        )
        .unwrap();
        self_
            .io_thread_join_handle
            .store(thread_handle.into(), Ordering::Release);

        while self_.io_thread_wake_handle.load(Ordering::Acquire) == 0 {
            core::hint::spin_loop()
        }

        self_
    }

    /// Returns the index of the subchannel in [0..IO_SUBCHANNELS).
    fn reserve_subchannel_impl(&self) -> u8 {
        for idx in 0..IO_SUBCHANNELS {
            if self.subchannels_in_use[idx as usize].swap(true, Ordering::AcqRel) {
                continue; // Was already reserved.
            }
            return idx;
        }
        panic!("Failed to reserve IO subchannel.")
    }

    fn release_subchannel(&self, idx: u8) {
        assert!(idx < IO_SUBCHANNELS);
        assert!(self.subchannels_in_use[idx as usize].swap(false, Ordering::AcqRel));
    }

    pub fn tcp_stream_created(&self, stream: &TcpStream) {
        assert!(
            self.tcp_streams
                .lock()
                .insert(stream.handle(), stream.weak())
                .is_none()
        );
    }

    pub fn udp_socket_created(&self, socket: &UdpSocket) {
        assert!(
            self.udp_sockets
                .lock()
                .insert(socket.handle(), socket.weak())
                .is_none()
        );
    }

    pub fn tcp_stream_dropped(&self, handle: u64) {
        let stream = self.tcp_streams.lock().remove(&handle).unwrap();
        assert_eq!(0, stream.strong_count());
    }

    pub fn tcp_listener_created(&self, listener: &Arc<super::rt_tcp::TcpListener>) {
        self.tcp_listeners
            .lock()
            .insert(listener.handle(), Arc::downgrade(listener));
    }

    pub fn tcp_listener_dropped(&self, handle: u64) {
        assert_eq!(
            0,
            self.tcp_listeners
                .lock()
                .remove(&handle)
                .unwrap()
                .strong_count()
        );
    }

    pub fn send_msg(&self, msg: io_channel::Msg) {
        loop {
            if self.send_queue.push(msg).is_ok() {
                self.maybe_wake_io_thread();
                return;
            }

            self.send_waiters
                .lock()
                .push_back(moto_sys::UserThreadControlBlock::this_thread_handle().into());
            self.maybe_wake_io_thread();
            let _ = moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, None);
        }
    }

    fn wait_for_resp(&self, resp_id: u64) -> io_channel::Msg {
        loop {
            {
                let mut recv_waiters = self.legacy_resp_waiters.lock();
                if let Some(resp) = recv_waiters.get_mut(&resp_id).unwrap().1.take() {
                    recv_waiters.remove(&resp_id);
                    return resp;
                }
            }

            // No need to wake the IO thread, as it will be woken by sys-io.
            let _ = moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, None);
        }
    }

    // Send message and wait for response.
    pub fn send_receive(&self, mut req: io_channel::Msg) -> io_channel::Msg {
        let req_id = self.next_msg_id.fetch_add(1, Ordering::Relaxed);

        // Add to waiters before sending the message, otherwise the response may
        // arive too quickly and the receiving code will panic due to a missing waiter.
        self.legacy_resp_waiters.lock().insert(
            req_id,
            (
                moto_sys::UserThreadControlBlock::get().self_handle.into(),
                None,
            ),
        );

        req.id = req_id;
        self.send_msg(req);
        self.wait_for_resp(req_id)
    }

    pub fn new_req_id(&self) -> u64 {
        self.next_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn post_msg(&self, req: io_channel::Msg) -> Result<(), io_channel::Msg> {
        if self.send_queue.push(req).is_ok() {
            self.maybe_wake_io_thread();
            Ok(())
        } else {
            Err(req)
        }
    }

    pub fn post_msg_with_response_waiter(
        &self,
        req: io_channel::Msg,
        handler: Weak<dyn ResponseHandler + Send + Sync>,
    ) -> Result<(), ErrorCode> {
        assert_ne!(0, req.id);

        // Add to response handlers before sending the message, otherwise the response may
        // arive too quickly and the receiving code will panic due to a missing waiter.
        assert!(
            self.response_handlers
                .lock()
                .insert(req.id, handler)
                .is_none()
        );

        if self.send_queue.push(req).is_ok() {
            self.maybe_wake_io_thread();
            Ok(())
        } else {
            Err(moto_rt::E_NOT_READY)
        }
    }

    // Note: this is called from the IO thread, so must not sleep/block.
    fn on_orphan_message(&self, msg: io_channel::Msg) {
        /*
        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} orphan incoming message {:?} for 0x{:x}",
            file!(),
            line!(),
            api_net::NetCmd::try_from(msg.command).unwrap(),
            msg.handle
        );
        */
        let Ok(cmd) = api_net::NetCmd::try_from(msg.command) else {
            // This is logged always because if a new incoming message is added that
            // has to be handled but is not, we may have a problem.
            moto_log!(
                "{}:{} orphan incoming message {} for 0x{:x}; release i/o page?",
                file!(),
                line!(),
                msg.command,
                msg.handle
            );
            return;
        };

        match cmd {
            api_net::NetCmd::TcpStreamRx => {
                // RX raced with the client dropping the sream. Need to get page to free it.
                let sz_read = msg.payload.args_64()[1];
                assert_ne!(0, sz_read);
                // crate::moto_log!("orphan RX");
                // Get the page so that it is properly dropped.
                let _ = self.conn.get_page(msg.payload.shared_pages()[0]);
            }
            api_net::NetCmd::EvtTcpStreamStateChanged => {}
            api_net::NetCmd::TcpStreamClose => {}
            api_net::NetCmd::UdpSocketTxRx => {
                // RX raced with the client dropping the sream. Need to get page to free it.
                // Get the page so that it is properly dropped.
                let sz = msg.payload.args_16()[10];
                if sz != 0 {
                    let _ = self.conn.get_page(msg.payload.shared_pages()[11]);
                }
            }
            api_net::NetCmd::UdpSocketTxRxAck => {}
            _ => {
                // This is logged always because if a new incoming message is added that
                // has to be handled but is not, we may have a problem.
                moto_log!(
                    "{}:{} orphan incoming message {:?} for 0x{:x}; release i/o page?",
                    file!(),
                    line!(),
                    cmd,
                    msg.handle
                );
            }
        }
    }

    #[inline]
    fn wake_driver(&self) {
        let _ = moto_sys::SysCpu::wake(self.conn.server_handle());
    }

    pub fn alloc_page(&self, subchannel_mask: u64) -> Result<io_channel::IoPage, ErrorCode> {
        self.conn
            .alloc_page(subchannel_mask)
            .map_err(|err| err.into())
    }

    pub fn may_alloc_page(&self, subchannel_mask: u64) -> bool {
        self.conn.may_alloc_page(subchannel_mask)
    }

    pub fn get_page(&self, page_idx: u16) -> Result<io_channel::IoPage, u16> {
        self.conn.get_page(page_idx).map_err(|err| err.into())
    }
}

pub struct ChannelReservation {
    channel: Arc<NetChannel>,
    subchannel_idx: Option<u8>,
}

impl Drop for ChannelReservation {
    fn drop(&mut self) {
        if let Some(idx) = self.subchannel_idx {
            self.channel.release_subchannel(idx);
        }

        NET.lock().release_channel_reservation(&self.channel);
    }
}

impl ChannelReservation {
    pub fn channel(&self) -> &Arc<NetChannel> {
        &self.channel
    }

    pub fn reserve_subchannel(&mut self) {
        assert!(self.subchannel_idx.is_none());
        self.subchannel_idx = Some(self.channel.reserve_subchannel_impl());
    }

    pub fn subchannel_mask(&self) -> u64 {
        api_net::io_subchannel_mask(self.subchannel_idx.unwrap())
    }

    pub fn subchannel_idx(&self) -> u8 {
        self.subchannel_idx.unwrap()
    }
}

pub fn clear_rx_queue(
    rx_queue: &Arc<Mutex<super::inner_rx_stream::InnerRxStream>>,
    channel: &NetChannel,
) {
    // Clear RX queue: basically, free up server-allocated pages.
    let mut rxq = rx_queue.lock();
    while let Some(msg) = rxq.pop_front() {
        if msg.command == (api_net::NetCmd::EvtTcpStreamStateChanged as u16) {
            continue;
        }
        assert_eq!(msg.command, api_net::NetCmd::TcpStreamRx as u16);
        let sz_read = msg.payload.args_64()[1];
        if sz_read > 0 {
            let _ = channel.conn.get_page(msg.payload.shared_pages()[0]);
        }
    }

    if let Some(bytes_len) = rxq.loose_bytes().map(|bytes| bytes.len()) {
        rxq.consume_bytes(bytes_len);
    }
}

pub fn reserve_channel() -> ChannelReservation {
    NET.lock().reserve_channel()
}
