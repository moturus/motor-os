use crate::posix;
use crate::posix::PosixFile;
use crate::runtime::ResponseHandler;
use crate::runtime::WaitObject;
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
use moto_rt::error::*;
use moto_rt::moto_log;
use moto_rt::mutex::Mutex;
use moto_rt::netc;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_rt::time::Instant;
use moto_rt::RtFd;
use moto_sys::ErrorCode;
use moto_sys::SysHandle;
use moto_sys_io::api_net;
use moto_sys_io::api_net::TcpState;
use moto_sys_io::api_net::IO_SUBCHANNELS;

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

    let host: &str = core::str::from_raw_parts(host_bytes, host_bytes_sz);

    let addr = if host == "localhost" {
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)
    } else if let Ok(addr_v4) = Ipv4Addr::from_str(host) {
        SocketAddrV4::new(addr_v4, port)
    } else {
        crate::moto_log!("dns_lookup: {}:{}: not implemented", host, port);
        return E_NOT_IMPLEMENTED;
    };

    let res_addr = crate::rt_alloc::alloc(core::mem::size_of::<netc::sockaddr>() as u64, 16);
    let result: &mut [netc::sockaddr] =
        core::slice::from_raw_parts_mut(res_addr as usize as *mut netc::sockaddr, 1);

    let addr = netc::sockaddr { v4: addr.into() };
    result[0] = addr;
    *result_addr = res_addr as usize;
    *result_len = 1;
    E_OK
}

pub extern "C" fn bind(proto: u8, addr: *const netc::sockaddr) -> RtFd {
    if proto != moto_rt::net::PROTO_TCP {
        return -(E_NOT_IMPLEMENTED as RtFd);
    }
    let addr = unsafe { (*addr).into() };
    let listener = match TcpListener::bind(&addr) {
        Ok(x) => x,
        Err(err) => return -(err as RtFd),
    };
    posix::push_file(listener)
}

pub extern "C" fn listen(rt_fd: RtFd, max_backlog: u32) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return E_BAD_HANDLE;
    };
    let Some(listener) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpListener>() else {
        return E_BAD_HANDLE;
    };

    match listener.listen(max_backlog) {
        Ok(()) => E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn accept(rt_fd: RtFd, peer_addr: *mut netc::sockaddr) -> RtFd {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return -(E_BAD_HANDLE as RtFd);
    };
    let Some(listener) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpListener>() else {
        return -(E_BAD_HANDLE as RtFd);
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
        return E_BAD_HANDLE;
    };

    if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpStream>() {
        tcp_stream.setsockopt(option, ptr, len)
    } else if let Some(tcp_listener) =
        (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpListener>()
    {
        tcp_listener.setsockopt(option, ptr, len)
    } else {
        E_BAD_HANDLE
    }
}

pub unsafe extern "C" fn getsockopt(rt_fd: RtFd, option: u64, ptr: usize, len: usize) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return E_BAD_HANDLE;
    };

    if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpStream>() {
        tcp_stream.getsockopt(option, ptr, len)
    } else if let Some(tcp_listener) =
        (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpListener>()
    {
        tcp_listener.getsockopt(option, ptr, len)
    } else {
        E_BAD_HANDLE
    }
}

pub extern "C" fn peek(rt_fd: i32, buf: *mut u8, buf_sz: usize) -> i64 {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return -(E_BAD_HANDLE as i64);
    };
    let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpStream>() else {
        return -(E_INVALID_ARGUMENT as i64);
    };

    let buf = unsafe { core::slice::from_raw_parts_mut(buf, buf_sz) };
    match tcp_stream.peek(buf) {
        Ok(sz) => sz as i64,
        Err(err) => -(err as i64),
    }
}

pub unsafe extern "C" fn socket_addr(rt_fd: RtFd, addr: *mut netc::sockaddr) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return E_BAD_HANDLE;
    };
    if let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpStream>() {
        if let Some(socket_addr) = tcp_stream.socket_addr() {
            *addr = (socket_addr).into();
            return E_OK;
        }
        return E_INVALID_ARGUMENT;
    };
    if let Some(tcp_listener) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpListener>() {
        *addr = (*tcp_listener.socket_addr()).into();
        return E_OK;
    };

    E_BAD_HANDLE
}

pub unsafe extern "C" fn peer_addr(rt_fd: RtFd, addr: *mut netc::sockaddr) -> ErrorCode {
    let Some(posix_file) = posix::get_file(rt_fd) else {
        return E_BAD_HANDLE;
    };
    let Some(tcp_stream) = (posix_file.as_ref() as &dyn Any).downcast_ref::<TcpStream>() else {
        return E_BAD_HANDLE;
    };

    match tcp_stream.peer_addr() {
        Ok(peer_addr) => {
            *addr = peer_addr.into();
            E_OK
        }
        Err(err) => err,
    }
}

#[allow(unused)]
pub fn vdso_internal_helper(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    match a1 {
        0 => NET.lock().assert_empty(),
        _ => panic!("Unrecognized option {a1}"),
    }

    0
}

// -------------------------------- implementation details ------------------------------ //

// Note: we have an IO thread per net channel instead of a single IO thread:
// - simpler/easier to code here: no need to "schedule" between channels
// - will scale better in the future when the driver side is also multithreaded
// - the usually assumed negatives are not necessarily as bad in Moturus OS
//   as in e.g. Linux:
//   - threads are "lighter", i.e. they consume less memory
//   - thread scheduling is potentially better, as Moturus OS is designed
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

static NET: Mutex<NetRuntime> = Mutex::new(NetRuntime {
    full_channels: BTreeMap::new(),
    channels: BTreeMap::new(),

    #[cfg(feature = "netdev")]
    num_tcp_listeners: AtomicU64::new(0),
    #[cfg(feature = "netdev")]
    num_tcp_streams: AtomicU64::new(0),
});

fn stats_tcp_listener_created() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_listeners.fetch_add(1, Ordering::Relaxed);
}

fn stats_tcp_listener_dropped() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_listeners.fetch_sub(1, Ordering::Relaxed);
}

fn stats_tcp_stream_created() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_streams.fetch_add(1, Ordering::Relaxed);
}

fn stats_tcp_stream_dropped() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_streams.fetch_sub(1, Ordering::Relaxed);
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
}

impl NetRuntime {
    #[cfg(feature = "netdev")]
    fn assert_empty(&self) {
        super::rt_thread::sleep(
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
struct NetChannel {
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

                // let wait_res = moto_sys::SysCpu::wait(
                //     &mut [self.conn.server_handle()],
                //     SysHandle::NONE,
                //     SysHandle::NONE,
                //     Some(moto_rt::time::Instant::now() + Duration::from_secs(10)),
                // );
                // if let Err(moto_rt::E_TIMED_OUT) = wait_res {
                //     crate::moto_log!("io_thread timo");
                //     self.conn.dump_state();
                // }
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
            // crate::util::moto_log!(
            //     "{}:{} got resp for msg {}:0x{:x}:{}",
            //     file!(),
            //     line!(),
            //     msg.id,
            //     msg.handle,
            //     msg.command
            // );

            let wait_handle: SysHandle = if msg.id == 0 {
                // This is an incoming packet, or similar, without a dedicated waiter.
                let stream_handle = msg.handle;
                let stream = {
                    let mut tcp_streams = self.tcp_streams.lock();
                    if let Some(stream) = tcp_streams.get_mut(&stream_handle) {
                        stream.upgrade()
                    } else {
                        None
                    }
                };
                if let Some(stream) = stream {
                    // Note: we must hold the lock while processing the message, otherwise the wait handle might get updated
                    //       and we will lose the wakeup. Sad story, don't ask...
                    let mut rx_lock = stream.rx_waiter.lock();
                    stream.process_incoming_msg(msg);
                    rx_lock.take().unwrap_or(SysHandle::NONE)
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

    // Attempts to send some messages. Returns true if the io thread may sleep.
    fn io_thread_send_messages(
        &self,
        msg: Option<io_channel::Msg>,
    ) -> (bool, Option<io_channel::Msg>) {
        let mut sent_messages = 0;
        if let Some(msg) = msg {
            fence(Ordering::SeqCst);
            if let Err(err) = self.conn.send(msg) {
                assert_eq!(err, moto_rt::E_NOT_READY);
                self.wake_driver();
                return (false, Some(msg));
            }
            sent_messages += 1;
        }

        while let Some(msg) = self.send_queue.pop() {
            fence(Ordering::SeqCst);
            if let Err(err) = self.conn.send(msg) {
                assert_eq!(err, moto_rt::E_NOT_READY);
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

    fn maybe_wake_io_thread(&self) {
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
            Self::io_thread_init as usize as u64,
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

    fn tcp_stream_created(&self, stream: &TcpStream) {
        assert!(self
            .tcp_streams
            .lock()
            .insert(stream.handle(), stream.me.clone())
            .is_none());
    }

    fn tcp_stream_dropped(&self, handle: u64) {
        let stream = self.tcp_streams.lock().remove(&handle).unwrap();
        assert_eq!(0, stream.strong_count());
    }

    fn tcp_listener_created(&self, listener: &Arc<TcpListener>) {
        self.tcp_listeners
            .lock()
            .insert(listener.handle, Arc::downgrade(listener));
    }

    fn tcp_listener_dropped(&self, handle: u64) {
        assert_eq!(
            0,
            self.tcp_listeners
                .lock()
                .remove(&handle)
                .unwrap()
                .strong_count()
        );
    }

    fn send_msg(&self, msg: io_channel::Msg) {
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
    fn send_receive(&self, mut req: io_channel::Msg) -> io_channel::Msg {
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

    fn new_req_id(&self) -> u64 {
        self.next_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    fn post_msg(&self, req: io_channel::Msg) -> Result<(), io_channel::Msg> {
        if self.send_queue.push(req).is_ok() {
            self.maybe_wake_io_thread();
            Ok(())
        } else {
            Err(req)
        }
    }

    fn post_msg_with_response_waiter(
        &self,
        req: io_channel::Msg,
        handler: Weak<dyn ResponseHandler + Send + Sync>,
    ) -> Result<(), ErrorCode> {
        assert_ne!(0, req.id);

        // Add to response handlers before sending the message, otherwise the response may
        // arive too quickly and the receiving code will panic due to a missing waiter.
        assert!(self
            .response_handlers
            .lock()
            .insert(req.id, handler)
            .is_none());

        if self.send_queue.push(req).is_ok() {
            self.maybe_wake_io_thread();
            Ok(())
        } else {
            Err(E_NOT_READY)
        }
    }

    // Note: this is called from the IO thread, so must not sleep/block.
    fn on_orphan_message(&self, msg: io_channel::Msg) {
        match msg.command {
            api_net::CMD_TCP_STREAM_RX => {
                // RX raced with the client dropping the sream. Need to get page to free it.
                let sz_read = msg.payload.args_64()[1];
                if sz_read > 0 {
                    crate::moto_log!("orphan RX");
                    let _ = self.conn.get_page(msg.payload.shared_pages()[0]);
                }
            }
            api_net::EVT_TCP_STREAM_STATE_CHANGED => {}
            api_net::CMD_TCP_STREAM_CLOSE => {}
            _ => {
                // #[cfg(debug_assertions)]
                // This is logged always because if a new incoming message is added that
                // has to be handled but is not, we may have a problem.
                moto_log!(
                    "{}:{} orphan incoming message {} for 0x{:x}; release i/o page?",
                    file!(),
                    line!(),
                    msg.command,
                    msg.handle
                );
            }
        }
    }

    #[inline]
    fn wake_driver(&self) {
        let _ = moto_sys::SysCpu::wake(self.conn.server_handle());
    }
}

struct ChannelReservation {
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
    fn reserve_subchannel(&mut self) {
        assert!(self.subchannel_idx.is_none());
        self.subchannel_idx = Some(self.channel.reserve_subchannel_impl());
    }

    fn subchannel_mask(&self) -> u64 {
        api_net::io_subchannel_mask(self.subchannel_idx.unwrap())
    }

    fn subchannel_idx(&self) -> u8 {
        self.subchannel_idx.unwrap()
    }
}

struct RxBuf {
    page: io_channel::IoPage,
    len: usize,
    consumed: usize,
}

impl RxBuf {
    fn bytes(&self) -> &[u8] {
        &self.page.bytes()[self.consumed..self.len]
    }

    fn consume(&mut self, sz: usize) {
        self.consumed += sz;
        assert!(self.consumed <= self.len);
    }

    fn is_consumed(&self) -> bool {
        self.consumed == self.len
    }

    fn available(&self) -> usize {
        self.len - self.consumed
    }
}

pub struct TcpStream {
    channel_reservation: ChannelReservation,
    local_addr: Mutex<Option<SocketAddr>>,
    remote_addr: SocketAddr,
    handle: AtomicU64,
    wait_object: WaitObject,
    nonblocking: AtomicBool,
    me: Weak<TcpStream>,

    // This is, most of the time, a single-producer, single-consumer queue.
    // MUST be locked before rx_buf is locked.
    recv_queue: Mutex<VecDeque<io_channel::Msg>>,
    next_rx_seq: CachePadded<AtomicU64>,

    // A partially consumed incoming RX. MUST NOT be locked when recv_queue lock is acquired.
    rx_buf: Mutex<Option<RxBuf>>,

    // A pending tx message.
    tx_msg: Mutex<Option<(io_channel::Msg, usize)>>,

    rx_waiter: Mutex<Option<SysHandle>>,

    tcp_state: AtomicU32, // rt_api::TcpState
    rx_done: AtomicBool,

    rx_timeout_ns: AtomicU64,
    tx_timeout_ns: AtomicU64,

    subchannel_mask: u64, // Never changes.

    stats_rx_bytes: CachePadded<AtomicU64>,
    stats_tx_bytes: CachePadded<AtomicU64>,

    error: AtomicU16, // Erorr during async ops.
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let handle = self.handle.load(Ordering::Relaxed);
        if handle == 0 {
            stats_tcp_stream_dropped();
            return;
        }

        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_CLOSE;
        req.handle = self.handle();

        if moto_sys::UserThreadControlBlock::get().self_handle
            == self.channel().io_thread_wake_handle.load(Ordering::Relaxed)
        {
            // We cannot do send_receive here because it will block the IO thread.
            self.channel().send_queue.push(req).unwrap(); // TODO: don't panic on failure.
        } else {
            let _ = self.channel().send_receive(req);
        }
        // moto_log!("TcpStream dropped");

        // Clear RX queue: basically, free up server-allocated pages.
        {
            let mut rxq = self.recv_queue.lock();
            while let Some(msg) = rxq.pop_front() {
                if msg.command == api_net::EVT_TCP_STREAM_STATE_CHANGED {
                    continue;
                }
                assert_eq!(msg.command, api_net::CMD_TCP_STREAM_RX);
                let sz_read = msg.payload.args_64()[1];
                if sz_read > 0 {
                    let _ = self.channel().conn.get_page(msg.payload.shared_pages()[0]);
                }
            }
        }

        // Clear TX queue (of length 0 or 1).
        let tx_msg = self.tx_msg.lock().take();
        if let Some((msg, _)) = tx_msg {
            assert_eq!(msg.command, api_net::CMD_TCP_STREAM_TX);
            let sz_read = msg.payload.args_64()[1];
            if sz_read > 0 {
                let _ = self.channel().conn.get_page(msg.payload.shared_pages()[0]);
            }
        }

        self.channel().tcp_stream_dropped(self.handle());
        stats_tcp_stream_dropped();
    }
}

impl PosixFile for TcpStream {
    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_or_peek(&mut [buf], false)
    }

    unsafe fn read_vectored(&self, bufs: &mut [&mut [u8]]) -> Result<usize, ErrorCode> {
        self.read_or_peek(bufs, false)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        self.write(&[buf])
    }

    unsafe fn write_vectored(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        self.write(bufs)
    }

    fn flush(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    fn close(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    fn poll_add(&self, r_id: u64, token: Token, interests: Interests) -> Result<(), ErrorCode> {
        self.wait_object.add_interests(r_id, token, interests)?;
        self.maybe_raise_events(interests, token);
        Ok(())
    }

    fn poll_set(&self, r_id: u64, token: Token, interests: Interests) -> Result<(), ErrorCode> {
        self.wait_object.set_interests(r_id, token, interests)?;
        self.maybe_raise_events(interests, token);
        Ok(())
    }

    fn poll_del(&self, r_id: u64) -> Result<(), ErrorCode> {
        self.wait_object.del_interests(r_id)
    }
}

impl ResponseHandler for TcpStream {
    fn on_response(&self, resp: io_channel::Msg) {
        assert_eq!(resp.command, api_net::CMD_TCP_STREAM_CONNECT);
        self.on_connect_response(resp);
    }
}

impl TcpStream {
    fn handle(&self) -> u64 {
        let handle = self.handle.load(Ordering::Relaxed);
        assert_ne!(0, handle);
        handle
    }

    fn channel(&self) -> &NetChannel {
        &self.channel_reservation.channel
    }

    fn maybe_raise_events(&self, interests: Interests, token: Token) {
        let mut events = 0;

        // maybe_raise_events is called from poll_add/poll_set,
        // so we raise events that are expected and don't raise events
        // that are not expected (based on mio tests, so somewhat ad-hoc).
        let state = self.tcp_state();
        if state == TcpState::Closed {
            // MIO TCP tests assume this.
            events = moto_rt::poll::POLL_WRITE_CLOSED
                | moto_rt::poll::POLL_READ_CLOSED
                | moto_rt::poll::POLL_READABLE
                | moto_rt::poll::POLL_WRITABLE;
            self.wait_object.on_event(events);
            return;
        }

        if (interests & moto_rt::poll::POLL_WRITABLE != 0)
            && self.have_write_buffer_space()
            && state.can_write()
        {
            events |= moto_rt::poll::POLL_WRITABLE;
        }
        if ((interests & moto_rt::poll::POLL_READABLE) != 0)
            && (self.rx_buf.lock().is_some() || !self.recv_queue.lock().is_empty())
            && state.can_read()
        {
            events |= moto_rt::poll::POLL_READABLE;
            if self.rx_done.load(Ordering::Acquire) {
                events |= moto_rt::poll::POLL_READ_CLOSED;
            }
        }

        if events != 0 {
            self.wait_object.on_event(events);
        }
    }

    fn ack_rx(&self) {
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_RX_ACK;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = self.next_rx_seq.load(Ordering::Relaxed) - 1;
        self.channel().send_msg(req);
    }

    fn tcp_state(&self) -> api_net::TcpState {
        api_net::TcpState::try_from(self.tcp_state.load(Ordering::Relaxed)).unwrap()
    }

    // Note: this is called from the IO thread, so must not sleep.
    fn process_incoming_msg(&self, msg: io_channel::Msg) {
        // The main challenge/nuance here is that sometimes we need to raise
        // poll events here, and sometimes we have to delay them. For example,
        // while there are messages in RXQ, we should not raise POLL_READ_CLOSED.
        let mut recv_q = self.recv_queue.lock();
        let have_rx_bytes = self.rx_buf.lock().is_some() || !recv_q.is_empty();
        if have_rx_bytes {
            // No need to raise POLL_READABLE, as this is not a state change
            // (receive queue non-empty).
            if msg.command == api_net::EVT_TCP_STREAM_STATE_CHANGED {
                let new_state = TcpState::try_from(msg.payload.args_32()[0]).unwrap();
                match new_state {
                    TcpState::Closed => {
                        // Deal only with TX closure: RX closing will happen later.
                        self.mark_tx_done();
                    }
                    _ => panic!("Unexpected TcpState {:?}", new_state),
                }
            }
            recv_q.push_back(msg);
            return;
        }

        // RXQ is empty.
        match msg.command {
            api_net::CMD_TCP_STREAM_RX => {
                let sz_read = msg.payload.args_64()[1] as usize;
                if sz_read > 0 {
                    recv_q.push_back(msg);
                    drop(recv_q);
                    // The RXQ was empty, this is a new (edge) event.
                    self.wait_object.on_event(moto_rt::poll::POLL_READABLE);
                } else {
                    // RX done. Need to raise the event here.
                    drop(recv_q);
                    self.mark_rx_done();
                }
            }
            api_net::EVT_TCP_STREAM_STATE_CHANGED => {
                let new_state = TcpState::try_from(msg.payload.args_32()[0]).unwrap();
                match new_state {
                    TcpState::Closed => {
                        self.mark_rx_done();
                        self.mark_tx_done();
                    }
                    _ => panic!("Unexpected TcpState {:?}", new_state),
                }
            }
            _ => panic!(
                "{}:{}: Unrecognized msg {} for stream 0x{:x}",
                file!(),
                line!(),
                msg.command,
                msg.handle
            ),
        }
    }

    fn connect(
        socket_addr: &SocketAddr,
        timeout: Option<Duration>,
        nonblocking: bool,
    ) -> Result<Arc<TcpStream>, ErrorCode> {
        let mut channel_reservation = NET.lock().reserve_channel();
        channel_reservation.reserve_subchannel();
        let subchannel_mask = channel_reservation.subchannel_mask();

        let mut req = if let Some(timo) = timeout {
            api_net::tcp_stream_connect_timeout_request(
                socket_addr,
                channel_reservation.subchannel_idx(),
                Instant::now() + timo,
            )
        } else {
            api_net::tcp_stream_connect_request(socket_addr, channel_reservation.subchannel_idx())
        };

        let new_stream = Arc::new_cyclic(|me| TcpStream {
            channel_reservation,
            local_addr: Mutex::new(None),
            remote_addr: *socket_addr,
            handle: AtomicU64::new(SysHandle::NONE.into()),
            wait_object: WaitObject::new(
                moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_WRITABLE,
            ),
            me: me.clone(),
            nonblocking: AtomicBool::new(nonblocking),
            recv_queue: Mutex::new(VecDeque::new()),
            next_rx_seq: AtomicU64::new(1).into(),
            rx_buf: Mutex::new(None),
            tx_msg: Mutex::new(None),
            rx_waiter: Mutex::new(None),
            tcp_state: AtomicU32::new(api_net::TcpState::Connecting.into()),
            rx_done: AtomicBool::new(false),
            rx_timeout_ns: AtomicU64::new(u64::MAX),
            tx_timeout_ns: AtomicU64::new(u64::MAX),
            subchannel_mask,
            stats_rx_bytes: AtomicU64::new(0).into(),
            stats_tx_bytes: AtomicU64::new(0).into(),
            error: AtomicU16::new(E_OK),
        });
        stats_tcp_stream_created();

        if nonblocking {
            let req_id = new_stream.channel().new_req_id();
            req.id = req_id;
            new_stream
                .channel()
                .post_msg_with_response_waiter(req, new_stream.me.clone())?;
            return Ok(new_stream);
        }

        let resp = new_stream.channel().send_receive(req);
        new_stream.on_connect_response(resp)?;

        Ok(new_stream)
    }

    fn on_connect_response(&self, resp: io_channel::Msg) -> Result<(), ErrorCode> {
        if resp.status() != moto_rt::E_OK {
            #[cfg(debug_assertions)]
            moto_log!(
                "{}:{} TcpStream::connect {:?} failed",
                file!(),
                line!(),
                self.remote_addr,
            );

            let prev = self
                .tcp_state
                .swap(TcpState::Closed.into(), Ordering::Release);
            assert_eq!(prev, TcpState::Connecting.into());

            self.error.store(resp.status(), Ordering::Relaxed);

            self.wait_object.on_event(
                moto_rt::poll::POLL_READ_CLOSED
                    | moto_rt::poll::POLL_WRITE_CLOSED
                    | moto_rt::poll::POLL_ERROR,
            );
            return Err(resp.status());
        }

        assert_ne!(0, resp.handle);
        self.handle.store(resp.handle, Ordering::Relaxed);
        *self.local_addr.lock() = Some(api_net::get_socket_addr(&resp.payload));
        let prev = self
            .tcp_state
            .swap(TcpState::ReadWrite.into(), Ordering::Release);
        assert_eq!(prev, TcpState::Connecting.into());
        self.channel().tcp_stream_created(self);

        self.wait_object.on_event(moto_rt::poll::POLL_WRITABLE);

        self.ack_rx();

        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} new outgoing TcpStream {:?} -> {:?} 0x{:x}, mask: 0x{:x}",
            file!(),
            line!(),
            self.local_addr.lock().unwrap(),
            self.remote_addr,
            self.handle(),
            self.subchannel_mask
        );

        Ok(())
    }

    unsafe fn setsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_NONBLOCKING => {
                assert_eq!(len, 1);
                let nonblocking = *(ptr as *const u8);
                if nonblocking > 1 {
                    return E_INVALID_ARGUMENT;
                }
                self.set_nonblocking(nonblocking == 1)
            }
            moto_rt::net::SO_RCVTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let timeout = *(ptr as *const u64);
                self.set_read_timeout(timeout);
                moto_rt::E_OK
            }
            moto_rt::net::SO_SNDTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let timeout = *(ptr as *const u64);
                self.set_write_timeout(timeout);
                moto_rt::E_OK
            }
            moto_rt::net::SO_SHUTDOWN => {
                assert_eq!(len, 1);
                let val = *(ptr as *const u8);
                let read = val & moto_rt::net::SHUTDOWN_READ != 0;
                let write = val & moto_rt::net::SHUTDOWN_WRITE != 0;
                self.shutdown(read, write)
            }
            moto_rt::net::SO_NODELAY => {
                assert_eq!(len, 1);
                let nodelay = *(ptr as *const u8);
                self.set_nodelay(nodelay)
            }
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                let ttl = *(ptr as *const u32);
                self.set_ttl(ttl)
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    unsafe fn getsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_RCVTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let timeout = self.read_timeout();
                *(ptr as *mut u64) = timeout;
                moto_rt::E_OK
            }
            moto_rt::net::SO_SNDTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let timeout = self.write_timeout();
                *(ptr as *mut u64) = timeout;
                moto_rt::E_OK
            }
            moto_rt::net::SO_NODELAY => {
                assert_eq!(len, 1);
                match self.nodelay() {
                    Ok(nodelay) => {
                        *(ptr as *mut u8) = nodelay;
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                }
            }
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                match self.ttl() {
                    Ok(ttl) => {
                        *(ptr as *mut u32) = ttl;
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                }
            }
            moto_rt::net::SO_ERROR => {
                assert_eq!(len, 2);
                let err = self.take_error();
                *(ptr as *mut u16) = err;
                moto_rt::E_OK
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    fn set_read_timeout(&self, timeout_ns: u64) {
        self.rx_timeout_ns.store(timeout_ns, Ordering::Relaxed);
    }

    fn set_write_timeout(&self, timeout_ns: u64) {
        self.tx_timeout_ns.store(timeout_ns, Ordering::Relaxed);
    }

    fn read_timeout(&self) -> u64 {
        self.rx_timeout_ns.load(Ordering::Relaxed)
    }

    fn write_timeout(&self) -> u64 {
        self.tx_timeout_ns.load(Ordering::Relaxed)
    }

    fn peek(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_or_peek(&mut [buf], true)
    }

    fn mark_rx_done(&self) {
        let prev = self.rx_done.swap(true, Ordering::AcqRel);
        if prev {
            return;
        }
        let mut prev_state = self.tcp_state();
        loop {
            let new_state = match prev_state {
                TcpState::ReadWrite => TcpState::WriteOnly,
                TcpState::ReadOnly => TcpState::Closed,
                TcpState::Closed => return,
                _ => panic!("Unexpected TCP state: {:?}", prev_state),
            };
            match self.tcp_state.compare_exchange_weak(
                prev_state.into(),
                new_state.into(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(prev) => {
                    prev_state = prev.try_into().unwrap();
                    core::hint::spin_loop();
                }
            }
        }

        self.wait_object
            .on_event(moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_READ_CLOSED);
    }

    fn mark_tx_done(&self) {
        let mut prev_state = self.tcp_state();
        loop {
            let new_state = match prev_state {
                TcpState::ReadWrite => TcpState::ReadOnly,
                TcpState::WriteOnly => TcpState::Closed,
                TcpState::ReadOnly | TcpState::Closed => return,
                _ => panic!("Unexpected TCP state: {:?}", prev_state),
            };
            match self.tcp_state.compare_exchange_weak(
                prev_state.into(),
                new_state.into(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(prev) => {
                    prev_state = prev.try_into().unwrap();
                    core::hint::spin_loop();
                }
            }
        }

        self.wait_object
            .on_event(moto_rt::poll::POLL_WRITABLE | moto_rt::poll::POLL_WRITE_CLOSED);
    }

    fn process_rx_message(
        &self,
        bufs: &mut [&mut [u8]],
        msg: io_channel::Msg,
        peek: bool,
    ) -> Result<usize, ErrorCode> {
        fence(Ordering::SeqCst);

        if msg.command == api_net::EVT_TCP_STREAM_STATE_CHANGED {
            // Note: this message was preprocessed in process_incoming_msg,
            // and the state was set to read-only.
            let new_state = TcpState::try_from(msg.payload.args_32()[0]).unwrap();
            match new_state {
                TcpState::Closed => {
                    self.mark_rx_done();
                    return Ok(0);
                }
                _ => panic!("Unexpected TcpState {:?}", new_state),
            }
        }

        assert_eq!(msg.command, api_net::CMD_TCP_STREAM_RX);
        let sz_read = msg.payload.args_64()[1] as usize;
        assert!(sz_read <= moto_ipc::io_channel::PAGE_SIZE);
        let rx_seq_incoming = msg.payload.args_64()[2];
        let rx_seq = self.next_rx_seq.fetch_add(1, Ordering::Relaxed);
        assert_eq!(rx_seq, rx_seq_incoming);
        if rx_seq & (api_net::TCP_RX_MAX_INFLIGHT - 1) == 0 {
            self.ack_rx();
        }

        if sz_read == 0 {
            assert_eq!(msg.payload.shared_pages()[0], u16::MAX);
            self.mark_rx_done();
            return Ok(0);
        }

        let io_page = self
            .channel()
            .conn
            .get_page(msg.payload.shared_pages()[0])
            .unwrap();
        // #[cfg(debug_assertions)]
        // moto_log!(
        //     "{}:{} incoming {} bytes for stream 0x{:x} rx_seq {}",
        //     file!(),
        //     line!(),
        //     sz_read,
        //     msg.handle,
        //     rx_seq
        // );

        self.stats_rx_bytes
            .fetch_add(sz_read as u64, Ordering::Relaxed);
        // #[cfg(debug_assertions)]
        // moto_log!(
        //     "{}:{} stream 0x{:x}: total RX bytes {}",
        //     file!(),
        //     line!(),
        //     msg.handle,
        //     self.stats_rx_bytes.load(Ordering::Relaxed)
        // );

        let mut buf_lock = self.rx_buf.lock();
        let rx_buf = &mut *buf_lock;
        assert!(rx_buf.is_none());
        *rx_buf = Some(RxBuf {
            page: io_page,
            len: sz_read,
            consumed: 0,
        });

        let Some(rx_buf) = rx_buf.as_mut() else {
            unreachable!()
        };
        let copied_bytes = unsafe { Self::rx_copy(rx_buf.bytes(), bufs) };
        if !peek {
            rx_buf.consume(copied_bytes);
            if rx_buf.is_consumed() {
                *buf_lock = None;
            }
        }

        Ok(copied_bytes)
    }

    unsafe fn rx_copy(mut src: &[u8], dst: &mut [&mut [u8]]) -> usize {
        let mut copied_bytes = 0;
        for buf in dst {
            let to_copy = buf.len().min(src.len());
            core::ptr::copy_nonoverlapping(src.as_ptr(), buf.as_mut_ptr(), to_copy);

            copied_bytes += to_copy;
            src = &src[to_copy..];
            if src.is_empty() {
                break;
            }
        }

        copied_bytes
    }

    fn poll_rx(&self, bufs: &mut [&mut [u8]], peek: bool) -> Result<usize, ErrorCode> {
        {
            let mut buf_lock = self.rx_buf.lock();
            if let Some(rx_buf) = &mut *buf_lock {
                let copied_bytes = unsafe { Self::rx_copy(rx_buf.bytes(), bufs) };
                if !peek {
                    rx_buf.consume(copied_bytes);
                    if rx_buf.is_consumed() {
                        *buf_lock = None;
                    }
                }
                return Ok(copied_bytes);
            }
        }

        {
            if let Some(msg) = self.recv_queue.lock().pop_front() {
                return self.process_rx_message(bufs, msg, peek);
            }
        }

        if self.rx_done.load(Ordering::Relaxed) {
            return Ok(0);
        }

        Err(moto_rt::E_NOT_READY)
    }

    fn read_or_peek(&self, bufs: &mut [&mut [u8]], peek: bool) -> Result<usize, ErrorCode> {
        match self.poll_rx(bufs, peek) {
            Ok(sz) => return Ok(sz),
            Err(err) => assert_eq!(err, moto_rt::E_NOT_READY),
        }

        if self.nonblocking.load(Ordering::Relaxed) {
            return Err(moto_rt::E_NOT_READY);
        }

        let rx_timeout_ns = self.rx_timeout_ns.load(Ordering::Relaxed);
        let rx_timeout = if rx_timeout_ns == u64::MAX {
            None
        } else {
            Some(Instant::now() + Duration::from_nanos(rx_timeout_ns))
        };

        loop {
            if let Some(timeout) = rx_timeout {
                if Instant::now() >= timeout {
                    return Err(moto_rt::E_TIMED_OUT);
                }
            }

            match self.poll_rx(bufs, peek) {
                Ok(sz) => return Ok(sz),
                Err(err) => assert_eq!(err, moto_rt::E_NOT_READY),
            }
            {
                // Store this thread's handle so that it is woken when an RX message arrives.
                *self.rx_waiter.lock() =
                    Some(moto_sys::UserThreadControlBlock::get().self_handle.into());
            }

            // Re-check for incoming messages.
            match self.poll_rx(bufs, peek) {
                Ok(sz) => {
                    *self.rx_waiter.lock() = None;
                    return Ok(sz);
                }
                Err(err) => assert_eq!(err, moto_rt::E_NOT_READY),
            }

            // Note: even if the socket is closed, there can be RX packets buffered
            // in sys-io, so we don't stop reading until we get a zero-length packet.

            // Note: this thread will be woken because we stored its handle in stream_entry.1 above.
            self.channel().maybe_wake_io_thread();

            const DEBUG_TIMEOUT: Duration = Duration::from_secs(5);
            let debug_timeout = Instant::now() + DEBUG_TIMEOUT;
            let mut debug_assert = false;
            let timo = if let Some(timeout) = rx_timeout {
                if timeout < debug_timeout {
                    timeout
                } else {
                    debug_assert = true;
                    debug_timeout
                }
            } else {
                debug_assert = true;
                debug_timeout
            };
            if let Err(err) = moto_sys::SysCpu::wait(
                &mut [],
                SysHandle::NONE,
                SysHandle::NONE,
                // rx_timeout,
                Some(timo),
            ) {
                assert_eq!(err, moto_rt::E_TIMED_OUT);
                if debug_assert {
                    // TODO: this assert triggered on 2024-05-29 and on 2024-06-25.
                    // assert!(self.recv_queue.lock().is_empty());
                    let queue_length = self.recv_queue.lock().len();
                    if queue_length > 0 {
                        moto_log!(
                            "{}:{} this is bad: RX timo with recv queue {}",
                            file!(),
                            line!(),
                            queue_length
                        );
                    }
                }
            }
        }
    }

    fn maybe_can_write(&self) {
        if self.have_write_buffer_space() {
            self.wait_object.on_event(moto_rt::poll::POLL_WRITABLE);
        } else {
            self.channel()
                .write_waiters
                .lock()
                .push_back(self.me.clone());
        }
    }

    fn have_write_buffer_space(&self) -> bool {
        {
            let mut tx_lock = self.tx_msg.lock();
            if let Some((msg, write_sz)) = tx_lock.take() {
                if let Err(msg) = self.try_tx(msg, write_sz) {
                    *tx_lock = Some((msg, write_sz));
                    return false;
                }
            }
        }

        self.channel().conn.may_alloc_page(self.subchannel_mask)
    }

    fn write(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        if bufs.is_empty() {
            return Ok(0);
        }
        if !self.tcp_state().can_write() {
            return Err(moto_rt::E_NOT_CONNECTED);
        }

        if self.nonblocking.load(Ordering::Relaxed) {
            return self.write_nonblocking(bufs);
        }

        let timestamp = Instant::now();
        let timo_ns = self.tx_timeout_ns.load(Ordering::Relaxed);
        let abs_timeout = if timo_ns == u64::MAX {
            None
        } else {
            Some(timestamp + Duration::from_nanos(timo_ns))
        };

        // TODO: now we sleep exponentially long (up to a limit) on stuck writes.
        //       We should add a new msg to the driver so that it wakes us up
        //       when writes are unstuck.
        let mut sleep_timo_usec = 1;
        let mut spin_loop_counter: u64 = 0;
        let mut yield_counter: u64 = 0;
        let io_page = loop {
            if let Some(timo) = abs_timeout {
                if Instant::now() >= timo {
                    return Err(moto_rt::E_TIMED_OUT);
                }
            }

            match self.channel().conn.alloc_page(self.subchannel_mask) {
                Ok(page) => break page,
                Err(_) => {
                    if !self.tcp_state().can_write() {
                        return Ok(0);
                    }

                    if spin_loop_counter < 100 {
                        spin_loop_counter += 1;
                        core::hint::spin_loop();
                        continue;
                    } else if yield_counter < 100 {
                        moto_sys::SysCpu::sched_yield();
                        yield_counter += 1;
                        continue;
                    }

                    let mut sleep_timo = Instant::now() + Duration::from_micros(sleep_timo_usec);
                    if let Some(timo) = abs_timeout {
                        if timo < sleep_timo {
                            sleep_timo = timo;
                        }
                    }
                    sleep_timo_usec *= 2;
                    if sleep_timo_usec > 3_000_000 {
                        sleep_timo_usec = 3_000_000;
                        moto_log!(
                            "{}:{} alloc page stuck for socket 0x{:x}",
                            file!(),
                            line!(),
                            self.handle()
                        );
                        self.channel().conn.dump_state();
                    }

                    let _ = moto_sys::SysCpu::wait(
                        &mut [],
                        SysHandle::NONE,
                        SysHandle::NONE,
                        Some(sleep_timo),
                    );
                }
            }
        };
        let write_sz = unsafe { Self::tx_copy(bufs, io_page.bytes_mut()) };

        let msg =
            api_net::tcp_stream_tx_msg(self.handle(), io_page, write_sz, Instant::now().as_u64());
        self.channel().send_msg(msg);
        self.stats_tx_bytes
            .fetch_add(write_sz as u64, Ordering::Relaxed);
        // #[cfg(debug_assertions)]
        // moto_log!(
        //     "{}:{} stream 0x{:x} TX bytes {}",
        //     file!(),
        //     line!(),
        //     self.handle(),
        //     self.stats_tx_bytes.load(Ordering::Relaxed)
        // );
        Ok(write_sz)
    }

    unsafe fn tx_copy(src: &[&[u8]], mut dst: &mut [u8]) -> usize {
        let mut written = 0;
        for buf in src {
            let to_write = buf.len().min(dst.len());
            core::ptr::copy_nonoverlapping(buf.as_ptr(), dst.as_mut_ptr(), to_write);
            written += to_write;
            dst = &mut dst[to_write..];

            if dst.is_empty() {
                break;
            }
        }

        written
    }

    fn write_nonblocking(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        // These are checked at the callsite.
        debug_assert!(self.tcp_state().can_write());

        // Serialize writes (= keep tx_lock), as we have only one self.tx_msg to store into.
        let mut tx_lock = self.tx_msg.lock();
        if let Some((msg, write_sz)) = tx_lock.take() {
            if let Err(msg) = self.try_tx(msg, write_sz) {
                *tx_lock = Some((msg, write_sz));
                self.channel()
                    .write_waiters
                    .lock()
                    .push_back(self.me.clone());
                return Err(moto_rt::E_NOT_READY);
            }
        }

        let Ok(io_page) = self.channel().conn.alloc_page(self.subchannel_mask) else {
            self.channel()
                .write_waiters
                .lock()
                .push_back(self.me.clone());
            return Err(moto_rt::E_NOT_READY);
        };

        let write_sz = unsafe { Self::tx_copy(bufs, io_page.bytes_mut()) };

        let msg =
            api_net::tcp_stream_tx_msg(self.handle(), io_page, write_sz, Instant::now().as_u64());
        if let Err(msg) = self.try_tx(msg, write_sz) {
            *tx_lock = Some((msg, write_sz));
            self.channel()
                .write_waiters
                .lock()
                .push_back(self.me.clone());
        }

        // We copied write_sz bytes out, so must return Ok(write_sz).
        Ok(write_sz)
    }

    fn try_tx(&self, msg: io_channel::Msg, write_sz: usize) -> Result<(), io_channel::Msg> {
        self.channel().post_msg(msg)?;

        self.stats_tx_bytes
            .fetch_add(write_sz as u64, Ordering::Relaxed);
        // #[cfg(debug_assertions)]
        // moto_log!(
        //     "{}:{} stream 0x{:x} TX bytes {}",
        //     file!(),
        //     line!(),
        //     self.handle(),
        //     self.stats_tx_bytes.load(Ordering::Relaxed)
        // );

        Ok(())
    }

    fn peer_addr(&self) -> Result<SocketAddr, ErrorCode> {
        core::sync::atomic::fence(Ordering::Acquire);
        // https://docs.rs/mio/0.8.8/mio/net/struct.TcpStream.html#method.connect
        // suggests that peer_addr() should return non-error only if connected.
        match self.tcp_state() {
            api_net::TcpState::Closed => Err(moto_rt::E_NOT_CONNECTED),
            api_net::TcpState::Listening => Err(moto_rt::E_INVALID_ARGUMENT),
            api_net::TcpState::PendingAccept => Err(moto_rt::E_INVALID_ARGUMENT),
            api_net::TcpState::Connecting => Err(moto_rt::E_NOT_CONNECTED),
            api_net::TcpState::ReadWrite => Ok(self.remote_addr),
            api_net::TcpState::ReadOnly => Ok(self.remote_addr),
            api_net::TcpState::WriteOnly => Ok(self.remote_addr),
            api_net::TcpState::_Max => {
                panic!("bad state {}", self.tcp_state.load(Ordering::Relaxed))
            }
        }
    }

    fn socket_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.lock()
    }

    fn shutdown(&self, read: bool, write: bool) -> ErrorCode {
        assert!(read || write);
        let mut option = 0_u64;
        if read {
            option |= api_net::TCP_OPTION_SHUT_RD;

            // Clear RXQ.
            let mut rxq = self.recv_queue.lock();
            while let Some(msg) = rxq.pop_front() {
                if msg.command == api_net::EVT_TCP_STREAM_STATE_CHANGED {
                    let new_state = TcpState::try_from(msg.payload.args_32()[0]).unwrap();
                    match new_state {
                        TcpState::Closed => {
                            // Deal only with TX closure: RX closing will happen later.
                            self.mark_tx_done();
                        }
                        _ => panic!("Unexpected TcpState {:?}", new_state),
                    }
                    continue;
                }
                assert_eq!(msg.command, api_net::CMD_TCP_STREAM_RX);
                let sz_read = msg.payload.args_64()[1];
                if sz_read > 0 {
                    let _ = self.channel().conn.get_page(msg.payload.shared_pages()[0]);
                }
            }
            self.mark_rx_done();
        }
        if write {
            option |= api_net::TCP_OPTION_SHUT_WR;
            self.mark_tx_done();
        }

        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_SET_OPTION;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = option;
        let resp = self.channel().send_receive(req);

        resp.status()
    }

    fn set_linger(&self, dur: Option<Duration>) -> Result<(), ErrorCode> {
        if let Some(dur) = dur {
            if dur == Duration::ZERO {
                return Ok(());
            }
        }

        // At the moment, socket shutdown or drop drops all unsent bytes, which
        // corresponds to SO_LINGER(0). This may or may not be what the user
        // wants, but anything different requires changing sys-io code/logic,
        // at there are higher-priority work to do.
        Err(moto_rt::E_NOT_IMPLEMENTED)
    }

    fn linger(&self) -> Result<Option<Duration>, ErrorCode> {
        Ok(Some(Duration::ZERO)) // see set_linger() above.
    }

    fn set_nodelay(&self, nodelay: u8) -> ErrorCode {
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_SET_OPTION;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_NODELAY;
        req.payload.args_64_mut()[1] = nodelay as u64;
        self.channel().send_receive(req).status()
    }

    fn nodelay(&self) -> Result<u8, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_GET_OPTION;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_NODELAY;
        let resp = self.channel().send_receive(req);

        if resp.status() == moto_rt::E_OK {
            let res = resp.payload.args_64()[0];
            Ok(res as u8)
        } else {
            Err(resp.status())
        }
    }

    fn set_ttl(&self, ttl: u32) -> ErrorCode {
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_SET_OPTION;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        req.payload.args_32_mut()[2] = ttl;
        self.channel().send_receive(req).status()
    }

    fn ttl(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_GET_OPTION;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        let resp = self.channel().send_receive(req);

        if resp.status() == moto_rt::E_OK {
            Ok(resp.payload.args_32()[0])
        } else {
            Err(resp.status())
        }
    }

    fn take_error(&self) -> ErrorCode {
        let err = self.error.swap(E_OK, Ordering::Relaxed);
        err as ErrorCode
    }

    fn set_nonblocking(&self, nonblocking: bool) -> ErrorCode {
        self.nonblocking.store(nonblocking, Ordering::Release);
        moto_rt::E_OK
    }
}

struct AcceptRequest {
    channel_reservation: Option<ChannelReservation>,
    req: moto_ipc::io_channel::Msg,
}

struct PendingAccept {
    req: AcceptRequest,
    resp: moto_ipc::io_channel::Msg,
}

pub struct TcpListener {
    socket_addr: SocketAddr,
    channel_reservation: ChannelReservation,
    handle: u64,
    nonblocking: AtomicBool,
    wait_object: WaitObject,

    // All outgoing accept requests are stored here: req_id => req.
    accept_requests: Mutex<BTreeMap<u64, AcceptRequest>>,

    // Incoming async accepts are stored here. Better processed
    // in arrival order.
    async_accepts: Mutex<VecDeque<PendingAccept>>,

    // Incoming sync accepts are stored here: req_id => acc;
    // have to be processed by id.
    sync_accepts: Mutex<BTreeMap<u64, PendingAccept>>,
    max_backlog: AtomicU32,
    me: Weak<TcpListener>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut msg = io_channel::Msg::new();
        msg.command = api_net::CMD_TCP_LISTENER_DROP;
        msg.handle = self.handle;

        self.channel().send_msg(msg);
        self.channel().tcp_listener_dropped(self.handle);

        stats_tcp_listener_dropped();
    }
}

impl PosixFile for TcpListener {
    fn close(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    fn poll_add(&self, r_id: u64, token: Token, interests: Interests) -> Result<(), ErrorCode> {
        self.wait_object.add_interests(r_id, token, interests)?;

        let have_async_accepts = !self.async_accepts.lock().is_empty();
        if (interests & moto_rt::poll::POLL_READABLE != 0) && have_async_accepts {
            self.wait_object.on_event(moto_rt::poll::POLL_READABLE);
        }

        Ok(())
    }

    fn poll_set(&self, r_id: u64, token: Token, interests: Interests) -> Result<(), ErrorCode> {
        self.wait_object.set_interests(r_id, token, interests)?;

        let have_async_accepts = !self.async_accepts.lock().is_empty();
        if (interests & moto_rt::poll::POLL_READABLE != 0) && have_async_accepts {
            self.wait_object.on_event(moto_rt::poll::POLL_READABLE);
        }

        Ok(())
    }

    fn poll_del(&self, r_id: u64) -> Result<(), ErrorCode> {
        self.wait_object.del_interests(r_id)
    }
}

impl ResponseHandler for TcpListener {
    fn on_response(&self, resp: io_channel::Msg) {
        let req = self.accept_requests.lock().remove(&resp.id).unwrap();
        let wake_handle = SysHandle::from_u64(req.req.wake_handle);

        if wake_handle != SysHandle::NONE {
            // The accept was blocking; a thread is waiting.
            assert!(self
                .sync_accepts
                .lock()
                .insert(req.req.id, PendingAccept { req, resp })
                .is_none());
            let _ = moto_sys::SysCpu::wake(wake_handle);
            return;
        }

        self.async_accepts
            .lock()
            .push_back(PendingAccept { req, resp });
        if self.async_accepts.lock().len() < (self.max_backlog.load(Ordering::Relaxed) as usize) {
            self.post_accept(false).unwrap(); // TODO: how to post an accept later?
        }

        self.wait_object.on_event(moto_rt::poll::POLL_READABLE);
    }
}

impl TcpListener {
    fn channel(&self) -> &NetChannel {
        &self.channel_reservation.channel
    }

    fn bind(socket_addr: &SocketAddr) -> Result<Arc<TcpListener>, ErrorCode> {
        let mut socket_addr = *socket_addr;
        if socket_addr.port() == 0 && socket_addr.ip().is_unspecified() {
            crate::moto_log!("we don't currently allow binding to/listening on 0.0.0.0:0");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let req = api_net::bind_tcp_listener_request(&socket_addr, None);
        let channel_reservation = NET.lock().reserve_channel();
        let resp = channel_reservation.channel.send_receive(req);
        if resp.status() != moto_rt::E_OK {
            return Err(resp.status());
        }

        if socket_addr.port() == 0 {
            let actual_addr = api_net::get_socket_addr(&resp.payload);
            assert_eq!(socket_addr.ip(), actual_addr.ip());
            assert_ne!(0, actual_addr.port());
            socket_addr.set_port(actual_addr.port());
        }

        let tcp_listener = Arc::new_cyclic(|me| TcpListener {
            socket_addr,
            channel_reservation,
            handle: resp.handle,
            nonblocking: AtomicBool::new(false),
            wait_object: WaitObject::new(moto_rt::poll::POLL_READABLE),
            accept_requests: Mutex::new(BTreeMap::new()),
            async_accepts: Mutex::new(VecDeque::new()),
            sync_accepts: Mutex::new(BTreeMap::new()),
            max_backlog: AtomicU32::new(32),
            me: me.clone(),
        });
        tcp_listener.channel().tcp_listener_created(&tcp_listener);
        stats_tcp_listener_created();

        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} new TcpListener {:?}",
            file!(),
            line!(),
            tcp_listener.socket_addr
        );

        Ok(tcp_listener)
    }

    fn listen(&self, max_backlog: u32) -> Result<(), ErrorCode> {
        if !self.nonblocking.load(Ordering::Relaxed) {
            return Err(E_INVALID_ARGUMENT);
        }

        if max_backlog == 0 {
            return Err(E_INVALID_ARGUMENT);
        }
        self.max_backlog.store(max_backlog, Ordering::Relaxed);
        if !self.accept_requests.lock().is_empty() {
            return Ok(()); // Already listening.
        }

        if self.async_accepts.lock().len() >= (max_backlog as usize) {
            return Ok(()); // The backlog is too large.
        }

        self.post_accept(false)
            .map(|_| ())
            .inspect_err(|_| panic!("TODO: what can we do here?"))
    }

    fn socket_addr(&self) -> &SocketAddr {
        &self.socket_addr
    }

    fn get_pending_accept(&self) -> Result<PendingAccept, ErrorCode> {
        if let Some(pending_accept) = self.async_accepts.lock().pop_front() {
            return Ok(pending_accept);
        }

        if self.nonblocking.load(Ordering::Relaxed) {
            return Err(E_NOT_READY);
        };

        let req_id = self.post_accept(true).unwrap(); // TODO: wait for channel to become ready.
        loop {
            {
                if let Some(pending_accept) = self.sync_accepts.lock().remove(&req_id) {
                    return Ok(pending_accept);
                }
            }

            let _ = moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, None);
        }
    }

    fn accept(&self) -> Result<(Arc<TcpStream>, SocketAddr), ErrorCode> {
        let mut pending_accept = self.get_pending_accept()?;
        if pending_accept.resp.status() != moto_rt::E_OK {
            return Err(pending_accept.resp.status());
        }

        let remote_addr = api_net::get_socket_addr(&pending_accept.resp.payload);
        let channel_reservation = pending_accept.req.channel_reservation.take().unwrap();
        let subchannel_mask = channel_reservation.subchannel_mask();

        let new_stream = Arc::new_cyclic(|me| TcpStream {
            local_addr: Mutex::new(Some(self.socket_addr)),
            remote_addr,
            handle: AtomicU64::new(pending_accept.resp.handle),
            wait_object: WaitObject::new(
                moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_WRITABLE,
            ),
            me: me.clone(),
            nonblocking: AtomicBool::new(self.nonblocking.load(Ordering::Relaxed)),
            channel_reservation,
            recv_queue: Mutex::new(VecDeque::new()),
            next_rx_seq: AtomicU64::new(1).into(),
            rx_buf: Mutex::new(None),
            tx_msg: Mutex::new(None),
            rx_waiter: Mutex::new(None),
            tcp_state: AtomicU32::new(api_net::TcpState::ReadWrite.into()),
            rx_done: AtomicBool::new(false),
            rx_timeout_ns: AtomicU64::new(u64::MAX),
            tx_timeout_ns: AtomicU64::new(u64::MAX),
            subchannel_mask,
            stats_rx_bytes: AtomicU64::new(0).into(),
            stats_tx_bytes: AtomicU64::new(0).into(),
            error: AtomicU16::new(E_OK),
        });
        stats_tcp_stream_created();

        new_stream.channel().tcp_stream_created(&new_stream);
        new_stream.ack_rx();

        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} new incoming TcpStream {:?} <- {:?} 0x{:x} mask: 0x{:x}",
            file!(),
            line!(),
            new_stream.local_addr.lock().unwrap(),
            new_stream.remote_addr,
            new_stream.handle(),
            new_stream.subchannel_mask
        );

        Ok((new_stream, remote_addr))
    }

    fn post_accept(&self, blocking: bool) -> Result<u64, ErrorCode> {
        // Because a listener can spawn thousands, millions of sockets
        // (think a long-running web server), we cannot use the listener's
        // channel for incoming connections.
        let mut channel_reservation = NET.lock().reserve_channel();
        let channel = channel_reservation.channel.clone();

        channel_reservation.reserve_subchannel();
        let subchannel_mask = channel_reservation.subchannel_mask();

        let mut req = api_net::accept_tcp_listener_request(self.handle, subchannel_mask);
        let req_id = channel_reservation.channel.new_req_id();
        req.id = req_id;
        if blocking {
            req.wake_handle = moto_sys::UserThreadControlBlock::get().self_handle;
        }
        let accept_request = AcceptRequest {
            channel_reservation: Some(channel_reservation),
            req,
        };

        assert!(self
            .accept_requests
            .lock()
            .insert(req.id, accept_request)
            .is_none());

        channel
            .post_msg_with_response_waiter(req, self.me.clone())
            .inspect_err(|_| {
                assert!(self.accept_requests.lock().remove(&req.id).is_some());
            })
            .map(|_| req_id)
    }

    unsafe fn setsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_NONBLOCKING => {
                assert_eq!(len, 1);
                let nonblocking = *(ptr as *const u8);
                if nonblocking > 1 {
                    return E_INVALID_ARGUMENT;
                }
                self.set_nonblocking(nonblocking == 1)
            }
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                let ttl = *(ptr as *const u32);
                self.set_ttl(ttl)
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    unsafe fn getsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                match self.ttl() {
                    Ok(ttl) => {
                        *(ptr as *mut u32) = ttl;
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                }
            }
            moto_rt::net::SO_ERROR => {
                assert_eq!(len, 2);
                let err = self.take_error();
                *(ptr as *mut u16) = err;
                moto_rt::E_OK
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    fn set_ttl(&self, ttl: u32) -> ErrorCode {
        if ttl > (u8::MAX as u32) {
            return moto_rt::E_INVALID_ARGUMENT;
        }
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_LISTENER_SET_OPTION;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        req.payload.args_8_mut()[23] = ttl as u8;
        self.channel().send_receive(req).status()
    }

    fn ttl(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_LISTENER_GET_OPTION;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        let resp = self.channel().send_receive(req);

        if resp.status() == moto_rt::E_OK {
            Ok(resp.payload.args_8()[23] as u32)
        } else {
            Err(resp.status())
        }
    }
    fn set_only_v6(&self, _: bool) -> Result<(), ErrorCode> {
        Err(moto_rt::E_NOT_IMPLEMENTED) // This is deprected since Rust 1.16
    }

    fn only_v6(&self) -> Result<bool, ErrorCode> {
        Err(moto_rt::E_NOT_IMPLEMENTED) // This is deprected since Rust 1.16
    }

    fn take_error(&self) -> ErrorCode {
        moto_rt::E_OK
    }

    fn set_nonblocking(&self, nonblocking: bool) -> ErrorCode {
        let was_blocking = !self.nonblocking.swap(nonblocking, Ordering::Release);
        if nonblocking && was_blocking {
            match self.listen(1024) {
                Ok(()) => E_OK,
                Err(err) => err,
            }
            // TODO: at the moment, previously-issues blocking accepts
            // will remain blocking. Maybe they should be kicked with E_NOT_READY?
        } else {
            E_OK
        }
    }
}
