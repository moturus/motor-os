use crate::util::fd::Fd;
use crate::util::fd::DESCRIPTORS;
use moto_rt::error::*;
use moto_rt::moto_log;
use moto_rt::mutex::Mutex;
use moto_rt::netc;
use moto_rt::RtFd;
use moto_sys_io::api_net;

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
    DESCRIPTORS.push(alloc::sync::Arc::new(Fd::TcpListener(listener)))
}

pub extern "C" fn accept(listener: RtFd, peer_addr: *mut netc::sockaddr) -> RtFd {
    let fd = if let Some(fd) = DESCRIPTORS.get(listener) {
        fd
    } else {
        return -(E_BAD_HANDLE as RtFd);
    };

    let Fd::TcpListener(listener) = fd.as_ref() else {
        return -(E_BAD_HANDLE as RtFd);
    };

    let (stream, addr) = match listener.accept() {
        Ok(x) => x,
        Err(err) => return -(err as RtFd),
    };
    let stream = DESCRIPTORS.push(alloc::sync::Arc::new(Fd::TcpStream(stream)));
    unsafe {
        *peer_addr = addr.into();
    }
    stream
}

pub extern "C" fn tcp_connect(addr: *const netc::sockaddr, timeout_ns: u64) -> RtFd {
    let addr = unsafe { (*addr).into() };
    let timeout = if timeout_ns == u64::MAX {
        None
    } else {
        Some(Duration::from_nanos(timeout_ns))
    };
    let stream = match TcpStream::connect(&addr, timeout) {
        Ok(x) => x,
        Err(err) => return -(err as RtFd),
    };
    DESCRIPTORS.push(alloc::sync::Arc::new(Fd::TcpStream(stream)))
}

pub unsafe extern "C" fn setsockopt(rt_fd: RtFd, option: u64, ptr: usize, len: usize) -> ErrorCode {
    let fd = if let Some(fd) = DESCRIPTORS.get(rt_fd) {
        fd
    } else {
        return E_BAD_HANDLE;
    };

    let Fd::TcpStream(tcp_stream) = fd.as_ref() else {
        return E_BAD_HANDLE;
    };

    match option {
        moto_rt::net::SO_RCVTIMEO => {
            assert_eq!(len, core::mem::size_of::<u64>());
            let timeout = *(ptr as *const u64);
            tcp_stream.set_read_timeout(timeout);
            moto_rt::E_OK
        }
        moto_rt::net::SO_SNDTIMEO => {
            assert_eq!(len, core::mem::size_of::<u64>());
            let timeout = *(ptr as *const u64);
            tcp_stream.set_write_timeout(timeout);
            moto_rt::E_OK
        }
        moto_rt::net::SO_SHUTDOWN => {
            assert_eq!(len, 1);
            let val = *(ptr as *const u8);
            let read = val & moto_rt::net::SHUTDOWN_READ != 0;
            let write = val & moto_rt::net::SHUTDOWN_WRITE != 0;
            tcp_stream.shutdown(read, write)
        }
        moto_rt::net::SO_NODELAY => {
            assert_eq!(len, 1);
            let nodelay = *(ptr as *const u8);
            tcp_stream.set_nodelay(nodelay)
        }
        moto_rt::net::SO_TTL => {
            assert_eq!(len, 4);
            let ttl = *(ptr as *const u32);
            tcp_stream.set_ttl(ttl)
        }
        _ => panic!("unrecognized option {option}"),
    }
}

pub unsafe extern "C" fn getsockopt(rt_fd: RtFd, option: u64, ptr: usize, len: usize) -> ErrorCode {
    let fd = if let Some(fd) = DESCRIPTORS.get(rt_fd) {
        fd
    } else {
        return E_BAD_HANDLE;
    };

    let Fd::TcpStream(tcp_stream) = fd.as_ref() else {
        return E_BAD_HANDLE;
    };

    match option {
        moto_rt::net::SO_RCVTIMEO => {
            assert_eq!(len, core::mem::size_of::<u64>());
            let timeout = tcp_stream.read_timeout();
            *(ptr as *mut u64) = timeout;
            moto_rt::E_OK
        }
        moto_rt::net::SO_SNDTIMEO => {
            assert_eq!(len, core::mem::size_of::<u64>());
            let timeout = tcp_stream.write_timeout();
            *(ptr as *mut u64) = timeout;
            moto_rt::E_OK
        }
        moto_rt::net::SO_NODELAY => {
            assert_eq!(len, 1);
            match tcp_stream.nodelay() {
                Ok(nodelay) => {
                    *(ptr as *mut u8) = nodelay;
                    moto_rt::E_OK
                }
                Err(err) => err,
            }
        }
        moto_rt::net::SO_TTL => {
            assert_eq!(len, 4);
            match tcp_stream.ttl() {
                Ok(ttl) => {
                    *(ptr as *mut u32) = ttl;
                    moto_rt::E_OK
                }
                Err(err) => err,
            }
        }
        _ => panic!("unrecognized option {option}"),
    }
}

pub unsafe extern "C" fn peer_addr(rt_fd: RtFd, addr: *mut netc::sockaddr) -> ErrorCode {
    let fd = if let Some(fd) = DESCRIPTORS.get(rt_fd) {
        fd
    } else {
        return E_BAD_HANDLE;
    };

    let Fd::TcpStream(tcp_stream) = fd.as_ref() else {
        return E_BAD_HANDLE;
    };

    *addr = (*tcp_stream.peer_addr()).into();
    E_OK
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

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::sync::atomic::*;
use core::time::Duration;
use crossbeam::utils::CachePadded;
use moto_ipc::io_channel;
use moto_rt::time::Instant;
use moto_sys::ErrorCode;
use moto_sys::SysHandle;
use moto_sys_io::api_net::IO_SUBCHANNELS;

static NET: Mutex<NetRuntime> = Mutex::new(NetRuntime {
    full_channels: BTreeMap::new(),
    channels: BTreeMap::new(),
});

struct NetRuntime {
    // Channels at capacity. We need sets, but this is rustc-dep-of-std, and our options are limited.
    full_channels: BTreeMap<u64, Arc<NetChannel>>,
    // Channels that can accommodate more sockets.
    channels: BTreeMap<u64, Arc<NetChannel>>,
}

impl NetRuntime {
    fn reserve_channel(&mut self) -> Arc<NetChannel> {
        if let Some(entry) = self.channels.first_entry() {
            let channel = entry.get().clone();
            let reservations = 1 + channel.reservations.fetch_add(1, Ordering::Relaxed);
            if reservations == IO_SUBCHANNELS {
                self.channels.remove(&channel.id());
                self.full_channels.insert(channel.id(), channel.clone());
            }

            channel
        } else {
            let channel = NetChannel::new();
            channel.reservations.fetch_add(1, Ordering::Relaxed);
            self.channels.insert(channel.id(), channel.clone());
            channel
        }
    }

    fn release_channel(&mut self, channel: Arc<NetChannel>) {
        channel.reservations.fetch_sub(1, Ordering::Relaxed);
        if let Some(channel) = self.full_channels.remove(&channel.id()) {
            // TODO: maybe clear empty channels?
            self.channels.insert(channel.id(), channel);
        }
    }
}

struct NetChannel {
    conn: io_channel::ClientConnection,
    reservations: AtomicUsize,

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

    // Threads waiting for specific resp_id: map resp_id => (thread handle, resp).
    resp_waiters: Mutex<BTreeMap<u64, (SysHandle, Option<io_channel::Msg>)>>,

    io_thread_join_handle: AtomicU64,
    io_thread_wake_handle: AtomicU64,

    io_thread_running: CachePadded<AtomicBool>,
    io_thread_wake_requested: CachePadded<AtomicBool>,
    exiting: CachePadded<AtomicBool>,
}

impl Drop for NetChannel {
    fn drop(&mut self) {
        self.exiting.store(true, Ordering::Release);
        todo!("wait for the IO thread to finish")
    }
}

impl NetChannel {
    fn id(&self) -> u64 {
        self.conn.server_handle().into()
    }

    fn io_thread(&self) -> ! {
        let mut maybe_msg = None;
        loop {
            self.io_thread_running.store(true, Ordering::Release);
            let mut should_sleep = self.io_thread_poll_messages();
            let (sleep, msg) = self.io_thread_send_messages(maybe_msg);
            maybe_msg = msg;
            should_sleep &= sleep;

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
    fn io_thread_poll_messages(self: &Self) -> bool {
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

            let wait_handle: Option<SysHandle> = if msg.id == 0 {
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
                    rx_lock.take()
                } else {
                    self.on_orphan_message(msg);
                    None
                }
            } else {
                let mut resp_waiters = self.resp_waiters.lock();
                if let Some((handle, resp)) = resp_waiters.get_mut(&msg.id) {
                    *resp = Some(msg);
                    Some(*handle)
                } else {
                    panic!("unexpected msg");
                }
            };

            if let Some(wait_handle) = wait_handle {
                if wait_handle.as_u64() != moto_sys::UserThreadControlBlock::get().self_handle {
                    let _ = moto_sys::SysCpu::wake(wait_handle);
                }
            }

            if received_messages > 32 {
                return false;
            }
        }

        true
    }

    // Attempts to send some messages. Returns true if the io thread may sleep.
    fn io_thread_send_messages(
        self: &Self,
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
            moto_sys::UserThreadControlBlock::get().self_handle.into(),
            Ordering::Release,
        );

        self_.io_thread();
    }

    fn new() -> Arc<Self> {
        let mut subchannels_in_use = Vec::with_capacity(IO_SUBCHANNELS);
        for _ in 0..IO_SUBCHANNELS {
            subchannels_in_use.push(AtomicBool::new(false));
        }

        let self_ = Arc::new(NetChannel {
            conn: io_channel::ClientConnection::connect("sys-io").unwrap(),
            subchannels_in_use,
            tcp_streams: Mutex::new(BTreeMap::new()),
            tcp_listeners: Mutex::new(BTreeMap::new()),
            reservations: AtomicUsize::new(0),
            next_msg_id: CachePadded::new(AtomicU64::new(1)),
            send_queue: crossbeam_queue::ArrayQueue::new(io_channel::CHANNEL_PAGE_COUNT),
            send_waiters: Mutex::new(VecDeque::new()),
            resp_waiters: Mutex::new(BTreeMap::new()),
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
    fn reserve_subchannel(&self) -> usize {
        for idx in 0..IO_SUBCHANNELS {
            if self.subchannels_in_use[idx].swap(true, Ordering::AcqRel) {
                continue; // Was already reserved.
            }
            return idx;
        }
        panic!("Failed to reserve IO subchannel.")
    }

    fn release_subchannel(&self, idx: usize) {
        assert!(idx < IO_SUBCHANNELS);
        assert!(self.subchannels_in_use[idx].swap(false, Ordering::AcqRel));
    }

    fn tcp_stream_created(self: &Arc<Self>, stream: &Arc<TcpStream>) {
        assert!(self
            .tcp_streams
            .lock()
            .insert(stream.handle, Arc::downgrade(stream))
            .is_none());
    }

    fn tcp_stream_dropped(self: &Arc<Self>, handle: u64, subchannel_idx: usize) {
        let stream = self.tcp_streams.lock().remove(&handle).unwrap();
        assert_eq!(0, stream.strong_count());

        self.release_subchannel(subchannel_idx);
        NET.lock().release_channel(self.clone());
    }

    fn tcp_listener_created(self: &Arc<Self>, listener: &Arc<TcpListener>) {
        self.tcp_listeners
            .lock()
            .insert(listener.handle, Arc::downgrade(listener));
    }

    fn tcp_listener_dropped(self: &Arc<Self>, handle: u64) {
        assert_eq!(
            0,
            self.tcp_listeners
                .lock()
                .remove(&handle)
                .unwrap()
                .strong_count()
        );

        NET.lock().release_channel(self.clone());
    }

    fn send_msg(self: &Arc<Self>, msg: io_channel::Msg) {
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

    fn wait_for_resp(self: &Arc<Self>, resp_id: u64) -> io_channel::Msg {
        loop {
            {
                let mut recv_waiters = self.resp_waiters.lock();
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
    fn send_receive(self: &Arc<Self>, mut req: io_channel::Msg) -> io_channel::Msg {
        let req_id = self.next_msg_id.fetch_add(1, Ordering::Relaxed);

        // Add to waiters before sending the message, otherwise the response may
        // arive too quickly and the receiving code will panic due to a missing waiter.
        self.resp_waiters.lock().insert(
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

    // Note: this is called from the IO thread, so must not sleep/block.
    fn on_orphan_message(self: &Self, msg: io_channel::Msg) {
        match msg.command {
            api_net::CMD_TCP_STREAM_RX => {
                // RX raced with the client dropping the sream. Need to get page to free it.
                let sz_read = msg.payload.args_64()[1];
                if sz_read > 0 {
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
    channel: Arc<NetChannel>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    handle: u64,

    // This is, most of the time, a single-producer, single-consumer queue.
    recv_queue: Mutex<VecDeque<io_channel::Msg>>,
    next_rx_seq: AtomicU64,

    // A partially consumed incoming RX.
    rx_buf: Mutex<Option<RxBuf>>,

    rx_waiter: Mutex<Option<SysHandle>>,

    tcp_state: AtomicU32, // rt_api::TcpState
    rx_done: AtomicBool,

    rx_timeout_ns: AtomicU64,
    tx_timeout_ns: AtomicU64,

    subchannel_idx: usize, // Never changes.
    subchannel_mask: u64,  // Never changes.

    stats_rx_bytes: AtomicU64,
    stats_tx_bytes: AtomicU64,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_CLOSE;
        req.handle = self.handle;

        if moto_sys::UserThreadControlBlock::get().self_handle
            == self.channel.io_thread_wake_handle.load(Ordering::Relaxed)
        {
            // We cannot do send_receive here because it will block the IO thread.
            self.channel.send_queue.push(req).unwrap(); // TODO: don't panic on failure.
        } else {
            let _ = self.channel.send_receive(req);
        }

        // Clear RX queue: basically, free up server-allocated pages.
        {
            let mut queue = self.recv_queue.lock();
            while let Some(msg) = queue.pop_front() {
                assert_eq!(msg.command, api_net::CMD_TCP_STREAM_RX);
                let sz_read = msg.payload.args_64()[1];
                if sz_read > 0 {
                    let _ = self.channel.conn.get_page(msg.payload.shared_pages()[0]);
                }
            }
        }

        self.channel
            .tcp_stream_dropped(self.handle, self.subchannel_idx);
    }
}

impl TcpStream {
    fn ack_rx(&self) {
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_RX_ACK;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = self.next_rx_seq.load(Ordering::Relaxed) - 1;
        self.channel.send_msg(req);
    }

    fn tcp_state(&self) -> api_net::TcpState {
        api_net::TcpState::try_from(self.tcp_state.load(Ordering::Relaxed)).unwrap()
    }

    // Note: this is called from the IO thread, so must not sleep.
    fn process_incoming_msg(&self, msg: io_channel::Msg) {
        match msg.command {
            api_net::CMD_TCP_STREAM_RX => {
                self.recv_queue.lock().push_back(msg);
            }
            api_net::EVT_TCP_STREAM_STATE_CHANGED => {
                self.tcp_state
                    .store(msg.payload.args_32()[0], Ordering::Relaxed);
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
    ) -> Result<Arc<TcpStream>, ErrorCode> {
        let channel = NET.lock().reserve_channel();
        let subchannel_idx = channel.reserve_subchannel();
        let subchannel_mask = api_net::io_subchannel_mask(subchannel_idx);

        let req = if let Some(timo) = timeout {
            api_net::tcp_stream_connect_timeout_request(
                socket_addr,
                subchannel_mask,
                Instant::now() + timo,
            )
        } else {
            api_net::tcp_stream_connect_request(socket_addr, subchannel_mask)
        };

        let resp = channel.send_receive(req);
        if resp.status() != moto_rt::E_OK {
            #[cfg(debug_assertions)]
            moto_log!(
                "{}:{} TcpStream::connect {:?} failed",
                file!(),
                line!(),
                socket_addr,
            );

            channel.release_subchannel(subchannel_idx);
            NET.lock().release_channel(channel.clone());
            return Err(resp.status());
        }

        let inner = Arc::new(TcpStream {
            local_addr: api_net::get_socket_addr(&resp.payload).unwrap(),
            remote_addr: *socket_addr,
            handle: resp.handle,
            channel: channel.clone(),
            recv_queue: Mutex::new(VecDeque::new()),
            next_rx_seq: AtomicU64::new(1),
            rx_buf: Mutex::new(None),
            rx_waiter: Mutex::new(None),
            tcp_state: AtomicU32::new(api_net::TcpState::ReadWrite.into()),
            rx_done: AtomicBool::new(false),
            rx_timeout_ns: AtomicU64::new(u64::MAX),
            tx_timeout_ns: AtomicU64::new(u64::MAX),
            subchannel_idx,
            subchannel_mask,
            stats_rx_bytes: AtomicU64::new(0),
            stats_tx_bytes: AtomicU64::new(0),
        });

        channel.tcp_stream_created(&inner);
        inner.ack_rx();

        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} new outgoing TcpStream {:?} -> {:?} 0x{:x}",
            file!(),
            line!(),
            inner.local_addr,
            inner.remote_addr,
            inner.handle
        );

        Ok(inner)
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

    fn peek(&self, _buf: &mut [u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    fn process_rx_message(&self, buf: &mut [u8], msg: io_channel::Msg) -> Result<usize, ErrorCode> {
        fence(Ordering::SeqCst);
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
            self.rx_done.store(true, Ordering::Release);
            #[cfg(debug_assertions)]
            moto_log!(
                "{}:{} RX closed for stream 0x{:x} rx_seq {}",
                file!(),
                line!(),
                msg.handle,
                rx_seq
            );
            return Ok(0);
        }

        let io_page = self
            .channel
            .conn
            .get_page(msg.payload.shared_pages()[0])
            .unwrap();
        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} incoming {} bytes for stream 0x{:x} rx_seq {}",
            file!(),
            line!(),
            sz_read,
            msg.handle,
            rx_seq
        );

        self.stats_rx_bytes
            .fetch_add(sz_read as u64, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} stream 0x{:x}: total RX bytes {}",
            file!(),
            line!(),
            msg.handle,
            self.stats_rx_bytes.load(Ordering::Relaxed)
        );
        let sz_read = if sz_read > buf.len() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    io_page.bytes().as_ptr(),
                    buf.as_mut_ptr(),
                    buf.len(),
                );
            }

            let mut buf_lock = self.rx_buf.lock();
            let rx_buf = &mut *buf_lock;
            assert!(rx_buf.is_none());
            *rx_buf = Some(RxBuf {
                page: io_page,
                len: sz_read,
                consumed: buf.len(),
            });
            buf.len()
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(io_page.bytes().as_ptr(), buf.as_mut_ptr(), sz_read);
            }
            sz_read
        };

        return Ok(sz_read);
    }

    fn poll_rx(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        {
            let mut buf_lock = self.rx_buf.lock();
            if let Some(rx_buf) = &mut *buf_lock {
                let sz_read = buf.len().min(rx_buf.available());
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        rx_buf.bytes().as_ptr(),
                        buf.as_mut_ptr(),
                        sz_read,
                    );
                }

                rx_buf.consume(sz_read);
                if rx_buf.is_consumed() {
                    *buf_lock = None;
                }

                return Ok(sz_read);
            }
        }

        {
            if let Some(msg) = self.recv_queue.lock().pop_front() {
                return self.process_rx_message(buf, msg);
            }
        }

        if self.rx_done.load(Ordering::Relaxed) {
            return Ok(0);
        }

        Err(moto_rt::E_NOT_READY)
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        match self.poll_rx(buf) {
            Ok(sz) => return Ok(sz),
            Err(err) => assert_eq!(err, moto_rt::E_NOT_READY),
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

            match self.poll_rx(buf) {
                Ok(sz) => return Ok(sz),
                Err(err) => assert_eq!(err, moto_rt::E_NOT_READY),
            }
            {
                // Store this thread's handle so that it is woken when an RX message arrives.
                *self.rx_waiter.lock() =
                    Some(moto_sys::UserThreadControlBlock::get().self_handle.into());
            }

            // Re-check for incoming messages.
            match self.poll_rx(buf) {
                Ok(sz) => {
                    *self.rx_waiter.lock() = None;
                    return Ok(sz);
                }
                Err(err) => assert_eq!(err, moto_rt::E_NOT_READY),
            }

            // Note: even if the socket is closed, there can be RX packets buffered
            // in sys-io, so we don't stop reading until we get a zero-length packet.

            // Note: this thread will be woken because we stored its handle in stream_entry.1 above.
            self.channel.maybe_wake_io_thread();

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

    pub fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        if buf.len() == 0 {
            return Ok(0);
        }

        if !self.tcp_state().can_write() {
            return Ok(0);
        }

        let timestamp = Instant::now();
        let write_sz = buf.len().min(io_channel::PAGE_SIZE);
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

            match self.channel.conn.alloc_page(self.subchannel_mask) {
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
                            u64::from(self.handle)
                        );
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
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                io_page.bytes_mut().as_mut_ptr(),
                write_sz,
            );
        }

        let msg = api_net::tcp_stream_tx_msg(self.handle, io_page, write_sz, timestamp.as_u64());
        self.channel.send_msg(msg);
        self.stats_tx_bytes
            .fetch_add(write_sz as u64, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} stream 0x{:x} TX bytes {}",
            file!(),
            line!(),
            self.handle,
            self.stats_tx_bytes.load(Ordering::Relaxed)
        );
        Ok(write_sz)
    }

    fn peer_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }

    fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        Ok(self.local_addr)
    }

    fn shutdown(&self, read: bool, write: bool) -> ErrorCode {
        assert!(read || write);
        let mut option = 0_u64;
        if read {
            option |= api_net::TCP_OPTION_SHUT_RD;
        }
        if write {
            option |= api_net::TCP_OPTION_SHUT_WR;
        }

        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_SET_OPTION;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = option;
        let resp = self.channel.send_receive(req);

        if resp.status() == moto_rt::E_OK {
            self.tcp_state
                .store(resp.payload.args_32()[5], Ordering::Relaxed);
            moto_rt::E_OK
        } else {
            resp.status()
        }
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
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_NODELAY;
        req.payload.args_64_mut()[1] = nodelay as u64;
        self.channel.send_receive(req).status()
    }

    fn nodelay(&self) -> Result<u8, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_GET_OPTION;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_NODELAY;
        let resp = self.channel.send_receive(req);

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
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        req.payload.args_32_mut()[2] = ttl;
        self.channel.send_receive(req).status()
    }

    fn ttl(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::CMD_TCP_STREAM_GET_OPTION;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        let resp = self.channel.send_receive(req);

        if resp.status() == moto_rt::E_OK {
            Ok(resp.payload.args_32()[0])
        } else {
            Err(resp.status())
        }
    }

    fn take_error(&self) -> Result<Option<ErrorCode>, ErrorCode> {
        // We don't have this unixism.
        Ok(None)
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), ErrorCode> {
        todo!()
    }
}

pub struct TcpListener {
    socket_addr: SocketAddr,
    channel: Arc<NetChannel>,
    handle: u64,
    nonblocking: AtomicBool,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut msg = io_channel::Msg::new();
        msg.command = api_net::CMD_TCP_LISTENER_DROP;
        msg.handle = self.handle;
        self.channel.send_msg(msg);
        self.channel.tcp_listener_dropped(self.handle)
    }
}

impl TcpListener {
    fn bind(socket_addr: &SocketAddr) -> Result<Arc<TcpListener>, ErrorCode> {
        let req = api_net::bind_tcp_listener_request(socket_addr, None);
        let channel = NET.lock().reserve_channel();
        let resp = channel.send_receive(req);
        if resp.status() != moto_rt::E_OK {
            NET.lock().release_channel(channel);
            return Err(resp.status());
        }

        let inner = Arc::new(TcpListener {
            socket_addr: *socket_addr,
            channel: channel.clone(),
            handle: resp.handle,
            nonblocking: AtomicBool::new(false),
        });
        channel.tcp_listener_created(&inner);

        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} new TcpListener {:?}",
            file!(),
            line!(),
            inner.socket_addr
        );

        Ok(inner)
    }

    fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        Ok(self.socket_addr)
    }

    fn accept(&self) -> Result<(Arc<TcpStream>, SocketAddr), ErrorCode> {
        // Because a listener can spawn thousands, millions of sockets
        // (think a long-running web server), we cannot use the listener's
        // channel for incoming connections.

        if self.nonblocking.load(Ordering::Relaxed) {
            todo!()
        }
        let channel = NET.lock().reserve_channel();
        let subchannel_idx = channel.reserve_subchannel();
        let subchannel_mask = api_net::io_subchannel_mask(subchannel_idx);

        let req = api_net::accept_tcp_listener_request(self.handle, subchannel_mask);
        let resp = channel.send_receive(req);
        if resp.status() != moto_rt::E_OK {
            channel.release_subchannel(subchannel_idx);
            NET.lock().release_channel(channel);
            return Err(resp.status());
        }

        let remote_addr = api_net::get_socket_addr(&resp.payload).unwrap();

        let inner = Arc::new(TcpStream {
            local_addr: self.socket_addr,
            remote_addr: remote_addr.clone(),
            handle: resp.handle,
            channel: channel.clone(),
            recv_queue: Mutex::new(VecDeque::new()),
            next_rx_seq: AtomicU64::new(1),
            rx_buf: Mutex::new(None),
            rx_waiter: Mutex::new(None),
            tcp_state: AtomicU32::new(api_net::TcpState::ReadWrite.into()),
            rx_done: AtomicBool::new(false),
            rx_timeout_ns: AtomicU64::new(u64::MAX),
            tx_timeout_ns: AtomicU64::new(u64::MAX),
            subchannel_idx,
            subchannel_mask,
            stats_rx_bytes: AtomicU64::new(0),
            stats_tx_bytes: AtomicU64::new(0),
        });

        channel.tcp_stream_created(&inner);
        inner.ack_rx();

        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} new incoming TcpStream {:?} <- {:?} mask: 0x{:x}",
            file!(),
            line!(),
            inner.local_addr,
            inner.remote_addr,
            inner.subchannel_mask
        );

        Ok((inner, remote_addr))
    }

    fn set_ttl(&self, _ttl: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    fn ttl(&self) -> Result<u32, ErrorCode> {
        todo!()
    }

    fn set_only_v6(&self, _: bool) -> Result<(), ErrorCode> {
        Err(moto_rt::E_NOT_IMPLEMENTED) // This is deprected since Rust 1.16
    }

    fn only_v6(&self) -> Result<bool, ErrorCode> {
        Err(moto_rt::E_NOT_IMPLEMENTED) // This is deprected since Rust 1.16
    }

    fn take_error(&self) -> Result<Option<ErrorCode>, ErrorCode> {
        // We don't have this unixism.
        Ok(None)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<(), ErrorCode> {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
        if nonblocking {
            todo!("Kick existing blocking accept()s.");
        }
        Ok(())
    }
}
