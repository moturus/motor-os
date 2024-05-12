use crate::rt_api;
use crate::util::ArrayQueue;
use crate::util::CachePadded;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::sync::Weak;
use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
use core::net::SocketAddr;
use core::net::SocketAddrV4;
use core::sync::atomic::*;
use core::time::Duration;
use moto_ipc::io_channel;
use moto_sys::time::Instant;
use moto_sys::ErrorCode;
use moto_sys::SysHandle;

// #[cfg(debug_assertions)]
use super::util::moturus_log;

static NET: crate::mutex::Mutex<NetRuntime> = crate::mutex::Mutex::new(NetRuntime {
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
    fn on_channel_available(&mut self, channel: &Arc<NetChannel>) {
        if let Some(channel) = self.full_channels.remove(&channel.id()) {
            self.channels.insert(channel.id(), channel);
        }
    }

    fn reserve_channel(&mut self) -> Arc<NetChannel> {
        let channel = if let Some(entry) = self.channels.first_entry() {
            entry.get().reservations.fetch_add(1, Ordering::Relaxed);
            entry.get().clone()
        } else {
            let channel = NetChannel::new();
            channel.reservations.fetch_add(1, Ordering::Relaxed);
            self.channels.insert(channel.id(), channel.clone());
            channel
        };

        if channel.at_capacity() {
            self.channels.remove(&channel.id());
            self.full_channels.insert(channel.id(), channel.clone());
        }

        channel
    }

    fn release_channel(&mut self, channel: Arc<NetChannel>) {
        channel.reservations.fetch_sub(0, Ordering::Relaxed);
        self.on_channel_available(&channel);
    }
}

struct NetChannel {
    conn: io_channel::ClientConnection,

    // We use weak references to TcpStream below because ultimately the user
    // owns tcp streams, and we want to clear things away when the user drops them.
    tcp_streams:
        crate::external::spin::Mutex<BTreeMap<u64, (Weak<TcpStreamImpl>, Option<SysHandle>)>>,

    tcp_listeners: crate::external::spin::Mutex<BTreeMap<u64, Weak<TcpListenerImpl>>>,

    reservations: AtomicUsize,

    next_msg_id: AtomicU64,

    this_thread_is_sender: CachePadded<AtomicBool>,
    send_queue: crate::util::ArrayQueue<io_channel::Msg>,

    this_thread_is_receiver: CachePadded<AtomicBool>,
    // Map resp_id => (thread handle, resp).
    recv_waiters: crate::external::spin::Mutex<BTreeMap<u64, (SysHandle, Option<io_channel::Msg>)>>,
}

impl NetChannel {
    // Max TCP/UDP sockets per channel.
    const MAX_SOCKETS: usize = 16;

    fn id(&self) -> u64 {
        self.conn.server_handle().into()
    }

    fn new() -> Arc<Self> {
        Arc::new(NetChannel {
            conn: io_channel::ClientConnection::connect("sys-io").unwrap(),
            tcp_streams: crate::external::spin::Mutex::new(BTreeMap::new()),
            tcp_listeners: crate::external::spin::Mutex::new(BTreeMap::new()),
            reservations: AtomicUsize::new(0),
            next_msg_id: AtomicU64::new(1),
            this_thread_is_sender: CachePadded::new(AtomicBool::new(false)),
            send_queue: crate::util::ArrayQueue::new(io_channel::CHANNEL_PAGE_COUNT),
            this_thread_is_receiver: CachePadded::new(AtomicBool::new(false)),
            recv_waiters: crate::external::spin::Mutex::new(BTreeMap::new()),
        })
    }

    fn at_capacity(&self) -> bool {
        self.reservations.load(Ordering::Relaxed)
            + self.tcp_streams.lock().len()
            + self.tcp_listeners.lock().len()
            == Self::MAX_SOCKETS
    }

    fn tcp_stream_created(self: &Arc<Self>, stream: &Arc<TcpStreamImpl>) {
        self.tcp_streams
            .lock()
            .insert(stream.handle, (Arc::downgrade(stream), None));
    }

    fn tcp_stream_dropped(self: &Arc<Self>, handle: u64) {
        assert_eq!(
            0,
            self.tcp_streams
                .lock()
                .remove(&handle)
                .unwrap()
                .0
                .strong_count()
        );

        NET.lock().on_channel_available(self);
    }

    fn tcp_listener_created(self: &Arc<Self>, listener: &Arc<TcpListenerImpl>) {
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

        NET.lock().on_channel_available(self);
    }

    fn wait_for_resp(self: &Arc<Self>, resp_id: u64) -> io_channel::Msg {
        loop {
            self.receive_or_wait_handle_set(None);

            {
                let mut recv_waiters = self.recv_waiters.lock();
                if let Some(resp) = recv_waiters.get_mut(&resp_id).unwrap().1.take() {
                    recv_waiters.remove(&resp_id);
                    return resp;
                }
            }
            // Give another thread a chance to become the receiver.
            let _ = moto_sys::syscalls::SysCpu::wait(
                &mut [],
                SysHandle::NONE,
                SysHandle::NONE,
                Some(moto_sys::time::Instant::now() + Duration::from_micros(5)),
            );
        }
    }

    // Send message and wait for response.
    fn send_receive(self: &Arc<Self>, mut req: io_channel::Msg) -> io_channel::Msg {
        let req_id = self.next_msg_id.fetch_add(1, Ordering::Relaxed);

        // Add to waiters before sending the message, otherwise the response may
        // arive too quickly and the receiving code will panic due to a missing waiter.
        self.recv_waiters.lock().insert(
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

    fn receive_or_wait_handle_set(self: &Arc<Self>, timeout: Option<Instant>) {
        if !self.this_thread_is_receiver.swap(true, Ordering::AcqRel) {
            self.do_receive_messages(timeout);
            self.this_thread_is_receiver.store(false, Ordering::Release);
        } else {
            // Note: this function is only called if a wait_handle is set (that's its name!),
            //       so this thread will be woken for sure (inless the wake is lost, but
            //       this is the kernel's problem).
            let _ = moto_sys::syscalls::SysCpu::wait(
                &mut [],
                SysHandle::NONE,
                SysHandle::NONE,
                timeout,
            );
        }
    }

    fn on_orphan_message(self: &Arc<Self>, msg: io_channel::Msg) {
        match msg.command {
            rt_api::net::CMD_TCP_STREAM_RX => {
                // RX raced with the client dropping the sream. Need to get page to free it.
                let sz_read = msg.payload.args_64()[1];
                if sz_read > 0 {
                    let _ = self.conn.get_page(msg.payload.shared_pages()[0]);
                }
            }
            rt_api::net::EVT_TCP_STREAM_STATE_CHANGED => {}
            _ => {
                // #[cfg(debug_assertions)]
                // This is logged always because if a new incoming message is added that
                // has to be handled but is not, we may have a problem.
                moturus_log!(
                    "{}:{} orphan incoming message {} for 0x{:x}; release i/o page?",
                    file!(),
                    line!(),
                    msg.command,
                    msg.handle
                );
            }
        }
    }

    fn poll_messages(self: &Arc<Self>) -> usize {
        let result;
        if !self.this_thread_is_receiver.swap(true, Ordering::AcqRel) {
            result = self.do_poll_messages();
            self.this_thread_is_receiver.store(false, Ordering::Release);
        } else {
            result = 0;
        }

        result
    }

    // Poll messages, if any. Returns the number of messages polled (capped).
    fn do_poll_messages(self: &Arc<Self>) -> usize {
        let mut received_messages = 0;

        while let Ok(msg) = self.conn.recv() {
            received_messages += 1;

            let wait_handle: Option<SysHandle> = if msg.id == 0 {
                // This is an incoming packet, or similar.
                let handle = msg.handle;
                {
                    let mut tcp_streams = self.tcp_streams.lock();
                    if let Some(s) = tcp_streams.get_mut(&handle) {
                        if let Some(stream) = s.0.upgrade() {
                            match msg.command {
                                rt_api::net::CMD_TCP_STREAM_RX => {
                                    #[cfg(debug_assertions)]
                                    moturus_log!(
                                        "{}:{} got recv msg {}",
                                        file!(),
                                        line!(),
                                        msg.command
                                    );
                                    stream.recv_queue.push(msg).unwrap(); // TODO: handle error?
                                }
                                rt_api::net::EVT_TCP_STREAM_STATE_CHANGED => {
                                    #[cfg(debug_assertions)]
                                    moturus_log!(
                                        "{}:{}: got STATE EVENT {:?} for 0x{:x}",
                                        file!(),
                                        line!(),
                                        rt_api::net::TcpState::try_from(msg.payload.args_32()[0]),
                                        msg.handle
                                    );
                                    stream
                                        .tcp_state
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

                            // Return the handle of a sleeping/reading thread, if any.
                            s.1.take()
                        } else {
                            self.on_orphan_message(msg);
                            tcp_streams.remove(&handle);
                            continue;
                        }
                    } else {
                        self.on_orphan_message(msg);
                        continue;
                    }
                }
            } else {
                let mut recv_waiters = self.recv_waiters.lock();
                if let Some((handle, resp)) = recv_waiters.get_mut(&msg.id) {
                    *resp = Some(msg);
                    Some(*handle)
                } else {
                    panic!("unexpected msg");
                }
            };

            if let Some(wait_handle) = wait_handle {
                if wait_handle.as_u64() != moto_sys::UserThreadControlBlock::get().self_handle {
                    let _ = moto_sys::syscalls::SysCpu::wake(wait_handle);
                }
            }

            if received_messages > 32 {
                return received_messages;
            }
        }

        received_messages
    }

    // This will return when the receive queue is empty or after N messages have been received.
    fn do_receive_messages(self: &Arc<Self>, timeout: Option<Instant>) {
        loop {
            if let Some(timeout) = timeout {
                if Instant::now() >= timeout {
                    return;
                }
            }

            if self.do_poll_messages() > 0 {
                return;
            }

            let server_handle = self.conn.server_handle();
            let _ = moto_sys::syscalls::SysCpu::wait(
                &mut [server_handle],
                SysHandle::NONE,
                SysHandle::NONE,
                timeout,
            );
        }
    }

    // This will return when either the send queue is empty or there is an active sender.
    // Returns true if any messages have been sent.
    fn send_messages(self: &Arc<Self>) {
        loop {
            if self.this_thread_is_sender.swap(true, Ordering::AcqRel) {
                return;
            }

            // This thread is now the writer.
            let mut sent_messages = 0;
            while let Some(msg) = self.send_queue.pop() {
                sent_messages += 1;
                if sent_messages > 32 {
                    break;
                }

                loop {
                    match self.conn.send(msg) {
                        Ok(()) => break,
                        Err(err) => {
                            assert_eq!(err, ErrorCode::NotReady);
                            let server_handle = self.conn.server_handle();
                            let _ = moto_sys::syscalls::SysCpu::wait(
                                &mut [server_handle],
                                SysHandle::NONE,
                                server_handle,
                                None,
                            );
                            continue;
                        }
                    }
                }
            }

            self.this_thread_is_sender.store(false, Ordering::Release);
            let _ = moto_sys::syscalls::SysCpu::wake(self.conn.server_handle());

            if self.send_queue.is_empty() {
                return;
            } else {
                // Give another thread a chance to become the sender.
                let _ = moto_sys::syscalls::SysCpu::wait(
                    &mut [],
                    SysHandle::NONE,
                    SysHandle::NONE,
                    Some(moto_sys::time::Instant::now() + Duration::from_micros(5)),
                );
            }
        }
    }

    // Sends a write message or queues it.
    fn send_msg(self: &Arc<Self>, msg: io_channel::Msg) {
        while self.send_queue.push(msg).is_err() {} // TODO: be smarter?
        self.send_messages();
    }

    fn alloc_page(self: &Arc<Self>, timeout_ns: u64) -> Result<io_channel::IoPage, ErrorCode> {
        let timeout = if timeout_ns == u64::MAX {
            None
        } else {
            Some(Instant::now() + Duration::from_nanos(timeout_ns))
        };

        loop {
            if let Some(timeout) = timeout {
                if Instant::now() >= timeout {
                    return Err(ErrorCode::TimedOut);
                }
            }

            if let Ok(page) = self.conn.alloc_page() {
                return Ok(page);
            }

            if self.send_queue.is_empty() {
                let _ = moto_sys::syscalls::SysCpu::wait(
                    &mut [],
                    SysHandle::NONE,
                    SysHandle::NONE,
                    Some(moto_sys::time::Instant::now() + Duration::from_micros(50)),
                );
            } else {
                self.send_messages();
            }
        }
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

pub struct TcpStreamImpl {
    channel: Arc<NetChannel>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    handle: u64,
    recv_queue: ArrayQueue<io_channel::Msg>,
    next_rx_seq: AtomicU64,

    // A partially consumed incoming RX.
    rx_buf: crate::external::spin::Mutex<Option<RxBuf>>,

    tcp_state: AtomicU32, // rt_api::TcpState
    rx_done: AtomicBool,

    rx_timeout_ns: AtomicU64,
    tx_timeout_ns: AtomicU64,
}

impl Drop for TcpStreamImpl {
    fn drop(&mut self) {
        let mut req = io_channel::Msg::new();
        req.command = rt_api::net::CMD_TCP_STREAM_DROP;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = self.next_rx_seq.load(Ordering::Relaxed) - 1;
        #[cfg(debug_assertions)]
        moturus_log!(
            "{}:{} sending rx_ack {}",
            file!(),
            line!(),
            req.payload.args_64_mut()[0]
        );
        self.channel.send_msg(req);
        self.channel.tcp_stream_dropped(self.handle);
    }
}

impl TcpStreamImpl {
    fn ack_rx(&self) {
        let mut req = io_channel::Msg::new();
        req.command = rt_api::net::CMD_TCP_STREAM_RX_ACK;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = self.next_rx_seq.load(Ordering::Relaxed) - 1;
        #[cfg(debug_assertions)]
        moturus_log!(
            "{}:{} sending rx_ack {}",
            file!(),
            line!(),
            req.payload.args_64_mut()[0]
        );
        self.channel.send_msg(req);
    }

    fn tcp_state(&self) -> rt_api::net::TcpState {
        rt_api::net::TcpState::try_from(self.tcp_state.load(Ordering::Relaxed)).unwrap()
    }
}

pub struct TcpStream {
    inner: Arc<TcpStreamImpl>,
}

impl TcpStream {
    fn connect_impl(
        socket_addr: &SocketAddr,
        timeout: Option<Duration>,
    ) -> Result<TcpStream, ErrorCode> {
        #[cfg(debug_assertions)]
        moturus_log!(
            "{}:{} TcpStream::connect {:?} started",
            file!(),
            line!(),
            socket_addr,
        );

        let channel = NET.lock().reserve_channel();
        let req = if let Some(timo) = timeout {
            rt_api::net::tcp_stream_connect_timeout_request(
                socket_addr,
                moto_sys::time::Instant::now() + timo,
            )
        } else {
            crate::rt_api::net::tcp_stream_connect_request(socket_addr)
        };

        let resp = channel.send_receive(req);
        if resp.status().is_err() {
            #[cfg(debug_assertions)]
            moturus_log!(
                "{}:{} TcpStream::connect {:?} failed",
                file!(),
                line!(),
                socket_addr,
            );

            NET.lock().release_channel(channel.clone());
            return Err(resp.status());
        }

        let inner = Arc::new(TcpStreamImpl {
            local_addr: rt_api::net::get_socket_addr(&resp.payload).unwrap(),
            remote_addr: *socket_addr,
            handle: resp.handle,
            channel: channel.clone(),
            recv_queue: ArrayQueue::new(io_channel::CHANNEL_PAGE_COUNT),
            next_rx_seq: AtomicU64::new(1),
            rx_buf: crate::external::spin::Mutex::new(None),
            tcp_state: AtomicU32::new(rt_api::net::TcpState::ReadWrite.into()),
            rx_done: AtomicBool::new(false),
            rx_timeout_ns: AtomicU64::new(u64::MAX),
            tx_timeout_ns: AtomicU64::new(u64::MAX),
        });

        channel.tcp_stream_created(&inner);
        NET.lock().release_channel(channel);
        inner.ack_rx();

        #[cfg(debug_assertions)]
        moturus_log!(
            "{}:{} new outgoing TcpStream {:?} -> {:?}",
            file!(),
            line!(),
            inner.local_addr,
            inner.remote_addr
        );

        Ok(Self { inner })
    }

    pub fn connect(socket_addr: &SocketAddr) -> Result<TcpStream, ErrorCode> {
        Self::connect_impl(socket_addr, None)
    }

    pub fn connect_timeout(
        socket_addr: &SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, ErrorCode> {
        Self::connect_impl(socket_addr, Some(timeout))
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), ErrorCode> {
        let timo_ns = if let Some(timo) = timeout {
            if timo.as_nanos() > (u64::MAX as u128) {
                u64::MAX
            } else {
                timo.as_nanos() as u64
            }
        } else {
            u64::MAX
        };

        self.inner.rx_timeout_ns.store(timo_ns, Ordering::Relaxed);
        Ok(())
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), ErrorCode> {
        let timo_ns = if let Some(timo) = timeout {
            if timo.as_nanos() > (u64::MAX as u128) {
                u64::MAX
            } else {
                timo.as_nanos() as u64
            }
        } else {
            u64::MAX
        };

        self.inner.tx_timeout_ns.store(timo_ns, Ordering::Relaxed);
        Ok(())
    }

    pub fn read_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        let timo_ns = self.inner.rx_timeout_ns.load(Ordering::Relaxed);
        if timo_ns == u64::MAX {
            Ok(None)
        } else {
            Ok(Some(Duration::from_nanos(timo_ns)))
        }
    }

    pub fn write_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        let timo_ns = self.inner.tx_timeout_ns.load(Ordering::Relaxed);
        if timo_ns == u64::MAX {
            Ok(None)
        } else {
            Ok(Some(Duration::from_nanos(timo_ns)))
        }
    }

    pub fn peek(&self, _buf: &mut [u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    fn process_rx_message(&self, buf: &mut [u8], msg: io_channel::Msg) -> Result<usize, ErrorCode> {
        assert_eq!(msg.command, crate::rt_api::net::CMD_TCP_STREAM_RX);
        let sz_read = msg.payload.args_64()[1] as usize;
        let rx_seq_incoming = msg.payload.args_64()[2];
        let rx_seq = self.inner.next_rx_seq.fetch_add(1, Ordering::Relaxed);
        assert_eq!(rx_seq, rx_seq_incoming);
        if rx_seq & (crate::rt_api::net::TCP_RX_MAX_INFLIGHT - 1) == 0 {
            self.inner.ack_rx();
        }

        if sz_read == 0 {
            assert_eq!(msg.payload.shared_pages()[0], u16::MAX);
            self.inner.rx_done.store(true, Ordering::Release);
            #[cfg(debug_assertions)]
            moturus_log!(
                "{}:{} RX closed for stream 0x{:x} rx_seq {}",
                file!(),
                line!(),
                msg.handle,
                rx_seq
            );
            return Ok(0);
        }

        let io_page = self
            .inner
            .channel
            .conn
            .get_page(msg.payload.shared_pages()[0]);
        #[cfg(debug_assertions)]
        moturus_log!(
            "{}:{} incoming {} bytes for stream 0x{:x} rx_seq {}",
            file!(),
            line!(),
            sz_read,
            msg.handle,
            rx_seq
        );

        let sz_read = if sz_read > buf.len() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    io_page.bytes().as_ptr(),
                    buf.as_mut_ptr(),
                    buf.len(),
                );
            }

            let mut buf_lock = self.inner.rx_buf.lock();
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

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        {
            let mut buf_lock = self.inner.rx_buf.lock();
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

        let rx_timeout_ns = self.inner.rx_timeout_ns.load(Ordering::Relaxed);
        let rx_timeout = if rx_timeout_ns == u64::MAX {
            None
        } else {
            Some(moto_sys::time::Instant::now() + Duration::from_nanos(rx_timeout_ns))
        };

        let handle = self.inner.handle;
        loop {
            if let Some(timeout) = rx_timeout {
                if Instant::now() >= timeout {
                    return Err(ErrorCode::TimedOut);
                }
            }
            let msg = {
                let mut streams_lock = self.inner.channel.tcp_streams.lock();
                let stream_entry = streams_lock.get_mut(&handle).unwrap();
                if let Some(msg) = stream_entry.0.upgrade().unwrap().recv_queue.pop() {
                    Some(msg)
                } else {
                    if self.inner.rx_done.load(Ordering::Relaxed) {
                        return Ok(0);
                    }

                    // Store this thread's handle so that it is woken when an RX message arrives.
                    stream_entry.1 =
                        Some(moto_sys::UserThreadControlBlock::get().self_handle.into());
                    None
                }
            };

            if let Some(msg) = msg {
                return self.process_rx_message(buf, msg);
            } else {
                // Note: even if the socket is closed, there can be RX packets buffered
                // in sys-io, so we don't stop reading until we get a zero-length packet.

                // Note: this thread will be woken because we stored its handle i stream_entry.1 above.
                self.inner.channel.receive_or_wait_handle_set(rx_timeout);
            }
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        if buf.len() == 0 {
            return Ok(0);
        }

        if !self.inner.tcp_state().can_write() {
            return Ok(0);
        }

        if self.inner.channel.poll_messages() > 0 {
            if !self.inner.tcp_state().can_write() {
                return Ok(0);
            }
        }

        let timestamp = moto_sys::time::Instant::now().as_u64();

        let write_sz = buf.len().min(io_channel::PAGE_SIZE);
        let io_page = self
            .inner
            .channel
            .alloc_page(self.inner.tx_timeout_ns.load(Ordering::Relaxed))?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                io_page.bytes_mut().as_mut_ptr(),
                write_sz,
            );
        }

        let msg = rt_api::net::tcp_stream_tx_msg(self.inner.handle, io_page, write_sz, timestamp);

        self.inner.channel.send_msg(msg);
        Ok(write_sz)
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, ErrorCode> {
        Ok(self.inner.remote_addr)
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        Ok(self.inner.local_addr)
    }

    pub fn shutdown(&self, read: bool, write: bool) -> Result<(), ErrorCode> {
        assert!(read || write);
        let mut option = 0_u64;
        if read {
            option |= rt_api::net::TCP_OPTION_SHUT_RD;
        }
        if write {
            option |= rt_api::net::TCP_OPTION_SHUT_WR;
        }

        let mut req = io_channel::Msg::new();
        req.command = rt_api::net::CMD_TCP_STREAM_SET_OPTION;
        req.handle = self.inner.handle;
        req.payload.args_64_mut()[0] = option;
        let resp = self.inner.channel.send_receive(req);

        if resp.status().is_ok() {
            self.inner
                .tcp_state
                .store(resp.payload.args_32()[5], Ordering::Relaxed);
            Ok(())
        } else {
            Err(resp.status())
        }
    }

    pub fn duplicate(&self) -> Result<TcpStream, ErrorCode> {
        Ok(TcpStream {
            inner: self.inner.clone(),
        })
    }

    pub fn set_linger(&self, dur: Option<Duration>) -> Result<(), ErrorCode> {
        if let Some(dur) = dur {
            if dur == Duration::ZERO {
                return Ok(());
            }
        }

        // At the moment, socket shutdown or drop drops all unsent bytes, which
        // corresponds to SO_LINGER(0). This may or may not be what the user
        // wants, but anything different requires changing sys-io code/logic,
        // at there are higher-priority work to do.
        Err(ErrorCode::NotImplemented)
    }

    pub fn linger(&self) -> Result<Option<Duration>, ErrorCode> {
        Ok(Some(Duration::ZERO)) // see set_linger() above.
    }

    pub fn set_nodelay(&self, nodelay: bool) -> Result<(), ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = rt_api::net::CMD_TCP_STREAM_SET_OPTION;
        req.handle = self.inner.handle;
        req.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_NODELAY;
        req.payload.args_64_mut()[1] = if nodelay { 1 } else { 0 };
        let resp = self.inner.channel.send_receive(req);

        if resp.status().is_ok() {
            Ok(())
        } else {
            Err(resp.status())
        }
    }

    pub fn nodelay(&self) -> Result<bool, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = rt_api::net::CMD_TCP_STREAM_GET_OPTION;
        req.handle = self.inner.handle;
        req.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_NODELAY;
        let resp = self.inner.channel.send_receive(req);

        if resp.status().is_ok() {
            let res = resp.payload.args_64()[0];
            if res == 1 {
                Ok(true)
            } else if res == 0 {
                Ok(false)
            } else {
                panic!("Unexpected nodelay value: {}", res)
            }
        } else {
            Err(resp.status())
        }
    }

    pub fn set_ttl(&self, ttl: u32) -> Result<(), ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = rt_api::net::CMD_TCP_STREAM_SET_OPTION;
        req.handle = self.inner.handle;
        req.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_TTL;
        req.payload.args_32_mut()[2] = ttl;
        let resp = self.inner.channel.send_receive(req);

        if resp.status().is_ok() {
            Ok(())
        } else {
            Err(resp.status())
        }
    }

    pub fn ttl(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = rt_api::net::CMD_TCP_STREAM_GET_OPTION;
        req.handle = self.inner.handle;
        req.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_TTL;
        let resp = self.inner.channel.send_receive(req);

        if resp.status().is_ok() {
            Ok(resp.payload.args_32()[0])
        } else {
            Err(resp.status())
        }
    }

    pub fn take_error(&self) -> Result<Option<ErrorCode>, ErrorCode> {
        // We don't have this unixism.
        Ok(None)
    }

    pub fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), ErrorCode> {
        todo!()
    }
}

impl core::fmt::Debug for TcpStream {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

struct TcpListenerImpl {
    socket_addr: SocketAddr,
    channel: Arc<NetChannel>,
    handle: u64,
    nonblocking: AtomicBool,
}

impl Drop for TcpListenerImpl {
    fn drop(&mut self) {
        let mut msg = io_channel::Msg::new();
        msg.command = rt_api::net::CMD_TCP_LISTENER_DROP;
        msg.handle = self.handle;
        self.channel.send_msg(msg);
        self.channel.tcp_listener_dropped(self.handle)
    }
}

pub struct TcpListener {
    inner: Arc<TcpListenerImpl>,
}

impl TcpListener {
    pub fn bind(socket_addr: &SocketAddr) -> Result<TcpListener, ErrorCode> {
        let req = rt_api::net::bind_tcp_listener_request(socket_addr);
        let channel = NET.lock().reserve_channel();
        let resp = channel.send_receive(req);
        if resp.status().is_err() {
            NET.lock().release_channel(channel);
            return Err(resp.status());
        }

        let inner = Arc::new(TcpListenerImpl {
            socket_addr: *socket_addr,
            channel: channel.clone(),
            handle: resp.handle,
            nonblocking: AtomicBool::new(false),
        });
        channel.tcp_listener_created(&inner);
        NET.lock().release_channel(channel);

        #[cfg(debug_assertions)]
        moturus_log!(
            "{}:{} new TcpListener {:?}",
            file!(),
            line!(),
            inner.socket_addr
        );

        Ok(Self { inner })
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        Ok(self.inner.socket_addr)
    }

    pub fn accept(&self) -> Result<(TcpStream, SocketAddr), ErrorCode> {
        // Because a listener can spawn thousands, millions of sockets
        // (think a long-running web server), we cannot use the listener's
        // channel for incoming connections.

        if self.inner.nonblocking.load(Ordering::Relaxed) {
            todo!()
        }
        let channel = NET.lock().reserve_channel();
        let req = rt_api::net::accept_tcp_listener_request(self.inner.handle);
        let resp = channel.send_receive(req);
        if resp.status().is_err() {
            return Err(resp.status());
        }

        let remote_addr = rt_api::net::get_socket_addr(&resp.payload).unwrap();

        let inner = Arc::new(TcpStreamImpl {
            local_addr: self.inner.socket_addr,
            remote_addr: remote_addr.clone(),
            handle: resp.handle,
            channel: channel.clone(),
            recv_queue: ArrayQueue::new(io_channel::CHANNEL_PAGE_COUNT),
            next_rx_seq: AtomicU64::new(1),
            rx_buf: crate::external::spin::Mutex::new(None),
            tcp_state: AtomicU32::new(rt_api::net::TcpState::ReadWrite.into()),
            rx_done: AtomicBool::new(false),
            rx_timeout_ns: AtomicU64::new(u64::MAX),
            tx_timeout_ns: AtomicU64::new(u64::MAX),
        });

        channel.tcp_stream_created(&inner);
        NET.lock().release_channel(channel);
        inner.ack_rx();

        #[cfg(debug_assertions)]
        moturus_log!(
            "{}:{} new incoming TcpStream {:?} <- {:?}",
            file!(),
            line!(),
            inner.local_addr,
            inner.remote_addr
        );

        Ok((TcpStream { inner }, remote_addr))
    }

    pub fn duplicate(&self) -> Result<TcpListener, ErrorCode> {
        Ok(TcpListener {
            inner: self.inner.clone(),
        })
    }

    pub fn set_ttl(&self, _ttl: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn ttl(&self) -> Result<u32, ErrorCode> {
        todo!()
    }

    pub fn set_only_v6(&self, _: bool) -> Result<(), ErrorCode> {
        Err(ErrorCode::NotImplemented) // This is deprected since Rust 1.16
    }

    pub fn only_v6(&self) -> Result<bool, ErrorCode> {
        Err(ErrorCode::NotImplemented) // This is deprected since Rust 1.16
    }

    pub fn take_error(&self) -> Result<Option<ErrorCode>, ErrorCode> {
        // We don't have this unixism.
        Ok(None)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), ErrorCode> {
        self.inner.nonblocking.store(nonblocking, Ordering::Relaxed);
        if nonblocking {
            todo!("Kick existing blocking accept()s.");
        }
        Ok(())
    }
}

impl core::fmt::Debug for TcpListener {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

pub struct UdpSocket {}

impl UdpSocket {
    pub fn bind(_: &SocketAddr) -> Result<UdpSocket, ErrorCode> {
        todo!()
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, ErrorCode> {
        todo!()
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        todo!()
    }

    pub fn recv_from(&self, _: &mut [u8]) -> Result<(usize, SocketAddr), ErrorCode> {
        todo!()
    }

    pub fn peek_from(&self, _: &mut [u8]) -> Result<(usize, SocketAddr), ErrorCode> {
        todo!()
    }

    pub fn send_to(&self, _: &[u8], _: &SocketAddr) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn duplicate(&self) -> Result<UdpSocket, ErrorCode> {
        todo!()
    }

    pub fn set_read_timeout(&self, _: Option<Duration>) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn set_write_timeout(&self, _: Option<Duration>) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn read_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        todo!()
    }

    pub fn write_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        todo!()
    }

    pub fn set_broadcast(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn broadcast(&self) -> Result<bool, ErrorCode> {
        todo!()
    }

    pub fn set_multicast_loop_v4(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn multicast_loop_v4(&self) -> Result<bool, ErrorCode> {
        todo!()
    }

    pub fn set_multicast_ttl_v4(&self, _: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn multicast_ttl_v4(&self) -> Result<u32, ErrorCode> {
        todo!()
    }

    pub fn set_multicast_loop_v6(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn multicast_loop_v6(&self) -> Result<bool, ErrorCode> {
        todo!()
    }

    pub fn join_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn join_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn leave_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn leave_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn set_ttl(&self, _: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn ttl(&self) -> Result<u32, ErrorCode> {
        todo!()
    }

    pub fn take_error(&self) -> Result<Option<ErrorCode>, ErrorCode> {
        todo!()
    }

    pub fn set_nonblocking(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn recv(&self, _: &mut [u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn peek(&self, _: &mut [u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn send(&self, _: &[u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn connect(&self, _addr: &SocketAddr) -> Result<(), ErrorCode> {
        todo!()
    }
}

impl core::fmt::Debug for UdpSocket {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

pub struct LookupHost {
    addr: SocketAddr,
    next: Option<SocketAddr>,
}

impl LookupHost {
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    fn new(addr: SocketAddr) -> Self {
        Self {
            addr: addr.clone(),
            next: Some(addr),
        }
    }
}

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        self.next.take()
    }
}

impl TryFrom<&str> for LookupHost {
    type Error = ErrorCode;

    fn try_from(v: &str) -> Result<LookupHost, ErrorCode> {
        // Split the string by ':' and convert the second part to u16.
        let (host, port_str) = v.rsplit_once(':').ok_or(ErrorCode::InvalidArgument)?;
        let port: u16 = port_str.parse().map_err(|_| ErrorCode::InvalidArgument)?;
        (host, port).try_into()
    }
}

impl<'a> TryFrom<(&'a str, u16)> for LookupHost {
    type Error = ErrorCode;

    fn try_from(host_port: (&'a str, u16)) -> Result<LookupHost, ErrorCode> {
        use core::str::FromStr;

        let (host, port) = host_port;

        if host == "localhost" {
            Ok(LookupHost::new(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                port,
            ))))
        } else if let Ok(addr_v4) = Ipv4Addr::from_str(host) {
            Ok(LookupHost::new(SocketAddr::V4(SocketAddrV4::new(
                addr_v4, port,
            ))))
        } else {
            #[cfg(debug_assertions)]
            crate::util::moturus_log!(
                "LookupHost::try_from: {}:{}: DNS lookup not implemented",
                host,
                port
            );
            Err(ErrorCode::NotImplemented)
        }
    }
}
