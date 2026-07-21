//! The UDP socket state machine (design section 5): `UdpSocket` and its
//! blocking-path futures. The vdso keeps only a thin veneer (the PosixFile
//! impl and poll-registry event synthesis); this half talks to sys-io through
//! [`super::channel`] and emits readiness through an abstract
//! [`crate::net::readiness::NetEventListener`], naming no vdso type.

use crate::net::readiness::{NetEventListener, Readiness};
use super::channel::{ChannelReservation, NetChannel};
use super::tcp::{RX_PARK_RECHECK, TX_PARK_RECHECK, block_on_recheck};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::sync::atomic::*;
use moto_io_internal::udp_queues::{UdpDefragmentingQueue, UdpFragmentingQueue};
use moto_ipc::io_channel;
use moto_rt::{E_NOT_READY, E_TIMED_OUT};
use moto_rt::{ErrorCode, mutex::Mutex};
use moto_sys_io::api_net;

pub struct UdpSocket {
    channel_reservation: ChannelReservation,
    local_addr: SocketAddr,
    handle: u64,
    // The socket's sole poll-registry handle: state-machine edges emit through
    // it (raise_readiness), and the veneer downcasts it back to the concrete
    // source for interest registration. No poll-registry type sits in the
    // struct, so the state machine is movable to moto-io (Stage F).
    event_listener: Arc<dyn NetEventListener>,
    nonblocking: AtomicBool,

    tx_queue: Mutex<UdpFragmentingQueue>,
    rx_queue: Mutex<UdpDefragmentingQueue>,

    peer_addr: Mutex<Option<SocketAddr>>,

    rx_timeout_ns: AtomicU64,
    tx_timeout_ns: AtomicU64,

    // Wakers of parked blocking recv/send futures, drained (wake-all-and-
    // recheck) at the RX / TX-ack points -- the D5 replacement for the old
    // EventSourceManaged readable/writable futex pair.
    rx_wakers: Mutex<Vec<core::task::Waker>>,
    tx_wakers: Mutex<Vec<core::task::Waker>>,

    me: Weak<UdpSocket>,
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        // Clear TX queue.
        let msg = self.tx_queue.lock().take_msg();
        if let Some(msg) = msg {
            assert_eq!(msg.command, api_net::NetCmd::UdpSocketTxRx as u16);
            let sz_read = msg.payload.args_64()[1];
            if sz_read > 0 {
                let _ = self.channel().get_page(msg.payload.shared_pages()[11]);
            }
        }

        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::UdpSocketDrop as u16;
        req.handle = self.handle();

        // Guaranteed delivery: never drop the message (sys-io would leak the
        // socket), never panic on a full send queue, and never deadlock when
        // this drop runs on the runtime thread (see send_msg_guaranteed). The
        // rx task briefly upgrades the Weak it keeps in udp_sockets, so a
        // socket whose fd is already closed drops here, on the IO thread.
        self.channel().send_msg_guaranteed(req);

        // Balance stats_udp_socket_created(): the decrement was missing, which
        // stage-E's assert_empty (now checking num_udp_sockets) would trip on.
        crate::net::channel::stats_udp_socket_dropped();
    }
}

impl UdpSocket {
    pub fn handle(&self) -> u64 {
        self.handle
    }

    pub fn weak(&self) -> Weak<Self> {
        self.me.clone()
    }

    fn channel(&self) -> &NetChannel {
        self.channel_reservation.channel()
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        *self.peer_addr.lock()
    }

    pub fn bind(
        socket_addr: &SocketAddr,
        event_listener: Arc<dyn NetEventListener>,
    ) -> Result<Arc<UdpSocket>, ErrorCode> {
        if socket_addr.port() == 0 && socket_addr.ip().is_unspecified() {
            // crate::moto_log!("we don't currently allow binding to 0.0.0.0:0");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        Self::bind_inner(socket_addr, false, event_listener)
    }

    pub fn bind_for_remote(
        remote_addr: &SocketAddr,
        event_listener: Arc<dyn NetEventListener>,
    ) -> Result<Arc<UdpSocket>, ErrorCode> {
        if remote_addr.ip().is_unspecified() {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        Self::bind_inner(remote_addr, true, event_listener)
    }

    fn bind_inner(
        requested_addr: &SocketAddr,
        select_route: bool,
        event_listener: Arc<dyn NetEventListener>,
    ) -> Result<Arc<UdpSocket>, ErrorCode> {
        let mut channel_reservation = super::channel::reserve_channel();
        channel_reservation.reserve_subchannel();
        let subchannel_mask = channel_reservation.subchannel_mask();
        let req = if select_route {
            api_net::bind_udp_socket_for_remote_request(
                requested_addr,
                channel_reservation.subchannel_idx(),
            )
        } else {
            api_net::bind_udp_socket_request(requested_addr, channel_reservation.subchannel_idx())
        };
        let resp = channel_reservation.channel().send_receive(req);
        if resp.status().is_err() {
            return Err(resp.status);
        }

        let socket_addr = api_net::get_socket_addr(&resp.payload);
        assert_ne!(0, socket_addr.port());
        if select_route {
            assert_eq!(requested_addr.is_ipv4(), socket_addr.is_ipv4());
        } else {
            assert_eq!(requested_addr.ip(), socket_addr.ip());
            if requested_addr.port() != 0 {
                assert_eq!(requested_addr.port(), socket_addr.port());
            }
        }

        let udp_socket = Arc::new_cyclic(|me| {
            UdpSocket {
                local_addr: socket_addr,
                channel_reservation,
                handle: resp.handle,
                nonblocking: AtomicBool::new(false),
                event_listener,
                tx_queue: Mutex::new(UdpFragmentingQueue::new(resp.handle, subchannel_mask)),
                peer_addr: Mutex::new(None),
                rx_queue: Mutex::new(UdpDefragmentingQueue::new()),
                rx_timeout_ns: AtomicU64::new(u64::MAX),
                tx_timeout_ns: AtomicU64::new(u64::MAX),
                rx_wakers: Mutex::new(Vec::new()),
                tx_wakers: Mutex::new(Vec::new()),
                me: me.clone(),
            }
        });
        udp_socket.channel().udp_socket_created(&udp_socket);
        crate::net::channel::stats_udp_socket_created();

        log::debug!(
            "new UdpSocket 0x{:x} addr {:?}",
            resp.handle,
            udp_socket.local_addr
        );

        Ok(udp_socket)
    }

    pub fn connect(&self, addr: &SocketAddr) {
        *self.peer_addr.lock() = Some(*addr);
    }

    pub fn recv_or_peek_from(
        &self,
        buf: &mut [u8],
        peek: bool,
    ) -> Result<(usize, SocketAddr), ErrorCode> {
        if self.nonblocking.load(Ordering::Acquire) {
            return self.recv_or_peek_from_nonblocking(buf, peek);
        }

        let deadline = {
            let timo = self.rx_timeout_ns.load(Ordering::Relaxed);
            if timo == u64::MAX {
                None
            } else {
                Some(moto_rt::time::Instant::now() + core::time::Duration::from_nanos(timo))
            }
        };

        let fut = UdpRecvFuture {
            socket: self,
            buf,
            peek,
        };
        match block_on_recheck(fut, deadline, RX_PARK_RECHECK) {
            Ok(res) => res,
            Err(_fut) => Err(E_TIMED_OUT),
        }
    }

    fn recv_or_peek_from_nonblocking(
        &self,
        buf: &mut [u8],
        peek: bool,
    ) -> Result<(usize, SocketAddr), ErrorCode> {
        if peek {
            self.peek_from_nonblocking(buf)
        } else {
            self.recv_from_nonblocking(buf)
        }
    }

    fn recv_from_nonblocking(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ErrorCode> {
        let datagram = loop {
            let Some(datagram) = self.rx_queue.lock().next_datagram().unwrap() else {
                return Err(E_NOT_READY);
            };

            if let Some(peer_addr) = self.peer_addr()
                && peer_addr != datagram.addr
            {
                continue;
            }

            break datagram;
        };

        let bytes = datagram.slice();
        let sz = bytes.len().min(buf.len());
        buf[0..sz].clone_from_slice(&bytes[0..sz]);

        Ok((sz, datagram.addr))
    }

    fn peek_from_nonblocking(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ErrorCode> {
        let mut rx_queue = self.rx_queue.lock();
        let datagram = loop {
            let Some(datagram) = rx_queue.peek_datagram().unwrap() else {
                return Err(E_NOT_READY);
            };

            if let Some(peer_addr) = self.peer_addr()
                && peer_addr != datagram.addr
            {
                // Need to remove the datagram from the queue.
                let _ = rx_queue.next_datagram();
                continue;
            }

            break datagram;
        };

        let bytes = datagram.slice();
        let sz = bytes.len().min(buf.len());
        buf[0..sz].clone_from_slice(&bytes[0..sz]);

        Ok((sz, datagram.addr))
    }

    pub fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
        if buf.len() > moto_rt::net::MAX_UDP_PAYLOAD {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        if self.nonblocking.load(Ordering::Acquire) {
            return self.send_to_nonblocking(buf, addr);
        }

        let deadline = {
            let timo = self.tx_timeout_ns.load(Ordering::Relaxed);
            if timo == u64::MAX {
                None
            } else {
                Some(moto_rt::time::Instant::now() + core::time::Duration::from_nanos(timo))
            }
        };

        let fut = UdpSendFuture {
            socket: self,
            buf,
            addr: *addr,
        };
        match block_on_recheck(fut, deadline, TX_PARK_RECHECK) {
            Ok(res) => res,
            Err(_fut) => Err(E_TIMED_OUT),
        }
    }

    fn send_to_nonblocking(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
        if !self.tx_queue.lock().is_empty() {
            self.try_tx();
        }

        let mut tx_queue = self.tx_queue.lock();
        if tx_queue.is_full() {
            return Err(E_NOT_READY);
        }

        tx_queue.push_back(buf, *addr);
        drop(tx_queue);

        self.try_tx();

        Ok(buf.len())
    }

    fn try_tx(&self) {
        let mut tx_lock = self.tx_queue.lock();
        let page_allocator = |subchannel_mask: u64| self.channel().alloc_page(subchannel_mask);
        loop {
            let Some(msg) = tx_lock.pop_front(page_allocator) else {
                return;
            };

            if let Err(msg) = self.channel().post_msg(msg) {
                tx_lock.push_front(msg);
                return;
            }
        }
    }

    // Note: this is called from the I/O thread so should not block.
    pub fn process_incoming_msg(&self, msg: io_channel::Msg) {
        let cmd = api_net::NetCmd::try_from(msg.command).unwrap();
        match cmd {
            api_net::NetCmd::UdpSocketTxRx => {
                let notify = {
                    let mut rx_queue = self.rx_queue.lock();
                    rx_queue
                        .push_back(msg, |idx| self.channel().get_page(idx))
                        .unwrap();

                    rx_queue.have_datagram().unwrap()
                };
                if notify {
                    self.raise_readiness(Readiness::READABLE);
                    self.wake_rx_waiters();
                }
            }
            api_net::NetCmd::UdpSocketTxRxAck => {
                self.raise_readiness(Readiness::WRITABLE);
                self.try_tx();
                self.wake_tx_waiters();
            }
            _ => panic!("Unexpected UDP cmd: {:?}", cmd),
        }
    }

    pub fn peek(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.recv_or_peek_from(buf, true).map(|(sz, _)| sz)
    }

    fn set_nonblocking(&self, val: bool) {
        self.nonblocking.store(val, Ordering::Release);
    }

    /// # Safety
    ///
    /// `ptr` must be valid for `len` readable bytes holding the value for `option`.
    pub unsafe fn setsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        unsafe {
            match option {
                moto_rt::net::SO_NONBLOCKING => {
                    assert_eq!(len, 1);
                    let nonblocking = *(ptr as *const u8);
                    if nonblocking > 1 {
                        return moto_rt::E_INVALID_ARGUMENT;
                    }
                    self.set_nonblocking(nonblocking == 1);
                    moto_rt::E_OK
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
                moto_rt::net::SO_TTL => {
                    assert_eq!(len, 4);
                    let _ttl = *(ptr as *const u32);
                    // self.set_ttl(ttl)
                    panic!("UDP: set_ttl() not implemented")
                }
                _ => panic!("unrecognized option {option}"),
            }
        }
    }

    /// # Safety
    ///
    /// `ptr` must be valid for `len` writable bytes to receive `option`'s value.
    pub unsafe fn getsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        unsafe {
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
                moto_rt::net::SO_TTL => {
                    assert_eq!(len, 4);
                    panic!("UDP: ttl() not implemented")
                    // match self.ttl() {
                    //     Ok(ttl) => {
                    //         *(ptr as *mut u32) = ttl;
                    //         moto_rt::E_OK
                    //     }
                    //     Err(err) => err,
                    // }
                }
                moto_rt::net::SO_ERROR => {
                    assert_eq!(len, 2);
                    // let err = self.take_error();
                    // *(ptr as *mut u16) = err;
                    *(ptr as *mut u16) = moto_rt::E_OK;
                    moto_rt::E_OK
                }
                _ => panic!("unrecognized option {option}"),
            }
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

    fn raise_readiness(&self, edges: Readiness) {
        self.event_listener.on_readiness(edges);
    }

    /// The socket's readiness sink. The vdso veneer installed a concrete
    /// poll-registry source and downcasts this abstract handle back to it.
    pub fn event_listener(&self) -> &dyn NetEventListener {
        self.event_listener.as_ref()
    }

    /// Whether the TX queue cannot take another datagram (veneer WRITABLE
    /// synthesis).
    pub fn tx_queue_full(&self) -> bool {
        self.tx_queue.lock().is_full()
    }

    /// Whether a complete datagram is ready to receive (veneer READABLE
    /// synthesis).
    pub fn has_rx_datagram(&self) -> bool {
        self.rx_queue.lock().have_datagram().unwrap()
    }

    fn add_rx_waker(&self, waker: &core::task::Waker) {
        self.rx_wakers.lock().push(waker.clone());
    }

    fn add_tx_waker(&self, waker: &core::task::Waker) {
        self.tx_wakers.lock().push(waker.clone());
    }

    fn wake_rx_waiters(&self) {
        for waker in self.rx_wakers.lock().drain(..) {
            waker.wake();
        }
    }

    fn wake_tx_waiters(&self) {
        for waker in self.tx_wakers.lock().drain(..) {
            waker.wake();
        }
    }
}

// ------------- blocking-path futures (design 5.3): the UDP mirror of ------------
// the tcp read/write futures, driven by the shared block_on_recheck. All
// state lives in the socket, so a dropped (timed-out) instance leaves at
// most a stale waker entry. Register-then-recheck closes the race with the
// rx task queueing between the poll's check and the waker registration.

struct UdpRecvFuture<'a, 'b> {
    socket: &'a UdpSocket,
    buf: &'b mut [u8],
    peek: bool,
}

impl core::future::Future for UdpRecvFuture<'_, '_> {
    type Output = Result<(usize, SocketAddr), ErrorCode>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        use core::task::Poll;

        let this = self.get_mut();
        match this
            .socket
            .recv_or_peek_from_nonblocking(this.buf, this.peek)
        {
            Err(E_NOT_READY) => {}
            res => return Poll::Ready(res),
        }
        this.socket.add_rx_waker(cx.waker());
        match this
            .socket
            .recv_or_peek_from_nonblocking(this.buf, this.peek)
        {
            Err(E_NOT_READY) => Poll::Pending,
            res => Poll::Ready(res),
        }
    }
}

struct UdpSendFuture<'a, 'b> {
    socket: &'a UdpSocket,
    buf: &'b [u8],
    addr: SocketAddr,
}

impl core::future::Future for UdpSendFuture<'_, '_> {
    type Output = Result<usize, ErrorCode>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        use core::task::Poll;

        let this = self.get_mut();
        match this.socket.send_to_nonblocking(this.buf, &this.addr) {
            Err(E_NOT_READY) => {}
            res => return Poll::Ready(res),
        }
        this.socket.add_tx_waker(cx.waker());
        match this.socket.send_to_nonblocking(this.buf, &this.addr) {
            Err(E_NOT_READY) => Poll::Pending,
            res => Poll::Ready(res),
        }
    }
}
