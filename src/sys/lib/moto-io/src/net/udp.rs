//! The UDP socket state machine (design section 5): `UdpSocket` and its
//! async data-path futures. It talks to sys-io through [`super::channel`] and
//! emits readiness through an abstract
//! [`crate::net::readiness::NetEventListener`], naming no vdso type.
//!
//! Nothing POSIX lives here. `O_NONBLOCK`, `SO_RCVTIMEO`/`SO_SNDTIMEO` and the
//! raw option-pointer dispatch belong to the descriptor, not the socket, so
//! they are the vdso `RtUdpSocket` wrapper's (design 6.3); a native owner has
//! no descriptor and wants none of them. What stays is what sys-io must be
//! told, such as the typed [`UdpSocket::set_ttl_async`].

use super::channel::{ChannelReservation, NetChannel};
use crate::net::readiness::{NetEventListener, Readiness};
use crate::net::wait::{WaitSet, WaiterId};
use alloc::sync::{Arc, Weak};
use core::net::SocketAddr;
use core::sync::atomic::*;
use moto_io_internal::udp_queues::{UdpDefragmentingQueue, UdpFragmentingQueue};
use moto_ipc::io_channel;
use moto_rt::E_NOT_READY;
use moto_rt::{ErrorCode, mutex::Mutex};
use moto_sys_io::api_net;

pub struct UdpSocket {
    channel: Arc<NetChannel>,
    // Taken by close(), which transfers it to the teardown record carrying
    // the socket's release; the channel stays alive through `channel` above.
    channel_reservation: Mutex<Option<ChannelReservation>>,
    // Only the netdev page-exhaustion test reads it today.
    #[cfg_attr(not(feature = "netdev"), allow(dead_code))]
    subchannel_mask: u64,
    local_addr: SocketAddr,
    handle: u64,
    // Where state-machine edges are emitted (raise_readiness), if a host
    // asked for push delivery. None for a native owner, which reads the
    // readiness futures instead. No poll-registry type sits in the struct:
    // the vdso wrapper that installed this keeps the concrete source itself.
    event_listener: Option<Arc<dyn NetEventListener>>,

    tx_queue: Mutex<UdpFragmentingQueue>,
    rx_queue: Mutex<UdpDefragmentingQueue>,

    peer_addr: Mutex<Option<SocketAddr>>,

    // Parked futures own cancellation-aware registrations.
    rx_waiters: WaitSet,
    tx_waiters: WaitSet,

    // Set by the first close(); makes the release idempotent so Drop can be
    // the fallback for a socket that no close() ever reached.
    closed: AtomicBool,

    me: Weak<UdpSocket>,
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        // The fallback for a socket no close() ever reached: a native owner
        // dropping its last reference. Idempotent, and it leaves nothing for
        // this destructor to do afterwards -- the TX queue is emptied there
        // and nothing can be staged after it.
        self.close();
    }
}

impl UdpSocket {
    /// Release the socket: tell sys-io to drop it, and stop routing for it.
    /// Idempotent, so both the closing descriptor and [`Drop`] can call it.
    ///
    /// This must run on the thread that closes the socket, not wherever the
    /// last reference happens to die: sys-io frees the bound address when it
    /// receives the message queued below, and a caller that binds the same
    /// address next would otherwise race its own close. The channel's IO
    /// thread briefly upgrades the weak reference it keeps in `udp_sockets`
    /// on every pass, so a `Drop` that waited for the last reference could
    /// well run there, after the close call had already returned.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }

        self.discard_unstaged_tx();
        self.rx_queue.lock().clear();

        self.wake_rx_waiters();
        self.wake_tx_waiters();
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::UdpSocketDrop as u16;
        req.handle = self.handle();

        self.channel.udp_socket_dropped(self.handle());

        // Hand the release to the driver: a destructor cannot wait for
        // staging room, and the record's reservation keeps the channel alive
        // until sys-io has the message. Queuing it here, before this call
        // returns, is what stops the caller's next bind from overtaking it;
        // the record itself waits for the datagrams this socket had already
        // handed to the channel, which must reach a socket sys-io still has.
        let reservation = self.channel_reservation.lock().take().unwrap();
        self.channel.enqueue_teardown(reservation, req);

        // Balance stats_udp_socket_created(): the decrement was missing, which
        // stage-E's assert_empty (now checking num_udp_sockets) would trip on.
        crate::net::channel::stats_udp_socket_dropped();
    }

    /// Discard the datagrams the socket never handed to the channel, and
    /// return the io page of one staged behind a full staging queue.
    ///
    /// UDP is lossy by contract and the fragmenting queue already drops
    /// datagrams once it is full, so a close discards what is left rather
    /// than waiting for pages or staging room. `try_tx` reads `closed` under
    /// this same lock, so nothing is staged after this returns.
    fn discard_unstaged_tx(&self) {
        let mut tx_queue = self.tx_queue.lock();
        if let Some(msg) = tx_queue.take_msg() {
            assert_eq!(msg.command, api_net::NetCmd::UdpSocketTxRx as u16);
            // An empty datagram carries no page, and page index 0 is a real
            // page, so the size is what says whether there is one to return.
            if msg.payload.args_16()[10] != 0 {
                let _ = self.channel.get_page(msg.payload.shared_pages()[11]);
            }
        }
        tx_queue.clear();
    }

    pub fn handle(&self) -> u64 {
        self.handle
    }

    pub fn weak(&self) -> Weak<Self> {
        self.me.clone()
    }

    fn channel(&self) -> &NetChannel {
        &self.channel
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        *self.peer_addr.lock()
    }

    /// Bind on a host-owned channel: the reservation names the channel the
    /// socket lives on (design section 4), and the global pool is not
    /// consulted.
    pub async fn bind_reserved(
        reservation: super::channel::Reservation,
        socket_addr: &SocketAddr,
        event_listener: Option<Arc<dyn NetEventListener>>,
    ) -> Result<Arc<UdpSocket>, ErrorCode> {
        if socket_addr.port() == 0 && socket_addr.ip().is_unspecified() {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        Self::bind_inner(
            reservation.into_channel_reservation(),
            socket_addr,
            false,
            event_listener,
        )
        .await
    }

    /// [`Self::bind_for_remote`] on a host-owned channel (design section 4);
    /// the global pool is not consulted.
    pub async fn bind_for_remote_reserved(
        reservation: super::channel::Reservation,
        remote_addr: &SocketAddr,
        event_listener: Option<Arc<dyn NetEventListener>>,
    ) -> Result<Arc<UdpSocket>, ErrorCode> {
        if remote_addr.ip().is_unspecified() {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        Self::bind_inner(
            reservation.into_channel_reservation(),
            remote_addr,
            true,
            event_listener,
        )
        .await
    }

    async fn bind_inner(
        mut channel_reservation: super::channel::ChannelReservation,
        requested_addr: &SocketAddr,
        select_route: bool,
        event_listener: Option<Arc<dyn NetEventListener>>,
    ) -> Result<Arc<UdpSocket>, ErrorCode> {
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
        let channel = channel_reservation.channel().clone();
        let (channel_reservation, resp) = channel
            .rpc_bind(
                req,
                channel_reservation,
                api_net::NetCmd::UdpSocketDrop as u16,
            )
            .await
            .into_result()?;

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

        let udp_socket = Arc::new_cyclic(|me| UdpSocket {
            local_addr: socket_addr,
            channel: channel_reservation.channel().clone(),
            channel_reservation: Mutex::new(Some(channel_reservation)),
            handle: resp.handle,
            event_listener,
            subchannel_mask,
            tx_queue: Mutex::new(UdpFragmentingQueue::new(resp.handle, subchannel_mask)),
            peer_addr: Mutex::new(None),
            rx_queue: Mutex::new(UdpDefragmentingQueue::new()),
            rx_waiters: WaitSet::new(),
            tx_waiters: WaitSet::new(),
            closed: AtomicBool::new(false),
            me: me.clone(),
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

    // ---------------------- async-first data-path API ---------------------- //
    //
    // The native surface (design 5.4), the UDP mirror of the TCP one: copies
    // happen in the polling context, never on the channel runtime. The veneer
    // layers blocking, `SO_*TIMEO` and `O_NONBLOCK` on top.

    /// Nonblocking receive or peek: `Ok((n, from))` with a datagram,
    /// `E_NOT_READY` when the socket would block, `E_NOT_CONNECTED` after
    /// close.
    pub fn try_recv_from(
        &self,
        buf: &mut [u8],
        peek: bool,
    ) -> Result<(usize, SocketAddr), ErrorCode> {
        self.recv_or_peek_from_nonblocking(buf, peek)
    }

    /// The receive future the veneer parks on and a native reactor awaits.
    /// Cancel-safe.
    pub fn recv_from_future<'a, 'b>(
        &'a self,
        buf: &'b mut [u8],
        peek: bool,
    ) -> UdpRecvFuture<'a, 'b> {
        UdpRecvFuture {
            socket: self,
            buf,
            peek,
            waiter_id: None,
        }
    }

    /// Resolves once a receive would not block. A native reactor awaits this,
    /// then calls `try_recv_from`.
    pub fn readable(&self) -> UdpReadable<'_> {
        UdpReadable {
            socket: self,
            waiter_id: None,
        }
    }

    /// Nonblocking send: `Ok(n)` when queued, `E_NOT_READY` when the TX queue
    /// is full, `E_INVALID_ARGUMENT` when the payload is oversized,
    /// `E_NOT_CONNECTED` after close.
    pub fn try_send_to(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
        self.send_to_nonblocking(buf, addr)
    }

    /// The send future the veneer parks on and a native reactor awaits.
    /// Cancel-safe.
    pub fn send_to_future<'a, 'b>(
        &'a self,
        buf: &'b [u8],
        addr: &SocketAddr,
    ) -> UdpSendFuture<'a, 'b> {
        UdpSendFuture {
            socket: self,
            buf,
            addr: *addr,
            waiter_id: None,
        }
    }

    /// Resolves once a send would not block. A native reactor awaits this,
    /// then calls `try_send_to`.
    pub fn writable(&self) -> UdpWritable<'_> {
        UdpWritable {
            socket: self,
            waiter_id: None,
        }
    }

    fn recv_or_peek_from_nonblocking(
        &self,
        buf: &mut [u8],
        peek: bool,
    ) -> Result<(usize, SocketAddr), ErrorCode> {
        if self.is_closed() {
            return Err(moto_rt::E_NOT_CONNECTED);
        }

        if peek {
            self.peek_from_nonblocking(buf)
        } else {
            self.recv_from_nonblocking(buf)
        }
    }

    /// Drop queued datagrams a connected socket must never deliver
    /// (foreign source), freeing their pages, and report whether a
    /// deliverable one remains. The read paths filter too (connect can
    /// race queued arrivals), but filtering only there let a foreign
    /// arrival raise a spurious READABLE on a connected socket -- the
    /// kernel-side filter epoll consumers assume (mio's udp discard
    /// contract, storm-soak finding 2026-08-10).
    fn purge_foreign_have_datagram(&self, rx_queue: &mut UdpDefragmentingQueue) -> bool {
        let Some(peer_addr) = self.peer_addr() else {
            return rx_queue.have_datagram().unwrap();
        };
        loop {
            let deliverable = match rx_queue.peek_datagram().unwrap() {
                None => return false,
                Some(datagram) => datagram.addr == peer_addr,
            };
            if deliverable {
                return true;
            }
            let _ = rx_queue.next_datagram();
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

    fn send_to_nonblocking(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
        if self.is_closed() {
            return Err(moto_rt::E_NOT_CONNECTED);
        }

        if buf.len() > moto_rt::net::MAX_UDP_PAYLOAD {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        if !self.tx_queue.lock().is_empty() {
            self.try_tx();
        }

        let mut tx_queue = self.tx_queue.lock();
        if self.is_closed() {
            return Err(moto_rt::E_NOT_CONNECTED);
        }
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
        // A closed socket's release is already queued, behind the datagrams
        // it had handed to the channel; anything staged now would reach
        // sys-io after that release, for a socket it no longer has.
        if self.closed.load(Ordering::Acquire) {
            return;
        }
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
                let mut rx_queue = self.rx_queue.lock();
                if self.is_closed() {
                    drop(rx_queue);
                    if msg.payload.args_16()[10] != 0 {
                        let _ = self.channel().get_page(msg.payload.shared_pages()[11]);
                    }
                    return;
                }
                let notify = {
                    rx_queue
                        .push_back(msg, |idx| self.channel().get_page(idx))
                        .unwrap();

                    self.purge_foreign_have_datagram(&mut rx_queue)
                };
                if notify {
                    self.raise_readiness(Readiness::READABLE);
                    self.wake_rx_waiters();
                }
            }
            api_net::NetCmd::UdpSocketTxRxAck => {
                if self.is_closed() {
                    return;
                }
                self.raise_readiness(Readiness::WRITABLE);
                self.on_channel_tx_progress();
            }
            _ => panic!("Unexpected UDP cmd: {:?}", cmd),
        }
    }

    /// Re-drive queued datagrams and wake senders after channel TX progress.
    pub(super) fn on_channel_tx_progress(&self) {
        self.try_tx();
        self.wake_tx_waiters();
    }

    /// Set the unicast TTL without blocking the polling thread.
    pub async fn set_ttl_async(&self, ttl: u32) -> Result<(), ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::UdpSocketSetOption as u16;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::UDP_OPTION_TTL;
        req.payload.args_32_mut()[2] = ttl;
        let resp = self.channel().rpc(req).await;
        if resp.status().is_ok() {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    /// Read the unicast TTL without blocking the polling thread.
    pub async fn ttl_async(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::UdpSocketGetOption as u16;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::UDP_OPTION_TTL;
        let resp = self.channel().rpc(req).await;
        if resp.status().is_ok() {
            Ok(resp.payload.args_32()[0])
        } else {
            Err(resp.status)
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn raise_readiness(&self, edges: Readiness) {
        if let Some(listener) = &self.event_listener {
            listener.on_readiness(edges);
        }
    }

    /// Whether the TX queue cannot take another datagram (the vdso wrapper's
    /// WRITABLE synthesis).
    pub fn tx_queue_full(&self) -> bool {
        self.tx_queue.lock().is_full()
    }

    /// Whether a complete datagram is ready to receive (the vdso wrapper's
    /// READABLE synthesis).
    pub fn has_rx_datagram(&self) -> bool {
        let mut rx_queue = self.rx_queue.lock();
        self.purge_foreign_have_datagram(&mut rx_queue)
    }

    fn add_rx_waker(&self, id: &mut Option<WaiterId>, waker: &core::task::Waker) {
        self.rx_waiters.register(id, waker);
    }

    fn remove_rx_waker(&self, id: &mut Option<WaiterId>) {
        self.rx_waiters.unregister(id);
    }

    fn add_tx_waker(&self, id: &mut Option<WaiterId>, waker: &core::task::Waker) {
        self.tx_waiters.register(id, waker);
    }

    fn remove_tx_waker(&self, id: &mut Option<WaiterId>) {
        self.tx_waiters.unregister(id);
    }

    fn wake_rx_waiters(&self) {
        self.rx_waiters.wake_all();
    }

    fn wake_tx_waiters(&self) {
        self.tx_waiters.wake_all();
    }

    #[doc(hidden)]
    #[cfg(feature = "netdev")]
    pub fn rx_waiter_count(&self) -> usize {
        self.rx_waiters.len()
    }

    #[doc(hidden)]
    #[cfg(feature = "netdev")]
    pub fn tx_waiter_count(&self) -> usize {
        self.tx_waiters.len()
    }

    #[doc(hidden)]
    #[cfg(feature = "netdev")]
    pub fn channel_udp_socket_count_for_test(&self) -> usize {
        self.channel().udp_socket_count_for_test()
    }

    /// Run a netdev test while this socket has no allocatable TX pages.
    #[doc(hidden)]
    #[cfg(feature = "netdev")]
    pub fn with_tx_pages_exhausted_for_test(&self, f: impl FnOnce()) {
        let mut pages = alloc::vec::Vec::new();
        while let Ok(page) = self.channel().alloc_page(self.subchannel_mask) {
            pages.push(page);
        }
        f();
        drop(pages);
        self.channel().wake_waiters_for_test();
    }
}

// ------------- blocking-path futures (design 5.3): the UDP mirror of ------------
// the tcp read/write futures, parked on by the veneer's block_on. All
// data-path state lives in the socket. Register-then-recheck closes the race
// with the rx task queueing between the poll's check and waker registration.

pub struct UdpRecvFuture<'a, 'b> {
    socket: &'a UdpSocket,
    buf: &'b mut [u8],
    peek: bool,
    waiter_id: Option<WaiterId>,
}

impl Drop for UdpRecvFuture<'_, '_> {
    fn drop(&mut self) {
        self.socket.remove_rx_waker(&mut self.waiter_id);
    }
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
            res => {
                this.socket.remove_rx_waker(&mut this.waiter_id);
                return Poll::Ready(res);
            }
        }
        this.socket.add_rx_waker(&mut this.waiter_id, cx.waker());
        match this
            .socket
            .recv_or_peek_from_nonblocking(this.buf, this.peek)
        {
            Err(E_NOT_READY) => Poll::Pending,
            res => {
                this.socket.remove_rx_waker(&mut this.waiter_id);
                Poll::Ready(res)
            }
        }
    }
}

pub struct UdpSendFuture<'a, 'b> {
    socket: &'a UdpSocket,
    buf: &'b [u8],
    addr: SocketAddr,
    waiter_id: Option<WaiterId>,
}

impl Drop for UdpSendFuture<'_, '_> {
    fn drop(&mut self) {
        self.socket.remove_tx_waker(&mut self.waiter_id);
    }
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
            res => {
                this.socket.remove_tx_waker(&mut this.waiter_id);
                return Poll::Ready(res);
            }
        }
        this.socket.add_tx_waker(&mut this.waiter_id, cx.waker());
        match this.socket.send_to_nonblocking(this.buf, &this.addr) {
            Err(E_NOT_READY) => Poll::Pending,
            res => {
                this.socket.remove_tx_waker(&mut this.waiter_id);
                Poll::Ready(res)
            }
        }
    }
}

/// Receive-readiness future (design 5.4): resolves once `try_recv_from` would
/// not block. A native reactor awaits this, then drains with `try_recv_from`;
/// the vdso veneer parks on the richer `recv_from_future`. Cancel-safe.
pub struct UdpReadable<'a> {
    socket: &'a UdpSocket,
    waiter_id: Option<WaiterId>,
}

impl Drop for UdpReadable<'_> {
    fn drop(&mut self) {
        self.socket.remove_rx_waker(&mut self.waiter_id);
    }
}

impl core::future::Future for UdpReadable<'_> {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        use core::task::Poll;

        let this = self.get_mut();
        let socket = this.socket;
        if socket.is_closed() {
            socket.remove_rx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        if socket.has_rx_datagram() {
            socket.remove_rx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        socket.add_rx_waker(&mut this.waiter_id, cx.waker());
        if socket.has_rx_datagram() {
            socket.remove_rx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        if socket.is_closed() {
            socket.remove_rx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        Poll::Pending
    }
}

/// Send-readiness future (design 5.4): resolves once `try_send_to` would not
/// block. First flushes already-queued datagrams (`try_tx`), then reports
/// TX-queue room; the tx waker fires when an acknowledgement or other channel
/// progress may have made room. Cancel-safe.
pub struct UdpWritable<'a> {
    socket: &'a UdpSocket,
    waiter_id: Option<WaiterId>,
}

impl Drop for UdpWritable<'_> {
    fn drop(&mut self) {
        self.socket.remove_tx_waker(&mut self.waiter_id);
    }
}

impl core::future::Future for UdpWritable<'_> {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        use core::task::Poll;

        let this = self.get_mut();
        let socket = this.socket;
        if socket.is_closed() {
            socket.remove_tx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        if !socket.tx_queue_full() {
            socket.remove_tx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        // Push any already-queued datagrams to sys-io; that may free room.
        socket.try_tx();
        if !socket.tx_queue_full() {
            socket.remove_tx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        socket.add_tx_waker(&mut this.waiter_id, cx.waker());
        if !socket.tx_queue_full() {
            socket.remove_tx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        if socket.is_closed() {
            socket.remove_tx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        Poll::Pending
    }
}
