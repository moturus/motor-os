//! The TCP socket state machines (design section 5): `TcpStream` and
//! `TcpListener`, plus their async data-path futures. Everything here talks to
//! sys-io through the channel runtime in [`super::channel`] and emits readiness
//! through an abstract [`crate::net::readiness::NetEventListener`], so it names
//! no vdso type.
//!
//! Nothing POSIX lives on either type. `O_NONBLOCK`,
//! `SO_RCVTIMEO`/`SO_SNDTIMEO` and the raw option-pointer dispatch belong to
//! the descriptor, not the socket, so they are the vdso `RtTcpStream` and
//! `RtTcpListener` wrappers' (design 6.3); a native owner has no descriptor
//! and wants none of them. What stays is what sys-io must be told, such as the
//! typed [`TcpStream::set_nodelay_async`] and [`TcpListener::set_ttl_async`].

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::sync::Weak;
use core::net::SocketAddr;
use core::sync::atomic::*;
use core::time::Duration;
use moto_ipc::io_channel;
use moto_rt::moto_log;
use moto_rt::mutex::Mutex;
use moto_rt::time::Instant;
use moto_sys::ErrorCode;
use moto_sys::SysHandle;
use moto_sys_io::api_net;
use moto_sys_io::api_net::TcpState;

use super::channel::ChannelReservation;
use super::channel::NetChannel;
use super::channel::RpcWaiter;
use crate::net::readiness::NetEventListener;
use crate::net::readiness::Readiness;
use crate::net::wait::{WaitSet, WaiterId};

/// An accepted-but-not-yet-claimed connection: the accept response plus
/// the channel reservation made when the accept was posted.
pub(super) struct PendingAccept {
    cleanup: PendingAcceptCleanup,
    resp: moto_ipc::io_channel::Msg,
}

struct PendingAcceptCleanup {
    listener: Weak<TcpListener>,
    reservation: Option<ChannelReservation>,
    recv_queue: Option<Arc<Mutex<crate::net::inner_rx_stream::InnerRxStream>>>,
    handle: u64,
    close_stream: bool,
}

impl PendingAcceptCleanup {
    fn commit(
        mut self,
    ) -> (
        ChannelReservation,
        Arc<Mutex<crate::net::inner_rx_stream::InnerRxStream>>,
    ) {
        (
            self.reservation.take().unwrap(),
            self.recv_queue.take().unwrap(),
        )
    }
}

impl Drop for PendingAcceptCleanup {
    fn drop(&mut self) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let Some(recv_queue) = self.recv_queue.take() else {
            return;
        };
        let channel = reservation.channel().clone();

        if let Some(listener) = self.listener.upgrade() {
            let removed = listener.pending_accept_queues.lock().remove(&self.handle);
            debug_assert!(
                removed
                    .as_ref()
                    .is_none_or(|queue| Arc::ptr_eq(queue, &recv_queue))
            );
        }

        super::channel::clear_rx_queue(&recv_queue, &channel);
        if self.close_stream {
            channel.enqueue_teardown(
                reservation,
                super::channel::tcp_stream_close_msg(self.handle),
            );
        }
    }
}

pub struct TcpListener {
    socket_addr: SocketAddr,
    channel_reservation: Option<ChannelReservation>,
    handle: u64,
    // Where state-machine edges are emitted (raise_readiness). No poll-registry
    // type sits in the struct: the vdso wrapper that installed this keeps the
    // concrete source it needs for interest registration.
    event_listener: Arc<dyn NetEventListener>,

    // In-flight accept requests: req_id => the reservation the accepted
    // stream will use. Blocking accepts additionally await a oneshot held in
    // the channel's RPC map.
    accept_requests: Mutex<BTreeMap<u64, ChannelReservation>>,

    // Incoming async accepts are stored here. Better processed
    // in arrival order.
    async_accepts: Mutex<VecDeque<PendingAccept>>,

    // In sys-io, connected sockets may generate tcp stream messages such as
    // rx, rx_done, close, etc. Here (vdso), the stream is not created until
    // the user calls accept() asynchronously (vs the I/O thread), so
    // we need a place to store messages for not-yet-accepted TCP streams.
    // MIO test actually tests this scenario.
    pending_accept_queues:
        Mutex<BTreeMap<u64, Arc<Mutex<crate::net::inner_rx_stream::InnerRxStream>>>>,

    max_backlog: AtomicU32,
    me: Weak<TcpListener>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut msg = io_channel::Msg::new();
        msg.command = api_net::NetCmd::TcpListenerDrop as u16;
        msg.handle = self.handle;

        while let Some((_, stream)) = { self.pending_accept_queues.lock().pop_first() } {
            // Free up server-allocated pages.
            super::channel::clear_rx_queue(&stream, self.channel());
        }

        self.channel().tcp_listener_dropped(self.handle);

        super::channel::stats_tcp_listener_dropped();

        // Transfer both the close and the reservation to the driver. Drop
        // never waits for staging/ring room, and the reservation keeps this
        // channel alive until sys-io accepts the close.
        let reservation = self.channel_reservation.take().unwrap();
        let channel = reservation.channel().clone();
        channel.enqueue_teardown(reservation, msg);
    }
}

impl TcpListener {
    // Called inline from rx dispatch: the pending_accept_queue must
    // exist before the next message for the new stream is dispatched.
    pub(super) fn on_accept_response(
        &self,
        resp: io_channel::Msg,
        sync_tx: Option<moto_async::oneshot::Sender<PendingAccept>>,
    ) {
        let reservation = self.accept_requests.lock().remove(&resp.id).unwrap();

        // First, create the pending_accept_queue; only then publish the
        // pending accept (a racing accept must not miss the queue).
        let recv_queue = crate::net::inner_rx_stream::InnerRxStream::new();
        self.pending_accept_queues
            .lock()
            .insert(resp.handle, recv_queue.clone());

        let cleanup = PendingAcceptCleanup {
            listener: self.me.clone(),
            reservation: Some(reservation),
            recv_queue: Some(recv_queue),
            handle: resp.handle,
            close_stream: resp.status().is_ok(),
        };
        let pending = PendingAccept { cleanup, resp };

        if let Some(tx) = sync_tx {
            // The accept caller awaits this through the one-shot receiver.
            // PendingAccept owns rollback, so either a failed send or a later
            // receiver cancellation closes an unclaimed successful stream.
            let _ = tx.send(pending);
            return;
        }

        self.async_accepts.lock().push_back(pending);
        if self.async_accepts.lock().len() < (self.max_backlog.load(Ordering::Relaxed) as usize) {
            // Re-arm the next accept slot. Runs on the rx task; the
            // guaranteed post keeps the slot even if the reserved channel's
            // send queue is momentarily full.
            self.post_accept(None);
        }

        self.raise_readiness(Readiness::READABLE);
    }

    fn raise_readiness(&self, edges: Readiness) {
        self.event_listener.on_readiness(edges);
    }

    /// Whether an async accept is already queued (the veneer raises READABLE
    /// on interest registration if so).
    pub fn has_async_accepts(&self) -> bool {
        !self.async_accepts.lock().is_empty()
    }
}

impl TcpListener {
    pub fn handle(&self) -> u64 {
        self.handle
    }

    #[doc(hidden)]
    #[cfg(feature = "netdev")]
    pub fn channel_tx_waiter_count_for_test(&self) -> usize {
        self.channel().tx_waiter_count()
    }

    #[doc(hidden)]
    #[cfg(feature = "netdev")]
    pub fn channel_rpc_waiter_count_for_test(&self) -> usize {
        self.channel().rpc_waiter_count()
    }

    fn channel(&self) -> &super::channel::NetChannel {
        self.channel_reservation.as_ref().unwrap().channel()
    }

    pub async fn bind(
        socket_addr: &SocketAddr,
        event_listener: Arc<dyn NetEventListener>,
    ) -> Result<Arc<TcpListener>, ErrorCode> {
        let mut socket_addr = *socket_addr;
        if socket_addr.port() == 0 && socket_addr.ip().is_unspecified() {
            moto_log!("we don't currently allow binding to/listening on 0.0.0.0:0");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let req = api_net::bind_tcp_listener_request(&socket_addr, None);
        let channel_reservation = super::channel::reserve_channel();
        let channel = channel_reservation.channel().clone();
        let (channel_reservation, resp) = channel
            .rpc_bind(
                req,
                channel_reservation,
                api_net::NetCmd::TcpListenerDrop as u16,
            )
            .await
            .into_result()?;

        if socket_addr.port() == 0 {
            let actual_addr = api_net::get_socket_addr(&resp.payload);
            assert_eq!(socket_addr.ip(), actual_addr.ip());
            assert_ne!(0, actual_addr.port());
            socket_addr.set_port(actual_addr.port());
        }

        let tcp_listener = Arc::new_cyclic(|me| TcpListener {
            socket_addr,
            channel_reservation: Some(channel_reservation),
            handle: resp.handle,
            event_listener,
            accept_requests: Mutex::new(BTreeMap::new()),
            async_accepts: Mutex::new(VecDeque::new()),
            pending_accept_queues: Mutex::new(BTreeMap::new()),
            max_backlog: AtomicU32::new(32),
            me: me.clone(),
        });
        tcp_listener.channel().tcp_listener_created(&tcp_listener);
        crate::net::channel::stats_tcp_listener_created();

        log::debug!("new TcpListener {:?}", tcp_listener.socket_addr);

        Ok(tcp_listener)
    }

    pub fn add_to_pending_queue(&self, msg: io_channel::Msg) -> bool {
        let queues = self.pending_accept_queues.lock();
        for (id, queue) in &*queues {
            if *id == msg.handle {
                queue.lock().push_back(msg);
                return true;
            }
        }

        false
    }

    /// Arm the accept backlog: post an accept request now, and keep up to
    /// `max_backlog` completed connections queued for a caller that has not
    /// asked for one yet. A caller that only ever awaits [`Self::accept`] does
    /// not need this -- that path posts its own request.
    pub fn listen(&self, max_backlog: u32) -> Result<(), ErrorCode> {
        if max_backlog == 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.max_backlog.store(max_backlog, Ordering::Relaxed);
        if !self.accept_requests.lock().is_empty() {
            return Ok(()); // Already listening.
        }

        if self.async_accepts.lock().len() >= (max_backlog as usize) {
            return Ok(()); // The backlog is too large.
        }

        self.post_accept(None);
        Ok(())
    }

    pub fn socket_addr(&self) -> &SocketAddr {
        &self.socket_addr
    }

    /// Pop a ready incoming connection or await the next one. The vdso veneer
    /// drives this with `block_on_sync`; a native user awaits it.
    async fn next_pending_accept(&self) -> PendingAccept {
        if let Some(pending_accept) = self.async_accepts.lock().pop_front() {
            return pending_accept;
        }

        let (tx, rx) = moto_async::oneshot();
        self.post_accept(Some(tx));

        // The sender lives in the channel's RPC map; it cannot be
        // dropped unresolved while we hold &self (see rx dispatch).
        rx.await.expect("accept RPC dropped")
    }

    /// Nonblocking accept: an already-queued incoming connection, or
    /// `E_NOT_READY`.
    pub fn try_accept<L: NetEventListener + 'static>(
        &self,
        make_listener: &dyn Fn() -> Arc<L>,
    ) -> Result<(Arc<TcpStream>, Arc<L>, SocketAddr), ErrorCode> {
        let Some(pending) = self.async_accepts.lock().pop_front() else {
            return Err(moto_rt::E_NOT_READY);
        };
        self.build_accepted_stream(pending, make_listener)
    }

    /// Accept, resolving once an incoming connection is available. The vdso
    /// drives this to completion; a native user awaits it.
    pub async fn accept<L: NetEventListener + 'static>(
        &self,
        make_listener: &dyn Fn() -> Arc<L>,
    ) -> Result<(Arc<TcpStream>, Arc<L>, SocketAddr), ErrorCode> {
        let pending = self.next_pending_accept().await;
        self.build_accepted_stream(pending, make_listener)
    }

    /// Turn an accepted `PendingAccept` into a live `TcpStream`. Shared by the
    /// blocking (`accept`) and nonblocking (`try_accept`) paths.
    ///
    /// The readiness sink is built here, so it is returned rather than left for
    /// the caller to recover: a host that keeps a concrete source (the vdso
    /// wrapper does) would otherwise have to downcast the abstract handle back.
    /// It stays a factory rather than a ready-made `Arc` because `try_accept`
    /// must be able to report `E_NOT_READY` without allocating one -- that is
    /// every turn of mio's accept loop.
    fn build_accepted_stream<L: NetEventListener + 'static>(
        &self,
        pending: PendingAccept,
        make_listener: &dyn Fn() -> Arc<L>,
    ) -> Result<(Arc<TcpStream>, Arc<L>, SocketAddr), ErrorCode> {
        if pending.resp.status().is_err() {
            let status = pending.resp.status;
            drop(pending);
            return Err(status);
        }

        let PendingAccept { cleanup, resp } = pending;

        let remote_addr = api_net::get_socket_addr(&resp.payload);
        let (channel_reservation, recv_queue) = cleanup.commit();
        let subchannel_mask = channel_reservation.subchannel_mask();

        let event_listener = make_listener();
        let new_stream = Arc::new_cyclic(|me| TcpStream {
            local_addr: Mutex::new(Some(self.socket_addr)),
            remote_addr,
            handle: AtomicU64::new(resp.handle),
            event_listener: event_listener.clone(),
            me: me.clone(),
            channel_reservation: Some(channel_reservation),
            recv_queue,
            rx_waiters: WaitSet::new(),
            tcp_state_driver: AtomicU32::new(api_net::TcpState::ReadWrite.into()),
            rx_closed: AtomicBool::new(false),
            tx_closed: AtomicBool::new(false),
            subchannel_mask,
            error: AtomicU16::new(moto_rt::E_OK),
            pending_tx: Mutex::new(VecDeque::new()),
        });
        crate::net::channel::stats_tcp_stream_created();

        new_stream.channel().tcp_stream_created(&new_stream);
        // Now we can remove the queue.
        assert!(
            self.pending_accept_queues
                .lock()
                .remove(&resp.handle)
                .is_some()
        );

        new_stream.ack_rx();
        new_stream.on_accepted();

        #[cfg(debug_assertions)]
        log::debug!(
            "New incoming TcpStream {:?} <- {:?} 0x{:x} mask: 0x{:x}",
            new_stream.local_addr.lock().unwrap(),
            new_stream.remote_addr,
            new_stream.handle(),
            new_stream.subchannel_mask
        );

        Ok((new_stream, event_listener, remote_addr))
    }

    /// Reserve a fresh channel for one incoming connection and transfer the
    /// accept RPC to its driver. The listener owns the reservation until a
    /// response arrives; dropping the listener cancels indefinitely pending
    /// accepts without waiting for a response that sys-io does not send.
    fn post_accept(&self, sync_tx: Option<moto_async::oneshot::Sender<PendingAccept>>) {
        // Because a listener can spawn thousands, millions of sockets
        // (think a long-running web server), we cannot use the listener's
        // channel for incoming connections.
        let mut channel_reservation = crate::net::channel::reserve_channel();
        let channel = channel_reservation.channel().clone();

        channel_reservation.reserve_subchannel();
        let subchannel_mask = channel_reservation.subchannel_mask();

        let mut req = api_net::accept_tcp_listener_request(self.handle, subchannel_mask);
        req.id = channel.new_req_id();

        assert!(
            self.accept_requests
                .lock()
                .insert(req.id, channel_reservation)
                .is_none()
        );

        let waiter = RpcWaiter::Accept {
            listener: self.me.clone(),
            tx: sync_tx,
        };
        channel.enqueue_rpc(req, waiter);
    }

    /// Set the listener TTL without blocking the polling thread.
    pub async fn set_ttl_async(&self, ttl: u32) -> Result<(), ErrorCode> {
        if ttl > u8::MAX as u32 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpListenerSetOption as u16;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        req.payload.args_8_mut()[23] = ttl as u8;
        let resp = self.channel().rpc(req).await;
        if resp.status().is_ok() {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    /// Read the listener TTL without blocking the polling thread.
    pub async fn ttl_async(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpListenerGetOption as u16;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        let resp = self.channel().rpc(req).await;
        if resp.status().is_ok() {
            Ok(resp.payload.args_8()[23] as u32)
        } else {
            Err(resp.status)
        }
    }
}

pub struct TcpStream {
    channel_reservation: Option<ChannelReservation>,
    local_addr: Mutex<Option<SocketAddr>>,
    remote_addr: SocketAddr,
    handle: AtomicU64,
    // Where state-machine edges are emitted (raise_readiness). No poll-registry
    // type sits in the struct: the vdso wrapper that installed this keeps the
    // concrete source itself.
    event_listener: Arc<dyn NetEventListener>,
    me: Weak<TcpStream>,

    // This is, most of the time, a single-producer, single-consumer queue.
    // MUST be locked before rx_buf is locked.
    recv_queue: Arc<Mutex<crate::net::inner_rx_stream::InnerRxStream>>,

    // Wakers of parked read futures, drained (wake-all-and-recheck) on
    // every incoming message and read-closing state change. Multiple
    // entries = concurrent readers on dup'd FDs, all correct candidates
    // for the next byte.
    rx_waiters: WaitSet,

    // This reflects the state as reported by the driver (sys-io).
    tcp_state_driver: AtomicU32, // rt_api::TcpState

    // This reflects the local state, as could be different from
    // the state in sys-io:
    //
    // When the user calls shutdown(write), the request
    // is forwarded to sys-io, which may delay the state
    // change if there are unsent bytes in local buffers
    // (it is expected that all bytes written by the user
    // before the shutdown are sent out).
    //
    // MIO test expects writes that follow shutdown(write)
    // to fail, so the _local_ state should reflect the
    // shutdown before the driver reports the new state.
    rx_closed: AtomicBool,
    tx_closed: AtomicBool,

    subchannel_mask: u64, // Never changes.

    error: AtomicU16, // Erorr during async ops.

    // Written TX bytes awaiting pickup by the IO thread; see PendingTxPage.
    pending_tx: Mutex<VecDeque<PendingTxPage>>,
}

/// A TX io_page in the stream's `pending_tx` queue, not yet sent to sys-io.
///
/// Writes append into the queue's back page while it has room (no page
/// alloc, no queue traffic), so page fill adapts to how far the app runs
/// ahead of the IO thread. Each page is pushed together with a MARKER
/// message (see `channel::tcp_tx_marker_msg`) enqueued on the ordinary send
/// queue: the IO thread claims pending pages when it pops the marker and
/// binds their lengths at that moment ([`TcpStream::claim_pending_tx`]), so
/// data is never delayed beyond one IO-thread pass — the same latency as a
/// directly-queued message. Only the back page can be partially filled
/// (with one exception: a marker-enqueue retry after a full send queue can
/// re-push a partial page behind a concurrent writer's page; the claim path
/// therefore stops at the first partial page rather than assuming).
struct PendingTxPage {
    page: io_channel::IoPage,
    filled: usize,
}

/// Which half of a TCP stream to shut down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shutdown {
    Read,
    Write,
    Both,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let handle = self.handle.load(Ordering::Acquire);
        if handle == 0 {
            super::channel::stats_tcp_stream_dropped();
            return;
        }

        let reservation = self.channel_reservation.take().unwrap();
        let channel = reservation.channel().clone();

        // Transfer written bytes and the close as one FIFO record. Its
        // reservation keeps the channel alive until the driver has accepted
        // every message; drop itself never waits for staging/ring room.
        let mut messages = VecDeque::new();
        while let Some(msg) = self.claim_pending_tx() {
            messages.push_back(msg);
        }

        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamClose as u16;
        req.handle = self.handle();
        messages.push_back(req);

        // Clear RX queue: basically, free up server-allocated pages.
        super::channel::clear_rx_queue(&self.recv_queue, &channel);
        assert!(self.recv_queue.lock().is_empty());

        channel.tcp_stream_dropped(self.handle());
        super::channel::stats_tcp_stream_dropped();

        channel.enqueue_teardown_messages(reservation, messages);
    }
}

impl TcpStream {
    pub fn handle(&self) -> u64 {
        let handle = self.handle.load(Ordering::Acquire);
        assert_ne!(0, handle);
        handle
    }

    pub fn weak(&self) -> Weak<Self> {
        self.me.clone()
    }

    fn channel(&self) -> &NetChannel {
        self.channel_reservation.as_ref().unwrap().channel()
    }

    /// Whether the receive queue holds anything (the veneer raises READABLE
    /// on interest registration only when it does).
    pub fn has_rx_bytes(&self) -> bool {
        !self.recv_queue.lock().is_empty()
    }

    /// Tell sys-io this stream is ready to receive: sys-io's RX pump does
    /// not send anything until the first TcpStreamRxAck arrives, so this is
    /// sent once per stream, on connect/accept. (The pre-2026-07 protocol
    /// also acked every 8th Rx message; those acks gated nothing on the
    /// sys-io side and were deleted.)
    fn ack_rx(&self) {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamRxAck as u16;
        req.handle = self.handle();
        self.channel().enqueue_control(req);
    }

    pub fn tcp_state(&self) -> api_net::TcpState {
        api_net::TcpState::try_from(self.tcp_state_driver.load(Ordering::Acquire)).unwrap()
    }

    /// Register a read future's waker. The caller must re-check for RX
    /// progress after registering (register-then-recheck closes the race
    /// with the rx task queueing in between).
    fn add_rx_waker(&self, id: &mut Option<WaiterId>, waker: &core::task::Waker) {
        self.rx_waiters.register(id, waker);
    }

    fn remove_rx_waker(&self, id: &mut Option<WaiterId>) {
        self.rx_waiters.unregister(id);
    }

    /// Wake parked read futures, removing their registrations before invoking
    /// arbitrary waker code.
    fn wake_rx_waiters(&self) {
        self.rx_waiters.wake_all();
    }

    #[doc(hidden)]
    #[cfg(feature = "netdev")]
    pub fn rx_waiter_count(&self) -> usize {
        self.rx_waiters.len()
    }

    #[doc(hidden)]
    #[cfg(feature = "netdev")]
    pub fn tx_waiter_count(&self) -> usize {
        self.channel().tx_waiter_count()
    }

    /// Run a netdev test while this stream has no allocatable TX pages.
    #[doc(hidden)]
    #[cfg(feature = "netdev")]
    pub fn with_tx_pages_exhausted_for_test(&self, f: impl FnOnce()) {
        let mut pages = alloc::vec::Vec::new();
        while let Ok(page) = self.channel().alloc_page(self.subchannel_mask) {
            pages.push(page);
        }
        f();
    }

    #[doc(hidden)]
    #[cfg(feature = "netdev")]
    pub fn fill_stream_drop_send_queue_for_test(&self) {
        self.channel().fill_stream_drop_send_queue_for_test();
    }

    // Note: this is called from the rx task, so must not sleep. Every
    // path ends in wake_rx_waiters(): parked readers re-check after any
    // RX progress or state change (wake-all-and-recheck).
    pub fn process_incoming_msg(&self, msg: io_channel::Msg) {
        #[cfg(debug_assertions)]
        log::debug!(
            "incoming msg {:?} for stream 0x{:x}",
            api_net::NetCmd::try_from(msg.command).unwrap(),
            msg.handle
        );

        // sys-io returns the original id-zero TX message only when an
        // asynchronous write fails (normally because it raced a close). It
        // carries no RX page and must never enter recv_queue: if unread data
        // is present, poll_rx() and clear_rx_queue() both interpret queued
        // messages as RX data or an ordered state change.
        if msg.command == (api_net::NetCmd::TcpStreamTx as u16) {
            debug_assert_ne!(msg.status, moto_rt::E_OK);
            log::debug!("TX reply for stream 0x{:x}", msg.handle);
            self.wake_rx_waiters();
            return;
        }

        // The main challenge/nuance here is that sometimes we need to raise
        // poll events here, and sometimes we have to delay them. For example,
        // while there are messages in RXQ, we should not raise POLL_READ_CLOSED.
        let mut recv_q = self.recv_queue.lock();

        // If the read half has been shut down locally (shutdown(SHUT_RD)), drop any
        // RX bytes that were already in flight: the application has declared it will
        // not read them, so we discard the data and return the server-allocated page
        // to the channel instead of queueing it (which would spuriously raise
        // POLL_READABLE after READ_CLOSED was already delivered). State-change events
        // still flow through below.
        if msg.command == (api_net::NetCmd::TcpStreamRx as u16)
            && self.rx_closed.load(Ordering::Acquire)
        {
            // Claiming the page(s) and dropping them frees them.
            super::channel::claim_rx_page(self.channel(), &msg, &mut |_page, _len| {});
            self.wake_rx_waiters();
            return;
        }

        let have_rx_bytes = !recv_q.is_empty();
        if have_rx_bytes {
            recv_q.push_back(msg);
            drop(recv_q);

            // No need to raise POLL_READABLE, as this is not a state change
            // (receive queue non-empty).
            if msg.command == (api_net::NetCmd::EvtTcpStreamStateChanged as u16) {
                let new_state = TcpState::try_from(msg.payload.args_32()[0]).unwrap();
                if !new_state.can_write() {
                    // We cannot close the socket yet as there are RX bytes (potentially).
                    self.set_tcp_state(TcpState::ReadOnly);
                }
                // RX done event happens when the recv_q is drained.
            }
            self.wake_rx_waiters();
            return;
        }

        // RXQ is empty.
        if msg.command == (api_net::NetCmd::TcpStreamRx as u16) {
            recv_q.push_back(msg);
            drop(recv_q);
            // The RXQ was empty, this is a new (edge) event.
            self.raise_readiness(Readiness::READABLE);
        } else if msg.command == (api_net::NetCmd::EvtTcpStreamStateChanged as u16) {
            drop(recv_q);
            let new_state = TcpState::try_from(msg.payload.args_32()[0]).unwrap();
            self.set_tcp_state(new_state);
        } else {
            panic!(
                "{}:{}: Unrecognized msg {} for stream 0x{:x}",
                file!(),
                line!(),
                msg.command,
                msg.handle
            )
        }

        self.wake_rx_waiters();
    }

    // The stream was just accepted; there can be messages in its recv_queue that
    // should be processed in order to trigger poll events. The logic is the same
    // as in process_incoming_msg above.
    // TODO: refactor combine process_incoming_msg() and on_accepted(), as
    // the logic is somewhat similar.
    fn on_accepted(&self) {
        let mut recv_q = self.recv_queue.lock();
        if recv_q.is_empty() {
            return;
        }

        if recv_q.have_loose_bytes() {
            // Already some queue processing has been done.
            return;
        }

        let msg = recv_q.pop_front().unwrap();

        if msg.command == (api_net::NetCmd::TcpStreamRx as u16) {
            let sz_read = msg.payload.args_64()[1] as usize;
            if sz_read > 0 {
                // push_front: more Rx messages may have been queued behind
                // this one while the accept was in flight.
                recv_q.push_front(msg);
                drop(recv_q);
                self.raise_readiness(Readiness::READABLE);
            }
        } else if msg.command == (api_net::NetCmd::EvtTcpStreamStateChanged as u16) {
            let new_state = TcpState::try_from(msg.payload.args_32()[0]).unwrap();
            drop(recv_q);
            self.set_tcp_state(new_state);
        } else {
            panic!(
                "{}:{}: Unrecognized msg {} for stream 0x{:x}",
                file!(),
                line!(),
                msg.command,
                msg.handle
            );
        }
    }

    /// Reserve the channel and build the Connecting stream + connect request
    /// shared by the blocking and nonblocking connect paths.
    fn connect_setup(
        socket_addr: &SocketAddr,
        timeout: Option<Duration>,
        event_listener: Arc<dyn NetEventListener>,
    ) -> (Arc<TcpStream>, io_channel::Msg) {
        let mut channel_reservation = super::channel::reserve_channel();
        channel_reservation.reserve_subchannel();
        let subchannel_mask = channel_reservation.subchannel_mask();

        let req = if let Some(timo) = timeout {
            api_net::tcp_stream_connect_timeout_request(
                socket_addr,
                channel_reservation.subchannel_idx(),
                Instant::now() + timo,
            )
        } else {
            api_net::tcp_stream_connect_request(socket_addr, channel_reservation.subchannel_idx())
        };

        let new_stream = Arc::new_cyclic(|me| TcpStream {
            channel_reservation: Some(channel_reservation),
            local_addr: Mutex::new(None),
            remote_addr: *socket_addr,
            handle: AtomicU64::new(SysHandle::NONE.into()),
            event_listener,
            me: me.clone(),
            recv_queue: crate::net::inner_rx_stream::InnerRxStream::new(),
            rx_waiters: WaitSet::new(),
            tcp_state_driver: AtomicU32::new(api_net::TcpState::Connecting.into()),
            rx_closed: AtomicBool::new(false),
            tx_closed: AtomicBool::new(false),
            subchannel_mask,
            error: AtomicU16::new(moto_rt::E_OK),
            pending_tx: Mutex::new(VecDeque::new()),
        });
        super::channel::stats_tcp_stream_created();

        (new_stream, req)
    }

    /// Start a nonblocking connect: post the request and return the still
    /// Connecting stream. The completion runs inline in rx dispatch.
    pub fn connect_nonblocking(
        socket_addr: &SocketAddr,
        timeout: Option<Duration>,
        event_listener: Arc<dyn NetEventListener>,
    ) -> Result<Arc<TcpStream>, ErrorCode> {
        let (new_stream, mut req) = Self::connect_setup(socket_addr, timeout, event_listener);
        req.id = new_stream.channel().new_req_id();
        new_stream.channel().post_rpc(
            req,
            RpcWaiter::Connect {
                stream: new_stream.me.clone(),
                tx: None,
            },
        )?;
        Ok(new_stream)
    }

    /// Connect, resolving once the peer responds. The vdso veneer drives this
    /// to completion with `block_on_sync`; a native user awaits it.
    pub async fn connect(
        socket_addr: &SocketAddr,
        timeout: Option<Duration>,
        event_listener: Arc<dyn NetEventListener>,
    ) -> Result<Arc<TcpStream>, ErrorCode> {
        let (new_stream, req) = Self::connect_setup(socket_addr, timeout, event_listener);

        // The completion (tcp_streams registration, state, events) runs
        // inline in rx dispatch, exactly like the nonblocking path: if it
        // ran here, a state change dispatched right behind the connect
        // response could miss the not-yet-registered stream and be lost.
        // We only learn the outcome through the oneshot.
        let resp = new_stream
            .channel()
            .rpc_connect(req, new_stream.me.clone())
            .await;
        if resp.status().is_err() {
            return Err(resp.status);
        }

        Ok(new_stream)
    }

    // Called inline from rx dispatch: the tcp_streams registration must
    // exist before the next message for the stream is dispatched.
    pub(super) fn on_connect_response(&self, resp: io_channel::Msg) -> Result<(), ErrorCode> {
        if resp.status().is_err() {
            log::debug!("TcpStream::connect {:?} failed", self.remote_addr,);

            let prev = self
                .tcp_state_driver
                .swap(TcpState::Closed.into(), Ordering::Release);
            assert_eq!(prev, TcpState::Connecting.into());

            self.error.store(resp.status, Ordering::Release);

            self.raise_readiness(
                Readiness::READ_CLOSED | Readiness::WRITE_CLOSED | Readiness::ERROR,
            );
            // A reader can park while the stream is still Connecting
            // (another thread/FD); the failed connect is its EOF.
            self.wake_rx_waiters();
            return Err(resp.status);
        }

        assert_ne!(0, resp.handle);
        self.handle.store(resp.handle, Ordering::Release);
        *self.local_addr.lock() = Some(api_net::get_socket_addr(&resp.payload));
        let prev = self
            .tcp_state_driver
            .swap(TcpState::ReadWrite.into(), Ordering::AcqRel);
        assert_eq!(prev, TcpState::Connecting.into());
        self.channel().tcp_stream_created(self);

        self.raise_readiness(Readiness::WRITABLE);

        self.ack_rx();

        log::debug!(
            "new outgoing TcpStream {:?} -> {:?} 0x{:x}, mask: 0x{:x}",
            self.local_addr.lock().unwrap(),
            self.remote_addr,
            self.handle(),
            self.subchannel_mask
        );

        Ok(())
    }

    fn set_tcp_state(&self, new_state: TcpState) {
        let mut prev_state = self.tcp_state();
        let mut new_state = new_state;
        // Assigned on the only loop-exit path (the successful CAS break).
        let notify_rx_done;
        let notify_tx_done;

        if !new_state.can_read() {
            self.rx_closed.store(true, Ordering::Relaxed);
        }
        if !new_state.can_write() {
            self.tx_closed.store(true, Ordering::Relaxed);
        }

        loop {
            let can_read = prev_state.can_read() && new_state.can_read();
            let can_write = prev_state.can_write() && new_state.can_write();
            if can_read {
                new_state = TcpState::ReadOnly;
            } else if can_write {
                new_state = TcpState::WriteOnly;
            } else {
                assert!(!can_read && !can_write);
                new_state = TcpState::Closed;
            }

            match self.tcp_state_driver.compare_exchange_weak(
                prev_state.into(),
                new_state.into(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    notify_rx_done = prev_state.can_read() && !new_state.can_read();
                    notify_tx_done = prev_state.can_write() && !new_state.can_write();
                    break;
                }
                Err(prev) => {
                    prev_state = prev.try_into().unwrap();
                    core::hint::spin_loop();
                }
            }
        }

        let mut edges = Readiness::EMPTY;
        if notify_rx_done {
            edges |= Readiness::READABLE | Readiness::READ_CLOSED;
            // A parked reader must observe the closed read half (this
            // path is also reached from a caller-thread shutdown, where
            // no incoming message will wake it).
            self.wake_rx_waiters();
        }
        if notify_tx_done {
            edges |= Readiness::WRITABLE | Readiness::WRITE_CLOSED;
            // Likewise parked writers: their close check ends the write.
            self.channel().wake_tx_wakers();
        }

        if !edges.is_empty() {
            self.raise_readiness(edges);
        }
    }

    fn poll_rx(&self, bufs: &mut [&mut [u8]], peek: bool) -> Result<usize, ErrorCode> {
        let mut recv_q = self.recv_queue.lock();

        loop {
            // Claim the pages of all leading Rx messages, so that a single
            // read drains as much as fits in `bufs` instead of one page
            // per call.
            while recv_q
                .front()
                .is_some_and(|msg| msg.command == (api_net::NetCmd::TcpStreamRx as u16))
            {
                let msg = recv_q.pop_front().unwrap();
                super::channel::claim_rx_page(self.channel(), &msg, &mut |page, len| {
                    recv_q.push_bytes(page, len)
                });
            }

            let copied = recv_q.copy_out(bufs, peek);
            if copied > 0 || recv_q.have_loose_bytes() {
                // copied == 0 with bytes still queued means `bufs` had no
                // capacity; a zero-sized read returns 0.
                return Ok(copied);
            }

            // No RX bytes; the front message, if any, is not an Rx.
            let Some(msg) = recv_q.pop_front() else {
                if self.rx_closed.load(Ordering::Acquire) {
                    return Ok(0);
                }
                match self.tcp_state() {
                    TcpState::Closed | TcpState::WriteOnly => {
                        return Ok(0);
                    }
                    _ => return Err(moto_rt::E_NOT_READY),
                }
            };

            if msg.command != (api_net::NetCmd::EvtTcpStreamStateChanged as u16) {
                panic!("bad cmd: {} {}", msg.command, msg.status);
            }

            // Note: this message was preprocessed in process_incoming_msg,
            // and the state was set to read-only.
            let new_state = TcpState::try_from(msg.payload.args_32()[0]).unwrap();
            drop(recv_q);
            self.set_tcp_state(new_state);
            match self.tcp_state() {
                TcpState::Closed | TcpState::WriteOnly => {
                    return Ok(0);
                }
                _ => {
                    recv_q = self.recv_queue.lock();
                }
            }
        }
    }

    // ---------------------- async-first data-path API ---------------------- //
    //
    // The native surface (design 5.4): copies happen in the polling context
    // (the caller thread for a vdso `block_on`, an app's executor thread for a
    // native user), never on the channel runtime. The veneer layers blocking,
    // `SO_*TIMEO` and `O_NONBLOCK` on top of these.

    /// Nonblocking read or peek: `Ok(n)` when bytes are copied, `Ok(0)` at
    /// EOF, `E_NOT_READY` when the socket would block.
    pub fn try_read(&self, bufs: &mut [&mut [u8]], peek: bool) -> Result<usize, ErrorCode> {
        self.poll_rx(bufs, peek)
    }

    /// The read/peek future the veneer parks on and a native reactor awaits.
    /// Cancel-safe: dropping it unregisters its waker immediately.
    pub fn read_future<'a, 'b, 'c>(
        &'a self,
        bufs: &'b mut [&'c mut [u8]],
        peek: bool,
    ) -> TcpReadFuture<'a, 'b, 'c> {
        TcpReadFuture {
            stream: self,
            bufs,
            peek,
            waiter_id: None,
        }
    }

    /// Resolves once a read would not block (data buffered or read half
    /// closed). A native reactor awaits this, then calls `try_read`.
    pub fn readable(&self) -> Readable<'_> {
        Readable {
            stream: self,
            waiter_id: None,
        }
    }

    /// Nonblocking write: writes what fits now (`Ok(n)`, at least one byte),
    /// `E_NOT_READY` when fully backpressured, `E_NOT_CONNECTED` on a closed
    /// write half.
    pub fn try_write(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        if bufs.is_empty() {
            return Ok(0);
        }
        if !self.tcp_state().can_write() || self.tx_closed.load(Ordering::Acquire) {
            return Err(moto_rt::E_NOT_CONNECTED);
        }
        self.write_nonblocking(bufs)
    }

    /// The write future the veneer parks on and a native reactor awaits. Its
    /// `written` field carries committed bytes, so a cancelled instance can
    /// surrender partial progress (design rule 7).
    pub fn write_future<'a, 'b, 'c>(&'a self, bufs: &'b [&'c [u8]]) -> TcpWriteFuture<'a, 'b, 'c> {
        let total = bufs.iter().map(|b| b.len()).sum();
        TcpWriteFuture {
            stream: self,
            bufs,
            total,
            written: 0,
            waiter_id: None,
        }
    }

    /// Resolves once a write would not block (send-queue room or write half
    /// closed). A native reactor awaits this, then calls `try_write`.
    pub fn writable(&self) -> Writable<'_> {
        Writable {
            stream: self,
            waiter_id: None,
        }
    }

    pub fn maybe_can_write(&self) {
        if self.have_write_buffer_space() {
            self.raise_readiness(Readiness::WRITABLE);
        } else {
            self.channel().add_write_waiter(self);
            // Close the race with a channel pass draining write_waiters
            // between the check above and the registration: on an
            // otherwise idle channel no later pass would re-examine us,
            // and the WRITABLE edge would be lost (observed as mio-test
            // tcp::test_write hanging). Re-check and raise directly; a
            // spurious WRITABLE is level-correct, a lost one is not.
            if self.have_write_buffer_space() {
                self.raise_readiness(Readiness::WRITABLE);
            }
        }
    }

    fn raise_readiness(&self, edges: Readiness) {
        self.event_listener.on_readiness(edges);
    }

    pub fn have_write_buffer_space(&self) -> bool {
        if self.channel().may_alloc_page(self.subchannel_mask) {
            return true;
        }
        // A partially-filled pending page also accepts bytes.
        self.pending_tx
            .lock()
            .back()
            .map(|back| back.filled < io_channel::PAGE_SIZE)
            .unwrap_or(false)
    }

    /// Whether the write half is still open: not closed by a state edge and
    /// not locally shut down. The veneer's spin loop bails to
    /// `E_NOT_CONNECTED` the moment this goes false.
    pub fn can_write_now(&self) -> bool {
        self.tcp_state().can_write() && !self.tx_closed.load(Ordering::Acquire)
    }

    /// Copy from `src` (skipping its first `offset` bytes) into `dst`;
    /// returns the bytes copied.
    fn tx_copy_at(src: &[&[u8]], mut offset: usize, dst: &mut [u8]) -> usize {
        let mut written = 0;
        for buf in src {
            if offset >= buf.len() {
                offset -= buf.len();
                continue;
            }
            let src_bytes = &buf[offset..];
            offset = 0;

            let to_write = src_bytes.len().min(dst.len() - written);
            dst[written..(written + to_write)].copy_from_slice(&src_bytes[..to_write]);
            written += to_write;

            if written == dst.len() {
                break;
            }
        }

        written
    }

    /// Append bytes from `bufs[offset..]` into the pending back page, if it
    /// has room. Returns the bytes appended. The marker enqueued when that
    /// page was pushed is still pending (or the page would have been
    /// claimed), so the appended bytes ride it — no new message needed.
    fn append_pending_tx(&self, bufs: &[&[u8]], offset: usize) -> usize {
        let mut pending = self.pending_tx.lock();
        let Some(back) = pending.back_mut() else {
            return 0;
        };
        if back.filled == io_channel::PAGE_SIZE {
            return 0;
        }
        let n = Self::tx_copy_at(bufs, offset, &mut back.page.bytes_mut()[back.filled..]);
        back.filled += n;
        n
    }

    fn write_nonblocking(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        // These are checked at the callsite.
        debug_assert!(self.tcp_state().can_write());

        let total_in: usize = bufs.iter().map(|b| b.len()).sum();
        if total_in == 0 {
            return Ok(0);
        }

        let mut written = self.append_pending_tx(bufs, 0);

        while written < total_in {
            let Ok(page) = self.channel().alloc_page(self.subchannel_mask) else {
                break;
            };
            let filled = Self::tx_copy_at(bufs, written, page.bytes_mut());
            debug_assert!(filled > 0);

            let mut pending = self.pending_tx.lock();
            pending.push_back(PendingTxPage { page, filled });
            if self
                .channel()
                .post_msg(super::channel::tcp_tx_marker_msg(self.handle()))
                .is_err()
            {
                // Full send queue; retracting the entry drops (frees) the page.
                let _ = pending.pop_back();
                break;
            }
            written += filled;
        }

        if written == 0 {
            // Registers and re-checks (see maybe_can_write): space
            // appearing concurrently raises WRITABLE, and NOT_READY
            // stays correct either way -- the caller polls and retries.
            self.maybe_can_write();
            return Err(moto_rt::E_NOT_READY);
        }
        Ok(written)
    }

    /// Pop pending TX pages and build one wire message out of them: up to
    /// [`api_net::TCP_TX_MAX_PAGES`] pages, stopping after the first
    /// partially-filled one (the multi-page format requires all pages full
    /// except the last). Returns None if nothing is pending. Called by the
    /// IO thread when it pops a marker — the late length-binding that makes
    /// page fill adapt to load.
    pub(super) fn claim_pending_tx(&self) -> Option<io_channel::Msg> {
        // Multi-page messages matter in this direction — A/B-measured twice
        // (2026-07-11): capping claims at one full page dropped bulk TX
        // 400 -> 342 MiB/s with sys-io's per-msg task spawn in place, and
        // 616 -> 546 after the spawn was removed and Tx dispatched inline —
        // the residual per-message machinery (ring pop, dispatch, socket
        // lookup, stats, notify) still costs ~1-1.5µs, which binds at bulk
        // message rates. The reverse direction measured no difference and
        // stays single-page.
        let mut page_ids = [0_u16; api_net::TCP_TX_MAX_PAGES];
        let mut num_pages = 0_usize;
        let mut total = 0_usize;
        {
            let mut pending = self.pending_tx.lock();
            while num_pages < api_net::TCP_TX_MAX_PAGES {
                let Some(entry) = pending.pop_front() else {
                    break;
                };
                let filled = entry.filled;
                total += filled;
                page_ids[num_pages] = io_channel::IoPage::into_u16(entry.page);
                num_pages += 1;
                if filled < io_channel::PAGE_SIZE {
                    break;
                }
            }
        }

        match num_pages {
            0 => None,
            1 => {
                // Mirrors api_net::tcp_stream_tx_msg (which takes the page
                // by value; ours is already converted).
                let mut msg = io_channel::Msg::new();
                msg.command = api_net::NetCmd::TcpStreamTx as u16;
                msg.handle = self.handle();
                msg.payload.shared_pages_mut()[0] = page_ids[0];
                msg.payload.args_64_mut()[1] = total as u64;
                msg.payload.args_64_mut()[2] = Instant::now().as_u64();
                Some(msg)
            }
            _ => Some(api_net::tcp_stream_tx_multi_msg(
                self.handle(),
                &page_ids[..num_pages],
                total as u32,
                Instant::now().as_u64(),
            )),
        }
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, ErrorCode> {
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
                panic!(
                    "bad state {}",
                    self.tcp_state_driver.load(Ordering::Relaxed)
                )
            }
        }
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.lock()
    }

    /// Shut down one or both halves without blocking the polling thread.
    ///
    /// Cancellation before the request enters the channel leaves the stream
    /// unchanged. Once queued, the local shutdown remains committed even if
    /// the future is dropped, matching the request sys-io now owns.
    pub async fn shutdown_async(&self, shutdown: Shutdown) -> Result<(), ErrorCode> {
        let (read, write) = match shutdown {
            Shutdown::Read => (true, false),
            Shutdown::Write => (false, true),
            Shutdown::Both => (true, true),
        };
        let mut option = 0_u64;
        if read {
            option |= api_net::TCP_OPTION_SHUT_RD;
        }
        if write {
            option |= api_net::TCP_OPTION_SHUT_WR;
        }

        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = option;
        let resp = self
            .channel()
            .rpc_after_send(req, || {
                if read {
                    self.rx_closed.store(true, Ordering::Release);
                    // SHUT_RD is local and discards already-buffered data.
                    // Complete it at the queue-ownership boundary so dropping
                    // the response future cannot retain pages or lose EOF.
                    super::channel::clear_rx_queue(&self.recv_queue, self.channel());
                    self.set_tcp_state(TcpState::WriteOnly);
                }
                if write {
                    // Every completed write queued its TX marker before this
                    // request. The channel expands those markers in FIFO
                    // order, so sys-io receives all committed bytes first.
                    self.tx_closed.store(true, Ordering::Release);
                }
            })
            .await;

        if resp.status().is_ok() {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    /// Set the stream's linger behavior without blocking the polling thread.
    pub async fn set_linger_async(&self, duration: Option<Duration>) -> Result<(), ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_LINGER;
        if let Some(duration) = duration {
            req.payload.args_32_mut()[2] = 1;
            req.payload.args_32_mut()[3] = u32::try_from(duration.as_secs()).unwrap_or(u32::MAX);
        }
        let resp = self.channel().rpc(req).await;
        if resp.status().is_ok() {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    /// Read the stream's linger behavior without blocking the polling thread.
    pub async fn linger_async(&self) -> Result<Option<Duration>, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamGetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_LINGER;
        let resp = self.channel().rpc(req).await;
        if !resp.status().is_ok() {
            return Err(resp.status);
        }
        if resp.payload.args_32()[2] == 0 {
            Ok(None)
        } else {
            Ok(Some(Duration::from_secs(resp.payload.args_32()[3] as u64)))
        }
    }

    /// Set `TCP_NODELAY` without blocking the polling thread.
    pub async fn set_nodelay_async(&self, nodelay: bool) -> Result<(), ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_NODELAY;
        req.payload.args_64_mut()[1] = nodelay as u64;
        let resp = self.channel().rpc(req).await;
        if resp.status().is_ok() {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    /// Read `TCP_NODELAY` without blocking the polling thread.
    pub async fn nodelay_async(&self) -> Result<bool, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamGetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_NODELAY;
        let resp = self.channel().rpc(req).await;
        if resp.status().is_ok() {
            Ok(resp.payload.args_64()[0] != 0)
        } else {
            Err(resp.status)
        }
    }

    /// Set the stream TTL without blocking the polling thread.
    pub async fn set_ttl_async(&self, ttl: u32) -> Result<(), ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        req.payload.args_32_mut()[2] = ttl;
        let resp = self.channel().rpc(req).await;
        if resp.status().is_ok() {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    /// Read the stream TTL without blocking the polling thread.
    pub async fn ttl_async(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamGetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        let resp = self.channel().rpc(req).await;
        if resp.status().is_ok() {
            Ok(resp.payload.args_32()[0])
        } else {
            Err(resp.status)
        }
    }

    /// Take and clear the error an async operation left behind; this is what
    /// `SO_ERROR` reports, and reading it is what clears it.
    pub fn take_error(&self) -> ErrorCode {
        let err = self.error.swap(moto_rt::E_OK, Ordering::Relaxed);
        err as ErrorCode
    }
}

// -------------------- data-path futures (design 5.3/5.4) ------------------- //
//
// The async cores of read/write. Copies happen in poll, i.e. on the polling
// thread (a vdso caller via the veneer's block_on, or a native app's
// executor), never the channel runtime. The blocking spin/park/timeout that
// drives these for the vdso lives in the veneer (rt.vdso net::blocking).

impl TcpStream {
    /// `push_pending_tx` without the blocking retry: on a full send
    /// queue the entry is retracted (freeing the page) and Err returned;
    /// the caller re-copies on its next attempt. Backpressure-path cost.
    fn try_push_pending_tx(
        &self,
        page: io_channel::IoPage,
        bufs: &[&[u8]],
        offset: usize,
    ) -> Result<usize, ()> {
        let filled = Self::tx_copy_at(bufs, offset, page.bytes_mut());
        debug_assert!(filled > 0);
        let mut pending = self.pending_tx.lock();
        pending.push_back(PendingTxPage { page, filled });
        if self
            .channel()
            .post_msg(super::channel::tcp_tx_marker_msg(self.handle()))
            .is_ok()
        {
            return Ok(filled);
        }
        // We held the lock throughout, so the entry is still the back;
        // dropping it frees the page.
        let _ = pending.pop_back();
        Err(())
    }
}

/// A blocking read expressed as a future. Cancel-safe (design rule 7):
/// all RX state lives in the stream, and dropping an instance unregisters
/// its waker immediately.
pub struct TcpReadFuture<'a, 'b, 'c> {
    pub stream: &'a TcpStream,
    pub bufs: &'b mut [&'c mut [u8]],
    pub peek: bool,
    waiter_id: Option<WaiterId>,
}

impl Drop for TcpReadFuture<'_, '_, '_> {
    fn drop(&mut self) {
        self.stream.remove_rx_waker(&mut self.waiter_id);
    }
}

impl core::future::Future for TcpReadFuture<'_, '_, '_> {
    type Output = Result<usize, ErrorCode>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        use core::task::Poll;

        let this = self.get_mut();
        match this.stream.poll_rx(this.bufs, this.peek) {
            Err(moto_rt::E_NOT_READY) => {}
            res => {
                this.stream.remove_rx_waker(&mut this.waiter_id);
                return Poll::Ready(res);
            }
        }
        // Register-then-recheck closes the race with the rx task
        // queueing between the check above and the registration.
        this.stream.add_rx_waker(&mut this.waiter_id, cx.waker());
        match this.stream.poll_rx(this.bufs, this.peek) {
            Err(moto_rt::E_NOT_READY) => Poll::Pending,
            res => {
                this.stream.remove_rx_waker(&mut this.waiter_id);
                Poll::Ready(res)
            }
        }
    }
}

/// A blocking write expressed as a future. Committed bytes ride in
/// `written`, so a timed-out instance surrenders partial progress
/// (design rule 7, the rt_tcp SO_SNDTIMEO contract: Ok(written)).
///
/// Wait/return policy mirrors the old blocking loop exactly: a closed
/// write half ends the write with Ok(written); a missing io_page parks
/// only while written == 0 (a partial write returns instead); a full
/// send queue parks unconditionally (the marker must land).
pub struct TcpWriteFuture<'a, 'b, 'c> {
    pub stream: &'a TcpStream,
    pub bufs: &'b [&'c [u8]],
    pub total: usize,
    pub written: usize,
    waiter_id: Option<WaiterId>,
}

impl Drop for TcpWriteFuture<'_, '_, '_> {
    fn drop(&mut self) {
        self.stream.channel().remove_tx_waker(&mut self.waiter_id);
    }
}

impl core::future::Future for TcpWriteFuture<'_, '_, '_> {
    type Output = Result<usize, ErrorCode>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        use core::task::Poll;

        let this = self.get_mut();
        let stream = this.stream;
        loop {
            if !stream.tcp_state().can_write() || stream.tx_closed.load(Ordering::Acquire) {
                stream.channel().remove_tx_waker(&mut this.waiter_id);
                return Poll::Ready(Ok(this.written));
            }

            // Top up the unclaimed pending back page: no alloc, no
            // queue traffic.
            this.written += stream.append_pending_tx(this.bufs, this.written);
            if this.written == this.total {
                stream.channel().remove_tx_waker(&mut this.waiter_id);
                return Poll::Ready(Ok(this.written));
            }

            let Ok(page) = stream.channel().alloc_page(stream.subchannel_mask) else {
                if this.written > 0 {
                    // Partial write: return it rather than wait for
                    // pages (the old loop's opportunistic tail).
                    stream.channel().remove_tx_waker(&mut this.waiter_id);
                    return Poll::Ready(Ok(this.written));
                }
                // The failed alloc set the subchannel's page-wait bits;
                // sys-io will wake the channel, whose next pass drains
                // TX waiters. Register, then re-check via the loop.
                stream
                    .channel()
                    .add_tx_waker(&mut this.waiter_id, cx.waker());
                if stream.channel().may_alloc_page(stream.subchannel_mask) {
                    continue;
                }
                return Poll::Pending;
            };

            match stream.try_push_pending_tx(page, this.bufs, this.written) {
                Ok(filled) => this.written += filled,
                Err(()) => {
                    // Full send queue. Register, re-check, park; the
                    // page was freed and is re-allocated on retry.
                    stream
                        .channel()
                        .add_tx_waker(&mut this.waiter_id, cx.waker());
                    if !stream.channel().send_queue_is_full() {
                        continue;
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

impl TcpStream {
    /// Whether a read would not block: buffered RX, or the read half is
    /// closed (an EOF read returns immediately). Mirrors the veneer's
    /// poll-registry READABLE synthesis.
    fn read_ready(&self) -> bool {
        !self.tcp_state().can_read()
            || self.rx_closed.load(Ordering::Acquire)
            || self.has_rx_bytes()
    }
}

/// Read-readiness future (design 5.4): resolves once `try_read` would not
/// block. A native reactor awaits this, then drains with `try_read`; the vdso
/// veneer parks on the richer `read_future` instead. Cancel-safe.
pub struct Readable<'a> {
    stream: &'a TcpStream,
    waiter_id: Option<WaiterId>,
}

impl Drop for Readable<'_> {
    fn drop(&mut self) {
        self.stream.remove_rx_waker(&mut self.waiter_id);
    }
}

impl core::future::Future for Readable<'_> {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        use core::task::Poll;

        let this = self.get_mut();
        let stream = this.stream;
        if stream.read_ready() {
            stream.remove_rx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        // Register-then-recheck closes the race with the rx task queueing
        // between the check above and the registration.
        stream.add_rx_waker(&mut this.waiter_id, cx.waker());
        if stream.read_ready() {
            stream.remove_rx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        Poll::Pending
    }
}

/// Write-readiness future (design 5.4): resolves once `try_write` would not
/// block. Arms the cross-process page-wait wake the same way the write
/// future does — a failed probe alloc sets the subchannel's page-wait bits,
/// so sys-io wakes the channel when it frees a page. Cancel-safe.
pub struct Writable<'a> {
    stream: &'a TcpStream,
    waiter_id: Option<WaiterId>,
}

impl Drop for Writable<'_> {
    fn drop(&mut self) {
        self.stream.channel().remove_tx_waker(&mut self.waiter_id);
    }
}

impl core::future::Future for Writable<'_> {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        use core::task::Poll;

        let this = self.get_mut();
        let stream = this.stream;
        if !stream.tcp_state().can_write() || stream.tx_closed.load(Ordering::Acquire) {
            // A closed write half never blocks; the write returns an error.
            stream.channel().remove_tx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        if stream.have_write_buffer_space() {
            stream.channel().remove_tx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        // Register, then arm: the failed alloc sets the page-wait bits sys-io
        // watches. A page that frees in the window is caught by the re-check.
        stream
            .channel()
            .add_tx_waker(&mut this.waiter_id, cx.waker());
        match stream.channel().alloc_page(stream.subchannel_mask) {
            Ok(page) => {
                // Room appeared; drop the probe page to free it.
                drop(page);
                stream.channel().remove_tx_waker(&mut this.waiter_id);
                Poll::Ready(())
            }
            Err(_) => {
                if stream.have_write_buffer_space() {
                    stream.channel().remove_tx_waker(&mut this.waiter_id);
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }
        }
    }
}
