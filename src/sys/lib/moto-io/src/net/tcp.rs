//! The TCP socket state machines (design section 5): `TcpStream` and
//! `TcpListener`, plus the blocking-path futures. The vdso keeps only a thin
//! veneer over these (PosixFile impls, the poll-registry event synthesis);
//! everything here talks to sys-io through the channel runtime in
//! [`super::channel`] and emits readiness through an abstract
//! [`crate::net::readiness::NetEventListener`], so it names no vdso type.

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
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

use crate::net::readiness::NetEventListener;
use crate::net::readiness::Readiness;
use super::channel::ChannelReservation;
use super::channel::NetChannel;
use super::channel::RpcWaiter;

/// An accepted-but-not-yet-claimed connection: the accept response plus
/// the channel reservation made when the accept was posted.
pub(super) struct PendingAccept {
    reservation: ChannelReservation,
    resp: moto_ipc::io_channel::Msg,
}

pub struct TcpListener {
    socket_addr: SocketAddr,
    channel_reservation: ChannelReservation,
    handle: u64,
    nonblocking: AtomicBool,
    // The socket's sole poll-registry handle: state-machine edges emit through
    // it (raise_readiness), and the veneer downcasts it back to the concrete
    // source for interest registration. No poll-registry type sits in the
    // struct, so the state machine is movable to moto-io (Stage F).
    event_listener: Arc<dyn NetEventListener>,

    // In-flight accept requests: req_id => the reservation the accepted
    // stream will use. Blocking accepts additionally await a oneshot
    // held in the channel's RPC map.
    accept_requests: Mutex<BTreeMap<u64, ChannelReservation>>,

    // Incoming async accepts are stored here. Better processed
    // in arrival order.
    async_accepts: Mutex<VecDeque<PendingAccept>>,

    // In sys-io, connected sockets may generate tcp stream messages such as
    // rx, rx_done, close, etc. Here (vdso), the stream is not created until
    // the user calls accept() asynchronously (vs the I/O thread), so
    // we need a place to store messages for not-yet-accepted TCP streams.
    // MIO test actually tests this scenario.
    pending_accept_queues: Mutex<BTreeMap<u64, Arc<Mutex<crate::net::inner_rx_stream::InnerRxStream>>>>,

    max_backlog: AtomicU32,
    me: Weak<TcpListener>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut msg = io_channel::Msg::new();
        msg.command = api_net::NetCmd::TcpListenerDrop as u16;
        msg.handle = self.handle;

        self.channel().send_msg(msg);

        while let Some((_, stream)) = { self.pending_accept_queues.lock().pop_first() } {
            // Free up server-allocated pages.
            super::channel::clear_rx_queue(&stream, self.channel());
        }

        self.channel().tcp_listener_dropped(self.handle);

        super::channel::stats_tcp_listener_dropped();
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
        self.pending_accept_queues
            .lock()
            .insert(resp.handle, crate::net::inner_rx_stream::InnerRxStream::new());

        let pending = PendingAccept { reservation, resp };

        if let Some(tx) = sync_tx {
            // The blocking accept's caller awaits this on its parker.
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

    /// The listener's readiness sink. The vdso veneer installed a concrete
    /// poll-registry source and downcasts this abstract handle back to it.
    pub fn event_listener(&self) -> &dyn NetEventListener {
        self.event_listener.as_ref()
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

    fn channel(&self) -> &super::channel::NetChannel {
        self.channel_reservation.channel()
    }

    pub fn bind(
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
        let resp = channel_reservation.channel().send_receive(req);
        if resp.status().is_err() {
            return Err(resp.status);
        }

        if socket_addr.port() == 0 {
            let actual_addr = api_net::get_socket_addr(&resp.payload);
            assert_eq!(socket_addr.ip(), actual_addr.ip());
            assert_ne!(0, actual_addr.port());
            socket_addr.set_port(actual_addr.port());
        }

        let tcp_listener = Arc::new_cyclic(|me| {
            TcpListener {
                socket_addr,
                channel_reservation,
                handle: resp.handle,
                nonblocking: AtomicBool::new(false),
                event_listener,
                accept_requests: Mutex::new(BTreeMap::new()),
                async_accepts: Mutex::new(VecDeque::new()),
                pending_accept_queues: Mutex::new(BTreeMap::new()),
                max_backlog: AtomicU32::new(32),
                me: me.clone(),
            }
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

    pub fn listen(&self, max_backlog: u32) -> Result<(), ErrorCode> {
        if !self.nonblocking.load(Ordering::Relaxed) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

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

    fn get_pending_accept(&self) -> Result<PendingAccept, ErrorCode> {
        if let Some(pending_accept) = self.async_accepts.lock().pop_front() {
            return Ok(pending_accept);
        }

        if self.nonblocking.load(Ordering::Relaxed) {
            return Err(moto_rt::E_NOT_READY);
        };

        let (tx, rx) = moto_async::oneshot();
        self.post_accept(Some(tx));

        // The sender lives in the channel's RPC map; it cannot be
        // dropped unresolved while we hold &self (see rx dispatch).
        Ok(moto_async::block_on_sync(rx).expect("accept RPC dropped"))
    }

    pub fn accept(
        &self,
        make_listener: &dyn Fn() -> Arc<dyn NetEventListener>,
    ) -> Result<(Arc<TcpStream>, SocketAddr), ErrorCode> {
        let PendingAccept { reservation, resp } = self.get_pending_accept()?;
        if resp.status().is_err() {
            let rx_queue = self
                .pending_accept_queues
                .lock()
                .remove(&resp.handle)
                .unwrap();
            crate::net::channel::clear_rx_queue(&rx_queue, self.channel());
            return Err(resp.status);
        }

        let remote_addr = api_net::get_socket_addr(&resp.payload);
        let channel_reservation = reservation;
        let subchannel_mask = channel_reservation.subchannel_mask();

        // Don't remove the queue until the channel can access it via the new stream.
        let recv_queue = self
            .pending_accept_queues
            .lock()
            .get(&resp.handle)
            .unwrap()
            .clone();

        let new_stream = Arc::new_cyclic(|me| {
            TcpStream {
                local_addr: Mutex::new(Some(self.socket_addr)),
                remote_addr,
                handle: AtomicU64::new(resp.handle),
                event_listener: make_listener(),
                me: me.clone(),
                nonblocking: AtomicBool::new(self.nonblocking.load(Ordering::Relaxed)),
                channel_reservation,
                recv_queue,
                rx_wakers: Mutex::new(Vec::new()),
                tcp_state_driver: AtomicU32::new(api_net::TcpState::ReadWrite.into()),
                rx_closed: AtomicBool::new(false),
                tx_closed: AtomicBool::new(false),
                rx_timeout_ns: AtomicU64::new(u64::MAX),
                tx_timeout_ns: AtomicU64::new(u64::MAX),
                subchannel_mask,
                error: AtomicU16::new(moto_rt::E_OK),
                pending_tx: Mutex::new(VecDeque::new()),
            }
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

        Ok((new_stream, remote_addr))
    }

    /// Reserve a fresh channel for one incoming connection and post the
    /// accept RPC on it. Guaranteed delivery (design 5.2): a full send
    /// queue no longer fails and drops the slot. A caller-thread post (a
    /// blocking accept, or `listen`) parks until there is room; a re-post
    /// from the rx task (see `on_accept_response`) hands the retry to a
    /// task when the reserved channel is the one we run on, and otherwise
    /// briefly waits out that channel's queue — never a self-deadlock.
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

        let waiter = RpcWaiter::Accept(self.me.clone(), sync_tx);
        channel.send_rpc_guaranteed(req, waiter);
    }

    /// # Safety
    ///
    /// `ptr` must be valid for `len` readable bytes holding the value for `option`.
    pub unsafe fn setsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_NONBLOCKING => {
                assert_eq!(len, 1);
                let nonblocking = unsafe { *(ptr as *const u8) };
                if nonblocking > 1 {
                    return moto_rt::E_INVALID_ARGUMENT;
                }
                self.set_nonblocking(nonblocking == 1)
            }
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                let ttl = unsafe { *(ptr as *const u32) };
                self.set_ttl(ttl)
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    /// # Safety
    ///
    /// `ptr` must be valid for `len` writable bytes to receive `option`'s value.
    pub unsafe fn getsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                match self.ttl() {
                    Ok(ttl) => {
                        unsafe { *(ptr as *mut u32) = ttl };
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                }
            }
            moto_rt::net::SO_ERROR => {
                assert_eq!(len, 2);
                let err = self.take_error();
                unsafe { *(ptr as *mut u16) = err };
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
        req.command = api_net::NetCmd::TcpListenerSetOption as u16;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        req.payload.args_8_mut()[23] = ttl as u8;
        self.channel().send_receive(req).status
    }

    fn ttl(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpListenerGetOption as u16;
        req.handle = self.handle;
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        let resp = self.channel().send_receive(req);

        if resp.status().is_ok() {
            Ok(resp.payload.args_8()[23] as u32)
        } else {
            Err(resp.status)
        }
    }

    fn take_error(&self) -> ErrorCode {
        moto_rt::E_OK
    }

    fn set_nonblocking(&self, nonblocking: bool) -> ErrorCode {
        let was_blocking = !self.nonblocking.swap(nonblocking, Ordering::Release);
        if nonblocking && was_blocking {
            match self.listen(1024) {
                Ok(()) => moto_rt::E_OK,
                Err(err) => err,
            }
            // TODO: at the moment, previously-issues blocking accepts
            // will remain blocking. Maybe they should be kicked with moto_rt::E_NOT_READY?
        } else {
            moto_rt::E_OK
        }
    }
}

pub struct TcpStream {
    channel_reservation: ChannelReservation,
    local_addr: Mutex<Option<SocketAddr>>,
    remote_addr: SocketAddr,
    handle: AtomicU64,
    // The socket's sole poll-registry handle: state-machine edges emit through
    // it (raise_readiness), and the veneer downcasts it back to the concrete
    // source for interest registration. No poll-registry type sits in the
    // struct, so the state machine is movable to moto-io (Stage F).
    event_listener: Arc<dyn NetEventListener>,
    nonblocking: AtomicBool,
    me: Weak<TcpStream>,

    // This is, most of the time, a single-producer, single-consumer queue.
    // MUST be locked before rx_buf is locked.
    recv_queue: Arc<Mutex<crate::net::inner_rx_stream::InnerRxStream>>,

    // Wakers of parked read futures, drained (wake-all-and-recheck) on
    // every incoming message and read-closing state change. Multiple
    // entries = concurrent readers on dup'd FDs, all correct candidates
    // for the next byte.
    rx_wakers: Mutex<Vec<core::task::Waker>>,

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

    rx_timeout_ns: AtomicU64,
    tx_timeout_ns: AtomicU64,

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

impl Drop for TcpStream {
    fn drop(&mut self) {
        let handle = self.handle.load(Ordering::Acquire);
        if handle == 0 {
            super::channel::stats_tcp_stream_dropped();
            return;
        }

        // Written bytes must reach the wire before the close.
        self.flush_pending_tx();

        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamClose as u16;
        req.handle = self.handle();

        // Guaranteed delivery: never drop the close (sys-io would leak the
        // stream), never panic on a full send queue, and never deadlock when
        // this drop runs on the IO thread (see send_msg_guaranteed).
        self.channel().send_msg_guaranteed(req);

        // Clear RX queue: basically, free up server-allocated pages.
        super::channel::clear_rx_queue(&self.recv_queue, self.channel());
        assert!(self.recv_queue.lock().is_empty());

        self.channel().tcp_stream_dropped(self.handle());
        super::channel::stats_tcp_stream_dropped();
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
        self.channel_reservation.channel()
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
        self.channel().send_msg(req);
    }

    pub fn tcp_state(&self) -> api_net::TcpState {
        api_net::TcpState::try_from(self.tcp_state_driver.load(Ordering::Acquire)).unwrap()
    }

    /// Register a read future's waker. The caller must re-check for RX
    /// progress after registering (register-then-recheck closes the race
    /// with the rx task queueing in between).
    fn add_rx_waker(&self, waker: &core::task::Waker) {
        let mut wakers = self.rx_wakers.lock();
        if !wakers.iter().any(|w| w.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }

    /// Wake parked read futures. drain() keeps the Vec's capacity: no
    /// allocation per park/wake cycle. Waking under the lock is fine
    /// (a bridge-waker wake never blocks).
    fn wake_rx_waiters(&self) {
        let mut wakers = self.rx_wakers.lock();
        for waker in wakers.drain(..) {
            waker.wake();
        }
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
        } else if msg.command == (api_net::NetCmd::TcpStreamTx as u16) {
            // TX closed. The driver was supposed to clear IO Pages.
            drop(recv_q);
            log::debug!("TX reply for stream 0x{:x}", msg.handle);
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

    pub fn connect(
        socket_addr: &SocketAddr,
        timeout: Option<Duration>,
        nonblocking: bool,
        event_listener: Arc<dyn NetEventListener>,
    ) -> Result<Arc<TcpStream>, ErrorCode> {
        let mut channel_reservation = super::channel::reserve_channel();
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

        let new_stream = Arc::new_cyclic(|me| {
            TcpStream {
                channel_reservation,
                local_addr: Mutex::new(None),
                remote_addr: *socket_addr,
                handle: AtomicU64::new(SysHandle::NONE.into()),
                event_listener,
                me: me.clone(),
                nonblocking: AtomicBool::new(nonblocking),
                recv_queue: crate::net::inner_rx_stream::InnerRxStream::new(),
                rx_wakers: Mutex::new(Vec::new()),
                tcp_state_driver: AtomicU32::new(api_net::TcpState::Connecting.into()),
                rx_closed: AtomicBool::new(false),
                tx_closed: AtomicBool::new(false),
                rx_timeout_ns: AtomicU64::new(u64::MAX),
                tx_timeout_ns: AtomicU64::new(u64::MAX),
                subchannel_mask,
                error: AtomicU16::new(moto_rt::E_OK),
                pending_tx: Mutex::new(VecDeque::new()),
            }
        });
        super::channel::stats_tcp_stream_created();

        if nonblocking {
            req.id = new_stream.channel().new_req_id();
            new_stream
                .channel()
                .post_rpc(req, RpcWaiter::Connect(new_stream.me.clone(), None))?;
            return Ok(new_stream);
        }

        // The completion (tcp_streams registration, state, events) runs
        // inline in rx dispatch, exactly like the nonblocking path: if it
        // ran here, a state change dispatched right behind the connect
        // response could miss the not-yet-registered stream and be lost.
        // We only learn the outcome through the oneshot.
        let (tx, rx) = moto_async::oneshot();
        req.id = new_stream.channel().new_req_id();
        new_stream
            .channel()
            .send_rpc(req, RpcWaiter::Connect(new_stream.me.clone(), Some(tx)));
        let resp = moto_async::block_on_sync(rx).expect("connect RPC dropped");
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

    pub fn peek(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_or_peek(&mut [buf], true)
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

    pub fn read_or_peek(&self, bufs: &mut [&mut [u8]], peek: bool) -> Result<usize, ErrorCode> {
        match self.poll_rx(bufs, peek) {
            Ok(sz) => return Ok(sz),
            Err(err) => assert_eq!(err, moto_rt::E_NOT_READY),
        }

        if self.nonblocking.load(Ordering::Relaxed) {
            return Err(moto_rt::E_NOT_READY);
        }

        // The rx task wakes the future on every incoming message and
        // read-closing state edge; even a closed socket keeps reading
        // until the buffered RX drains (poll_rx owns that logic). The
        // recheck park (RX_PARK_RECHECK) is the old loop's 5-second
        // read timeout kept as lost-wake insurance.
        let rx_timeout_ns = self.rx_timeout_ns.load(Ordering::Relaxed);
        let fut = TcpReadFuture {
            stream: self,
            bufs,
            peek,
        };
        let deadline = if rx_timeout_ns == u64::MAX {
            None
        } else {
            Some(Instant::now() + Duration::from_nanos(rx_timeout_ns))
        };
        match block_on_recheck(fut, deadline, RX_PARK_RECHECK) {
            Ok(res) => res,
            Err(_fut) => Err(moto_rt::E_TIMED_OUT),
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

    /// The stream's readiness sink. The vdso veneer installed a concrete
    /// poll-registry source and downcasts this abstract handle back to it.
    pub fn event_listener(&self) -> &dyn NetEventListener {
        self.event_listener.as_ref()
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

    pub fn write(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        if bufs.is_empty() {
            return Ok(0);
        }
        if !self.tcp_state().can_write() || self.tx_closed.load(Ordering::Acquire) {
            return Err(moto_rt::E_NOT_CONNECTED);
        }

        if self.nonblocking.load(Ordering::Relaxed) {
            return self.write_nonblocking(bufs);
        }

        let total_in: usize = bufs.iter().map(|b| b.len()).sum();
        if total_in == 0 {
            return Ok(0);
        }

        // Fast path before committing to a park: write what fits, then spin
        // and yield (re-checking for page room) instead of parking. A small
        // write that briefly outruns sys-io's drain grabs a freed page here
        // rather than paying a park+wake syscall per write (see TX_WRITE_SPINS).
        // A return here means at least one byte moved; only a fully backpressured
        // write (nothing written after the whole budget) falls to the future.
        match self.write_nonblocking(bufs) {
            Ok(n) => return Ok(n),
            Err(err) if err != moto_rt::E_NOT_READY => return Err(err),
            Err(_) => {}
        }
        for i in 0..(TX_WRITE_SPINS + TX_WRITE_YIELDS) {
            if i < TX_WRITE_SPINS {
                core::hint::spin_loop();
            } else {
                moto_sys::SysCpu::sched_yield();
            }
            if !self.tcp_state().can_write() || self.tx_closed.load(Ordering::Acquire) {
                return Err(moto_rt::E_NOT_CONNECTED);
            }
            if self.have_write_buffer_space() {
                match self.write_nonblocking(bufs) {
                    Ok(n) => return Ok(n),
                    Err(err) if err != moto_rt::E_NOT_READY => return Err(err),
                    Err(_) => {}
                }
            }
        }

        // The future owns the whole blocking dance: pending-page top-up,
        // page alloc (parking on the channel's tx_wakers; the failed
        // alloc's page-wait bits make sys-io wake the channel), marker
        // enqueue. Committed bytes survive a timeout (design rule 7).
        let timo_ns = self.tx_timeout_ns.load(Ordering::Relaxed);
        let fut = TcpWriteFuture {
            stream: self,
            bufs,
            total: total_in,
            written: 0,
        };
        let deadline = if timo_ns == u64::MAX {
            None
        } else {
            Some(Instant::now() + Duration::from_nanos(timo_ns))
        };
        // Bounded-recheck park (see TX_PARK_RECHECK): a lost backpressure
        // wake self-heals within one tick instead of hanging.
        match block_on_recheck(fut, deadline, TX_PARK_RECHECK) {
            Ok(res) => res,
            // Timed out: surrender partial progress (design rule 7).
            Err(fut) => {
                if fut.written > 0 {
                    Ok(fut.written)
                } else {
                    Err(moto_rt::E_TIMED_OUT)
                }
            }
        }
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
    /// page fill adapt to load — and by [`Self::flush_pending_tx`].
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

    /// Send all pending TX bytes now, ahead of a Close/shutdown(write)
    /// control message; the pages' markers, still queued behind us, then
    /// no-op on the emptied queue. Guaranteed delivery, because this runs
    /// from drop, potentially on the IO thread itself.
    fn flush_pending_tx(&self) {
        while let Some(msg) = self.claim_pending_tx() {
            self.channel().send_msg_guaranteed(msg);
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

    fn shutdown(&self, read: bool, write: bool) -> ErrorCode {
        // Note: for the write half we don't change tcp state here; we do that when
        // we receive the appropriate event from sys-io. The read half is handled
        // locally below (see the comment after send_receive).
        assert!(read || write);
        let mut option = 0_u64;
        if read {
            option |= api_net::TCP_OPTION_SHUT_RD;
            self.rx_closed.store(true, Ordering::Release);
        }
        if write {
            option |= api_net::TCP_OPTION_SHUT_WR;
            self.tx_closed.store(true, Ordering::Release);
            // Bytes written before the shutdown must go out before sys-io
            // sees SHUT_WR (their still-queued markers will no-op).
            self.flush_pending_tx();
        }

        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = option;
        let resp = self.channel().send_receive(req);

        if read && resp.status().is_ok() {
            // shutdown(SHUT_RD) is a local operation: the read half is closed
            // immediately, independent of the remote. sys-io only flips an internal
            // flag in response to TCP_OPTION_SHUT_RD and does not push a state change
            // back to us, so we complete the read shutdown here rather than waiting
            // for a state-change event (which would otherwise only arrive once the
            // connection is torn down).
            //
            // Bytes already received from the remote but not yet read by the
            // application are dropped: this matches POSIX shutdown(SHUT_RD) semantics,
            // where queued receive data is discarded and subsequent reads return EOF.
            // Dropping them here (before raising READ_CLOSED) also guarantees we never
            // deliver READ_CLOSED ahead of bytes the application could still observe.
            // Any RX bytes still in flight are dropped in process_incoming_msg() (see
            // the rx_closed guard there).
            super::channel::clear_rx_queue(&self.recv_queue, self.channel());
            self.set_tcp_state(TcpState::WriteOnly);
        }

        resp.status
    }

    // SO_LINGER is implemented against sys-io but not yet wired to the
    // setsockopt/getsockopt dispatch; kept for when the native API adds it.
    #[allow(dead_code)]
    fn set_linger(&self, dur: Option<Duration>) -> ErrorCode {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_LINGER;
        if let Some(dur) = dur {
            req.payload.args_32_mut()[2] = 1;
            req.payload.args_32_mut()[3] = u32::try_from(dur.as_secs()).unwrap_or(u32::MAX);
        } else {
            req.payload.args_32_mut()[2] = 0;
        }
        self.channel().send_receive(req).status
    }

    #[allow(dead_code)]
    fn linger(&self) -> Result<Option<Duration>, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamGetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_LINGER;
        let resp = self.channel().send_receive(req);

        if resp.status().is_ok() {
            if resp.payload.args_32()[2] == 0 {
                Ok(None)
            } else {
                let secs = resp.payload.args_32()[3];
                Ok(Some(Duration::from_secs(secs as u64)))
            }
        } else {
            Err(resp.status)
        }
    }

    fn set_nodelay(&self, nodelay: u8) -> ErrorCode {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_NODELAY;
        req.payload.args_64_mut()[1] = nodelay as u64;
        self.channel().send_receive(req).status
    }

    fn nodelay(&self) -> Result<u8, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamGetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_NODELAY;
        let resp = self.channel().send_receive(req);

        if resp.status().is_ok() {
            let res = resp.payload.args_64()[0];
            Ok(res as u8)
        } else {
            Err(resp.status)
        }
    }

    fn set_ttl(&self, ttl: u32) -> ErrorCode {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        req.payload.args_32_mut()[2] = ttl;
        self.channel().send_receive(req).status
    }

    fn ttl(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamGetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        let resp = self.channel().send_receive(req);

        if resp.status().is_ok() {
            Ok(resp.payload.args_32()[0])
        } else {
            Err(resp.status)
        }
    }

    fn take_error(&self) -> ErrorCode {
        let err = self.error.swap(moto_rt::E_OK, Ordering::Relaxed);
        err as ErrorCode
    }

    fn set_nonblocking(&self, nonblocking: bool) -> ErrorCode {
        self.nonblocking.store(nonblocking, Ordering::Release);
        moto_rt::E_OK
    }
}

// ------------------- blocking-path futures (design 5.3) ------------------- //
//
// The sync read/write paths drive these via block_on_sync /
// block_on_sync_deadline. Copies happen in poll, i.e. on the polling
// caller thread, never the channel runtime.

/// Longest a bounded-recheck park sleeps before re-polling regardless of
/// wakes. The TX backpressure wake crosses the process boundary (sys-io
/// frees a page -> wakes the channel runtime -> the tx-waker list), and
/// that path is not race-free in practice — the old blocking write loop
/// carried an exponential sleep ladder (max 3s) for exactly this reason.
/// A miss now costs at most one tick of extra latency instead of a hang;
/// a healthy send never waits this long, so steady-state TX pays nothing.
/// Also the UDP send recheck (rt_udp shares block_on_recheck).
pub(super) const TX_PARK_RECHECK: Duration = Duration::from_millis(500);

/// Read-side recheck interval: the old blocking read loop woke every 5s
/// (its `DEBUG_TIMEOUT`) even without data, which masked any lost RX
/// wake; kept here as the same insurance. A blocked reader waiting for
/// data pays one wasted wakeup per interval, as it did before. Also the
/// UDP recv recheck (rt_udp shares block_on_recheck).
pub(super) const RX_PARK_RECHECK: Duration = Duration::from_secs(5);

/// A blocking write spins then yields this many times, re-checking for TX-page
/// room, before it commits to a park. Restores the pre-D4b ladder's cheap page
/// grab: a small write that briefly outruns sys-io's drain catches a freed page
/// here instead of paying a park+wake syscall per write (~30% of default-buffer
/// bulk TX, kill checkpoint 2). Uncontended writes and RR never reach the spin.
const TX_WRITE_SPINS: usize = 100;
const TX_WRITE_YIELDS: usize = 100;

/// Drive `fut` on the calling thread, capping each park at `recheck` so a
/// lost wake self-heals on the next tick. `deadline` is the real
/// `SO_*TIMEO` bound if any; `Err(fut)` is only returned once that real
/// deadline passes (never on a recheck tick), so the caller can extract
/// partial progress.
pub(super) fn block_on_recheck<F: core::future::Future + Unpin>(
    mut fut: F,
    deadline: Option<Instant>,
    recheck: Duration,
) -> Result<F::Output, F> {
    loop {
        let now = Instant::now();
        if let Some(d) = deadline
            && now >= d
        {
            return Err(fut);
        }
        let tick = match deadline {
            Some(d) => d.min(now + recheck),
            None => now + recheck,
        };
        match moto_async::block_on_sync_deadline(fut, tick) {
            Ok(v) => return Ok(v),
            // Either the recheck tick or the real deadline fired; the loop
            // top distinguishes them and re-polls (self-healing a lost wake).
            Err(f) => fut = f,
        }
    }
}

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
/// all RX state lives in the stream; dropping a timed-out instance
/// leaves at most a stale waker entry.
pub(super) struct TcpReadFuture<'a, 'b, 'c> {
    pub stream: &'a TcpStream,
    pub bufs: &'b mut [&'c mut [u8]],
    pub peek: bool,
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
            res => return Poll::Ready(res),
        }
        // Register-then-recheck closes the race with the rx task
        // queueing between the check above and the registration.
        this.stream.add_rx_waker(cx.waker());
        match this.stream.poll_rx(this.bufs, this.peek) {
            Err(moto_rt::E_NOT_READY) => Poll::Pending,
            res => Poll::Ready(res),
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
pub(super) struct TcpWriteFuture<'a, 'b, 'c> {
    pub stream: &'a TcpStream,
    pub bufs: &'b [&'c [u8]],
    pub total: usize,
    pub written: usize,
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
                return Poll::Ready(Ok(this.written));
            }

            // Top up the unclaimed pending back page: no alloc, no
            // queue traffic.
            this.written += stream.append_pending_tx(this.bufs, this.written);
            if this.written == this.total {
                return Poll::Ready(Ok(this.written));
            }

            let Ok(page) = stream.channel().alloc_page(stream.subchannel_mask) else {
                if this.written > 0 {
                    // Partial write: return it rather than wait for
                    // pages (the old loop's opportunistic tail).
                    return Poll::Ready(Ok(this.written));
                }
                // The failed alloc set the subchannel's page-wait bits;
                // sys-io will wake the channel, whose next pass drains
                // tx_wakers. Register, then re-check via the loop.
                stream.channel().add_tx_waker(cx.waker());
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
                    stream.channel().add_tx_waker(cx.waker());
                    if !stream.channel().send_queue_is_full() {
                        continue;
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}
