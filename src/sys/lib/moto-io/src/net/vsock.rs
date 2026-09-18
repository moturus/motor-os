//! Native virtio-vsock streams driven by the existing networking channel.

use alloc::sync::{Arc, Weak};
use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};

use moto_ipc::io_channel;
use moto_rt::mutex::Mutex;
use moto_sys::ErrorCode;
use moto_sys_io::{api_net, api_vsock};

use super::channel::{ChannelReservation, NetChannel, Reservation};
use super::inner_rx_stream::InnerRxStream;
use super::pending_stream_tx::PendingStreamTx;
use super::wait::{WaitSet, WaiterId};

pub use super::Shutdown;
pub use moto_sys_io::api_vsock::VsockAddr;

/// Query whether sys-io discovered a vsock device.
///
/// The caller must drive the client's [`super::NetDriver`]. This reserves no
/// socket and does not initialize the device, queues, or guest CID.
/// Returns [`moto_rt::Error::NotAllowed`] when the caller lacks CAP_VSOCK and
/// [`moto_rt::Error::NotFound`] when no device was discovered. Native errors
/// from capability lookup and channel operation are preserved.
pub async fn availability(client: &super::NetClient) -> Result<(), moto_rt::Error> {
    let response = client
        .rpc(moto_sys_io::api_vsock::availability_request())
        .await;
    moto_sys_io::api_vsock::availability_response(&response)
}

/// Return the device's current local CID, lazily activating it if needed.
///
/// The caller must drive the client's [`super::NetDriver`]. This takes no
/// socket reservation. Capability, absence, and cached initialization errors
/// are returned directly from sys-io.
pub async fn local_cid(client: &super::NetClient) -> Result<u32, moto_rt::Error> {
    let response = client
        .rpc(moto_sys_io::api_vsock::local_cid_request())
        .await;
    // Failed channels synthesize only a native status, not a success shape.
    response.status()?;
    moto_sys_io::api_vsock::decode_local_cid_response(&response)
}

/// A bound native listener on the caller's explicitly driven
/// [`super::NetDriver`].
///
/// The bound port is stable. [`Self::socket_addr_async`] queries sys-io so a
/// permanent device failure is reported instead of returning stale metadata.
pub struct VsockListener {
    channel_reservation: Option<ChannelReservation>,
    port: u32,
    handle: u64,
}

impl VsockListener {
    /// Bind through one explicitly reserved slot. Port zero requests an
    /// ephemeral port; `u32::MAX` is invalid.
    pub async fn bind_reserved(
        reservation: Reservation,
        port: u32,
    ) -> Result<Arc<Self>, ErrorCode> {
        let request = api_vsock::listener_bind_request(port).map_err(ErrorCode::from)?;
        let channel_reservation = reservation.into_channel_reservation();
        let channel = channel_reservation.channel().clone();
        let pending = channel
            .rpc_bind(
                request,
                channel_reservation,
                api_net::NetCmd::VsockListenerDrop as u16,
            )
            .await;

        // Failed-channel responses carry no canonical command or payload.
        pending.response().status()?;
        let decoded = api_vsock::decode_listener_bind_response(pending.response())
            .map_err(ErrorCode::from)?;
        let (channel_reservation, response) = pending.into_result()?;
        debug_assert_eq!(decoded.handle, response.handle);

        Ok(Arc::new(Self {
            channel_reservation: Some(channel_reservation),
            port: decoded.local.port,
            handle: decoded.handle,
        }))
    }

    /// Return the bound port paired with the device's current local CID.
    pub async fn socket_addr_async(&self) -> Result<VsockAddr, ErrorCode> {
        let response = self.channel().rpc(api_vsock::local_cid_request()).await;
        response.status()?;
        let cid = api_vsock::decode_local_cid_response(&response).map_err(ErrorCode::from)?;
        Ok(VsockAddr {
            cid,
            port: self.port,
        })
    }

    /// Accept through a slot reserved on any channel owned by this process.
    ///
    /// The future borrows this listener. Canceling a sent accept releases the
    /// reservation, but may occupy one bounded server waiter until a peer
    /// arrives or the listener is removed; a successful late reply is closed.
    pub async fn accept_reserved(
        &self,
        reservation: Reservation,
    ) -> Result<Arc<VsockStream>, ErrorCode> {
        let mut reservation = reservation.into_channel_reservation();
        reservation.reserve_subchannel();
        let request = api_vsock::listener_accept_request(self.handle, reservation.subchannel_idx())
            .map_err(ErrorCode::from)?;
        let cleanup = reservation.driver_credit();
        let stream = VsockStream::new_pending(reservation, None);
        let response = stream
            .channel()
            .rpc_vsock_open(request, stream.me.clone(), cleanup)
            .await;
        response.status()?;
        Ok(stream)
    }

    fn channel(&self) -> &NetChannel {
        self.channel_reservation.as_ref().unwrap().channel()
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        let reservation = self.channel_reservation.take().unwrap();
        let channel = reservation.channel().clone();
        if channel.is_failed() {
            drop(reservation);
        } else {
            channel.enqueue_teardown(reservation, api_vsock::listener_drop_request(self.handle));
        }
    }
}

/// A native stream on the caller's explicitly driven [`super::NetDriver`].
/// Share the returned `Arc` for concurrent reads and writes. Writes report
/// local byte acceptance, not peer receipt; an accepted prefix is returned
/// immediately, so canceling a pending write has accepted no bytes.
///
/// Drop queues accepted TX and close without blocking. Keep driving the
/// channel until its driver exits so queued teardown can reach sys-io.
pub struct VsockStream {
    channel_reservation: Option<ChannelReservation>,
    local_addr: Mutex<Option<VsockAddr>>,
    peer_addr: Mutex<Option<VsockAddr>>,
    handle: AtomicU64,
    me: Weak<Self>,
    recv_queue: Arc<Mutex<InnerRxStream>>,
    rx_waiters: WaitSet,
    // Low 32 bits are cumulative STATE_* flags; bits 32..48 retain the
    // terminal ErrorCode. One word publishes terminal and cause atomically.
    state: AtomicU64,
    local_receive_shutdown: AtomicBool,
    subchannel_mask: u64,
    // Serializes byte acceptance with publication of SEND shutdown. It is
    // held only during one nonblocking staging attempt, never across await.
    write_admission: Mutex<()>,
    pending_tx: PendingStreamTx,
}

impl VsockStream {
    /// Connect through an explicitly reserved slot on an existing NetDriver.
    pub async fn connect_reserved(
        reservation: Reservation,
        peer: VsockAddr,
    ) -> Result<Arc<Self>, ErrorCode> {
        let mut reservation = reservation.into_channel_reservation();
        reservation.reserve_subchannel();
        let request = api_vsock::connect_request(peer, reservation.subchannel_idx())
            .map_err(ErrorCode::from)?;
        let cleanup = reservation.driver_credit();
        let stream = Self::new_pending(reservation, Some(peer));

        let response = stream
            .channel()
            .rpc_vsock_open(request, stream.me.clone(), cleanup)
            .await;
        response.status()?;
        Ok(stream)
    }

    fn new_pending(reservation: ChannelReservation, peer: Option<VsockAddr>) -> Arc<Self> {
        let subchannel_mask = reservation.subchannel_mask();
        Arc::new_cyclic(|me| Self {
            channel_reservation: Some(reservation),
            local_addr: Mutex::new(None),
            peer_addr: Mutex::new(peer),
            handle: AtomicU64::new(0),
            me: me.clone(),
            recv_queue: InnerRxStream::new(),
            rx_waiters: WaitSet::new(),
            state: AtomicU64::new(0),
            local_receive_shutdown: AtomicBool::new(false),
            subchannel_mask,
            write_admission: Mutex::new(()),
            pending_tx: PendingStreamTx::new(),
        })
    }

    pub fn peer_addr(&self) -> Result<VsockAddr, ErrorCode> {
        if self.handle.load(Ordering::Acquire) == 0 {
            Err(moto_rt::E_NOT_CONNECTED)
        } else {
            Ok(self.peer_addr.lock().unwrap())
        }
    }

    pub fn socket_addr(&self) -> Option<VsockAddr> {
        *self.local_addr.lock()
    }

    pub fn try_read(&self, bufs: &mut [&mut [u8]]) -> Result<usize, ErrorCode> {
        if bufs.iter().all(|buf| buf.is_empty()) {
            return self.zero_io_result();
        }
        self.poll_rx(bufs)
    }

    pub fn read_future<'a, 'b, 'c>(
        &'a self,
        bufs: &'b mut [&'c mut [u8]],
    ) -> VsockReadFuture<'a, 'b, 'c> {
        VsockReadFuture {
            stream: self,
            bufs,
            waiter_id: None,
        }
    }

    pub fn readable(&self) -> Readable<'_> {
        Readable {
            stream: self,
            waiter_id: None,
        }
    }

    pub fn try_write(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        let total = bufs.iter().map(|buf| buf.len()).sum::<usize>();
        if total == 0 {
            return self.zero_io_result();
        }
        let _admission = self.write_admission.lock();
        if !self.can_write() {
            return Err(self.dead_write_error());
        }
        self.write_nonblocking(bufs, total)
    }

    pub fn write_future<'a, 'b, 'c>(
        &'a self,
        bufs: &'b [&'c [u8]],
    ) -> VsockWriteFuture<'a, 'b, 'c> {
        VsockWriteFuture {
            stream: self,
            bufs,
            waiter_id: None,
        }
    }

    pub fn writable(&self) -> Writable<'_> {
        Writable {
            stream: self,
            waiter_id: None,
        }
    }

    /// Queue shutdown before committing the corresponding local closure.
    /// Cancellation before queue ownership changes nothing; cancellation
    /// afterwards leaves sys-io responsible for completing the operation.
    pub async fn shutdown_async(&self, shutdown: Shutdown) -> Result<(), ErrorCode> {
        if self.device_failed() {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }
        let flags = match shutdown {
            Shutdown::Read => api_vsock::SHUTDOWN_RECEIVE,
            Shutdown::Write => api_vsock::SHUTDOWN_SEND,
            Shutdown::Both => api_vsock::SHUTDOWN_RECEIVE | api_vsock::SHUTDOWN_SEND,
        };
        let request =
            api_vsock::shutdown_request(self.handle()?, flags).map_err(ErrorCode::from)?;
        let committed = AtomicBool::new(false);
        let mut rpc = core::pin::pin!(self.channel().rpc_after_send(request, || {
            if flags & api_vsock::SHUTDOWN_RECEIVE != 0 {
                let mut queue = self.recv_queue.lock();
                self.local_receive_shutdown.store(true, Ordering::Release);
                self.state
                    .fetch_or(api_vsock::STATE_READ_CLOSED as u64, Ordering::AcqRel);
                super::channel::clear_vsock_rx_queue_locked(&mut queue, self.channel());
            }
            if flags & api_vsock::SHUTDOWN_SEND != 0 {
                self.state
                    .fetch_or(api_vsock::STATE_WRITE_CLOSED as u64, Ordering::AcqRel);
            }
            committed.store(true, Ordering::Release);
        }));
        let response = core::future::poll_fn(|cx| {
            let result = {
                let _admission = self.write_admission.lock();
                if self.device_failed() {
                    Poll::Ready(Err(moto_rt::E_INTERNAL_ERROR))
                } else {
                    rpc.as_mut().poll(cx).map(Ok)
                }
            };
            if committed.swap(false, Ordering::AcqRel) {
                if flags & api_vsock::SHUTDOWN_RECEIVE != 0 {
                    self.wake_rx_waiters();
                }
                if flags & api_vsock::SHUTDOWN_SEND != 0 {
                    self.channel().wake_tx_wakers();
                }
            }
            result
        })
        .await?;
        response.status().map_err(ErrorCode::from)
    }

    pub(super) fn weak(&self) -> Weak<Self> {
        self.me.clone()
    }

    pub(super) fn handle_value(&self) -> u64 {
        self.handle.load(Ordering::Acquire)
    }

    pub(super) fn on_open_response(
        &self,
        response: &mut io_channel::Msg,
        expected_command: u16,
    ) -> Result<(), ErrorCode> {
        if response.status().is_err() {
            return Err(response.status);
        }
        let decoded = match api_net::NetCmd::try_from(expected_command) {
            Ok(api_net::NetCmd::VsockStreamConnect) if response.command == expected_command => {
                api_vsock::decode_connect_response(response)
                    .map(|decoded| (decoded.handle, decoded.local, None))
            }
            Ok(api_net::NetCmd::VsockListenerAccept) if response.command == expected_command => {
                api_vsock::decode_listener_accept_response(response)
                    .map(|decoded| (decoded.handle, decoded.local, Some(decoded.peer)))
            }
            _ => Err(moto_rt::Error::InvalidData),
        };
        let (handle, local, peer) = match decoded {
            Ok(decoded) => decoded,
            Err(error) => {
                if response.handle != 0 {
                    let credit = self
                        .channel_reservation
                        .as_ref()
                        .unwrap()
                        .driver_credit();
                    self.channel()
                        .enqueue_control(credit, api_vsock::close_request(response.handle));
                }
                response.status = error.into();
                return Err(response.status);
            }
        };

        *self.local_addr.lock() = Some(local);
        if let Some(peer) = peer {
            *self.peer_addr.lock() = Some(peer);
        }
        debug_assert!(self.peer_addr.lock().is_some());
        self.channel().vsock_stream_created(self, handle);
        // Publish the usable handle only after endpoints and routing exist.
        self.handle.store(handle, Ordering::Release);
        self.channel().wake_tx_wakers();
        Ok(())
    }

    pub(super) fn on_channel_failed(&self) {
        {
            let _admission = self.write_admission.lock();
            self.pending_tx.clear();
            self.store_terminal(moto_rt::E_NOT_CONNECTED);
        }
        self.wake_rx_waiters();
        self.channel().wake_tx_wakers();
    }

    /// Called inline by the channel RX task and never awaits.
    pub(super) fn process_incoming_msg(&self, msg: io_channel::Msg) {
        let command = api_net::NetCmd::try_from(msg.command).ok();
        match command {
            Some(api_net::NetCmd::VsockStreamTx) => {
                // sys-io already recovered the TX page(s). The ordered state
                // notification is authoritative for terminal semantics.
                self.channel().wake_tx_wakers();
            }
            Some(api_net::NetCmd::VsockStreamRx) => {
                // Serialize the local RECEIVE check with queue insertion.
                // Shutdown commits its flag and clears under this same lock,
                // so an in-flight page is rejected here or included in clear.
                let mut queue = self.recv_queue.lock();
                if self.local_receive_shutdown.load(Ordering::Acquire) || self.device_failed() {
                    drop(queue);
                    super::channel::claim_vsock_rx_page(
                        self.channel(),
                        &msg,
                        &mut |_page, _len| {},
                    );
                } else {
                    queue.push_back(msg);
                    drop(queue);
                }
                self.wake_rx_waiters();
            }
            Some(api_net::NetCmd::EvtVsockStreamStateChanged) => {
                match api_vsock::decode_state_changed(&msg) {
                    Ok(change)
                        if change.flags & api_vsock::STATE_TERMINAL != 0
                            && change.cause == Some(moto_rt::Error::InternalError) =>
                    {
                        self.record_device_failure();
                    }
                    Ok(change) if change.flags & api_vsock::STATE_READ_CLOSED != 0 => {
                        // Keep final read closure behind every preceding RX
                        // page. Early terminal/write closure is deliberately
                        // not queued: more validated RX may still follow.
                        self.recv_queue.lock().push_back(msg);
                        self.apply_state_change(change.flags, change.cause);
                        self.wake_rx_waiters();
                    }
                    Ok(change) => self.apply_state_change(change.flags, change.cause),
                    Err(_) => self.record_terminal(moto_rt::E_INTERNAL_ERROR),
                }
            }
            _ => self.record_terminal(moto_rt::E_INTERNAL_ERROR),
        }
    }

    pub(super) fn claim_pending_tx(&self) -> Option<io_channel::Msg> {
        let mut page_ids = [0_u16; api_vsock::STREAM_TX_MAX_PAGES];
        let (num_pages, total) = self.pending_tx.claim(&mut page_ids);
        if num_pages == 0 {
            return None;
        }
        // PendingStreamTx has already transferred each IoPage to its raw ID.
        // The multi format is valid for one page too and avoids reconstructing
        // ownership merely to select the classic encoding.
        Some(api_vsock::stream_tx_multi_msg(
            self.handle_value(),
            &page_ids[..num_pages],
            total as u32,
            moto_rt::time::Instant::now().as_u64(),
        ))
    }

    fn handle(&self) -> Result<u64, ErrorCode> {
        let handle = self.handle_value();
        if handle == 0 {
            Err(moto_rt::E_NOT_CONNECTED)
        } else {
            Ok(handle)
        }
    }

    fn channel(&self) -> &NetChannel {
        self.channel_reservation.as_ref().unwrap().channel()
    }

    fn state(&self) -> u32 {
        self.state.load(Ordering::Acquire) as u32
    }

    fn apply_state_change(&self, flags: u32, cause: Option<moto_rt::Error>) {
        self.record_state(flags, cause.map(ErrorCode::from));
        if flags & (api_vsock::STATE_WRITE_CLOSED | api_vsock::STATE_TERMINAL) != 0 {
            self.channel().wake_tx_wakers();
        }
    }

    fn record_terminal(&self, cause: ErrorCode) {
        self.store_terminal(cause);
        self.wake_rx_waiters();
        self.channel().wake_tx_wakers();
    }

    fn record_device_failure(&self) {
        let admission = self.write_admission.lock();
        self.pending_tx.clear();
        let mut queue = self.recv_queue.lock();
        super::channel::clear_vsock_rx_queue_locked(&mut queue, self.channel());
        let flags = api_vsock::STATE_READ_CLOSED
            | api_vsock::STATE_WRITE_CLOSED
            | api_vsock::STATE_TERMINAL;
        self.state.store(
            flags as u64 | (moto_rt::E_INTERNAL_ERROR as u64) << 32,
            Ordering::Release,
        );
        drop(queue);
        drop(admission);
        self.wake_rx_waiters();
        self.channel().wake_tx_wakers();
    }

    fn store_terminal(&self, cause: ErrorCode) {
        let flags = api_vsock::STATE_READ_CLOSED
            | api_vsock::STATE_WRITE_CLOSED
            | api_vsock::STATE_TERMINAL;
        self.record_state(flags, Some(cause));
    }

    fn record_state(&self, flags: u32, cause: Option<ErrorCode>) {
        let mut previous = self.state.load(Ordering::Acquire);
        loop {
            let previous_flags = previous as u32;
            let mut next = previous | flags as u64;
            if previous_flags & api_vsock::STATE_TERMINAL == 0
                && flags & api_vsock::STATE_TERMINAL != 0
            {
                next |= (cause.unwrap_or(moto_rt::E_OK) as u64) << 32;
            }
            match self.state.compare_exchange_weak(
                previous,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => previous = current,
            }
        }
    }

    fn terminal_cause(&self) -> ErrorCode {
        (self.state.load(Ordering::Acquire) >> 32) as ErrorCode
    }

    fn device_failed(&self) -> bool {
        self.state() & api_vsock::STATE_TERMINAL != 0
            && self.terminal_cause() == moto_rt::E_INTERNAL_ERROR
    }

    fn zero_io_result(&self) -> Result<usize, ErrorCode> {
        if self.device_failed() {
            Err(moto_rt::E_INTERNAL_ERROR)
        } else {
            Ok(0)
        }
    }

    fn can_write(&self) -> bool {
        self.state() & (api_vsock::STATE_WRITE_CLOSED | api_vsock::STATE_TERMINAL) == 0
            && !self.channel().is_failed()
    }

    fn dead_write_error(&self) -> ErrorCode {
        let cause = self.terminal_cause();
        if cause == moto_rt::E_OK {
            moto_rt::E_NOT_CONNECTED
        } else {
            cause
        }
    }

    fn dead_read_result(&self) -> Result<usize, ErrorCode> {
        if self.device_failed() {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }
        if self.local_receive_shutdown.load(Ordering::Acquire) {
            return Ok(0);
        }
        let cause = self.terminal_cause();
        if self.state() & api_vsock::STATE_TERMINAL != 0 && cause != moto_rt::E_OK {
            Err(cause)
        } else {
            Ok(0)
        }
    }

    fn poll_rx(&self, bufs: &mut [&mut [u8]]) -> Result<usize, ErrorCode> {
        let mut queue = self.recv_queue.lock();
        if self.device_failed() {
            return Err(moto_rt::E_INTERNAL_ERROR);
        }
        if self.local_receive_shutdown.load(Ordering::Acquire) {
            return Ok(0);
        }
        loop {
            while queue
                .front()
                .is_some_and(|msg| msg.command == api_net::NetCmd::VsockStreamRx as u16)
            {
                let msg = queue.pop_front().unwrap();
                super::channel::claim_vsock_rx_page(self.channel(), &msg, &mut |page, len| {
                    queue.push_bytes(page, len)
                });
            }

            let copied = queue.copy_out(bufs, false);
            if copied > 0 || queue.have_loose_bytes() {
                return Ok(copied);
            }

            let Some(msg) = queue.pop_front() else {
                if self.state() & api_vsock::STATE_READ_CLOSED != 0 {
                    return self.dead_read_result();
                }
                return Err(moto_rt::E_NOT_READY);
            };
            let change =
                api_vsock::decode_state_changed(&msg).map_err(|_| moto_rt::E_INTERNAL_ERROR)?;
            self.apply_state_change(change.flags, change.cause);
        }
    }

    fn have_write_buffer_space(&self) -> bool {
        self.pending_tx.has_room()
            || (!self.channel().send_queue_is_full()
                && self.channel().may_alloc_page(self.subchannel_mask))
    }

    fn write_nonblocking(&self, bufs: &[&[u8]], total: usize) -> Result<usize, ErrorCode> {
        let mut written = self.pending_tx.append(bufs, 0);
        while written < total {
            if self.channel().send_queue_is_full() {
                break;
            }
            let Ok(page) = self.channel().alloc_page(self.subchannel_mask) else {
                break;
            };
            let Ok(filled) = self.pending_tx.try_push(
                page,
                bufs,
                written,
                self.channel(),
                super::channel::vsock_tx_marker_msg(self.handle()?),
            ) else {
                break;
            };
            written += filled;
        }
        if written == 0 {
            Err(moto_rt::E_NOT_READY)
        } else {
            Ok(written)
        }
    }

    fn read_ready(&self) -> bool {
        !self.recv_queue.lock().is_empty() || self.state() & api_vsock::STATE_READ_CLOSED != 0
    }

    fn wake_rx_waiters(&self) {
        self.rx_waiters.wake_all();
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        let handle = self.handle_value();
        if handle == 0 {
            return;
        }
        let reservation = self.channel_reservation.take().unwrap();
        let channel = reservation.channel().clone();
        // One message per reserved TX page, plus close, bounds teardown storage.
        const MAX_MESSAGES: usize =
            io_channel::CHANNEL_PAGE_COUNT / api_net::IO_SUBCHANNELS as usize + 1;
        let mut messages = [io_channel::Msg::new(); MAX_MESSAGES];
        let mut num_messages = 0;
        while let Some(msg) = self.claim_pending_tx() {
            messages[num_messages] = msg;
            num_messages += 1;
        }
        messages[num_messages] = api_vsock::close_request(handle);
        num_messages += 1;

        super::channel::clear_vsock_rx_queue(&self.recv_queue, &channel);
        debug_assert!(self.recv_queue.lock().is_empty());
        channel.vsock_stream_dropped(handle);
        if channel.is_failed() {
            drop(reservation);
        } else {
            channel.enqueue_teardown_messages(reservation, &messages[..num_messages]);
        }
    }
}

pub struct VsockReadFuture<'a, 'b, 'c> {
    stream: &'a VsockStream,
    bufs: &'b mut [&'c mut [u8]],
    waiter_id: Option<WaiterId>,
}

impl Drop for VsockReadFuture<'_, '_, '_> {
    fn drop(&mut self) {
        self.stream.rx_waiters.unregister(&mut self.waiter_id);
    }
}

impl core::future::Future for VsockReadFuture<'_, '_, '_> {
    type Output = Result<usize, ErrorCode>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.bufs.iter().all(|buf| buf.is_empty()) {
            return Poll::Ready(this.stream.zero_io_result());
        }
        match this.stream.poll_rx(this.bufs) {
            Err(moto_rt::E_NOT_READY) => {}
            result => {
                this.stream.rx_waiters.unregister(&mut this.waiter_id);
                return Poll::Ready(result);
            }
        }
        this.stream
            .rx_waiters
            .register(&mut this.waiter_id, cx.waker());
        match this.stream.poll_rx(this.bufs) {
            Err(moto_rt::E_NOT_READY) => Poll::Pending,
            result => {
                this.stream.rx_waiters.unregister(&mut this.waiter_id);
                Poll::Ready(result)
            }
        }
    }
}

pub struct VsockWriteFuture<'a, 'b, 'c> {
    stream: &'a VsockStream,
    bufs: &'b [&'c [u8]],
    waiter_id: Option<WaiterId>,
}

impl Drop for VsockWriteFuture<'_, '_, '_> {
    fn drop(&mut self) {
        self.stream.channel().remove_tx_waker(&mut self.waiter_id);
    }
}

impl core::future::Future for VsockWriteFuture<'_, '_, '_> {
    type Output = Result<usize, ErrorCode>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.stream.try_write(this.bufs) {
            Err(moto_rt::E_NOT_READY) => {}
            result => {
                this.stream.channel().remove_tx_waker(&mut this.waiter_id);
                return Poll::Ready(result);
            }
        }
        this.stream
            .channel()
            .add_tx_waker(&mut this.waiter_id, cx.waker());
        match this.stream.try_write(this.bufs) {
            Err(moto_rt::E_NOT_READY) => Poll::Pending,
            result => {
                this.stream.channel().remove_tx_waker(&mut this.waiter_id);
                Poll::Ready(result)
            }
        }
    }
}

pub struct Readable<'a> {
    stream: &'a VsockStream,
    waiter_id: Option<WaiterId>,
}

impl Drop for Readable<'_> {
    fn drop(&mut self) {
        self.stream.rx_waiters.unregister(&mut self.waiter_id);
    }
}

impl core::future::Future for Readable<'_> {
    type Output = ();

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.stream.read_ready() {
            this.stream.rx_waiters.unregister(&mut this.waiter_id);
            return Poll::Ready(());
        }
        this.stream
            .rx_waiters
            .register(&mut this.waiter_id, cx.waker());
        if this.stream.read_ready() {
            this.stream.rx_waiters.unregister(&mut this.waiter_id);
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

pub struct Writable<'a> {
    stream: &'a VsockStream,
    waiter_id: Option<WaiterId>,
}

impl Drop for Writable<'_> {
    fn drop(&mut self) {
        self.stream.channel().remove_tx_waker(&mut self.waiter_id);
    }
}

impl core::future::Future for Writable<'_> {
    type Output = ();

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if !this.stream.can_write() || this.stream.have_write_buffer_space() {
            this.stream.channel().remove_tx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        this.stream
            .channel()
            .add_tx_waker(&mut this.waiter_id, cx.waker());
        if !this.stream.can_write() || this.stream.have_write_buffer_space() {
            this.stream.channel().remove_tx_waker(&mut this.waiter_id);
            return Poll::Ready(());
        }
        if this.stream.channel().send_queue_is_full() {
            return Poll::Pending;
        }
        match this
            .stream
            .channel()
            .alloc_page(this.stream.subchannel_mask)
        {
            Ok(page) => {
                drop(page);
                if !this.stream.can_write() || this.stream.have_write_buffer_space() {
                    this.stream.channel().remove_tx_waker(&mut this.waiter_id);
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }
            Err(_) if !this.stream.can_write() || this.stream.pending_tx.has_room() => {
                this.stream.channel().remove_tx_waker(&mut this.waiter_id);
                Poll::Ready(())
            }
            Err(_) => Poll::Pending,
        }
    }
}
