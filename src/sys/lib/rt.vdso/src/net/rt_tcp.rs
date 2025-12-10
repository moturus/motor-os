use crate::posix;
use crate::posix::PosixFile;
use crate::posix::PosixKind;
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
use moto_rt::error::*;
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

use super::rt_net::ChannelReservation;
use super::rt_net::NetChannel;
use super::rt_net::ResponseHandler;

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
    event_source: EventSourceManaged,

    // All outgoing accept requests are stored here: req_id => req.
    accept_requests: Mutex<BTreeMap<u64, AcceptRequest>>,

    // Incoming async accepts are stored here. Better processed
    // in arrival order.
    async_accepts: Mutex<VecDeque<PendingAccept>>,

    // Incoming sync accepts are stored here: req_id => acc;
    // have to be processed by id.
    sync_accepts: Mutex<BTreeMap<u64, PendingAccept>>,

    // In sys-io, connected sockets may generate tcp stream messages such as
    // rx, rx_done, close, etc. Here (vdso), the stream is not created until
    // the user calls accept() asynchronously (vs the I/O thread), so
    // we need a place to store messages for not-yet-accepted TCP streams.
    // MIO test actually tests this scenario.
    pending_accept_queues: Mutex<BTreeMap<u64, Arc<Mutex<super::inner_rx_stream::InnerRxStream>>>>,

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
            super::rt_net::clear_rx_queue(&stream, self.channel());
        }

        self.channel().tcp_listener_dropped(self.handle);

        super::rt_net::stats_tcp_listener_dropped();
    }
}

impl PosixFile for TcpListener {
    fn kind(&self) -> PosixKind {
        PosixKind::TcpListener
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.on_closed_locally(rt_fd);
        Ok(())
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.event_source
            .add_interests(r_id, source_fd, token, interests)?;

        let have_async_accepts = !self.async_accepts.lock().is_empty();
        if (interests & moto_rt::poll::POLL_READABLE != 0) && have_async_accepts {
            self.event_source.on_event(moto_rt::poll::POLL_READABLE);
        }

        Ok(())
    }

    fn poll_set(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.event_source
            .set_interests(r_id, source_fd, token, interests)?;

        let have_async_accepts = !self.async_accepts.lock().is_empty();
        if (interests & moto_rt::poll::POLL_READABLE != 0) && have_async_accepts {
            self.event_source.on_event(moto_rt::poll::POLL_READABLE);
        }

        Ok(())
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.del_interests(r_id, source_fd)
    }
}

impl ResponseHandler for TcpListener {
    // Called from the I/O thread.
    fn on_response(&self, resp: io_channel::Msg) {
        let req = self.accept_requests.lock().remove(&resp.id).unwrap();
        let wake_handle = SysHandle::from_u64(req.req.wake_handle);

        // First, create the pending_accept_queue.
        self.pending_accept_queues
            .lock()
            .insert(resp.handle, super::inner_rx_stream::InnerRxStream::new());

        // Then create the pending accept (must happen after the queue is created above,
        // otherwise racing accept may miss the queue).
        if wake_handle != SysHandle::NONE {
            // The accept was blocking; a thread is waiting.
            assert!(
                self.sync_accepts
                    .lock()
                    .insert(req.req.id, PendingAccept { req, resp })
                    .is_none()
            );
            let _ = moto_sys::SysCpu::wake(wake_handle);
            return;
        }

        self.async_accepts
            .lock()
            .push_back(PendingAccept { req, resp });
        if self.async_accepts.lock().len() < (self.max_backlog.load(Ordering::Relaxed) as usize) {
            self.post_accept(false).unwrap(); // TODO: how to post an accept later?
        }

        self.event_source.on_event(moto_rt::poll::POLL_READABLE);
    }
}

impl TcpListener {
    pub fn handle(&self) -> u64 {
        self.handle
    }

    fn channel(&self) -> &super::rt_net::NetChannel {
        self.channel_reservation.channel()
    }

    pub fn bind(socket_addr: &SocketAddr) -> Result<Arc<TcpListener>, ErrorCode> {
        let mut socket_addr = *socket_addr;
        if socket_addr.port() == 0 && socket_addr.ip().is_unspecified() {
            crate::moto_log!("we don't currently allow binding to/listening on 0.0.0.0:0");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let req = api_net::bind_tcp_listener_request(&socket_addr, None);
        let channel_reservation = super::rt_net::reserve_channel();
        let resp = channel_reservation.channel().send_receive(req);
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

            // While a TCP Listener never becomes writable, a MIO test expects
            // a successful WRITABLE interest registration:
            // https://github.com/tokio-rs/mio/blob/9a9d691891d5f7d91c7493b65d0b80726699faa8/tests/poll.rs#L56
            // so we have to allow that.
            event_source: EventSourceManaged::new(
                moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_WRITABLE,
            ),

            accept_requests: Mutex::new(BTreeMap::new()),
            async_accepts: Mutex::new(VecDeque::new()),
            sync_accepts: Mutex::new(BTreeMap::new()),
            pending_accept_queues: Mutex::new(BTreeMap::new()),
            max_backlog: AtomicU32::new(32),
            me: me.clone(),
        });
        tcp_listener.channel().tcp_listener_created(&tcp_listener);
        crate::net::rt_net::stats_tcp_listener_created();

        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} new TcpListener {:?}",
            file!(),
            line!(),
            tcp_listener.socket_addr
        );

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

    pub fn socket_addr(&self) -> &SocketAddr {
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

    pub fn accept(&self) -> Result<(Arc<TcpStream>, SocketAddr), ErrorCode> {
        let mut pending_accept = self.get_pending_accept()?;
        if pending_accept.resp.status() != moto_rt::E_OK {
            let rx_queue = self
                .pending_accept_queues
                .lock()
                .remove(&pending_accept.resp.handle)
                .unwrap();
            crate::net::rt_net::clear_rx_queue(&rx_queue, self.channel());
            return Err(pending_accept.resp.status());
        }

        let remote_addr = api_net::get_socket_addr(&pending_accept.resp.payload);
        let channel_reservation = pending_accept.req.channel_reservation.take().unwrap();
        let subchannel_mask = channel_reservation.subchannel_mask();

        // Don't remove the queue until the channel can access it via the new stream.
        let recv_queue = self
            .pending_accept_queues
            .lock()
            .get(&pending_accept.resp.handle)
            .unwrap()
            .clone();

        let new_stream = Arc::new_cyclic(|me| TcpStream {
            local_addr: Mutex::new(Some(self.socket_addr)),
            remote_addr,
            handle: AtomicU64::new(pending_accept.resp.handle),
            event_source: EventSourceManaged::new(
                moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_WRITABLE,
            ),
            me: me.clone(),
            nonblocking: AtomicBool::new(self.nonblocking.load(Ordering::Relaxed)),
            channel_reservation,
            recv_queue,
            next_rx_seq: AtomicU64::new(1).into(),
            rx_waiter: Mutex::new(None),
            tcp_state_driver: AtomicU32::new(api_net::TcpState::ReadWrite.into()),
            rx_closed: AtomicBool::new(false),
            tx_closed: AtomicBool::new(false),
            rx_timeout_ns: AtomicU64::new(u64::MAX),
            tx_timeout_ns: AtomicU64::new(u64::MAX),
            subchannel_mask,
            error: AtomicU16::new(E_OK),
        });
        crate::net::rt_net::stats_tcp_stream_created();

        new_stream.channel().tcp_stream_created(&new_stream);
        // Now we can remove the queue.
        assert!(
            self.pending_accept_queues
                .lock()
                .remove(&pending_accept.resp.handle)
                .is_some()
        );

        new_stream.ack_rx();
        new_stream.on_accepted();

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
        let mut channel_reservation = crate::net::rt_net::reserve_channel();
        let channel = channel_reservation.channel().clone();

        channel_reservation.reserve_subchannel();
        let subchannel_mask = channel_reservation.subchannel_mask();

        let mut req = api_net::accept_tcp_listener_request(self.handle, subchannel_mask);
        let req_id = channel_reservation.channel().new_req_id();
        req.id = req_id;
        if blocking {
            req.wake_handle = moto_sys::UserThreadControlBlock::get().self_handle;
        }
        let accept_request = AcceptRequest {
            channel_reservation: Some(channel_reservation),
            req,
        };

        assert!(
            self.accept_requests
                .lock()
                .insert(req.id, accept_request)
                .is_none()
        );

        channel
            .post_msg_with_response_waiter(req, self.me.clone())
            .inspect_err(|_| {
                assert!(self.accept_requests.lock().remove(&req.id).is_some());
            })
            .map(|_| req_id)
    }

    pub unsafe fn setsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_NONBLOCKING => {
                assert_eq!(len, 1);
                let nonblocking = unsafe { *(ptr as *const u8) };
                if nonblocking > 1 {
                    return E_INVALID_ARGUMENT;
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
        self.channel().send_receive(req).status()
    }

    fn ttl(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpListenerGetOption as u16;
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

pub struct TcpStream {
    channel_reservation: ChannelReservation,
    local_addr: Mutex<Option<SocketAddr>>,
    remote_addr: SocketAddr,
    handle: AtomicU64,
    event_source: EventSourceManaged,
    nonblocking: AtomicBool,
    me: Weak<TcpStream>,

    // This is, most of the time, a single-producer, single-consumer queue.
    // MUST be locked before rx_buf is locked.
    recv_queue: Arc<Mutex<super::inner_rx_stream::InnerRxStream>>,
    next_rx_seq: CachePadded<AtomicU64>,

    rx_waiter: Mutex<Option<SysHandle>>,

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
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let handle = self.handle.load(Ordering::Acquire);
        if handle == 0 {
            super::rt_net::stats_tcp_stream_dropped();
            return;
        }

        if self.tcp_state() != TcpState::Closed {
            let mut req = io_channel::Msg::new();
            req.command = api_net::NetCmd::TcpStreamClose as u16;
            req.handle = self.handle();

            // TODO: is this unwrap OK?
            self.channel().post_msg(req).unwrap();
        }
        // moto_log!("TcpStream dropped");

        // Clear RX queue: basically, free up server-allocated pages.
        super::rt_net::clear_rx_queue(&self.recv_queue, self.channel());
        assert!(self.recv_queue.lock().is_empty());

        self.channel().tcp_stream_dropped(self.handle());
        super::rt_net::stats_tcp_stream_dropped();
    }
}

impl PosixFile for TcpStream {
    fn kind(&self) -> PosixKind {
        PosixKind::TcpStream
    }

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

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.on_closed_locally(rt_fd);
        Ok(())
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.event_source
            .add_interests(r_id, source_fd, token, interests)?;
        self.maybe_raise_events(interests);
        Ok(())
    }

    fn poll_set(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.event_source
            .set_interests(r_id, source_fd, token, interests)?;
        self.maybe_raise_events(interests);
        Ok(())
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.del_interests(r_id, source_fd)
    }
}

impl ResponseHandler for TcpStream {
    fn on_response(&self, resp: io_channel::Msg) {
        assert_eq!(resp.command, api_net::NetCmd::TcpStreamConnect as u16);
        self.on_connect_response(resp);
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

    fn maybe_raise_events(&self, interests: Interests) {
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
            self.event_source.on_event(events);
            return;
        }

        match state {
            TcpState::Listening | TcpState::PendingAccept | TcpState::Connecting => return,
            _ => {}
        }

        if (interests & moto_rt::poll::POLL_WRITABLE != 0)
            && self.have_write_buffer_space()
            && state.can_write()
        {
            events |= moto_rt::poll::POLL_WRITABLE;
        }

        if ((interests & moto_rt::poll::POLL_READABLE) != 0)
            && state.can_read()
            && (!self.recv_queue.lock().is_empty())
        {
            events |= moto_rt::poll::POLL_READABLE;
        }

        if !state.can_read() {
            events |= moto_rt::poll::POLL_READ_CLOSED;
        }

        if events != 0 {
            self.event_source.on_event(events);
        }
    }

    fn ack_rx(&self) {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamRxAck as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = self.next_rx_seq.load(Ordering::Relaxed) - 1;
        self.channel().send_msg(req);
    }

    fn tcp_state(&self) -> api_net::TcpState {
        api_net::TcpState::try_from(self.tcp_state_driver.load(Ordering::Acquire)).unwrap()
    }

    // Note: this is called from the IO thread, so must not sleep.
    pub fn process_incoming_msg(&self, msg: io_channel::Msg) -> SysHandle {
        let mut rx_lock = self.rx_waiter.lock();
        /*
        #[cfg(debug_assertions)]
        crate::moto_log!(
            "{}:{} incoming msg {:?} for stream 0x{:x}",
            file!(),
            line!(),
            api_net::NetCmd::try_from(msg.command).unwrap(),
            msg.handle
        );
        */

        // The main challenge/nuance here is that sometimes we need to raise
        // poll events here, and sometimes we have to delay them. For example,
        // while there are messages in RXQ, we should not raise POLL_READ_CLOSED.
        let mut recv_q = self.recv_queue.lock();
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
            return rx_lock.take().unwrap_or(SysHandle::NONE);
        }

        // RXQ is empty.
        if msg.command == (api_net::NetCmd::TcpStreamRx as u16) {
            recv_q.push_back(msg);
            drop(recv_q);
            // The RXQ was empty, this is a new (edge) event.
            self.event_source.on_event(moto_rt::poll::POLL_READABLE);
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

        rx_lock.take().unwrap_or(SysHandle::NONE)
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

        if recv_q.loose_bytes().is_some() {
            // Already some queue processing has been done.
            return;
        }

        let msg = recv_q.pop_front().unwrap();

        if msg.command == (api_net::NetCmd::TcpStreamRx as u16) {
            let sz_read = msg.payload.args_64()[1] as usize;
            if sz_read > 0 {
                recv_q.push_back(msg);
                drop(recv_q);
                self.event_source.on_event(moto_rt::poll::POLL_READABLE);
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
    ) -> Result<Arc<TcpStream>, ErrorCode> {
        let mut channel_reservation = super::rt_net::reserve_channel();
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
            event_source: EventSourceManaged::new(
                moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_WRITABLE,
            ),
            me: me.clone(),
            nonblocking: AtomicBool::new(nonblocking),
            recv_queue: super::inner_rx_stream::InnerRxStream::new(),
            next_rx_seq: AtomicU64::new(1).into(),
            rx_waiter: Mutex::new(None),
            tcp_state_driver: AtomicU32::new(api_net::TcpState::Connecting.into()),
            rx_closed: AtomicBool::new(false),
            tx_closed: AtomicBool::new(false),
            rx_timeout_ns: AtomicU64::new(u64::MAX),
            tx_timeout_ns: AtomicU64::new(u64::MAX),
            subchannel_mask,
            error: AtomicU16::new(E_OK),
        });
        super::rt_net::stats_tcp_stream_created();

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
                .tcp_state_driver
                .swap(TcpState::Closed.into(), Ordering::Release);
            assert_eq!(prev, TcpState::Connecting.into());

            self.error.store(resp.status(), Ordering::Release);

            self.event_source.on_event(
                moto_rt::poll::POLL_READ_CLOSED
                    | moto_rt::poll::POLL_WRITE_CLOSED
                    | moto_rt::poll::POLL_ERROR,
            );
            return Err(resp.status());
        }

        assert_ne!(0, resp.handle);
        self.handle.store(resp.handle, Ordering::Release);
        *self.local_addr.lock() = Some(api_net::get_socket_addr(&resp.payload));
        let prev = self
            .tcp_state_driver
            .swap(TcpState::ReadWrite.into(), Ordering::AcqRel);
        assert_eq!(prev, TcpState::Connecting.into());
        self.channel().tcp_stream_created(self);

        self.event_source.on_event(moto_rt::poll::POLL_WRITABLE);

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

    pub unsafe fn setsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        unsafe {
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
    }

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
        let mut notify_rx_done = false;
        let mut notify_tx_done = false;

        if !new_state.can_read() {
            self.rx_closed.store(true, Ordering::Relaxed);
        }
        if !new_state.can_write() {
            self.rx_closed.store(true, Ordering::Relaxed);
        }

        loop {
            let can_read = prev_state.can_read() && new_state.can_read();
            let can_write = prev_state.can_read() && new_state.can_write();
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

        let mut events = 0;
        if notify_rx_done {
            events |= moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_READ_CLOSED;
        }
        if notify_tx_done {
            events |= moto_rt::poll::POLL_WRITABLE | moto_rt::poll::POLL_WRITE_CLOSED;
        }

        if events != 0 {
            self.event_source.on_event(events);
        }
    }

    fn poll_rx(&self, bufs: &mut [&mut [u8]], peek: bool) -> Result<usize, ErrorCode> {
        let mut recv_q = self.recv_queue.lock();

        if let Some(bytes) = recv_q.loose_bytes() {
            let copied_bytes = unsafe { Self::rx_copy(bytes, bufs) };
            if !peek {
                recv_q.consume_bytes(copied_bytes);
            }
            return Ok(copied_bytes);
        }

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

        if msg.command == (api_net::NetCmd::EvtTcpStreamStateChanged as u16) {
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
                    // Careful: recursion.
                    return self.poll_rx(bufs, peek);
                }
            }
        }

        if msg.command != (api_net::NetCmd::TcpStreamRx as u16) {
            panic!("bad cmd: {} {}", msg.command, msg.status);
        }
        let sz_read = msg.payload.args_64()[1] as usize;
        assert!(sz_read <= moto_ipc::io_channel::PAGE_SIZE);
        assert_ne!(0, sz_read);
        let rx_seq_incoming = msg.payload.args_64()[2];
        let rx_seq = self.next_rx_seq.fetch_add(1, Ordering::Relaxed);
        assert_eq!(rx_seq, rx_seq_incoming);

        let io_page = self
            .channel()
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

        recv_q.push_bytes(io_page, sz_read);
        drop(recv_q);

        if rx_seq & (api_net::TCP_RX_MAX_INFLIGHT - 1) == 0 {
            self.ack_rx();
        }
        // Careful: recursion!
        self.poll_rx(bufs, peek)
    }

    unsafe fn rx_copy(mut src: &[u8], dst: &mut [&mut [u8]]) -> usize {
        let mut copied_bytes = 0;
        for buf in dst {
            let to_copy = buf.len().min(src.len());
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), buf.as_mut_ptr(), to_copy) };

            copied_bytes += to_copy;
            src = &src[to_copy..];
            if src.is_empty() {
                break;
            }
        }

        copied_bytes
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
            if let Some(timeout) = rx_timeout
                && Instant::now() >= timeout
            {
                return Err(moto_rt::E_TIMED_OUT);
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
                    let queue_empty = self.recv_queue.lock().is_empty();
                    if !queue_empty {
                        moto_log!(
                            "{}:{} this is bad: RX timo with recv queue",
                            file!(),
                            line!()
                        );
                    }
                }
            }
        }
    }

    pub fn maybe_can_write(&self) {
        if self.have_write_buffer_space() {
            self.event_source.on_event(moto_rt::poll::POLL_WRITABLE);
        } else {
            self.channel().add_write_waiter(self);
        }
    }

    fn have_write_buffer_space(&self) -> bool {
        self.channel().may_alloc_page(self.subchannel_mask)
    }

    fn write(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        if bufs.is_empty() {
            return Ok(0);
        }
        if !self.tcp_state().can_write() || self.tx_closed.load(Ordering::Acquire) {
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
            if let Some(timo) = abs_timeout
                && Instant::now() >= timo
            {
                return Err(moto_rt::E_TIMED_OUT);
            }

            match self.channel().alloc_page(self.subchannel_mask) {
                Ok(page) => break page,
                Err(_) => {
                    if !self.tcp_state().can_write() || self.tx_closed.load(Ordering::Acquire) {
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
                    if let Some(timo) = abs_timeout
                        && timo < sleep_timo
                    {
                        sleep_timo = timo;
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
                        // self.channel().conn.dump_state();
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
        Ok(write_sz)
    }

    unsafe fn tx_copy(src: &[&[u8]], mut dst: &mut [u8]) -> usize {
        let mut written = 0;
        for buf in src {
            let to_write = buf.len().min(dst.len());
            unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), dst.as_mut_ptr(), to_write) };
            written += to_write;
            dst = &mut dst[to_write..];

            if dst.is_empty() {
                break;
            }
        }

        written
    }

    fn do_write_nonblocking(&self, iovec: &[&[u8]]) -> Result<usize, ErrorCode> {
        let Ok(io_page) = self.channel().alloc_page(self.subchannel_mask) else {
            self.channel().add_write_waiter(self);
            return Err(moto_rt::E_NOT_READY);
        };

        let write_sz = unsafe { Self::tx_copy(iovec, io_page.bytes_mut()) };

        let msg =
            api_net::tcp_stream_tx_msg(self.handle(), io_page, write_sz, Instant::now().as_u64());
        if let Err(msg) = self.try_tx(msg, write_sz) {
            // Get the page back so that it can be released.
            let io_page = self
                .channel()
                .get_page(msg.payload.shared_pages()[0])
                .unwrap();
            core::mem::drop(io_page);
            self.channel().add_write_waiter(self);
            return Err(moto_rt::E_NOT_READY);
        }

        Ok(write_sz)
    }

    fn write_nonblocking(&self, iovec: &[&[u8]]) -> Result<usize, ErrorCode> {
        // These are checked at the callsite.
        debug_assert!(self.tcp_state().can_write());

        fn seek_exact<'a>(bufs: &'a [&'a [u8]], mut offset: usize) -> (&'a [u8], &'a [&'a [u8]]) {
            for (i, buf) in bufs.iter().enumerate() {
                if offset < buf.len() {
                    return (&buf[offset..], &bufs[i + 1..]);
                }
                offset -= buf.len();
            }
            (&[], &[])
        }

        let mut total_written = 0;

        loop {
            let (head, tail) = seek_exact(iovec, total_written);

            if head.is_empty() && tail.is_empty() {
                return Ok(total_written);
            }

            let result = if total_written == 0 {
                self.do_write_nonblocking(iovec)
            } else if head.is_empty() {
                self.do_write_nonblocking(tail)
            } else {
                let mut iovec = Vec::with_capacity(tail.len() + 1);
                iovec.push(head);
                iovec.extend_from_slice(tail);
                self.do_write_nonblocking(&iovec)
            };

            match result {
                Ok(0) => panic!(),
                Ok(n) => {
                    total_written += n;
                }
                Err(e) => {
                    if total_written > 0 {
                        return Ok(total_written);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    fn try_tx(&self, msg: io_channel::Msg, write_sz: usize) -> Result<(), io_channel::Msg> {
        self.channel().post_msg(msg)?;
        Ok(())
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
        // Note: we don't change tcp state here, we do that when we receive
        // the appropriate event from sys-io.
        assert!(read || write);
        let mut option = 0_u64;
        if read {
            option |= api_net::TCP_OPTION_SHUT_RD;
            self.rx_closed.store(true, Ordering::Release);
        }
        if write {
            option |= api_net::TCP_OPTION_SHUT_WR;
            self.tx_closed.store(true, Ordering::Release);
        }

        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = option;
        let resp = self.channel().send_receive(req);

        resp.status()
    }

    fn set_linger(&self, dur: Option<Duration>) -> Result<(), ErrorCode> {
        if let Some(dur) = dur
            && dur == Duration::ZERO
        {
            return Ok(());
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
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_NODELAY;
        req.payload.args_64_mut()[1] = nodelay as u64;
        self.channel().send_receive(req).status()
    }

    fn nodelay(&self) -> Result<u8, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamGetOption as u16;
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
        req.command = api_net::NetCmd::TcpStreamSetOption as u16;
        req.handle = self.handle();
        req.payload.args_64_mut()[0] = api_net::TCP_OPTION_TTL;
        req.payload.args_32_mut()[2] = ttl;
        self.channel().send_receive(req).status()
    }

    fn ttl(&self) -> Result<u32, ErrorCode> {
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamGetOption as u16;
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
