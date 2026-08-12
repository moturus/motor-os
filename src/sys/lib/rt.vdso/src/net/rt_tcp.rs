//! The vdso TCP wrappers (design 6.3): `RtTcpStream` and `RtTcpListener` are
//! what the FD table stores, and they own everything POSIX about a TCP
//! descriptor -- `O_NONBLOCK`, `SO_RCVTIMEO`/`SO_SNDTIMEO`, the raw
//! option-pointer dispatch, the `PosixFile` impl, and the poll-registry
//! source -- over the moto-io `TcpStream` and `TcpListener`, which keep only
//! what is on the wire.
//!
//! The wrapper holds the concrete `EventSourceManaged` it installed as each
//! socket's readiness observer, so it never has to recover one from the
//! socket. That is why the observer moto-io stores can stay an opaque handle,
//! and why it is optional there at all.

use crate::posix::PosixFile;
use crate::posix::PosixKind;
use crate::runtime::EventSourceManaged;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use moto_io::net::tcp::Shutdown;
use moto_io::net::tcp::TcpListener;
use moto_io::net::tcp::TcpStream;
use moto_rt::RtFd;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_sys::ErrorCode;
use moto_sys_io::api_net::TcpState;

/// A connected-TCP descriptor: the native stream plus the POSIX state a native
/// caller does not have. Because the wrapper is the shared
/// `Arc<dyn PosixFile>`, a `dup` shares these flags, which is the
/// open-file-description behavior the FD table already gives every other file
/// kind.
pub struct RtTcpStream {
    inner: Arc<TcpStream>,
    events: Arc<EventSourceManaged>,
    nonblocking: AtomicBool,
    read_timeout_ns: AtomicU64,
    write_timeout_ns: AtomicU64,
}

impl RtTcpStream {
    /// Wrap a native stream. `events` must be the source that was installed as
    /// this stream's readiness listener, so that the level the wrapper
    /// synthesizes and the edges the stream emits reach one registry.
    /// `nonblocking` seeds `O_NONBLOCK`: a nonblocking `connect` starts set,
    /// and an accepted stream inherits the flag its listener had.
    pub fn new(
        inner: Arc<TcpStream>,
        events: Arc<EventSourceManaged>,
        nonblocking: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            events,
            nonblocking: AtomicBool::new(nonblocking),
            read_timeout_ns: AtomicU64::new(u64::MAX),
            write_timeout_ns: AtomicU64::new(u64::MAX),
        })
    }

    /// The native stream, for the ABI shims that only need its address, its
    /// peer, or one of its `try_*`/future entry points.
    pub fn inner(&self) -> &TcpStream {
        &self.inner
    }

    /// Whether the descriptor is in `O_NONBLOCK` mode; the blocking wrappers
    /// consult this to choose the `try_*` fast return.
    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Acquire)
    }

    /// The `SO_RCVTIMEO` deadline in nanoseconds, or `u64::MAX` for none.
    /// A blocking reader turns this into its park deadline.
    pub fn read_timeout(&self) -> u64 {
        self.read_timeout_ns.load(Ordering::Relaxed)
    }

    /// The `SO_SNDTIMEO` deadline in nanoseconds, or `u64::MAX` for none.
    pub fn write_timeout(&self) -> u64 {
        self.write_timeout_ns.load(Ordering::Relaxed)
    }

    /// # Safety
    ///
    /// `ptr` must be valid for `len` readable bytes holding the value for
    /// `option`.
    pub unsafe fn setsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_NONBLOCKING => {
                assert_eq!(len, 1);
                let nonblocking = unsafe { *(ptr as *const u8) };
                if nonblocking > 1 {
                    return moto_rt::E_INVALID_ARGUMENT;
                }
                self.nonblocking.store(nonblocking == 1, Ordering::Release);
                moto_rt::E_OK
            }
            moto_rt::net::SO_RCVTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let timeout = unsafe { *(ptr as *const u64) };
                self.read_timeout_ns.store(timeout, Ordering::Relaxed);
                moto_rt::E_OK
            }
            moto_rt::net::SO_SNDTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let timeout = unsafe { *(ptr as *const u64) };
                self.write_timeout_ns.store(timeout, Ordering::Relaxed);
                moto_rt::E_OK
            }
            // The remote options: each costs an RPC to sys-io, so these are the
            // arms that block. `ptr` outlives the future because this drives it
            // to completion before returning.
            moto_rt::net::SO_SHUTDOWN => {
                assert_eq!(len, 1);
                let val = unsafe { *(ptr as *const u8) };
                let read = val & moto_rt::net::SHUTDOWN_READ != 0;
                let write = val & moto_rt::net::SHUTDOWN_WRITE != 0;
                let shutdown = match (read, write) {
                    (true, true) => Shutdown::Both,
                    (true, false) => Shutdown::Read,
                    (false, true) => Shutdown::Write,
                    (false, false) => return moto_rt::E_INVALID_ARGUMENT,
                };
                into_error_code(moto_async::block_on_sync(
                    self.inner.shutdown_async(shutdown),
                ))
            }
            moto_rt::net::SO_NODELAY => {
                assert_eq!(len, 1);
                let nodelay = unsafe { *(ptr as *const u8) };
                if nodelay > 1 {
                    return moto_rt::E_INVALID_ARGUMENT;
                }
                into_error_code(moto_async::block_on_sync(
                    self.inner.set_nodelay_async(nodelay == 1),
                ))
            }
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                let ttl = unsafe { *(ptr as *const u32) };
                into_error_code(moto_async::block_on_sync(self.inner.set_ttl_async(ttl)))
            }
            moto_rt::net::SO_LINGER => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let millis = unsafe { *(ptr as *const u64) };
                let duration = if millis == u64::MAX {
                    None
                } else {
                    Some(Duration::from_millis(millis))
                };
                into_error_code(moto_async::block_on_sync(
                    self.inner.set_linger_async(duration),
                ))
            }
            moto_rt::net::SO_RCVBUF | moto_rt::net::SO_SNDBUF => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let bytes = unsafe { *(ptr as *const u64) };
                let rcv = option == moto_rt::net::SO_RCVBUF;
                match moto_async::block_on_sync(self.inner.set_buffer_size_async(rcv, bytes)) {
                    Ok(_effective) => moto_rt::E_OK,
                    Err(err) => err,
                }
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    /// # Safety
    ///
    /// `ptr` must be valid for `len` writable bytes to receive `option`'s
    /// value.
    pub unsafe fn getsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_RCVTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                unsafe { *(ptr as *mut u64) = self.read_timeout() };
                moto_rt::E_OK
            }
            moto_rt::net::SO_SNDTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                unsafe { *(ptr as *mut u64) = self.write_timeout() };
                moto_rt::E_OK
            }
            moto_rt::net::SO_NODELAY => {
                assert_eq!(len, 1);
                match moto_async::block_on_sync(self.inner.nodelay_async()) {
                    Ok(nodelay) => {
                        unsafe { *(ptr as *mut u8) = nodelay as u8 };
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                }
            }
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                match moto_async::block_on_sync(self.inner.ttl_async()) {
                    Ok(ttl) => {
                        unsafe { *(ptr as *mut u32) = ttl };
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                }
            }
            moto_rt::net::SO_LINGER => {
                assert_eq!(len, core::mem::size_of::<u64>());
                match moto_async::block_on_sync(self.inner.linger_async()) {
                    Ok(duration) => {
                        unsafe {
                            *(ptr as *mut u64) = duration
                                .map(|duration| duration.as_millis() as u64)
                                .unwrap_or(u64::MAX)
                        };
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                }
            }
            moto_rt::net::SO_ERROR => {
                assert_eq!(len, 2);
                unsafe { *(ptr as *mut u16) = self.inner.take_error() };
                moto_rt::E_OK
            }
            moto_rt::net::SO_RCVBUF | moto_rt::net::SO_SNDBUF => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let rcv = option == moto_rt::net::SO_RCVBUF;
                match moto_async::block_on_sync(self.inner.buffer_size_async(rcv)) {
                    Ok(bytes) => {
                        unsafe { *(ptr as *mut u64) = bytes };
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                }
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    /// Synthesize the poll events a freshly-registered interest expects, based
    /// on the stream's current state (mio semantics, somewhat ad-hoc). Called
    /// from poll_add/poll_set only; a wrapper concern (it emits through the
    /// concrete `EventSourceManaged`), reading the native stream through its
    /// public accessors.
    fn maybe_raise_events(&self, interests: Interests) {
        let mut events = 0;

        let state = self.inner.tcp_state();
        if state == TcpState::Closed {
            // MIO TCP tests assume this.
            events = moto_rt::poll::POLL_WRITE_CLOSED
                | moto_rt::poll::POLL_READ_CLOSED
                | moto_rt::poll::POLL_READABLE
                | moto_rt::poll::POLL_WRITABLE;
            self.events.on_event(events);
            return;
        }

        match state {
            TcpState::Listening | TcpState::PendingAccept | TcpState::Connecting => return,
            _ => {}
        }

        if (interests & moto_rt::poll::POLL_WRITABLE != 0)
            && self.inner.have_write_buffer_space()
            && state.can_write()
        {
            events |= moto_rt::poll::POLL_WRITABLE;
        }

        if ((interests & moto_rt::poll::POLL_READABLE) != 0)
            && state.can_read()
            && self.inner.has_rx_bytes()
        {
            events |= moto_rt::poll::POLL_READABLE;
        }

        if !state.can_read() {
            // A closed read half is readable: `read()` returns 0 at once, and
            // the state only advances here once the receive queue is drained,
            // so there is nothing else it could return. epoll reports a peer's
            // FIN the same way (EPOLLIN | EPOLLRDHUP), as does the event path
            // this synthesizes for -- `TcpStream::set_tcp_state` raises
            // READABLE with READ_CLOSED. Without it a stream half-closed
            // *before* it was registered looks unreadable to mio, and its
            // reader never learns of the EOF.
            events |= moto_rt::poll::POLL_READ_CLOSED | moto_rt::poll::POLL_READABLE;
        }

        if events != 0 {
            self.events.on_event(events);
        }
    }
}

/// The `Result`-to-`ErrorCode` shape the raw option ABI returns.
fn into_error_code(result: Result<(), ErrorCode>) -> ErrorCode {
    match result {
        Ok(()) => moto_rt::E_OK,
        Err(err) => err,
    }
}

impl PosixFile for RtTcpStream {
    fn kind(&self) -> PosixKind {
        PosixKind::TcpStream
    }

    fn descriptor_attr(
        &self,
        object_id: core::num::NonZeroU64,
    ) -> Result<moto_rt::fs::FileAttr, ErrorCode> {
        Ok(crate::posix::synthetic_attr(
            moto_rt::fs::FILETYPE_SOCKET,
            object_id,
        ))
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        crate::net::blocking::tcp_read(self, &mut [buf], false)
    }

    unsafe fn read_vectored(&self, bufs: &mut [&mut [u8]]) -> Result<usize, ErrorCode> {
        crate::net::blocking::tcp_read(self, bufs, false)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        crate::net::blocking::tcp_write(self, &[buf])
    }

    unsafe fn write_vectored(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        crate::net::blocking::tcp_write(self, bufs)
    }

    fn flush(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        self.events.on_closed_locally(rt_fd);
        Ok(())
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.events
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
        self.events
            .set_interests(r_id, source_fd, token, interests)?;
        self.maybe_raise_events(interests);
        Ok(())
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.events.del_interests(r_id, source_fd)
    }
}

/// The flipped listener's readiness observer: the poll translation the
/// shared `EventSourceManaged` impl provides, plus the accept pump's
/// completion poke -- a READABLE edge means a completion reached the ready
/// queue, so the standing donation was consumed and the pump re-arms. The
/// pump slot is set right after the pump exists (the pump needs the bound
/// listener, which needs this observer); no completion can precede it,
/// because completions follow donations and donations follow the pump.
pub struct ListenerEvents {
    events: Arc<EventSourceManaged>,
    pump: moto_rt::mutex::Mutex<Option<Arc<crate::net::accept_pump::AcceptPump>>>,
}

impl ListenerEvents {
    pub fn new(events: Arc<EventSourceManaged>) -> Arc<Self> {
        Arc::new(Self {
            events,
            pump: moto_rt::mutex::Mutex::new(None),
        })
    }

    pub fn set_pump(&self, pump: Arc<crate::net::accept_pump::AcceptPump>) {
        *self.pump.lock() = Some(pump);
    }
}

impl moto_io::net::readiness::NetEventListener for ListenerEvents {
    fn log_diag(&self, handle: u64) {
        self.events.log_diag(handle);
    }

    fn on_readiness(&self, edges: moto_io::net::readiness::Readiness) {
        self.events.on_readiness(edges);
        if edges.contains(moto_io::net::readiness::Readiness::READABLE)
            && let Some(pump) = &*self.pump.lock()
        {
            pump.poke();
        }
    }
}

/// A TCP-listener descriptor: the native listener plus the POSIX state a
/// native caller does not have, which for a listener is `O_NONBLOCK` alone --
/// the ABI has no accept timeout. Because the wrapper is the shared
/// `Arc<dyn PosixFile>`, a `dup` shares the flag, which is the
/// open-file-description behavior the FD table already gives every other file
/// kind.
///
/// The wrapper also owns the accept pump (design 6.5): the native listener
/// is host-owned (`bind_reserved`), and every accept slot it ever holds is
/// a `NET_POOL` reservation the pump (or a blocking accept caller) donated.
pub struct RtTcpListener {
    inner: Arc<TcpListener>,
    events: Arc<EventSourceManaged>,
    pump: Arc<crate::net::accept_pump::AcceptPump>,
    nonblocking: AtomicBool,
}

impl Drop for RtTcpListener {
    fn drop(&mut self) {
        // The last descriptor is gone: stop the pump eagerly (its `Weak`
        // to the native listener would end it anyway, but a pump parked in
        // a pool reserve only re-checks when poked).
        self.pump.stop();
    }
}

/// The depth setting `O_NONBLOCK` arms the accept backlog to; a later
/// `listen()` replaces it with what its caller asked for. A nonblocking accept
/// answers only from that queue, so without one it would never have a
/// connection to take.
const DEFAULT_ACCEPT_BACKLOG: u32 = 1024;

impl RtTcpListener {
    /// Wrap a bound native listener. `events` must be the source inside the
    /// `ListenerEvents` that was installed as this listener's readiness
    /// listener, so that the level the wrapper synthesizes and the edges the
    /// listener emits reach one registry.
    pub fn new(
        inner: Arc<TcpListener>,
        events: Arc<EventSourceManaged>,
        pump: Arc<crate::net::accept_pump::AcceptPump>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            events,
            pump,
            nonblocking: AtomicBool::new(false),
        })
    }

    /// The native listener, for the ABI shims that need its address or one of
    /// its accept entry points.
    pub fn inner(&self) -> &TcpListener {
        &self.inner
    }

    /// The accept pump, for the ABI shims' claim pokes and donations.
    pub fn pump(&self) -> &crate::net::accept_pump::AcceptPump {
        &self.pump
    }

    /// Whether the descriptor is in `O_NONBLOCK` mode; `accept` consults this
    /// to choose `try_accept`, and the stream it returns inherits it.
    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Acquire)
    }

    /// The `listen()` ABI. Nonblocking only, as it was while the native
    /// listener owned the flag: a blocking `accept` donates its own slot, so
    /// a backlog it never reads would just hold connections sys-io has
    /// already completed. On a host-owned listener arming is the pump's
    /// backlog, never native `listen()` (decision 2: arming is donating).
    pub fn listen(&self, max_backlog: u32) -> ErrorCode {
        if !self.is_nonblocking() {
            return moto_rt::E_INVALID_ARGUMENT;
        }
        if max_backlog == 0 {
            return moto_rt::E_INVALID_ARGUMENT;
        }
        self.pump.set_backlog(max_backlog);
        moto_rt::E_OK
    }

    /// # Safety
    ///
    /// `ptr` must be valid for `len` readable bytes holding the value for
    /// `option`.
    pub unsafe fn setsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_NONBLOCKING => {
                assert_eq!(len, 1);
                let nonblocking = unsafe { *(ptr as *const u8) };
                if nonblocking > 1 {
                    return moto_rt::E_INVALID_ARGUMENT;
                }
                let nonblocking = nonblocking == 1;
                let was_nonblocking = self.nonblocking.swap(nonblocking, Ordering::Release);
                if nonblocking && !was_nonblocking {
                    // Arming the backlog here is what mio depends on: it marks
                    // the descriptor before it calls `listen`, and its accept
                    // loop only ever answers from the queue.
                    //
                    // TODO: at the moment, previously-issued blocking accepts
                    // will remain blocking. Maybe they should be kicked with
                    // moto_rt::E_NOT_READY?
                    self.pump.set_backlog(DEFAULT_ACCEPT_BACKLOG);
                }
                moto_rt::E_OK
            }
            // The remote options: each costs an RPC to sys-io, so these are
            // the arms that block. `ptr` outlives the future because this
            // drives it to completion before returning.
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                let ttl = unsafe { *(ptr as *const u32) };
                into_error_code(moto_async::block_on_sync(self.inner.set_ttl_async(ttl)))
            }
            moto_rt::net::SO_RCVBUF | moto_rt::net::SO_SNDBUF => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let bytes = unsafe { *(ptr as *const u64) };
                let rcv = option == moto_rt::net::SO_RCVBUF;
                into_error_code(moto_async::block_on_sync(
                    self.inner.set_buffer_size_async(rcv, bytes),
                ))
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    /// # Safety
    ///
    /// `ptr` must be valid for `len` writable bytes to receive `option`'s
    /// value.
    pub unsafe fn getsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                match moto_async::block_on_sync(self.inner.ttl_async()) {
                    Ok(ttl) => {
                        unsafe { *(ptr as *mut u32) = ttl };
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                }
            }
            moto_rt::net::SO_ERROR => {
                assert_eq!(len, 2);
                // A listener has no deferred error to report: bind and listen
                // failures go back to the caller that asked for them.
                unsafe { *(ptr as *mut u16) = moto_rt::E_OK };
                moto_rt::E_OK
            }
            moto_rt::net::SO_RCVBUF | moto_rt::net::SO_SNDBUF => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let rcv = option == moto_rt::net::SO_RCVBUF;
                match moto_async::block_on_sync(self.inner.buffer_size_async(rcv)) {
                    Ok(bytes) => {
                        unsafe { *(ptr as *mut u64) = bytes };
                        moto_rt::E_OK
                    }
                    Err(err) => err,
                }
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    /// Synthesize the poll events a freshly-registered interest expects: a
    /// listener holding a completed connection is already readable. Called
    /// from poll_add/poll_set only; a wrapper concern, reading the native
    /// listener through its public accessor.
    fn maybe_raise_events(&self, interests: Interests) {
        if (interests & moto_rt::poll::POLL_READABLE != 0) && self.inner.has_async_accepts() {
            self.events.on_event(moto_rt::poll::POLL_READABLE);
        }
    }
}

impl PosixFile for RtTcpListener {
    fn kind(&self) -> PosixKind {
        PosixKind::TcpListener
    }

    fn descriptor_attr(
        &self,
        object_id: core::num::NonZeroU64,
    ) -> Result<moto_rt::fs::FileAttr, ErrorCode> {
        Ok(crate::posix::synthetic_attr(
            moto_rt::fs::FILETYPE_SOCKET,
            object_id,
        ))
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        self.events.on_closed_locally(rt_fd);
        Ok(())
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.events
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
        self.events
            .set_interests(r_id, source_fd, token, interests)?;
        self.maybe_raise_events(interests);
        Ok(())
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.events.del_interests(r_id, source_fd)
    }
}
