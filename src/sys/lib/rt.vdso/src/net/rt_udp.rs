//! The vdso UDP wrapper (design 6.3): `RtUdpSocket` is what the FD table
//! stores, and it owns everything POSIX about a UDP socket -- `O_NONBLOCK`,
//! `SO_RCVTIMEO`/`SO_SNDTIMEO`, the raw option-pointer dispatch, the
//! `PosixFile` impl, and the poll-registry source -- over the moto-io
//! `UdpSocket`, which keeps only what is on the wire.
//!
//! Holding the concrete `EventSourceManaged` here is what removes the UDP
//! `as_any` downcast: the wrapper is what installed the source as the
//! socket's readiness listener, so it already has it and never has to
//! recover it from the abstract handle.

use crate::posix::PosixFile;
use crate::posix::PosixKind;
use crate::runtime::EventSourceManaged;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use moto_io::net::udp::UdpSocket;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_rt::{ErrorCode, RtFd};

/// A UDP descriptor: the native socket plus the POSIX state a native caller
/// does not have. Because the wrapper is the shared `Arc<dyn PosixFile>`, a
/// `dup` shares these flags, which is the open-file-description behavior the
/// FD table already gives every other file kind.
pub struct RtUdpSocket {
    inner: Arc<UdpSocket>,
    events: Arc<EventSourceManaged>,
    nonblocking: AtomicBool,
    read_timeout_ns: AtomicU64,
    write_timeout_ns: AtomicU64,
}

impl RtUdpSocket {
    /// Wrap a bound native socket. `events` must be the source that was
    /// installed as this socket's readiness listener, so that the level the
    /// wrapper synthesizes and the edges the socket emits reach one registry.
    pub fn new(inner: Arc<UdpSocket>, events: Arc<EventSourceManaged>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            events,
            nonblocking: AtomicBool::new(false),
            read_timeout_ns: AtomicU64::new(u64::MAX),
            write_timeout_ns: AtomicU64::new(u64::MAX),
        })
    }

    /// The native socket, for the ABI shims that only need its address, its
    /// peer, or one of its `try_*`/future entry points.
    pub fn inner(&self) -> &UdpSocket {
        &self.inner
    }

    /// Whether the descriptor is in `O_NONBLOCK` mode; the blocking wrappers
    /// consult this to choose the `try_*` fast return.
    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Acquire)
    }

    /// The `SO_RCVTIMEO` deadline in nanoseconds, or `u64::MAX` for none.
    /// A blocking receiver turns this into its park deadline.
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
            // The one remote option: it costs an RPC to sys-io, so it is the
            // only arm that blocks. `ptr` outlives the future because this
            // drives it to completion before returning.
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                let ttl = unsafe { *(ptr as *const u32) };
                match moto_async::block_on_sync(self.inner.set_ttl_async(ttl)) {
                    Ok(()) => moto_rt::E_OK,
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
                // let err = self.take_error();
                // *(ptr as *mut u16) = err;
                unsafe { *(ptr as *mut u16) = moto_rt::E_OK };
                moto_rt::E_OK
            }
            _ => panic!("unrecognized option {option}"),
        }
    }
}

impl PosixFile for RtUdpSocket {
    fn kind(&self) -> PosixKind {
        PosixKind::UdpSocket
    }

    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        let Some(addr) = self.inner.peer_addr() else {
            return Err(moto_rt::E_NOT_CONNECTED);
        };

        crate::net::blocking::udp_send(self, buf, &addr)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        crate::net::blocking::udp_recv(self, buf, false).map(|(sz, _)| sz)
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        self.events.on_closed_locally(rt_fd);
        Ok(())
    }

    fn wants_last_close(&self) -> bool {
        true
    }

    /// A UDP socket holds a bound address in sys-io, and sys-io releases it
    /// only when told. Tell it here rather than from `Drop`, which can run on
    /// the channel IO thread after this call returned, so a caller that
    /// rebinds the same address does not race its own close.
    fn on_last_close(&self) {
        self.inner.close();
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

impl RtUdpSocket {
    /// Synthesize the poll events a freshly-registered interest expects.
    /// Called from poll_add/poll_set only; a wrapper concern (it emits
    /// through the concrete `EventSourceManaged`), reading the native socket
    /// through its public accessors.
    fn maybe_raise_events(&self, interests: Interests) {
        let mut events = 0;

        if (interests & moto_rt::poll::POLL_WRITABLE != 0) && !self.inner.tx_queue_full() {
            events |= moto_rt::poll::POLL_WRITABLE;
        }

        if (interests & moto_rt::poll::POLL_READABLE) != 0 && self.inner.has_rx_datagram() {
            events |= moto_rt::poll::POLL_READABLE;
        }

        if events != 0 {
            self.events.on_event(events);
        }
    }
}
