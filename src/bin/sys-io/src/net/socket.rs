use std::task::{RawWaker, RawWakerVTable};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

use moto_sys::SysHandle;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub(super) struct SocketId(u64);

impl From<u64> for SocketId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<SocketId> for u64 {
    fn from(value: SocketId) -> Self {
        value.0
    }
}

#[derive(Debug)]
pub(super) struct MotoSocket {
    pub id: SocketId, // Unique across all devices.
    pub handle: smoltcp::iface::SocketHandle,
    pub device_idx: usize,

    pub proc_handle: SysHandle,

    // We need socket's original listener to let it know when a socket has been closed:
    // we cap the number of active sockets/streams allowed per listener.
    pub listener_id: Option<super::tcp_listener::TcpListenerId>,

    // We also need to track the issuing connect sqe.
    pub connect_sqe: Option<moto_ipc::io_channel::QueueEntry>,

    pub ephemeral_port: Option<u16>,

    // Both rx_bufs and tx_bufs are sorted below according to their arrival times
    // (which _should_ be the same order as their timestamps, but this is not enforced).
    // When set_read_timeout or set_write_timeout ops happen, we go
    // through the appropriate x_bufs queue and expire any requests/bufs that need
    // expiring.
    pub rx_bufs: VecDeque<super::IoBuf>,
    pub tx_bufs: VecDeque<super::IoBuf>,

    pub state: moto_runtime::rt_api::net::TcpState,

    pub read_timeout: std::time::Duration,
    pub write_timeout: std::time::Duration,
    pub next_timeout: Option<moto_sys::time::Instant>,
}

impl Drop for MotoSocket {
    fn drop(&mut self) {
        assert!(self.listener_id.is_none());
        assert!(self.connect_sqe.is_none());
        assert!(self.ephemeral_port.is_none());
        assert!(self.rx_bufs.is_empty());
        assert!(self.tx_bufs.is_empty());
    }
}

#[derive(Clone)]
pub struct SocketWaker {
    socket_id: SocketId,
    woken_sockets: Rc<RefCell<VecDeque<SocketId>>>,
}

impl SocketWaker {
    pub fn new(socket_id: SocketId, woken_sockets: Rc<RefCell<VecDeque<SocketId>>>) -> Self {
        Self {
            socket_id,
            woken_sockets,
        }
    }

    pub fn into_raw_waker(self) -> RawWaker {
        let waker = Box::new(self);
        let ptr = Box::into_raw(waker) as *const ();

        RawWaker::new(ptr, &SOCKET_WAKER_VTABLE)
    }

    fn wake(&self) {
        log::debug!(
            "{}:{} socket wake 0x{:x}",
            file!(),
            line!(),
            u64::from(self.socket_id)
        );
        self.woken_sockets.borrow_mut().push_back(self.socket_id)
    }
}

static SOCKET_WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(clone_waker, wake_waker, wake_by_ref_waker, drop_waker);

unsafe fn clone_waker(ptr: *const ()) -> RawWaker {
    let waker = &*(ptr as *const SocketWaker);
    waker.clone().into_raw_waker()
}

unsafe fn wake_waker(ptr: *const ()) {
    let waker = &*(ptr as *const SocketWaker);
    waker.wake();
    drop(Box::from_raw(ptr as *mut SocketWaker));
}

unsafe fn wake_by_ref_waker(ptr: *const ()) {
    let waker = &*(ptr as *const SocketWaker);
    waker.wake();
}

unsafe fn drop_waker(ptr: *const ()) {
    drop(Box::from_raw(ptr as *mut SocketWaker));
}
