use std::task::{RawWaker, RawWakerVTable};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

use moto_ipc::io_channel;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
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

// What to do with the socket once its TX queue is drained.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum TxDoneAction {
    CloseWr,
    Close,
    Drop,
}

pub(super) struct MotoSocket {
    pub id: SocketId, // Unique across all devices.
    pub handle: smoltcp::iface::SocketHandle,
    pub device_idx: usize,

    pub conn: Rc<io_channel::ServerConnection>,
    pub pid: u64,

    // We need socket's original listener to let it know when a socket has been closed
    // or connected or whatever: accept() requests use listener_id.
    pub listener_id: Option<super::tcp_listener::TcpListenerId>,

    // We also need to track the issuing connect request.
    pub connect_req: Option<moto_ipc::io_channel::Msg>,

    pub ephemeral_port: Option<u16>,

    pub tx_queue: VecDeque<super::TxBuf>,

    pub tx_done_action: Option<TxDoneAction>,

    pub rx_seq: u64,
    pub rx_ack: u64,

    pub state: moto_sys_io::api_net::TcpState,

    // When the socket becomes CloseWait or Closed, sys-io notifies the client once.
    pub rx_closed_notified: bool,

    // See moto_ipc::io_channel::ServerConnection::alloc_page().
    pub subchannel_mask: u64,

    // SmolTcp sockets don't provide a way to get the address a socket is listening on,
    // so we cache it ourselves.
    pub listening_on: Option<std::net::SocketAddr>,
    // If this was a listening socket, and its state transitioned to smth else,
    // we create a replacement listening socket, and set this flag to true.
    pub replacement_listener_created: bool,

    // stats
    pub stats_rx_bytes: u64, // Bytes sent to the application.
    pub stats_tx_bytes: u64, // Bytes received from the application.
}

impl Drop for MotoSocket {
    fn drop(&mut self) {
        assert!(self.listener_id.is_none());
        assert!(self.connect_req.is_none());
        assert!(self.ephemeral_port.is_none());
        assert!(self.tx_queue.is_empty());
    }
}

impl MotoSocket {
    #[allow(unused)]
    pub(super) fn dump_state(&self) {
        log::warn!(
            "socket: id {} conn 0x{:x} txq len: {}",
            self.id.0,
            self.conn.wait_handle().as_u64(),
            self.tx_queue.len()
        );
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
        // log::debug!(
        //     "{}:{} socket wake 0x{:x}",
        //     file!(),
        //     line!(),
        //     u64::from(self.socket_id)
        // );
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
