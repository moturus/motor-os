use moto_sys_io::api_net::TcpState;
use std::sync::Arc;
use std::task::{RawWaker, RawWakerVTable};
use std::time::Instant;
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

use moto_ipc::io_channel;

use super::netdev::EphemeralTcpPort;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
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

// Due to the asyncrhonous nature of our implementation, some
// shutdown actions are deferred. For example, when the user writes
// some bytes into the socket and then closes it, the bytes should be
// sent to the remote socket before the socket is closed and dropped.
//
// Similarly, when the remote socket is closed, there still could be
// RX bytes in local buffers, which have to be delivered to the user
// before the socket is closed/dropped.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum DeferredAction {
    CloseRd,
    CloseWr,
    Close, // Will drop the socket after sending the event to the user.
}

fn add_deferred_action_impl(
    prev: &mut Option<(DeferredAction, Instant)>,
    new: DeferredAction,
    started: Instant,
) {
    if new == DeferredAction::Close {
        *prev = Some((new, started));
        return;
    }

    let Some((prev_val, prev_cnt)) = *prev else {
        *prev = Some((new, started));
        return;
    };

    if new == prev_val {
        *prev = Some((new, prev_cnt.min(started)));
        return;
    }

    *prev = Some((DeferredAction::Close, prev_cnt.min(started)));
}

pub(super) struct TcpSocket {
    pub id: SocketId, // Unique across all devices.
    pub handle: smoltcp::iface::SocketHandle,
    pub device_idx: usize,

    pub conn: Rc<io_channel::ServerConnection>,
    pub pid: u64, // Used for stats. Cached to avoid doing a syscall.

    // We need socket's original listener to let it know when a socket has been closed
    // or connected or whatever: accept() requests use listener_id.
    pub listener_id: Option<super::tcp_listener::TcpListenerId>,

    // We also need to track the issuing connect request.
    pub connect_req: Option<moto_ipc::io_channel::Msg>,

    // This is an ephemeral port allocated to this socket.
    pub ephemeral_port: Option<u16>,

    // This is a shared ephemeral port.
    pub shared_ephemeral_port: Option<Arc<EphemeralTcpPort>>,

    pub tx_queue: VecDeque<super::TxBuf>,

    // u32 -> deferred action counter, used for backoff and cancelling.
    deferred_action: Option<(DeferredAction, Instant)>,

    pub rx_seq: u64,
    pub rx_ack: u64,

    // Note that this state is at a higher level than the canonical
    // TcpState (FIN1, FIN2, etc.).
    pub state: moto_sys_io::api_net::TcpState,

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

impl Drop for TcpSocket {
    fn drop(&mut self) {
        assert!(self.listener_id.is_none());
        assert!(self.connect_req.is_none());
        assert!(self.ephemeral_port.is_none());
        assert!(self.tx_queue.is_empty());
    }
}

impl TcpSocket {
    pub(super) fn new(
        socket_id: SocketId,
        handle: smoltcp::iface::SocketHandle,
        device_idx: usize,
        conn: Rc<io_channel::ServerConnection>,
        pid: u64,
    ) -> Self {
        TcpSocket {
            id: socket_id,
            handle,
            device_idx,
            conn,
            pid,
            listener_id: None,
            connect_req: None,
            ephemeral_port: None,
            shared_ephemeral_port: None,
            tx_queue: VecDeque::new(),
            deferred_action: None,
            rx_seq: 0,
            rx_ack: u64::MAX,
            state: TcpState::Closed,
            subchannel_mask: u64::MAX,
            listening_on: None,
            replacement_listener_created: false,
            stats_rx_bytes: 0,
            stats_tx_bytes: 0,
        }
    }

    #[allow(unused)]
    pub(super) fn dump_state(&self) {
        log::warn!(
            "socket: id {} conn 0x{:x} txq len: {}",
            self.id.0,
            self.conn.wait_handle().as_u64(),
            self.tx_queue.len()
        );
    }

    pub(super) fn add_deferred_action(
        &mut self,
        deferred_action: DeferredAction,
        started: Instant,
    ) {
        add_deferred_action_impl(&mut self.deferred_action, deferred_action, started)
    }

    pub(super) fn take_deferred_action(&mut self) -> Option<(DeferredAction, Instant)> {
        self.deferred_action.take()
    }
}

pub(super) struct UdpSocket {
    pub id: SocketId, // Unique across all devices.
    pub handle: smoltcp::iface::SocketHandle,
    pub device_idx: usize,

    pub conn: Rc<io_channel::ServerConnection>,
    pub pid: u64, // Used for stats. Cached to avoid doing a syscall.

    pub ephemeral_port: Option<u16>,

    pub tx_queue: VecDeque<super::TxBuf>,

    pub rx_seq: u64,
    pub rx_ack: u64,

    // See moto_ipc::io_channel::ServerConnection::alloc_page().
    pub subchannel_mask: u64,

    // stats
    pub stats_rx_bytes: u64, // Bytes sent to the application.
    pub stats_tx_bytes: u64, // Bytes received from the application.
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        assert!(self.ephemeral_port.is_none());
        assert!(self.tx_queue.is_empty());
    }
}

impl UdpSocket {
    pub(super) fn new(
        socket_id: SocketId,
        handle: smoltcp::iface::SocketHandle,
        device_idx: usize,
        conn: Rc<io_channel::ServerConnection>,
        pid: u64,
    ) -> Self {
        UdpSocket {
            id: socket_id,
            handle,
            device_idx,
            conn,
            pid,
            ephemeral_port: None,
            tx_queue: VecDeque::new(),
            rx_seq: 0,
            rx_ack: u64::MAX,
            subchannel_mask: u64::MAX,
            stats_rx_bytes: 0,
            stats_tx_bytes: 0,
        }
    }

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
