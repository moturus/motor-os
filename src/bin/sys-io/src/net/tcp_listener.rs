use std::{
    collections::{HashSet, VecDeque},
    net::SocketAddr,
};

use moto_ipc::io_channel;
use moto_sys::SysHandle;

use super::socket::SocketId;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub(super) struct TcpListenerId(u64);

impl From<u64> for TcpListenerId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<TcpListenerId> for u64 {
    fn from(value: TcpListenerId) -> Self {
        value.0
    }
}

pub struct TcpListener {
    proc_handle: SysHandle,
    socket_addr: SocketAddr, // What the user gave us, can be 0.0.0.0:port.

    // If listener::accept() is called first, it's sqe will be added
    // to pending_accepts.
    pending_accepts: VecDeque<io_channel::QueueEntry>,

    // Connected sockets that did not yet emit the accept QE.
    // Note: connected_sockets below may contain dropped sockets.
    connected_sockets: VecDeque<(SocketId, SocketAddr)>,

    // Pure listening sockets. We need to track them to drop when the listener is dropped.
    listening_sockets: HashSet<SocketId>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        assert!(
            self.pending_accepts.is_empty()
                && self.connected_sockets.is_empty()
                && self.listening_sockets.is_empty()
        );
    }
}

impl TcpListener {
    pub fn new(proc_handle: SysHandle, socket_addr: SocketAddr) -> Self {
        Self {
            proc_handle,
            socket_addr,
            pending_accepts: VecDeque::new(),
            connected_sockets: VecDeque::new(),
            listening_sockets: HashSet::new(),
        }
    }

    pub fn proc_handle(&self) -> SysHandle {
        self.proc_handle
    }

    pub fn socket_addr(&self) -> &SocketAddr {
        &self.socket_addr
    }

    pub fn add_connected_socket(&mut self, id: SocketId, addr: SocketAddr) {
        assert!(self.pending_accepts.is_empty());
        assert!(self.listening_sockets.remove(&id));
        self.connected_sockets.push_back((id, addr));
    }

    pub fn get_connected_socket(&mut self) -> Option<(SocketId, SocketAddr)> {
        self.connected_sockets.pop_front()
    }

    pub fn add_pending_accept(&mut self, sqe: io_channel::QueueEntry) {
        assert!(self.connected_sockets.is_empty());
        self.pending_accepts.push_back(sqe);
    }

    pub fn get_pending_accept(&mut self) -> Option<io_channel::QueueEntry> {
        self.pending_accepts.pop_front()
    }

    pub fn add_listening_socket(&mut self, id: SocketId) {
        assert!(self.listening_sockets.insert(id));
    }

    pub fn remove_listening_socket(&mut self, id: SocketId) -> bool {
        self.listening_sockets.remove(&id)
    }

    pub fn take_listening_sockets(&mut self) -> HashSet<SocketId> {
        let mut res = HashSet::new();
        core::mem::swap(&mut res, &mut self.listening_sockets);
        res
    }
}
