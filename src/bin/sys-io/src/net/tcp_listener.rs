use std::{
    collections::{HashSet, VecDeque},
    net::SocketAddr,
    rc::Rc,
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
    conn: Rc<io_channel::ServerConnection>,
    socket_addr: SocketAddr, // What the user gave us, can be 0.0.0.0:port.

    // If listener::accept() is called first, it's sqe will be added
    // to pending_accepts.
    pending_accepts: VecDeque<(io_channel::Msg, Rc<io_channel::ServerConnection>)>,

    // Connected sockets that did not yet emit the accept QE.
    // Note: connected_sockets below may contain dropped sockets.
    pending_sockets: VecDeque<(SocketId, SocketAddr)>,

    // Pure listening sockets. We need to track them to drop when the listener is dropped.
    listening_sockets: HashSet<SocketId>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        assert!(
            self.pending_accepts.is_empty()
                && self.pending_sockets.is_empty()
                && self.listening_sockets.is_empty()
        );
    }
}

impl TcpListener {
    pub fn new(conn: std::rc::Rc<io_channel::ServerConnection>, socket_addr: SocketAddr) -> Self {
        Self {
            conn,
            socket_addr,
            pending_accepts: VecDeque::new(),
            pending_sockets: VecDeque::new(),
            listening_sockets: HashSet::new(),
        }
    }

    pub fn conn_handle(&self) -> SysHandle {
        self.conn.wait_handle()
    }

    pub fn socket_addr(&self) -> &SocketAddr {
        &self.socket_addr
    }

    pub fn add_pending_socket(&mut self, id: SocketId, addr: SocketAddr) {
        assert!(self.listening_sockets.remove(&id));
        self.pending_sockets.push_back((id, addr));
    }

    pub fn pop_pending_socket(&mut self) -> Option<(SocketId, SocketAddr)> {
        self.pending_sockets.pop_front()
    }

    pub fn remove_pending_socket(&mut self, id: SocketId) {
        for idx in 0..self.pending_sockets.len() {
            if self.pending_sockets[idx].0 == id {
                let _ = self.pending_sockets.remove(idx);
                return;
            }
        }
    }

    pub fn add_pending_accept(
        &mut self,
        msg: io_channel::Msg,
        conn: &Rc<io_channel::ServerConnection>,
    ) {
        assert!(self.pending_sockets.is_empty());
        self.pending_accepts.push_back((msg, conn.clone()));
    }

    pub fn get_pending_accept(
        &mut self,
    ) -> Option<(io_channel::Msg, Rc<io_channel::ServerConnection>)> {
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
