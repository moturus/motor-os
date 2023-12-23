use std::{collections::VecDeque, net::SocketAddr};

use moto_ipc::io_channel;
pub use moto_runtime::rt_api::net::TcpState;
use moto_sys::SysHandle;

// While we try to make TCP structs below behave similarly to how
// they behave in Rust API, we necessarily have to do some things
// differently because here we manage low-level stuff like sockets.
pub struct TcpListener {
    id: u64,
    process: SysHandle,
    device_idx: Option<usize>,
    socket_addr: SocketAddr,

    // If listener::accept() is called first, it's sqe will be added
    // to pending_accepts.
    pending_accepts: VecDeque<io_channel::QueueEntry>,
    // If a remote connection comes before accept() is called,
    // a TcpStream object will be created, and its ID added to pending_streams.
    pending_streams: VecDeque<u64>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        assert!(self.pending_accepts.is_empty() && self.pending_streams.is_empty());
    }
}

impl TcpListener {
    pub fn new(
        id: u64,
        process: SysHandle,
        device_idx: Option<usize>,
        socket_addr: SocketAddr,
    ) -> Self {
        Self {
            id,
            process,
            device_idx,
            socket_addr,
            pending_accepts: VecDeque::new(),
            pending_streams: VecDeque::new(),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn process(&self) -> SysHandle {
        self.process
    }

    pub fn device_idx(&self) -> Option<usize> {
        self.device_idx
    }

    pub fn socket_addr(&self) -> &SocketAddr {
        &self.socket_addr
    }

    pub fn add_pending_stream(&mut self, id: u64) {
        assert!(self.pending_accepts.is_empty());
        self.pending_streams.push_back(id);
    }

    pub fn get_pending_stream(&mut self) -> Option<u64> {
        self.pending_streams.pop_front()
    }

    pub fn add_pending_accept(&mut self, sqe: io_channel::QueueEntry) {
        assert!(self.pending_streams.is_empty());
        self.pending_accepts.push_back(sqe);
    }

    pub fn get_pending_accept(&mut self) -> Option<io_channel::QueueEntry> {
        self.pending_accepts.pop_front()
    }

    // Called on process/client drop.
    pub fn hard_drop(&mut self) {
        self.pending_accepts.clear();
        self.pending_streams.clear();
    }
}

pub struct TcpStream {
    id: u64,
    process: SysHandle,
    device_idx: usize,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    state: TcpState,
    connect_sqe: io_channel::QueueEntry,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        assert_eq!(self.state, TcpState::Closed);
    }
}

impl TcpStream {
    pub fn new_outgoing(
        id: u64,
        process: SysHandle,
        device_idx: usize,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        connect_sqe: io_channel::QueueEntry,
    ) -> Self {
        Self {
            id,
            process,
            device_idx,
            local_addr,
            remote_addr,
            state: TcpState::Connecting,
            connect_sqe,
        }
    }

    pub fn new_incoming(
        id: u64,
        process: SysHandle,
        device_idx: usize,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Self {
        Self {
            id,
            process,
            device_idx,
            local_addr,
            remote_addr,
            state: TcpState::ReadWrite,
            connect_sqe: io_channel::QueueEntry::new(),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn device(&self) -> usize {
        self.device_idx
    }

    pub fn clear_device(&mut self) {
        self.device_idx = usize::MAX;
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.local_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }

    pub fn mark_accepted(&mut self) {}

    pub fn state(&self) -> TcpState {
        self.state
    }

    pub fn set_state(&mut self, state: TcpState) {
        self.state = state;
    }

    pub fn process(&self) -> &SysHandle {
        &self.process
    }

    pub fn connect_sqe(&self) -> &io_channel::QueueEntry {
        &self.connect_sqe
    }

    // Called when the client/process is dropped.
    pub fn hard_drop(&mut self) {
        self.state = TcpState::Closed;
    }
}
