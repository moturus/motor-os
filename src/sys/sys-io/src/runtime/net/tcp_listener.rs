use moto_sys::SysHandle;
use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    io::ErrorKind,
    net::SocketAddr,
    rc::Rc,
};

pub(super) struct TcpListener {
    listener_id: u64,
    runtime: super::NetRuntime,
    socket_addr: SocketAddr, // What the user gave us, can be 0.0.0.0:port.
    client: SysHandle,       // Denormalized for quick validation.

    // If listener::accept() is called first, it's sqe will be added
    // to pending_accepts.
    pending_accepts: VecDeque<moto_ipc::io_channel::Msg>,

    // Connected sockets that did not yet emit the accept QE.
    // Note: connected_sockets below may contain dropped sockets.
    pending_sockets: VecDeque<(u64, SocketAddr)>,

    // Pure listening sockets. We need to track them to drop when the listener is dropped.
    listening_sockets: HashSet<u64>,

    pub ephemeral_tcp_port: Option<Rc<super::EphemeralTcpPort>>,

    // Will be applied to all new sockets.
    ttl: u8,
}

impl TcpListener {
    pub(super) async fn bind(
        runtime: &super::NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        todo!()
    }
}
