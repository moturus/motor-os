use moto_sys::SysHandle;
use std::{cell::RefCell, io::ErrorKind, net::SocketAddr, rc::Rc};

/// Common socket stuff. We (have to) mimic smoltcp structure, which
/// is mostly sockets partitioned by interfaces/devices. While technically
/// it may be possible to do Interface::poll() on all sockets, or on sockets
/// "shared" across devices, the semantics of this op is most likely different
/// from the "wildcard" listener semantics in Unix/Rust.
///
/// So three reasons why our sockets are "narrow" (don't cross devices):
/// - semantics is messy/underdefined (and not the same in Unix and smoltcp)
/// - efficiency: partitioned socket sets will work faster than one fat bucket
/// - API precision: it's better to define a strict API and then relax it
///   vs define a loose API and then deal with weird edge cases and Hyrum's law
mod tcp;
mod udp;

pub(super) enum SocketState {
    Udp(udp::UdpState),
    Tcp(tcp::TcpState),
}

impl SocketState {
    pub(super) fn unwrap_tcp_mut(&mut self) -> &mut tcp::TcpState {
        if let Self::Tcp(tcp_state) = self {
            tcp_state
        } else {
            panic!()
        }
    }
    pub(super) fn unwrap_tcp(&self) -> &tcp::TcpState {
        if let Self::Tcp(tcp_state) = self {
            tcp_state
        } else {
            panic!()
        }
    }

    pub(super) fn unwrap_udp(&mut self) -> &mut udp::UdpState {
        if let Self::Udp(udp_state) = self {
            udp_state
        } else {
            panic!()
        }
    }
}

pub(super) struct SocketBase {
    socket_id: u64,
    runtime: super::NetRuntime,
    device_idx: usize,
    smoltcp_handle: smoltcp::iface::SocketHandle,
    device_notify: Rc<moto_async::LocalNotify>,
    local_addr: SocketAddr,

    // Denormalized for quick validation.
    client_sender: moto_ipc::io_channel::Sender,

    // The socket is "detached" from its client and should be
    // dropped when last TX bytes are out (RX is not happening
    // because nobody is listening on our side).
    lingering: bool,
}

impl SocketBase {
    pub(super) fn new(
        socket_id: u64,
        runtime: super::NetRuntime,
        device_idx: usize,
        smoltcp_handle: smoltcp::iface::SocketHandle,
        socket_addr: SocketAddr,
        client_sender: moto_ipc::io_channel::Sender,
    ) -> Self {
        let device_notify = runtime.inner.borrow().devices[device_idx]
            .device_runtime_notify
            .clone();

        Self {
            socket_id,
            runtime,
            device_idx,
            smoltcp_handle,
            device_notify,
            local_addr: socket_addr,
            client_sender,
            lingering: false,
        }
    }

    pub(super) fn socket_id(&self) -> u64 {
        self.socket_id
    }

    pub(super) fn sender(&self) -> &moto_ipc::io_channel::Sender {
        &self.client_sender
    }

    pub(super) fn device_notify(&self) -> Rc<moto_async::LocalNotify> {
        self.device_notify.clone()
    }
}

pub(super) struct MotoSocket {
    base: SocketBase,
    state: SocketState,
}

impl Drop for MotoSocket {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            let mut inner = self.base.runtime.inner.borrow_mut();
            assert!(inner.sockets.get(&self.base.socket_id).is_none());
        }

        let Self { base, state } = self;

        match state {
            SocketState::Udp(udp_state) => Self::on_udp_socket_drop(base, udp_state),
            SocketState::Tcp(tcp_state) => Self::on_tcp_socket_drop(base, tcp_state),
        }

        let socket_id = base.socket_id;
        let client_handle = base.client_sender.remote_handle();
        let device_idx = base.device_idx;
        let smol_handle = base.smoltcp_handle;

        let mut runtime_ref = base.runtime.inner.borrow_mut();
        #[cfg(debug_assertions)]
        if let Some(client) = runtime_ref.clients.get_mut(&client_handle) {
            assert!(client.sockets.get(&socket_id).is_none());
        }

        // Will panic if not found.
        runtime_ref.devices[device_idx].sockets.remove(smol_handle);
    }
}

impl MotoSocket {
    pub(super) fn socket_id(&self) -> u64 {
        self.base.socket_id
    }

    pub(super) fn is_tcp(&self) -> bool {
        matches!(self.state, SocketState::Tcp(_))
    }

    pub(super) fn new(base: SocketBase, kind: SocketState) -> Rc<RefCell<Self>> {
        let this = Rc::new(RefCell::new(Self { base, state: kind }));
        let this_cloned = this.clone();
        {
            let socket_ref = this.borrow_mut();
            let base = &socket_ref.base;
            let mut inner = base.runtime.inner.borrow_mut();
            inner.sockets.insert(base.socket_id, this_cloned);
            inner
                .clients
                .get_mut(&base.client_sender.remote_handle())
                .unwrap()
                .sockets
                .insert(base.socket_id);
        }

        this
    }

    // Listening TCP sockets on accept change their clients.
    pub(super) fn set_client_sender(&mut self, client_sender: &moto_ipc::io_channel::Sender) {
        let prev_handle = self.base.client_sender.remote_handle();
        if prev_handle != client_sender.remote_handle() {
            let mut runtime_ref = self.base.runtime.inner.borrow_mut();
            if let Some(client) = runtime_ref.clients.get_mut(&prev_handle) {
                assert!(client.sockets.remove(&self.socket_id()));
            }

            if let Some(client) = runtime_ref.clients.get_mut(&client_sender.remote_handle()) {
                assert!(client.sockets.insert(self.socket_id()));
            }
            self.base.client_sender = client_sender.clone();
        }
    }

    pub(super) fn unwrap_tcp(&self) -> &tcp::TcpState {
        self.state.unwrap_tcp()
    }
    pub(super) fn unwrap_tcp_mut(&mut self) -> &mut tcp::TcpState {
        self.state.unwrap_tcp_mut()
    }
}
