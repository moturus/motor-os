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
    client: SysHandle, // Denormalized for quick validation.
}

impl SocketBase {
    pub(super) fn new(
        socket_id: u64,
        runtime: super::NetRuntime,
        device_idx: usize,
        smoltcp_handle: smoltcp::iface::SocketHandle,
        socket_addr: SocketAddr,
        client: SysHandle,
    ) -> Self {
        let device_notify = runtime.inner.borrow().devices[device_idx].notify.clone();

        Self {
            socket_id,
            runtime,
            device_idx,
            smoltcp_handle,
            device_notify,
            local_addr: socket_addr,
            client,
        }
    }

    pub(super) fn socket_id(&self) -> u64 {
        self.socket_id
    }

    pub(super) fn client(&self) -> SysHandle {
        self.client
    }

    pub(super) fn sender(&self) -> Option<moto_ipc::io_channel::Sender> {
        self.runtime.get_sender(self.client)
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
    }
}

impl MotoSocket {
    pub(super) fn socket_id(&self) -> u64 {
        self.base.socket_id
    }

    pub(super) fn new(base: SocketBase, kind: SocketState) -> Self {
        Self { base, state: kind }
    }

    // Listening TCP sockets on accept change their clients.
    pub(super) fn set_client(&mut self, client: SysHandle) {
        self.base.client = client;
    }

    fn on_drop(this: Rc<RefCell<Self>>) {
        let this_ref = this.borrow();
        let Self { base, state: kind } = &*this_ref;

        let socket_id = base.socket_id;
        let client_handle = base.client;

        let mut runtime_ref = base.runtime.inner.borrow_mut();
        let client = runtime_ref.clients.get_mut(&client_handle).unwrap();
        assert!(client.sockets.remove(&socket_id));

        // Don't remove from devices as some bytes may need to get out.
    }

    pub(super) fn unwrap_tcp(&self) -> &tcp::TcpState {
        self.state.unwrap_tcp()
    }
    pub(super) fn unwrap_tcp_mut(&mut self) -> &mut tcp::TcpState {
        self.state.unwrap_tcp_mut()
    }
}
