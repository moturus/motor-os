use moto_sys::SysHandle;

use crate::runtime::channel_budget::ClientSender;
use std::{cell::RefCell, io::ErrorKind, net::SocketAddr, rc::Rc};

/// Common socket stuff. We (have to) mimic moto-netstack's structure, which
/// is mostly sockets partitioned by interfaces/devices. While technically
/// it may be possible to do Interface::poll() on all sockets, or on sockets
/// "shared" across devices, the semantics of this op is most likely different
/// from the "wildcard" listener semantics in Unix/Rust.
///
/// So three reasons why our sockets are "narrow" (don't cross devices):
/// - semantics is messy/underdefined (and not the same in Unix and moto-netstack)
/// - efficiency: partitioned socket sets will work faster than one fat bucket
/// - API precision: it's better to define a strict API and then relax it
///   vs define a loose API and then deal with weird edge cases and Hyrum's law
pub(super) mod tcp;
mod udp;

pub(super) enum SocketState {
    Udp(udp::UdpState),
    Tcp(tcp::TcpState),
    Vsock(super::vsock::VsockSocketState),
    VsockListener(crate::runtime::vsock::listener::ListenerState<super::vsock::PendingAccept>),
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
    backend: SocketBackend,

    // The owning client's channel. A TCP socket retired to TIME-WAIT drops
    // it: nothing goes to the client again, and the channel's shared pages
    // must not outlive the client by the ten seconds of TIME-WAIT.
    client_sender: Option<ClientSender>,
    // The channel's handle, which keys the client's socket set; denormalized
    // for quick validation and kept after the sender is dropped.
    client_handle: SysHandle,

    // The socket is "detached" from its client and should be
    // dropped when last TX bytes are out (RX is not happening
    // because nobody is listening on our side).
    lingering: bool,
}

pub(super) struct IpSocketBackend {
    device_idx: usize,
    device_notify: Rc<moto_sdk::async_runtime::LocalNotify>,
    local_addr: SocketAddr,
    publication: IpSocketPublication,
}

enum IpSocketPublication {
    Private,
    Sending(moto_sdk::async_runtime::oneshot::Receiver<bool>),
    Published,
}

pub(super) enum SocketBackend {
    Ip(IpSocketBackend),
    Vsock(crate::runtime::vsock::admission::ConnectionTuple),
    VsockListener,
}

impl SocketBase {
    pub(super) fn new_ip(
        socket_id: u64,
        runtime: super::NetRuntime,
        device_idx: usize,
        socket_addr: SocketAddr,
        client_sender: ClientSender,
    ) -> Self {
        let device_notify = runtime.inner.borrow().devices[device_idx]
            .device_runtime_notify
            .clone();

        Self {
            socket_id,
            runtime,
            backend: SocketBackend::Ip(IpSocketBackend {
                device_idx,
                device_notify,
                local_addr: socket_addr,
                publication: IpSocketPublication::Private,
            }),
            client_handle: client_sender.remote_handle(),
            client_sender: Some(client_sender),
            lingering: false,
        }
    }

    pub(super) fn socket_id(&self) -> u64 {
        self.socket_id
    }

    pub(super) fn new_vsock(
        socket_id: u64,
        runtime: super::NetRuntime,
        tuple: crate::runtime::vsock::admission::ConnectionTuple,
        client_sender: ClientSender,
    ) -> Self {
        Self {
            socket_id,
            runtime,
            backend: SocketBackend::Vsock(tuple),
            client_handle: client_sender.remote_handle(),
            client_sender: Some(client_sender),
            lingering: false,
        }
    }

    pub(super) fn new_vsock_listener(
        socket_id: u64,
        runtime: super::NetRuntime,
        client_sender: ClientSender,
    ) -> Self {
        Self {
            socket_id,
            runtime,
            backend: SocketBackend::VsockListener,
            client_handle: client_sender.remote_handle(),
            client_sender: Some(client_sender),
            lingering: false,
        }
    }

    pub(super) fn ip_backend(&self) -> &IpSocketBackend {
        let SocketBackend::Ip(backend) = &self.backend else {
            panic!("vsock has no IP backend")
        };
        backend
    }

    fn ip_backend_mut(&mut self) -> &mut IpSocketBackend {
        let SocketBackend::Ip(backend) = &mut self.backend else {
            panic!("vsock has no IP backend")
        };
        backend
    }

    pub(super) fn vsock_tuple(&self) -> crate::runtime::vsock::admission::ConnectionTuple {
        let SocketBackend::Vsock(tuple) = self.backend else {
            panic!("IP socket has no vsock tuple")
        };
        tuple
    }

    /// The client's channel; a socket that dropped it never sends again.
    pub(super) fn sender(&self) -> &ClientSender {
        self.client_sender
            .as_ref()
            .expect("socket released its client channel")
    }

    pub(super) fn client_handle(&self) -> SysHandle {
        self.client_handle
    }

    /// Drops this socket's reference to the client's channel.
    pub(super) fn release_client_sender(&mut self) {
        self.client_sender = None;
    }

    pub(super) fn runtime(&self) -> &super::NetRuntime {
        &self.runtime
    }
}

impl IpSocketBackend {
    /// The socket id in the netstack's handle type. There is one identity,
    /// allocated by `next_socket_id`.
    pub(super) fn handle(&self, socket_id: u64) -> moto_netstack::iface::SocketHandle {
        socket_id.into()
    }

    pub(super) fn device_notify(&self) -> Rc<moto_sdk::async_runtime::LocalNotify> {
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

        match (&base.backend, state) {
            (SocketBackend::Ip(_), SocketState::Udp(udp_state)) => {
                Self::on_udp_socket_drop(base, udp_state)
            }
            (SocketBackend::Ip(_), SocketState::Tcp(tcp_state)) => {
                Self::on_tcp_socket_drop(base, tcp_state)
            }
            (SocketBackend::Vsock(_), SocketState::Vsock(vsock_state)) => {
                super::vsock::on_socket_drop(base, vsock_state);
                return;
            }
            (SocketBackend::VsockListener, SocketState::VsockListener(listener)) => {
                super::vsock::on_listener_drop(base, listener);
                return;
            }
            _ => panic!("socket state/backend mismatch"),
        }

        let socket_id = base.socket_id;
        let client_handle = base.client_handle;
        let ip = base.ip_backend();
        let device_idx = ip.device_idx;
        let netstack_handle = ip.handle(socket_id);

        let mut runtime_ref = base.runtime.inner.borrow_mut();
        #[cfg(debug_assertions)]
        if let Some(client) = runtime_ref.clients.get_mut(&client_handle) {
            assert!(client.sockets.get(&socket_id).is_none());
        }

        // Will panic if not found.
        runtime_ref.devices[device_idx]
            .sockets
            .remove(netstack_handle);
        runtime_ref.devices.reap(device_idx);
    }
}

impl MotoSocket {
    /// Publish the handle before starting I/O. Removal can take the receiver
    /// to order its terminal notification after this reply without retaining
    /// the socket while a client is not reading its channel.
    pub(super) async fn publish_ip_socket(
        socket: Rc<RefCell<Self>>,
        reply: moto_sdk::ipc::io_channel::Msg,
    ) -> bool {
        use futures::FutureExt;

        let sender = socket.borrow().base.sender().clone();
        // The usual reply fits immediately and needs no extra allocation.
        if let Some(result) = sender.send(reply).now_or_never() {
            if result.is_ok() {
                socket.borrow_mut().base.ip_backend_mut().publication =
                    IpSocketPublication::Published;
            }
            return result.is_ok();
        }
        let (sent, ready) = moto_sdk::async_runtime::oneshot();
        {
            let mut socket = socket.borrow_mut();
            let ip = socket.base.ip_backend_mut();
            assert!(matches!(ip.publication, IpSocketPublication::Private));
            ip.publication = IpSocketPublication::Sending(ready);
        }
        let weak = Rc::downgrade(&socket);
        drop(socket);
        let success = sender.send(reply).await.is_ok();
        let published = weak.upgrade().is_some_and(|socket| {
            let mut socket = socket.borrow_mut();
            let ip = socket.base.ip_backend_mut();
            if !success || !matches!(ip.publication, IpSocketPublication::Sending(_)) {
                return false;
            }
            ip.publication = IpSocketPublication::Published;
            true
        });
        let _ = sent.send(success);
        published
    }

    pub(super) fn socket_id(&self) -> u64 {
        self.base.socket_id
    }

    pub(super) fn sender(&self) -> &ClientSender {
        self.base.sender()
    }

    pub(super) fn vsock_tuple(&self) -> crate::runtime::vsock::admission::ConnectionTuple {
        self.base.vsock_tuple()
    }

    pub(super) fn is_tcp(&self) -> bool {
        matches!(self.state, SocketState::Tcp(_))
    }

    pub(super) fn is_vsock(&self) -> bool {
        matches!(self.state, SocketState::Vsock(_))
    }

    pub(super) fn is_vsock_listener(&self) -> bool {
        matches!(self.state, SocketState::VsockListener(_))
    }

    pub(super) fn new_ip(
        base: SocketBase,
        kind: SocketState,
    ) -> std::io::Result<Rc<RefCell<Self>>> {
        let runtime = base.runtime.clone();
        let socket_id = base.socket_id;
        let device_idx = base.ip_backend().device_idx;
        let netstack_handle = base.ip_backend().handle(socket_id);
        let client_handle = base.client_handle;
        let mut inner = runtime.inner.borrow_mut();
        if !inner
            .clients
            .get(&client_handle)
            .is_some_and(|client| !client.shutting_down)
        {
            inner.devices[device_idx].sockets.remove(netstack_handle);
            return Err(ErrorKind::NotConnected.into());
        }

        let this = Rc::new(RefCell::new(Self { base, state: kind }));
        assert!(inner.sockets.insert(socket_id, this.clone()).is_none());
        assert!(
            inner
                .clients
                .get_mut(&client_handle)
                .unwrap()
                .sockets
                .insert(socket_id)
        );
        Ok(this)
    }

    pub(super) fn new_vsock(
        base: SocketBase,
        state: super::vsock::VsockSocketState,
    ) -> std::io::Result<Rc<RefCell<Self>>> {
        let runtime = base.runtime.clone();
        let socket_id = base.socket_id;
        let client_handle = base.client_handle;
        let mut inner = runtime.inner.borrow_mut();
        if !inner
            .clients
            .get(&client_handle)
            .is_some_and(|client| !client.shutting_down)
        {
            inner.vsock.tuples.remove_stream(socket_id);
            return Err(ErrorKind::NotConnected.into());
        }

        let this = Rc::new(RefCell::new(Self {
            base,
            state: SocketState::Vsock(state),
        }));
        assert!(inner.sockets.insert(socket_id, this.clone()).is_none());
        assert!(
            inner
                .clients
                .get_mut(&client_handle)
                .unwrap()
                .sockets
                .insert(socket_id)
        );
        Ok(this)
    }

    pub(super) fn new_vsock_listener(
        base: SocketBase,
        listener: crate::runtime::vsock::listener::ListenerState<super::vsock::PendingAccept>,
    ) -> std::io::Result<Rc<RefCell<Self>>> {
        let runtime = base.runtime.clone();
        let socket_id = base.socket_id;
        let client_handle = base.client_handle;
        let mut inner = runtime.inner.borrow_mut();
        if !inner
            .clients
            .get(&client_handle)
            .is_some_and(|client| !client.shutting_down)
        {
            inner.vsock.tuples.remove_listener(socket_id);
            return Err(ErrorKind::NotConnected.into());
        }

        let this = Rc::new(RefCell::new(Self {
            base,
            state: SocketState::VsockListener(listener),
        }));
        assert!(inner.sockets.insert(socket_id, this.clone()).is_none());
        assert!(
            inner
                .clients
                .get_mut(&client_handle)
                .unwrap()
                .sockets
                .insert(socket_id)
        );
        Ok(this)
    }

    // Accepted TCP/vsock sockets may move to another channel of the owner.
    pub(super) fn set_client_sender(&mut self, client_sender: &ClientSender) -> bool {
        let prev_handle = self.base.client_handle;
        let next_handle = client_sender.remote_handle();
        let mut runtime_ref = self.base.runtime.inner.borrow_mut();
        if !runtime_ref
            .clients
            .get(&next_handle)
            .is_some_and(|client| !client.shutting_down)
        {
            return false;
        }

        if prev_handle != next_handle {
            if let Some(client) = runtime_ref.clients.get_mut(&prev_handle) {
                assert!(client.sockets.remove(&self.socket_id()));
            }

            assert!(
                runtime_ref
                    .clients
                    .get_mut(&next_handle)
                    .unwrap()
                    .sockets
                    .insert(self.socket_id())
            );
            self.base.client_sender = Some(client_sender.clone());
            self.base.client_handle = next_handle;
        }
        true
    }

    pub(super) fn unwrap_tcp(&self) -> &tcp::TcpState {
        self.state.unwrap_tcp()
    }
    pub(super) fn unwrap_tcp_mut(&mut self) -> &mut tcp::TcpState {
        self.state.unwrap_tcp_mut()
    }

    pub(super) fn unwrap_vsock(&self) -> &super::vsock::VsockSocketState {
        let SocketState::Vsock(state) = &self.state else {
            panic!("not a vsock stream")
        };
        state
    }

    pub(super) fn unwrap_vsock_mut(&mut self) -> &mut super::vsock::VsockSocketState {
        let SocketState::Vsock(state) = &mut self.state else {
            panic!("not a vsock stream")
        };
        state
    }

    pub(super) fn unwrap_vsock_listener(
        &self,
    ) -> &crate::runtime::vsock::listener::ListenerState<super::vsock::PendingAccept> {
        let SocketState::VsockListener(listener) = &self.state else {
            panic!("not a vsock listener")
        };
        listener
    }

    pub(super) fn unwrap_vsock_listener_mut(
        &mut self,
    ) -> &mut crate::runtime::vsock::listener::ListenerState<super::vsock::PendingAccept> {
        let SocketState::VsockListener(listener) = &mut self.state else {
            panic!("not a vsock listener")
        };
        listener
    }
}
