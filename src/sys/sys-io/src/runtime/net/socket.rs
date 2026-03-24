use std::{io::ErrorKind, net::SocketAddr, rc::Rc};

use moto_sys::SysHandle;

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
mod udp;

pub(super) enum SocketKind {
    Udp(udp::UdpSocket),
    // Tcp,
}

pub(super) struct BaseSocket {
    socket_id: u64,
    runtime: super::NetRuntime,
    device_idx: usize,
    smoltcp_handle: smoltcp::iface::SocketHandle,

    pub socket_addr: SocketAddr,
    client: SysHandle, // Denormalized for quick validation.
}

impl BaseSocket {
    pub(super) fn new(
        socket_id: u64,
        runtime: super::NetRuntime,
        device_idx: usize,
        smoltcp_handle: smoltcp::iface::SocketHandle,
        socket_addr: SocketAddr,
        client: SysHandle,
    ) -> Self {
        Self {
            socket_id,
            runtime,
            device_idx,
            smoltcp_handle,
            socket_addr,
            client,
        }
    }

    pub(super) fn socket_id(&self) -> u64 {
        self.socket_id
    }

    pub(super) fn client(&self) -> SysHandle {
        self.client
    }

    pub(super) fn device_notify(&self) -> Rc<moto_async::LocalNotify> {
        self.runtime.inner.borrow().devices[self.device_idx]
            .notify
            .clone()
    }

    pub(super) fn with_smoltcp_socket<F, S: smoltcp::socket::AnySocket<'static>, T>(
        &self,
        f: F,
    ) -> T
    where
        F: FnOnce(&mut S) -> T,
    {
        let mut inner = self.runtime.inner.borrow_mut();
        let device = &mut inner.devices[self.device_idx];
        let smoltcp_socket = device.sockets.get_mut::<S>(self.smoltcp_handle);
        f(smoltcp_socket)
    }
}

pub(super) struct MotoSocket {
    base: BaseSocket,
    kind: SocketKind,
}

impl Drop for MotoSocket {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            let mut inner = self.base.runtime.inner.borrow_mut();
            assert!(inner.sockets.get(&self.base.socket_id).is_none());
        }

        let runtime = self.base.runtime.clone();
        let device_idx = self.base.device_idx;
        let socket_addr = self.base.socket_addr;
        let smoltcp_handle = self.base.smoltcp_handle;

        // There could be bytes stuck in the socket. Wait for them to clear.
        // Async Rust really shines here!
        moto_async::LocalRuntime::spawn(async move {
            loop {
                let mut inner = runtime.inner.borrow_mut();
                let sockets = &mut inner.devices[device_idx].sockets;
                if sockets
                    .get_mut::<smoltcp::socket::udp::Socket>(smoltcp_handle)
                    .send_queue()
                    == 0
                {
                    sockets.remove(smoltcp_handle);
                    inner.devices[device_idx].remove_udp_addr_in_use(&socket_addr);
                    log::error!("Stale socket cleared.");
                    return;
                }

                moto_async::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
    }
}

impl MotoSocket {
    pub(super) fn socket_id(&self) -> u64 {
        self.base.socket_id
    }

    pub(super) fn new(base: BaseSocket, kind: SocketKind) -> Self {
        Self { base, kind }
    }

    /*
    pub(super) async fn udp_tx(
        runtime: &super::NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let socket_id = msg.handle;

        let mut inner = runtime.inner.borrow_mut();
        let Some(mut socket) = inner.sockets.get_mut(&socket_id) else {
            let page_idx = msg.payload.shared_pages()[11];
            let _io_page = sender.get_page(page_idx); // Get the page out to deallocate.
            return Err(ErrorKind::NotFound.into());
        };

        let Self { base, kind } = socket;

        if base.client() != sender.remote_handle() {
            log::debug!("UDP TX: wrong client for socket");
            let page_idx = msg.payload.shared_pages()[11];
            let _io_page = sender.get_page(page_idx); // Get the page out to deallocate.
            return Err(ErrorKind::NotFound.into());
        }

        #[allow(irrefutable_let_patterns)]
        let SocketKind::Udp(udp_socket) = kind else {
            log::debug!("UDP TX: bad socket kind");
            let page_idx = msg.payload.shared_pages()[11];
            let _io_page = sender.get_page(page_idx); // Get the page out to deallocate.
            return Err(ErrorKind::InvalidInput.into());
        };

        xx // TODO: udp_socket.tx needs access to base, inner, self... how to decompose?
        udp_socket.tx(base, msg, sender).await
    }
    */

    // pub(super) fn with_base_kind<F, T>(&mut self, f: F) -> T
    // where
    //     F: FnOnce(&mut BaseSocket, &mut SocketKind) -> T,
    // {
    //     let Self { base, kind } = self;
    //     f(base, kind)
    // }
}
