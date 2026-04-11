use std::{cell::RefCell, io::ErrorKind, net::SocketAddr, rc::Rc};

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

pub(super) enum SocketState {
    Udp(udp::UdpState),
    // Tcp,
}

pub(super) struct SocketBase {
    socket_id: u64,
    runtime: super::NetRuntime,
    device_idx: usize,
    smoltcp_handle: smoltcp::iface::SocketHandle,
    device_notify: Rc<moto_async::LocalNotify>,

    pub socket_addr: SocketAddr,

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
        self.device_notify.clone()
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

        let runtime = self.base.runtime.clone();
        let device_idx = self.base.device_idx;
        let socket_addr = self.base.socket_addr;
        let smoltcp_handle = self.base.smoltcp_handle;
        let socket_id = self.base.socket_id;

        // UDP sockets don't linger.
        {
            let mut inner = runtime.inner.borrow_mut();
            let sockets = &mut inner.devices[device_idx].sockets;

            #[cfg(debug_assertions)]
            if sockets
                .get_mut::<smoltcp::socket::udp::Socket>(smoltcp_handle)
                .send_queue()
                != 0
            {
                log::debug!("Dropped UDP socket 0x{socket_id:x} with unsent bytes.");
            } else {
                log::debug!("Dropped UDP socket 0x{socket_id:x}.");
            }

            sockets.remove(smoltcp_handle);
            inner.devices[device_idx].remove_udp_addr_in_use(&socket_addr);
        }

        // There could be bytes stuck in the socket. Wait for them to clear.
        // Async Rust really shines here!
        /*
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
                    log::debug!("Stale UDP socket 0x{socket_id:x} cleared.");
                    return;
                }

                moto_async::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
        */
    }
}

impl MotoSocket {
    pub(super) fn socket_id(&self) -> u64 {
        self.base.socket_id
    }

    pub(super) fn new(base: SocketBase, kind: SocketState) -> Self {
        Self { base, state: kind }
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
}
