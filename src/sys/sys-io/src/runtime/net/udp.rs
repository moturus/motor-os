use std::{cell::RefCell, rc::Rc, task::Poll};

pub(super) struct RawUdpSocket {
    socket_id: u64,
    runtime: super::NetRuntime,
    device_idx: usize,
    smoltcp_handle: smoltcp::iface::SocketHandle,
}

impl Drop for RawUdpSocket {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            let mut inner = self.runtime.inner.borrow_mut();
            assert!(inner.udp_sockets.get(&self.socket_id).is_none());
        }

        let runtime = self.runtime.clone();
        let device_idx = self.device_idx;
        let smoltcp_handle = self.smoltcp_handle;

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
                    log::error!("Stale UDP socket cleared.");
                    return;
                }

                moto_async::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
    }
}

impl RawUdpSocket {
    pub(super) fn socket_id(&self) -> u64 {
        self.socket_id
    }

    pub(super) fn bind(runtime: &super::NetRuntime, device_idx: usize, port: u16) -> Self {
        let rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 10],
            vec![0; 8192],
        );
        let tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 10],
            vec![0; 8192],
        );

        let mut smoltcp_socket = smoltcp::socket::udp::Socket::new(rx_buffer, tx_buffer);
        smoltcp_socket.bind(port).unwrap();
        let runtime = runtime.clone();

        let (socket_id, smoltcp_handle) = {
            let mut inner = runtime.inner.borrow_mut();
            (
                inner.next_socket_id(),
                inner.devices[device_idx].sockets.add(smoltcp_socket),
            )
        };

        Self {
            socket_id,
            runtime,
            device_idx,
            smoltcp_handle,
        }
    }

    fn with_smoltcp_socket<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut smoltcp::socket::udp::Socket) -> T,
    {
        let mut inner = self.runtime.inner.borrow_mut();
        let device = &mut inner.devices[self.device_idx];
        let smoltcp_socket = device
            .sockets
            .get_mut::<smoltcp::socket::udp::Socket>(self.smoltcp_handle);
        f(smoltcp_socket)
    }

    fn device_notify(&self) -> Rc<moto_async::LocalNotify> {
        self.runtime.inner.borrow().devices[self.device_idx]
            .notify
            .clone()
    }

    pub async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, smoltcp::wire::IpEndpoint)> {
        std::future::poll_fn(move |cx| {
            self.with_smoltcp_socket(|smoltcp_socket| {
                if smoltcp_socket.can_recv() {
                    let (len, metadata) = smoltcp_socket.recv_slice(buf).unwrap();
                    Poll::Ready(Ok((len, metadata.endpoint)))
                } else {
                    smoltcp_socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            })
        })
        .await
    }

    pub async fn send_to(
        &self,
        buf: &[u8],
        endpoint: smoltcp::wire::IpEndpoint,
    ) -> std::io::Result<usize> {
        std::future::poll_fn(|cx| {
            let notify = self.device_notify();

            self.with_smoltcp_socket(|smoltcp_socket| {
                if smoltcp_socket.can_send() {
                    let max_payload = smoltcp_socket.payload_send_capacity().min(buf.len());
                    smoltcp_socket
                        .send_slice(&buf[..max_payload], endpoint)
                        .unwrap();
                    notify.notify_one();
                    Poll::Ready(Ok(max_payload))
                } else {
                    smoltcp_socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
            })
        })
        .await
    }
}
