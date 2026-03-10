use std::{cell::RefCell, rc::Rc, task::Poll};

pub(super) struct RawUdpSocket {
    device: Rc<RefCell<super::NetDev<'static>>>,
    handle: smoltcp::iface::SocketHandle,
}

impl RawUdpSocket {
    pub fn bind(device: Rc<RefCell<super::NetDev<'static>>>, port: u16) -> Self {
        let rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 10],
            vec![0; 8192],
        );
        let tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 10],
            vec![0; 8192],
        );

        let mut socket = smoltcp::socket::udp::Socket::new(rx_buffer, tx_buffer);
        socket.bind(port).unwrap();

        let handle = {
            let mut dev = device.borrow_mut();
            dev.sockets.add(socket)
        };

        Self { device, handle }
    }

    pub async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, smoltcp::wire::IpEndpoint)> {
        std::future::poll_fn(|cx| {
            let mut device = self.device.borrow_mut();
            let socket = device
                .sockets
                .get_mut::<smoltcp::socket::udp::Socket>(self.handle);

            if socket.can_recv() {
                let (len, metadata) = socket.recv_slice(buf).unwrap();
                Poll::Ready(Ok((len, metadata.endpoint)))
            } else {
                socket.register_recv_waker(cx.waker());
                Poll::Pending
            }
        })
        .await
    }

    pub async fn send_to(
        &self,
        buf: &[u8],
        endpoint: smoltcp::wire::IpEndpoint,
    ) -> std::io::Result<usize> {
        std::future::poll_fn(|cx| {
            let mut device = self.device.borrow_mut();
            let socket = device
                .sockets
                .get_mut::<smoltcp::socket::udp::Socket>(self.handle);

            if socket.can_send() {
                let max_payload = socket.payload_send_capacity().min(buf.len());
                socket.send_slice(&buf[..max_payload], endpoint).unwrap();
                device.notify.notify_one();
                Poll::Ready(Ok(max_payload))
            } else {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
        })
        .await
    }
}
