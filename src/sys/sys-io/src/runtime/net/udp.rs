use std::{cell::RefCell, net::SocketAddr, rc::Rc, task::Poll};

use super::socket::BaseSocket;
use super::socket::MotoSocket;
use super::socket::SocketKind;

pub(super) struct UdpSocket {
    pub ephemeral_port: Option<u16>,
}

impl UdpSocket {
    pub(super) fn bind(
        runtime: &super::NetRuntime,
        device_idx: usize,
        socket_addr: SocketAddr,
    ) -> MotoSocket {
        let rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 10],
            vec![0; 8192],
        );
        let tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 10],
            vec![0; 8192],
        );

        let mut smoltcp_socket = smoltcp::socket::udp::Socket::new(rx_buffer, tx_buffer);
        smoltcp_socket.bind(socket_addr).unwrap();
        let runtime = runtime.clone();

        let (socket_id, smoltcp_handle) = {
            let mut inner = runtime.inner.borrow_mut();
            (
                inner.next_socket_id(),
                inner.devices[device_idx].sockets.add(smoltcp_socket),
            )
        };

        let base = BaseSocket::new(socket_id, runtime, device_idx, smoltcp_handle, socket_addr);
        MotoSocket::new(
            base,
            SocketKind::Udp(UdpSocket {
                ephemeral_port: None,
            }),
        )
    }

    pub async fn recv_from(
        &self,
        base: &super::socket::BaseSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, smoltcp::wire::IpEndpoint)> {
        std::future::poll_fn(move |cx| {
            base.with_smoltcp_socket::<_, smoltcp::socket::udp::Socket, _>(|smoltcp_socket| {
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
        base: &super::socket::BaseSocket,
        buf: &[u8],
        endpoint: smoltcp::wire::IpEndpoint,
    ) -> std::io::Result<usize> {
        std::future::poll_fn(|cx| {
            let notify = base.device_notify();

            base.with_smoltcp_socket::<_, smoltcp::socket::udp::Socket, _>(|smoltcp_socket| {
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
