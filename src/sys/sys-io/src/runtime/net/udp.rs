use std::io::ErrorKind;
use std::{cell::RefCell, net::SocketAddr, rc::Rc, task::Poll};

use moto_sys_io::api_net;

use super::NetRuntime;
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
    ) -> std::io::Result<MotoSocket> {
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
            inner.devices[device_idx].add_udp_addr_in_use(socket_addr)?;
            (
                inner.next_socket_id(),
                inner.devices[device_idx].sockets.add(smoltcp_socket),
            )
        };

        let base = BaseSocket::new(socket_id, runtime, device_idx, smoltcp_handle, socket_addr);
        Ok(MotoSocket::new(
            base,
            SocketKind::Udp(UdpSocket {
                ephemeral_port: None,
            }),
        ))
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

pub(crate) async fn bind(
    runtime: &NetRuntime,
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
) -> std::io::Result<()> {
    let mut socket_addr = moto_sys_io::api_net::get_socket_addr(&msg.payload);
    let mut inner = runtime.inner.borrow_mut();
    let mut resp = msg;

    // Verify that the IP is valid (if present) before the socket is created.
    let ip_addr = socket_addr.ip();

    if ip_addr.is_unspecified() {
        // We don't allow binding to an unspecified addr (yet?).
        return Err(ErrorKind::InvalidInput.into());
    }
    let device_idx = {
        match inner.ip_addresses.get(&ip_addr) {
            Some(idx) => *idx,
            None => {
                #[cfg(debug_assertions)]
                log::debug!("IP addr {ip_addr:?} not found");

                return Err(ErrorKind::InvalidInput.into());
            }
        }
    };

    // Allocate/assign port, if needed.
    let mut allocated_port = None;
    if socket_addr.port() == 0 {
        let local_port = match inner.devices[device_idx].get_ephemeral_udp_port(&ip_addr) {
            Some(port) => port,
            None => {
                log::warn!("get_ephemeral_udp_port({ip_addr:?}) failed");

                return Err(ErrorKind::OutOfMemory.into());
            }
        };
        socket_addr.set_port(local_port);
        api_net::put_socket_addr(&mut resp.payload, &socket_addr);
        allocated_port = Some(local_port);
    }

    drop(inner);
    let udp_socket = UdpSocket::bind(runtime, device_idx, socket_addr)?;
    // api_net::io_subchannel_mask(sqe.payload.args_8()[23]),

    let socket_id = udp_socket.socket_id();
    {
        let mut inner = runtime.inner.borrow_mut();
        inner.sockets.insert(socket_id, udp_socket);
        inner
            .clients
            .get_mut(&sender.remote_handle())
            .unwrap()
            .sockets
            .insert(socket_id);
    }
    /*
    let udp_socket_id = udp_socket.id;
    self.socket_ids.insert(udp_socket.id);
    self.udp_addresses_in_use.insert(socket_addr);
    self.udp_sockets.insert(udp_socket.id, udp_socket);

    let conn_udp_sockets = match self.conn_udp_sockets.get_mut(&conn.wait_handle()) {
        Some(val) => val,
        None => {
            self.conn_udp_sockets
                .insert(conn.wait_handle(), HashSet::new());
            self.conn_udp_sockets.get_mut(&conn.wait_handle()).unwrap()
        }
    };
    assert!(conn_udp_sockets.insert(udp_socket_id));
    */

    #[cfg(debug_assertions)]
    log::debug!(
        "sys-io: new udp socket on {:?}, conn: 0x{:x}",
        socket_addr,
        sender.remote_handle().as_u64()
    );

    let mut resp = msg;
    resp.handle = socket_id;
    resp.status = moto_rt::E_OK;
    let _ = sender.send(resp).await;
    Ok(())
}
