use core::task::Poll;
use std::io::{Error, ErrorKind, Result};
use std::net::IpAddr;
use std::time::Duration;

use futures::FutureExt;
use moto_ipc::io_channel;
use moto_sys_io::api_net;
use smoltcp::iface::SocketHandle;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::icmp;
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpAddress};

use super::NetRuntime;
use crate::util::{map_err_into_native, map_native_error};

struct IcmpSocketGuard {
    runtime: NetRuntime,
    device_idx: usize,
    handle: SocketHandle,
    identifier: u16,
}

impl Drop for IcmpSocketGuard {
    fn drop(&mut self) {
        let mut inner = self.runtime.inner.borrow_mut();
        let device = &mut inner.devices[self.device_idx];
        device.sockets.remove(self.handle);
        device.free_icmp_identifier(self.identifier);
    }
}

fn make_payload(request_id: u64, sequence: u16, data_len: usize) -> Vec<u8> {
    let seed = request_id.wrapping_mul(31).wrapping_add(sequence as u64);
    (0..data_len)
        .map(|idx| (seed.wrapping_add(idx as u64) & 0xff) as u8)
        .collect()
}

fn emit_request(
    bytes: &mut [u8],
    source: IpAddr,
    destination: IpAddr,
    identifier: u16,
    sequence: u16,
    data: &[u8],
) {
    let checksum = ChecksumCapabilities::default();
    match (source, destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            let repr = Icmpv4Repr::EchoRequest {
                ident: identifier,
                seq_no: sequence,
                data,
            };
            repr.emit(&mut Icmpv4Packet::new_unchecked(bytes), &checksum);
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let repr = Icmpv6Repr::EchoRequest {
                ident: identifier,
                seq_no: sequence,
                data,
            };
            repr.emit(
                &source,
                &destination,
                &mut Icmpv6Packet::new_unchecked(bytes),
                &checksum,
            );
        }
        _ => unreachable!("route source and destination must use the same IP family"),
    }
}

fn is_matching_reply(
    bytes: &[u8],
    source: IpAddr,
    destination: IpAddr,
    local_addr: IpAddr,
    identifier: u16,
    sequence: u16,
    expected_data: &[u8],
) -> bool {
    if source != destination {
        return false;
    }

    let checksum = ChecksumCapabilities::default();
    match (source, local_addr) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            let Ok(packet) = Icmpv4Packet::new_checked(bytes) else {
                return false;
            };
            matches!(
                Icmpv4Repr::parse(&packet, &checksum),
                Ok(Icmpv4Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                }) if ident == identifier && seq_no == sequence && data == expected_data
            )
        }
        (IpAddr::V6(source), IpAddr::V6(local_addr)) => {
            let Ok(packet) = Icmpv6Packet::new_checked(bytes) else {
                return false;
            };
            matches!(
                Icmpv6Repr::parse(
                    &source,
                    &local_addr,
                    &packet,
                    &checksum,
                ),
                Ok(Icmpv6Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                }) if ident == identifier && seq_no == sequence && data == expected_data
            )
        }
        _ => false,
    }
}

pub(super) async fn echo(
    runtime: &NetRuntime,
    msg: io_channel::Msg,
    sender: &io_channel::Sender,
) -> Result<()> {
    let request = api_net::decode_icmp_echo_request(&msg).map_err(map_native_error)?;
    let Some((device_idx, local_addr)) = runtime.find_route(&request.destination) else {
        return Err(ErrorKind::NetworkUnreachable.into());
    };

    let icmp_len = request.data_len as usize + 8;
    let ip_header_len = if request.destination.is_ipv4() {
        20
    } else {
        40
    };
    let ip_mtu = runtime.inner.borrow().devices[device_idx].ip_mtu();
    if icmp_len + ip_header_len > ip_mtu {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "ICMP echo request exceeds route MTU",
        ));
    }

    let identifier = runtime.inner.borrow_mut().devices[device_idx]
        .get_icmp_identifier()
        .ok_or(ErrorKind::AddrInUse)?;

    let rx_metadata = vec![icmp::PacketMetadata::EMPTY; 4];
    let rx_payload = vec![0; icmp_len * 4];
    let tx_metadata = vec![icmp::PacketMetadata::EMPTY];
    let tx_payload = vec![0; icmp_len];
    let mut socket = icmp::Socket::new(
        icmp::PacketBuffer::new(rx_metadata, rx_payload),
        icmp::PacketBuffer::new(tx_metadata, tx_payload),
    );
    if socket.bind(icmp::Endpoint::Ident(identifier)).is_err() {
        runtime.inner.borrow_mut().devices[device_idx].free_icmp_identifier(identifier);
        return Err(ErrorKind::InvalidInput.into());
    }

    let handle = runtime.inner.borrow_mut().devices[device_idx]
        .sockets
        .add(socket);
    let socket_guard = IcmpSocketGuard {
        runtime: runtime.clone(),
        device_idx,
        handle,
        identifier,
    };

    let payload = make_payload(msg.id, request.sequence, request.data_len as usize);
    let started = moto_rt::time::Instant::now();
    {
        let mut inner = runtime.inner.borrow_mut();
        let device = &mut inner.devices[device_idx];
        let socket = device.sockets.get_mut::<icmp::Socket>(handle);
        let bytes = socket
            .send(icmp_len, IpAddress::from(request.destination))
            .map_err(|err| {
                log::warn!("unable to enqueue ICMP echo request: {err:?}");
                ErrorKind::InvalidInput
            })?;
        emit_request(
            bytes,
            local_addr,
            request.destination,
            identifier,
            request.sequence,
            &payload,
        );
        device.device_runtime_notify.notify_one();
    }

    let receive = core::future::poll_fn(|cx| {
        let mut inner = runtime.inner.borrow_mut();
        let socket = inner.devices[device_idx]
            .sockets
            .get_mut::<icmp::Socket>(handle);

        while socket.can_recv() {
            let Ok((bytes, source)) = socket.recv() else {
                break;
            };
            let source: IpAddr = source.into();
            if is_matching_reply(
                bytes,
                source,
                request.destination,
                local_addr,
                identifier,
                request.sequence,
                &payload,
            ) {
                return Poll::Ready(source);
            }
        }

        socket.register_recv_waker(cx.waker());
        Poll::Pending
    })
    .fuse();
    let timeout = moto_async::sleep(Duration::from_millis(request.timeout_ms as u64)).fuse();
    futures::pin_mut!(receive, timeout);

    let reply = futures::select_biased! {
        source = receive => Some((source, started.elapsed())),
        _ = timeout => None,
    };

    drop(socket_guard);

    match reply {
        Some((source, rtt)) => sender
            .send(api_net::encode_icmp_echo_response(msg, source, rtt))
            .await
            .map_err(map_native_error),
        None => {
            let mut response = msg;
            response.status = map_err_into_native(ErrorKind::TimedOut.into()).into();
            sender.send(response).await.map_err(map_native_error)
        }
    }
}
