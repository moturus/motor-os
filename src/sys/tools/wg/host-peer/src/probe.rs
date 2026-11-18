//! One bounded, independently verified echo request for peer-initiated tests.
use moto_netstack::iface::{SocketHandle, SocketSet};
use moto_netstack::phy::ChecksumCapabilities;
use moto_netstack::socket::icmp;
use moto_netstack::time::{Duration, Instant};
use moto_netstack::wire::{Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpAddress};

const IDENT: u16 = 0x5750;
const PAYLOAD: &[u8] = b"wireguard-host-peer-probe";

pub struct Probe {
    socket: SocketHandle,
    pending: Option<Request>,
}

struct Request {
    local: IpAddress,
    remote: IpAddress,
    sequence: u16,
    deadline: Instant,
}

impl Probe {
    pub fn new(sockets: &mut SocketSet<'static>, id: u64) -> Self {
        let buffer =
            || icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
        let mut socket = icmp::Socket::new(buffer(), buffer());
        socket.bind(icmp::Endpoint::Ident(IDENT)).unwrap();
        Self {
            socket: sockets.add(id, socket),
            pending: None,
        }
    }

    pub fn start(
        &mut self,
        sockets: &mut SocketSet<'static>,
        local: IpAddress,
        remote: IpAddress,
        sequence: u16,
        now: Instant,
    ) -> Result<(), &'static str> {
        if self.pending.is_some() || local.version() != remote.version() {
            return Err("probe pending or incompatible address family");
        }
        let socket = sockets.get_mut::<icmp::Socket>(self.socket);
        let bytes = socket
            .send(8 + PAYLOAD.len(), remote)
            .map_err(|_| "probe queue full")?;
        let checksums = ChecksumCapabilities::default();
        match (local, remote) {
            (IpAddress::Ipv4(_), IpAddress::Ipv4(_)) => {
                Icmpv4Repr::EchoRequest {
                    ident: IDENT,
                    seq_no: sequence,
                    data: PAYLOAD,
                }
                .emit(&mut Icmpv4Packet::new_unchecked(bytes), &checksums);
            }
            (IpAddress::Ipv6(local), IpAddress::Ipv6(remote)) => {
                Icmpv6Repr::EchoRequest {
                    ident: IDENT,
                    seq_no: sequence,
                    data: PAYLOAD,
                }
                .emit(
                    &local,
                    &remote,
                    &mut Icmpv6Packet::new_unchecked(bytes),
                    &checksums,
                );
            }
            _ => unreachable!(),
        }
        self.pending = Some(Request {
            local,
            remote,
            sequence,
            deadline: now + Duration::from_secs(3),
        });
        Ok(())
    }

    /// A completed probe reports success once; expiration reports failure.
    pub fn poll(&mut self, sockets: &mut SocketSet<'static>, now: Instant) -> Option<bool> {
        let request = self.pending.as_ref()?;
        let socket = sockets.get_mut::<icmp::Socket>(self.socket);
        while let Ok((bytes, source)) = socket.recv() {
            if source == request.remote && request.matches(bytes) {
                self.pending = None;
                return Some(true);
            }
        }
        if now >= request.deadline {
            self.pending = None;
            return Some(false);
        }
        None
    }
}

impl Request {
    fn matches(&self, bytes: &[u8]) -> bool {
        let checksums = ChecksumCapabilities::default();
        match (self.local, self.remote) {
            (IpAddress::Ipv4(_), IpAddress::Ipv4(_)) => {
                let Ok(packet) = Icmpv4Packet::new_checked(bytes) else {
                    return false;
                };
                matches!(
                    Icmpv4Repr::parse(&packet, &checksums),
                    Ok(Icmpv4Repr::EchoReply { ident: IDENT, seq_no, data })
                        if seq_no == self.sequence && data == PAYLOAD
                )
            }
            (IpAddress::Ipv6(local), IpAddress::Ipv6(remote)) => {
                let Ok(packet) = Icmpv6Packet::new_checked(bytes) else {
                    return false;
                };
                matches!(
                    Icmpv6Repr::parse(&remote, &local, &packet, &checksums),
                    Ok(Icmpv6Repr::EchoReply { ident: IDENT, seq_no, data })
                        if seq_no == self.sequence && data == PAYLOAD
                )
            }
            _ => false,
        }
    }
}
