//! The same inner TCP/IP services run behind either host-peer transport.
use crate::{bench, link::Link};
use moto_netstack::iface::{Config, Interface, Route, SocketHandle, SocketSet};
use moto_netstack::socket::{tcp, udp};
use moto_netstack::time::{Duration, Instant};
use moto_netstack::wire::{HardwareAddress, IpAddress, IpCidr};

#[cfg(test)]
mod tests;

pub const TCP_ECHO_PORT: u16 = 7000;
pub const UDP_ECHO_PORT: u16 = 7001;
pub const BENCH_PORT: u16 = 40000;
const TCP_BUFFER: usize = 131_072;
const LISTENERS: usize = 16;

struct Service {
    handle: SocketHandle,
    port: u16,
    bench: bench::Session,
    started: Option<Instant>,
}

pub struct Stack {
    interface: Interface,
    sockets: SocketSet<'static>,
    link: Link,
    services: Vec<Service>,
    udp: SocketHandle,
    scratch: Vec<u8>,
    probe: crate::probe::Probe,
}

impl Stack {
    pub fn new(addresses: &[IpCidr], now: Instant) -> Result<Self, getrandom::Error> {
        assert!(!addresses.is_empty());
        let mut config = Config::new(HardwareAddress::Ip);
        let mut seed = [0; 8];
        getrandom::getrandom(&mut seed)?;
        config.random_seed = u64::from_ne_bytes(seed);
        getrandom::getrandom(&mut config.ipv4_fragment_id_key)?;
        getrandom::getrandom(&mut config.tcp_isn_key)?;
        getrandom::getrandom(&mut config.tcp_cookie_key)?;
        config.auto_icmp_echo_reply = true;
        let mut link = Link::default();
        let mut interface = Interface::new(config, &mut link, now);
        interface.update_ip_addrs(|list| list.extend_from_slice(addresses));
        interface.routes_mut().update(|routes| {
            for prefix in ["0.0.0.0/0", "::/0"] {
                let prefix: IpCidr = prefix.parse().unwrap();
                if addresses
                    .iter()
                    .any(|a| a.address().version() == prefix.address().version())
                {
                    routes.push(Route::new_interface(prefix));
                }
            }
        });
        let mut sockets = SocketSet::new();
        let mut services = Vec::with_capacity(2 * LISTENERS);
        for port in [TCP_ECHO_PORT, BENCH_PORT] {
            for _ in 0..LISTENERS {
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                    tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                );
                socket.set_nagle_enabled(false);
                socket.set_timeout(Some(Duration::from_secs(30)));
                let handle = sockets.add(services.len() as u64 + 1, socket);
                sockets.tcp_listen(handle, port).unwrap();
                services.push(Service {
                    handle,
                    port,
                    bench: bench::Session::default(),
                    started: None,
                });
            }
        }
        let buffer =
            || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65_536]);
        let udp = sockets.add(
            services.len() as u64 + 1,
            udp::Socket::new(buffer(), buffer()),
        );
        sockets.udp_bind(udp, UDP_ECHO_PORT).unwrap();
        let probe = crate::probe::Probe::new(&mut sockets, services.len() as u64 + 2);
        Ok(Self {
            interface,
            sockets,
            link,
            services,
            udp,
            scratch: vec![0; 65_536],
            probe,
        })
    }

    pub fn receive(&mut self, packet: &[u8]) -> bool {
        self.link.receive_packet(packet)
    }

    pub fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.link.take_packet()
    }

    pub fn poll(&mut self, now: Instant) {
        self.interface.poll(now, &mut self.link, &mut self.sockets);
        self.service_udp();
        for service in &mut self.services {
            let socket = self.sockets.get_mut::<tcp::Socket>(service.handle);
            if socket.state() == tcp::State::Closed {
                service.bench = bench::Session::default();
                service.started = None;
                self.sockets
                    .tcp_listen(service.handle, service.port)
                    .unwrap();
                continue;
            }
            if socket.is_listening() {
                continue;
            }
            let started = *service.started.get_or_insert(now);
            for _ in 0..32 {
                let mut progress = false;
                if service.port == BENCH_PORT {
                    if socket.can_recv() {
                        progress |= socket
                            .recv(|bytes| {
                                let count = service.bench.receive(bytes);
                                (count, count != 0)
                            })
                            .unwrap();
                    }
                    if socket.can_send() {
                        let output = service.bench.output(65_536);
                        if !output.is_empty() {
                            let count = socket.send_slice(output).unwrap();
                            service.bench.sent(count);
                            progress |= count != 0;
                        }
                    }
                } else if socket.can_recv() && socket.can_send() {
                    let capacity =
                        (socket.send_capacity() - socket.send_queue()).min(self.scratch.len());
                    let count = socket.recv_slice(&mut self.scratch[..capacity]).unwrap();
                    assert_eq!(socket.send_slice(&self.scratch[..count]).unwrap(), count);
                    progress = count != 0;
                }
                if !progress {
                    break;
                }
            }
            if service.bench.failed()
                || (service.port == BENCH_PORT
                    && service.bench.handshaking()
                    && now - started >= Duration::from_secs(5))
            {
                self.sockets.tcp_abort(service.handle);
            } else if socket.state() == tcp::State::CloseWait && !socket.can_recv() {
                self.sockets.tcp_close(service.handle);
            }
        }
        self.interface.poll(now, &mut self.link, &mut self.sockets);
    }

    fn service_udp(&mut self) {
        let socket = self.sockets.get_mut::<udp::Socket>(self.udp);
        for _ in 0..32 {
            if !socket.can_recv() || !socket.can_send() {
                break;
            }
            let (len, endpoint) = socket.recv_slice(&mut self.scratch).unwrap();
            // Preserve the destination address as the source of the reply.
            // Dropping on a full datagram buffer is normal UDP backpressure.
            match socket.send_slice(&self.scratch[..len], endpoint) {
                Ok(()) | Err(udp::SendError::BufferFull) => {}
                Err(error) => panic!("invalid UDP echo endpoint: {error}"),
            }
        }
    }

    pub fn poll_delay(&mut self, now: Instant) -> Duration {
        self.interface
            .poll_delay(now, &self.sockets)
            .unwrap_or(Duration::from_millis(250))
            .min(Duration::from_millis(250))
    }

    pub fn start_ping(
        &mut self,
        remote: IpAddress,
        sequence: u16,
        now: Instant,
    ) -> Result<(), &'static str> {
        let local = self
            .interface
            .ip_addrs()
            .iter()
            .map(IpCidr::address)
            .find(|local| local.version() == remote.version())
            .ok_or("no local address for probe")?;
        self.probe
            .start(&mut self.sockets, local, remote, sequence, now)
    }

    pub fn poll_ping(&mut self, now: Instant) -> Option<bool> {
        self.probe.poll(&mut self.sockets, now)
    }
}
