//! Local listening sockets; accepted connections share the final SSH peer.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::net::{TcpListener, TcpStream};

use super::args::ConnectionOptions;
use super::forward_args::{ListenAddress, LocalForward, TargetAddress};
use super::socks;
use super::transport::Peer;
use crate::forward::accept::{AcceptSocket, ErrorAction, classify};
use crate::forward::{Tasks, memory_pressure, relay};

#[derive(Default)]
pub struct Listeners {
    sockets: Vec<Listener>,
    forwards: Vec<LocalForward>,
    next: usize,
}

struct Listener {
    socket: AcceptSocket,
    forward: usize,
}

#[derive(Debug)]
pub struct AcceptFailure {
    index: usize,
    error: io::Error,
}

pub struct Accepted {
    pub socket: TcpStream,
    pub originator: SocketAddr,
    pub target: Option<TargetAddress>,
}

impl Accepted {
    pub fn spawn(self, peer: Arc<Peer>, tasks: &Tasks) {
        let Some(job) = tasks.reserve(memory_pressure()) else {
            eprintln!("ssh: cannot admit another forwarded connection");
            return;
        };
        job.spawn(async move {
            let result = async {
                self.socket.set_nodelay(true)?;
                if let Some(target) = &self.target {
                    forward(peer, self.socket, target, self.originator, None).await
                } else {
                    let mut socket = BufReader::with_capacity(1024, self.socket);
                    let request = socks::negotiate(&mut socket).await?;
                    forward(
                        peer,
                        socket,
                        &request.target,
                        self.originator,
                        Some(&request),
                    )
                    .await
                }
            }
            .await;
            if let Err(error) = &result {
                match &self.target {
                    Some(target) => {
                        eprintln!("ssh: forward to {}:{}: {error}", target.host, target.port)
                    }
                    None => eprintln!("ssh: dynamic forward: {error}"),
                }
            }
            result
        });
    }
}

async fn forward<S: AsyncRead + AsyncWrite + Unpin>(
    peer: Arc<Peer>,
    mut socket: S,
    target: &TargetAddress,
    originator: SocketAddr,
    response: Option<&socks::Request>,
) -> io::Result<()> {
    let window = peer.receive_window();
    let opened = peer
        .channel_open_direct_tcpip_with_credit(
            &target.host,
            u32::from(target.port),
            originator.ip().to_string(),
            u32::from(originator.port()),
        )
        .await;
    if let Some(request) = response
        && let Err(error) = request.respond(&mut socket, opened.as_ref().err()).await
    {
        if let Ok((channel, credit)) = opened {
            let (reader, writer) = channel.split();
            drop((socket, credit, reader));
            if let Err(cleanup) = writer.close().await {
                log::debug!("closing failed SOCKS reply: {cleanup}");
            }
        }
        return Err(error);
    }
    let (channel, credit) = opened.map_err(io::Error::other)?;
    // An established relay owns its channel, not the connection.
    drop(peer);
    relay(channel, socket, credit, window, memory_pressure).await
}

impl Listeners {
    pub async fn bind(options: &ConnectionOptions) -> io::Result<Self> {
        let mut listeners = Self {
            forwards: options.local_forwards.clone(),
            ..Self::default()
        };
        for (index, forward) in options.local_forwards.iter().enumerate() {
            match bind(&forward.listen, options.gateway_ports).await {
                Ok(sockets) => {
                    listeners
                        .sockets
                        .extend(sockets.into_iter().map(|socket| Listener {
                            socket: AcceptSocket::new(socket),
                            forward: index,
                        }))
                }
                Err(error) => {
                    let message = format!(
                        "local forward {}:{}: {error}",
                        forward.listen.host.as_deref().unwrap_or("localhost"),
                        forward.listen.port
                    );
                    if options.exit_on_forward_failure {
                        return Err(io::Error::other(message));
                    }
                    eprintln!("Warning: {message}");
                }
            }
        }
        Ok(listeners)
    }

    pub async fn accept(&mut self) -> Result<Accepted, AcceptFailure> {
        std::future::poll_fn(|cx| {
            for offset in 0..self.sockets.len() {
                let index = (self.next + offset) % self.sockets.len();
                let listener = &mut self.sockets[index];
                if let Poll::Ready(result) = listener.socket.poll_accept(cx) {
                    let forward = listener.forward;
                    self.next = (index + 1) % self.sockets.len();
                    return Poll::Ready(
                        result
                            .map(|(socket, originator)| Accepted {
                                socket,
                                originator,
                                target: self.forwards[forward].target.clone(),
                            })
                            .map_err(|error| AcceptFailure { index, error }),
                    );
                }
            }
            Poll::Pending
        })
        .await
    }

    pub fn failed(&mut self, failure: AcceptFailure) {
        let AcceptFailure { index, error } = failure;
        let address = self.sockets[index]
            .socket
            .local_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "unknown socket".into());
        match classify(&error) {
            ErrorAction::Continue => log::debug!("local forward accept {address}: {error}"),
            ErrorAction::Pause => {
                eprintln!("Warning: local forward accept {address}: {error}; pausing this socket");
                self.sockets[index].socket.pause();
            }
            ErrorAction::Retire => {
                eprintln!("Warning: local forward accept {address}: {error}; retiring this socket");
                let retired = self.sockets.remove(index);
                self.next = index % self.sockets.len().max(1);
                if !self
                    .sockets
                    .iter()
                    .any(|socket| socket.forward == retired.forward)
                {
                    let address = &self.forwards[retired.forward].listen;
                    eprintln!(
                        "Warning: local forward {}:{} has no listening sockets",
                        address.host.as_deref().unwrap_or("localhost"),
                        address.port
                    );
                }
            }
        }
    }
}

async fn bind(address: &ListenAddress, gateway_ports: bool) -> io::Result<Vec<TcpListener>> {
    let hosts = match address.host.as_deref() {
        Some("" | "*") => Some(["0.0.0.0", "::"]),
        None if gateway_ports => Some(["0.0.0.0", "::"]),
        None | Some("localhost") => Some(["127.0.0.1", "::1"]),
        Some(_) => None,
    };
    let addresses = if let Some(hosts) = hosts {
        hosts
            .into_iter()
            .map(|ip| SocketAddr::new(ip.parse().unwrap(), address.port))
            .collect()
    } else {
        tokio::net::lookup_host((address.host.as_deref().unwrap(), address.port))
            .await?
            .collect::<Vec<_>>()
    };
    let mut unique = Vec::new();
    for address in addresses {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    let mut sockets = Vec::new();
    let mut port = address.port;
    let mut last_error = None;
    for mut address in unique {
        address.set_port(port);
        match TcpListener::bind(address).await {
            Ok(listener) => {
                port = listener.local_addr()?.port();
                sockets.push(listener);
            }
            Err(error) => {
                // Families may be unavailable or overlap on the host. One
                // successful address is enough, but report every partial failure.
                eprintln!("Warning: cannot bind local forward {address}: {error}");
                last_error = Some(error);
            }
        }
    }
    if sockets.is_empty() {
        Err(last_error.unwrap_or_else(|| io::Error::other("no local bind addresses")))
    } else {
        Ok(sockets)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::forward_args::LocalForward;
    use super::*;

    struct SocksServer(
        tokio::sync::mpsc::UnboundedSender<(
            russh::Channel<russh::server::Msg>,
            russh::server::ChannelOpenHandle,
            String,
        )>,
    );

    impl russh::server::Handler for SocksServer {
        type Error = russh::Error;
        async fn auth_none(&mut self, _: &str) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }
        async fn channel_open_direct_tcpip(
            &mut self,
            channel: russh::Channel<russh::server::Msg>,
            host: &str,
            _: u32,
            _: &str,
            _: u32,
            reply: russh::server::ChannelOpenHandle,
            _: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.0.send((channel, reply, host.into())).unwrap();
            Ok(())
        }
    }

    #[tokio::test]
    async fn dynamic_jobs_wait_for_confirmation_and_preserve_buffered_payload() {
        use super::super::args::{Destination, HostKeyPolicy};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let root = std::env::temp_dir().join(format!("motor-socks-relay-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
            std::fs::create_dir(&root).unwrap();
            let transport = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut options = options(Some("127.0.0.1"), false);
            options.port = transport.local_addr().unwrap().port();
            options.known_hosts = Some(root.join("known_hosts"));
            options.host_key_policy = HostKeyPolicy::AcceptNew;
            options.local_forwards[0].target = None;
            let (opens, mut opened) = tokio::sync::mpsc::unbounded_channel();
            let server = tokio::spawn(async move {
                let config = Arc::new(russh::server::Config {
                    keys: vec![russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519).unwrap()],
                    ..Default::default()
                });
                russh::server::run_stream(config, transport.accept().await.unwrap().0, SocksServer(opens)).await.unwrap().await
            });
            let destination = Destination::parse_with_default("127.0.0.1", "motor").unwrap();
            let mut peer = super::super::transport::connect(&options, &destination).await.unwrap();
            assert!(peer.authenticate_none("motor").await.unwrap().success());
            peer.share_connection();
            let peer = Arc::new(peer);
            let mut listeners = Listeners::bind(&options).await.unwrap();
            let address = listeners.sockets[0].socket.local_addr().unwrap();
            let tasks = Tasks::default();
            for version in [4, 5] {
                let mut application = TcpStream::connect(address).await.unwrap();
                listeners.accept().await.unwrap().spawn(peer.clone(), &tasks);
                let name = b"Unresolved.invalid.";
                let mut wire = if version == 4 { vec![4, 1, 0, 80, 0, 0, 0, 1, 0] }
                    else { vec![5, 1, 0, 5, 1, 0, 3, name.len() as u8] };
                wire.extend(name);
                if version == 4 { wire.push(0); } else { wire.extend([0, 80]); }
                wire.extend(b"payload");
                application.write_all(&wire).await.unwrap();
                application.shutdown().await.unwrap();
                if version == 5 {
                    let mut method = [0; 2];
                    application.read_exact(&mut method).await.unwrap();
                    assert_eq!(method, [5, 0]);
                }
                let (channel, reply, host) = opened.recv().await.unwrap();
                assert_eq!(host, "Unresolved.invalid.");
                tokio::select! {
                    biased;
                    byte = application.read_u8() => panic!("SOCKS replied before SSH confirmation: {byte:?}"),
                    () = std::future::ready(()) => {}
                }
                reply.accept().await;
                let mut channel = channel.into_stream();
                let mut bytes = Vec::new();
                channel.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"payload");
                channel.write_all(b"relayed").await.unwrap();
                channel.shutdown().await.unwrap();
                drop(channel);
                let mut bytes = Vec::new();
                application.read_to_end(&mut bytes).await.unwrap();
                let response: &[u8] = if version == 4 { &[0, 90, 0, 0, 0, 0, 0, 0] }
                    else { &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0] };
                assert_eq!(&bytes[..response.len()], response);
                assert_eq!(&bytes[response.len()..], b"relayed");
                tasks.wait_idle().await;
            }
            assert_eq!(Arc::strong_count(&peer), 1);
            Arc::try_unwrap(peer).ok().unwrap().close().await.unwrap();
            assert!(matches!(server.await.unwrap(), Ok(()) | Err(russh::Error::Disconnect)));
            std::fs::remove_dir_all(root).unwrap();
        }).await.expect("dynamic relay stalled");
    }

    fn options(bind: Option<&str>, gateway_ports: bool) -> ConnectionOptions {
        let mut options = ConnectionOptions::default();
        options.gateway_ports = gateway_ports;
        options.local_forwards = vec![LocalForward {
            listen: ListenAddress {
                host: bind.map(str::to_owned),
                port: 0,
            },
            target: Some(TargetAddress {
                host: "unresolved.invalid".into(),
                port: 80,
            }),
        }];
        options
    }

    #[tokio::test]
    async fn defaults_bind_both_loopbacks_and_explicit_bind_overrides_gateway_ports() {
        let listeners = Listeners::bind(&options(None, false)).await.unwrap();
        let addresses: Vec<_> = listeners
            .sockets
            .iter()
            .map(|s| s.socket.local_addr().unwrap())
            .collect();
        assert_eq!(addresses.len(), 2);
        assert!(addresses.iter().all(|a| a.ip().is_loopback()));
        assert_eq!(addresses[0].port(), addresses[1].port());
        let mut listeners = Listeners::bind(&options(Some("127.0.0.1"), true))
            .await
            .unwrap();
        assert_eq!(listeners.sockets.len(), 1);
        let address = listeners.sockets[0].socket.local_addr().unwrap();
        assert!(
            TcpStream::connect(("127.0.0.2", address.port()))
                .await
                .is_err()
        );
        let client = TcpStream::connect(address).await.unwrap();
        let accepted = listeners.accept().await.unwrap();
        assert_eq!(accepted.originator, client.local_addr().unwrap());
        assert_eq!(accepted.target.unwrap().host, "unresolved.invalid");
    }

    #[tokio::test]
    async fn wildcard_defaults_and_explicit_wildcards_accept_other_local_addresses() {
        for (host, gateway) in [(None, true), (Some("*"), false), (Some(""), false)] {
            let mut listeners = Listeners::bind(&options(host, gateway)).await.unwrap();
            // Linux's second wildcard bind overlaps IPv4; Motor binds both families.
            #[cfg(target_os = "linux")]
            assert_eq!(listeners.sockets.len(), 1);
            let address = listeners.sockets[0].socket.local_addr().unwrap();
            assert!(address.ip().is_unspecified());
            let client = TcpStream::connect(("127.0.0.2", address.port()))
                .await
                .unwrap();
            assert_eq!(
                listeners.accept().await.unwrap().originator,
                client.local_addr().unwrap()
            );
        }
    }

    #[tokio::test]
    async fn setup_failure_keeps_other_listeners_or_releases_them_when_exit_is_required() {
        let blocked = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for exit in [false, true] {
            // Keep the port out of the ephemeral allocator across setup.
            // Reuse lets the forwarding code bind this reserved address.
            let available = tokio::net::TcpSocket::new_v4().unwrap();
            available.set_reuseaddr(true).unwrap();
            available.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let address = available.local_addr().unwrap();
            let mut options = options(Some("127.0.0.1"), false);
            options.exit_on_forward_failure = exit;
            options.local_forwards[0].listen.port = address.port();
            let mut refused = options.local_forwards[0].clone();
            refused.listen.port = blocked.local_addr().unwrap().port();
            options.local_forwards.push(refused);
            let result = Listeners::bind(&options).await;
            if exit {
                assert!(result.is_err());
                assert!(TcpStream::connect(address).await.is_err());
            } else {
                let mut listeners = result.unwrap();
                assert_eq!(listeners.sockets.len(), 1);
                let client = TcpStream::connect(address).await.unwrap();
                assert_eq!(
                    listeners.accept().await.unwrap().originator,
                    client.local_addr().unwrap()
                );
            }
            drop(available);
        }
    }

    #[tokio::test]
    async fn accept_rotates_among_ready_listeners() {
        let mut options = options(Some("127.0.0.1"), false);
        let mut other = options.local_forwards[0].clone();
        other.target.as_mut().unwrap().host = "second.invalid".into();
        options.local_forwards.push(other);
        let mut listeners = Listeners::bind(&options).await.unwrap();
        let mut clients = Vec::new();
        for index in [0, 0, 1] {
            clients.push(
                TcpStream::connect(listeners.sockets[index].socket.local_addr().unwrap())
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            listeners.accept().await.unwrap().target.unwrap().host,
            "unresolved.invalid"
        );
        assert_eq!(
            listeners.accept().await.unwrap().target.unwrap().host,
            "second.invalid"
        );
        assert_eq!(
            listeners.accept().await.unwrap().target.unwrap().host,
            "unresolved.invalid"
        );
    }
}
