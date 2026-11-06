//! Local listening sockets; accepted connections share the final SSH peer.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use tokio::net::{TcpListener, TcpStream};

use super::args::ConnectionOptions;
use super::forward_args::{ListenAddress, TargetAddress};
use super::transport::Peer;
use crate::forward::{Tasks, memory_pressure, relay};

#[derive(Default)]
pub struct Listeners {
    sockets: Vec<(TcpListener, TargetAddress)>,
    next: usize,
}

pub struct Accepted {
    pub socket: TcpStream,
    pub originator: SocketAddr,
    pub target: TargetAddress,
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
                let window = peer.receive_window();
                let (channel, credit) = peer
                    .channel_open_direct_tcpip_with_credit(
                        &self.target.host,
                        u32::from(self.target.port),
                        self.originator.ip().to_string(),
                        u32::from(self.originator.port()),
                    )
                    .await
                    .map_err(io::Error::other)?;
                // An established relay owns its channel, not the connection.
                drop(peer);
                relay(channel, self.socket, credit, window, memory_pressure).await
            }
            .await;
            if let Err(error) = &result {
                eprintln!(
                    "ssh: forward to {}:{}: {error}",
                    self.target.host, self.target.port
                );
            }
            result
        });
    }
}

impl Listeners {
    pub async fn bind(options: &ConnectionOptions) -> io::Result<Self> {
        let mut listeners = Self::default();
        for forward in &options.local_forwards {
            match bind(&forward.listen, options.gateway_ports).await {
                Ok(sockets) => listeners.sockets.extend(
                    sockets
                        .into_iter()
                        .map(|socket| (socket, forward.target.clone())),
                ),
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

    pub async fn accept(&mut self) -> io::Result<Accepted> {
        std::future::poll_fn(|cx| {
            for offset in 0..self.sockets.len() {
                let index = (self.next + offset) % self.sockets.len();
                let (listener, target) = &self.sockets[index];
                if let Poll::Ready(result) = listener.poll_accept(cx) {
                    self.next = (index + 1) % self.sockets.len();
                    return Poll::Ready(result.map(|(socket, originator)| Accepted {
                        socket,
                        originator,
                        target: target.clone(),
                    }));
                }
            }
            Poll::Pending
        })
        .await
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

    fn options(bind: Option<&str>, gateway_ports: bool) -> ConnectionOptions {
        let mut options = ConnectionOptions::default();
        options.gateway_ports = gateway_ports;
        options.local_forwards = vec![LocalForward {
            listen: ListenAddress {
                host: bind.map(str::to_owned),
                port: 0,
            },
            target: TargetAddress {
                host: "unresolved.invalid".into(),
                port: 80,
            },
        }];
        options
    }

    #[tokio::test]
    async fn defaults_bind_both_loopbacks_and_explicit_bind_overrides_gateway_ports() {
        let listeners = Listeners::bind(&options(None, false)).await.unwrap();
        let addresses: Vec<_> = listeners
            .sockets
            .iter()
            .map(|(s, _)| s.local_addr().unwrap())
            .collect();
        assert_eq!(addresses.len(), 2);
        assert!(addresses.iter().all(|a| a.ip().is_loopback()));
        assert_eq!(addresses[0].port(), addresses[1].port());
        let mut listeners = Listeners::bind(&options(Some("127.0.0.1"), true))
            .await
            .unwrap();
        assert_eq!(listeners.sockets.len(), 1);
        let address = listeners.sockets[0].0.local_addr().unwrap();
        assert!(
            TcpStream::connect(("127.0.0.2", address.port()))
                .await
                .is_err()
        );
        let client = TcpStream::connect(address).await.unwrap();
        let accepted = listeners.accept().await.unwrap();
        assert_eq!(accepted.originator, client.local_addr().unwrap());
        assert_eq!(accepted.target.host, "unresolved.invalid");
    }

    #[tokio::test]
    async fn wildcard_defaults_and_explicit_wildcards_accept_other_local_addresses() {
        for (host, gateway) in [(None, true), (Some("*"), false), (Some(""), false)] {
            let mut listeners = Listeners::bind(&options(host, gateway)).await.unwrap();
            // Linux's second wildcard bind overlaps IPv4; Motor binds both families.
            #[cfg(target_os = "linux")]
            assert_eq!(listeners.sockets.len(), 1);
            let address = listeners.sockets[0].0.local_addr().unwrap();
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
            let available = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = available.local_addr().unwrap();
            let mut options = options(Some("127.0.0.1"), false);
            options.exit_on_forward_failure = exit;
            options.local_forwards[0].listen.port = address.port();
            let mut refused = options.local_forwards[0].clone();
            refused.listen.port = blocked.local_addr().unwrap().port();
            options.local_forwards.push(refused);
            drop(available);
            let result = Listeners::bind(&options).await;
            if exit {
                assert!(result.is_err());
                assert!(TcpStream::connect(address).await.is_err());
            } else {
                let mut listeners = result.unwrap();
                let client = TcpStream::connect(address).await.unwrap();
                assert_eq!(
                    listeners.accept().await.unwrap().originator,
                    client.local_addr().unwrap()
                );
            }
        }
    }

    #[tokio::test]
    async fn accept_rotates_among_ready_listeners() {
        let mut options = options(Some("127.0.0.1"), false);
        let mut other = options.local_forwards[0].clone();
        other.target.host = "second.invalid".into();
        options.local_forwards.push(other);
        let mut listeners = Listeners::bind(&options).await.unwrap();
        let mut clients = Vec::new();
        for index in [0, 0, 1] {
            clients.push(
                TcpStream::connect(listeners.sockets[index].0.local_addr().unwrap())
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            listeners.accept().await.unwrap().target.host,
            "unresolved.invalid"
        );
        assert_eq!(
            listeners.accept().await.unwrap().target.host,
            "second.invalid"
        );
        assert_eq!(
            listeners.accept().await.unwrap().target.host,
            "unresolved.invalid"
        );
    }
}
