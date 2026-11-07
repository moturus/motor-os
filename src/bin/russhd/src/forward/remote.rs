//! Connection-owned listening sockets for remote TCP forwards.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Default)]
pub struct Listeners {
    groups: HashMap<(String, u16), Group>,
}

struct Group {
    stop: watch::Sender<()>,
    running: Vec<JoinHandle<()>>,
}

impl Listeners {
    pub async fn register(
        &mut self,
        address: &str,
        port: u32,
        gateway_ports: bool,
        handle: russh::server::Handle,
        tasks: Arc<super::Tasks>,
        window: usize,
    ) -> io::Result<u16> {
        let port = validate_request(address, port)?;
        if self.groups.contains_key(&(address.to_owned(), port)) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "remote forward already registered",
            ));
        }
        let bound = if gateway_ports {
            BoundListeners::wildcard(port).await?
        } else {
            BoundListeners::loopback(address, u32::from(port)).await?
        };
        let port = bound.port;
        let key = (address.to_owned(), port);
        if self.groups.contains_key(&key) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "allocated remote forward already registered",
            ));
        }
        let (stop, stopped) = watch::channel(());
        let running = bound
            .sockets
            .into_iter()
            .map(|listener| {
                tokio::spawn(accept(
                    listener,
                    stopped.clone(),
                    address.to_owned(),
                    port,
                    handle.clone(),
                    tasks.clone(),
                    window,
                ))
            })
            .collect();
        self.groups.insert(key, Group { stop, running });
        Ok(port)
    }

    /// No acknowledgement until every accept task has released its socket.
    /// Relay jobs have their own connection scope and keep running.
    pub async fn cancel(&mut self, address: &str, port: u32) -> io::Result<bool> {
        let port = validate_request(address, port)?;
        let Some(group) = self.groups.remove(&(address.to_owned(), port)) else {
            return Ok(false);
        };
        drop(group.stop);
        let mut error = None;
        for task in group.running {
            if let Err(join_error) = task.await {
                log::error!("remote accept task failed: {join_error}");
                error = Some(io::Error::other(join_error));
            }
        }
        error.map_or(Ok(true), Err)
    }
}

async fn accept(
    listener: TcpListener,
    mut stopped: watch::Receiver<()>,
    address: String,
    port: u16,
    handle: russh::server::Handle,
    tasks: Arc<super::Tasks>,
    window: usize,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = stopped.changed() => return,
            result = listener.accept() => result,
        };
        let (socket, originator) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                log::warn!("remote forward accept failed: {error}");
                return;
            }
        };
        let Some(job) = tasks.reserve(super::memory_pressure()) else {
            continue;
        };
        let handle = handle.clone();
        let address = address.clone();
        job.spawn(async move {
            socket.set_nodelay(true)?;
            let (channel, credit) = handle
                .channel_open_forwarded_tcpip_with_credit(
                    address,
                    u32::from(port),
                    originator.ip().to_string(),
                    u32::from(originator.port()),
                )
                .await
                .map_err(io::Error::other)?;
            drop(handle);
            super::relay(channel, socket, credit, window, super::memory_pressure).await
        });
    }
}

pub struct BoundListeners {
    pub sockets: Vec<TcpListener>,
    pub port: u16,
}

fn validate_request(address: &str, port: u32) -> io::Result<u16> {
    if !address.is_empty() && address != "*" && super::validate_target(address, 1).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid remote bind address",
        ));
    }
    u16::try_from(port)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid remote bind port"))
}

impl BoundListeners {
    pub async fn wildcard(port: u16) -> io::Result<Self> {
        if port != 0 {
            return Self::bind(
                vec![
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                ],
                port,
            )
            .await;
        }
        // Motor OS requires an explicit port for wildcard listeners. Select it
        // here on every platform, so the same bounded search is tested on hosts.
        let listener = ephemeral_v4(rand::random_range(49152..=u16::MAX)).await?;
        let port = listener.local_addr()?.port();
        let mut sockets = vec![listener];
        match TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)).await {
            Ok(listener) => sockets.push(listener),
            Err(error) => log::warn!("cannot bind remote forward [::]:{port}: {error}"),
        }
        Ok(Self { sockets, port })
    }

    /// GatewayPorts no: only an explicit loopback address selects one family.
    /// Other valid requests bind both loopback families, without resolving names.
    pub async fn loopback(address: &str, port: u32) -> io::Result<Self> {
        let port = validate_request(address, port)?;
        let ipv4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let addresses = match address {
            "127.0.0.1" => vec![ipv4],
            "::1" => vec![ipv6],
            _ => vec![ipv4, ipv6],
        };
        Self::bind(addresses, port).await
    }

    async fn bind(addresses: Vec<IpAddr>, mut port: u16) -> io::Result<Self> {
        let mut sockets = Vec::new();
        let mut last_error = None;
        for ip in addresses {
            let address = SocketAddr::new(ip, port);
            match TcpListener::bind(address).await {
                Ok(listener) => {
                    port = listener.local_addr()?.port();
                    sockets.push(listener);
                }
                Err(error) => {
                    // A family may be unavailable or occupied. Keep successful
                    // listeners, but make every partial failure visible.
                    log::warn!("cannot bind remote forward {address}: {error}");
                    last_error = Some(error);
                }
            }
        }
        if sockets.is_empty() {
            Err(last_error.unwrap_or_else(|| io::Error::other("no remote bind addresses")))
        } else {
            Ok(Self { sockets, port })
        }
    }
}

async fn ephemeral_v4(start: u16) -> io::Result<TcpListener> {
    const FIRST: u32 = 49152;
    const COUNT: u32 = 16384;
    for offset in 0..64 {
        let port = (FIRST + (u32::from(start) - FIRST + offset) % COUNT) as u16;
        match TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await {
            Ok(listener) => return Ok(listener),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::AlreadyExists
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "all 64 wildcard port candidates are occupied",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wildcard_zero_uses_a_selected_port_shared_by_every_family() {
        let bound = BoundListeners::wildcard(0).await.unwrap();
        assert!(bound.port >= 49152);
        assert!(!bound.sockets.is_empty());
        for socket in &bound.sockets {
            let actual = socket.local_addr().unwrap();
            assert!(actual.ip().is_unspecified());
            assert_eq!(actual.port(), bound.port);
        }
    }

    #[tokio::test]
    async fn wildcard_port_search_skips_a_live_listener_and_wraps_the_range() {
        let first = ephemeral_v4(u16::MAX).await.unwrap();
        let first_port = first.local_addr().unwrap().port();
        let second = ephemeral_v4(first_port).await.unwrap();
        let second_port = second.local_addr().unwrap().port();
        assert!(first_port >= 49152);
        assert!(second_port >= 49152);
        assert_ne!(first_port, second_port);
        // If 65535 was free, the second search wraps past our live listener;
        // otherwise the first search already wrapped past its existing owner.
        assert!(first_port != u16::MAX || second_port < first_port);
    }

    #[test]
    fn remote_requests_bound_text_and_ports_without_resolving_names() {
        for address in [
            "",
            "*",
            "localhost",
            "192.0.2.4",
            "2001:db8::4",
            "not-a-real-host.invalid",
        ] {
            assert_eq!(validate_request(address, 0).unwrap(), 0);
            assert_eq!(validate_request(address, 65535).unwrap(), 65535);
        }
        for address in [
            "has space",
            "bad/host",
            "[::1]",
            "a%zone",
            "é",
            "a\0b",
            &"a".repeat(256),
        ] {
            assert!(validate_request(address, 22).is_err());
        }
        assert!(validate_request("localhost", 65536).is_err());
        assert!(validate_request("localhost", u32::MAX).is_err());
    }

    #[tokio::test]
    async fn explicit_loopback_chooses_one_family() {
        for address in ["127.0.0.1", "::1"] {
            let bound = BoundListeners::loopback(address, 0).await.unwrap();
            assert_ne!(bound.port, 0);
            assert_eq!(bound.sockets.len(), 1);
            assert_eq!(
                bound.sockets[0].local_addr().unwrap(),
                SocketAddr::new(address.parse().unwrap(), bound.port)
            );
        }
    }

    #[tokio::test]
    async fn other_requests_share_one_port_on_both_loopback_families() {
        for address in ["", "*", "localhost", "192.0.2.4", "not-a-real-host.invalid"] {
            let bound = BoundListeners::loopback(address, 0).await.unwrap();
            assert_eq!(bound.sockets.len(), 2);
            for socket in &bound.sockets {
                let actual = socket.local_addr().unwrap();
                assert!(actual.ip().is_loopback());
                assert_eq!(actual.port(), bound.port);
            }
        }
    }

    #[tokio::test]
    async fn partial_family_failure_preserves_the_other_listener() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let bound = BoundListeners::loopback("localhost", u32::from(port))
            .await
            .unwrap();
        assert_eq!(bound.port, port);
        assert_eq!(bound.sockets.len(), 1);
        assert_eq!(
            bound.sockets[0].local_addr().unwrap().ip(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }

    #[tokio::test]
    async fn a_conflict_leaves_the_existing_listeners_bound() {
        let original = BoundListeners::loopback("localhost", 0).await.unwrap();
        assert!(
            BoundListeners::loopback("*", u32::from(original.port))
                .await
                .is_err()
        );
        for listener in &original.sockets {
            let address = listener.local_addr().unwrap();
            let connected = tokio::net::TcpStream::connect(address).await.unwrap();
            let (_, origin) = listener.accept().await.unwrap();
            assert_eq!(origin, connected.local_addr().unwrap());
        }
    }
}
