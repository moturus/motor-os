use super::*;
use crate::forward::accept::test_support::{inject, reserve_loopback_port};
use russh::{Channel, client, server};
use std::future::{Future, poll_fn};
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, advance, timeout};

type Opened = (Channel<client::Msg>, client::ChannelOpenHandle);

struct Incoming(mpsc::UnboundedSender<Opened>);
impl client::Handler for Incoming {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: client::ChannelOpenHandle,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send((channel, reply)).unwrap();
        Ok(())
    }
}

struct Server;
impl server::Handler for Server {
    type Error = russh::Error;
    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
}

struct Pair {
    client: client::Handle<Incoming>,
    server: server::RunningSession<Server>,
    opened: mpsc::UnboundedReceiver<Opened>,
    listeners: Listeners,
    tasks: Arc<crate::forward::Tasks>,
}

impl Pair {
    async fn new() -> Self {
        let (client_wire, server_wire) = tokio::io::duplex(64 * 1024);
        let starting = tokio::spawn(server::run_stream(
            Arc::new(server::Config {
                keys: vec![
                    russh::keys::PrivateKey::random(
                        &mut rand::rng(),
                        russh::keys::ssh_key::Algorithm::Ed25519,
                    )
                    .unwrap(),
                ],
                inactivity_timeout: None,
                ..Default::default()
            }),
            server_wire,
            Server,
        ));
        let (opened_tx, opened) = mpsc::unbounded_channel();
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            client_wire,
            Incoming(opened_tx),
        )
        .await
        .unwrap();
        let server = starting.await.unwrap().unwrap();
        assert!(client.authenticate_none("user").await.unwrap().success());
        Self {
            client,
            server,
            opened,
            listeners: Listeners::default(),
            tasks: Arc::new(crate::forward::Tasks::default()),
        }
    }

    async fn register(&mut self, address: &str, port: u32) -> u16 {
        self.listeners
            .register(
                address,
                port,
                false,
                self.server.handle(),
                self.tasks.clone(),
                8192,
            )
            .await
            .unwrap()
    }

    fn errors(&self, address: &str, port: u16, index: usize) -> mpsc::UnboundedSender<io::Error> {
        self.listeners
            .groups
            .lock()
            .unwrap()
            .get(&(address.into(), port))
            .unwrap()
            .accept_errors[index]
            .clone()
    }

    async fn finish(self) {
        drop(self.listeners);
        self.tasks.cancel();
        self.tasks.wait_idle().await;
        self.client
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        assert!(matches!(
            self.client.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
        assert!(matches!(
            self.server.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
    }
}

async fn exchange(mut socket: TcpStream, (channel, reply): Opened) {
    reply.accept().await;
    let mut channel = channel.into_stream();
    socket.write_all(b"request").await.unwrap();
    socket.shutdown().await.unwrap();
    let mut request = Vec::new();
    channel.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"request");
    channel.write_all(b"response").await.unwrap();
    channel.shutdown().await.unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response");
}

#[tokio::test]
async fn remote_connection_errors_preserve_the_listener_and_subsequent_traffic() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new().await;
        let port = pair.register("127.0.0.1", 0).await;
        let errors = pair.errors("127.0.0.1", port, 0);
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::Interrupted,
        ] {
            inject(&errors, kind).await.unwrap();
            pair.client.send_ping().await.unwrap();
        }
        let socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        exchange(socket, pair.opened.recv().await.unwrap()).await;
        pair.tasks.wait_idle().await;
        assert!(
            pair.listeners
                .cancel("127.0.0.1", port.into())
                .await
                .unwrap()
        );
        pair.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_exhausted_remote_socket_does_not_pause_the_other_family() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new().await;
        let port = pair.register("localhost", 0).await;
        let start = Instant::now();
        inject(
            &pair.errors("localhost", port, 0),
            io::ErrorKind::OutOfMemory,
        )
        .await
        .unwrap();
        let paused = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let healthy = TcpStream::connect((Ipv6Addr::LOCALHOST, port))
            .await
            .unwrap();
        let opened = pair.opened.recv().await.unwrap();
        assert_eq!(Instant::now(), start);
        assert!(
            poll_fn(|cx| Poll::Ready(Box::pin(pair.opened.recv()).as_mut().poll(cx)))
                .await
                .is_pending()
        );
        advance(Duration::from_millis(99)).await;
        assert!(
            poll_fn(|cx| Poll::Ready(Box::pin(pair.opened.recv()).as_mut().poll(cx)))
                .await
                .is_pending()
        );
        advance(Duration::from_millis(1)).await;
        let resumed = pair.opened.recv().await.unwrap();
        assert_eq!(Instant::now() - start, crate::forward::ACCEPT_PAUSE);
        tokio::join!(exchange(healthy, opened), exchange(paused, resumed));
        pair.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn total_remote_listener_loss_releases_its_key_and_preserves_admitted_relays() {
    let _process_and_rebind = crate::forward::accept::test_support::PROCESS_AND_REBIND
        .lock()
        .await;
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new().await;
        let (port, _reservations) = reserve_loopback_port();
        assert_eq!(pair.register("localhost", port.into()).await, port);
        let first = pair.errors("localhost", port, 0);
        let last = pair.errors("localhost", port, 1);
        inject(&first, io::ErrorKind::NotConnected).await.unwrap();
        assert_eq!(
            pair.listeners
                .groups
                .lock()
                .unwrap()
                .get(&("localhost".into(), port))
                .unwrap()
                .remaining,
            1
        );
        let released = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        drop(released);
        let socket = TcpStream::connect((Ipv6Addr::LOCALHOST, port))
            .await
            .unwrap();
        let admitted = pair.opened.recv().await.unwrap();
        inject(&last, io::ErrorKind::Other).await.unwrap();
        assert!(pair.listeners.groups.lock().unwrap().is_empty());
        assert!(
            !pair
                .listeners
                .cancel("localhost", port.into())
                .await
                .unwrap()
        );
        assert_eq!(pair.register("localhost", port.into()).await, port);
        assert!(
            pair.listeners
                .cancel("localhost", port.into())
                .await
                .unwrap()
        );
        exchange(socket, admitted).await;
        pair.tasks.wait_idle().await;
        pair.client.send_ping().await.unwrap();
        pair.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn remote_cancellation_during_a_pause_or_queued_failure_releases_every_socket() {
    let _process_and_rebind = crate::forward::accept::test_support::PROCESS_AND_REBIND
        .lock()
        .await;
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new().await;
        for processed in [true, false] {
            let (port, _reservations) = reserve_loopback_port();
            assert_eq!(pair.register("localhost", port.into()).await, port);
            let first = pair.errors("localhost", port, 0);
            let last = pair.errors("localhost", port, 1);
            let start = Instant::now();
            if processed {
                inject(&first, io::ErrorKind::OutOfMemory).await.unwrap();
            } else {
                first.send(io::ErrorKind::NotConnected.into()).unwrap();
            }
            assert!(
                pair.listeners
                    .cancel("localhost", port.into())
                    .await
                    .unwrap()
            );
            assert_eq!(Instant::now(), start);
            assert!(first.is_closed() && last.is_closed());
            let _v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            let _v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port))
                .await
                .unwrap();
        }
        pair.finish().await;
    })
    .await
    .unwrap();
}
