use super::*;
use std::sync::Arc;

use russh::{client, server};
use tokio::io::{AsyncReadExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, timeout};

const WINDOW: u32 = 64 * 1024;

struct Server {
    tasks: Tasks,
    opened: mpsc::UnboundedSender<Opened>,
}

struct Opened {
    channel: Channel<server::Msg>,
    credit: ReceiveCredit,
    reservation: Reservation,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let credit = session.receive_credit(channel.id()).unwrap();
        let reservation = self.tasks.reserve(false).unwrap();
        assert!(
            self.opened
                .send(Opened {
                    channel,
                    credit,
                    reservation
                })
                .is_ok()
        );
        reply.accept().await;
        Ok(())
    }
}

struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Fixture {
    client: client::Handle<Client>,
    server: tokio::task::JoinHandle<Result<(), russh::Error>>,
    opened: mpsc::UnboundedReceiver<Opened>,
    socket: DuplexStream,
    target: DuplexStream,
}

impl Fixture {
    async fn connect() -> Self {
        let (socket, peer) = tokio::io::duplex(32 * 1024);
        let (target, target_peer) = tokio::io::duplex(1024);
        let (opened, requests) = mpsc::unbounded_channel();
        let config = Arc::new(server::Config {
            keys: vec![
                russh::keys::PrivateKey::random(
                    &mut rand::rng(),
                    russh::keys::ssh_key::Algorithm::Ed25519,
                )
                .unwrap(),
            ],
            window_size: WINDOW,
            maximum_packet_size: 4096,
            channel_buffer_size: 4,
            inactivity_timeout: None,
            ..Default::default()
        });
        let handler = Server {
            tasks: Tasks::default(),
            opened,
        };
        let server =
            tokio::spawn(async move { server::run_stream(config, socket, handler).await?.await });
        let mut client = client::connect_stream(Arc::new(client::Config::default()), peer, Client)
            .await
            .unwrap();
        assert!(client.authenticate_none("user").await.unwrap().success());
        Self {
            client,
            server,
            opened: requests,
            socket: target,
            target: target_peer,
        }
    }
}

#[tokio::test]
async fn half_close_drains_both_directions_and_returns_receive_credit() {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::connect().await;
        let channel = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        let socket = fixture.socket;
        let (done, finished) = oneshot::channel();
        opened.reservation.spawn(async move {
            let result = relay(
                opened.channel,
                socket,
                opened.credit,
                WINDOW as usize,
                || false,
            )
            .await;
            let _ = done.send(result);
            Ok(())
        });
        let mut stream = channel.into_stream();
        let mut target = fixture.target;
        let target_job = tokio::spawn(async move {
            let mut input = Vec::new();
            target.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, vec![3; 2 * WINDOW as usize]);
            target
                .write_all(&vec![7; 2 * WINDOW as usize])
                .await
                .unwrap();
            target.shutdown().await.unwrap();
        });
        stream
            .write_all(&vec![3; 2 * WINDOW as usize])
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, vec![7; 2 * WINDOW as usize]);
        target_job.await.unwrap();
        finished.await.unwrap().unwrap();
        drop(stream);
        fixture
            .client
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        assert!(matches!(
            fixture.client.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
        assert!(matches!(
            fixture.server.await.unwrap(),
            Ok(()) | Err(russh::Error::Disconnect)
        ));
    })
    .await
    .unwrap();
}
