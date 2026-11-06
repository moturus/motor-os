use std::sync::Arc;

use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelId, ChannelMsg, ReceiveCredit, client, server};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

const WINDOW: u32 = 1024;

struct Opened {
    channel: Channel<server::Msg>,
    handle: server::Handle,
    _credit: ReceiveCredit,
}

struct Server {
    opened: mpsc::UnboundedSender<Opened>,
    received: mpsc::UnboundedSender<usize>,
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
        reply.accept().await;
        assert!(
            self.opened
                .send(Opened {
                    channel,
                    handle: session.handle(),
                    _credit: credit,
                })
                .is_ok()
        );
        Ok(())
    }

    async fn data(
        &mut self,
        _: ChannelId,
        data: &[u8],
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.received.send(data.len()).unwrap();
        Ok(())
    }
}

struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Fixture {
    client: client::Handle<Client>,
    opened: mpsc::UnboundedReceiver<Opened>,
    received: mpsc::UnboundedReceiver<usize>,
    server: tokio::task::JoinHandle<Result<(), russh::Error>>,
}

impl Fixture {
    async fn connect(client_window: u32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (opened_tx, opened) = mpsc::unbounded_channel();
        let (received_tx, received) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let config = Arc::new(server::Config {
                keys: vec![
                    russh::keys::PrivateKey::random(
                        &mut rand::rng(),
                        russh::keys::ssh_key::Algorithm::Ed25519,
                    )
                    .unwrap(),
                ],
                window_size: WINDOW,
                maximum_packet_size: 128,
                channel_buffer_size: 16,
                event_buffer_size: 1,
                inactivity_timeout: None,
                ..Default::default()
            });
            let (socket, _) = listener.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();
            server::run_stream(
                config,
                socket,
                Server {
                    opened: opened_tx,
                    received: received_tx,
                },
            )
            .await?
            .await
        });
        let config = Arc::new(client::Config {
            window_size: client_window,
            inactivity_timeout: None,
            ..Default::default()
        });
        let mut client = client::connect(config, address, Client).await.unwrap();
        assert!(client.authenticate_none("user").await.unwrap().success());
        Self {
            client,
            opened,
            received,
            server,
        }
    }

    async fn finish(self) {
        self.client
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        assert!(matches!(
            self.client.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
        assert!(matches!(
            self.server.await.unwrap(),
            Ok(()) | Err(russh::Error::Disconnect)
        ));
    }
}

#[tokio::test]
async fn peer_close_unstalls_server_with_zero_window() {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::connect(0).await;
        let first = fixture.client.channel_open_session().await.unwrap();
        let first_server = fixture.opened.recv().await.unwrap();
        let mut other = fixture.client.channel_open_session().await.unwrap();
        let other_server = fixture.opened.recv().await.unwrap();

        // The second send fits only after the one-slot application queue has
        // dispatched the first into the channel's zero-window pending data.
        first_server
            .handle
            .data(first_server.channel.id(), vec![1])
            .await
            .unwrap();
        first_server
            .handle
            .data(first_server.channel.id(), vec![2])
            .await
            .unwrap();
        first.close().await.unwrap();

        // EOF needs no window, but ordinary application messages cannot advance
        // while the closed channel still contributes pending outbound data.
        other_server
            .handle
            .eof(other_server.channel.id())
            .await
            .unwrap();
        assert!(matches!(other.wait().await, Some(ChannelMsg::Eof)));
        fixture.finish().await;
    })
    .await
    .expect("peer close left the server's application queue stalled");
}

#[tokio::test]
async fn peer_close_unstalls_client_with_exhausted_credit() {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::connect(client::Config::default().window_size).await;
        let first = fixture.client.channel_open_session().await.unwrap();
        let first_server = fixture.opened.recv().await.unwrap();
        fixture
            .client
            .data(first.id(), vec![1; WINDOW as usize + 1])
            .await
            .unwrap();

        // Receiving a full window proves the oversized send was dispatched.
        // Its last byte is pending, since the retained credit is never consumed.
        let mut received = 0;
        while received < WINDOW as usize {
            received += fixture.received.recv().await.unwrap();
        }
        assert_eq!(received, WINDOW as usize);
        first_server
            .handle
            .close(first_server.channel.id())
            .await
            .unwrap();

        let _other = fixture.client.channel_open_session().await.unwrap();
        let _other_server = fixture.opened.recv().await.unwrap();
        fixture.finish().await;
    })
    .await
    .expect("peer close left the client's application queue stalled");
}
