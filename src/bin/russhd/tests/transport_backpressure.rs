//! The SSH reader must keep running while the underlying write half is full.

use std::sync::Arc;

use russh::{Channel, ChannelMsg, client, server};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

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

struct Server(mpsc::UnboundedSender<Channel<server::Msg>>);
impl server::Handler for Server {
    type Error = russh::Error;
    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.0.send(channel).unwrap();
        Ok(())
    }
}

#[tokio::test]
async fn both_peers_read_while_transport_writes_are_backpressured() {
    // KEX fits; one data packet does not. Channel windows and application
    // receivers exceed the entire transfer, isolating transport backpressure.
    let (client_wire, server_wire) = tokio::io::duplex(4096);
    let server_config = Arc::new(server::Config {
        keys: vec![
            russh::keys::PrivateKey::random(
                &mut rand::rng(),
                russh::keys::ssh_key::Algorithm::Ed25519,
            )
            .unwrap(),
        ],
        window_size: 1024 * 1024,
        channel_buffer_size: 1024,
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let (opened, mut channels) = mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        server::run_stream(server_config, server_wire, Server(opened))
            .await
            .unwrap()
            .await
    });
    let mut session = timeout(
        Duration::from_secs(5),
        client::connect_stream(
            Arc::new(client::Config {
                window_size: 1024 * 1024,
                channel_buffer_size: 1024,
                ..Default::default()
            }),
            client_wire,
            Client,
        ),
    )
    .await
    .expect("bounded transport handshake stalled")
    .unwrap();
    assert!(session.authenticate_none("user").await.unwrap().success());
    let client_channel = session.channel_open_session().await.unwrap();
    let server_channel = channels.recv().await.unwrap();
    let (mut client_reader, client_writer) = client_channel.split();
    let (mut server_reader, server_writer) = server_channel.split();
    const LENGTH: usize = 256 * 1024;
    let transfer = async {
        let client_send = async {
            let mut writer = client_writer.make_writer();
            writer.write_all(&vec![0x51; LENGTH]).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let server_send = async {
            let mut writer = server_writer.make_writer();
            writer.write_all(&vec![0xa3; LENGTH]).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let client_read = async {
            let mut received = 0;
            while let Some(message) = client_reader.wait().await {
                match message {
                    ChannelMsg::Data { data } => {
                        assert!(data.iter().all(|byte| *byte == 0xa3));
                        received += data.len();
                    }
                    ChannelMsg::Eof => break,
                    _ => {}
                }
            }
            assert_eq!(received, LENGTH);
        };
        let server_read = async {
            let mut received = 0;
            while let Some(message) = server_reader.wait().await {
                match message {
                    ChannelMsg::Data { data } => {
                        assert!(data.iter().all(|byte| *byte == 0x51));
                        received += data.len();
                    }
                    ChannelMsg::Eof => break,
                    _ => {}
                }
            }
            assert_eq!(received, LENGTH);
        };
        tokio::join!(client_send, server_send, client_read, server_read);
    };
    let result = timeout(Duration::from_secs(5), transfer).await;
    server.abort();
    let _ = server.await;
    result.expect("transport flush stopped both SSH readers");
}
