#![cfg(unix)]

use std::sync::Arc;

use russh::{Channel, ChannelId, ChannelMsg, client, server};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

const WINDOW: u32 = 8192;

#[derive(Debug)]
enum Event {
    Confirmed,
    Keys,
}

struct Client(mpsc::UnboundedSender<Event>);

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_open_confirmation(
        &mut self,
        _: ChannelId,
        _: u32,
        _: u32,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(Event::Confirmed).unwrap();
        Ok(())
    }

    async fn kex_done(
        &mut self,
        _: Option<&[u8]>,
        _: &russh::Names,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(Event::Keys).unwrap();
        Ok(())
    }
}

type Opened = (Channel<server::Msg>, server::ChannelOpenHandle);

struct Server(mpsc::UnboundedSender<Opened>);

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        host: &str,
        port: u32,
        origin: &str,
        origin_port: u32,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        assert_eq!(
            (host, port, origin, origin_port),
            ("target", 1234, "origin", 5678)
        );
        self.0.send((channel, reply)).unwrap();
        Ok(())
    }
}

struct Pair {
    client: client::Handle<Client>,
    server: server::RunningSession<Server>,
    opened: mpsc::UnboundedReceiver<Opened>,
    events: mpsc::UnboundedReceiver<Event>,
}

impl Pair {
    async fn connect() -> Self {
        let (socket, peer) = tokio::io::duplex(64 * 1024);
        let (opened_tx, opened) = mpsc::unbounded_channel();
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
            socket,
            Server(opened_tx),
        ));
        let (events_tx, mut events) = mpsc::unbounded_channel();
        let mut client = client::connect_stream(
            Arc::new(client::Config {
                window_size: WINDOW,
                maximum_packet_size: 1024,
                channel_buffer_size: 16,
                inactivity_timeout: None,
                ..Default::default()
            }),
            peer,
            Client(events_tx),
        )
        .await
        .unwrap();
        let server = starting.await.unwrap().unwrap();
        assert!(matches!(events.recv().await, Some(Event::Keys)));
        assert!(client.authenticate_none("user").await.unwrap().success());
        Self {
            client,
            server,
            opened,
            events,
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
            self.server.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
    }
}

async fn read_window(channel: &mut Channel<client::Msg>) {
    let mut bytes = 0;
    while bytes < WINDOW {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                assert!(data.iter().all(|byte| *byte == 9));
                bytes += data.len() as u32;
            }
            other => panic!("expected data, got {other:?}"),
        }
    }
    assert_eq!(bytes, WINDOW);
}

#[tokio::test]
async fn credit_handoff_precedes_confirmation_and_survives_a_paused_opener() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::connect().await;
        let mut opening = Box::pin(
            pair.client
                .channel_open_direct_tcpip_with_credit("target", 1234, "origin", 5678),
        );
        let (remote, reply) = tokio::select! {
            opened = pair.opened.recv() => opened.unwrap(),
            result = opening.as_mut() => panic!("open completed before reply: {result:?}"),
        };
        reply.accept().await;
        assert!(matches!(pair.events.recv().await, Some(Event::Confirmed)));
        // Do not poll the opener again while the peer sends its first window.
        remote.data_bytes(vec![9; WINDOW as usize]).await.unwrap();
        pair.client.send_ping().await.unwrap();
        assert_eq!(remote.writable_packet_size().await, 0);
        pair.client.rekey_soon().await.unwrap();
        assert!(matches!(pair.events.recv().await, Some(Event::Keys)));
        pair.client.send_ping().await.unwrap();
        assert_eq!(remote.writable_packet_size().await, 0);
        let (mut channel, credit) = opening.await.unwrap();
        read_window(&mut channel).await;
        credit.consumed(WINDOW);
        let (sent, ()) = tokio::join!(
            remote.data_bytes(vec![9; WINDOW as usize]),
            read_window(&mut channel)
        );
        sent.unwrap();
        assert_eq!(remote.writable_packet_size().await, 0);
        pair.finish().await;
    })
    .await
    .expect("manual outgoing credit stalled");
}

#[tokio::test]
async fn cancellation_before_or_after_confirmation_closes_only_that_channel() {
    timeout(Duration::from_secs(5), async {
        for confirmed in [false, true] {
            let mut pair = Pair::connect().await;
            let mut opening = Box::pin(
                pair.client
                    .channel_open_direct_tcpip_with_credit("target", 1234, "origin", 5678),
            );
            let (mut remote, reply) = tokio::select! {
                opened = pair.opened.recv() => opened.unwrap(),
                result = opening.as_mut() => panic!("open completed before reply: {result:?}"),
            };
            if confirmed {
                reply.accept().await;
                assert!(matches!(pair.events.recv().await, Some(Event::Confirmed)));
                drop(opening); // Confirmation arrived, but the opener never resumed.
            } else {
                drop(opening);
                pair.client.send_ping().await.unwrap();
                reply.accept().await;
            }
            loop {
                match remote.wait().await {
                    Some(ChannelMsg::Close) => break,
                    None => panic!("canceled channel ended without close"),
                    Some(_) => {}
                }
            }
            assert!(matches!(
                pair.events.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            pair.client.send_ping().await.unwrap();
            pair.finish().await;
        }
    })
    .await
    .expect("canceled outgoing open stalled");
}

#[tokio::test]
async fn refusal_and_transport_loss_end_the_outgoing_handoff() {
    timeout(Duration::from_secs(5), async {
        for refused in [true, false] {
            let mut pair = Pair::connect().await;
            let mut opening = Box::pin(
                pair.client
                    .channel_open_direct_tcpip_with_credit("target", 1234, "origin", 5678),
            );
            let (_remote, reply) = tokio::select! {
                opened = pair.opened.recv() => opened.unwrap(),
                result = opening.as_mut() => panic!("open completed before reply: {result:?}"),
            };
            if refused {
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                assert!(matches!(
                    opening.await,
                    Err(russh::Error::ChannelOpenFailure(
                        russh::ChannelOpenFailure::ConnectFailed
                    ))
                ));
                pair.client.send_ping().await.unwrap();
                pair.finish().await;
            } else {
                pair.server
                    .handle()
                    .disconnect(russh::Disconnect::ByApplication, "".into(), "".into())
                    .await
                    .unwrap();
                assert!(matches!(opening.await, Err(russh::Error::Disconnect)));
                // A received protocol disconnect is a normal client shutdown.
                pair.client.await.unwrap();
                assert!(matches!(
                    pair.server.await,
                    Ok(()) | Err(russh::Error::Disconnect)
                ));
                drop(reply);
            }
        }
    })
    .await
    .expect("failed outgoing open stalled");
}
