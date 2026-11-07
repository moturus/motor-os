#![cfg(unix)]

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;

use russh::{Channel, ChannelId, ChannelMsg, ReceiveCredit, client, server};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

type Incoming = (Channel<client::Msg>, ReceiveCredit);

async fn assert_pending(future: impl Future) {
    let mut future = Box::pin(future);
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

struct Client {
    opened: mpsc::UnboundedSender<Incoming>,
    closed: mpsc::UnboundedSender<()>,
}

impl client::Handler for Client {
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
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let credit = session.receive_credit(channel.id()).unwrap();
        credit.defer_close();
        reply.accept().await;
        self.opened.send((channel, credit)).unwrap();
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _: ChannelId,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.closed.send(()).unwrap();
        Ok(())
    }
}

struct Server(mpsc::UnboundedSender<()>);

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_close(
        &mut self,
        _: ChannelId,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(()).unwrap();
        Ok(())
    }
}

struct Pair {
    client: client::Handle<Client>,
    server: server::RunningSession<Server>,
    left: Incoming,
    right: (Channel<server::Msg>, ReceiveCredit),
    client_closed: mpsc::UnboundedReceiver<()>,
    server_closed: mpsc::UnboundedReceiver<()>,
}

impl Pair {
    async fn connect() -> Self {
        let (socket, peer) = tokio::io::duplex(64 * 1024);
        let (client_closed_tx, client_closed) = mpsc::unbounded_channel();
        let (server_closed_tx, server_closed) = mpsc::unbounded_channel();
        let config = Arc::new(server::Config {
            keys: vec![
                russh::keys::PrivateKey::random(
                    &mut rand::rng(),
                    russh::keys::ssh_key::Algorithm::Ed25519,
                )
                .unwrap(),
            ],
            inactivity_timeout: None,
            ..Default::default()
        });
        let starting = tokio::spawn(server::run_stream(config, socket, Server(server_closed_tx)));
        let (opened_tx, mut opened) = mpsc::unbounded_channel();
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            peer,
            Client {
                opened: opened_tx,
                closed: client_closed_tx,
            },
        )
        .await
        .unwrap();
        let server = starting.await.unwrap().unwrap();
        assert!(client.authenticate_none("user").await.unwrap().success());
        let handle = server.handle();
        let opening = tokio::spawn(async move {
            handle
                .channel_open_forwarded_tcpip_with_credit("target", 80, "origin", 1234)
                .await
        });
        let left = opened.recv().await.unwrap();
        let right = opening.await.unwrap().unwrap();
        right.1.defer_close();
        Self {
            client,
            server,
            left,
            right,
            client_closed,
            server_closed,
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

async fn check_drain<S, T>(
    sender: &(Channel<S>, ReceiveCredit),
    receiver: &mut (Channel<T>, ReceiveCredit),
    closed: &mut mpsc::UnboundedReceiver<()>,
    client: &client::Handle<Client>,
) where
    S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
    T: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    let payload = vec![17; 4096];
    sender.0.data(payload.as_slice()).await.unwrap();
    sender.0.eof().await.unwrap();
    sender.0.close().await.unwrap();
    closed.recv().await.unwrap();
    // The handler saw close, but the application has consumed no payload yet.
    assert_pending(sender.1.wait_closed()).await;
    client.send_ping().await.unwrap();
    let mut output = Vec::new();
    loop {
        match receiver.0.wait().await {
            Some(ChannelMsg::Data { data }) => {
                output.extend_from_slice(&data);
                receiver.1.consumed(data.len() as u32);
            }
            Some(ChannelMsg::Eof) => {}
            Some(ChannelMsg::Close) => break,
            other => panic!("unexpected drain event: {other:?}"),
        }
    }
    assert_eq!(output, payload);
    assert_pending(sender.1.wait_closed()).await;
    receiver.0.close().await.unwrap();
    sender.1.wait_closed().await.unwrap();
    receiver.1.wait_closed().await.unwrap();
    client.send_ping().await.unwrap();
}

#[tokio::test]
async fn both_channel_directions_drain_before_close_acknowledgement() {
    timeout(Duration::from_secs(5), async {
        for from_client in [false, true] {
            let mut pair = Pair::connect().await;
            if from_client {
                check_drain(
                    &pair.left,
                    &mut pair.right,
                    &mut pair.server_closed,
                    &pair.client,
                )
                .await;
            } else {
                check_drain(
                    &pair.right,
                    &mut pair.left,
                    &mut pair.client_closed,
                    &pair.client,
                )
                .await;
            }
            pair.finish().await;
        }
    })
    .await
    .expect("channel close drain stalled");
}

#[tokio::test]
async fn last_credit_drop_acknowledges_close_without_blocking_the_connection() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::connect().await;
        pair.left.0.close().await.unwrap();
        pair.server_closed.recv().await.unwrap();
        assert_pending(pair.left.1.wait_closed()).await;
        drop(pair.right.1);
        pair.left.1.wait_closed().await.unwrap();
        pair.client.send_ping().await.unwrap();
        pair.client
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        assert!(matches!(
            pair.client.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
        assert!(matches!(
            pair.server.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
    })
    .await
    .expect("credit drop retained the channel");
}

#[tokio::test]
async fn transport_loss_releases_a_waiting_close() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::connect().await;
        pair.left.0.close().await.unwrap();
        pair.server_closed.recv().await.unwrap();
        assert_pending(pair.left.1.wait_closed()).await;
        pair.server.abort();
        assert!(matches!(
            pair.left.1.wait_closed().await,
            Err(russh::Error::Disconnect)
        ));
        assert!(pair.client.await.is_err());
        assert!(matches!(pair.server.await, Err(russh::Error::Disconnect)));
    })
    .await
    .expect("transport loss retained the close waiter");
}
