#![cfg(unix)]

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use russh::{Channel, client, server};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, timeout};

const WINDOW: u32 = 8192;
const CAPACITY: usize = 1024;

struct Client(mpsc::UnboundedSender<()>);

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        _: Option<&[u8]>,
        _: &russh::Names,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(()).unwrap();
        Ok(())
    }
}

struct Server(mpsc::UnboundedSender<Channel<server::Msg>>);

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(channel).unwrap();
        reply.accept().await;
        Ok(())
    }
}

struct ObservedSocket {
    inner: DuplexStream,
    blocked: Option<oneshot::Sender<()>>,
}

impl AsyncRead for ObservedSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for ObservedSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, data);
        if result.is_pending()
            && let Some(blocked) = this.blocked.take()
        {
            let _ = blocked.send(());
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn client_relay_preserves_credit_and_queued_data_across_rekey_and_close() {
    timeout(Duration::from_secs(5), async {
        let (socket, peer) = tokio::io::duplex(64 * 1024);
        let (opened_tx, mut opened) = mpsc::unbounded_channel();
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
        let (rekey_tx, mut rekeyed) = mpsc::unbounded_channel();
        let mut client = client::connect_stream(
            Arc::new(client::Config {
                window_size: WINDOW,
                maximum_packet_size: 1024,
                channel_buffer_size: 2,
                inactivity_timeout: None,
                ..Default::default()
            }),
            peer,
            Client(rekey_tx),
        )
        .await
        .unwrap();
        let server = starting.await.unwrap().unwrap();
        rekeyed.recv().await.unwrap();
        assert!(client.authenticate_none("user").await.unwrap().success());
        let (channel, credit) = client
            .channel_open_direct_tcpip_with_credit("target", 1234, "origin", 5678)
            .await
            .unwrap();
        let remote = opened.recv().await.unwrap();
        let (inner, mut target) = tokio::io::duplex(CAPACITY);
        let (blocked, stalled) = oneshot::channel();
        let relay = tokio::spawn(russhd::forward::relay(
            channel,
            ObservedSocket {
                inner,
                blocked: Some(blocked),
            },
            credit,
            WINDOW as usize,
            || false,
        ));
        let payload = vec![7; WINDOW as usize + CAPACITY];
        remote.data_bytes(payload.clone()).await.unwrap();
        stalled.await.unwrap();
        client.send_ping().await.unwrap();
        assert_eq!(remote.writable_packet_size().await, 0);
        client.rekey_soon().await.unwrap();
        rekeyed.recv().await.unwrap();
        client.send_ping().await.unwrap();
        assert_eq!(remote.writable_packet_size().await, 0);
        remote.eof().await.unwrap();
        remote.close().await.unwrap();
        let mut received = Vec::new();
        target.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, payload);
        relay.await.unwrap().unwrap();
        client
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        assert!(matches!(
            client.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
        assert!(matches!(
            server.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
    })
    .await
    .unwrap();
}
