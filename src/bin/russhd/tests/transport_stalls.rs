//! Read progress and bounded responses while the transport cannot write.
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use russh::{Channel, ChannelMsg, client, server};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio::time::{Duration, timeout};

#[derive(Default)]
struct Waiter(Mutex<Option<Waker>>);
impl Waiter {
    fn register(&self, waker: &Waker) {
        *self.0.lock().unwrap() = Some(waker.clone());
    }
    fn wake(&self) {
        let waker = self.0.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[derive(Default)]
struct Gate {
    blocked: AtomicBool,
    eof: AtomicBool,
    entered: Notify,
    reader: Waiter,
    writer: Waiter,
}
impl Gate {
    fn release(&self) {
        self.blocked.store(false, Ordering::Release);
        self.writer.wake();
    }
}

struct Wire {
    inner: DuplexStream,
    gate: Arc<Gate>,
}
impl AsyncRead for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.gate.reader.register(cx.waker());
        if self.gate.eof.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for Wire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.gate.writer.register(cx.waker());
        if self.gate.blocked.load(Ordering::Acquire) {
            self.gate.entered.notify_one();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
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

struct Fixture {
    client: client::Handle<Client>,
    server: tokio::task::JoinHandle<Result<(), russh::Error>>,
    incoming: mpsc::UnboundedReceiver<Channel<server::Msg>>,
    client_gate: Arc<Gate>,
    server_gate: Arc<Gate>,
}
impl Fixture {
    async fn new(inactivity_timeout: Option<Duration>) -> Self {
        let (client_wire, server_wire) = tokio::io::duplex(4096);
        let client_gate = Arc::new(Gate::default());
        let server_gate = Arc::new(Gate::default());
        let config = Arc::new(server::Config {
            keys: vec![
                russh::keys::PrivateKey::random(
                    &mut rand::rng(),
                    russh::keys::ssh_key::Algorithm::Ed25519,
                )
                .unwrap(),
            ],
            window_size: 8192,
            maximum_packet_size: 1024,
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout,
            ..Default::default()
        });
        let (opened, incoming) = mpsc::unbounded_channel();
        let server_stream = Wire {
            inner: server_wire,
            gate: server_gate.clone(),
        };
        let server = tokio::spawn(async move {
            server::run_stream(config, server_stream, Server(opened))
                .await
                .unwrap()
                .await
        });
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            Wire {
                inner: client_wire,
                gate: client_gate.clone(),
            },
            Client,
        )
        .await
        .unwrap();
        assert!(client.authenticate_none("user").await.unwrap().success());
        Self {
            client,
            server,
            incoming,
            client_gate,
            server_gate,
        }
    }
    async fn channel(&mut self) -> (Channel<client::Msg>, Channel<server::Msg>) {
        let client = self.client.channel_open_session().await.unwrap();
        (client, self.incoming.recv().await.unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn eof_while_writing(block_client: bool) {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::new(None).await;
        let (client_data, server_data) = fixture.channel().await;
        let (client_probe, server_probe) = fixture.channel().await;
        let gate = if block_client {
            fixture.client_gate.clone()
        } else {
            fixture.server_gate.clone()
        };
        gate.blocked.store(true, Ordering::Release);
        let sending = tokio::spawn(async move {
            if block_client {
                client_data.data(&[1; 8192][..]).await.unwrap();
            } else {
                server_data.data(&[1; 8192][..]).await.unwrap();
            }
        });
        gate.entered.notified().await;
        let mut reader = if block_client {
            let (reader, _) = client_probe.split();
            server_probe.eof().await.unwrap();
            reader
        } else {
            let (reader, _) = server_probe.split();
            client_probe.eof().await.unwrap();
            reader
        };
        while let Some(message) = reader.wait().await {
            if matches!(message, ChannelMsg::Eof) {
                assert!(gate.blocked.load(Ordering::Acquire));
                gate.release();
                sending.await.unwrap();
                return;
            }
        }
        panic!("probe ended without EOF");
    })
    .await
    .expect("transport write blocked the other channel's EOF");
}

#[tokio::test]
async fn client_reads_channel_control_while_transport_write_is_blocked() {
    eof_while_writing(true).await;
}
#[tokio::test]
async fn server_reads_channel_control_while_transport_write_is_blocked() {
    eof_while_writing(false).await;
}

#[tokio::test]
async fn peer_requests_cannot_grow_blocked_transport_output_without_bound() {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::new(None).await;
        fixture.server_gate.blocked.store(true, Ordering::Release);
        let requests = async {
            loop {
                if fixture.client.send_keepalive(true).await.is_err() {
                    break;
                }
            }
        };
        let stopped = async { (&mut fixture.server).await.unwrap() };
        tokio::pin!(requests, stopped);
        tokio::select! {
            result = &mut stopped => assert!(matches!(result, Err(russh::Error::Pending))),
            () = &mut requests => assert!(matches!(stopped.await, Err(russh::Error::Pending))),
        }
    })
    .await
    .expect("blocked response queue did not reach its bound");
}

#[tokio::test(start_paused = true)]
async fn blocked_transport_write_preserves_inactivity_timeout() {
    let mut fixture = Fixture::new(Some(Duration::from_secs(1))).await;
    let (_client, channel) = fixture.channel().await;
    fixture.server_gate.blocked.store(true, Ordering::Release);
    channel.data(&[1; 1024][..]).await.unwrap();
    fixture.server_gate.entered.notified().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    let result = timeout(Duration::from_secs(5), &mut fixture.server)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(russh::Error::InactivityTimeout)));
}

#[tokio::test]
async fn read_eof_cancels_a_blocked_transport_write() {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::new(None).await;
        let (_client, channel) = fixture.channel().await;
        fixture.server_gate.blocked.store(true, Ordering::Release);
        channel.data(&[1; 1024][..]).await.unwrap();
        fixture.server_gate.entered.notified().await;
        fixture.server_gate.eof.store(true, Ordering::Release);
        fixture.server_gate.reader.wake();
        assert!((&mut fixture.server).await.unwrap().is_err());
    })
    .await
    .expect("transport read EOF did not release the blocked writer");
}
