use super::*;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use russh::{client, server};
use tokio::io::{AsyncReadExt, DuplexStream, ReadBuf};
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

impl Opened {
    fn start<R, P>(self, socket: R, pressure: P) -> oneshot::Receiver<io::Result<()>>
    where
        R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        P: FnMut() -> bool + Send + 'static,
    {
        let (done, finished) = oneshot::channel();
        self.reservation.spawn(async move {
            let result = relay(self.channel, socket, self.credit, WINDOW as usize, pressure).await;
            let _ = done.send(result);
            Ok(())
        });
        finished
    }
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
    server: server::RunningSession<Server>,
    opened: mpsc::UnboundedReceiver<Opened>,
    socket: DuplexStream,
    target: DuplexStream,
}

impl Fixture {
    async fn connect() -> Self {
        Self::connect_with(client::Config::default(), 4096, 1024).await
    }

    async fn connect_with(
        client_config: client::Config,
        packet_size: u32,
        capacity: usize,
    ) -> Self {
        let (socket, peer) = tokio::io::duplex(32 * 1024);
        let (target, target_peer) = tokio::io::duplex(capacity);
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
            maximum_packet_size: packet_size,
            channel_buffer_size: 4,
            inactivity_timeout: None,
            ..Default::default()
        });
        let handler = Server {
            tasks: Tasks::default(),
            opened,
        };
        let starting = tokio::spawn(server::run_stream(config, socket, handler));
        let mut client = client::connect_stream(Arc::new(client_config), peer, Client)
            .await
            .unwrap();
        let server = starting.await.unwrap().unwrap();
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

async fn finish(client: client::Handle<Client>, server: server::RunningSession<Server>) {
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
}

async fn aborted_peer(client: client::Handle<Client>) {
    match client.await {
        Ok(()) | Err(russh::Error::Disconnect) => {}
        Err(russh::Error::IO(error)) => assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof),
        Err(error) => panic!("unexpected peer termination: {error:?}"),
    }
}

struct ObservedSocket {
    inner: DuplexStream,
    read: Option<oneshot::Sender<usize>>,
    write_blocked: Option<oneshot::Sender<()>>,
}

impl AsyncRead for ObservedSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(())))
            && buffer.filled().len() > before
            && let Some(read) = this.read.take()
        {
            let _ = read.send(buffer.filled().len() - before);
        }
        result
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
            && let Some(blocked) = this.write_blocked.take()
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
async fn half_close_drains_both_directions_and_returns_receive_credit() {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::connect().await;
        let channel = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        let finished = opened.start(fixture.socket, || false);
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
        finish(fixture.client, fixture.server).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn peer_close_drains_received_bytes_to_a_slow_target() {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::connect().await;
        let channel = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        channel.data_bytes(vec![13; 2048]).await.unwrap();
        channel.eof().await.unwrap();
        channel.close().await.unwrap();
        // The ordered ping proves the data, EOF and close reached the server.
        fixture.client.send_ping().await.unwrap();
        let mut work = Box::pin(relay(
            opened.channel,
            fixture.socket,
            opened.credit,
            WINDOW as usize,
            || false,
        ));
        poll_fn(|cx| {
            assert!(
                work.as_mut().poll(cx).is_pending(),
                "peer close discarded the backlog before the target read it"
            );
            Poll::Ready(())
        })
        .await;
        let reader = tokio::spawn(async move {
            let mut target = fixture.target;
            let mut output = Vec::new();
            target.read_to_end(&mut output).await.unwrap();
            output
        });
        work.await.unwrap();
        assert_eq!(reader.await.unwrap(), vec![13; 2048]);
        finish(fixture.client, fixture.server).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socket_eof_leaves_channel_to_socket_alive() {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::connect().await;
        let mut channel = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        let finished = opened.start(fixture.socket, || false);
        fixture.target.shutdown().await.unwrap();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Eof) => break,
                Some(ChannelMsg::Data { .. } | ChannelMsg::Close) | None => {
                    panic!("unexpected channel termination before input")
                }
                _ => {}
            }
        }
        let reader = tokio::spawn(async move {
            let mut output = Vec::new();
            fixture.target.read_to_end(&mut output).await.unwrap();
            output
        });
        channel
            .data_bytes(vec![19; 2 * WINDOW as usize])
            .await
            .unwrap();
        channel.eof().await.unwrap();
        finished.await.unwrap().unwrap();
        assert_eq!(reader.await.unwrap(), vec![19; 2 * WINDOW as usize]);
        // EOF ends payload delivery; window and close events still need a reader.
        loop {
            match channel.wait().await {
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(ChannelMsg::Close) => break,
                message => panic!("unexpected event after EOF: {message:?}"),
            }
        }
        finish(fixture.client, fixture.server).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn forwarding_resumes_across_an_explicit_rekey() {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::connect().await;
        let channel = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        let finished = opened.start(fixture.socket, || false);
        let mut stream = channel.into_stream();
        let echo = tokio::spawn(async move {
            let mut target = fixture.target;
            let mut buffer = [0; 1024];
            loop {
                let count = target.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                target.write_all(&buffer[..count]).await.unwrap();
            }
            target.shutdown().await.unwrap();
        });
        for round in 0..4 {
            let data: Vec<_> = (0..24 * 1024).map(|i| (i + round) as u8).collect();
            stream.write_all(&data).await.unwrap();
            let mut response = vec![0; data.len()];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, data);
            if round == 1 {
                fixture.client.rekey_soon().await.unwrap();
                fixture.client.send_ping().await.unwrap();
            }
        }
        stream.shutdown().await.unwrap();
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty());
        echo.await.unwrap();
        finished.await.unwrap().unwrap();
        drop(stream);
        finish(fixture.client, fixture.server).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn receive_credit_tracks_socket_writes_instead_of_queued_bytes() {
    timeout(Duration::from_secs(5), async {
        // Two packets fit the fixture's queue before the relay's first poll.
        let mut fixture = Fixture::connect_with(client::Config::default(), 32 * 1024, 1024).await;
        let mut channel = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        channel.data_bytes(vec![1; WINDOW as usize]).await.unwrap();
        fixture.client.send_ping().await.unwrap();
        let mut work = Box::pin(relay(
            opened.channel,
            fixture.socket,
            opened.credit,
            WINDOW as usize,
            || false,
        ));
        poll_fn(|cx| {
            assert!(work.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // Only the target's 1024-byte socket buffer accepted data. Process the
        // resulting window adjustment before inspecting the client's credit.
        fixture.client.send_ping().await.unwrap();
        assert_eq!(channel.writable_packet_size().await, 1024);
        let (done, finished) = oneshot::channel();
        opened.reservation.spawn(async move {
            let _ = done.send(work.await);
            Ok(())
        });
        let reader = tokio::spawn(async move {
            let mut target = fixture.target;
            let mut output = Vec::new();
            target.read_to_end(&mut output).await.unwrap();
            target.shutdown().await.unwrap();
            output
        });
        channel.data_bytes(vec![2; WINDOW as usize]).await.unwrap();
        channel.eof().await.unwrap();
        finished.await.unwrap().unwrap();
        let output = reader.await.unwrap();
        assert_eq!(output.len(), 2 * WINDOW as usize);
        assert!(output[..WINDOW as usize].iter().all(|&byte| byte == 1));
        assert!(output[WINDOW as usize..].iter().all(|&byte| byte == 2));
        let mut eof = false;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(ChannelMsg::Eof) => {
                    assert!(!eof);
                    eof = true;
                }
                Some(ChannelMsg::Close) => break,
                message => panic!("unexpected event after input: {message:?}"),
            }
        }
        assert!(eof);
        finish(fixture.client, fixture.server).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socket_and_window_stalls_leave_another_channel_receiving() {
    timeout(Duration::from_secs(5), async {
        let config = client::Config {
            window_size: 0,
            ..Default::default()
        };
        let mut fixture = Fixture::connect_with(config, 4096, 1).await;
        let first = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        let other = fixture.client.channel_open_session().await.unwrap();
        let mut other_server = fixture.opened.recv().await.unwrap();
        let (read, read_seen) = oneshot::channel();
        let (write_blocked, write_seen) = oneshot::channel();
        let finished = opened.start(
            ObservedSocket {
                inner: fixture.socket,
                read: Some(read),
                write_blocked: Some(write_blocked),
            },
            || false,
        );
        fixture.target.write_all(&[91]).await.unwrap();
        assert_eq!(read_seen.await.unwrap(), 1);
        first.data_bytes(vec![5; 8]).await.unwrap();
        write_seen.await.unwrap();
        for _ in 0..256 {
            first.data_bytes(vec![7]).await.unwrap();
        }
        other.eof().await.unwrap();
        loop {
            match other_server.channel.wait().await {
                Some(ChannelMsg::Eof) => break,
                None => panic!("other channel ended before its EOF arrived"),
                _ => {}
            }
        }
        fixture.client.send_ping().await.unwrap();
        fixture.server.abort();
        assert!(matches!(
            fixture.server.await,
            Err(russh::Error::Disconnect)
        ));
        assert!(finished.await.is_err());
        let mut output = Vec::new();
        fixture.target.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, [5]);
        assert!(fixture.target.write_all(&[1]).await.is_err());
        aborted_peer(fixture.client).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn peer_close_ends_a_window_blocked_writer_without_disconnect() {
    timeout(Duration::from_secs(5), async {
        let config = client::Config {
            window_size: 0,
            ..Default::default()
        };
        let mut fixture = Fixture::connect_with(config, 4096, 1024).await;
        let channel = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        let (read, read_seen) = oneshot::channel();
        let finished = opened.start(
            ObservedSocket {
                inner: fixture.socket,
                read: Some(read),
                write_blocked: None,
            },
            || false,
        );
        fixture.target.write_all(&[31]).await.unwrap();
        assert_eq!(read_seen.await.unwrap(), 1);
        channel.close().await.unwrap();
        finished.await.unwrap().unwrap();
        let mut output = Vec::new();
        fixture.target.read_to_end(&mut output).await.unwrap();
        assert!(output.is_empty());
        assert!(fixture.target.write_all(&[1]).await.is_err());
        fixture.client.send_ping().await.unwrap();
        finish(fixture.client, fixture.server).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn transport_loss_releases_a_full_inbound_queue_and_socket() {
    timeout(Duration::from_secs(5), async {
        let mut fixture = Fixture::connect_with(client::Config::default(), 32 * 1024, 0).await;
        let channel = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        channel.data_bytes(vec![11; WINDOW as usize]).await.unwrap();
        fixture.client.send_ping().await.unwrap();
        let mut work = Box::pin(relay(
            opened.channel,
            fixture.socket,
            opened.credit,
            WINDOW as usize,
            || false,
        ));
        // Both data packets are queued; a zero-capacity target accepts none.
        // This poll must consume the whole window before parking on the write.
        poll_fn(|cx| {
            assert!(work.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(channel.writable_packet_size().await, 0);
        let (done, finished) = oneshot::channel();
        opened.reservation.spawn(async move {
            let _ = done.send(work.await);
            Ok(())
        });
        fixture.server.abort();
        assert!(matches!(
            fixture.server.await,
            Err(russh::Error::Disconnect)
        ));
        assert!(finished.await.is_err());
        let mut output = Vec::new();
        fixture.target.read_to_end(&mut output).await.unwrap();
        assert!(output.is_empty());
        assert!(fixture.target.write_all(&[1]).await.is_err());
        aborted_peer(fixture.client).await;
    })
    .await
    .unwrap();
}
