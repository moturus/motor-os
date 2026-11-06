use super::*;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;

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
    server: tokio::task::JoinHandle<Result<(), russh::Error>>,
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
        let server =
            tokio::spawn(async move { server::run_stream(config, socket, handler).await?.await });
        let mut client = client::connect_stream(Arc::new(client_config), peer, Client)
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

async fn finish(
    client: client::Handle<Client>,
    server: tokio::task::JoinHandle<Result<(), russh::Error>>,
) {
    client
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await
        .unwrap();
    assert!(matches!(
        client.await,
        Ok(()) | Err(russh::Error::Disconnect)
    ));
    assert!(matches!(
        server.await.unwrap(),
        Ok(()) | Err(russh::Error::Disconnect)
    ));
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
