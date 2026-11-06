use super::local_forwarding::Client;
use super::*;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};

struct Open {
    channel: Channel<russh::server::Msg>,
    reply: Option<russh::server::ChannelOpenHandle>,
    transport: russh::server::Handle,
    destination: Option<(String, u32, String, u32)>,
}

struct Handler {
    opens: Sender<Open>,
    closed: Sender<()>,
}

impl Drop for Handler {
    fn drop(&mut self) {
        let _ = self.closed.send(());
    }
}

impl russh::server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.opens
            .send(Open {
                channel,
                reply: None,
                transport: session.handle(),
                destination: None,
            })
            .unwrap();
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"ready".as_slice())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<russh::server::Msg>,
        host: &str,
        port: u32,
        origin: &str,
        origin_port: u32,
        reply: russh::server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.opens
            .send(Open {
                channel,
                reply: Some(reply),
                transport: session.handle(),
                destination: Some((host.into(), port, origin.into(), origin_port)),
            })
            .unwrap();
        Ok(())
    }
}

struct Server {
    port: u16,
    opens: Receiver<Open>,
    closed: Receiver<()>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn start(window_size: u32) -> Self {
        let (address, listening) = std::sync::mpsc::channel();
        let (opens, opened) = std::sync::mpsc::channel();
        let (closed, ended) = std::sync::mpsc::channel();
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let config = std::sync::Arc::new(russh::server::Config {
                    keys: vec![russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519).unwrap()],
                    window_size,
                    inactivity_timeout: None,
                    ..Default::default()
                });
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                address.send(listener.local_addr().unwrap().port()).unwrap();
                let socket = tokio::select! {
                    _ = &mut stopped => return,
                    socket = listener.accept() => socket.unwrap().0,
                };
                let running = russh::server::run_stream(config, socket, Handler { opens, closed }).await.unwrap();
                tokio::select! {
                    _ = &mut stopped => {}
                    result = running => match result {
                        Ok(()) | Err(russh::Error::Disconnect) => {}
                        Err(russh::Error::IO(error)) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof) => {}
                        result => panic!("tunnel server failed: {result:?}"),
                    }
                }
            });
        });
        Self {
            port: listening.recv_timeout(Duration::from_secs(5)).unwrap(),
            opens: opened,
            closed: ended,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    fn opened(&self) -> Open {
        self.opens
            .recv_timeout(Duration::from_secs(5))
            .expect("SSH client did not open a channel")
    }

    fn ended(&self) {
        self.closed
            .recv_timeout(Duration::from_secs(5))
            .expect("SSH connection leaked");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
fn command_close_drains_an_open_that_has_not_yet_been_confirmed() {
    let fixture = Fixture::start();
    let server = Server::start(8192);
    let available = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = available.local_addr().unwrap();
    drop(available);
    let mut args = fixture.ssh_args();
    args[3] = server.port.to_string();
    args.extend([
        "-L".into(),
        format!("127.0.0.1:{}:Far-End.invalid:80", local.port()),
        "motor@127.0.0.1".into(),
        "controlled-command".into(),
    ]);
    let mut client = Client::start(&args);
    let _stdout = client.ready();
    let session = server.opened();
    assert!(session.destination.is_none());
    let mut socket = TcpStream::connect(local).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let forward = server.opened();
    assert_eq!(
        forward.destination.as_ref().unwrap(),
        &(
            "Far-End.invalid".into(),
            80,
            socket.local_addr().unwrap().ip().to_string(),
            u32::from(socket.local_addr().unwrap().port())
        )
    );
    block_on(async {
        session
            .transport
            .exit_status_request(session.channel.id(), 7)
            .await
            .unwrap();
        session.channel.eof().await.unwrap();
        session.channel.close().await.unwrap();
        // Local close releases the server's channel receiver immediately. A
        // rejected global request, ordered after close, is the wire barrier.
        assert_eq!(
            session
                .transport
                .forward_tcpip("barrier.invalid".into(), 1)
                .await,
            Err(())
        );
    });
    assert!(client.0.try_wait().unwrap().is_none());
    block_on(async { forward.reply.unwrap().accept().await });
    socket.write_all(b"admitted-before-exit").unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
    block_on(async {
        let mut stream = forward.channel.into_stream();
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut bytes)
            .await
            .unwrap();
        assert_eq!(bytes, b"admitted-before-exit");
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"drained")
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut stream)
            .await
            .unwrap();
    });
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"drained");
    assert_eq!(client.wait().code(), Some(7));
    server.ended();
    assert!(TcpStream::connect(local).is_err());
}

fn connect_when_listening(address: std::net::SocketAddr, client: &mut Client) -> TcpStream {
    // -N has no command-output readiness marker. Wait only for the listener's
    // startup; the successful socket is the one used by the contract below.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(address) {
            Ok(socket) => return socket,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                assert!(
                    client.0.try_wait().unwrap().is_none(),
                    "tunnel exited before listening"
                );
                assert!(Instant::now() < deadline, "tunnel never listened");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("connecting to local tunnel: {error}"),
        }
    }
}

#[test]
fn tunnel_without_session_cancels_pending_and_window_blocked_work_on_loss_or_interrupt() {
    use std::os::unix::process::ExitStatusExt;

    for interrupt in [false, true] {
        for confirmed in [false, true] {
            let fixture = Fixture::start();
            let server = Server::start(0);
            let available = TcpListener::bind("127.0.0.1:0").unwrap();
            let local = available.local_addr().unwrap();
            drop(available);
            let mut args = fixture.ssh_args();
            args[3] = server.port.to_string();
            args.extend([
                "-N".into(),
                "-t".into(),
                "-L".into(),
                format!("127.0.0.1:{}:unchanged.invalid:80", local.port()),
                "motor@127.0.0.1".into(),
            ]);
            // The forced terminal would fail on this pipe if -N opened a session.
            let mut client = Client::start(&args);
            client
                .0
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"ignored stdin\n~.\n")
                .unwrap();
            let mut socket = connect_when_listening(local, &mut client);
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut forward = server.opened();
            assert!(forward.destination.is_some(), "-N opened a session channel");
            socket.write_all(b"waiting-for-window").unwrap();
            if confirmed {
                block_on(async {
                    forward.reply.take().unwrap().accept().await;
                    assert_eq!(
                        forward
                            .transport
                            .forward_tcpip("barrier.invalid".into(), 1)
                            .await,
                        Err(())
                    );
                    tokio::select! {
                        biased;
                        event = forward.channel.wait() => panic!("client sent without window credit: {event:?}"),
                        () = std::future::ready(()) => {}
                    }
                });
            }
            if interrupt {
                assert_eq!(
                    unsafe { libc::kill(client.0.id() as libc::pid_t, libc::SIGINT) },
                    0
                );
                assert_eq!(client.wait().signal(), Some(libc::SIGINT));
            } else {
                block_on(async {
                    forward
                        .transport
                        .disconnect(
                            russh::Disconnect::ByApplication,
                            "test transport loss".into(),
                            "".into(),
                        )
                        .await
                        .unwrap();
                });
                assert_eq!(client.wait().code(), Some(255));
            }
            server.ended();
            match socket.read(&mut [0]) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                result => panic!("forwarded socket survived shutdown: {result:?}"),
            }
            assert!(TcpStream::connect(local).is_err());
            assert!(
                server.opens.try_recv().is_err(),
                "-N opened another channel"
            );
        }
    }
}
