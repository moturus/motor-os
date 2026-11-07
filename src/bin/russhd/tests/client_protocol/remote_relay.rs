use super::*;
use russh::{ChannelMsg, ReceiveCredit, client};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

struct Opened {
    channel: Channel<client::Msg>,
    reply: client::ChannelOpenHandle,
    credit: ReceiveCredit,
    address: String,
    port: u32,
    origin: String,
    origin_port: u32,
}

struct Incoming(mpsc::UnboundedSender<Opened>);

impl client::Handler for Incoming {
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
        address: &str,
        port: u32,
        origin: &str,
        origin_port: u32,
        reply: client::ChannelOpenHandle,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let credit = session.receive_credit(channel.id()).unwrap();
        self.0
            .send(Opened {
                channel,
                reply,
                credit,
                address: address.to_owned(),
                port,
                origin: origin.to_owned(),
                origin_port,
            })
            .unwrap_or_else(|_| panic!("incoming forward receiver dropped"));
        Ok(())
    }
}

async fn connect(fixture: &Fixture) -> (client::Handle<Incoming>, mpsc::UnboundedReceiver<Opened>) {
    let (opened, receiver) = mpsc::unbounded_channel();
    let mut session = client::connect(
        std::sync::Arc::new(client::Config {
            window_size: 8192,
            maximum_packet_size: 1024,
            channel_buffer_size: 16,
            ..Default::default()
        }),
        ("127.0.0.1", fixture.port),
        Incoming(opened),
    )
    .await
    .unwrap();
    let key = russh::keys::load_secret_key(&fixture.identity, None).unwrap();
    assert!(
        session
            .authenticate_publickey(
                "motor",
                russh::keys::PrivateKeyWithHashAlg::new(std::sync::Arc::new(key), None,)
            )
            .await
            .unwrap()
            .success()
    );
    (session, receiver)
}

async fn round_trip(mut socket: TcpStream, mut opened: Opened) {
    opened.reply.accept().await;
    socket.write_all(b"request").await.unwrap();
    socket.shutdown().await.unwrap();
    let mut request = Vec::new();
    loop {
        match opened.channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                request.extend_from_slice(&data);
                opened.credit.consumed(data.len() as u32);
            }
            Some(ChannelMsg::Eof) => break,
            event => panic!("unexpected incoming request event: {event:?}"),
        }
    }
    assert_eq!(request, b"request");
    opened
        .channel
        .data_bytes(b"response".to_vec())
        .await
        .unwrap();
    opened.channel.eof().await.unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response");
    loop {
        match opened.channel.wait().await {
            Some(ChannelMsg::Close) => break,
            Some(ChannelMsg::WindowAdjusted { .. }) => {}
            event => panic!("unexpected incoming completion event: {event:?}"),
        }
    }
}

#[test]
fn one_remote_listener_admits_100_pending_opens_without_stalling_a_command() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        let (session, mut incoming) = connect(&fixture).await;
        let port = session.tcpip_forward("localhost", 0).await.unwrap();
        let mut pending = Vec::new();
        for _ in 0..100 {
            let socket = TcpStream::connect(("127.0.0.1", port as u16))
                .await
                .unwrap();
            pending.push((socket, incoming.recv().await.unwrap()));
        }
        let mut command = session.channel_open_session().await.unwrap();
        command
            .exec(true, "/bin/echo remote-command-ok")
            .await
            .unwrap();
        command.eof().await.unwrap();
        let mut output = Vec::new();
        let mut status = None;
        loop {
            match command.wait().await {
                Some(ChannelMsg::Data { data }) => output.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status }) => status = Some(exit_status),
                Some(ChannelMsg::Close) => break,
                Some(_) => {}
                None => panic!("command ended without close"),
            }
        }
        assert_eq!(output, b"remote-command-ok\n");
        assert_eq!(status, Some(0));
        let mut exchanges = tokio::task::JoinSet::new();
        for (socket, opened) in pending {
            exchanges.spawn(round_trip(socket, opened));
        }
        while let Some(result) = exchanges.join_next().await {
            result.unwrap();
        }
        session
            .cancel_tcpip_forward("localhost", port)
            .await
            .unwrap();
    });
}

#[test]
fn gateway_ports_overrides_explicit_loopback_with_wildcard_binds_and_allocated_ports() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true\ngateway_ports = true");
    block_on(async {
        let (session, mut incoming) = connect(&fixture).await;
        let mut requested = 0;
        for _ in 0..2 {
            let reply = session.tcpip_forward("::1", requested).await.unwrap();
            let port = if requested == 0 {
                reply
            } else {
                assert_eq!(reply, 0);
                requested
            };
            assert!((49152..=65535).contains(&port));
            // An explicit IPv6 loopback request is exposed over IPv4 too.
            let socket = TcpStream::connect(("127.0.0.1", port as u16))
                .await
                .unwrap();
            let opened = incoming.recv().await.unwrap();
            assert_eq!(opened.address, "::1");
            assert_eq!(opened.port, port);
            round_trip(socket, opened).await;
            session.cancel_tcpip_forward("::1", port).await.unwrap();
            let _released = TcpListener::bind(("0.0.0.0", port as u16)).await.unwrap();
            requested = port;
        }
    });
}

#[test]
fn cancelling_a_listener_preserves_an_admitted_open_and_its_bind_identity() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        let (session, mut incoming) = connect(&fixture).await;
        let address = "bind-name.invalid";
        let port = session.tcpip_forward(address, 0).await.unwrap();
        let socket = TcpStream::connect(("127.0.0.1", port as u16))
            .await
            .unwrap();
        let opened = incoming.recv().await.unwrap();
        assert_eq!(opened.address, address);
        assert_eq!(opened.port, port);
        let origin = socket.local_addr().unwrap();
        assert_eq!(opened.origin, origin.ip().to_string());
        assert_eq!(opened.origin_port, u32::from(origin.port()));
        // Cancel while confirmation is still withheld, rather than after drain.
        session.cancel_tcpip_forward(address, port).await.unwrap();
        let _rebound = TcpListener::bind(("127.0.0.1", port as u16)).await.unwrap();
        round_trip(socket, opened).await;
        session.send_ping().await.unwrap();
    });
}

#[test]
fn a_pending_or_refused_remote_open_leaves_other_accepts_and_ssh_responsive() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        let (session, mut incoming) = connect(&fixture).await;
        let port = session.tcpip_forward("localhost", 0).await.unwrap();
        let mut stalled = TcpStream::connect(("127.0.0.1", port as u16))
            .await
            .unwrap();
        let first = incoming.recv().await.unwrap();
        let working = TcpStream::connect(("127.0.0.1", port as u16))
            .await
            .unwrap();
        let second = incoming.recv().await.unwrap();
        session.send_ping().await.unwrap();
        round_trip(working, second).await;
        first
            .reply
            .reject(russh::ChannelOpenFailure::ConnectFailed)
            .await;
        assert_eq!(stalled.read(&mut [0]).await.unwrap(), 0);
        session.send_ping().await.unwrap();
        session
            .cancel_tcpip_forward("localhost", port)
            .await
            .unwrap();
    });
}

#[test]
fn connection_loss_releases_pending_opens_blocked_relays_and_listener_ports() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        let (session, mut incoming) = connect(&fixture).await;
        let port = session.tcpip_forward("127.0.0.1", 0).await.unwrap();
        let mut pending = TcpStream::connect(("127.0.0.1", port as u16))
            .await
            .unwrap();
        let _unconfirmed = incoming.recv().await.unwrap();
        let mut active = TcpStream::connect(("127.0.0.1", port as u16))
            .await
            .unwrap();
        let mut confirmed = incoming.recv().await.unwrap();
        confirmed.reply.accept().await;
        active.write_all(&vec![9; 8193]).await.unwrap();
        let mut received = 0;
        while received < 8192 {
            match confirmed.channel.wait().await {
                Some(ChannelMsg::Data { data }) => received += data.len(),
                event => panic!("unexpected blocked relay event: {event:?}"),
            }
        }
        assert_eq!(received, 8192);
        // No consumed credit: the extra byte remains blocked at SSH's window.
        tokio::select! {
            biased;
            event = confirmed.channel.wait() => panic!("unearned window credit: {event:?}"),
            result = session.send_ping() => result.unwrap(),
        }
        session
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        assert!(matches!(
            session.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
        assert_eq!(pending.read(&mut [0]).await.unwrap(), 0);
        match active.read(&mut [0]).await {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("blocked TCP relay remained open: {other:?}"),
        }
        // A new authenticated connection can immediately reclaim the old port.
        let other = fixture.connect().await;
        assert_eq!(other.tcpip_forward("127.0.0.1", port).await.unwrap(), 0);
        other.cancel_tcpip_forward("127.0.0.1", port).await.unwrap();
    });
}
