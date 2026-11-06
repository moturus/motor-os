use super::*;
use russh::{ChannelMsg, ChannelOpenFailure, Error};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

async fn open_target(
    session: &russh::client::Handle<TestClient>,
    listener: &TcpListener,
) -> (Channel<russh::client::Msg>, TcpStream) {
    let channel = session
        .channel_open_direct_tcpip(
            "127.0.0.1",
            u32::from(listener.local_addr().unwrap().port()),
            "127.0.0.1",
            1,
        )
        .await
        .unwrap();
    let (target, _) = listener.accept().await.unwrap();
    (channel, target)
}

async fn drain_closed(channel: &mut Channel<russh::client::Msg>) -> Vec<u8> {
    let mut output = Vec::new();
    let mut eof = false;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => output.extend_from_slice(&data),
            Some(ChannelMsg::Eof) => eof = true,
            Some(ChannelMsg::Close) => break,
            None => panic!("forward ended without close"),
            Some(_) => {}
        }
    }
    assert!(eof);
    output
}

#[test]
fn direct_forwarding_requires_opt_in_and_reports_open_failures() {
    for (extra, enabled) in [
        ("", false),
        ("allow_tcp_forwarding = false", false),
        ("allow_tcp_forwarding = true", true),
    ] {
        let fixture = Fixture::configured(extra);
        block_on(async {
            let session = fixture.connect().await;
            if !enabled {
                let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                target.set_nonblocking(true).unwrap();
                assert!(matches!(
                    session
                        .channel_open_direct_tcpip(
                            "127.0.0.1",
                            u32::from(target.local_addr().unwrap().port()),
                            "127.0.0.1",
                            1
                        )
                        .await,
                    Err(Error::ChannelOpenFailure(
                        ChannelOpenFailure::AdministrativelyProhibited
                    ))
                ));
                assert_eq!(
                    target.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
            let refused = TcpSocket::new_v4().unwrap();
            refused.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let overlong = "a".repeat(256);
            for (host, port, reason) in [
                (
                    "127.0.0.1",
                    65536,
                    ChannelOpenFailure::AdministrativelyProhibited,
                ),
                ("127.0.0.1", 0, ChannelOpenFailure::ConnectFailed),
                ("has space", 22, ChannelOpenFailure::ConnectFailed),
                ("é", 22, ChannelOpenFailure::ConnectFailed),
                (overlong.as_str(), 22, ChannelOpenFailure::ConnectFailed),
                (
                    "127.0.0.1",
                    u32::from(refused.local_addr().unwrap().port()),
                    ChannelOpenFailure::ConnectFailed,
                ),
            ] {
                let expected = if enabled {
                    reason
                } else {
                    ChannelOpenFailure::AdministrativelyProhibited
                };
                assert!(
                    matches!(
                        session.channel_open_direct_tcpip(host, port, "127.0.0.1", 1).await,
                        Err(Error::ChannelOpenFailure(actual)) if actual == expected
                    ),
                    "{host}:{port}"
                );
            }
            // A refused forward leaves authentication and session channels usable.
            sftp_handshake(&session).await;
        });
    }
}

#[test]
fn direct_forwarding_resolves_locally_and_drains_both_half_closes() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        let session = fixture.connect().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for host in ["127.0.0.1", "localhost"] {
            let mut channel = session
                .channel_open_direct_tcpip(
                    host,
                    u32::from(listener.local_addr().unwrap().port()),
                    "127.0.0.1",
                    1,
                )
                .await
                .unwrap();
            let (mut target, _) = listener.accept().await.unwrap();
            channel.data_bytes(b"request".to_vec()).await.unwrap();
            channel.eof().await.unwrap();
            let mut request = Vec::new();
            target.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            target.write_all(b"response").await.unwrap();
            target.shutdown().await.unwrap();
            assert_eq!(drain_closed(&mut channel).await, b"response");
        }
    });
}

#[test]
fn one_connection_supports_256_forwards_and_reuses_closed_slots() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        let session = fixture.connect().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for count in [256, 16] {
            let mut forwards = Vec::new();
            for _ in 0..count {
                forwards.push(open_target(&session, &listener).await);
            }
            sftp_handshake(&session).await;
            // Exercise every live channel before draining their replies. Serial
            // one-byte round trips accumulate Nagle/delayed-ACK latency instead.
            for (index, (channel, _)) in forwards.iter().enumerate() {
                let marker = [index as u8];
                channel.data_bytes(marker.to_vec()).await.unwrap();
                channel.eof().await.unwrap();
            }
            for (index, (_, target)) in forwards.iter_mut().enumerate() {
                let marker = [index as u8];
                let mut request = Vec::new();
                target.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, marker);
                target.write_all(&marker).await.unwrap();
                target.shutdown().await.unwrap();
            }
            for (index, (mut channel, _)) in forwards.into_iter().enumerate() {
                let marker = [index as u8];
                assert_eq!(drain_closed(&mut channel).await, marker);
            }
        }
    });
}

#[test]
fn forward_eof_preserves_shell_input_and_shell_close_preserves_the_forward() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        let session = fixture.connect().await;
        let shell = session.channel_open_session().await.unwrap();
        shell.exec(true, "cat").await.unwrap();
        let (mut shell_reader, shell_writer) = shell.split();
        shell_writer.data_bytes(b"before\n".to_vec()).await.unwrap();
        let mut output = Vec::new();
        assert!(read_until(&mut shell_reader, &mut output, |out| out == b"before\n").await);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut channel, mut target) = open_target(&session, &listener).await;
        channel.data_bytes(b"forward".to_vec()).await.unwrap();
        channel.eof().await.unwrap();
        let mut request = Vec::new();
        target.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"forward");

        // The target has observed the forward's EOF before more shell input.
        shell_writer.data_bytes(b"after\n".to_vec()).await.unwrap();
        assert!(
            read_until(&mut shell_reader, &mut output, |out| out
                == b"before\nafter\n")
            .await
        );
        shell_writer.eof().await.unwrap();
        read_until(&mut shell_reader, &mut output, |_| false).await;

        target
            .write_all(b"session closed, forward alive")
            .await
            .unwrap();
        target.shutdown().await.unwrap();
        assert_eq!(
            drain_closed(&mut channel).await,
            b"session closed, forward alive"
        );
        sftp_handshake(&session).await;
    });
}

#[test]
fn close_and_disconnect_release_a_forward_with_zero_outbound_credit() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        for close_channel in [true, false] {
            let session = fixture
                .connect_with(russh::client::Config {
                    window_size: 0,
                    ..Default::default()
                })
                .await;
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (channel, mut target) = open_target(&session, &listener).await;
            channel.data_bytes(b"connected".to_vec()).await.unwrap();
            let mut request = [0; 9];
            target.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"connected");
            target.write_all(b"blocked by zero window").await.unwrap();
            session.send_ping().await.unwrap();
            if close_channel {
                channel.close().await.unwrap();
                session.send_ping().await.unwrap();
            } else {
                session
                    .disconnect(russh::Disconnect::ByApplication, "test", "")
                    .await
                    .unwrap();
                assert!(matches!(session.await, Err(Error::Disconnect)));
            }
            // A reset is also a release if teardown races unread TCP data.
            match target.read(&mut [0]).await {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => panic!("target retained after teardown: {other:?}"),
            }
        }
    });
}
