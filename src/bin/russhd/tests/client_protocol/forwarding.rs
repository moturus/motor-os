use super::*;
use russh::{ChannelMsg, ChannelOpenFailure, Error};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};

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
            let mut response = Vec::new();
            let mut eof = false;
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => response.extend_from_slice(&data),
                    Some(ChannelMsg::Eof) => eof = true,
                    Some(ChannelMsg::Close) => break,
                    None => panic!("forward ended without close"),
                    Some(_) => {}
                }
            }
            assert_eq!(response, b"response");
            assert!(eof);
        }
    });
}
