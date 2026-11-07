use super::local_forwarding::Client;
use super::remote_peer::{Event, Peer, Reply};
use super::*;
use std::net::TcpListener;

fn start(fixture: &Fixture, peer: &Peer, forwards: &[String]) -> Client {
    let mut args = fixture.ssh_args();
    args[3] = peer.port.to_string();
    for forward in forwards {
        args.extend(["-R".into(), forward.clone()]);
    }
    args.extend(["motor@127.0.0.1".into(), "controlled-command".into()]);
    Client::start(&args)
}

fn finish(peer: &Peer, handle: &russh::server::Handle, client: &mut Client, status: u32) {
    let session = peer.sessions.recv_timeout(Duration::from_secs(5)).unwrap();
    block_on(async {
        handle
            .exit_status_request(session.id(), status)
            .await
            .unwrap();
        handle.eof(session.id()).await.unwrap();
        handle.close(session.id()).await.unwrap();
    });
    assert_eq!(client.wait().code(), Some(status as i32));
}

#[test]
fn unrequested_remote_opens_are_rejected_without_dialing_or_ending_the_connection() {
    let fixture = Fixture::start();
    for requested in [false, true] {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let replies = if requested {
            vec![Reply {
                accepted: true,
                allocated: 9000,
                early_opens: vec![],
            }]
        } else {
            vec![]
        };
        let peer = Peer::start(replies);
        let forwards = if requested {
            vec![format!(
                "0:127.0.0.1:{}",
                target.local_addr().unwrap().port()
            )]
        } else {
            vec![]
        };
        let mut client = start(&fixture, &peer, &forwards);
        let _stdout = client.ready();
        let handle = peer.handle();
        for (address, port) in [
            ("127.0.0.1", 9000),
            ("LOCALHOST", 9000),
            ("*", 9000),
            ("localhost", 9001),
            ("localhost", 0),
            ("localhost", 65536),
        ] {
            block_on(async {
                let result = handle
                    .channel_open_forwarded_tcpip(address, port, "origin", 1234)
                    .await;
                assert!(
                    matches!(
                        result,
                        Err(russh::Error::ChannelOpenFailure(
                            russh::ChannelOpenFailure::AdministrativelyProhibited
                        ))
                    ),
                    "{address}:{port}: {result:?}"
                );
            });
            assert_eq!(
                target.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        if requested {
            block_on(async {
                let channel = handle
                    .channel_open_forwarded_tcpip("localhost", 9000, "origin", 1234)
                    .await
                    .unwrap();
                assert!(
                    matches!(peer.events.recv_timeout(Duration::from_secs(5)).unwrap(),
                    Event::Confirmed(id) if id == channel.id())
                );
                let (socket, _) = target.accept().unwrap();
                drop(socket);
                channel.close().await.unwrap();
            });
        } else {
            block_on(async {
                assert!(matches!(
                    handle
                        .channel_open_forwarded_tcpip("localhost", 9000, "origin", 1234)
                        .await,
                    Err(russh::Error::ChannelOpenFailure(
                        russh::ChannelOpenFailure::AdministrativelyProhibited
                    ))
                ));
            });
        }
        assert!(client.0.try_wait().unwrap().is_none());
        finish(&peer, &handle, &mut client, 0);
    }
}
