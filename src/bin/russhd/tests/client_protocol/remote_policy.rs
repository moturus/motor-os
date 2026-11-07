use super::local_forwarding::Client;
use super::remote_peer::{Event, Peer, Reply};
use super::*;
use std::net::{Shutdown, TcpListener};

pub(super) fn start(fixture: &Fixture, peer: &Peer, forwards: &[String]) -> Client {
    let mut args = fixture.ssh_args();
    args[3] = peer.port.to_string();
    for forward in forwards {
        args.extend(["-R".into(), forward.clone()]);
    }
    args.extend(["motor@127.0.0.1".into(), "controlled-command".into()]);
    Client::start(&args)
}

pub(super) fn finish(
    peer: &Peer,
    handle: &russh::server::Handle,
    client: &mut Client,
    status: u32,
) {
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

#[test]
fn early_open_uses_the_allocated_key_after_setup_and_transfers_both_directions() {
    let fixture = Fixture::start();
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let peer = Peer::start(vec![Reply {
        accepted: true,
        allocated: 9000,
        early_opens: vec![("localhost".into(), 9000)],
    }]);
    let mut client = start(
        &fixture,
        &peer,
        &[format!(
            "0:127.0.0.1:{}",
            target.local_addr().unwrap().port()
        )],
    );
    let _stdout = client.ready();
    let handle = peer.handle();
    let id = match peer.events.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Confirmed(id) => id,
        _ => panic!("early forwarded open was not confirmed"),
    };
    let (mut socket, _) = target.accept().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    block_on(handle.data(id, b"early".as_slice())).unwrap();
    let mut data = [0; 5];
    socket.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"early");
    socket.write_all(b"reply").unwrap();
    match peer.events.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Data(found, bytes) => {
            assert_eq!(found, id);
            assert_eq!(bytes, b"reply");
        }
        _ => panic!("early forwarded response was lost"),
    }
    socket.shutdown(Shutdown::Write).unwrap();
    assert!(
        matches!(peer.events.recv_timeout(Duration::from_secs(5)).unwrap(), Event::Eof(found) if found == id)
    );
    block_on(handle.eof(id)).unwrap();
    assert_eq!(socket.read(&mut [0]).unwrap(), 0);
    finish(&peer, &handle, &mut client, 7);
}

#[test]
fn failed_requests_and_invalid_allocations_never_authorize_an_early_open() {
    let fixture = Fixture::start();
    for (accepted, allocated) in [(false, 9000), (true, 0), (true, 65536), (true, u32::MAX)] {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let peer = Peer::start(vec![Reply {
            accepted,
            allocated,
            early_opens: vec![("localhost".into(), 9000)],
        }]);
        let mut client = start(
            &fixture,
            &peer,
            &[format!(
                "0:127.0.0.1:{}",
                target.local_addr().unwrap().port()
            )],
        );
        let _stdout = client.ready();
        let handle = peer.handle();
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
        finish(&peer, &handle, &mut client, 0);
        // Normal exit drains the early-open task too. A forbidden dial would
        // leave a connection in this listener's backlog even after SSH exits.
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(peer.events.try_recv().is_err());
        let mut errors = String::new();
        client
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut errors)
            .unwrap();
        assert_eq!(errors.lines().count(), 1, "{errors}");
        assert!(errors.contains("Warning: remote forward"), "{errors}");
        assert!(!errors.contains("Allocated port"), "{errors}");
    }
}
