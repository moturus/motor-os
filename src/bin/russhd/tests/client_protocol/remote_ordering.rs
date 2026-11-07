use super::remote_peer::{Event, Peer, Reply};
use super::remote_policy::{finish, start};
use super::*;
use std::net::{Shutdown, TcpListener};

#[test]
fn an_open_for_a_later_request_waits_for_that_requests_actual_reply() {
    let fixture = Fixture::start();
    for accepted in [false, true] {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        first.set_nonblocking(true).unwrap();
        second.set_nonblocking(true).unwrap();
        let peer = Peer::start(vec![
            Reply {
                accepted: true,
                allocated: 9000,
                early_opens: vec![("localhost".into(), 9001)],
            },
            Reply {
                accepted,
                allocated: 9001,
                early_opens: vec![],
            },
        ]);
        let mut client = start(
            &fixture,
            &peer,
            &[
                format!("0:127.0.0.1:{}", first.local_addr().unwrap().port()),
                format!("0:127.0.0.1:{}", second.local_addr().unwrap().port()),
            ],
        );
        let _stdout = client.ready();
        let handle = peer.handle();
        if accepted {
            let id = match peer.events.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Confirmed(id) => id,
                _ => panic!("accepted second request did not authorize its open"),
            };
            let (socket, _) = second.accept().unwrap();
            block_on(handle.eof(id)).unwrap();
            drop(socket);
        } else {
            block_on(async {
                assert!(matches!(
                    handle
                        .channel_open_forwarded_tcpip("localhost", 9001, "origin", 1234)
                        .await,
                    Err(russh::Error::ChannelOpenFailure(
                        russh::ChannelOpenFailure::AdministrativelyProhibited
                    ))
                ));
            });
        }
        finish(&peer, &handle, &mut client, 0);
        assert_eq!(
            first.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        if !accepted {
            assert_eq!(
                second.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(peer.events.try_recv().is_err());
        }
    }
}

#[test]
fn command_close_denies_new_opens_while_an_admitted_remote_forward_drains() {
    let fixture = Fixture::start();
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let peer = Peer::start(vec![Reply {
        accepted: true,
        allocated: 9000,
        early_opens: vec![],
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
    let (mut channel, credit) = block_on(handle.channel_open_forwarded_tcpip_with_credit(
        "localhost",
        9000,
        "origin",
        1234,
    ))
    .unwrap();
    credit.defer_close();
    let (mut socket, _) = target.accept().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let session = peer.sessions.recv_timeout(Duration::from_secs(5)).unwrap();
    block_on(async {
        handle.exit_status_request(session.id(), 7).await.unwrap();
        handle.eof(session.id()).await.unwrap();
        handle.close(session.id()).await.unwrap();
        // This open follows session close on the wire, while the first relay
        // holds its task reservation and keeps the SSH connection alive.
        assert!(matches!(
            handle
                .channel_open_forwarded_tcpip("localhost", 9000, "origin", 1234)
                .await,
            Err(russh::Error::ChannelOpenFailure(
                russh::ChannelOpenFailure::AdministrativelyProhibited
            ))
        ));
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(client.0.try_wait().unwrap().is_none());
        channel.data(b"after-session".as_slice()).await.unwrap();
        channel.eof().await.unwrap();
    });
    let mut request = Vec::new();
    socket.read_to_end(&mut request).unwrap();
    assert_eq!(request, b"after-session");
    socket.write_all(b"drained").unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
    block_on(async {
        let mut response = Vec::new();
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    response.extend_from_slice(&data);
                    credit.consumed(data.len() as u32);
                }
                Some(russh::ChannelMsg::Eof) => break,
                Some(russh::ChannelMsg::WindowAdjusted { .. }) => {}
                message => panic!("unexpected draining event: {message:?}"),
            }
        }
        assert_eq!(response, b"drained");
        channel.close().await.unwrap();
        credit.wait_closed().await.unwrap();
    });
    assert_eq!(client.wait().code(), Some(7));
}
