use super::local_forwarding::Client;
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn start(fixture: &Fixture) -> (Client, std::process::ChildStdout, std::net::SocketAddr) {
    let available = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = available.local_addr().unwrap();
    drop(available);
    let mut args = fixture.ssh_args();
    args.extend([
        "-D".into(),
        format!("127.0.0.1:{}", address.port()),
        "motor@127.0.0.1".into(),
        "printf ready; cat".into(),
    ]);
    let mut client = Client::start(&args);
    let stdout = client.ready();
    (client, stdout, address)
}

fn request(kind: u8, port: u16) -> Vec<u8> {
    let mut wire = match kind {
        0 => vec![4, 1],
        1 => vec![4, 1],
        _ => vec![5, 1, 0, 5, 1, 0],
    };
    if kind < 2 {
        wire.extend(port.to_be_bytes());
        wire.extend(if kind == 0 {
            [127, 0, 0, 1]
        } else {
            [0, 0, 0, 1]
        });
        wire.push(0);
        if kind == 1 {
            wire.extend(b"localhost\0");
        }
    } else {
        match kind {
            2 => wire.extend([1, 127, 0, 0, 1]),
            3 => {
                wire.extend([3, 9]);
                wire.extend(b"localhost");
            }
            4 => {
                wire.push(4);
                wire.extend(std::net::Ipv6Addr::LOCALHOST.octets());
            }
            _ => unreachable!(),
        }
        wire.extend(port.to_be_bytes());
    }
    wire
}

#[test]
fn dynamic_forwarding_supports_all_address_forms_and_preserves_pipelined_payload() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    let (mut client, _stdout, local) = start(&fixture);
    block_on(async {
        for kind in 0..5 {
            let target = TcpListener::bind(if kind == 4 { "[::1]:0" } else { "127.0.0.1:0" })
                .await
                .unwrap();
            let mut application = TcpStream::connect(local).await.unwrap();
            let mut wire = request(kind, target.local_addr().unwrap().port());
            wire.extend(b"pipelined-payload");
            application.write_all(&wire).await.unwrap();
            application.shutdown().await.unwrap();
            let (mut target, _) = target.accept().await.unwrap();
            let mut bytes = Vec::new();
            target.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"pipelined-payload");
            target.write_all(b"dynamic-reply").await.unwrap();
            target.shutdown().await.unwrap();
            let mut response = Vec::new();
            application.read_to_end(&mut response).await.unwrap();
            let header: &[u8] = if kind < 2 {
                &[0, 90, 0, 0, 0, 0, 0, 0]
            } else {
                &[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
            };
            assert_eq!(&response[..header.len()], header);
            assert_eq!(&response[header.len()..], b"dynamic-reply");
        }
    });
    drop(client.0.stdin.take());
    assert!(client.wait().success());
    assert!(std::net::TcpStream::connect(local).is_err());
}

#[test]
fn stalled_or_invalid_handshakes_leave_the_connection_responsive_and_cancel_on_loss() {
    let mut fixture = Fixture::configured("allow_tcp_forwarding = true");
    let (mut client, mut stdout, local) = start(&fixture);
    block_on(async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port().to_be_bytes();
        let mut stalled = TcpStream::connect(local).await.unwrap();
        stalled.write_all(&[5, 1]).await.unwrap();
        let mut oversized_user = vec![4, 1, port[0], port[1], 127, 0, 0, 1];
        oversized_user.extend(vec![b'u'; 1025]);
        let mut unsupported = request(2, target.local_addr().unwrap().port());
        unsupported[4] = 3;
        for (wire, expected) in [
            (vec![6], vec![]),
            (
                vec![4, 2, port[0], port[1], 127, 0, 0, 1],
                vec![0, 91, 0, 0, 0, 0, 0, 0],
            ),
            (oversized_user, vec![0, 91, 0, 0, 0, 0, 0, 0]),
            (vec![5, 1, 2], vec![5, 0xff]),
            (unsupported, vec![5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]),
            (
                vec![5, 1, 0, 5, 1, 0, 0xff],
                vec![5, 0, 5, 8, 0, 1, 0, 0, 0, 0, 0, 0],
            ),
        ] {
            let mut application = TcpStream::connect(local).await.unwrap();
            application.write_all(&wire).await.unwrap();
            application.shutdown().await.unwrap();
            let mut response = Vec::new();
            application.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, expected);
        }
        tokio::select! {
            biased;
            socket = target.accept() => panic!("invalid handshake dialled a target: {socket:?}"),
            () = std::future::ready(()) => {}
        }
        client
            .0
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"still-alive")
            .unwrap();
        let mut marker = [0; 11];
        stdout.read_exact(&mut marker).unwrap();
        assert_eq!(&marker, b"still-alive");
        // The stalled handshake retains a shared peer until cancellation.
        fixture.child.kill().unwrap();
        fixture.child.wait().unwrap();
        assert_eq!(client.wait().code(), Some(255));
        assert_eq!(stalled.read(&mut [0]).await.unwrap(), 0);
    });
    assert!(std::net::TcpStream::connect(local).is_err());
}
