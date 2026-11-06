use super::local_forwarding::Client;
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

fn arguments(fixture: &Fixture, port: u16) -> (Vec<String>, std::net::SocketAddr) {
    let available = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local = available.local_addr().unwrap();
    let mut args = fixture.ssh_args();
    args.extend([
        "-L".into(),
        format!("127.0.0.1:{}:127.0.0.1:{port}", local.port()),
        "motor@127.0.0.1".into(),
        "printf ready; cat".into(),
    ]);
    (args, local)
}

#[test]
fn a_local_reader_that_stops_does_not_park_another_forward_or_the_command() {
    let mut fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (args, local) = arguments(&fixture, target.local_addr().unwrap().port());
        let mut client = Client::start(&args);
        let mut stdout = client.ready();
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(64 * 1024).unwrap();
        let _stalled = socket.connect(local).await.unwrap();
        let (mut flooding, _) = target.accept().await.unwrap();
        let payload = vec![0x5a; 2 * FULL_DUPLEX_STREAM_SIZE];
        let sending = flooding.write_all(&payload);
        tokio::pin!(sending);
        tokio::select! {
            biased;
            result = &mut sending => panic!("flood completed before filling the stalled path: {result:?}"),
            () = async {
                let mut socket = TcpStream::connect(local).await.unwrap();
                let (mut remote, _) = target.accept().await.unwrap();
                socket.write_all(b"another-forward").await.unwrap();
                socket.shutdown().await.unwrap();
                let mut bytes = Vec::new();
                remote.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"another-forward");
                remote.write_all(b"responsive").await.unwrap();
                remote.shutdown().await.unwrap();
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"responsive");
            } => {}
        }
        client
            .0
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"command-alive")
            .unwrap();
        let mut marker = [0; 13];
        stdout.read_exact(&mut marker).unwrap();
        assert_eq!(&marker, b"command-alive");
        tokio::select! {
            biased;
            result = &mut sending => panic!("stalled reader consumed the complete flood: {result:?}"),
            () = std::future::ready(()) => {}
        }
        // The slow reader deliberately never drains; transport failure must
        // cancel that relay and release its listener independently of writes.
        fixture.child.kill().unwrap();
        fixture.child.wait().unwrap();
        assert_eq!(client.wait().code(), Some(255));
        assert!(std::net::TcpStream::connect(local).is_err());
    });
}

#[test]
fn both_tcp_peers_can_write_a_complete_ssh_window_before_reading() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (args, local) = arguments(&fixture, target.local_addr().unwrap().port());
        let mut client = Client::start(&args);
        let _stdout = client.ready();
        let mut socket = TcpStream::connect(local).await.unwrap();
        let (mut remote, _) = target.accept().await.unwrap();
        let window = russh::client::Config::default().window_size as usize;
        let outgoing = vec![0xa5; window];
        let incoming = vec![0x5a; window];
        tokio::join!(
            async {
                socket.write_all(&outgoing).await.unwrap();
                socket.shutdown().await.unwrap();
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, incoming);
            },
            async {
                remote.write_all(&incoming).await.unwrap();
                remote.shutdown().await.unwrap();
                let mut bytes = Vec::new();
                remote.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, outgoing);
            },
        );
        drop(client.0.stdin.take());
        assert!(client.wait().success());
    });
}
