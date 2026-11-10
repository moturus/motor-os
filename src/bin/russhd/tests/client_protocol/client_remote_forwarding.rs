use super::local_forwarding::Client;
use super::*;
use std::net::{Shutdown, TcpListener, TcpStream};

#[test]
fn remote_forward_round_trip_half_close_and_command_exit_preserve_admitted_relays() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_port = target.local_addr().unwrap().port();
    let (remote, _port_guard) = reserve_tcp_port();
    let mut args = fixture.ssh_args();
    args.extend([
        "-R".into(),
        format!("127.0.0.1:{}:localhost:{target_port}", remote.port()),
        "-oExitOnForwardFailure=yes".into(),
        "motor@127.0.0.1".into(),
        "printf ready; cat; exit 7".into(),
    ]);
    let mut client = Client::start(&args);
    let mut stdout = client.ready();
    for sequence in 0..2 {
        let mut socket = TcpStream::connect(remote).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (mut local, _) = target.accept().unwrap();
        local
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        if sequence == 1 {
            client
                .0
                .stdin
                .take()
                .unwrap()
                .write_all(b"command-ended")
                .unwrap();
            let mut marker = [0; 13];
            stdout.read_exact(&mut marker).unwrap();
            assert_eq!(&marker, b"command-ended");
            assert!(client.0.try_wait().unwrap().is_none());
        }
        let payload =
            vec![sequence; russh::client::Config::default().window_size as usize + 32 * 1024];
        let expected = payload.clone();
        let echo = std::thread::spawn(move || {
            let mut received = Vec::new();
            local.read_to_end(&mut received).unwrap();
            assert_eq!(
                received.len(),
                expected.len(),
                "request length for sequence {sequence}"
            );
            assert!(
                received == expected,
                "request bytes changed for sequence {sequence}"
            );
            local.write_all(&received).unwrap();
            local.shutdown(Shutdown::Write).unwrap();
        });
        socket.write_all(&payload).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        let mut output = Vec::new();
        socket.read_to_end(&mut output).unwrap();
        assert_eq!(
            output.len(),
            payload.len(),
            "response length for sequence {sequence}"
        );
        assert!(
            output == payload,
            "response bytes changed for sequence {sequence}"
        );
        echo.join().unwrap();
        if sequence == 0 {
            assert!(client.0.try_wait().unwrap().is_none());
        }
    }
    assert_eq!(client.wait().code(), Some(7));
    // Remote listener cleanup is asynchronous and covered by remote_relay.
}

#[test]
fn allocated_remote_port_is_reported_and_sessionless_tunnel_survives_forward_eof() {
    let mut fixture = Fixture::configured("allow_tcp_forwarding = true");
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut args = fixture.ssh_args();
    args.extend([
        "-N".into(),
        "-t".into(),
        "-R".into(),
        format!("0:127.0.0.1:{}", target.local_addr().unwrap().port()),
        "-oExitOnForwardFailure=yes".into(),
        "motor@127.0.0.1".into(),
    ]);
    let mut client = Client::start(&args);
    let stderr = client.0.stderr.take().unwrap();
    let (ports, allocated) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if let Some(rest) = line.strip_prefix("Allocated port ") {
                ports
                    .send(
                        rest.split_whitespace()
                            .next()
                            .unwrap()
                            .parse::<u16>()
                            .unwrap(),
                    )
                    .unwrap();
            }
            lines.push(line);
        }
        lines
    });
    let port = allocated.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_ne!(port, 0);
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (mut local, _) = target.accept().unwrap();
    local
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.write_all(b"remote").unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
    let mut request = Vec::new();
    local.read_to_end(&mut request).unwrap();
    assert_eq!(request, b"remote");
    local.write_all(b"allocated").unwrap();
    local.shutdown(Shutdown::Write).unwrap();
    let mut output = Vec::new();
    socket.read_to_end(&mut output).unwrap();
    assert_eq!(output, b"allocated");
    drop(client.0.stdin.take());
    assert!(client.0.try_wait().unwrap().is_none());
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    assert_eq!(client.wait().code(), Some(255));
    assert_eq!(
        reader
            .join()
            .unwrap()
            .iter()
            .filter(|line| line.starts_with("Allocated port "))
            .count(),
        1
    );
}
