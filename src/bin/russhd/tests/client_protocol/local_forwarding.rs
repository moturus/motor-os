use super::*;
use std::net::{Shutdown, TcpListener, TcpStream};

struct Client(Child);

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Client {
    fn start(args: &[String]) -> Self {
        Self(
            Command::new(SSH)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "SSH client did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn ready(&mut self) -> std::process::ChildStdout {
        let mut stdout = self.0.stdout.take().unwrap();
        let (ready, readiness) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut bytes = [0; 5];
            ready
                .send(stdout.read_exact(&mut bytes).map(|()| bytes))
                .unwrap();
            stdout
        });
        assert_eq!(
            readiness
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            *b"ready"
        );
        reader.join().unwrap()
    }
}

#[test]
fn local_forward_round_trip_half_close_keeps_session_alive_and_drains_after_exit() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_port = target.local_addr().unwrap().port();
    let available = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = available.local_addr().unwrap();
    drop(available);
    let mut args = fixture.ssh_args();
    args.extend([
        "-L".into(),
        format!("127.0.0.1:{}:localhost:{target_port}", local.port()),
        "motor@127.0.0.1".into(),
        "printf ready; cat; exit 7".into(),
    ]);
    let mut client = Client::start(&args);
    let mut stdout = client.ready();

    for sequence in 0..2 {
        let mut socket = TcpStream::connect(local).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (mut remote, _) = target.accept().unwrap();
        remote
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        if sequence == 1 {
            // The command exits while this admitted forward is still active.
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
        }
        let payload = vec![sequence; 256 * 1024];
        let expected = payload.clone();
        let echo = std::thread::spawn(move || {
            let mut received = Vec::new();
            remote.read_to_end(&mut received).unwrap();
            assert_eq!(received, expected);
            remote.write_all(&received).unwrap();
            remote.shutdown(Shutdown::Write).unwrap();
        });
        socket.write_all(&payload).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        let mut output = Vec::new();
        socket.read_to_end(&mut output).unwrap();
        assert_eq!(output, payload);
        echo.join().unwrap();
        if sequence == 0 {
            assert!(client.0.try_wait().unwrap().is_none());
            client
                .0
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"session-alive")
                .unwrap();
            let mut marker = [0; 13];
            stdout.read_exact(&mut marker).unwrap();
            assert_eq!(&marker, b"session-alive");
        }
    }
    assert_eq!(client.wait().code(), Some(7));
    assert!(TcpStream::connect(local).is_err());
}

#[test]
fn local_setup_failure_warns_or_exits_before_starting_the_command() {
    let fixture = Fixture::start();
    let blocked = TcpListener::bind("127.0.0.1:0").unwrap();
    for exit in [false, true] {
        let available = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = available.local_addr().unwrap();
        drop(available);
        let mut args = fixture.ssh_args();
        args.extend([
            "-L".into(),
            format!("127.0.0.1:{}:localhost:80", local.port()),
            "-L".into(),
            format!(
                "127.0.0.1:{}:localhost:80",
                blocked.local_addr().unwrap().port()
            ),
            "-o".into(),
            format!("ExitOnForwardFailure={}", if exit { "yes" } else { "no" }),
            "motor@127.0.0.1".into(),
            "printf command-ran".into(),
        ]);
        let output = fixture.run(&args, b"");
        assert_eq!(
            output.status.code(),
            Some(if exit { 255 } else { 0 }),
            "{output:?}"
        );
        assert_eq!(
            output.stdout,
            if exit {
                b"".as_slice()
            } else {
                b"command-ran".as_slice()
            }
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("local forward"),
            "{output:?}"
        );
        assert!(TcpStream::connect(local).is_err());
    }
}

#[test]
fn target_refusal_closes_only_that_socket_and_prints_one_error() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    // Reserve a destination port without listening, so refusal is deterministic.
    let refused = block_on(async {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        socket
    });
    let available = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = available.local_addr().unwrap();
    drop(available);
    let mut args = fixture.ssh_args();
    args.extend([
        "-L".into(),
        format!(
            "127.0.0.1:{}:127.0.0.1:{}",
            local.port(),
            refused.local_addr().unwrap().port()
        ),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "motor@127.0.0.1".into(),
        "printf ready; cat".into(),
    ]);
    let mut client = Client::start(&args);
    let mut stdout = client.ready();
    let mut socket = TcpStream::connect(local).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert_eq!(socket.read(&mut [0]).unwrap(), 0);
    client
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"still-alive")
        .unwrap();
    let mut output = Vec::new();
    stdout.read_to_end(&mut output).unwrap();
    assert_eq!(output, b"still-alive");
    assert!(client.wait().success());
    let mut errors = String::new();
    client
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut errors)
        .unwrap();
    assert_eq!(errors.lines().count(), 1, "{errors}");
    assert!(errors.contains("ssh: forward to"), "{errors}");
}

#[test]
fn configured_local_forward_runs_only_on_final_ssh_hop_and_not_on_scp_or_sftp() {
    let jump = Fixture::configured("allow_tcp_forwarding = true");
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let blocked_jump = TcpListener::bind("127.0.0.1:0").unwrap();
    let available = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = available.local_addr().unwrap();
    let path = fixture.root.join("local-forward-config");
    std::fs::write(&path, format!(
        "Host jump\nHostName 127.0.0.1\nPort {}\nLocalForward 127.0.0.1:{} localhost:80\nHost final\nHostName 127.0.0.1\nPort {}\nProxyJump jump\nLocalForward 127.0.0.1:{} localhost:{}\nHost *\nUser motor\nIdentityFile {}\nUserKnownHostsFile {}\nStrictHostKeyChecking accept-new\nBatchMode yes\nExitOnForwardFailure yes\n",
        jump.port, blocked_jump.local_addr().unwrap().port(), fixture.port, local.port(), target.local_addr().unwrap().port(), fixture.identity.display(), fixture.known_hosts.display(),
    )).unwrap();
    let config = vec!["-F".to_owned(), path.display().to_string()];
    let source = fixture.root.join("local-forward-source");
    let destination = fixture.root.join("local-forward-destination");
    std::fs::write(&source, b"scp without listeners").unwrap();
    let scp = [
        vec!["--motor-applet=scp".into()],
        config.clone(),
        vec![
            source.display().to_string(),
            format!("final:{}", destination.display()),
        ],
    ]
    .concat();
    let output = fixture.run(&scp, b"");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read(destination).unwrap(),
        b"scp without listeners"
    );
    let batch = fixture.root.join("local-forward-batch");
    std::fs::write(&batch, "pwd\n").unwrap();
    let sftp = [
        vec!["--motor-applet=sftp".into()],
        config.clone(),
        vec!["-b".into(), batch.display().to_string(), "final".into()],
    ]
    .concat();
    let output = fixture.run(&sftp, b"");
    assert!(output.status.success(), "{output:?}");
    drop(available);
    let args = [config, vec!["final".into(), "printf ready; cat".into()]].concat();
    let mut client = Client::start(&args);
    let _stdout = client.ready();
    let mut socket = TcpStream::connect(local).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.write_all(b"through-jump").unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
    let (mut remote, _) = target.accept().unwrap();
    let mut bytes = Vec::new();
    remote.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"through-jump");
    remote.write_all(b"reply").unwrap();
    remote.shutdown(Shutdown::Write).unwrap();
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"reply");
    drop(client.0.stdin.take());
    assert!(client.wait().success());
}
