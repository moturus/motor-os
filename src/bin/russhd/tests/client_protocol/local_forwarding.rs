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
    let mut stdout = client.0.stdout.take().unwrap();
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
    let mut stdout = reader.join().unwrap();

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
