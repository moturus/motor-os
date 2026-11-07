use super::local_forwarding::Client;
use super::*;
use std::net::{TcpListener, TcpStream};

#[test]
fn remote_setup_failure_warns_or_releases_all_listeners_before_command_start() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    let blocked = TcpListener::bind("127.0.0.1:0").unwrap();
    for exit in [false, true] {
        let (remote, _remote_guard) = reserve_tcp_port();
        let (local, _local_guard) = reserve_tcp_port();
        let mut args = fixture.ssh_args();
        args.extend([
            "-L".into(),
            format!("127.0.0.1:{}:localhost:80", local.port()),
            "-R".into(),
            format!("127.0.0.1:{}:localhost:80", remote.port()),
            "-R".into(),
            format!(
                "127.0.0.1:{}:localhost:80",
                blocked.local_addr().unwrap().port()
            ),
            format!("-oExitOnForwardFailure={}", if exit { "yes" } else { "no" }),
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
            if exit { b"".as_slice() } else { b"command-ran" }
        );
        let errors = String::from_utf8(output.stderr).unwrap();
        assert_eq!(errors.lines().count(), 1, "{errors}");
        if exit {
            assert_eq!(errors, format!("ssh: {}\n", russh::Error::RequestDenied));
        } else {
            assert!(errors.contains("remote forward"), "{errors}");
        }
        assert!(TcpStream::connect(local).is_err());
        assert!(TcpStream::connect(remote).is_err());
    }
}

#[test]
fn remote_target_refusal_closes_only_the_forward_and_prints_one_error() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    let (target, _target_guard) = reserve_tcp_port();
    let (remote, _remote_guard) = reserve_tcp_port();
    let mut args = fixture.ssh_args();
    args.extend([
        "-R".into(),
        format!("127.0.0.1:{}:127.0.0.1:{}", remote.port(), target.port()),
        "-oExitOnForwardFailure=yes".into(),
        "motor@127.0.0.1".into(),
        "printf ready; cat".into(),
    ]);
    let mut client = Client::start(&args);
    let mut stdout = client.ready();
    let mut socket = TcpStream::connect(remote).unwrap();
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
    assert!(errors.contains("ssh: remote forward to"), "{errors}");
}
