use super::local_forwarding::Client;
use super::*;
use std::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn configured_remote_forwards_run_only_on_the_final_ssh_hop_and_never_for_copy_applets() {
    let jump = Fixture::configured("allow_tcp_forwarding = true");
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let blocked_jump = TcpListener::bind("127.0.0.1:0").unwrap();
    let blocked_final = TcpListener::bind("127.0.0.1:0").unwrap();
    let path = fixture.root.join("remote-forward-config");
    let config_text = |port| {
        format!(
            "Host jump\nHostName 127.0.0.1\nPort {}\nRemoteForward 127.0.0.1:{} localhost:80\nHost final\nHostName 127.0.0.1\nPort {}\nProxyJump jump\nRemoteForward 127.0.0.1:{} localhost:{}\nHost *\nUser motor\nIdentityFile {}\nUserKnownHostsFile {}\nStrictHostKeyChecking accept-new\nBatchMode yes\nExitOnForwardFailure yes\n",
            jump.port,
            blocked_jump.local_addr().unwrap().port(),
            fixture.port,
            port,
            target.local_addr().unwrap().port(),
            fixture.identity.display(),
            fixture.known_hosts.display(),
        )
    };
    std::fs::write(
        &path,
        config_text(blocked_final.local_addr().unwrap().port()),
    )
    .unwrap();
    let config = vec!["-F".to_owned(), path.display().to_string()];
    let source = fixture.root.join("remote-forward-source");
    let destination = fixture.root.join("remote-forward-destination");
    std::fs::write(&source, b"copy ignores remote listeners").unwrap();
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
        b"copy ignores remote listeners"
    );
    let batch = fixture.root.join("remote-forward-batch");
    std::fs::write(&batch, "pwd\n").unwrap();
    let sftp = [
        vec!["--motor-applet=sftp".into()],
        config.clone(),
        vec!["-b".into(), batch.display().to_string(), "final".into()],
    ]
    .concat();
    let output = fixture.run(&sftp, b"");
    assert!(output.status.success(), "{output:?}");

    let (remote, _remote_guard) = reserve_tcp_port();
    std::fs::write(&path, config_text(remote.port())).unwrap();
    let args = [config, vec!["final".into(), "printf ready; cat".into()]].concat();
    let mut client = Client::start(&args);
    let mut stdout = client.ready();
    let socket = TcpStream::connect(remote).unwrap();
    socket.set_nonblocking(true).unwrap();
    block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::from_std(target).unwrap();
            let mut socket = tokio::net::TcpStream::from_std(socket).unwrap();
            let sending = async {
                socket.write_all(b"through-jump").await.unwrap();
                socket.shutdown().await.unwrap();
                let mut output = Vec::new();
                socket.read_to_end(&mut output).await.unwrap();
                assert_eq!(output, b"through-jump");
            };
            let echo = async {
                let (mut target, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                target.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, b"through-jump");
                target.write_all(&request).await.unwrap();
                target.shutdown().await.unwrap();
            };
            tokio::join!(sending, echo);
        })
        .await
        .expect("remote forward through jump stalled");
    });
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
    assert!(TcpStream::connect(remote).is_err());
}
