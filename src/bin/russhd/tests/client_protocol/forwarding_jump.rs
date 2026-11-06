use super::*;

#[test]
fn a_real_russhd_jump_relays_streams_scp_and_sftp() {
    let jump = Fixture::configured("allow_tcp_forwarding = true");
    let target = Fixture::start();
    let path = target.root.join("forwarding-config");
    std::fs::write(
        &path,
        format!(
            "Host jump\nHostName 127.0.0.1\nUser motor\nPort {}\nHost target\nHostName 127.0.0.1\nUser motor\nPort {}\nProxyJump jump\nHost *\nIdentityFile {}\nUserKnownHostsFile {}\nStrictHostKeyChecking accept-new\nBatchMode yes\n",
            jump.port, target.port, target.identity.display(), target.known_hosts.display(),
        ),
    ).unwrap();
    let config = vec!["-F".to_owned(), path.display().to_string()];
    for program in [SSH, "ssh"] {
        let mut args = config.clone();
        if program == "ssh" {
            args.extend(["-o".to_owned(), "LogLevel=ERROR".to_owned()]);
        }
        args.extend([
            "target".to_owned(),
            "printf out; printf err >&2; cat; exit 7".to_owned(),
        ]);
        let output = run_full_duplex_with(program, &args, b"input\r\n".to_vec());
        assert_eq!(output.status.code(), Some(7), "{output:?}");
        assert_eq!(output.stdout, b"outinput\r\n");
        assert_eq!(output.stderr, b"err");
    }

    let payload = (0..FULL_DUPLEX_STREAM_SIZE)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    let args = [config.clone(), vec!["target".to_owned(), "cat".to_owned()]].concat();
    let output = run_full_duplex(&args, payload.clone());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, payload);

    let source = target.root.join("forward-source");
    let remote = target.root.join("forward-remote");
    let downloaded = target.root.join("forward-download");
    std::fs::write(&source, &payload).unwrap();
    for (from, to) in [
        (
            source.display().to_string(),
            format!("target:{}", remote.display()),
        ),
        (
            format!("target:{}", remote.display()),
            downloaded.display().to_string(),
        ),
    ] {
        let args = [
            vec!["--motor-applet=scp".to_owned()],
            config.clone(),
            vec![from, to],
        ]
        .concat();
        let output = run_full_duplex(&args, Vec::new());
        assert!(output.status.success(), "{output:?}");
    }
    assert_eq!(std::fs::read(downloaded).unwrap(), payload);

    let batch = target.root.join("forward-batch");
    let sftp_download = target.root.join("forward-sftp-download");
    std::fs::write(
        &batch,
        format!("get {} {}\n", remote.display(), sftp_download.display()),
    )
    .unwrap();
    let args = [
        vec!["--motor-applet=sftp".to_owned()],
        config,
        vec![
            "-b".to_owned(),
            batch.display().to_string(),
            "target".to_owned(),
        ],
    ]
    .concat();
    let output = run_full_duplex(&args, Vec::new());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(sftp_download).unwrap(), payload);
}
