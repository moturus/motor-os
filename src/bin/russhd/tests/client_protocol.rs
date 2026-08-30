#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use russh::server::{Auth, Session};
use russh::{Channel, ChannelId};

const RUSSHD: &str = env!("CARGO_BIN_EXE_russhd");
const SSH: &str = env!("CARGO_BIN_EXE_ssh");

struct Fixture {
    child: Child,
    log_thread: Option<std::thread::JoinHandle<()>>,
    root: PathBuf,
    port: u16,
    known_hosts: PathBuf,
    identity: PathBuf,
}

impl Fixture {
    fn start() -> Self {
        static ID: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "russhd-client-protocol-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sshd.toml");
        let config = std::fs::read_to_string(source)
            .unwrap()
            .replace("0.0.0.0:2222", "127.0.0.1:0")
            .replace("/system/bin:/user/bin", "/bin:/usr/bin");
        let config_path = root.join("sshd.toml");
        std::fs::write(&config_path, config).unwrap();

        let mut child = Command::new(RUSSHD)
            .arg(&config_path)
            .current_dir(&root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (address_tx, address_rx) = std::sync::mpsc::sync_channel(1);
        let log_thread = std::thread::spawn(move || {
            let mut sent = false;
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if !sent && let Some(address) = line.split("Listening on ").nth(1) {
                    let _ = address_tx.send(address.trim().to_owned());
                    sent = true;
                }
            }
        });
        let address = address_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("russhd did not report its listening address");
        let port = address.rsplit(':').next().unwrap().parse().unwrap();
        Self {
            child,
            log_thread: Some(log_thread),
            known_hosts: root.join("known_hosts"),
            identity: Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/test.key"),
            root,
            port,
        }
    }

    fn base_args(&self, applet: Option<&str>) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(applet) = applet {
            args.push(format!("--motor-applet={applet}"));
        }
        args.extend([
            "-P".to_owned(),
            self.port.to_string(),
            "-i".to_owned(),
            self.identity.to_string_lossy().into_owned(),
            "-o".to_owned(),
            "IdentitiesOnly=yes".to_owned(),
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=accept-new".to_owned(),
            "-o".to_owned(),
            format!("UserKnownHostsFile={}", self.known_hosts.display()),
        ]);
        args
    }

    fn ssh_args(&self) -> Vec<String> {
        let mut args = self.base_args(None);
        args[0] = "-p".to_owned();
        args
    }

    fn run(&self, args: &[String], input: &[u8]) -> Output {
        let mut child = Command::new(SSH)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(thread) = self.log_thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const FULL_DUPLEX_STREAM_SIZE: usize = 8 * 1024 * 1024;

#[derive(Clone)]
struct OutputOnlyServer;

impl russh::server::Server for OutputOnlyServer {
    type Handler = Self;

    fn new_client(&mut self, _addr: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl russh::server::Handler for OutputOnlyServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let handle = session.handle();
        tokio::spawn(async move {
            let _ = handle
                .data(channel, vec![0_u8; FULL_DUPLEX_STREAM_SIZE])
                .await;
            let _ = handle.exit_status_request(channel, 0).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }

    fn adjust_window(&mut self, _channel: ChannelId, _current: u32) -> u32 {
        // Stop replenishing the receive window: this command deliberately does
        // not consume stdin while it writes more than one window of stdout.
        1
    }
}

fn start_output_only_server() -> (std::thread::JoinHandle<()>, u16) {
    let (address_tx, address_rx) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                address_tx.send(listener.local_addr().unwrap()).unwrap();
                let (socket, _) = listener.accept().await.unwrap();
                let config = russh::server::Config {
                    keys: vec![
                        russh::keys::PrivateKey::random(
                            &mut rand::rng(),
                            russh::keys::ssh_key::Algorithm::Ed25519,
                        )
                        .unwrap(),
                    ],
                    ..Default::default()
                };
                let running = russh::server::run_stream(
                    std::sync::Arc::new(config),
                    socket,
                    OutputOnlyServer,
                )
                .await
                .unwrap();
                let _ = running.await;
            });
    });
    let port = address_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("test SSH server did not report its listening address")
        .port();
    (thread, port)
}

fn run_full_duplex(args: &[String], input: Vec<u8>) -> Output {
    let mut child = Command::new(SSH)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let input_thread = std::thread::spawn(move || stdin.write_all(&input));
    let output_thread = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let error_thread = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = input_thread.join();
            let stdout = output_thread.join().unwrap().unwrap();
            let stderr = error_thread.join().unwrap().unwrap();
            panic!(
                "ssh did not finish full-duplex relay: {} stdout bytes, stderr: {}",
                stdout.len(),
                String::from_utf8_lossy(&stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    match input_thread.join().unwrap() {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(error) => panic!("writing ssh stdin failed: {error}"),
    }
    Output {
        status,
        stdout: output_thread.join().unwrap().unwrap(),
        stderr: error_thread.join().unwrap().unwrap(),
    }
}

#[test]
fn command_and_sftp_transfers_work_end_to_end() {
    let fixture = Fixture::start();
    let mut ssh = fixture.ssh_args();
    ssh.extend([
        "motor@127.0.0.1".to_owned(),
        "printf out; printf err >&2; cat; exit 7".to_owned(),
    ]);
    let output = fixture.run(&ssh, b"stdin\n");
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"outstdin\n");
    assert_eq!(output.stderr, b"err");

    let source = fixture.root.join("source");
    let remote = fixture.root.join("remote");
    let downloaded = fixture.root.join("downloaded");
    std::fs::write(&source, vec![0x5a; 384 * 1024]).unwrap();
    let mut upload = fixture.base_args(Some("scp"));
    upload.extend([
        source.to_string_lossy().into_owned(),
        format!("motor@127.0.0.1:{}", remote.display()),
    ]);
    let output = fixture.run(&upload, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut download = fixture.base_args(Some("scp"));
    download.extend([
        format!("motor@127.0.0.1:{}", remote.display()),
        downloaded.to_string_lossy().into_owned(),
    ]);
    let output = fixture.run(&download, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(source).unwrap(),
        std::fs::read(downloaded).unwrap()
    );

    let remote_dir = fixture.root.join("sftp-dir");
    let batch_download = fixture.root.join("batch-download");
    let batch = fixture.root.join("batch");
    std::fs::write(
        &batch,
        format!(
            "mkdir {}\nput {} {}/put\nls {}\nrename {}/put {}/renamed\nget {}/renamed {}\nrm {}/renamed\nrmdir {}\n",
            remote_dir.display(),
            fixture.root.join("source").display(),
            remote_dir.display(),
            remote_dir.display(),
            remote_dir.display(),
            remote_dir.display(),
            remote_dir.display(),
            batch_download.display(),
            remote_dir.display(),
            remote_dir.display(),
        ),
    )
    .unwrap();
    let mut sftp = fixture.base_args(Some("sftp"));
    sftp.extend([
        "-b".to_owned(),
        batch.to_string_lossy().into_owned(),
        "motor@127.0.0.1".to_owned(),
    ]);
    let output = fixture.run(&sftp, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(fixture.root.join("source")).unwrap(),
        std::fs::read(batch_download).unwrap()
    );

    let generated = fixture.root.join("generated");
    let keygen = vec![
        "--motor-applet=ssh-keygen".to_owned(),
        "-q".to_owned(),
        "-t".to_owned(),
        "ed25519".to_owned(),
        "-N".to_owned(),
        String::new(),
        "-f".to_owned(),
        generated.to_string_lossy().into_owned(),
    ];
    let output = fixture.run(&keygen, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let replacement = std::fs::read_to_string(generated.with_extension("pub")).unwrap();
    std::fs::write(
        &fixture.known_hosts,
        format!("[127.0.0.1]:{} {}", fixture.port, replacement),
    )
    .unwrap();
    let mut changed = fixture.ssh_args();
    changed.extend(["motor@127.0.0.1".to_owned(), "true".to_owned()]);
    assert_eq!(fixture.run(&changed, b"").status.code(), Some(255));
}

#[test]
fn command_drains_output_while_remote_does_not_read_large_stdin() {
    let (server_thread, port) = start_output_only_server();
    let known_hosts = std::env::temp_dir().join(format!(
        "russhd-full-duplex-known-hosts-{}",
        std::process::id()
    ));
    let ssh = vec![
        "-p".to_owned(),
        port.to_string(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=accept-new".to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "motor@127.0.0.1".to_owned(),
        "output-only".to_owned(),
    ];
    let output = run_full_duplex(&ssh, vec![0x5a; FULL_DUPLEX_STREAM_SIZE]);
    server_thread.join().unwrap();
    let _ = std::fs::remove_file(known_hosts);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout.len(), FULL_DUPLEX_STREAM_SIZE);
    assert!(output.stdout.iter().all(|byte| *byte == 0));
}
