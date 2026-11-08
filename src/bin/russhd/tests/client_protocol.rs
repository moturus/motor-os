#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use russh::server::{Auth, Session};
use russh::{Channel, ChannelId};

#[path = "client_protocol/client_remote_forwarding.rs"]
mod client_remote_forwarding;
#[path = "client_protocol/dynamic_forwarding.rs"]
mod dynamic_forwarding;
#[path = "client_protocol/forwarding.rs"]
mod forwarding;
#[path = "client_protocol/forwarding_jump.rs"]
mod forwarding_jump;
#[path = "client_protocol/forwarding_progress.rs"]
mod forwarding_progress;
#[path = "client_protocol/local_forwarding.rs"]
mod local_forwarding;
#[path = "client_protocol/remote_failures.rs"]
mod remote_failures;
#[path = "client_protocol/remote_forwarding.rs"]
mod remote_forwarding;
#[path = "client_protocol/remote_ordering.rs"]
mod remote_ordering;
#[path = "client_protocol/remote_peer.rs"]
mod remote_peer;
#[path = "client_protocol/remote_policy.rs"]
mod remote_policy;
#[path = "client_protocol/remote_relay.rs"]
mod remote_relay;
#[path = "client_protocol/remote_routes.rs"]
mod remote_routes;
#[path = "client_protocol/tunnel_lifetime.rs"]
mod tunnel_lifetime;

const RUSSHD: &str = env!("CARGO_BIN_EXE_russhd");
const SSH: &str = env!("CARGO_BIN_EXE_ssh");
const SHIPPED_USERS: &str =
    include_str!("../../../../img_files/motor-os-base/user/cfg/russhd/users.toml");
const SHIPPED_KEYS: &str =
    include_str!("../../../../img_files/motor-os-base/user/cfg/ssh/authorized_keys.motor");

fn write_private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A reusable, non-listening reservation leaves no port-allocation gap while
/// the child creates its listener. Keep the returned socket until the test ends.
fn reserve_tcp_port() -> (std::net::SocketAddr, tokio::net::TcpSocket) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    (socket.local_addr().unwrap(), socket)
}

struct Fixture {
    child: Child,
    log_thread: Option<std::thread::JoinHandle<Vec<String>>>,
    root: PathBuf,
    port: u16,
    known_hosts: PathBuf,
    identity: PathBuf,
}

impl Fixture {
    fn start() -> Self {
        Self::configured("")
    }

    fn configured(extra: &str) -> Self {
        static ID: AtomicU64 = AtomicU64::new(0);
        // Credentials must sit in a private tree, which a shared /tmp cannot be.
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "russhd-client-protocol-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        write_private(&root.join("users.toml"), SHIPPED_USERS);
        write_private(&root.join("authorized_keys.motor"), SHIPPED_KEYS);
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sshd.toml");
        let config = std::fs::read_to_string(source)
            .unwrap()
            .replace("0.0.0.0:2222", "127.0.0.1:0")
            .replace("/system/bin:/user/bin", "/bin:/usr/bin")
            .replace(
                "/user/cfg/russhd/users.toml",
                root.join("users.toml").to_str().unwrap(),
            )
            .replace("/user/cfg/ssh", root.to_str().unwrap());
        let config_path = root.join("sshd.toml");
        std::fs::write(&config_path, format!("{config}\n{extra}")).unwrap();

        let mut child = Command::new(RUSSHD)
            .arg(&config_path)
            .current_dir(&root)
            .env("HOME", &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (address_tx, address_rx) = std::sync::mpsc::sync_channel(1);
        let log_thread = std::thread::spawn(move || {
            let mut sent = false;
            let mut lines = Vec::new();
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if !sent && let Some(address) = line.split("Listening on ").nth(1) {
                    let _ = address_tx.send(address.trim().to_owned());
                    sent = true;
                }
                lines.push(line);
            }
            lines
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
            "-F".to_owned(),
            "none".to_owned(),
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
        args[2] = "-p".to_owned();
        args
    }

    fn run_with(&self, program: &str, args: &[String], input: &[u8]) -> Output {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn run(&self, args: &[String], input: &[u8]) -> Output {
        self.run_with(SSH, args, input)
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

struct JumpFixture {
    port: u16,
    key: russh::keys::PrivateKey,
    closed: std::sync::mpsc::Receiver<()>,
    requests: std::sync::Arc<std::sync::Mutex<Vec<(String, u32)>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// How a jump fixture moves bytes between its forwarded channel and the target.
#[derive(Clone, Copy)]
enum Relay {
    /// A plain bidirectional copy, as an ordinary jump host does.
    Direct,
    /// Provokes the stall of a session stacked on a jump channel: the jump
    /// advertises a small window with 1 KiB packets, forwards the client's
    /// first 96 KiB, then reads nothing from the client for two seconds while
    /// it relays the target's output in 512-byte pieces. With `sleep 1; cat`
    /// on the target, hundreds of small packets reach the client while its
    /// window is exhausted and no window adjustment has been sent yet.
    StarvedWindow,
}

const STARVED_WINDOW: u32 = 512 * 1024;
const STARVED_PACKET: u32 = 1024;
const STARVED_FORWARD_FIRST: usize = 96 * 1024;
const STARVED_PAUSE: Duration = Duration::from_secs(2);
const STARVED_PIECE: usize = 512;

struct JumpHandler {
    user: String,
    identity: russh::keys::PublicKey,
    allowed_port: u16,
    relay: Relay,
    requests: std::sync::Arc<std::sync::Mutex<Vec<(String, u32)>>>,
    closed: std::sync::mpsc::Sender<()>,
}

/// The `Relay::StarvedWindow` byte pump; see there.
async fn starved_relay<S>(channel: S, socket: tokio::net::TcpStream)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut from_client, mut to_client) = tokio::io::split(channel);
    let (mut from_target, mut to_target) = socket.into_split();
    let towards_client = tokio::spawn(async move {
        let mut buf = vec![0; STARVED_PIECE];
        loop {
            let read = match from_target.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            if to_client.write_all(&buf[..read]).await.is_err() {
                break;
            }
        }
        let _ = to_client.shutdown().await;
    });
    let mut forwarded = 0;
    let mut paused = false;
    let mut buf = vec![0; 32 * 1024];
    loop {
        if !paused && forwarded >= STARVED_FORWARD_FIRST {
            paused = true;
            tokio::time::sleep(STARVED_PAUSE).await;
        }
        let read = match from_client.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        forwarded += read;
        if to_target.write_all(&buf[..read]).await.is_err() {
            break;
        }
    }
    let _ = to_target.shutdown().await;
    let _ = towards_client.await;
}

impl Drop for JumpHandler {
    fn drop(&mut self) {
        let _ = self.closed.send(());
    }
}

impl russh::server::Handler for JumpHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(if user == self.user && key.public_key == &self.identity {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<russh::server::Msg>,
        host: &str,
        port: u32,
        _origin: &str,
        _origin_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.requests.lock().unwrap().push((host.to_owned(), port));
        if host != "127.0.0.1" || port != u32::from(self.allowed_port) {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", self.allowed_port)).await?;
        reply.accept().await;
        match self.relay {
            Relay::Direct => {
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    // A deliberately refused host key may reset the tunnel mid-packet.
                    if let Err(error) =
                        tokio::io::copy_bidirectional(&mut stream, &mut socket).await
                    {
                        assert!(
                            matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::BrokenPipe
                            ),
                            "{error}"
                        );
                    }
                });
            }
            Relay::StarvedWindow => {
                tokio::spawn(starved_relay(channel.into_stream(), socket));
            }
        }
        Ok(())
    }
}

impl JumpFixture {
    fn start(user: &str, identity: &Path, allowed_port: u16) -> Self {
        Self::start_with(user, identity, allowed_port, Relay::Direct)
    }

    fn start_with(user: &str, identity: &Path, allowed_port: u16, relay: Relay) -> Self {
        let key = russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let identity = russh::keys::load_secret_key(identity, None)
            .unwrap()
            .public_key()
            .clone();
        let (address_tx, address_rx) = std::sync::mpsc::sync_channel(1);
        let (closed_tx, closed) = std::sync::mpsc::channel();
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = requests.clone();
        let user = user.to_owned();
        let host_key = key.clone();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let (window_size, maximum_packet_size) = match relay {
                    Relay::Direct => (2 * 1024 * 1024, 32 * 1024),
                    Relay::StarvedWindow => (STARVED_WINDOW, STARVED_PACKET),
                };
                let config = std::sync::Arc::new(russh::server::Config {
                    keys: vec![host_key],
                    auth_rejection_time: Duration::ZERO,
                    auth_rejection_time_initial: Some(Duration::ZERO),
                    window_size,
                    maximum_packet_size,
                    ..Default::default()
                });
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                address_tx.send(listener.local_addr().unwrap().port()).unwrap();
                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        socket = listener.accept() => {
                            let (socket, _) = socket.unwrap();
                            let handler = JumpHandler { user: user.clone(), identity: identity.clone(), allowed_port, relay, requests: log.clone(), closed: closed_tx.clone() };
                            let config = config.clone();
                            tokio::spawn(async move {
                                if let Ok(session) = russh::server::run_stream(config, socket, handler).await {
                                    let _ = session.await;
                                }
                            });
                        }
                    }
                }
            });
        });
        Self {
            port: address_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            key,
            closed,
            requests,
            stop: Some(stop_tx),
            thread: Some(thread),
        }
    }

    fn assert_closed(&self) {
        self.closed
            .recv_timeout(Duration::from_secs(5))
            .expect("jump connection leaked");
    }
}

impl Drop for JumpFixture {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
fn transport_uses_jump_forwarding_and_propagates_refusal() {
    use russhd::client::args::{ConnectionOptions, Destination, HostKeyPolicy};
    use russhd::client::transport;

    let target = Fixture::start();
    let first = JumpFixture::start("jump-user", &target.identity, target.port);
    let mut options = ConnectionOptions::default();
    options.port = first.port;
    options.known_hosts = Some(target.known_hosts.clone());
    options.host_key_policy = HostKeyPolicy::AcceptNew;
    options.batch_mode = true;
    let key = russh::keys::PrivateKeyWithHashAlg::new(
        std::sync::Arc::new(russh::keys::load_secret_key(&target.identity, None).unwrap()),
        None,
    );
    block_on(async {
        for host in ["127.0.0.1", "localhost"] {
            let jump_destination = Destination::parse("jump-user@127.0.0.1").unwrap();
            let mut jump = transport::connect(&options, &jump_destination)
                .await
                .unwrap();
            assert!(
                jump.authenticate_publickey("jump-user", key.clone())
                    .await
                    .unwrap()
                    .success()
            );
            let destination = Destination::parse(&format!("motor@{host}")).unwrap();
            let mut target_options = options.clone();
            target_options.port = target.port;
            let result = transport::connect_via(&jump, &target_options, &destination).await;
            if host == "localhost" {
                // This address is reachable directly, but the jump denies it.
                assert!(matches!(
                    result,
                    Err(russh::Error::ChannelOpenFailure(
                        russh::ChannelOpenFailure::AdministrativelyProhibited
                    ))
                ));
            } else {
                let mut peer = result.unwrap();
                assert!(
                    peer.authenticate_publickey("motor", key.clone())
                        .await
                        .unwrap()
                        .success()
                );
                let mut channel = peer.channel_open_session().await.unwrap();
                channel.exec(true, "printf tunneled; exit 7").await.unwrap();
                let mut output = Vec::new();
                let mut status = None;
                while let Some(message) = channel.wait().await {
                    match message {
                        russh::ChannelMsg::Data { data } => output.extend_from_slice(&data),
                        russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                        russh::ChannelMsg::Close => break,
                        _ => {}
                    }
                }
                assert_eq!(output, b"tunneled");
                assert_eq!(status, Some(7));
                peer.close().await.unwrap();
            }
            jump.close().await.unwrap();
        }
    });
    first.assert_closed();
    first.assert_closed();
    assert_eq!(
        *first.requests.lock().unwrap(),
        [
            ("127.0.0.1".to_owned(), target.port.into()),
            ("localhost".to_owned(), target.port.into()),
        ]
    );
    let known = std::fs::read_to_string(&target.known_hosts).unwrap();
    assert!(known.contains(&first.key.public_key().to_openssh().unwrap()));
    assert!(
        known
            .lines()
            .any(|line| line.starts_with(&format!("[127.0.0.1]:{} ", target.port)))
    );
    assert_eq!(known.lines().count(), 2);
}

#[test]
fn proxyjump_authenticates_every_hop_streams_and_transfers_files() {
    let target = Fixture::start();
    let second = JumpFixture::start("second-user", &target.identity, target.port);
    let first = JumpFixture::start("first-user", &target.identity, second.port);
    let path = target.root.join("client-config");
    let text = format!(
        "Host first\nHostName 127.0.0.1\nUser first-user\nPort {}\nHost second\nHostName 127.0.0.1\nUser second-user\nPort {}\nProxyJump first\nHost target\nHostName 127.0.0.1\nUser motor\nPort {}\nProxyJump second\nHost *\nIdentityFile {}\nUserKnownHostsFile {}\nStrictHostKeyChecking accept-new\nBatchMode yes\n",
        first.port,
        second.port,
        target.port,
        target.identity.display(),
        target.known_hosts.display()
    );
    std::fs::write(&path, &text).unwrap();
    let mut args = vec![
        "-F".to_owned(),
        path.to_str().unwrap().to_owned(),
        "target".to_owned(),
    ];
    args.push("printf out; printf err >&2; cat; exit 7".to_owned());
    let output = target.run(&args, b"input\r\n");
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert_eq!(output.stdout, b"outinput\r\n");
    assert_eq!(output.stderr, b"err");
    first.assert_closed();
    second.assert_closed();
    assert_eq!(
        *first.requests.lock().unwrap(),
        [("127.0.0.1".to_owned(), second.port.into())]
    );
    assert_eq!(
        *second.requests.lock().unwrap(),
        [("127.0.0.1".to_owned(), target.port.into())]
    );
    let known = std::fs::read_to_string(&target.known_hosts).unwrap();
    assert!(known.contains(&first.key.public_key().to_openssh().unwrap()));
    assert!(known.contains(&second.key.public_key().to_openssh().unwrap()));
    assert_eq!(known.lines().count(), 3);

    *args.last_mut().unwrap() = "cat".to_owned();
    let payload = (0..FULL_DUPLEX_STREAM_SIZE)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    let output = run_full_duplex(&args, payload.clone());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, payload);
    first.assert_closed();
    second.assert_closed();

    let source = target.root.join("jump-source");
    let remote = target.root.join("jump-remote");
    let downloaded = target.root.join("jump-downloaded");
    std::fs::write(&source, &payload).unwrap();
    let scp = [
        "--motor-applet=scp".to_owned(),
        "-F".to_owned(),
        path.to_str().unwrap().to_owned(),
    ];
    let upload = [
        scp.to_vec(),
        vec![
            source.display().to_string(),
            format!("target:{}", remote.display()),
        ],
    ]
    .concat();
    let output = target.run(&upload, b"");
    assert!(output.status.success(), "{output:?}");
    first.assert_closed();
    second.assert_closed();
    let download = [
        scp.to_vec(),
        vec![
            format!("target:{}", remote.display()),
            downloaded.display().to_string(),
        ],
    ]
    .concat();
    let output = target.run(&download, b"");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(downloaded).unwrap(), payload);
    first.assert_closed();
    second.assert_closed();

    let wrong = format!(
        "[127.0.0.1]:{} {}\n",
        target.port,
        first.key.public_key().to_openssh().unwrap()
    );
    std::fs::write(
        &target.known_hosts,
        known
            .lines()
            .filter(|line| !line.starts_with(&format!("[127.0.0.1]:{} ", target.port)))
            .map(|line| format!("{line}\n"))
            .collect::<String>()
            + &wrong,
    )
    .unwrap();
    let output = target.run(&args, b"");
    assert_eq!(output.status.code(), Some(255));
    assert!(String::from_utf8_lossy(&output.stderr).contains("target"));
    first.assert_closed();
    second.assert_closed();

    // Reject a wrong jump key before authentication or any target forwarding.
    let first_prefix = format!("[127.0.0.1]:{} ", first.port);
    let wrong_jump = known
        .lines()
        .map(|line| {
            if line.starts_with(&first_prefix) {
                format!(
                    "{first_prefix}{}\n",
                    second.key.public_key().to_openssh().unwrap()
                )
            } else {
                format!("{line}\n")
            }
        })
        .collect::<String>();
    std::fs::write(&target.known_hosts, wrong_jump).unwrap();
    let before = first.requests.lock().unwrap().len();
    let output = target.run(&args, b"");
    assert_eq!(output.status.code(), Some(255));
    assert!(String::from_utf8_lossy(&output.stderr).contains("first"));
    first.assert_closed();
    assert_eq!(first.requests.lock().unwrap().len(), before);
    std::fs::write(&target.known_hosts, &known).unwrap();

    std::fs::write(&path, text.replace("User first-user", "User wrong-user")).unwrap();
    let output = target.run(&args, b"");
    assert_eq!(output.status.code(), Some(255));
    first.assert_closed();
    assert_eq!(first.requests.lock().unwrap().len(), before);

    // A refused forwarding request must not fall back to a direct TCP dial.
    std::fs::write(
        &path,
        text.replace(
            &format!("Port {}\nProxyJump second", target.port),
            "Port 1\nProxyJump second",
        ),
    )
    .unwrap();
    let output = target.run(&args, b"");
    assert_eq!(output.status.code(), Some(255));
    first.assert_closed();
    second.assert_closed();
}

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
    run_full_duplex_with(SSH, args, input)
}

fn run_full_duplex_with(program: &str, args: &[String], input: Vec<u8>) -> Output {
    run_streaming(program, args, input, Duration::ZERO, Duration::ZERO)
}

fn run_streaming(
    program: &str,
    args: &[String],
    input: Vec<u8>,
    input_delay: Duration,
    output_delay: Duration,
) -> Output {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let input_thread = std::thread::spawn(move || {
        std::thread::sleep(input_delay);
        stdin.write_all(&input)
    });
    let output_thread = std::thread::spawn(move || {
        std::thread::sleep(output_delay);
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
        std::fs::read(&source).unwrap(),
        std::fs::read(&downloaded).unwrap()
    );

    let replacement = b"replacement contents\n";
    std::fs::write(&source, replacement).unwrap();
    let output = fixture.run(&upload, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&remote).unwrap(), replacement);

    // Overwriting keeps the destination's mode instead of stamping the
    // source's.
    let probe = b"mode-preserving overwrite\n";
    std::fs::write(&source, probe).unwrap();
    std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = fixture.run(&upload, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&remote).unwrap(), probe);
    assert_eq!(
        std::fs::metadata(&remote).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let tree_source = fixture.root.join("tree-source");
    let nested_source = tree_source.join("nested/file");
    let empty_source = tree_source.join("empty");
    let upload_parent = fixture.root.join("upload-parent");
    let download_parent = fixture.root.join("download-parent");
    std::fs::create_dir_all(nested_source.parent().unwrap()).unwrap();
    std::fs::create_dir(&empty_source).unwrap();
    std::fs::create_dir(&upload_parent).unwrap();
    std::fs::create_dir(&download_parent).unwrap();
    std::fs::write(&nested_source, b"recursive upload\n").unwrap();
    let locked_source = tree_source.join("locked");
    let locked_file_source = locked_source.join("file");
    std::fs::create_dir(&locked_source).unwrap();
    std::fs::write(&locked_file_source, b"locked contents\n").unwrap();
    std::fs::set_permissions(&locked_source, std::fs::Permissions::from_mode(0o555)).unwrap();

    let mut recursive_upload = fixture.base_args(Some("scp"));
    recursive_upload.push("-r".to_owned());
    recursive_upload.extend([
        tree_source.to_string_lossy().into_owned(),
        format!("motor@127.0.0.1:{}", upload_parent.display()),
    ]);
    let output = fixture.run(&recursive_upload, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let remote_tree = upload_parent.join("tree-source");
    let remote_nested = remote_tree.join("nested/file");
    let remote_locked = remote_tree.join("locked");
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&remote_locked), 0o555);
    std::fs::write(&remote_nested, b"stale\n").unwrap();
    std::fs::write(remote_locked.join("file"), b"stale locked\n").unwrap();
    std::fs::set_permissions(&remote_tree, std::fs::Permissions::from_mode(0o775)).unwrap();
    let output = fixture.run(&recursive_upload, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&remote_nested).unwrap(),
        std::fs::read(&nested_source).unwrap()
    );
    assert!(remote_tree.join("empty").is_dir());
    // The merge overwrote a file inside a read-only directory in place and
    // left the permissions of directories it did not create alone.
    assert_eq!(
        std::fs::read(remote_locked.join("file")).unwrap(),
        std::fs::read(&locked_file_source).unwrap()
    );
    assert_eq!(mode(&remote_tree), 0o775);
    assert_eq!(mode(&remote_locked), 0o555);

    let mut recursive_download = fixture.base_args(Some("scp"));
    recursive_download.push("-r".to_owned());
    recursive_download.extend([
        format!("motor@127.0.0.1:{}", remote_tree.display()),
        download_parent.to_string_lossy().into_owned(),
    ]);
    let output = fixture.run(&recursive_download, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let downloaded_tree = download_parent.join("tree-source");
    let downloaded_nested = downloaded_tree.join("nested/file");
    let downloaded_locked = downloaded_tree.join("locked");
    std::fs::write(&remote_nested, b"recursive download replacement\n").unwrap();
    std::fs::write(downloaded_locked.join("file"), b"stale local\n").unwrap();
    let output = fixture.run(&recursive_download, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&downloaded_nested).unwrap(),
        std::fs::read(&remote_nested).unwrap()
    );
    assert!(downloaded_tree.join("empty").is_dir());
    assert_eq!(
        std::fs::read(downloaded_locked.join("file")).unwrap(),
        std::fs::read(remote_locked.join("file")).unwrap()
    );
    // Reopen the read-only fixtures so the fixture root can be removed.
    for dir in [&locked_source, &remote_locked, &downloaded_locked] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

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

#[test]
fn server_drains_output_while_child_does_not_read_large_stdin() {
    let fixture = Fixture::start();
    let mut ssh = fixture.ssh_args();
    ssh.extend([
        "motor@127.0.0.1".to_owned(),
        format!("/usr/bin/head -c {FULL_DUPLEX_STREAM_SIZE} /dev/zero"),
    ]);
    let output = run_full_duplex(&ssh, vec![0x5a; FULL_DUPLEX_STREAM_SIZE]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout.len(), FULL_DUPLEX_STREAM_SIZE);
    assert!(output.stdout.iter().all(|byte| *byte == 0));
}

#[test]
fn remote_close_drains_output_despite_late_stdin() {
    let fixture = Fixture::start();
    let mut ssh = fixture.ssh_args();
    ssh.extend([
        "motor@127.0.0.1".to_owned(),
        "head -c 73728 /dev/zero; printf remote-stderr >&2; exit 7".to_owned(),
    ]);
    // Hold the stdout pipe full while the remote closes and more stdin arrives.
    // Output queued in the SSH channel must survive the failed stdin send.
    let output = run_streaming(
        SSH,
        &ssh,
        vec![0; 4096],
        Duration::from_millis(200),
        Duration::from_millis(500),
    );
    assert_eq!(
        output.status.code(),
        Some(7),
        "{} stdout bytes; stderr: {}",
        output.stdout.len(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, vec![0; 73728]);
    assert_eq!(output.stderr, b"remote-stderr");
}

#[test]
fn small_stdin_chunks_stream_bidirectionally() {
    let fixture = Fixture::start();
    let input = (0..FULL_DUPLEX_STREAM_SIZE)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    let output = block_on(async {
        let (session, mut reader, writer) = fixture.session(None, "cat").await;
        let send = async {
            // Send separate SSH messages; writes to a local pipe may coalesce.
            for chunk in input.chunks(512) {
                writer.data_bytes(chunk.to_vec()).await.unwrap();
            }
            writer.eof().await.unwrap();
        };
        let receive = async {
            let mut out = Vec::new();
            read_until(&mut reader, &mut out, |_| false).await;
            out
        };
        let ((), output) = tokio::join!(send, receive);
        session
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        output
    });
    assert_eq!(output, input);
}

#[test]
fn server_returns_window_credit_as_child_consumes_stdin() {
    let fixture = Fixture::start();
    let mut ssh = fixture.ssh_args();
    ssh.extend(["motor@127.0.0.1".to_owned(), "cat".to_owned()]);
    let input = vec![0x5a; FULL_DUPLEX_STREAM_SIZE];
    let output = run_full_duplex(&ssh, input.clone());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout.len(), input.len());
    assert!(output.stdout.iter().all(|byte| *byte == 0x5a));
}

#[test]
fn pty_output_survives_client_eof_before_terminal_controls() {
    let fixture = Fixture::start();
    let mut ssh = fixture.ssh_args();
    ssh.extend([
        "-tt".to_owned(),
        "motor@127.0.0.1".to_owned(),
        r#"sleep 0.1; printf '\033[?2048$p\033[?2048hvisible\n'"#.to_owned(),
    ]);
    let output = fixture.run_with("ssh", &ssh, b"");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"visible\n\r");
}

#[test]
fn pty_input_keeps_flowing_while_the_child_queries_its_terminal() {
    // rush asks for the text area with every prompt, and russhd answers through
    // the task that writes the child's stdin. A paste larger than the stdin pipe
    // must not hold those questions up: the output behind them stops, and then
    // the child that would have read the rest of the paste stops too.
    let fixture = Fixture::start();
    let mut ssh = fixture.ssh_args();
    ssh.extend([
        "-tt".to_owned(),
        "motor@127.0.0.1".to_owned(),
        r#"while IFS= read -r line && [ "$line" != end ]; do printf '\033[18t\033[18t\033[18t\033[18t%s\n' "$line"; done"#
            .to_owned(),
    ]);
    let lines = (0..20_000)
        .map(|i| format!("line {i}\n"))
        .collect::<String>();
    let output = run_full_duplex_with("ssh", &ssh, format!("{lines}end\n").into_bytes());

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        lines.replace('\n', "\n\r")
    );
}

/// Accepts the host key of the russhd that the test itself started.
struct TestClient;

impl russh::client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

type TestSession = (
    russh::client::Handle<TestClient>,
    russh::ChannelReadHalf,
    russh::ChannelWriteHalf<russh::client::Msg>,
);

impl Fixture {
    /// A pty session of `cols` x `rows` running `command`. OpenSSH with a piped
    /// stdin sends a zero size, which leaves russhd nothing to answer with.
    async fn pty_session(&self, cols: u32, rows: u32, command: &str) -> TestSession {
        self.session(Some((cols, rows)), command).await
    }

    async fn unauthenticated(&self) -> russh::client::Handle<TestClient> {
        self.unauthenticated_with(russh::client::Config::default())
            .await
    }

    async fn unauthenticated_with(
        &self,
        config: russh::client::Config,
    ) -> russh::client::Handle<TestClient> {
        russh::client::connect(
            std::sync::Arc::new(config),
            ("127.0.0.1", self.port),
            TestClient,
        )
        .await
        .unwrap()
    }

    /// An authenticated connection with no channel open yet.
    async fn connect(&self) -> russh::client::Handle<TestClient> {
        self.connect_with(russh::client::Config::default()).await
    }

    async fn connect_with(
        &self,
        config: russh::client::Config,
    ) -> russh::client::Handle<TestClient> {
        let mut session = self.unauthenticated_with(config).await;
        let key = russh::keys::load_secret_key(&self.identity, None).unwrap();
        let auth = session
            .authenticate_publickey(
                "motor",
                russh::keys::PrivateKeyWithHashAlg::new(std::sync::Arc::new(key), None),
            )
            .await
            .unwrap();
        assert!(auth.success());
        session
    }

    async fn session(&self, pty: Option<(u32, u32)>, command: &str) -> TestSession {
        let session = self.connect().await;
        let channel = session.channel_open_session().await.unwrap();
        if let Some((cols, rows)) = pty {
            channel
                .request_pty(true, "xterm", cols, rows, 0, 0, &[])
                .await
                .unwrap();
        }
        channel.exec(true, command).await.unwrap();
        let (reader, writer) = channel.split();
        (session, reader, writer)
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(10), future)
                .await
                .expect("the SSH session did not finish")
        })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Appends the session's output to `out` until `done(out)`, or until the
/// channel closes, which returns false.
async fn read_until(
    reader: &mut russh::ChannelReadHalf,
    out: &mut Vec<u8>,
    done: impl Fn(&[u8]) -> bool,
) -> bool {
    while !done(out) {
        match reader.wait().await {
            Some(russh::ChannelMsg::Data { data }) => out.extend_from_slice(&data),
            Some(russh::ChannelMsg::Close) | None => return false,
            Some(_) => {}
        }
    }
    true
}

#[test]
fn pty_answers_reach_the_child_whole_and_behind_client_input() {
    // The child echoes what it reads, so the answers russhd queued behind each
    // chunk of the paste come back inside the lines.
    let fixture = Fixture::start();
    let lines = (0..20_000)
        .map(|i| format!("line {i}\n"))
        .collect::<String>();
    let input = format!("{lines}end\n");
    let output = block_on(async {
        let (_session, mut reader, writer) = fixture
            .pty_session(
                100,
                30,
                r#"while IFS= read -r line; do printf '\033[18t\033[18t%s\n' "$line"; case $line in *end) break ;; esac; done"#,
            )
            .await;
        let bytes = input.clone().into_bytes();
        tokio::spawn(async move { writer.data_bytes(bytes).await });
        let mut out = Vec::new();
        read_until(&mut reader, &mut out, |_| false).await;
        out
    });

    let output = String::from_utf8(output).unwrap().replace("\n\r", "\n");
    let answer = "\x1b[8;30;100t";
    assert!(output.contains(answer), "the child got no answers");
    assert_eq!(output.replace(answer, ""), input);
}

#[test]
fn pty_size_reports_survive_a_child_that_floods_questions() {
    // The child subscribes to size reports, asks for its text area far more
    // often than russhd keeps answers for, and reads nothing until the client
    // has resized it. Answers past the limit are dropped; the new size is not.
    let fixture = Fixture::start();
    let questions = 60_000;
    let old_report = b"\x1b[48;30;100;0;0t";
    let new_report = b"\x1b[48;40;120;0;0t";
    let answer = b"\x1b[8;30;100t";
    let resized = fixture.root.join("resized");
    let read = fixture.root.join("read");
    // The child waits for a file before each step. After `resized`, its extra
    // questions outnumber russhd's control channel, so `synced` is output only
    // once the resize queued before them has been handled.
    let command = format!(
        r#"printf '\033[?2048h'; printf '\033[18t%.0s' $(seq {questions}); printf 'flooded\n'
        while [ ! -e '{resized}' ]; do sleep 0.01; done
        printf '\033[18t%.0s' $(seq 32); printf 'synced\n'
        while [ ! -e '{read}' ]; do sleep 0.01; done
        cat"#,
        resized = resized.display(),
        read = read.display(),
    );
    let echoed = block_on(async {
        let (session, mut reader, writer) = fixture.pty_session(100, 30, &command).await;
        let mut out = Vec::new();
        let flooded = b"flooded\n\r";
        assert!(read_until(&mut reader, &mut out, |out| find(out, flooded).is_some()).await);
        writer.window_change(120, 40, 0, 0).await.unwrap();
        // russhd answers the ping after it has queued the window change.
        session.send_ping().await.unwrap();
        std::fs::write(&resized, b"").unwrap();
        let synced = b"synced\n\r";
        assert!(read_until(&mut reader, &mut out, |out| find(out, synced).is_some()).await);
        std::fs::write(&read, b"").unwrap();
        let start = find(&out, synced).unwrap() + synced.len();
        assert!(
            read_until(&mut reader, &mut out, |out| out.ends_with(new_report)).await,
            "the new size never reached the child"
        );
        writer.eof().await.unwrap();
        out.split_off(start)
    });

    let answers = echoed
        .strip_prefix(old_report)
        .and_then(|rest| rest.strip_suffix(new_report))
        .expect("the child read something other than its size reports and answers");
    assert!(answers.chunks(answer.len()).all(|chunk| chunk == answer));
    let count = answers.len() / answer.len();
    assert!(
        count > 0 && count < questions,
        "{count} of {questions} questions were answered"
    );
}

/// Waits until the server has finished closing `channel`.
async fn wait_closed(channel: &mut russh::Channel<russh::client::Msg>) {
    while let Some(msg) = channel.wait().await {
        if matches!(msg, russh::ChannelMsg::Close) {
            break;
        }
    }
}

/// The command's output, read until the server closes the channel.
async fn output_of(session: &russh::client::Handle<TestClient>, command: &str) -> Vec<u8> {
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(true, command).await.unwrap();
    let mut out = Vec::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => out.extend_from_slice(&data),
            russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    out
}

/// Opens an SFTP subsystem and completes its version exchange.
async fn open_sftp(
    session: &russh::client::Handle<TestClient>,
) -> russh::Channel<russh::client::Msg> {
    let mut channel = session.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    // SSH_FXP_INIT for protocol version 3.
    channel
        .data_bytes(vec![0, 0, 0, 5, 1, 0, 0, 0, 3])
        .await
        .unwrap();
    let mut reply = Vec::new();
    while reply.len() < 9 {
        match channel.wait().await {
            Some(russh::ChannelMsg::Data { data }) => reply.extend_from_slice(&data),
            Some(russh::ChannelMsg::Close) | None => panic!("the SFTP channel closed early"),
            Some(_) => {}
        }
    }
    // SSH_FXP_VERSION.
    assert_eq!(reply[4], 2, "unexpected SFTP reply {reply:?}");
    channel
}

/// Completes an SFTP handshake and closes the channel from the client side.
async fn sftp_handshake(session: &russh::client::Handle<TestClient>) {
    let channel = open_sftp(session).await;
    // russh does not report the server's reply to a close the client sent, so
    // there is nothing to wait for: the next channel open is ordered after it.
    channel.eof().await.unwrap();
    channel.close().await.unwrap();
}

#[test]
fn server_closed_sftp_channels_release_the_connection() {
    let fixture = Fixture::start();
    block_on(async {
        let session = fixture.connect().await;
        for _ in 0..2 {
            let mut channel = open_sftp(&session).await;
            assert!(matches!(
                session.channel_open_session().await,
                Err(russh::Error::ChannelOpenFailure(_))
            ));

            // OpenSSH sends EOF and waits for the server's close. Sending
            // CLOSE ourselves would bypass the subsystem's completion path.
            channel.eof().await.unwrap();
            let mut exit_status = None;
            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::ExitStatus {
                        exit_status: status,
                    }) => {
                        exit_status = Some(status);
                    }
                    Some(russh::ChannelMsg::Close) => break,
                    None => panic!("SFTP ended without the server closing its channel"),
                    Some(_) => {}
                }
            }
            assert_eq!(exit_status, Some(0));
        }

        // Reuse the same authenticated connection; no fresh-connection fallback.
        assert_eq!(output_of(&session, "printf alive").await, b"alive");
    });
}

#[test]
fn one_channel_at_a_time_but_sequential_channels_share_a_connection() {
    let fixture = Fixture::start();
    block_on(async {
        let session = fixture.connect().await;

        // OpenSSH `ssh-copy-id -s` runs two sftp sessions over one master
        // connection. The second used to hit an assert and abort russhd.
        sftp_handshake(&session).await;
        sftp_handshake(&session).await;

        // While a command runs, a second session channel is refused and the
        // running command keeps its input and output.
        let mut busy = session.channel_open_session().await.unwrap();
        busy.exec(true, "cat").await.unwrap();
        assert!(matches!(
            session.channel_open_session().await,
            Err(russh::Error::ChannelOpenFailure(_))
        ));
        busy.data_bytes(&b"still here"[..]).await.unwrap();
        let mut echoed = Vec::new();
        while echoed.len() < b"still here".len() {
            match busy.wait().await {
                Some(russh::ChannelMsg::Data { data }) => echoed.extend_from_slice(&data),
                Some(russh::ChannelMsg::Close) | None => panic!("the busy channel closed"),
                Some(_) => {}
            }
        }
        assert_eq!(echoed, b"still here");
        busy.eof().await.unwrap();
        wait_closed(&mut busy).await;

        // Once the client has closed it, the connection takes a new channel.
        assert_eq!(output_of(&session, "printf alive").await, b"alive");
    });
}

#[test]
fn a_second_request_on_one_channel_ends_the_connection_not_the_server() {
    let fixture = Fixture::start();
    block_on(async {
        let session = fixture.connect().await;
        let mut channel = session.channel_open_session().await.unwrap();
        channel.exec(true, "cat").await.unwrap();
        // A second exec on a channel that already runs a command is a protocol
        // violation. russhd answers it by dropping the connection.
        let _ = channel.exec(true, "cat").await;
        while channel.wait().await.is_some() {}

        // russhd itself is still serving.
        let session = fixture.connect().await;
        assert_eq!(output_of(&session, "printf alive").await, b"alive");
    });
}

#[test]
fn proxyjump_survives_a_jump_that_starves_the_window() {
    let target = Fixture::start();
    let jump = JumpFixture::start_with(
        "jump-user",
        &target.identity,
        target.port,
        Relay::StarvedWindow,
    );
    let path = target.root.join("client-config");
    std::fs::write(
        &path,
        format!(
            "Host jump\nHostName 127.0.0.1\nUser jump-user\nPort {}\nHost target\nHostName 127.0.0.1\nUser motor\nPort {}\nProxyJump jump\nHost *\nIdentityFile {}\nUserKnownHostsFile {}\nStrictHostKeyChecking accept-new\nBatchMode yes\n",
            jump.port,
            target.port,
            target.identity.display(),
            target.known_hosts.display()
        ),
    )
    .unwrap();
    let args = vec![
        "-F".to_owned(),
        path.to_str().unwrap().to_owned(),
        "target".to_owned(),
        // The echo starts once the client has exhausted the jump's window.
        "sleep 1; cat".to_owned(),
    ];
    let payload = (0..2 * 1024 * 1024)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    let output = run_full_duplex(&args, payload.clone());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, payload);
    jump.assert_closed();
}

fn assert_both_methods(result: russh::client::AuthResult, context: &str) {
    let russh::client::AuthResult::Failure {
        remaining_methods,
        partial_success,
    } = result
    else {
        panic!("{context}: authenticated");
    };
    assert_eq!(
        &*remaining_methods,
        &[russh::MethodKind::Password, russh::MethodKind::PublicKey],
        "{context}"
    );
    assert!(!partial_success, "{context}");
}

#[test]
fn every_name_sees_the_same_methods_at_every_step() {
    let fixture = Fixture::start();
    let stranger =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519)
            .unwrap();
    let stranger = std::sync::Arc::new(stranger);
    // Two sessions per name: a rejection takes 3 s, and block_on allows 10.
    for user in ["motor", "nobody"] {
        block_on(async {
            let mut session = fixture.unauthenticated().await;
            let none = session.authenticate_none(user).await.unwrap();
            assert_both_methods(none, user);
            let password = session.authenticate_password(user, "wrong").await.unwrap();
            assert_both_methods(password, user);
        });
        block_on(async {
            let mut session = fixture.unauthenticated().await;
            let key = russh::keys::PrivateKeyWithHashAlg::new(stranger.clone(), None);
            let key = session.authenticate_publickey(user, key).await.unwrap();
            assert_both_methods(key, user);
        });
    }

    // The list costs no credential read, so a broken registry cannot show.
    write_private(&fixture.root.join("users.toml"), "not a registry");
    block_on(async {
        for user in ["motor", "nobody"] {
            let mut session = fixture.unauthenticated().await;
            let none = session.authenticate_none(user).await.unwrap();
            assert_both_methods(none, user);
        }
    });
}

/// A client that takes its time to sign: the server has already answered the
/// offer when this runs, and `remove` then empties the key file.
struct SlowSigner {
    key: std::sync::Arc<russh::keys::PrivateKey>,
    key_file: PathBuf,
    remove: bool,
}

#[derive(Debug)]
struct SignerError;

impl From<russh::SendError> for SignerError {
    fn from(_: russh::SendError) -> Self {
        Self
    }
}

impl russh::Signer for SlowSigner {
    type Error = SignerError;

    async fn auth_sign(
        &mut self,
        _key: &russh::keys::agent::AgentIdentity,
        _hash_alg: Option<russh::keys::HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        fn put(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        if self.remove {
            write_private(&self.key_file, "");
        }
        let signature: russh::keys::ssh_key::Signature =
            russh::keys::signature::Signer::sign(&*self.key, &to_sign);
        let mut blob = Vec::new();
        put(&mut blob, b"ssh-ed25519");
        put(&mut blob, signature.as_bytes());
        put(&mut to_sign, &blob);
        Ok(to_sign)
    }
}

#[test]
fn a_key_removed_between_offer_and_signature_does_not_authenticate() {
    let fixture = Fixture::start();
    let key = std::sync::Arc::new(russh::keys::load_secret_key(&fixture.identity, None).unwrap());
    block_on(async {
        // The signer must work, or the rejection below would prove nothing.
        for remove in [false, true] {
            let mut session = fixture.unauthenticated().await;
            let mut signer = SlowSigner {
                key: key.clone(),
                key_file: fixture.root.join("authorized_keys.motor"),
                remove,
            };
            let result = session
                .authenticate_publickey_with("motor", key.public_key().clone(), None, &mut signer)
                .await
                .unwrap();
            assert_eq!(result.success(), !remove, "remove = {remove}");
        }
    });
}

/// A new identity, as its private key's path and its public line.
fn new_identity(fixture: &Fixture, name: &str) -> (PathBuf, String) {
    let key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519)
            .unwrap();
    let path = fixture.root.join(name);
    let text = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap();
    write_private(&path, &text);
    let public = key.public_key().to_openssh().unwrap();
    write_private(&path.with_extension("pub"), &format!("{public}\n"));
    (path, public)
}

fn copy_id(fixture: &Fixture, key: &Path, target: &str) -> Output {
    fixture.run(
        &[
            "--motor-applet=ssh-copy-id".to_owned(),
            "-F".to_owned(),
            "none".to_owned(),
            "-p".to_owned(),
            fixture.port.to_string(),
            "-o".to_owned(),
            format!("IdentityFile={}", fixture.identity.display()),
            "-o".to_owned(),
            "IdentitiesOnly=yes".to_owned(),
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=accept-new".to_owned(),
            "-o".to_owned(),
            format!("UserKnownHostsFile={}", fixture.known_hosts.display()),
            "-i".to_owned(),
            key.with_extension("pub").display().to_string(),
            "-t".to_owned(),
            target.to_owned(),
            "motor@127.0.0.1".to_owned(),
        ],
        b"",
    )
}

#[test]
fn copy_id_writes_only_the_named_list() {
    let fixture = Fixture::start();
    let (key, public) = new_identity(&fixture, "alice");
    let (_, other) = new_identity(&fixture, "other");
    let path = fixture.root.join("list");
    let target = path.to_str().unwrap();
    let default_list = fixture.root.join(".ssh");
    let succeeds = |expected: &str| {
        let output = copy_id(&fixture, &key, target);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
    };

    // A missing file, an empty file, and each repeat of an installation.
    let installed = format!("{public}\n");
    succeeds(&installed);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    succeeds(&installed);
    std::fs::write(&path, "").unwrap();
    succeeds(&installed);

    // Comments survive, a commented-out key is not a key, and neither a CRLF
    // nor a missing final newline hides what is there.
    let start = format!("# {public}\n# note\n{other}");
    std::fs::write(&path, &start).unwrap();
    let appended = format!("{start}\n{public}\n");
    succeeds(&appended);
    succeeds(&appended);
    let crlf = format!("{public}\r\n# note\r\n");
    std::fs::write(&path, &crlf).unwrap();
    succeeds(&crlf);
    let renamed = format!("{public} another comment");
    std::fs::write(&path, &renamed).unwrap();
    succeeds(&renamed);

    assert!(!default_list.exists(), "-t must leave .ssh alone");
}

#[test]
fn copy_id_refuses_to_widen_a_restricted_key() {
    let fixture = Fixture::start();
    let (key, public) = new_identity(&fixture, "alice");
    let (_, other) = new_identity(&fixture, "other");
    let path = fixture.root.join("list");
    let target = path.to_str().unwrap();
    let blob = public.split_whitespace().nth(1).unwrap();
    let mut non_utf8 = format!("from=\"10.0.0.1\" {public} caf").into_bytes();
    non_utf8.extend_from_slice(b"\xe9\n");
    for restricted in [
        format!("from=\"10.0.0.1\" {public}\n").into_bytes(),
        format!("command=\"echo not {other}\" {public}\n").into_bytes(),
        format!("restrict {public} comment\n").into_bytes(),
        non_utf8,
        format!("from=\"10.0.0.1\" rsa-sha2-256 {blob}\n").into_bytes(),
    ] {
        std::fs::write(&path, &restricted).unwrap();
        let output = copy_id(&fixture, &key, target);
        assert!(!output.status.success(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("not as a plain record"), "{stderr}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("installed"));
        assert_eq!(std::fs::read(&path).unwrap(), restricted);
    }

    // A plain record alongside it means the key is already installed.
    let both = format!("from=\"10.0.0.1\" {public}\n{public}\n");
    std::fs::write(&path, &both).unwrap();
    let output = copy_id(&fixture, &key, target);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), both);

    // A restriction on another key, in any encoding, is no reason to refuse.
    let mut unrelated = format!("from=\"10.0.0.1\" {other} caf").into_bytes();
    unrelated.extend_from_slice(b"\xe9\n");
    std::fs::write(&path, &unrelated).unwrap();
    let output = copy_id(&fixture, &key, target);
    assert!(output.status.success(), "{output:?}");
    unrelated.extend_from_slice(format!("{public}\n").as_bytes());
    assert_eq!(std::fs::read(&path).unwrap(), unrelated);
}

#[test]
fn copy_id_needs_the_parent_and_resolves_relative_targets() {
    let fixture = Fixture::start();
    let (key, public) = new_identity(&fixture, "alice");
    let missing = fixture.root.join("missing/list");
    let output = copy_id(&fixture, &key, missing.to_str().unwrap());
    assert!(!output.status.success(), "{output:?}");
    assert!(!missing.parent().unwrap().exists());

    let output = copy_id(&fixture, &key, "relative-list");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read_to_string(fixture.root.join("relative-list")).unwrap(),
        format!("{public}\n")
    );
}

#[test]
fn a_key_installed_by_copy_id_logs_in_on_its_own() {
    let fixture = Fixture::start();
    let (key, _) = new_identity(&fixture, "alice");
    let list = fixture.root.join("authorized_keys.motor");
    let output = copy_id(&fixture, &key, list.to_str().unwrap());
    assert!(output.status.success(), "{output:?}");

    let mut args = fixture.ssh_args();
    let identity = args.iter().position(|arg| arg == "-i").unwrap() + 1;
    args[identity] = key.display().to_string();
    args.extend([
        "motor@127.0.0.1".to_owned(),
        "printf".to_owned(),
        "ok".to_owned(),
    ]);
    let output = fixture.run(&args, b"");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"ok");
}
