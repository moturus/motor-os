#![cfg(not(target_os = "motor"))]
use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant, SystemTime};
use wg::config::{Config, Peer};
use wg::crypto::{Action, BUFFER_SIZE, Crypto};

struct Fixture {
    directory: PathBuf,
    child: Child,
    lines: Receiver<String>,
    endpoint: SocketAddr,
}

impl Fixture {
    fn start(binary: &Path, bind: &str, initiate: Option<SocketAddr>) -> Self {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("wg-fork-peer-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        for name in ["local", "remote"] {
            assert!(
                Command::new(binary)
                    .arg("keygen")
                    .arg(directory.join(format!("{name}.key")))
                    .arg(directory.join(format!("{name}.pub")))
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let mut command = Command::new(binary);
        command
            .args([
                "serve",
                "--bind",
                bind,
                "--address",
                "10.20.0.1/32",
                "--address",
                "fd20::1/128",
                "--private-key",
            ])
            .arg(directory.join("remote.key"))
            .arg("--peer-key")
            .arg(directory.join("local.pub"));
        if let Some(endpoint) = initiate {
            command.args(["--endpoint", &endpoint.to_string()]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let (sender, lines) = channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let mut fixture = Self {
            directory,
            child,
            lines,
            endpoint: "127.0.0.1:1".parse().unwrap(),
        };
        fixture.endpoint = fixture
            .line()
            .strip_prefix("READY ")
            .unwrap()
            .parse()
            .unwrap();
        fixture
    }

    fn line(&self) -> String {
        self.lines.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    fn command(&mut self, command: &str) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{command}").unwrap();
    }

    fn key(&self, filename: &str) -> [u8; 32] {
        STANDARD
            .decode(
                std::fs::read_to_string(self.directory.join(filename))
                    .unwrap()
                    .trim(),
            )
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn config(&self, endpoint: Option<SocketAddr>) -> Config {
        Config {
            name: "wg-test".into(),
            private_key: self.key("local.key"),
            listen_port: 51820,
            transport_addresses: vec!["127.0.0.1".parse().unwrap()],
            cidrs: vec![
                "10.20.0.2/32".parse().unwrap(),
                "fd20::2/128".parse().unwrap(),
            ],
            peers: vec![Peer {
                public_key: self.key("remote.pub"),
                preshared_key: None,
                endpoint,
                allowed_ips: vec![
                    "10.20.0.1/32".parse().unwrap(),
                    "fd20::1/128".parse().unwrap(),
                ],
                persistent_keepalive: None,
            }],
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo(ipv6: bool) -> Vec<u8> {
    let header = if ipv6 { 40 } else { 20 };
    let mut packet = vec![0; header + 64];
    if ipv6 {
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&64_u16.to_be_bytes());
        packet[6] = 58;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"fd20::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"fd20::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    } else {
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&84_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 20, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 20, 0, 1]);
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
    }
    packet[header] = if ipv6 { 128 } else { 8 };
    packet[header + 4..header + 8].copy_from_slice(&[0x12, 0x34, 0, 1]);
    packet[header + 8..].fill(0xab);
    let mut checked = Vec::new();
    if ipv6 {
        checked.extend_from_slice(&packet[8..40]);
        checked.extend_from_slice(&[0, 0, 0, 64, 0, 0, 0, 58]);
    }
    checked.extend_from_slice(&packet[header..]);
    packet[header + 2..header + 4].copy_from_slice(&checksum(&checked).to_be_bytes());
    packet
}

fn send(socket: &UdpSocket, action: Action<'_>) -> Option<Vec<u8>> {
    match action {
        Action::None => None,
        Action::Network {
            destination,
            packet,
        } => {
            assert_eq!(socket.send_to(packet, destination).unwrap(), packet.len());
            None
        }
        Action::Tunnel(packet) => Some(packet.to_vec()),
    }
}

fn receive(socket: &UdpSocket, crypto: &mut Crypto) -> Option<Vec<u8>> {
    let mut input = [0; BUFFER_SIZE + 1];
    let mut output = [0; BUFFER_SIZE];
    let (len, source) = socket.recv_from(&mut input).unwrap();
    let delivered = send(socket, crypto.receive(source, &input[..len], &mut output));
    for _ in 0..32 {
        if !crypto.needs_flush(0) {
            break;
        }
        assert!(send(socket, crypto.flush(0, &mut output)).is_none());
    }
    delivered
}

#[test]
fn fork_interoperates_with_upstream_in_both_roles_and_families() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/wg-peer");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut build = Command::new("cargo");
    build
        .current_dir(&root)
        .args(["build", "--quiet", "--locked", "--offline"]);
    if profile == "release" {
        build.arg("--release");
    }
    assert!(build.status().unwrap().success());
    let binary = root.join("target").join(profile).join("wg-peer");
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for upstream_initiates in [false, true] {
            let socket = UdpSocket::bind(bind).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut fixture = Fixture::start(
                &binary,
                bind,
                upstream_initiates.then(|| socket.local_addr().unwrap()),
            );
            let mut crypto =
                Crypto::new(&fixture.config((!upstream_initiates).then_some(fixture.endpoint)))
                    .unwrap();
            if upstream_initiates {
                fixture.command("keepalive");
                assert_eq!(fixture.line(), "KEEPALIVE");
                let deadline = Instant::now() + Duration::from_secs(3);
                while crypto.endpoint(0).is_none() {
                    assert!(Instant::now() < deadline);
                    assert!(receive(&socket, &mut crypto).is_none());
                }
            }
            for ipv6 in [false, true] {
                let packet = echo(ipv6);
                let mut output = [0; BUFFER_SIZE];
                assert!(send(&socket, crypto.encapsulate(&packet, &mut output)).is_none());
                let deadline = Instant::now() + Duration::from_secs(3);
                let reply = loop {
                    assert!(Instant::now() < deadline);
                    if let Some(reply) = receive(&socket, &mut crypto) {
                        break reply;
                    }
                };
                let header = if ipv6 { 40 } else { 20 };
                assert_eq!(reply.len(), packet.len());
                assert_eq!(reply[header], if ipv6 { 129 } else { 0 });
                assert_eq!(&reply[header + 4..], &packet[header + 4..]);
                assert_eq!(crypto.endpoint(0), Some(fixture.endpoint));
            }
            fixture.command("quit");
            assert!(fixture.child.wait().unwrap().success());
        }
    }
}
