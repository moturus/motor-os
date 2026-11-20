use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, SystemTime};

struct Keys(PathBuf);

impl Keys {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("wg-peer-localhost-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let keys = Self(directory);
        for name in ["a", "b"] {
            wg_peer::options::keygen(&keys.path(name, "private"), &keys.path(name, "public"))
                .unwrap();
        }
        keys
    }

    fn path(&self, name: &str, kind: &str) -> String {
        self.0
            .join(format!("{name}.{kind}"))
            .to_str()
            .unwrap()
            .to_owned()
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Process {
    child: Child,
    lines: Receiver<String>,
    reader: Option<std::thread::JoinHandle<()>>,
    address: SocketAddr,
}

impl Process {
    fn start(
        bind: &str,
        inner: u8,
        keys: Option<(&Keys, &str, &str)>,
        endpoint: Option<SocketAddr>,
    ) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wg-peer"));
        command.args([
            "serve",
            "--bind",
            bind,
            "--address",
            &format!("10.20.0.{inner}/32"),
            "--address",
            &format!("fd20::{inner}/128"),
        ]);
        if let Some((keys, own, peer)) = keys {
            command.args([
                "--private-key",
                &keys.path(own, "private"),
                "--peer-key",
                &keys.path(peer, "public"),
            ]);
        } else {
            command.arg("--plain");
        }
        if let Some(endpoint) = endpoint {
            command.args(["--endpoint", &endpoint.to_string()]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let mut process = Self {
            child,
            lines,
            reader: Some(reader),
            address: "127.0.0.1:1".parse().unwrap(),
        };
        let line = process.line();
        process.address = line.strip_prefix("READY ").expect(&line).parse().unwrap();
        process
    }

    fn line(&self) -> String {
        self.lines.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    fn command(&mut self, command: &str) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{command}").unwrap();
    }

    fn ping(&mut self, address: &str) {
        self.command(&format!("ping {address}"));
        assert_eq!(self.line(), format!("PING-START {address}"));
        assert_eq!(self.line(), "PING OK");
    }

    fn finish(mut self) {
        self.command("quit");
        assert!(self.child.wait().unwrap().success());
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reader.take().unwrap().join().unwrap();
    }
}

#[test]
fn independent_processes_cover_both_transports_and_outer_families() {
    let keys = Keys::new();
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for encrypted in [false, true] {
            let mut b = Process::start(
                bind,
                1,
                encrypted.then_some((&keys, "b", "a")),
                (!encrypted).then(|| "127.0.0.1:1".parse().unwrap()),
            );
            let mut a = Process::start(
                bind,
                2,
                encrypted.then_some((&keys, "a", "b")),
                Some(b.address),
            );
            if !encrypted {
                b.command(&format!("endpoint {}", a.address));
                assert_eq!(b.line(), format!("ENDPOINT {}", a.address));
            }
            a.ping("10.20.0.1");
            a.ping("fd20::1");
            b.ping("10.20.0.2");
            b.ping("fd20::2");
            if encrypted {
                for invalid in ["replay", "tamper", "malformed"] {
                    a.command(invalid);
                    assert_eq!(a.line(), format!("SENT {invalid}"));
                }
                a.ping("10.20.0.1"); // Response orders the preceding invalid input before stats.
                b.command("stats");
                let stats = b.line();
                let rejected: u64 = stats
                    .split_ascii_whitespace()
                    .find_map(|field| field.strip_prefix("rejected="))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!(rejected >= 3, "{stats}");
                a.command(&format!("roam {bind}"));
                let moved: SocketAddr = a.line().strip_prefix("ROAM ").unwrap().parse().unwrap();
                assert_ne!(moved, a.address);
                a.command("keepalive");
                assert_eq!(a.line(), "KEEPALIVE");
                a.ping("fd20::1");
                b.ping("fd20::2");
                let address = b.address.to_string();
                b.finish();
                b = Process::start(&address, 1, Some((&keys, "b", "a")), None);
                a.command("handshake");
                assert_eq!(a.line(), "HANDSHAKE");
                assert_eq!(a.line(), "HANDSHAKE OK");
                a.ping("10.20.0.1");
                b.ping("fd20::2");
            }
            a.finish();
            b.finish();
        }
    }
}
