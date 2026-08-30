#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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
