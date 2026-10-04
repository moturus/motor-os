//! Motor SFTP mode requests before writes, including requests without OPEN attributes.
//! Invoked by test-sftp.sh against its local test VM.
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

fn number(packet: &mut Vec<u8>, value: u32) {
    packet.extend_from_slice(&value.to_be_bytes());
}

fn string(packet: &mut Vec<u8>, value: &[u8]) {
    number(packet, value.len().try_into().unwrap());
    packet.extend_from_slice(value);
}

fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

struct Session {
    ssh: Vec<String>,
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    id: u32,
}

impl Session {
    fn connect(key: &str, user: &str, host: &str, port: &str) -> Self {
        let ssh: Vec<_> = [
            "-F",
            "/dev/null",
            "-p",
            port,
            "-i",
            key,
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ]
        .into_iter()
        .map(str::to_owned)
        .chain([format!("{user}@{host}")])
        .collect();
        let mut child = Command::new("ssh")
            .arg("-s")
            .args(&ssh)
            .arg("sftp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut session = Self {
            input: child.stdin.take().unwrap(),
            output: child.stdout.take().unwrap(),
            child,
            ssh,
            id: 0,
        };
        assert_eq!(session.exchange(&[1, 0, 0, 0, 3])[0], 2);
        session
    }

    fn exchange(&mut self, packet: &[u8]) -> Vec<u8> {
        self.input
            .write_all(&(packet.len() as u32).to_be_bytes())
            .unwrap();
        self.input.write_all(packet).unwrap();
        self.input.flush().unwrap();
        let mut size = [0; 4];
        self.output.read_exact(&mut size).unwrap();
        let size = u32::from_be_bytes(size) as usize;
        assert!(size < 1024 * 1024);
        let mut reply = vec![0; size];
        self.output.read_exact(&mut reply).unwrap();
        reply
    }

    fn request(&mut self, kind: u8, args: &[u8]) -> Vec<u8> {
        self.id += 1;
        let mut packet = vec![kind];
        number(&mut packet, self.id);
        packet.extend_from_slice(args);
        let reply = self.exchange(&packet);
        assert_eq!(&reply[1..5], &self.id.to_be_bytes());
        reply
    }

    fn status(&mut self, kind: u8, args: &[u8], expected: u32) {
        let reply = self.request(kind, args);
        assert_eq!(reply[0], 101, "request {kind}: {reply:?}");
        assert_eq!(
            u32::from_be_bytes(reply[5..9].try_into().unwrap()),
            expected,
            "request {kind}: {reply:?}"
        );
    }

    fn open(&mut self, path: &str) -> Vec<u8> {
        self.open_with(path, 2, None, false) // WRITE, without CREATE or TRUNCATE.
    }

    /// OPEN with `pflags`, a permissions attribute and, with `times`, the
    /// access and modification times OpenSSH's `put -p` sends.
    fn open_with(&mut self, path: &str, pflags: u32, mode: Option<u32>, times: bool) -> Vec<u8> {
        let mut args = Vec::new();
        string(&mut args, path.as_bytes());
        number(&mut args, pflags);
        number(
            &mut args,
            (u32::from(mode.is_some()) * 4) | (u32::from(times) * 8),
        );
        if let Some(mode) = mode {
            number(&mut args, mode);
        }
        if times {
            number(&mut args, 1_700_000_000);
            number(&mut args, 1_700_000_001);
        }
        let reply = self.request(3, &args);
        assert_eq!(reply[0], 102, "open {path}: {reply:?}");
        let len = u32::from_be_bytes(reply[5..9].try_into().unwrap()) as usize;
        reply[9..9 + len].to_vec()
    }

    fn mode(&mut self, kind: u8, target: &[u8], mode: u32, size: Option<u64>, expected: u32) {
        let mut args = Vec::new();
        string(&mut args, target);
        number(&mut args, 4 | u32::from(size.is_some()));
        if let Some(size) = size {
            args.extend_from_slice(&size.to_be_bytes());
        }
        number(&mut args, mode);
        self.status(kind, &args, expected);
    }

    fn write(&mut self, handle: &[u8], data: &[u8]) {
        let mut args = Vec::new();
        string(&mut args, handle);
        args.extend_from_slice(&0u64.to_be_bytes());
        string(&mut args, data);
        self.status(6, &args, 0);
        // set_len waits for Tokio's buffered write, without closing the handle.
        let mut args = Vec::new();
        string(&mut args, handle);
        number(&mut args, 1);
        args.extend_from_slice(&(data.len() as u64).to_be_bytes());
        self.status(10, &args, 0);
    }

    fn close(&mut self, handle: &[u8]) {
        let mut args = Vec::new();
        string(&mut args, handle);
        self.status(4, &args, 0);
    }

    fn guest(&self, command: &str) -> Output {
        Command::new("ssh")
            .args(&self.ssh)
            .arg(command)
            .output()
            .unwrap()
    }

    fn run(&self, command: &str) -> Vec<u8> {
        let output = self.guest(command);
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn assert_private(&self, path: &str) {
        let output = self.guest(&format!(
            "MOTOR_OS_CAPS=0x4 /system/bin/cat {}",
            quoted(path)
        ));
        let stderr = String::from_utf8_lossy(&output.stderr);
        // cat's own read failure, not a failed ssh session or shell.
        assert_eq!(output.status.code(), Some(1), "None read {path}: {stderr}");
        assert!(
            stderr.contains("cat: error reading file"),
            "None read {path}: {stderr}"
        );
        assert!(output.stdout.is_empty(), "None read {path}");
    }

    fn finish(mut self) {
        drop(self.input);
        drop(self.output);
        assert!(self.child.wait().unwrap().success());
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        6,
        "usage: sftp-permissions KEY USER HOST PORT ROOT"
    );
    let mut session = Session::connect(&args[1], &args[2], &args[3], &args[4]);
    let root = &args[5];
    session.mode(9, format!("{root}/missing").as_bytes(), 0o600, None, 2);
    for kind in [9, 10] {
        // SETSTAT and FSETSTAT.
        let parent = format!("{root}/mode-{kind}");
        let path = format!("{parent}/file");
        session.run(&format!("/system/bin/mkdir {}", quoted(&parent)));
        session.run(&format!("echo original > {}", quoted(&path)));
        session.run(&format!("/system/bin/chmod rwxr-xr-x {}", quoted(&parent)));
        let handle = session.open(&path);
        let target = if kind == 9 { path.as_bytes() } else { &handle };
        // A combined chmod+truncate must reject the mode before destroying data.
        let size = if kind == 10 { Some(0) } else { None };
        session.mode(kind, target, 0o600, size, 3);
        session.close(&handle);
        assert_eq!(
            session.run(&format!("/system/bin/cat {}", quoted(&path))),
            b"original\n"
        );

        session.run(&format!("/system/bin/chmod rwxrwxr-x {}", quoted(&parent)));
        let handle = session.open(&path);
        // SETSTAT defers its mode on every writable handle of the entry.
        let second = (kind == 9).then(|| session.open(&path));
        let target = if kind == 9 { path.as_bytes() } else { &handle };
        session.mode(kind, target, 0o600, None, 0);
        session.assert_private(&path);
        session.write(&handle, b"private contents\n");
        session.assert_private(&path);
        // Making the completed upload public must wait for close.
        session.mode(kind, target, 0o644, None, 0);
        session.assert_private(&path);
        session.close(&handle);
        if let Some(second) = second {
            // The first close installed the deferred mode; after the shell
            // hides the file again, the second close installs it once more.
            session.run(&format!("/system/bin/chmod rwxrw---- {}", quoted(&path)));
            session.assert_private(&path);
            session.close(&second);
        }
        assert_eq!(
            session.run(&format!(
                "MOTOR_OS_CAPS=0x4 /system/bin/cat {}",
                quoted(&path)
            )),
            b"private contents\n"
        );
    }
    // FSETSTAT follows the open entry after a rename, including its new parent.
    let path = format!("{root}/mode-10/file");
    let moved = format!("{root}/mode-9/moved");
    let parent = format!("{root}/mode-9");
    let handle = session.open(&path);
    session.run(&format!(
        "/system/bin/mv {} {}",
        quoted(&path),
        quoted(&moved)
    ));
    session.run(&format!("echo replacement > {}", quoted(&path)));
    session.run(&format!("/system/bin/chmod rwxr-xr-x {}", quoted(&parent)));
    // SETSTAT follows the path's replacement, even while the old handle exists.
    session.mode(9, path.as_bytes(), 0o600, None, 0);
    session.assert_private(&path);
    session.mode(9, path.as_bytes(), 0o644, None, 0);
    session.mode(10, &handle, 0o600, None, 3);
    // OPEN never changes a mode: a download carrying a permissions attribute
    // (libssh2, curl) and an in-place upload carrying only timestamps succeed
    // under the protected parent and leave the file readable.
    let reader = session.open_with(&moved, 1, Some(0o600), false);
    session.close(&reader);
    let writer = session.open_with(&moved, 2, None, true);
    session.close(&writer);
    assert_eq!(
        session.run(&format!(
            "MOTOR_OS_CAPS=0x4 /system/bin/cat {}",
            quoted(&moved)
        )),
        b"private contents\n"
    );
    session.run(&format!("/system/bin/chmod rwxrwxr-x {}", quoted(&parent)));
    session.mode(10, &handle, 0o600, None, 0);
    session.assert_private(&moved);
    assert_eq!(
        session.run(&format!(
            "MOTOR_OS_CAPS=0x4 /system/bin/cat {}",
            quoted(&path)
        )),
        b"replacement\n"
    );
    session.close(&handle);
    session.finish();
    println!("SFTP permission requests: PASS");
}
