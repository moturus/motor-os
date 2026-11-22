use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

// A harness cross-built for the soak runs the standard image's installed rmux.
pub const RMUX: &str = match option_env!("RMUX_TEST_BINARY") {
    Some(path) => path,
    None => env!("CARGO_BIN_EXE_rmux"),
};
pub const PROBE: &str = env!("CARGO_BIN_EXE_rmux-probe");

pub fn caps() -> u64 {
    moto_sdk::sys::ProcessStaticPage::get().capabilities
}

pub struct Session {
    pub root: PathBuf,
}

impl Session {
    pub fn new(label: &str) -> Self {
        let root = PathBuf::from(format!("/none/tmp/rmux-{}-{label}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        if caps() & moto_sdk::sys::caps::CAP_INTERACTIVE != 0 {
            moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
                let client = moto_sdk::io::fs::FsClient::connect().unwrap();
                let (id, _) = client.stat(root.to_str().unwrap()).await.unwrap();
                let mut permissions = client.metadata(id).await.unwrap().permissions().unwrap();
                permissions.none = moto_sdk::io::fs::AccessPermissions::Rwx;
                client.set_all_permissions(id, permissions).await.unwrap();
            });
        }
        Self { root }
    }

    pub fn command(&self, program: &str, arguments: &[&str], mask: u64) -> Command {
        let mut command = Command::new(program);
        command
            .args(arguments)
            // Match the short prompt used by the former SSH-driven checks.
            .current_dir("/user")
            .env("TMPDIR", &self.root)
            .env("MOTOR_OS_CAPS", format!("{mask:#x}"));
        command
    }

    pub fn output(&self, program: &str, arguments: &[&str], mask: u64) -> Output {
        self.command(program, arguments, mask).output().unwrap()
    }

    pub fn success(&self, program: &str, arguments: &[&str], mask: u64) -> String {
        let output = self.output(program, arguments, mask);
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        String::from_utf8(output.stdout)
            .unwrap()
            .trim_end()
            .to_owned()
    }

    pub fn client(&self, program: &str, arguments: &[&str], mask: u64) -> Client {
        Client::new(&mut self.command(program, arguments, mask))
    }

    pub fn kill_session(&self, name: &str, mask: u64) {
        self.success(RMUX, &["kill-session", "-t", name], mask);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

pub struct Client {
    pub child: Child,
    receiver: Receiver<Vec<u8>>,
    reader: Option<std::thread::JoinHandle<()>>,
    pub bytes: Vec<u8>,
    parser: rmux::ansi::Parser,
    pub grid: rmux::grid::Grid,
}

impl Client {
    fn new(command: &mut Command) -> Self {
        let mut child = command
            .env("MOTURUS_STDIO_IS_TERMINAL", "true")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut buffer = [0; 4096];
            loop {
                let n = stdout.read(&mut buffer).unwrap();
                if n == 0 || sender.send(buffer[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            receiver,
            reader: Some(reader),
            bytes: Vec::new(),
            parser: rmux::ansi::Parser::new(),
            grid: rmux::grid::Grid::new(24, 80),
        }
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    }

    pub fn wait(&mut self, label: &str, condition: impl Fn(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !condition(self) {
            let bytes = self
                .receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|error| {
                    panic!("{label}: {error}; {}", String::from_utf8_lossy(&self.bytes))
                });
            self.accept(&bytes);
        }
    }

    fn accept(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
        self.parser.feed(bytes, &mut |action| {
            self.grid.apply(action);
        });
    }

    pub fn text(&mut self, text: &str) {
        self.wait(text, |client| {
            client
                .bytes
                .windows(text.len())
                .any(|bytes| bytes == text.as_bytes())
        });
    }

    pub fn finish(mut self, code: i32) -> Vec<u8> {
        self.child.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match self
                .receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(bytes) => self.accept(&bytes),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(error) => panic!("client did not exit: {error}"),
            }
        }
        assert_eq!(self.child.wait().unwrap().code(), Some(code));
        self.reader.take().unwrap().join().unwrap();
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.reader.is_some() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub fn until(label: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !condition() {
        assert!(Instant::now() < deadline, "{label}");
        std::thread::sleep(Duration::from_millis(20));
    }
}
