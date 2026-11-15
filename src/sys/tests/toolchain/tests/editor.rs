use crate::support::command;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

pub struct Editor {
    child: Child,
    receiver: mpsc::Receiver<Vec<u8>>,
    log: PathBuf,
    log_start: usize,
    pub screen: Vec<u8>,
    all: Vec<u8>,
    scanned: usize,
    closed: bool,
}

impl Editor {
    pub fn new(root: &Path, log: &Path, arguments: &[&str]) -> Self {
        let mut command = command(root, "/user/bin/dev/hx");
        command.args(["-v", "--log"]).arg(log).args(arguments);
        Self::spawn(root, log, command)
    }

    pub fn rmux(root: &Path, log: &Path) -> Self {
        let mut command = command(root, "/user/bin/rmux");
        let caps = moto_sdk::sys::ProcessStaticPage::get().capabilities;
        command
            .args(["new", "-s", "helix-tui"])
            .env("TMPDIR", root)
            // An unadorned child loses the authority to start rmux's server.
            .env("MOTOR_OS_CAPS", format!("{caps:#x}"));
        Self::spawn(root, log, command)
    }

    fn spawn(root: &Path, log: &Path, mut command: Command) -> Self {
        let mut child = command
            .env("MOTURUS_STDIO_IS_TERMINAL", "true")
            .env("XDG_CACHE_HOME", root.join("cache"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(fs::File::create(log.with_extension("stderr")).unwrap())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
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
            log: log.to_owned(),
            log_start: 0,
            screen: Vec::new(),
            all: Vec::new(),
            scanned: 0,
            closed: false,
        }
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    }

    pub fn keys(&mut self, bytes: &[u8]) {
        self.screen.clear();
        self.send(bytes);
    }

    fn pump(&mut self) {
        match self.receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(bytes) => {
                self.screen.extend_from_slice(&bytes);
                self.all.extend_from_slice(&bytes);
                // Behave like Motor's mode-2048 terminal provider. Keep the
                // unconsumed suffix so queries split between writes still work.
                while self.scanned < self.all.len() {
                    let remaining = &self.all[self.scanned..];
                    let query = b"\x1b[?2048$p";
                    let enable = b"\x1b[?2048h";
                    if remaining.starts_with(query) {
                        self.scanned += query.len();
                        self.send(b"\x1b[?2048;1$y");
                    } else if remaining.starts_with(enable) {
                        self.scanned += enable.len();
                        self.send(b"\x1b[48;24;80;0;0t");
                    } else if query.starts_with(remaining) || enable.starts_with(remaining) {
                        break;
                    } else {
                        self.scanned += 1;
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => self.closed = true,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }

    pub fn text(&mut self, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !String::from_utf8_lossy(&self.screen).contains(expected) {
            assert!(
                !self.closed && Instant::now() < deadline,
                "Helix did not show {expected:?}; log={}: {}, stderr={}, terminal={:?}",
                self.log.display(),
                fs::read_to_string(&self.log).unwrap_or_default(),
                fs::read_to_string(self.log.with_extension("stderr")).unwrap_or_default(),
                String::from_utf8_lossy(&self.screen)
            );
            self.pump();
        }
    }

    pub fn mark(&mut self) {
        self.log_start = fs::metadata(&self.log).map_or(0, |s| s.len() as usize);
        self.screen.clear();
    }

    pub fn log(&mut self, label: &str, ready: bool, predicate: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut file = None;
        let mut bytes = Vec::new();
        loop {
            if file.is_none() {
                match fs::File::open(&self.log) {
                    Ok(opened) => file = Some(opened),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("{}: {error}", self.log.display()),
                }
            }
            // Tail the log so observation does not repeatedly open and copy it
            // while the language server is scanning its source roots.
            if let Some(file) = &mut file {
                file.read_to_end(&mut bytes).unwrap();
            }
            let log = String::from_utf8_lossy(&bytes);
            for failure in ["failed to initialize language server", "StreamClosed"] {
                assert!(!log.contains(failure), "Helix {label}: {log}");
            }
            let timed_out = log.lines().any(|line| {
                let Some((_, request)) = line.split_once("request ") else {
                    return false;
                };
                request.split_once(" timed out").is_some_and(|(id, _)| {
                    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
                })
            });
            assert!(!timed_out, "Helix {label}: {log}");
            let matched = predicate(log.get(self.log_start..).unwrap_or(""))
                && (!ready || motor_analyzer_tests::helix::ready(&log));
            if matched {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Helix {label} did not complete: {log}"
            );
            self.pump();
        }
    }

    pub fn message(&mut self, expected: &str) {
        self.log(expected, false, |s| s.contains(expected));
    }

    pub fn replace(&mut self, text: &str) {
        self.keys(format!("%c{text}").as_bytes());
        self.text("INS");
        self.keys(b"\x1b");
        self.text("NOR");
    }

    pub fn save(&mut self) {
        self.mark();
        self.keys(b":w\r");
        self.message("\"method\":\"textDocument/formatting\"");
        self.message("\"method\":\"textDocument/didSave\"");
    }

    pub fn finish(self) {
        self.close(b":q!\r", &[(1049, 'l'), (1004, 'l'), (2004, 'l')], false);
    }

    pub fn finish_lsp(self) {
        self.close(b":q!\r", &[(1049, 'l'), (1004, 'l'), (2004, 'l')], true);
    }

    pub fn finish_shell(self) {
        // rmux restores bracketed paste to enabled for the surrounding shell.
        self.close(b"exit\n", &[(1049, 'l'), (2004, 'h')], false);
    }

    fn close(mut self, exit: &[u8], modes: &[(u32, char)], lsp: bool) {
        self.keys(exit);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !self.closed {
            assert!(
                Instant::now() < deadline,
                "Helix did not exit; {}",
                self.log.display()
            );
            self.pump();
        }
        assert!(self.child.wait().unwrap().success());
        let log = fs::read_to_string(&self.log).unwrap_or_default();
        // Basic terminal cases may quit before server initialization completes.
        // The LSP cases establish a live server and require its clean shutdown.
        if lsp {
            for method in ["initialized", "shutdown", "exit"] {
                assert!(
                    log.contains(&format!("\"method\":\"{method}\"")),
                    "Helix did not send {method}: {log}"
                );
            }
        }
        let all = String::from_utf8_lossy(&self.all);
        for (mode, restored) in modes {
            let begin = all
                .find(&format!("\x1b[?{mode}h"))
                .unwrap_or_else(|| panic!("terminal mode {mode} was not enabled: {all:?}"));
            let end = all
                .rfind(&format!("\x1b[?{mode}{restored}"))
                .unwrap_or_else(|| panic!("terminal mode {mode} was not restored: {all:?}"));
            assert!(begin < end, "terminal mode {mode} was not restored");
        }
        for mode in [1000, 1002, 1003, 1006] {
            assert!(
                !all.contains(&format!("\x1b[?{mode}h")),
                "mouse mode {mode} enabled"
            );
        }
    }
}

impl Drop for Editor {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
