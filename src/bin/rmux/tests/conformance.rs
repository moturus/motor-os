//! M9: the tmux oracle (details.md §9.1).
//!
//! Every other test here states what rmux should do and checks that it does.
//! This one states nothing: it drives each case through **both rmux and tmux**
//! and requires the two to paint the same picture. tmux is the reference, so
//! the corpus can be extended by anyone who can think of a key script without
//! having to know the answer first — which is rush's conformance thesis
//! (`rush/tests/conformance.rs:1-22`) with tmux in dash's place.
//!
//! # What makes the comparison valid
//!
//! `tests/defaults.tmux.conf` is a checked-in copy of the `~/.tmux.conf` that
//! §2.1 declares to be rmux's compiled-in defaults, and it is what tmux is
//! given with `-f`. Never the developer's own: the file is the spec and the
//! oracle's config at once, so the two cannot drift. Both sides also get a
//! pinned shell (`sh` resolves to dash here and to rush on Motor, and the
//! corpus tests rmux rather than the shell), an empty `$HOME` so no `rmux.toml`
//! or `.profile` can reach either, one 24x80 pty apiece, and nothing of the
//! environment they were run from.
//!
//! # The picture, not the bytes
//!
//! Byte-level agreement with tmux is neither achievable nor wanted, so both
//! streams are replayed into a [`Grid`] — rmux's own emulator doing the replay,
//! as `tests/host.rs` does and as §9.1 asks — and the *rows* are compared. One
//! thing is folded out on the way: **the status row**, which is chrome rather
//! than content and which the two word differently on purpose (tmux ends it
//! with a clock, §7.3). Borders are not — they are the box-drawing characters
//! tmux draws, junctions included (§7.1), so the corpus compares them.
//!
//! Requires tmux on the host; without it the suite skips rather than fails, so
//! a checkout on a machine without tmux still tests clean.

#![cfg(unix)]

use std::io::Read;
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use rmux::ansi::Parser;
use rmux::grid::Grid;

const RMUX: &str = env!("CARGO_BIN_EXE_rmux");
const TMUX: &str = "/usr/bin/tmux";
const ROWS: u16 = 24;
const COLS: u16 = 80;
/// Pinned on both sides. A login shell would read `/etc/profile`, which is the
/// host's business and not the same twice.
const SHELL: &str = "/bin/dash";
/// How long a screen has to hold still before it counts as settled.
const QUIET: Duration = Duration::from_millis(300);

/// One case: what is typed at a multiplexer, and the text that says the last
/// of it has taken effect.
struct Case {
    /// A sentence, so a failure names what was being tested.
    what: &'static str,
    /// Typed in order, `\x01` being the prefix (§2.1) and `\r` Enter. A chunk
    /// is sent only once the screen has stopped changing, because **typing at
    /// a shell that has not printed its prompt yet is a race rather than a
    /// case**: the echo comes from the pane's line discipline and the prompt
    /// from the shell, so which of the two lands first says nothing about the
    /// multiplexer. Split a case wherever a new shell appears.
    script: &'static [&'static str],
    /// Painted text that appears once the last chunk has taken effect. Cases
    /// that end at a shell prompt use [`SETTLE`], whose marker is absent from
    /// the command that prints it — a needle that also matched the echoed
    /// command line would be satisfied before the command had run.
    settled: &'static str,
}

/// Typed at the end of a case that ends at a shell prompt. The quotes keep
/// `OK` out of the echoed line, so the marker is the command's *output*.
const SETTLE: &str = "echo O''K\r";
const SETTLED: &str = "OK";

/// What a pane's emulator does with what a program prints (§5).
#[rustfmt::skip]
const SCREEN: &[Case] = &[
    Case { what: "a session starts with one shell at a prompt",
           script: &[SETTLE], settled: SETTLED },
    Case { what: "output wider than the pane wraps at the pane's edge",
           script: &["for i in 1 2 3 4 5 6 7 8 9; do printf 123456789; done; echo\r", SETTLE],
           settled: SETTLED },
    Case { what: "a line exactly as wide as the pane does not wrap early",
           script: &["for i in 1 2 3 4 5 6 7 8; do printf 1234567890; done; printf 'X\\n'\r", SETTLE],
           settled: SETTLED },
    Case { what: "a cursor motion moves the cursor and not the text",
           script: &["printf 'abc\\033[2Dz\\n'\r", SETTLE],
           settled: SETTLED },
    Case { what: "erase-to-end-of-line erases what is after the cursor",
           script: &["printf 'abcdef\\033[3D\\033[K\\n'\r", SETTLE],
           settled: SETTLED },
    Case { what: "a backspace steps back over a character without erasing it",
           script: &["printf 'abc\\bX\\n'\r", SETTLE],
           settled: SETTLED },
    Case { what: "a tab moves to the next tab stop",
           script: &["printf 'a\\tb\\tc\\n'\r", SETTLE],
           settled: SETTLED },
    Case { what: "styling changes no text",
           script: &["printf '\\033[1;31mred\\033[m plain\\n'\r", SETTLE],
           settled: SETTLED },
    Case { what: "clearing the screen leaves the prompt at the top",
           script: &["printf 'one\\ntwo\\n'\r", "printf '\\033[2J\\033[H'\r", SETTLE],
           settled: SETTLED },
    Case { what: "output longer than the pane scrolls the top of it away",
           script: &["i=0; while [ $i -lt 30 ]; do echo \"line$i\"; i=$((i+1)); done\r", SETTLE],
           settled: SETTLED },
    Case { what: "a scroll region scrolls what is inside it and holds the rest still",
           script: &["printf '\\033[2J\\033[H'\r",
                     "printf 'held\\033[3;10r\\033[3H'; i=0; while [ $i -lt 12 ]; do echo \"in$i\"; i=$((i+1)); done; printf '\\033[r'\r",
                     SETTLE],
           settled: SETTLED },
    // The one command whose whole point is that the picture does not change,
    // which is why tmux is the right judge of it: a redraw that dropped a row,
    // or put the cursor back somewhere else, would show up here as a screen
    // that stopped matching tmux's.
    Case { what: "prefix r redraws the console and changes nothing on it",
           script: &["printf 'above\\n'\r", SETTLE, "\x01r"],
           settled: SETTLED },
];

/// Windows: the list, the numbering, and the keys that move between them (§7.4).
#[rustfmt::skip]
const WINDOWS: &[Case] = &[
    Case { what: "prefix c opens a second window, and the first keeps running",
           script: &["x=inthefirst\r", "\x01c", SETTLE],
           settled: SETTLED },
    Case { what: "prefix p goes back to the window that is still there",
           script: &["x=inthefirst\r", "\x01c", "\x01p", "echo \"$x\"\r"],
           settled: "inthefirst" },
    Case { what: "prefix n goes to the next window",
           script: &["x=inthefirst\r", "\x01c", "y=inthesecond\r", "\x010", "\x01n", "echo \"$y\"\r"],
           settled: "inthesecond" },
    Case { what: "prefix 0 selects the window with that number",
           script: &["x=inthefirst\r", "\x01c", "\x010", "echo \"$x\"\r"],
           settled: "inthefirst" },
    Case { what: "S-Right, on the root table, goes to the next window",
           script: &["x=inthefirst\r", "\x01c", "y=inthesecond\r", "\x1b[1;2C", "\x1b[1;2C", "echo \"$y\"\r"],
           settled: "inthesecond" },
];

/// Panes: the split tree, its borders and the keys that move between them (§7.1).
#[rustfmt::skip]
const PANES: &[Case] = &[
    Case { what: "prefix | splits the pane side by side",
           script: &["x=ontheleft\r", "\x01|", SETTLE],
           settled: SETTLED },
    Case { what: "prefix - splits the pane one above the other",
           script: &["x=ontop\r", "\x01-", SETTLE],
           settled: SETTLED },
    Case { what: "M-Left goes back to the pane the split divided",
           script: &["x=ontheleft\r", "\x01|", "\x1b[1;3D", "echo \"$x\"\r"],
           settled: "ontheleft" },
    Case { what: "prefix o goes round the panes in order",
           script: &["x=first\r", "\x01|", "\x01o", "echo \"$x\"\r"],
           settled: "first" },
    Case { what: "a split of a split divides only the pane it was asked to",
           script: &["\x01|", "\x01-", SETTLE],
           settled: SETTLED },
    Case { what: "a command typed at the prompt splits the pane too",
           script: &["\x01:", "split-window -h\r", SETTLE],
           settled: SETTLED },
    // Where a resized border *lands* is the interesting part, and it is the
    // part a unit test can only check against itself. `C-Left` is tmux's own
    // binding, the pane it acts on is the one the split just made, and the
    // border has to end up in the same column in both.
    Case { what: "prefix C-Left moves the border one column",
           script: &["x=ontheleft\r", "\x01|", "\x01\x1b[1;5D", SETTLE],
           settled: SETTLED },
    Case { what: "prefix M-Right moves it five, the other way",
           script: &["x=ontop\r", "\x01-", "\x01\x1b[1;3B", SETTLE],
           settled: SETTLED },
];

/// Cases where rmux deliberately paints something else, with the reason. Each
/// is asserted to *still* differ, so this list cannot rot into a list of bugs
/// that were quietly fixed — or hide one that was quietly introduced. It is the
/// honest scope statement of the project (§9.1).
#[rustfmt::skip]
const DIVERGENCES: &[(Case, &str)] = &[
    (Case { what: "prefix & kills the window outright",
            script: &["x=inthefirst\r", "\x01c", "y=inthesecond\r", "\x01&"],
            settled: "$" },
     "tmux asks `kill-window? (y/n)` first; `confirm-before` is a command \
      rmux does not have, and a mode for two bindings is not worth it (M6)"),
    (Case { what: "a mode takes the keys that arrived with it",
            script: &["\x01:split-window -h\r", SETTLE], settled: SETTLED },
     "rmux decides what a key means as it is reached, so `prefix :` and the \
      command typed in the same read reach the prompt that key opened (M8); \
      tmux's prompt is not up yet and the command goes to the shell"),
    (Case { what: "copy mode says so on the status row",
            script: &["x=inthefirst\r", "\x01["], settled: "inthefirst" },
     "tmux draws its copy-mode indicator in the pane's top-right corner; \
      rmux borrows the status row, which a pane has no corner to spare for (M8)"),
];

/// A multiplexer running on a pty of this test's making, and the picture it has
/// painted so far.
struct Mux {
    master: std::fs::File,
    child: std::process::Child,
    grid: Grid,
    parser: Parser,
    dir: PathBuf,
    /// How to ask this one to end its sessions, which is also what reaps the
    /// shells in them (§3.6).
    end: fn(&Path),
}

impl Mux {
    /// rmux, with an empty `$HOME` but for the one setting the corpus pins.
    fn rmux(dir: &Path) -> Mux {
        std::fs::create_dir_all(dir.join(".config")).unwrap();
        std::fs::write(
            dir.join(".config/rmux.toml"),
            format!("default-shell = \"{SHELL}\"\n"),
        )
        .unwrap();
        Mux::spawn(dir, RMUX, &[], end_rmux)
    }

    /// tmux, given the checked-in copy of the file rmux's defaults *are*.
    fn tmux(dir: &Path) -> Mux {
        let defaults = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/defaults.tmux.conf");
        let conf = dir.join("tmux.conf");
        // Two pins, both to make the comparison possible rather than to change
        // what is compared. `default-command` rather than `default-shell`:
        // tmux runs the latter as a login shell, and what a login shell reads
        // is the host's. `assume-paste-time 0` turns off tmux's paste
        // heuristic, which forwards a binding verbatim when the key before it
        // arrived less than a millisecond earlier -- a whole key script does,
        // and rmux has no such heuristic (§8.1: a bound key is rmux's however
        // it arrived). Leaving it on would test tmux's timer.
        let text = format!(
            "{}\nset -g default-command \"{SHELL}\"\nset -g assume-paste-time 0\n",
            std::fs::read_to_string(&defaults).unwrap()
        );
        std::fs::write(&conf, text).unwrap();
        let sock = dir.join("sock");
        let args = [
            "-f",
            conf.to_str().unwrap(),
            "-S",
            sock.to_str().unwrap(),
            "new-session",
        ];
        Mux::spawn(dir, TMUX, &args, end_tmux)
    }

    fn spawn(dir: &Path, program: &str, args: &[&str], end: fn(&Path)) -> Mux {
        let (master, slave) = open_pty();
        let child = unsafe {
            Command::new(program)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("TERM", "xterm")
                // Box-drawing borders rather than the ACS charset, which the
                // replay below would render as the letters ACS puts them under.
                .env("LC_ALL", "C.UTF-8")
                .env("HOME", dir)
                .env("TMPDIR", dir)
                .args(args)
                .stdin(Stdio::from_raw_fd(dup(slave)))
                .stdout(Stdio::from_raw_fd(dup(slave)))
                .stderr(Stdio::from_raw_fd(dup(slave)))
                .spawn()
                .unwrap_or_else(|e| panic!("failed to spawn {program}: {e}"))
        };
        unsafe { libc::close(slave) };
        Mux {
            master,
            child,
            grid: Grid::new(ROWS as usize, COLS as usize),
            parser: Parser::new(),
            dir: dir.to_owned(),
            end,
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
        self.master.flush().unwrap();
    }

    fn pump(&mut self) {
        let mut buf = [0_u8; 4096];
        set_nonblocking(&self.master);
        match self.master.read(&mut buf) {
            Ok(0) => std::thread::sleep(Duration::from_millis(5)),
            Ok(n) => {
                let grid = &mut self.grid;
                self.parser.feed(&buf[..n], &mut |action| {
                    let _ = grid.apply(action);
                });
            }
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }

    /// Wait until some row of the painted screen holds `needle`.
    fn wait_painted(&mut self, needle: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if self.picture().iter().any(|row| row.contains(needle)) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.pump();
        }
    }

    /// Wait until the screen has stopped changing.
    ///
    /// The gate between one chunk of a case and the next, and before the
    /// picture is compared: a needle says something has happened, and this says
    /// nothing more is about to. A shell starting in a new window paints
    /// nothing for a moment and then a prompt, so the two have to be waited for
    /// separately.
    fn settle(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut last = self.picture();
        let mut since = Instant::now();
        while Instant::now() < deadline {
            self.pump();
            let now = self.picture();
            if now != last {
                last = now;
                since = Instant::now();
            } else if since.elapsed() >= QUIET {
                return;
            }
        }
    }

    /// The pane rows, without the status row.
    fn picture(&self) -> Vec<String> {
        (0..self.grid.rows() - 1)
            .map(|row| self.grid.line(row))
            .collect()
    }

    /// The picture as text, for a failure message that shows it.
    fn shown(&self) -> String {
        self.picture()
            .iter()
            .enumerate()
            .map(|(at, row)| format!("  {at:>2}|{row}\n"))
            .collect()
    }
}

impl Drop for Mux {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Killing the client is not enough: a session outliving its client is
        // what a detach *is* (§7.3), so both multiplexers leave a server and a
        // shell behind on purpose. `tests/host.rs` learned this the expensive
        // way -- 827 of them, after a few hundred runs.
        (self.end)(&self.dir);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn end_rmux(dir: &Path) {
    let rmux = |args: &[&str]| -> Option<String> {
        let mut child = Command::new(RMUX)
            .env("TMPDIR", dir)
            .env("HOME", dir)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        wait_bounded(&mut child)?;
        let out = child.wait_with_output().ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let Some(listing) = rmux(&["ls"]) else {
        return;
    };
    for line in listing.lines() {
        if let Some((name, _)) = line.split_once(':') {
            let _ = rmux(&["kill-session", "-t", name]);
        }
    }
}

fn end_tmux(dir: &Path) {
    if let Ok(mut child) = Command::new(TMUX)
        .arg("-S")
        .arg(dir.join("sock"))
        .arg("kill-server")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        wait_bounded(&mut child);
    }
}

/// Wait for a command, but not forever: this runs from a destructor, where a
/// hang would take every case after it with it (§9.3).
fn wait_bounded(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(_) => return None,
        }
    }
}

/// A scratch directory this case alone uses, so that two cases cannot meet on
/// one port file or one socket (§9.3).
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rmux-conf-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn open_pty() -> (std::fs::File, RawFd) {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
        let name = libc::ptsname(master);
        assert!(!name.is_null(), "ptsname failed");
        let slave = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
        assert!(slave >= 0, "opening the pty slave failed");

        // This terminal does not echo, so everything read back was painted by
        // the multiplexer under test rather than by the line discipline.
        let mut termios: libc::termios = std::mem::zeroed();
        assert_eq!(libc::tcgetattr(slave, &mut termios), 0);
        termios.c_lflag &= !libc::ECHO;
        assert_eq!(libc::tcsetattr(slave, libc::TCSANOW, &termios), 0);

        let winsize = libc::winsize {
            ws_row: ROWS,
            ws_col: COLS,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(libc::ioctl(slave, libc::TIOCSWINSZ, &winsize), 0);
        (std::fs::File::from_raw_fd(master), slave)
    }
}

fn dup(fd: RawFd) -> RawFd {
    let new = unsafe { libc::dup(fd) };
    assert!(new >= 0, "dup failed");
    new
}

fn set_nonblocking(file: &std::fs::File) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        let fd = file.as_raw_fd();
        libc::fcntl(
            fd,
            libc::F_SETFL,
            libc::fcntl(fd, libc::F_GETFL, 0) | libc::O_NONBLOCK,
        );
    }
}

/// Run one case through one multiplexer and hand back what it painted.
fn play(mut mux: Mux, case: &Case) -> Result<Vec<String>, String> {
    // The first prompt says the shell is up and listening; typing before it is
    // typing at whatever the pty happens to be buffering.
    if !mux.wait_painted("$") {
        return Err(format!("no prompt appeared:\n{}", mux.shown()));
    }
    for chunk in case.script {
        mux.settle();
        mux.send(chunk.as_bytes());
    }
    if !mux.wait_painted(case.settled) {
        return Err(format!(
            "{:?} never appeared:\n{}",
            case.settled,
            mux.shown()
        ));
    }
    mux.settle();
    Ok(mux.picture())
}

/// Compare rmux against tmux on `case`; `None` means they agree.
///
/// The two run at once, on scratch directories of their own: a case takes about
/// as long as a shell takes to start, and the corpus is long enough for that to
/// be worth halving.
fn disagreement(case: &Case, tag: &str) -> Option<String> {
    let (r, t) = std::thread::scope(|scope| {
        let r = scope.spawn(|| play(Mux::rmux(&scratch(&format!("{tag}-r"))), case));
        let t = scope.spawn(|| play(Mux::tmux(&scratch(&format!("{tag}-t"))), case));
        (r.join(), t.join())
    });
    let r = r.unwrap_or_else(|_| Err("panicked".to_owned()));
    let t = t.unwrap_or_else(|_| Err("panicked".to_owned()));
    match (r, t) {
        (Err(why), _) => Some(format!("rmux: {why}")),
        (_, Err(why)) => Some(format!("tmux: {why}")),
        (Ok(r), Ok(t)) if r != t => {
            let rows = (0..r.len().max(t.len()))
                .filter(|at| r.get(*at) != t.get(*at))
                .map(|at| {
                    format!(
                        "    row {at}:\n      rmux {:?}\n      tmux {:?}\n",
                        r.get(at).map(String::as_str).unwrap_or(""),
                        t.get(at).map(String::as_str).unwrap_or("")
                    )
                })
                .collect::<String>();
            Some(format!("the pictures differ:\n{rows}"))
        }
        _ => None,
    }
}

fn have_tmux() -> bool {
    Path::new(TMUX).exists() && Path::new(SHELL).exists()
}

/// Play every case in `corpus` and require tmux to agree with all of them.
///
/// One group per test function, which is what runs them in parallel: a case
/// costs about what starting a shell costs, and there is no state between them
/// beyond the scratch directory each already has.
fn corpus_agrees(corpus: &[Case], tag: &str) {
    if !have_tmux() {
        eprintln!("skipping: {TMUX} or {SHELL} is not installed");
        return;
    }
    let mut failures = Vec::new();
    for (at, case) in corpus.iter().enumerate() {
        if let Some(why) = disagreement(case, &format!("{tag}{at}")) {
            failures.push(format!("\n  case {at}: {}\n    {why}", case.what));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} {tag} cases disagree with tmux:{}",
        failures.len(),
        corpus.len(),
        failures.join("")
    );
}

#[test]
fn the_screen_corpus_agrees_with_tmux() {
    corpus_agrees(SCREEN, "screen");
}

#[test]
fn the_window_corpus_agrees_with_tmux() {
    corpus_agrees(WINDOWS, "window");
}

#[test]
fn the_pane_corpus_agrees_with_tmux() {
    corpus_agrees(PANES, "pane");
}

#[test]
fn the_documented_divergences_still_diverge() {
    if !have_tmux() {
        eprintln!("skipping: {TMUX} or {SHELL} is not installed");
        return;
    }
    let mut fixed = Vec::new();
    for (at, (case, reason)) in DIVERGENCES.iter().enumerate() {
        if disagreement(case, &format!("d{at}")).is_none() {
            fixed.push(format!("\n  {}: documented as {reason}", case.what));
        }
    }
    assert!(
        fixed.is_empty(),
        "these no longer diverge from tmux; remove them from DIVERGENCES:{}",
        fixed.join("")
    );
}
