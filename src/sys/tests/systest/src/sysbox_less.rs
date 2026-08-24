//! Tests for `sysbox less`.
//!
//! systest runs over a non-pty ssh session, so its own streams are not
//! terminals: the dump paths are exercised directly, while the pager gets the
//! terminal this test provides for it — pipes marked by the launch hint, sized
//! by `$LINES`/`$COLUMNS`, and then resized in band the way rmux and russhd
//! resize a program that is already running (docs/tui.md).

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const SYSBOX: &str = "/system/bin/sysbox";
const RUSH: &str = "/system/bin/rush";
const TYPEAHEAD_PARENT: &str = "sysbox-less-typeahead-parent";
const TYPEAHEAD_CHILD: &str = "sysbox-less-typeahead-child";

const TEN_LINES: &str = "line01\nline02\nline03\nline04\nline05\n\
                         line06\nline07\nline08\nline09\nline10\n";

fn build_files(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join("ten.txt"), TEN_LINES).unwrap();
    std::fs::write(root.join("two.txt"), b"first\nsecond\n").unwrap();
    std::fs::write(
        root.join("wrap.txt"),
        b"a\tb\n0123456789ABCDE\n\n\x1b[31mred\n",
    )
    .unwrap();
    std::fs::write(root.join("binary.bin"), [b'a', 0xff, b'b']).unwrap();
}

fn run_less(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(SYSBOX)
        .arg("less")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn less_stdin(input: &[u8]) -> std::process::Output {
    let mut child = Command::new(SYSBOX)
        .arg("less")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    drop(stdin); // EOF: `less` dumps what it read.
    child.wait_with_output().unwrap()
}

/// Without a terminal on both ends there is nothing to page on, and the text
/// comes out byte for byte, as `cat` would produce it.
fn test_dump(root: &Path) {
    let output = run_less(root, &["ten.txt"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), TEN_LINES);

    let output = less_stdin(TEN_LINES.as_bytes());
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), TEN_LINES);

    // No trailing newline is not one added.
    let output = less_stdin(b"no newline");
    assert_eq!(output.stdout, b"no newline");

    let output = less_stdin(b"");
    assert!(output.status.success());
    assert!(output.stdout.is_empty());

    println!("sysbox_less::test_dump PASS");
}

/// The shape a pipeline's last stage has: the data on stdin, a terminal on
/// stdout. Motor OS has no `/dev/tty` — a program's terminal is its own stdin
/// — so there is no keyboard to page with, and the text comes out whole
/// rather than one screenful with no way to ask for the next.
fn test_pipeline_shape(root: &Path) {
    let input = std::fs::File::open(root.join("ten.txt")).unwrap();
    let output = Command::new(SYSBOX)
        .arg("less")
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true")
        .env("LINES", "6")
        .env("COLUMNS", "32")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), TEN_LINES);

    println!("sysbox_less::test_pipeline_shape PASS");
}

fn test_errors(root: &Path) {
    let output = run_less(root, &["no-such-file"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no-such-file"));

    // Binary content is refused, not smeared over the screen.
    let output = run_less(root, &["binary.bin"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let output = less_stdin(&[b'a', 0xff, b'b']);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let output = run_less(root, &["ten.txt", "two.txt"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage"));

    let output = run_less(root, &["--help"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage"));

    println!("sysbox_less::test_errors PASS");
}

/// A terminal's stdin is a keyboard: with no filename there is nothing to
/// read, and `less` says so instead of hanging.
fn test_missing_filename() {
    let child = Command::new(SYSBOX)
        .arg("less")
        .env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("missing filename"),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    println!("sysbox_less::test_missing_filename PASS");
}

struct Pager {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    rows: usize,
    cols: usize,
    /// Everything the pager wrote before the frame just read: the alternate
    /// screen on the way in, then crossterm's own size negotiation.
    preamble: String,
}

fn spawn_terminal_command(
    cwd: &Path,
    program: &str,
    args: &[&str],
    rows: usize,
    cols: usize,
) -> Pager {
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        // This test is the pager's terminal provider; it does not need to be
        // on a terminal itself to be one.
        .env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true")
        .env("LINES", rows.to_string())
        .env("COLUMNS", cols.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    Pager {
        child,
        stdin,
        stdout,
        rows,
        cols,
        preamble: String::new(),
    }
}

fn spawn_pager(cwd: &Path, file: &str, rows: usize, cols: usize) -> Pager {
    spawn_terminal_command(cwd, SYSBOX, &["less", file], rows, cols)
}

fn spawn_shell_pager(cwd: &Path, command: &str, rows: usize, cols: usize) -> Pager {
    spawn_terminal_command(cwd, RUSH, &["-c", command], rows, cols)
}

impl Pager {
    /// One screen, as its rows: the pager's frames end with the attribute
    /// reset that closes the status line and start at the home position, with
    /// crossterm's own traffic — the alternate screen, the mode 2048
    /// negotiation, a fallback probe — in between and not part of either.
    fn frame(&mut self) -> Vec<String> {
        const END: &[u8] = b"\x1b[0m";

        let mut bytes = Vec::new();
        let mut byte = [0_u8; 1];
        while !bytes.ends_with(END) {
            assert_eq!(
                self.stdout.read(&mut byte).unwrap(),
                1,
                "the pager closed its stdout mid-frame: {:?}",
                String::from_utf8_lossy(&bytes)
            );
            bytes.push(byte[0]);
        }

        let written = String::from_utf8(bytes).unwrap();
        let start = written
            .rfind("\x1b[1;1H")
            .unwrap_or_else(|| panic!("no frame in {written:?}"));
        self.preamble = written[..start].to_owned();

        let frame = &written[start..];
        (1..=self.rows).map(|row| row_text(frame, row)).collect()
    }

    /// The pager repaints on every event, so exactly one frame follows a press.
    fn press(&mut self, keys: &str) -> Vec<String> {
        self.stdin.write_all(keys.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
        self.frame()
    }

    /// A terminal that changed shape says so in band: `CSI 48 ; rows ; cols ;
    /// h_px ; w_px t`, the report rmux and russhd push into the program's own
    /// stdin. There is no `SIGWINCH` here and nothing to ask afterwards.
    fn resize(&mut self, rows: usize, cols: usize) -> Vec<String> {
        write!(self.stdin, "\x1b[48;{rows};{cols};0;0t").unwrap();
        self.stdin.flush().unwrap();
        self.rows = rows;
        self.cols = cols;
        self.frame()
    }

    fn expect(&mut self, rows: Vec<String>, page: &[&str], status_prefix: &str) {
        let (status, content) = rows.split_last().unwrap();
        let content: Vec<&str> = content.iter().map(String::as_str).collect();
        assert_eq!(content, page);
        assert!(
            status.starts_with(status_prefix),
            "status {status:?} does not start with {status_prefix:?}"
        );
        assert!(
            status.chars().count() <= self.cols,
            "status {status:?} is wider than the screen"
        );
    }

    fn quit(mut self) {
        self.stdin.write_all(b"q").unwrap();
        self.stdin.flush().unwrap();

        // Quitting gives back the screen the reader was looking at.
        let mut tail = String::new();
        self.stdout.read_to_string(&mut tail).unwrap();
        assert!(
            tail.contains("\x1b[?1049l"),
            "the pager kept the alternate screen: {tail:?}"
        );
        assert!(self.child.wait().unwrap().success());
    }
}

/// What one 1-based row of a frame has painted on it: everything between that
/// row's cursor move and whatever escape sequence follows the text.
fn row_text(frame: &str, row: usize) -> String {
    let marker = format!("\x1b[{row};1H");
    let start = frame
        .find(&marker)
        .unwrap_or_else(|| panic!("no row {row} in {frame:?}"));

    let rest = &frame[start + marker.len()..];
    // The status line is painted in reverse video; its text starts after that.
    let rest = rest.strip_prefix("\x1b[7m").unwrap_or(rest);
    let end = rest.find('\x1b').unwrap_or(rest.len());
    rest[..end].to_owned()
}

fn test_paging(root: &Path) {
    let mut pager = spawn_pager(root, "ten.txt", 6, 32); // Five lines per page.

    let page1 = ["line01", "line02", "line03", "line04", "line05"];
    let page2 = ["line06", "line07", "line08", "line09", "line10"];

    let frame = pager.frame();
    pager.expect(frame, &page1, "ten.txt 5/10 lines (50%)");
    assert!(
        pager.preamble.contains("\x1b[?1049h"),
        "the pager painted over the reader's screen: {:?}",
        pager.preamble
    );

    // Forward to the last page; the end is a floor, not a wall to fall off.
    let frame = pager.press(" ");
    pager.expect(frame, &page2, "ten.txt (END) 10 lines");
    let frame = pager.press(" ");
    pager.expect(frame, &page2, "ten.txt (END) 10 lines");

    let frame = pager.press("b");
    pager.expect(frame, &page1, "ten.txt 5/10 lines (50%)");

    // Single lines, half pages, and the two ends.
    let frame = pager.press("j");
    pager.expect(
        frame,
        &["line02", "line03", "line04", "line05", "line06"],
        "ten.txt 6/10 lines (60%)",
    );
    let frame = pager.press("k");
    pager.expect(frame, &page1, "ten.txt 5/10 lines (50%)");
    let frame = pager.press("d");
    pager.expect(
        frame,
        &["line03", "line04", "line05", "line06", "line07"],
        "ten.txt 7/10 lines (70%)",
    );
    let frame = pager.press("u");
    pager.expect(frame, &page1, "ten.txt 5/10 lines (50%)");
    let frame = pager.press("G");
    pager.expect(frame, &page2, "ten.txt (END) 10 lines");
    let frame = pager.press("g");
    pager.expect(frame, &page1, "ten.txt 5/10 lines (50%)");

    // Arrow keys, page keys, and a key that means nothing.
    let frame = pager.press("\x1b[B");
    pager.expect(
        frame,
        &["line02", "line03", "line04", "line05", "line06"],
        "ten.txt 6/10 lines (60%)",
    );
    let frame = pager.press("\x1b[A");
    pager.expect(frame, &page1, "ten.txt 5/10 lines (50%)");
    let frame = pager.press("\x1b[6~");
    pager.expect(frame, &page2, "ten.txt (END) 10 lines");
    let frame = pager.press("\x1b[5~");
    pager.expect(frame, &page1, "ten.txt 5/10 lines (50%)");
    let frame = pager.press("z");
    pager.expect(frame, &page1, "ten.txt 5/10 lines (50%)");

    pager.quit();
    println!("sysbox_less::test_paging PASS");
}

/// A provider-backed shell preserves its terminal for a pager whose document
/// arrives through either a pipeline or an input redirect. Redirecting the
/// pager's output still selects byte-for-byte dump mode.
fn test_redirected_input_paging(root: &Path) {
    let page1 = ["line01", "line02", "line03", "line04", "line05"];
    let page2 = ["line06", "line07", "line08", "line09", "line10"];

    for command in ["cat ten.txt | less", "less < ten.txt"] {
        let mut pager = spawn_shell_pager(root, command, 6, 32);
        let frame = pager.frame();
        pager.expect(frame, &page1, "(stdin) 5/10 lines (50%)");
        let frame = pager.press(" ");
        pager.expect(frame, &page2, "(stdin) (END) 10 lines");
        pager.quit();
    }

    let output = Command::new(RUSH)
        .args(["-c", "cat ten.txt | less > paged.out"])
        .current_dir(root)
        .env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "redirected less failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(root.join("paged.out")).unwrap(),
        TEN_LINES
    );

    println!("sysbox_less::test_redirected_input_paging PASS");
}

pub fn is_helper(args: &[String]) -> bool {
    args.get(1)
        .is_some_and(|arg| matches!(arg.as_str(), TYPEAHEAD_PARENT | TYPEAHEAD_CHILD))
}

pub fn run_helper(args: &[String]) -> ! {
    if args[1] == TYPEAHEAD_CHILD {
        println!("TYPEAHEAD_READY");
        std::io::stdout().flush().unwrap();
        let gate = Path::new(&args[2]);
        while !gate.exists() {
            std::thread::yield_now();
        }
        std::process::exit(0)
    }

    let gate = &args[2];
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([TYPEAHEAD_CHILD, gate])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    assert!(child.wait().unwrap().success());
    let status = Command::new(SYSBOX)
        .args(["less", "ten.txt"])
        .status()
        .unwrap();
    std::process::exit(status.code().unwrap())
}

/// Bytes accepted by an uninterested child's synthesized terminal ring return
/// to the session stream at relay teardown and reach the next foreground app.
fn test_typeahead_reclaim(root: &Path) {
    let gate = root.join("typeahead.gate");
    let gate_arg = gate.to_str().unwrap();
    let mut pager = spawn_terminal_command(
        root,
        std::env::current_exe().unwrap().to_str().unwrap(),
        &[TYPEAHEAD_PARENT, gate_arg],
        6,
        32,
    );

    let mut ready = String::new();
    pager.stdout.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim_end(), "TYPEAHEAD_READY");
    pager.stdin.write_all(b"q").unwrap();
    pager.stdin.flush().unwrap();
    std::fs::write(&gate, b"go").unwrap();

    let mut output = String::new();
    pager.stdout.read_to_string(&mut output).unwrap();
    assert!(
        output.contains("\x1b[?1049h"),
        "pager did not start: {output:?}"
    );
    assert!(
        output.contains("\x1b[?1049l"),
        "pager did not quit: {output:?}"
    );
    assert!(pager.child.wait().unwrap().success());

    println!("sysbox_less::test_typeahead_reclaim PASS");
}

/// A file that fits on one screen is still a page: the rest of the screen is
/// blank, and the status line says so.
fn test_short_file(root: &Path) {
    let mut pager = spawn_pager(root, "two.txt", 6, 32);
    let frame = pager.frame();
    pager.expect(
        frame,
        &["first", "second", "", "", ""],
        "two.txt (END) 2 lines",
    );
    pager.quit();

    println!("sysbox_less::test_short_file PASS");
}

/// Paging counts what the terminal shows: tabs expanded, long lines wrapped,
/// and escape sequences spelled out rather than handed to the terminal.
fn test_wrapping(root: &Path) {
    let mut pager = spawn_pager(root, "wrap.txt", 4, 10);

    let frame = pager.frame();
    pager.expect(frame, &["a       b", "0123456789", "ABCDE"], "wrap.txt");
    let frame = pager.press("G");
    pager.expect(frame, &["ABCDE", "", "^[[31mred"], "wrap.txt");

    pager.quit();
    println!("sysbox_less::test_wrapping PASS");
}

/// A terminal that changes shape mid-read: the page is re-wrapped for the new
/// width, refilled for the new height, and the line the reader was on stays at
/// the top of the screen.
fn test_resize(root: &Path) {
    let mut pager = spawn_pager(root, "ten.txt", 6, 32);
    let frame = pager.frame();
    pager.expect(
        frame,
        &["line01", "line02", "line03", "line04", "line05"],
        "ten.txt 5/10 lines (50%)",
    );

    // A taller terminal shows more of the same file...
    let frame = pager.resize(8, 32);
    pager.expect(
        frame,
        &[
            "line01", "line02", "line03", "line04", "line05", "line06", "line07",
        ],
        "ten.txt 7/10 lines (70%)",
    );

    // ...and a shorter one keeps the reader where they were rather than
    // snapping back to the top.
    let frame = pager.press("G");
    pager.expect(
        frame,
        &[
            "line04", "line05", "line06", "line07", "line08", "line09", "line10",
        ],
        "ten.txt (END) 10 lines",
    );
    let frame = pager.resize(4, 32);
    pager.expect(
        frame,
        &["line04", "line05", "line06"],
        "ten.txt 6/10 lines (60%)",
    );

    pager.quit();

    // A narrower screen re-wraps: what was one line becomes two, and the line
    // at the top stays the line at the top.
    let mut pager = spawn_pager(root, "wrap.txt", 4, 10);
    let frame = pager.frame();
    pager.expect(frame, &["a       b", "0123456789", "ABCDE"], "wrap.txt");

    let frame = pager.press("G");
    pager.expect(frame, &["ABCDE", "", "^[[31mred"], "wrap.txt");
    let frame = pager.resize(4, 20);
    // Four rows now, not five: the status line is what a 20-column screen has
    // room to say about them.
    pager.expect(
        frame,
        &["0123456789ABCDE", "", "^[[31mred"],
        "wrap.txt (END) 4",
    );

    pager.quit();
    println!("sysbox_less::test_resize PASS");
}

/// `/system/bin/less` is the name people type: a rush shim over `sysbox less`. With
/// no terminal on either side of it, it dumps, exactly as the command does.
fn test_bin_shim(root: &Path) {
    let output = Command::new("/system/bin/less")
        .arg("ten.txt")
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "/system/bin/less failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap(), TEN_LINES);

    println!("sysbox_less::test_bin_shim PASS");
}

pub fn run_test() {
    let root: PathBuf = std::env::temp_dir().join("systest-sysbox-less");
    build_files(&root);

    test_dump(&root);
    test_pipeline_shape(&root);
    test_errors(&root);
    test_missing_filename();
    test_paging(&root);
    test_redirected_input_paging(&root);
    test_typeahead_reclaim(&root);
    test_short_file(&root);
    test_wrapping(&root);
    test_resize(&root);
    test_bin_shim(&root);

    std::fs::remove_dir_all(&root).unwrap();
    println!("sysbox_less::run_test PASS");
}
