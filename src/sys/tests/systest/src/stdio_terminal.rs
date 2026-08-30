/*
 * Per-descriptor `is_terminal()` tests (docs/tui.md).
 *
 * systest normally runs over a non-pty ssh session, so its own streams are
 * not terminals. These tests also decline any ambient session terminal, so
 * they exercise the same matrix when run interactively. They provide the
 * terminal themselves: a "report child" is spawned with all three streams,
 * with or without the terminal launch hint, and reports what its descriptors
 * answer. For mixed-stdio rows, the report child spawns mask children through
 * `std::process::Command`, which is what covers the `moto-rt` copy embedded
 * in the installed Rust toolchain; the launch-hint rows also spawn through
 * `moto_rt::process::spawn` directly.
 */

use std::io::{BufRead, BufReader, Read, Write};

const REPORT_CHILD: &str = "stdio-terminal-report-child";
const REPORT_PATH_ENV: &str = "MOTOR_STDIO_REPORT_PATH";
const MASK_CHILD: &str = "stdio-terminal-mask-child";
const FILE_RELAY_PARENT: &str = "stdio-terminal-file-relay-parent";
const CLOSE_STDIN_PARENT: &str = "stdio-terminal-close-stdin-parent";
const CLOSE_TERMINAL_PARENT: &str = "stdio-terminal-close-terminal-parent";

/// The mask child's exit code is `MASK_EXIT_BASE` plus its 3-bit mask, so a
/// child whose streams are all captured needs no working stdout to report
/// what it saw.
const MASK_EXIT_BASE: i32 = 64;

pub fn is_report_child(args: &[String]) -> bool {
    args.len() == 2 && args[1] == REPORT_CHILD
}

pub fn is_mask_child(args: &[String]) -> bool {
    args.len() == 2
        && matches!(
            args[1].as_str(),
            MASK_CHILD | FILE_RELAY_PARENT | CLOSE_STDIN_PARENT | CLOSE_TERMINAL_PARENT
        )
}

/// stdin/stdout/stderr as bits 2/1/0, so `{:03b}` prints in the order
/// docs/tui.md's mask table uses.
fn self_mask() -> u32 {
    use std::io::IsTerminal;

    let mut mask = 0;
    if std::io::stdin().is_terminal() {
        mask |= 0b100;
    }
    if std::io::stdout().is_terminal() {
        mask |= 0b010;
    }
    if std::io::stderr().is_terminal() {
        mask |= 0b001;
    }
    mask
}

pub fn run_mask_child(args: &[String]) -> ! {
    use std::process::{Command, Stdio};

    if args[1] == MASK_CHILD {
        let terminal = moto_rt::fs::is_terminal(moto_rt::FD_TERMINAL) as i32;
        std::process::exit(MASK_EXIT_BASE + self_mask() as i32 + terminal * 8)
    }

    if args[1] == CLOSE_STDIN_PARENT || args[1] == CLOSE_TERMINAL_PARENT {
        let fd = if args[1] == CLOSE_STDIN_PARENT {
            moto_rt::FD_STDIN
        } else {
            moto_rt::FD_TERMINAL
        };
        moto_rt::fs::close(fd).unwrap();
        let reused = moto_rt::fs::open(
            std::env::current_exe().unwrap().to_str().unwrap(),
            moto_rt::fs::O_READ,
        )
        .unwrap();
        assert_eq!(reused, fd);
    }

    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.arg(MASK_CHILD)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if args[1] != FILE_RELAY_PARENT {
        cmd.stdin(Stdio::null());
    }
    std::process::exit(cmd.status().unwrap().code().unwrap())
}

/// Spawns a mask child with one stream redirected, as an interactive shell
/// would for `> file`, `< file`, `2> file`, or `... &`.
fn spawn_mask_child(mode: &str) -> (u32, bool) {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new(std::env::current_exe().unwrap());
    let child = match mode {
        "filerelay" => FILE_RELAY_PARENT,
        "close0" => CLOSE_STDIN_PARENT,
        "close3" => CLOSE_TERMINAL_PARENT,
        _ => MASK_CHILD,
    };
    cmd.arg(child)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    match mode {
        "inherit" => {}
        "inpiped" | "close3" | "inpiped-no-terminal" => {
            cmd.stdin(Stdio::piped());
        }
        "outpiped" => {
            cmd.stdout(Stdio::piped());
        }
        "errpiped" => {
            cmd.stderr(Stdio::piped());
        }
        "innull" => {
            cmd.stdin(Stdio::null());
        }
        "infile" | "filerelay" => {
            cmd.stdin(std::fs::File::open(std::env::current_exe().unwrap()).unwrap());
        }
        "close0" => {}
        other => panic!("unknown mask mode {other:?}"),
    }
    if mode == "inpiped-no-terminal" {
        cmd.env(moto_rt::process::STDIO_NO_TERMINAL_ENV_KEY, "true");
    }

    let code = cmd.status().unwrap().code().unwrap();
    assert!(
        (MASK_EXIT_BASE..MASK_EXIT_BASE + 16).contains(&code),
        "mask child exited with {code}"
    );
    let result = (code - MASK_EXIT_BASE) as u32;
    (result & 0b111, result & 0b1000 != 0)
}

/// A terminal endpoint's size probe can leave its answer (e.g. `ESC[23;80R`)
/// in this child's stdin, glued to the next command typed into a pane
/// (rmux/details.md §3.2). Terminal reports are not commands: drop escape
/// sequences, keep everything else.
fn strip_escape_sequences(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\x1b' {
            out.push(ch);
            continue;
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            // CSI: parameter and intermediate bytes end at a final byte @..~.
            for ch in chars.by_ref() {
                if ('\x40'..='\x7e').contains(&ch) {
                    break;
                }
            }
        } else {
            chars.next();
        }
    }
    out
}

pub fn run_report_child() -> ! {
    let key = moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY;
    // The launch hint is consumed by the spawn path; it must never appear as
    // live environment, whichever way this child was spawned.
    let key_present = std::env::var(key).is_ok() as u32;
    let no_terminal_key_present =
        std::env::var(moto_rt::process::STDIO_NO_TERMINAL_ENV_KEY).is_ok() as u32;

    let mask = self_mask();
    // An existing descriptor's answer must not follow the mutable
    // environment, in either direction.
    unsafe { std::env::set_var(key, "true") };
    let mask_set = self_mask();
    unsafe { std::env::remove_var(key) };
    let mask_unset = self_mask();

    let terminal = moto_rt::fs::is_terminal(moto_rt::FD_TERMINAL) as u32;
    let first_open = moto_rt::fs::open(
        std::env::current_exe().unwrap().to_str().unwrap(),
        moto_rt::fs::O_READ,
    )
    .unwrap();
    moto_rt::fs::close(first_open).unwrap();

    // Duplicates share the descriptor's object, so they share its answer,
    // and descriptors above 2 are not special.
    let dup = moto_rt::fs::duplicate(moto_rt::FD_STDOUT).unwrap();
    let duporig = moto_rt::fs::is_terminal(moto_rt::FD_STDOUT) as u32;
    let dupnew = moto_rt::fs::is_terminal(dup) as u32;
    moto_rt::fs::close(dup).unwrap();

    let report = format!(
        "self={mask:03b} set={mask_set:03b} unset={mask_unset:03b} \
         key={key_present} nokey={no_terminal_key_present} \
         terminal={terminal} firstfd={first_open} \
         dupfd={dup} duporig={duporig} dupnew={dupnew}"
    );
    println!("{report}");
    std::io::stdout().flush().unwrap();
    if let Ok(path) = std::env::var(REPORT_PATH_ENV) {
        std::fs::write(path, report).unwrap();
    }

    loop {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).unwrap() == 0 {
            std::process::exit(1);
        }
        let line = strip_escape_sequences(&line);
        let words: Vec<&str> = line.split_ascii_whitespace().collect();
        match words.as_slice() {
            ["mask", mode] => {
                let (mask, terminal) = spawn_mask_child(mode);
                println!("mask={mask:03b} terminal={}", terminal as u32);
                std::io::stdout().flush().unwrap();
            }
            ["exit"] => std::process::exit(0),
            _ => panic!("unknown report command {line:?}"),
        }
    }
}

struct ReportChild {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    stderr: std::thread::JoinHandle<Vec<u8>>,
}

fn spawn_report_child(terminal: bool) -> ReportChild {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.arg(REPORT_CHILD)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(moto_rt::process::STDIO_NO_TERMINAL_ENV_KEY, "true");
    if terminal {
        // This test is the child's terminal provider; it does not need to
        // be on a terminal itself to be one.
        cmd.env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true");
    }
    let mut child = cmd.spawn().unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let mut child_stderr = child.stderr.take().unwrap();
    let stderr = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        child_stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    ReportChild {
        child,
        stdin,
        stdout,
        stderr,
    }
}

impl ReportChild {
    fn read_line(&mut self) -> String {
        let mut line = String::new();
        assert!(
            self.stdout.read_line(&mut line).unwrap() > 0,
            "the report child closed its stdout"
        );
        line.trim_end().to_owned()
    }

    fn mask(&mut self, mode: &str) -> (String, bool) {
        writeln!(self.stdin, "mask {mode}").unwrap();
        self.stdin.flush().unwrap();
        let line = self.read_line();
        (
            field(&line, "mask").to_owned(),
            field(&line, "terminal") == "1",
        )
    }

    fn finish(mut self) {
        writeln!(self.stdin, "exit").unwrap();
        self.stdin.flush().unwrap();
        let status = self.child.wait().unwrap();
        let stderr = self.stderr.join().unwrap();
        assert!(
            status.success(),
            "{status}: {}",
            String::from_utf8_lossy(&stderr)
        );
    }
}

fn field<'a>(report: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    report
        .split_ascii_whitespace()
        .find_map(|word| word.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no {key} in {report:?}"))
}

/// One report child, both self-report and mixed-stdio descendants checked
/// against the design doc's tables.
fn check_report_child(terminal: bool) {
    let (own, descendants): (&str, &[(&str, &str, bool)]) = if terminal {
        (
            "111",
            &[
                ("inherit", "111", false),
                ("outpiped", "101", false),
                ("inpiped", "011", true),
                ("errpiped", "110", false),
                ("innull", "011", true),
                ("infile", "011", true),
                ("filerelay", "000", true),
                ("inpiped-no-terminal", "011", false),
                ("close0", "000", false),
                ("close3", "000", false),
            ],
        )
    } else {
        // A captured child is not a terminal, and neither is anything that
        // inherits from it.
        ("000", &[("inherit", "000", false)])
    };

    let mut child = spawn_report_child(terminal);
    let report = child.read_line();

    assert_eq!(field(&report, "self"), own, "in {report:?}");
    assert_eq!(field(&report, "set"), own, "in {report:?}");
    assert_eq!(field(&report, "unset"), own, "in {report:?}");
    assert_eq!(field(&report, "key"), "0", "in {report:?}");
    assert_eq!(field(&report, "nokey"), "0", "in {report:?}");
    assert_eq!(field(&report, "terminal"), "0", "in {report:?}");
    assert_eq!(
        field(&report, "firstfd").parse::<i32>().unwrap(),
        moto_rt::FD_TERMINAL,
        "in {report:?}"
    );
    let expected = if terminal { "1" } else { "0" };
    assert_eq!(field(&report, "duporig"), expected, "in {report:?}");
    assert_eq!(field(&report, "dupnew"), expected, "in {report:?}");
    assert!(
        field(&report, "dupfd").parse::<i32>().unwrap() > 2,
        "in {report:?}"
    );

    for (mode, expected_mask, expected_terminal) in descendants {
        let (mask, terminal) = child.mask(mode);
        assert_eq!(mask, *expected_mask, "descendant {mode}");
        assert_eq!(terminal, *expected_terminal, "descendant {mode}");
    }
    child.finish();
}

fn test_terminal_backed_child() {
    check_report_child(true);
    println!("test_stdio_terminal_backed_child PASS");
}

fn test_captured_child_non_terminal() {
    check_report_child(false);
    println!("test_stdio_terminal_captured_child PASS");
}

/// Spawns a mask child through the runtime directly, with all three streams
/// captured, optionally marked by the launch hint.
fn direct_spawn_mask(mark_terminal: bool) -> (u32, [bool; 3]) {
    let mut env: Vec<(String, String)> = std::env::vars().collect();
    env.push((
        moto_rt::process::STDIO_NO_TERMINAL_ENV_KEY.to_owned(),
        "true".to_owned(),
    ));
    if mark_terminal {
        env.push((
            moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY.to_owned(),
            "true".to_owned(),
        ));
    }
    let spawn_args = moto_rt::process::SpawnArgs {
        program: std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        args: vec![MASK_CHILD.to_owned()],
        env,
        cwd: None,
        stdin: moto_rt::process::STDIO_MAKE_PIPE,
        stdout: moto_rt::process::STDIO_MAKE_PIPE,
        stderr: moto_rt::process::STDIO_MAKE_PIPE,
    };

    let res = moto_rt::process::spawn(spawn_args).unwrap();
    let parent_fds = [res.stdin, res.stdout, res.stderr];
    let parent_terminals = parent_fds.map(moto_rt::fs::is_terminal);

    let code = moto_rt::process::wait(res.handle).unwrap();
    for fd in parent_fds {
        moto_rt::fs::close(fd).unwrap();
    }
    moto_rt::alloc::release_handle(res.handle).unwrap();

    assert!(
        (MASK_EXIT_BASE..MASK_EXIT_BASE + 16).contains(&code),
        "mask child exited with {code}"
    );
    let result = (code - MASK_EXIT_BASE) as u32;
    assert_eq!(result & 0b1000, 0, "direct child unexpectedly got fd 3");
    (result & 0b111, parent_terminals)
}

fn test_direct_spawn_hint() {
    let (mask, parent) = direct_spawn_mask(false);
    assert_eq!(mask, 0b000);
    assert_eq!(parent, [false; 3]);

    let (mask, parent) = direct_spawn_mask(true);
    assert_eq!(
        mask, 0b111,
        "the launch hint marks explicitly created pipes"
    );
    assert_eq!(
        parent, [false; 3],
        "a parent-side ChildStdio is the provider's end, not a terminal"
    );

    println!("test_stdio_terminal_direct_spawn PASS");
}

fn test_non_stdio_descriptors() {
    // Invalid descriptors.
    assert!(!moto_rt::fs::is_terminal(-1));
    assert!(!moto_rt::fs::is_terminal(1_000_000));

    // A regular file.
    let exe = std::env::current_exe().unwrap();
    let fd = moto_rt::fs::open(exe.to_str().unwrap(), moto_rt::fs::O_READ).unwrap();
    assert!(!moto_rt::fs::is_terminal(fd));
    moto_rt::fs::close(fd).unwrap();

    // A socket.
    let addr: core::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let fd = moto_rt::net::bind(moto_rt::net::PROTO_UDP, &addr.into()).unwrap();
    assert!(!moto_rt::fs::is_terminal(fd));
    moto_rt::fs::close(fd).unwrap();

    println!("test_stdio_terminal_non_stdio_descriptors PASS");
}

pub fn run_all_tests() {
    test_terminal_backed_child();
    test_captured_child_non_terminal();
    test_direct_spawn_hint();
    test_non_stdio_descriptors();
}
