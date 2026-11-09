//! Subprocess regressions for `sysbox timeout`; run natively with `lorry test`.
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn fixture(args: &[String]) -> ! {
    match args[0].as_str() {
        "exit" => std::process::exit(args[1].parse().unwrap()),
        "sleep" => {
            std::thread::sleep(std::time::Duration::from_millis(args[1].parse().unwrap()));
            std::process::exit(23);
        }
        "io" => {
            for arg in &args[1..] {
                println!("<{arg}>");
            }
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            std::io::stdout().write_all(&input).unwrap();
            eprintln!("fixture stderr");
            std::process::exit(0);
        }
        _ => panic!("unknown fixture"),
    }
}

fn command(options: &[&str], fixture: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sysbox"));
    command.arg("timeout").args(options);
    if !fixture.is_empty() {
        command
            .arg(std::env::current_exe().unwrap())
            .arg("--fixture")
            .args(fixture);
    }
    command
}

fn run(options: &[&str], fixture: &[&str]) -> Output {
    command(options, fixture).output().unwrap()
}

#[track_caller]
fn expect(output: Output, code: i32, stdout: &[u8]) -> String {
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    assert_eq!(output.stdout, stdout, "{output:?}");
    String::from_utf8(output.stderr).unwrap()
}

fn exits_and_io() {
    for code in [0, 1, 23, 124, 125, 126, 127, 137, 255] {
        expect(run(&["10"], &["exit", &code.to_string()]), code, b"");
    }
    let mut child = command(&["10"], &["io", "", "two words", "--help", "'$(literal)'"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"input\n").unwrap();
    let diagnostic = expect(
        child.wait_with_output().unwrap(),
        0,
        b"<>\n<two words>\n<--help>\n<'$(literal)'>\ninput\n",
    );
    assert!(diagnostic.contains("fixture stderr\n"), "{diagnostic}");
}

fn durations() {
    for duration in [
        "0",
        "-0",
        "0s",
        "+10",
        ".5",
        "10s",
        "0.1m",
        "0.01h",
        "0.001d",
        "1e1",
        "inf",
        "infinity",
        "1e999",
        "18446744073709551616",
        "1e-999",
    ] {
        expect(run(&["--", duration], &["exit", "23"]), 23, b"");
    }
    // A disabled timer must let a child that runs for a while finish normally.
    expect(run(&["-k", ".001", "0"], &["sleep", "30"]), 23, b"");
    for duration in [".01", "0.01s", ".0001m", ".000001h", ".0000001d", "1e-12"] {
        expect(run(&[duration], &["sleep", "30000"]), 124, b"");
    }
}

fn termination() {
    for options in [
        vec!["-p", ".01"],
        vec!["--preserve-status", "--signal=SIGTERM", ".01"],
        vec!["-fps15", ".01"],
        vec!["--foreground", "-p", "-s", "term", ".01"],
    ] {
        expect(run(&options, &["sleep", "30000"]), 143, b"");
    }
    for signal in ["KILL", "SIGKILL", "kill", "9", "+9", "009"] {
        expect(run(&["-s", signal, ".01"], &["sleep", "30000"]), 124, b"");
        expect(run(&["-ps", signal, ".01"], &["sleep", "30000"]), 137, b"");
    }
    let diagnostic = expect(run(&["-v", ".01"], &["sleep", "30000"]), 124, b"");
    assert!(
        diagnostic.contains("timeout: sending signal TERM to command '"),
        "{diagnostic}"
    );
    // Check-only leaves the child alive; escalation must then terminate it.
    for options in [
        vec!["-vs0", "--kill-after=.01", ".01"],
        vec!["-pvfs", "0", "-k.01", ".01"],
    ] {
        let diagnostic = expect(run(&options, &["sleep", "30000"]), 137, b"");
        assert!(diagnostic.contains("sending signal 0"), "{diagnostic}");
        assert!(diagnostic.contains("sending signal KILL"), "{diagnostic}");
    }
    expect(run(&["-s0", "-k0", ".001"], &["sleep", "30"]), 124, b"");
    expect(run(&["-ps0", ".001"], &["sleep", "30"]), 23, b"");
    expect(run(&["-k0", ".01"], &["sleep", "30000"]), 124, b"");
}

fn errors(root: &Path) {
    for duration in [
        "", "-1", "NaN", "nan", "1ms", "1S", "1 ", "1_0", "1e", "-inf", "0x10", "1e1e1",
    ] {
        let diagnostic = expect(run(&["--", duration], &["exit", "0"]), 125, b"");
        assert!(diagnostic.contains("invalid time interval"), "{diagnostic}");
    }
    for options in [
        vec![],
        vec!["1"],
        vec!["-s"],
        vec!["-k"],
        vec!["--unknown"],
        vec!["--preserve-status=yes", "1"],
        vec!["--kill-after=", "1"],
        vec!["-k", "NaN", "1"],
    ] {
        let diagnostic = expect(run(&options, &[]), 125, b"");
        assert!(diagnostic.contains("timeout:"), "{diagnostic}");
    }
    for signal in [
        "HUP", "INT", "USR1", "STOP", "CONT", "1", "2", "65", "garbage", "", "SIG15", "SIG9",
        "SIG0",
    ] {
        let diagnostic = expect(run(&["-s", signal, "0"], &["exit", "0"]), 125, b"");
        assert!(diagnostic.contains("unsupported signal"), "{diagnostic}");
    }
    let missing = root.join("no-such-command");
    expect(
        command(&["0"], &[]).arg(&missing).output().unwrap(),
        127,
        b"",
    );
    expect(
        command(&["0"], &[])
            .arg("sysbox-timeout-missing-command")
            .env("PATH", root)
            .output()
            .unwrap(),
        127,
        b"",
    );
    expect(command(&["0"], &[]).arg(root).output().unwrap(), 126, b"");
    let invalid = root.join("invalid-executable");
    std::fs::write(&invalid, b"not an executable\n").unwrap();
    expect(
        command(&["0"], &[]).arg(invalid).output().unwrap(),
        126,
        b"",
    );
}

fn informational() {
    for flag in ["-h", "--help"] {
        let output = run(&[flag], &[]);
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("Usage: timeout"));
    }
    for flag in ["-V", "--version"] {
        let output = run(&[flag], &[]);
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("timeout (Motor OS sysbox)"));
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--fixture") {
        fixture(&args[1..]);
    }
    let root = std::env::temp_dir().join(format!("sysbox-timeout-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    eprintln!("timeout test artifacts: {}", root.display());
    exits_and_io();
    durations();
    termination();
    errors(&root);
    informational();
    std::fs::remove_dir_all(root).unwrap();
    println!("timeout: all subprocess tests passed");
}
