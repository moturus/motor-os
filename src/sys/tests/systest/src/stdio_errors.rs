use std::fs::File;
use std::io::{self, IoSlice, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};

const OUTPUT: &[u8] = b"hello\n";

fn child(fd: i32, operation: &str, outcome: &str) {
    if outcome == "closed" {
        // This fresh child owns the standard descriptor and has not buffered I/O.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    if operation == "print" {
        if fd == 1 {
            println!("hello");
        } else {
            eprintln!("hello");
        }
        return;
    }

    let (result, expected) = if fd == 0 {
        let mut byte = [0];
        let result = io::stdin().read(&mut byte);
        if outcome == "allow" {
            assert_eq!(byte, [b'i']);
        }
        (result, usize::from(outcome == "allow"))
    } else {
        let mut stream: Box<dyn Write> = if fd == 1 {
            Box::new(io::stdout().lock())
        } else {
            Box::new(io::stderr().lock())
        };
        match operation {
            "write" => (
                stream.write_all(OUTPUT).map(|()| OUTPUT.len()),
                OUTPUT.len(),
            ),
            "vectored" => (
                stream.write_vectored(&[IoSlice::new(b"hel"), IoSlice::new(b"lo\n")]),
                OUTPUT.len(),
            ),
            "flush" => (stream.flush().map(|()| 0), 0),
            _ => panic!("unknown operation: {operation}"),
        }
    };
    if outcome == "deny" {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    } else {
        assert_eq!(result.unwrap(), expected);
    }
}

pub fn run_command(args: &[String]) -> bool {
    if args.len() == 5 && args[1] == "stdio-errors-child" {
        child(args[2].parse().unwrap(), &args[3], &args[4]);
        return true;
    }
    false
}

pub fn run_all_tests() {
    use moto_sys::caps::{CAP_FS_WRITE, CAP_INTERACTIVE, CAP_SPAWN};

    let role = moto_sys::ProcessStaticPage::get().capabilities & CAP_INTERACTIVE;
    let root = std::env::temp_dir().join(format!("stdio-errors-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("stream");
    let exe = std::env::current_exe().unwrap();
    let mut failures = 0;
    let mut cases = 0;

    for fd in 0..=2 {
        let operations: &[&str] = if fd == 0 {
            &["read"]
        } else {
            &["write", "vectored", "flush", "print"]
        };
        for operation in operations {
            for outcome in ["allow", "closed", "deny"] {
                let mut command = Command::new(&exe);
                command.args(["stdio-errors-child", &fd.to_string(), operation, outcome]);
                // Keep the caller's role; only the allowed case gets FS-write.
                command.env(
                    "MOTOR_OS_CAPS",
                    format!(
                        "0x{:x}",
                        role | CAP_SPAWN | if outcome == "allow" { CAP_FS_WRITE } else { 0 }
                    ),
                );
                if fd == 0 {
                    std::fs::write(&path, b"input").unwrap();
                    let input = if outcome == "deny" {
                        std::fs::OpenOptions::new().write(true).open(&path).unwrap()
                    } else {
                        File::open(&path).unwrap()
                    };
                    command.stdin(Stdio::from(input));
                } else {
                    let output = Stdio::from(File::create(&path).unwrap());
                    if fd == 1 {
                        command.stdout(output);
                    } else {
                        command.stderr(output);
                    }
                }
                let output = command.output().unwrap();
                let expected_success = *operation != "print" || outcome != "deny";
                let mut passed = output.status.success() == expected_success;
                if fd != 0 {
                    let expected = if outcome == "allow" && *operation != "flush" {
                        OUTPUT
                    } else {
                        b""
                    };
                    passed &= std::fs::read(&path).unwrap() == expected;
                }
                println!(
                    "stdio fd={fd} {operation} {outcome}: {}",
                    if passed { "PASS" } else { "FAIL" }
                );
                if !passed {
                    eprintln!(
                        "status={}; stderr={}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    );
                    failures += 1;
                }
                cases += 1;
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
    assert_eq!(failures, 0, "{failures}/{cases} stdio error cases failed");
    println!("stdio errors PASS ({cases} cases)");
}
