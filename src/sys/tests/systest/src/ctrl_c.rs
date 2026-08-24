use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

const FD0_CHILD: &str = "ctrl-c-register-fd0-child";
const FD3_PARENT: &str = "ctrl-c-register-fd3-parent";
const FD3_CHILD: &str = "ctrl-c-register-fd3-child";
const NO_TERMINAL_CHILD: &str = "ctrl-c-register-no-terminal-child";
const EXIT_130_CHILD: &str = "ctrl-c-exit-130";

pub fn is_helper(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| {
        matches!(
            arg.as_str(),
            FD0_CHILD | FD3_PARENT | FD3_CHILD | NO_TERMINAL_CHILD | EXIT_130_CHILD
        )
    })
}

pub fn run_helper(args: &[String]) -> ! {
    if args[1] == EXIT_130_CHILD {
        std::process::exit(moto_sys::SysCpu::CTRL_C_EXIT_STATUS as i32)
    }

    if args[1] == NO_TERMINAL_CHILD {
        assert_eq!(
            moto_rt::process::ctrl_c_register_handler(),
            Err(moto_rt::Error::NotFound)
        );
        std::process::exit(0)
    }

    if args[1] == FD3_PARENT {
        let status = Command::new(std::env::current_exe().unwrap())
            .arg(FD3_CHILD)
            .stdin(Stdio::null())
            .status()
            .unwrap();
        std::process::exit(status.code().unwrap())
    }

    let fd = if args[1] == FD0_CHILD {
        moto_rt::FD_STDIN
    } else {
        moto_rt::FD_TERMINAL
    };
    assert!(moto_rt::fs::is_terminal(fd));
    let baseline = moto_rt::process::ctrl_c_register_handler().unwrap();
    assert_eq!(baseline, 0);

    moto_rt::fs::close(fd).unwrap();
    let reused = moto_rt::fs::open(
        std::env::current_exe().unwrap().to_str().unwrap(),
        moto_rt::fs::O_READ,
    )
    .unwrap();
    assert_eq!(reused, fd);
    assert_eq!(
        moto_rt::process::ctrl_c_register_handler(),
        Err(moto_rt::Error::AlreadyInUse)
    );

    println!("CTRL_C_REGISTERED");
    std::io::stdout().flush().unwrap();
    let error = moto_rt::process::ctrl_c_wait(baseline).unwrap_err();
    assert!(matches!(
        error,
        moto_rt::Error::BadHandle | moto_rt::Error::NotConnected
    ));
    println!("CTRL_C_CLOSED");
    std::process::exit(0)
}

fn test_closed_terminal(role: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg(role)
        .env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    assert_ne!(stdout.read_line(&mut line).unwrap(), 0);
    assert_eq!(line, "CTRL_C_REGISTERED\n");

    drop(child.stdin.take());
    let mut remainder = String::new();
    stdout.read_to_string(&mut remainder).unwrap();
    assert_eq!(remainder, "CTRL_C_CLOSED\n");
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{role} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn run_tests() {
    let output = Command::new(std::env::current_exe().unwrap())
        .arg(NO_TERMINAL_CHILD)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());

    test_closed_terminal(FD0_CHILD);
    test_closed_terminal(FD3_PARENT);
    println!("ctrl_c::run_tests PASS");
}
