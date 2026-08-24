use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

const FD0_CHILD: &str = "ctrl-c-register-fd0-child";
const FD3_PARENT: &str = "ctrl-c-register-fd3-parent";
const FD3_CHILD: &str = "ctrl-c-register-fd3-child";
const NO_TERMINAL_CHILD: &str = "ctrl-c-register-no-terminal-child";
const EXIT_130_CHILD: &str = "ctrl-c-exit-130";
const DEFAULT_CHILD: &str = "ctrl-c-default-child";
const HANDLER_CHILD: &str = "ctrl-c-handler-child";
const ROUTE_PARENT: &str = "ctrl-c-route-parent";
const ROUTE_NORMAL_CHILD: &str = "ctrl-c-route-normal-child";
const ROUTE_SPIN_CHILD: &str = "ctrl-c-route-spin-child";

pub fn is_helper(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| {
        matches!(
            arg.as_str(),
            FD0_CHILD
                | FD3_PARENT
                | FD3_CHILD
                | NO_TERMINAL_CHILD
                | EXIT_130_CHILD
                | DEFAULT_CHILD
                | HANDLER_CHILD
                | ROUTE_PARENT
                | ROUTE_NORMAL_CHILD
                | ROUTE_SPIN_CHILD
        )
    })
}

pub fn run_helper(args: &[String]) -> ! {
    match args[1].as_str() {
        DEFAULT_CHILD => run_default_child(),
        HANDLER_CHILD => run_handler_child(),
        ROUTE_PARENT => run_route_parent(),
        ROUTE_NORMAL_CHILD => run_route_normal_child(),
        ROUTE_SPIN_CHILD => run_route_spin_child(),
        _ => {}
    }

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

fn ready(marker: &str) {
    println!("{marker}");
    std::io::stdout().flush().unwrap();
}

fn run_default_child() -> ! {
    ready("CTRL_C_DEFAULT_READY");
    loop {
        std::hint::spin_loop();
    }
}

fn run_handler_child() -> ! {
    let baseline = moto_rt::process::ctrl_c_register_handler().unwrap();
    ready("CTRL_C_HANDLER_READY");
    let raised = moto_rt::process::ctrl_c_wait(baseline).unwrap();
    assert_eq!(raised, baseline.checked_add(1).unwrap());
    ready("CTRL_C_HANDLER_CALLED");
    std::process::exit(0)
}

fn run_route_parent() -> ! {
    let mut last = moto_rt::process::ctrl_c_register_handler().unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .arg(ROUTE_NORMAL_CHILD)
        .status()
        .unwrap();
    assert!(status.success());
    ready("CTRL_C_NORMAL_RESTORED");
    let raised = moto_rt::process::ctrl_c_wait(last).unwrap();
    assert_eq!(raised, last.checked_add(1).unwrap());
    last = raised;
    ready("CTRL_C_PARENT_AFTER_NORMAL");

    let status = Command::new(std::env::current_exe().unwrap())
        .arg(ROUTE_SPIN_CHILD)
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(moto_sys::SysCpu::CTRL_C_EXIT_STATUS as i32)
    );
    ready("CTRL_C_SPIN_STATUS_130");

    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, [b'x']);
    ready("CTRL_C_TYPEAHEAD_X");

    ready("CTRL_C_KILL_RESTORED");
    let raised = moto_rt::process::ctrl_c_wait(last).unwrap();
    assert_eq!(raised, last.checked_add(1).unwrap());
    ready("CTRL_C_PARENT_AFTER_KILL");
    std::process::exit(0)
}

fn run_route_normal_child() -> ! {
    ready("CTRL_C_NORMAL_CHILD_READY");
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, [b'n']);
    std::process::exit(0)
}

fn run_route_spin_child() -> ! {
    ready("CTRL_C_SPIN_CHILD_READY");
    loop {
        std::hint::spin_loop();
    }
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
