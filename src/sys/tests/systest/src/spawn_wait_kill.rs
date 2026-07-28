use moto_sys::stats::ProcessInfoV1;

use crate::subcommand;

const SHARED_LISTENER_CHILD: &str = "shared-listener-child";
const SHARED_LISTENER_URL: &str = "systest-shared-listener-restart";

fn spawn_shared_listener() -> (
    std::process::Child,
    std::io::BufReader<std::process::ChildStdout>,
) {
    use std::io::BufReader;
    use std::process::{Command, Stdio};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg(SHARED_LISTENER_CHILD)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    (child, stdout)
}

fn expect_shared_listener_ready(stdout: &mut impl std::io::BufRead) {
    let mut line = String::new();
    assert_ne!(0, stdout.read_line(&mut line).unwrap());
    assert_eq!("shared listener ready\n", line);
}

pub fn is_shared_listener_child(args: &[String]) -> bool {
    args.len() == 2 && args[1] == SHARED_LISTENER_CHILD
}

pub fn run_shared_listener_child() -> ! {
    use moto_ipc::sync::{ChannelSize, LocalServer};
    use moto_sys::SysHandle;
    use std::io::Write;

    let mut server = LocalServer::new(SHARED_LISTENER_URL, ChannelSize::Small, 2, 2).unwrap();
    println!("shared listener ready");
    std::io::stdout().flush().unwrap();
    loop {
        let _ = server.wait(SysHandle::NONE, &[]);
    }
}

pub fn test_shared_listener_restart() {
    use moto_ipc::sync::{ChannelSize, ClientConnection};

    let (mut first, mut first_stdout) = spawn_shared_listener();
    expect_shared_listener_ready(&mut first_stdout);
    first.kill().unwrap();

    // Retain `first` without waiting: the parent still owns a process handle,
    // but an Exiting process must no longer reserve discoverable service URLs.
    let (mut second, mut second_stdout) = spawn_shared_listener();
    expect_shared_listener_ready(&mut second_stdout);

    let mut client = ClientConnection::new(ChannelSize::Small).unwrap();
    client.connect(SHARED_LISTENER_URL).unwrap();

    second.kill().unwrap();
    assert_eq!(-1, first.wait().unwrap().code().unwrap());
    assert_eq!(-1, second.wait().unwrap().code().unwrap());
    println!("test_shared_listener_restart PASS");
}

pub fn smoke_test() {
    // Normal exit.
    let mut child = subcommand::spawn();
    let start = std::time::Instant::now();
    let spin_time = std::time::Duration::from_micros(10_000);
    child.spin(spin_time);

    assert!(child.try_wait().unwrap().is_none()); // Still running.

    use std::io::Read;
    use std::os::fd::FromRawFd;
    use std::os::motor::process::ChildExt;

    // Test "Child FD" feature.
    let handle = child.std_child().sys_handle();
    let fd = moto_rt::fs::open(
        format!("handle://{handle}").as_str(),
        moto_rt::fs::O_HANDLE_CHILD,
    )
    .unwrap();
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let res = std::sync::atomic::AtomicU64::new(0);
    let buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(&res as *const _ as usize as *mut u8, 8) };
    assert_eq!(
        file.read(buf).err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );

    child.do_exit(1234);
    assert_eq!(1234, child.wait().unwrap().code().unwrap());
    assert!(start.elapsed() > spin_time);
    assert_eq!(8, file.read(buf).unwrap());
    assert_eq!(1234, res.load(std::sync::atomic::Ordering::Acquire));

    // kill.
    let mut child = subcommand::spawn();
    assert!(child.try_wait().unwrap().is_none()); // Still running.
    child.kill();
    assert_eq!(-1, child.wait().unwrap().code().unwrap());

    println!("spawn_wait_kill smoke_test PASS");
}

pub fn test_pid_kill() {
    let mut child = subcommand::spawn();

    const PS_BUF_SIZE: usize = 1024;

    let mut processes: Vec<ProcessInfoV1> = Vec::with_capacity(PS_BUF_SIZE);
    for _ in 0..PS_BUF_SIZE {
        processes.push(ProcessInfoV1::default());
    }

    let cnt = match ProcessInfoV1::list(moto_sys::stats::PID_SYSTEM, &mut processes[..]) {
        Ok(cnt) => cnt,
        Err(err) => {
            eprintln!("PS failed.");
            std::process::exit(err as i32);
        }
    };

    if cnt == PS_BUF_SIZE {
        // Ask for more.
        println!("test_pid_kill: too many processes in the system.");
        child.kill();
        assert_eq!(-1, child.wait().unwrap().code().unwrap());
        return;
    }

    for proc in &processes {
        if proc.debug_name().contains("systest") {
            if proc.parent_pid != moto_sys::current_pid() {
                continue;
            }

            moto_sys::SysCpu::kill_pid(proc.pid).unwrap();
            break;
        }
    }

    assert_eq!(-1, child.wait().unwrap().code().unwrap());

    // sys-io usually has PID 2.
    assert!(moto_sys::SysCpu::kill_pid(2).is_err());

    println!("test_pid_kill PASS");
}
