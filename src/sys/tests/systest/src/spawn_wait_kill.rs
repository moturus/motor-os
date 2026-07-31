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

// Pids are bounded to the i32-positive range and reused after wrap; see
// docs/plans/pid-refactoring-design.md.
pub fn test_pid_invariants() {
    let pid = moto_sys::current_pid();
    assert!(pid >= 3, "systest is not sys-io: {pid}"); // 0/1/2 are reserved.
    assert!(pid < (1_u64 << 31), "pid does not fit i32: {pid}");
    assert_eq!(std::process::id() as u64, pid);

    println!("test_pid_invariants PASS");
}

const PID_QUERY_CHILD: &str = "pid-query-child";

pub fn is_pid_query_child(args: &[String]) -> bool {
    args.len() == 2 && args[1] == PID_QUERY_CHILD
}

pub fn run_pid_query_child() -> ! {
    // Both views of this process's pid; the parent asserts they agree.
    println!("{} {}", std::process::id(), moto_sys::current_pid());
    std::process::exit(0)
}

fn spawn_pid_query_child() -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .arg(PID_QUERY_CHILD)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

// Reaps the child and returns the (std::process::id, moto_sys::current_pid)
// pair it printed.
fn reap_pid_query_child(child: &mut std::process::Child) -> (u32, u64) {
    use std::io::Read;

    let mut reported = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut reported)
        .unwrap();
    assert_eq!(0, child.wait().unwrap().code().unwrap());

    let mut pids = reported.trim().split(' ');
    let std_pid = pids.next().unwrap().parse::<u32>().unwrap();
    let moto_pid = pids.next().unwrap().parse::<u64>().unwrap();
    assert_eq!(None, pids.next());
    assert_eq!(u64::from(std_pid), moto_pid);
    (std_pid, moto_pid)
}

// A spawner holds a process handle but had no way to learn the pid behind
// it; F_QUERY_PID is that missing mapping.
pub fn test_process_pid_query() {
    use std::os::motor::process::ChildExt;

    let mut child = spawn_pid_query_child();

    // Query while the child is still running: the answer must be the pid the
    // child itself reports.
    let pid = moto_sys::SysRay::process_pid(moto_sys::SysHandle::from_u64(child.sys_handle()))
        .expect("process_pid on a held process handle");
    assert!((3..(1_u64 << 31)).contains(&pid), "child pid {pid}");
    assert_ne!(pid, moto_sys::current_pid());

    assert_eq!(pid, reap_pid_query_child(&mut child).1);

    // SELF is a built-in pseudo handle, not an entry in this process's handle
    // table, so it resolves to no process object.
    assert_eq!(
        Err(moto_rt::E_INVALID_ARGUMENT),
        moto_sys::SysRay::process_pid(moto_sys::SysHandle::SELF)
    );

    println!("test_process_pid_query PASS");
}

// Child::id() used to be a hardcoded zero: the spawner never learned the
// child's pid. Now it is the real pid, and every layer agrees on it.
pub fn test_child_id() {
    use std::os::motor::process::ChildExt;

    let mut first = spawn_pid_query_child();
    let mut second = spawn_pid_query_child();
    assert_ne!(first.id(), second.id());

    for child in [&mut first, &mut second] {
        let id = child.id();
        assert!((3..(1_u32 << 31)).contains(&id), "Child::id() = {id}");
        assert_eq!(
            u64::from(id),
            moto_sys::SysRay::process_pid(moto_sys::SysHandle::from_u64(child.sys_handle()))
                .unwrap()
        );
        assert_eq!(id, reap_pid_query_child(child).0);
    }

    println!("test_child_id PASS");
}

const SPAWN_RESULT_PID_CHILD: &str = "spawn-result-pid-child";

pub fn is_spawn_result_pid_child(args: &[String]) -> bool {
    args.len() == 2 && args[1] == SPAWN_RESULT_PID_CHILD
}

pub fn run_spawn_result_pid_child() -> ! {
    // Pids fit i32, so the exit code carries the pid exactly.
    std::process::exit(moto_sys::current_pid() as i32)
}

// The runtime hands the spawner the child's pid in SpawnResult; the pid it
// reports must be the child's own.
pub fn test_spawn_result_pid() {
    let spawn_args = moto_rt::process::SpawnArgs {
        program: std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        args: vec![SPAWN_RESULT_PID_CHILD.to_owned()],
        env: std::env::vars().collect(),
        cwd: None,
        stdin: moto_rt::process::STDIO_INHERIT,
        stdout: moto_rt::process::STDIO_INHERIT,
        stderr: moto_rt::process::STDIO_INHERIT,
    };

    let res = moto_rt::process::spawn(spawn_args).unwrap();
    assert!(res.pid > 0, "spawn reported pid {}", res.pid);
    assert_eq!(
        res.pid as u64,
        moto_sys::SysRay::process_pid(moto_sys::SysHandle::from_u64(res.handle)).unwrap()
    );

    // The child exits with its own pid.
    assert_eq!(res.pid, moto_rt::process::wait(res.handle).unwrap());
    moto_rt::alloc::release_handle(res.handle).unwrap();

    println!("test_spawn_result_pid PASS");
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
