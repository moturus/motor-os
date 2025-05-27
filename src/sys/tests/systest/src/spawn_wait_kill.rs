use moto_sys::stats::ProcessStatsV1;

use crate::subcommand;

pub fn smoke_test() {
    // Normal exit.
    let mut child = subcommand::spawn();
    let start = std::time::Instant::now();
    let spin_time = std::time::Duration::from_micros(10_000);
    child.spin(spin_time);

    assert!(child.try_wait().unwrap().is_none()); // Still running.

    use std::io::Read;
    use std::os::fd::FromRawFd;
    use std::os::moturus::ChildExt;

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

    let mut processes: Vec<ProcessStatsV1> = Vec::with_capacity(PS_BUF_SIZE);
    for _ in 0..PS_BUF_SIZE {
        processes.push(ProcessStatsV1::default());
    }

    let cnt = match ProcessStatsV1::list(moto_sys::stats::PID_SYSTEM, &mut processes[..]) {
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
