use moto_sys::stats::{ThreadDataV1, ThreadStatus};
use moto_sys::{SysCpu, SysHandle, SysMem, SysObj, SysRay};
use std::time::{Duration, Instant};

const CHILD: &str = "debugger-kill-child";

pub fn is_child(args: &[String]) -> bool {
    args.len() == 3 && args[1] == CHILD
}

pub fn run_child(mode: &str) -> ! {
    SysMem::alloc(moto_sys::sys_mem::PAGE_SIZE_SMALL, 2048).unwrap();
    moto_sys::set_current_thread_name(mode).unwrap();
    loop {
        match mode {
            "spin" => core::hint::spin_loop(),
            "wait" => SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, None).unwrap(),
            "syscall" => SysCpu::sched_yield(),
            _ => unreachable!(),
        }
    }
}

fn wait_for(debug: SysHandle, tid: u64, ready: impl Fn(&ThreadDataV1) -> bool) -> ThreadDataV1 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let data = SysRay::dbg_get_thread_data_v1(debug, tid).unwrap();
        if ready(&data) {
            return data;
        }
        assert!(
            Instant::now() < deadline,
            "debuggee did not reach the required state"
        );
        SysCpu::sched_yield();
    }
}

/// Both fully paused threads and a pause racing a kill must release memory
/// without a debugger resume, even while process and debugger handles survive.
pub fn test_kill_paused() {
    for mode in ["spin", "wait", "syscall"] {
        for settled in [true, false] {
            for round in 0..4 {
                let child = moto_rt::process::spawn(moto_rt::process::SpawnArgs {
                    program: std::env::current_exe()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    args: vec![CHILD.to_owned(), mode.to_owned()],
                    env: std::env::vars().collect(),
                    cwd: None,
                    stdin: moto_rt::process::STDIO_NULL,
                    stdout: moto_rt::process::STDIO_NULL,
                    stderr: moto_rt::process::STDIO_NULL,
                })
                .unwrap();
                let handle = SysHandle::from_u64(child.handle);
                let debug = SysRay::dbg_attach(child.pid as u64).unwrap();
                let main = SysObj::get(handle, 0, "main_thread").unwrap();
                let mut tids = [0; 1];
                assert_eq!(SysRay::dbg_list_threads(debug, 0, &mut tids), Ok(1));
                let tid = tids[0];
                wait_for(debug, tid, |data| {
                    data.thread_name() == mode
                        && (mode != "wait" || matches!(data.status, ThreadStatus::LiveInWait))
                });
                assert!(crate::kernel_metric("pages_user", child.pid as u64) >= 2048);

                SysRay::dbg_pause_process(debug).unwrap();
                if mode == "wait" {
                    // Leave the wait after the process pause: its syscall exit
                    // must pause in the kernel rather than returning to userspace.
                    SysCpu::wake(main).unwrap();
                }
                if settled {
                    let data = wait_for(debug, tid, |data| data.paused_debuggee != 0);
                    if mode == "spin" {
                        assert!(matches!(data.status, ThreadStatus::LivePreempted));
                    } else if mode == "wait" {
                        assert!(matches!(data.status, ThreadStatus::LiveRunning));
                    }
                    if round == 0 {
                        SysRay::dbg_resume_process(debug).unwrap();
                        SysRay::dbg_resume_thread(debug, tid).unwrap();
                        wait_for(debug, tid, |data| {
                            data.paused_debuggee == 0
                                && (mode != "wait"
                                    || matches!(data.status, ThreadStatus::LiveInWait))
                        });
                        SysRay::dbg_pause_process(debug).unwrap();
                        if mode == "wait" {
                            SysCpu::wake(main).unwrap();
                        }
                        wait_for(debug, tid, |data| data.paused_debuggee != 0);
                    }
                }
                if round % 2 == 0 {
                    SysCpu::kill(handle).unwrap();
                } else {
                    SysCpu::kill_pid(child.pid as u64).unwrap();
                }
                crate::raw_spawn::wait_exit(handle, "kill paused debuggee");
                assert_eq!(SysRay::process_status(handle), Ok(Some(u64::MAX)));
                assert_eq!(crate::kernel_metric("active_threads", child.pid as u64), 0);
                assert_eq!(crate::kernel_metric("pages_user", child.pid as u64), 0);
                SysRay::dbg_detach(debug).unwrap();
                SysObj::put(main).unwrap();
                moto_rt::alloc::release_handle(child.handle).unwrap();
            }
        }
    }
    println!("debugger::test_kill_paused PASS");
}
