//! Process creation through the raw kernel API, ahead of the sys-io loader:
//! creating a process on a requester's behalf is sys-io's alone, killing a
//! child that was never woken completes its exit (also when racing its first
//! wake, or its creation), a thread woken twice before it runs starts once,
//! and an unstarted detached child dies with its parent, since nobody else
//! can wake it.

use moto_sys::stats::ProcessInfoV1;
use moto_sys::{SysCpu, SysHandle, SysObj, SysRay};
use std::time::{Duration, Instant};

const DETACHED_SUITE: &str = "raw-spawn-detached";
const DETACHED_CHILD: &str = "raw-spawn-unstarted-detached-child";

/// A process whose main thread never runs: an empty address space and an
/// entry point nothing jumps to.
fn create_unstarted(name: &str, detached: bool) -> SysHandle {
    let address_space = SysObj::create(
        SysHandle::NONE,
        0,
        &format!("address_space:debug_name={name}"),
    )
    .unwrap();
    let process = SysObj::create(
        address_space,
        0,
        &format!(
            "process:entry_point=4096;capabilities=0;detached={}",
            detached as u8
        ),
    )
    .unwrap();
    SysObj::put(address_space).unwrap();
    process
}

/// Gone, or listed as a zombie: a completed process stays listed while a
/// handle to it is held.
fn is_dead(pid: u64) -> bool {
    let mut info = [ProcessInfoV1::default(); 1];
    ProcessInfoV1::list(pid, &mut info).unwrap() == 0 || info[0].pid != pid || info[0].active == 0
}

fn wait_dead(pid: u64, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !is_dead(pid) {
        assert!(
            Instant::now() < deadline,
            "{what}: process {pid} is still alive"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Only sys-io creates processes on a requester's behalf; anyone else is
/// refused before the kernel looks at the handle.
fn test_requester_refused() {
    let address_space = SysObj::create(
        SysHandle::NONE,
        0,
        "address_space:debug_name=raw-spawn-requester",
    )
    .unwrap();
    let url = format!(
        "process:entry_point=4096;capabilities=0;requester={}",
        address_space.as_u64()
    );
    assert_eq!(
        SysObj::create(address_space, 0, &url),
        Err(moto_rt::E_NOT_ALLOWED)
    );
    SysObj::put(address_space).unwrap();
    println!("raw_spawn::test_requester_refused PASS");
}

/// Waits, bounded, for the process behind the handle to exit.
pub(crate) fn wait_exit(process: SysHandle, what: &str) {
    let deadline = moto_rt::time::Instant::now() + Duration::from_secs(10);
    loop {
        SysCpu::wait(
            &mut [process],
            SysHandle::NONE,
            SysHandle::NONE,
            Some(deadline),
        )
        .unwrap_or_else(|err| panic!("{what}: the exit did not complete: {err}"));
        if SysRay::process_status(process).unwrap().is_some() {
            break;
        }
    }
}

/// The kill of a child that was never woken completes its exit on its own:
/// the wait returns, and the process is gone once its last handle closes.
fn test_kill_unstarted_child() {
    let process = create_unstarted("raw-spawn-unstarted", false);
    let pid = SysRay::process_pid(process).unwrap();
    assert!(!is_dead(pid));
    SysCpu::kill(process).unwrap();
    wait_exit(process, "raw_spawn::test_kill_unstarted_child");
    SysObj::put(process).unwrap();
    wait_dead(pid, "raw_spawn::test_kill_unstarted_child");
    println!("raw_spawn::test_kill_unstarted_child PASS");
}

/// A kill racing the first wake: whichever the scheduler runs first, the
/// exit completes, and the start the wake queued must find nothing to do
/// when it runs after the process is gone with only a thread handle left.
fn test_kill_racing_a_wake() {
    for _ in 0..64 {
        let process = create_unstarted("raw-spawn-race", false);
        let main_thread = SysObj::get(process, 0, "main_thread").unwrap();
        SysCpu::wake(main_thread).unwrap();
        SysCpu::kill(process).unwrap();
        wait_exit(process, "raw_spawn::test_kill_racing_a_wake");
        SysObj::put(process).unwrap();
        SysCpu::sched_yield();
        SysObj::put(main_thread).unwrap();
    }
    println!("raw_spawn::test_kill_racing_a_wake PASS");
}

/// A detached child that was never woken has no one left to wake it once
/// its parent is gone: the parent's teardown kills it. Needs
/// `CAP_SPAWN_DETACHED`, which the suite's caller lacks; full-test.sh runs
/// `systest raw-spawn-detached` with it.
fn test_unstarted_detached_child_dies_with_parent() {
    let ours = moto_sys::ProcessStaticPage::get().capabilities;
    assert_ne!(ours & moto_sys::caps::CAP_SPAWN_DETACHED, 0);
    // Children do not inherit the detach capability unless given it.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg(DETACHED_CHILD)
        .env(moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY, format!("0x{ours:x}"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let pid: u64 = String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    wait_dead(
        pid,
        "raw_spawn::test_unstarted_detached_child_dies_with_parent",
    );
    println!("raw_spawn::test_unstarted_detached_child_dies_with_parent PASS");
}

/// A kill by pid racing the creation: the child can be found by its pid
/// before its main thread and its handle object exist, and the kill must
/// trip over neither. The creator still gets a handle, to a child that died
/// at once. Match our parent pid and a unique round name before killing, so
/// concurrent spawns cannot make us target an unrelated process.
fn test_kill_racing_creation() {
    use std::sync::atomic::{AtomicU64, Ordering};

    const ROUNDS: u64 = 200;
    let what = "raw_spawn::test_kill_racing_creation";
    let parent_pid = moto_sys::current_pid();
    let child_name = |round| format!("raw-spawn-creation-race-{round}");
    let killed_pid = AtomicU64::new(0);
    std::thread::scope(|scope| {
        let killer = scope.spawn(|| {
            let mut processes = [ProcessInfoV1::default(); 32];
            for round in 0..ROUNDS {
                let name = child_name(round);
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut start = 0;
                loop {
                    let count = ProcessInfoV1::list(start, &mut processes).unwrap();
                    if let Some(child) = processes[..count]
                        .iter()
                        .find(|p| p.parent_pid == parent_pid && p.debug_name() == name)
                    {
                        // Stats can be visible before the process's Arc is ready.
                        match SysCpu::kill_pid(child.pid) {
                            Ok(()) => {
                                killed_pid.store(child.pid, Ordering::Release);
                                break;
                            }
                            Err(moto_rt::E_INVALID_ARGUMENT) => {}
                            Err(err) => panic!("{what}: round {round}: kill failed: {err}"),
                        }
                    }
                    assert!(Instant::now() < deadline, "{what}: round {round}: no child");
                    start = if count == processes.len() {
                        processes[count - 1].pid + 1
                    } else {
                        0
                    };
                }
            }
        });
        for round in 0..ROUNDS {
            let process = create_unstarted(&child_name(round), false);
            let pid = SysRay::process_pid(process).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while killed_pid.load(Ordering::Acquire) != pid {
                assert!(
                    Instant::now() < deadline,
                    "{what}: round {round}: the kill never landed"
                );
                std::thread::yield_now();
            }
            wait_exit(process, what);
            SysObj::put(process).unwrap();
        }
        killer.join().unwrap();
    });
    println!("{what} PASS");
}

pub fn is_child(args: &[String]) -> bool {
    args.len() == 2 && (args[1] == DETACHED_SUITE || args[1] == DETACHED_CHILD)
}

/// The detached test under its own mask, or its helper: a detached child
/// created, never woken, and left behind at exit, its pid on stdout.
pub fn run_child(args: &[String]) -> ! {
    if args[1] == DETACHED_SUITE {
        test_unstarted_detached_child_dies_with_parent();
        std::process::exit(0)
    }
    let process = create_unstarted("raw-spawn-detached", true);
    println!("{}", SysRay::process_pid(process).unwrap());
    std::process::exit(0)
}

/// A thread woken twice before it runs starts once; the second wake is
/// pending for its first wait, as it would be for a running thread.
fn test_double_wake() {
    for _ in 0..64 {
        let process = create_unstarted("raw-spawn-double-wake", false);
        let main_thread = SysObj::get(process, 0, "main_thread").unwrap();
        SysCpu::wake(main_thread).unwrap();
        SysCpu::wake(main_thread).unwrap();
        // Nothing is mapped at the entry point: the thread dies on its first
        // instruction, and with it the process.
        wait_exit(process, "raw_spawn::test_double_wake");
        SysObj::put(main_thread).unwrap();
        SysObj::put(process).unwrap();
    }
    println!("raw_spawn::test_double_wake PASS");
}

pub fn run_all_tests() {
    test_requester_refused();
    test_kill_unstarted_child();
    test_kill_racing_a_wake();
    test_double_wake();
    test_kill_racing_creation();
    println!("raw_spawn::run_all_tests PASS");
}
