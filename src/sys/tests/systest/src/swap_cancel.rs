use moto_sys::{SysCpu, SysHandle, stats::ProcessInfoV1};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub fn run_command(args: &[String]) -> bool {
    match args.get(1).map(String::as_str) {
        Some("swap-cancel-owner") => {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["swap-cancel-worker", &args[2]])
                .status()
                .unwrap();
            assert!(status.success());
            true
        }
        Some("swap-cancel-worker") => run_worker(args[2] == "swap"),
        Some("wait-spill-worker") => run_spill_worker(Path::new(&args[2])),
        Some("test-swap-cancel") => {
            run_tests();
            true
        }
        Some("swap-cancel-soak") => {
            run_soak_tests();
            true
        }
        _ => false,
    }
}

fn handoff(peer: SysHandle, swap: bool) {
    let (swap_target, wake_target) = if swap {
        (peer, SysHandle::NONE)
    } else {
        (SysHandle::NONE, peer)
    };
    SysCpu::wait(&mut [], swap_target, wake_target, None).unwrap();
}

/// Affinity applies at the thread's next reschedule. Threads still on
/// different CPUs run the handoff loop side by side: every swap finds its
/// target running and every wait returns at once, so nothing direct-switches.
fn move_to_cpu(cpu: Option<u32>) {
    SysCpu::affine_to_cpu(cpu).unwrap();
    while cpu.is_some_and(|cpu| moto_sys::current_cpu() != cpu) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn run_worker(swap: bool) -> ! {
    let cpu = (moto_sys::num_cpus() > 1).then_some(1);
    move_to_cpu(cpu);
    let token = Arc::new(AtomicU64::new(0));
    let peer_handle = Arc::new(AtomicU64::new(0));
    let main_handle = moto_sys::current_thread();
    let before = crate::kernel_metric("direct_switch", moto_stats::provider::KERNEL);
    let peer_token = token.clone();
    let published_handle = peer_handle.clone();
    std::thread::spawn(move || {
        move_to_cpu(cpu);
        published_handle.store(moto_sys::current_thread().as_u64(), Ordering::Release);
        for index in 0..u64::MAX / 2 {
            while peer_token.load(Ordering::Acquire) != index * 2 + 1 {
                handoff(main_handle, swap);
            }
            peer_token.store(index * 2 + 2, Ordering::Release);
        }
    });
    while peer_handle.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    let peer = peer_handle.load(Ordering::Acquire).into();
    // One round trip establishes the wake control; extra warmup only adds
    // scheduler latency to the parent's readiness deadline.
    let ready_index = if swap { 100 } else { 0 };
    for index in 0..u64::MAX / 2 {
        token.store(index * 2 + 1, Ordering::Release);
        while token.load(Ordering::Acquire) != index * 2 + 2 {
            handoff(peer, swap);
        }
        if index == ready_index {
            if swap {
                assert!(
                    crate::kernel_metric("direct_switch", moto_stats::provider::KERNEL) > before,
                    "worker never entered the direct-switch path"
                );
            }
            std::io::stdout().write_all(b"ready\n").unwrap();
        }
    }
    unreachable!()
}

pub fn run_tests() {
    test_swap_cancel_releases_children();
    test_killed_waiters_release_handle_lists();
}

/// Kills during direct CPU handoffs beside unrelated workloads. The
/// handle-list check samples the kernel heap, which only the gate can do.
pub fn run_soak_tests() {
    test_swap_cancel_releases_children();
    println!("swap-cancel-soak PASS");
}

fn test_swap_cancel_releases_children() {
    // Each episode must clear its child record; these are distinct kills, not
    // retries. Ordinary wakes provide a control for the swap-target path.
    for episode in 0..4 {
        for mode in ["wake", "swap"] {
            let mut owner = Command::new(std::env::current_exe().unwrap())
                .args(["swap-cancel-owner", mode])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let pid = u64::from(owner.id());
            let deadline = Instant::now() + Duration::from_secs(5);
            // Read the signal without filesystem polling, keeping the same
            // startup bound even if the pipe never becomes readable.
            let mut stdout = owner.stdout.take().unwrap();
            let ready = std::thread::spawn(move || {
                let mut marker = [0; 6];
                stdout.read_exact(&mut marker).unwrap();
                assert_eq!(&marker, b"ready\n");
            });
            while !ready.is_finished() {
                assert!(
                    owner.try_wait().unwrap().is_none(),
                    "worker exited before readiness"
                );
                assert!(
                    Instant::now() < deadline,
                    "episode {episode} {mode}: worker did not become ready"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            ready.join().unwrap();
            owner.kill().unwrap();
            assert_eq!(owner.wait().unwrap().code(), Some(-1));
            // The last process handle must close before checking retained stats.
            drop(owner);
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut children = [ProcessInfoV1::default(); 2];
            loop {
                let count = ProcessInfoV1::list_children(pid, &mut children).unwrap();
                if count == 0 {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "episode {episode} {mode}: owner {pid} retained child {} (active={})",
                    children[0].pid,
                    children[0].active
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    println!("test_swap_cancel_releases_children PASS");
}

/// The kernel's wait-handle limit. A list this long does not fit the kernel's
/// inline buffer, so every waiter holds an 8 KiB kernel heap copy of it.
const SPILL_HANDLES: usize = 1024;
const SPILL_WAITERS: usize = 64;

fn spill_wait(tid: &AtomicU64) -> ! {
    let mut handles = vec![SysHandle::NONE; SPILL_HANDLES];
    tid.store(
        moto_sys::UserThreadControlBlock::this_thread_tid(),
        Ordering::Release,
    );
    loop {
        // Empty handles are skipped, so nothing wakes this wait on purpose. A
        // stray wake only repeats it; an error means it never held its list.
        handles.fill(SysHandle::NONE);
        if let Err(err) = SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None) {
            eprintln!("wait on {SPILL_HANDLES} handles failed: {err}");
            std::process::exit(1);
        }
    }
}

/// Whether the kernel holds this thread parked in `SysCpu::wait`.
fn parked_in_wait(tid: u64) -> bool {
    if tid == 0 {
        return false; // The thread has not started yet.
    }
    let thread = moto_sys::SysRay::dbg_get_thread_data_v1(SysHandle::SELF, tid).unwrap();
    matches!(thread.status, moto_sys::stats::ThreadStatus::LiveInWait)
        && thread.syscall_num == moto_sys::syscalls::SYS_CPU
        && thread.syscall_op == SysCpu::OP_WAIT
}

fn run_spill_worker(root: &Path) -> ! {
    let tids: Arc<Vec<AtomicU64>> =
        Arc::new((0..SPILL_WAITERS).map(|_| AtomicU64::new(0)).collect());
    for index in 0..SPILL_WAITERS {
        let tids = tids.clone();
        std::thread::spawn(move || spill_wait(&tids[index]));
    }
    // Ready means every waiter is parked with its list in the kernel. The
    // parent's readiness deadline bounds this loop.
    while !tids
        .iter()
        .all(|tid| parked_in_wait(tid.load(Ordering::Acquire)))
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    std::fs::write(root.join("ready"), std::process::id().to_string()).unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn kernel_heap_bytes() -> u64 {
    moto_sys::stats::MemoryStats::get().unwrap().heap_total
}

/// Runs one worker until all its waiters are parked, then kills it.
fn kill_spill_waiters(name: &str) {
    let root = crate::temp_path(&format!("wait-spill-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let mut worker = Command::new(std::env::current_exe().unwrap())
        .args(["wait-spill-worker", root.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit()) // A failed wait says why the worker exited.
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !root.join("ready").is_file() {
        assert!(
            worker.try_wait().unwrap().is_none(),
            "worker exited before readiness"
        );
        assert!(Instant::now() < deadline, "worker did not become ready");
        std::thread::sleep(Duration::from_millis(1));
    }
    worker.kill().unwrap();
    assert_eq!(worker.wait().unwrap().code(), Some(-1));
    std::fs::remove_dir_all(root).unwrap();
}

/// A killed thread's kernel stack is discarded, not unwound: the handle list
/// of its wait must not live there.
fn test_killed_waiters_release_handle_lists() {
    const EPISODES: u64 = 4;
    let lists = EPISODES * (SPILL_WAITERS * SPILL_HANDLES * size_of::<SysHandle>()) as u64;
    // The first worker grows the kernel's slabs for this many threads.
    kill_spill_waiters("warm-up");
    let before = kernel_heap_bytes();
    for episode in 0..EPISODES {
        kill_spill_waiters(&episode.to_string());
    }
    // Other system activity grows the kernel's slabs 256 KiB at a time, as
    // much as half of one worker's lists: judge all the workers together.
    let deadline = Instant::now() + Duration::from_secs(5);
    let growth = loop {
        let growth = kernel_heap_bytes().saturating_sub(before);
        if growth < lists / 2 {
            break growth;
        }
        assert!(
            Instant::now() < deadline,
            "kernel heap grew by {growth} bytes; the killed waiters' handle lists took {lists}"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    println!("test_killed_waiters_release_handle_lists PASS (kernel heap grew by {growth} bytes)");
}
