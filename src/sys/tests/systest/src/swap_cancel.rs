use moto_sys::{SysCpu, SysHandle, stats::ProcessInfoV1};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub fn run_command(args: &[String]) -> bool {
    match args.get(1).map(String::as_str) {
        Some("swap-cancel-owner") => {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["swap-cancel-worker", &args[2], &args[3]])
                .status()
                .unwrap();
            assert!(status.success());
            true
        }
        Some("swap-cancel-worker") => run_worker(Path::new(&args[2]), args[3] == "swap"),
        Some("test-swap-cancel") => {
            run_tests();
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

fn run_worker(root: &Path, swap: bool) -> ! {
    let cpu = (moto_sys::num_cpus() > 1).then_some(1);
    SysCpu::affine_to_cpu(cpu).unwrap();
    let token = Arc::new(AtomicU64::new(0));
    let peer_handle = Arc::new(AtomicU64::new(0));
    let main_handle = moto_sys::current_thread();
    let before = crate::kernel_metric("direct_switch", moto_stats::provider::KERNEL);
    let peer_token = token.clone();
    let published_handle = peer_handle.clone();
    std::thread::spawn(move || {
        SysCpu::affine_to_cpu(cpu).unwrap();
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
    for index in 0..u64::MAX / 2 {
        token.store(index * 2 + 1, Ordering::Release);
        while token.load(Ordering::Acquire) != index * 2 + 2 {
            handoff(peer, swap);
        }
        if index == 100 {
            if swap {
                assert!(
                    crate::kernel_metric("direct_switch", moto_stats::provider::KERNEL) > before,
                    "worker never entered the direct-switch path"
                );
            }
            std::fs::write(root.join("ready"), std::process::id().to_string()).unwrap();
        }
    }
    unreachable!()
}

pub fn run_tests() {
    // Each episode must clear its child record; these are distinct kills, not
    // retries. Ordinary wakes provide a control for the swap-target path.
    for episode in 0..4 {
        for mode in ["wake", "swap"] {
            let root = crate::temp_path(&format!(
                "swap-cancel-{}-{episode}-{mode}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let mut owner = Command::new(std::env::current_exe().unwrap())
                .args(["swap-cancel-owner", root.to_str().unwrap(), mode])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let pid = u64::from(owner.id());
            let deadline = Instant::now() + Duration::from_secs(5);
            while !root.join("ready").is_file() {
                assert!(
                    owner.try_wait().unwrap().is_none(),
                    "worker exited before readiness"
                );
                assert!(Instant::now() < deadline, "worker did not become ready");
                std::thread::sleep(Duration::from_millis(1));
            }
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
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    println!("test_swap_cancel_releases_children PASS");
}
