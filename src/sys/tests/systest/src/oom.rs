//! Armed-policy tests, launched by the System console with all resources
//! prepared before pressure. Observe the tested waiter, not just free pages.

use moto_sys::stats::{MetricDescWire, MetricEntry, PID_SYSTEM, ThreadStatus};
use moto_sys::{SysCpu, SysHandle, SysMem, SysObj, SysRay, sys_mem::PAGE_SIZE_SMALL};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const RW: u32 = SysMem::F_READABLE | SysMem::F_WRITABLE;

struct Metrics {
    parks: u32,
    faults: u32,
    runs: u32,
    kills: u32,
}

impl Metrics {
    fn new() -> Self {
        let mut desc = [MetricDescWire::new(0, ""); 128];
        let (count, total) = SysRay::query_stats_describe(&mut desc).unwrap();
        assert_eq!(count, total);
        let id = |name| {
            desc[..count]
                .iter()
                .find(|d| d.name_str() == name)
                .unwrap()
                .metric
        };
        Self {
            parks: id("mem.oom_parked_syscalls"),
            faults: id("mem.oom_parked_faults"),
            runs: id("mem.oom_runs"),
            kills: id("mem.oom_kills"),
        }
    }

    fn read(&self, metric: u32, pid: u64) -> u64 {
        let mut entries = [MetricEntry::default(); 128];
        let (count, total) = SysRay::query_stats(pid, &mut entries).unwrap();
        assert_eq!(count, total);
        entries[..count]
            .iter()
            .find(|e| e.metric == metric)
            .unwrap()
            .value
    }
}

struct Pressure(Vec<u64>);

impl Pressure {
    fn new() -> Self {
        let pages = moto_sys::stats::MemoryStats::get().unwrap().available / PAGE_SIZE_SMALL;
        Self(Vec::with_capacity((pages / 8192 + 64) as usize))
    }

    fn drain_to(&mut self, target: u64) {
        loop {
            let free = moto_sys::free_pages();
            if free <= target + 32 {
                break;
            }
            let pages = ((free - target) / 2).min(8192);
            // Avoid the eager allocator's rounding up to a huge page.
            let pages = if pages >= 512 {
                pages / 512 * 512
            } else {
                pages.min(128)
            };
            assert!(self.0.len() < self.0.capacity());
            self.0.push(SysMem::alloc(PAGE_SIZE_SMALL, pages).unwrap());
        }
    }
}

impl Drop for Pressure {
    fn drop(&mut self) {
        for addr in self.0.drain(..) {
            SysMem::free(addr).unwrap();
        }
    }
}

fn map(space: SysHandle, pages: u64) -> Result<u64, moto_rt::ErrorCode> {
    SysMem::map(space, RW, u64::MAX, u64::MAX, PAGE_SIZE_SMALL, pages)
}

fn in_map(debug: SysHandle, tid: u64) -> bool {
    let data = SysRay::dbg_get_thread_data_v1(debug, tid).unwrap();
    matches!(data.status, ThreadStatus::LiveInWait)
        && data.syscall_num == moto_sys::syscalls::SYS_MEM
        && data.syscall_op == SysMem::OP_MAP
}

/// A System caller mapping a process-less (User-class) space still waits.
/// A foreign wake must survive both the first park and its spurious retry.
fn syscall_wait(metrics: &Metrics, close_target: bool) {
    for attempt in 1..=3 {
        let space =
            SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=oom-wait").unwrap();
        let go = AtomicBool::new(false);
        let done = AtomicBool::new(false);
        let recovered_before_entry = AtomicBool::new(false);
        let tid = AtomicU64::new(0);
        let handle = AtomicU64::new(0);
        let mut pressure = Pressure::new();
        let before = metrics.read(metrics.parks, moto_sys::current_pid());
        let runs = metrics.read(metrics.runs, PID_SYSTEM);
        let observed = std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                handle.store(moto_sys::current_thread().as_u64(), Ordering::Release);
                tid.store(
                    moto_sys::UserThreadControlBlock::this_thread_tid(),
                    Ordering::Release,
                );
                while !go.load(Ordering::Acquire) {
                    SysCpu::sched_yield();
                }
                recovered_before_entry.store(moto_sys::free_pages() >= 768, Ordering::Release);
                let result = map(space, 256);
                done.store(true, Ordering::Release);
                // No intervening userspace wait may consume the test wake.
                let woke = SysCpu::wait(
                    &mut [],
                    SysHandle::NONE,
                    SysHandle::NONE,
                    Some(moto_rt::time::Instant::now() + Duration::from_millis(50)),
                );
                (result, woke)
            });
            while tid.load(Ordering::Acquire) == 0 {
                SysCpu::sched_yield();
            }
            pressure.drain_to(640);
            go.store(true, Ordering::Release);
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut observed = false;
            while !done.load(Ordering::Acquire) && Instant::now() < deadline {
                if metrics.read(metrics.parks, moto_sys::current_pid()) > before
                    && in_map(SysHandle::SELF, tid.load(Ordering::Acquire))
                {
                    observed = true;
                    break;
                }
                SysCpu::sched_yield();
            }
            let completed_before_release = done.load(Ordering::Acquire);
            if observed {
                let parks = metrics.read(metrics.parks, moto_sys::current_pid());
                SysCpu::wake(SysHandle::from_u64(handle.load(Ordering::Acquire))).unwrap();
                // Require the spurious return to register another wait while
                // pressure is still held. A lost wake after this is a failure.
                while metrics.read(metrics.parks, moto_sys::current_pid()) == parks
                    && Instant::now() < deadline
                {
                    SysCpu::sched_yield();
                }
                let reparked = metrics.read(metrics.parks, moto_sys::current_pid()) > parks;
                // Permanent size errors are still returned while the gate is closed.
                assert_eq!(map(space, (1 << 28) + 1), Err(moto_rt::E_OUT_OF_MEMORY));
                if close_target {
                    SysObj::put(space).unwrap();
                }
                drop(pressure);
                assert!(reparked, "OOM wake did not recheck its wait reason");
            } else {
                drop(pressure);
            }
            let (result, woke) = worker.join().unwrap();
            if observed && close_target {
                assert_eq!(result, Err(moto_rt::E_INVALID_ARGUMENT));
            } else {
                let addr = result.unwrap();
                SysMem::unmap(space, 0, u64::MAX, addr).unwrap();
            }
            if observed {
                assert_eq!(woke, Ok(()), "OOM park consumed the pending userspace wake");
            } else {
                // Only recovery before entry permits another attempt. A park
                // missed by the observer still fails, even if the map succeeded.
                assert_eq!(
                    metrics.read(metrics.parks, moto_sys::current_pid()),
                    before,
                    "worker parked but was not observed; not a pre-entry recovery miss"
                );
                assert!(
                    completed_before_release && recovered_before_entry.load(Ordering::Acquire),
                    "worker wait was not observed and recovery was not proven before entry"
                );
            }
            observed
        });
        if !observed || !close_target {
            SysObj::put(space).unwrap();
        }
        if observed {
            assert!(metrics.read(metrics.runs, PID_SYSTEM) > runs);
            println!("oom: syscall wait, wake retention, target_closed={close_target} PASS");
            return;
        }
        println!(
            "oom: attempt {attempt} missed: map succeeded and >=768 free pages before map entry"
        );
    }
    panic!("all three syscall pressure windows were missed");
}

/// Creation and first start both enforce the existing 4 MiB limit, including System.
fn spawn_refusal() {
    let space = SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=oom-start").unwrap();
    let stopped = SysObj::create(space, 0, "process:entry_point=4096;capabilities=1").unwrap();
    let thread = SysObj::get(stopped, 0, "main_thread").unwrap();
    let unclaimed =
        SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=oom-create").unwrap();
    let mut pressure = Pressure::new();
    pressure.drain_to(896); // Spawn's 4 MiB check, above OOM recovery.
    let create = SysObj::create(unclaimed, 0, "process:entry_point=4096;capabilities=0");
    SysCpu::wake(thread).unwrap();
    crate::raw_spawn::wait_exit(stopped, "delayed start under pressure");
    let status = SysRay::process_status(stopped).unwrap();
    drop(pressure);
    assert_eq!(create, Err(moto_rt::E_OUT_OF_MEMORY));
    assert_eq!(status, Some(u64::MAX)); // Start refusal, before the invalid entry point can run.
    for handle in [thread, stopped, space, unclaimed] {
        SysObj::put(handle).unwrap();
    }
    println!("oom: process creation and delayed start refusal PASS");
}

/// A large failed attempt whose rollback restores >=3 MiB returns an error.
fn large_rollback() {
    let space =
        SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=oom-rollback").unwrap();
    let mut pressure = Pressure::new();
    pressure.drain_to(2048);
    let result = map(space, 4096);
    let recovered = moto_sys::free_pages();
    drop(pressure);
    SysObj::put(space).unwrap();
    assert_eq!(result, Err(moto_rt::E_OUT_OF_MEMORY));
    assert!(recovered >= 768);
    println!("oom: large eager rollback PASS");
}

/// Never-started victims exercise kernel cleanup without an output dependency.
/// Prefer the newest None, spare older None and newer Interactive, then escalate.
fn victims(metrics: &Metrics) {
    for _ in 0..2 {
        let target =
            SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=oom-trigger").unwrap();
        let mut children = Vec::new();
        for (name, caps) in [("oom-older", 0), ("oom-newer", 0), ("oom-interactive", 64)] {
            let space = SysObj::create(
                SysHandle::NONE,
                0,
                &format!("address_space:debug_name={name}"),
            )
            .unwrap();
            let process = SysObj::create(
                space,
                0,
                &format!("process:entry_point=4096;capabilities={caps}"),
            )
            .unwrap();
            map(process, 8192).unwrap();
            SysObj::put(space).unwrap();
            children.push(process);
        }
        let runs = metrics.read(metrics.runs, PID_SYSTEM);
        let kills = metrics.read(metrics.kills, PID_SYSTEM);
        let mut pressure = Pressure::new();
        pressure.drain_to(640);
        // The User floor refusal starts a run and waits for the newest victim.
        let addr = map(children[0], 256).unwrap();
        crate::raw_spawn::wait_exit(children[1], "OOM newest victim");
        let older_alive = SysRay::process_status(children[0]).unwrap().is_none();
        let interactive_alive = SysRay::process_status(children[2]).unwrap().is_none();
        let recovered = moto_sys::free_pages() >= 768;
        drop(pressure);
        assert!(older_alive && interactive_alive && recovered);
        assert_eq!(metrics.read(metrics.kills, PID_SYSTEM), kills + 1);
        assert_eq!(metrics.read(metrics.runs, PID_SYSTEM), runs + 1);
        SysMem::unmap(children[0], 0, u64::MAX, addr).unwrap();
        SysCpu::kill(children[0]).unwrap();
        crate::raw_spawn::wait_exit(children[0], "older victim cleanup before escalation");
        let mut pressure = Pressure::new();
        pressure.drain_to(640);
        let addr = map(target, 256).unwrap();
        crate::raw_spawn::wait_exit(children[2], "OOM Interactive escalation");
        drop(pressure);
        assert_eq!(metrics.read(metrics.kills, PID_SYSTEM), kills + 2);
        assert_eq!(metrics.read(metrics.runs, PID_SYSTEM), runs + 2);
        SysMem::unmap(target, 0, u64::MAX, addr).unwrap();
        SysObj::put(target).unwrap();
        for child in children {
            SysObj::put(child).unwrap();
        }
    }
    println!("oom: newest victim, role priority, escalation, repeated recovery PASS");
}

#[repr(C)]
#[derive(Default)]
struct Control {
    ready: AtomicU64,
    go: AtomicBool,
    done: AtomicBool,
    recovered_before_fault: AtomicBool,
    driver_pid: AtomicU64,
    driver_done: AtomicBool,
}

struct Child {
    handle: SysHandle,
    pid: u64,
    control_addr: u64,
}

impl Child {
    fn new(mode: &str, system: bool) -> Self {
        let child = moto_rt::process::spawn(moto_rt::process::SpawnArgs {
            program: std::env::current_exe()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned(),
            args: vec!["oom-child".into(), mode.into()],
            env: vec![(
                moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY.into(),
                if system { "0x5" } else { "0" }.into(),
            )],
            cwd: None,
            stdin: moto_rt::process::STDIO_MAKE_PIPE,
            stdout: moto_rt::process::STDIO_NULL,
            stderr: moto_rt::process::STDIO_PARENT_STDERR,
        })
        .unwrap();
        let handle = SysHandle::from_u64(child.handle);
        let (remote, local) = SysMem::map2(
            handle,
            RW | SysMem::F_SHARE_SELF,
            u64::MAX,
            u64::MAX,
            PAGE_SIZE_SMALL,
            1,
        )
        .unwrap();
        unsafe {
            (local as *mut Control).write(Control::default());
        }
        assert_eq!(
            moto_rt::fs::write(child.stdin, &remote.to_le_bytes()),
            Ok(8)
        );
        moto_rt::fs::close(child.stdin).unwrap();
        let child = Self {
            handle,
            pid: child.pid as u64,
            control_addr: local,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.control().ready.load(Ordering::Acquire) == 0 {
            assert!(
                SysRay::process_status(child.handle).unwrap().is_none(),
                "OOM child exited during preparation"
            );
            assert!(Instant::now() < deadline, "OOM child not ready");
            SysCpu::sched_yield();
        }
        let mut info = [moto_sys::stats::ProcessInfoV1::default(); 1];
        assert_eq!(
            moto_sys::stats::ProcessInfoV1::list(child.pid, &mut info),
            Ok(1)
        );
        assert_eq!(info[0].pid, child.pid);
        assert_eq!(info[0].process_role, if system { 2 } else { 0 });
        child
    }

    fn control(&self) -> &Control {
        unsafe { &*(self.control_addr as *const Control) }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        SysCpu::kill(self.handle).unwrap();
        crate::raw_spawn::wait_exit(self.handle, "OOM child cleanup");
        // Retain the process and shared-page handles through reclamation.
        assert_eq!(crate::kernel_metric("active_threads", self.pid), 0);
        assert_eq!(crate::kernel_metric("pages_user", self.pid), 0);
        assert_eq!(crate::kernel_metric("pages_kernel", self.pid), 0);
        SysObj::put(self.handle).unwrap();
        SysMem::free(self.control_addr).unwrap();
    }
}

// Run this instruction path once before pressure: otherwise an executable
// file miss can wait on sys-io's pager before reaching the intended lazy fault.
#[inline(never)]
fn system_fault(metrics: &Metrics, control: &Control, pid: u64, pending: u64, addr: u64) {
    while metrics.read(metrics.parks, pid) == pending
        && !control.driver_done.load(Ordering::Acquire)
    {
        core::hint::spin_loop();
    }
    control
        .recovered_before_fault
        .store(moto_sys::free_pages() >= 768, Ordering::Release);
    unsafe {
        (addr as *mut u64).write_volatile(0x1234);
    }
}

pub fn run_child(mode: &str) -> ! {
    use std::io::Read;
    let mut bytes = [0; 8];
    std::io::stdin().read_exact(&mut bytes).unwrap();
    let control = unsafe { &*(u64::from_le_bytes(bytes) as *const Control) };
    let space = if mode == "cancel" {
        SysObj::create(
            SysHandle::NONE,
            0,
            "address_space:debug_name=oom-child-wait",
        )
        .unwrap()
    } else {
        SysHandle::SELF
    };
    let lazy = SysMem::map(
        SysHandle::SELF,
        RW | SysMem::F_LAZY,
        u64::MAX,
        u64::MAX,
        PAGE_SIZE_SMALL,
        256,
    )
    .unwrap();
    let ready = || {
        control.ready.store(
            moto_sys::UserThreadControlBlock::this_thread_tid(),
            Ordering::Release,
        );
        while !control.go.load(Ordering::Acquire) {
            SysCpu::sched_yield();
        }
    };
    if mode == "system-fault" {
        let metrics = Metrics::new();
        system_fault(&metrics, control, moto_sys::current_pid(), u64::MAX, lazy);
        ready();
        // Separate address spaces keep stats copy-out from contending with
        // the allocating driver's MM lock. Its refusal blocks System faults.
        system_fault(
            &metrics,
            control,
            control.driver_pid.load(Ordering::Acquire),
            0,
            lazy + PAGE_SIZE_SMALL,
        );
    } else if mode.starts_with("fault") {
        ready();
        for page in 0..256 {
            unsafe {
                ((lazy + page * PAGE_SIZE_SMALL) as *mut u64).write_volatile(page);
            }
        }
    } else {
        ready();
        map(space, if mode == "system" { 1024 } else { 256 }).unwrap();
    }
    control.done.store(true, Ordering::Release);
    // The parent controls termination and keeps both handles through cleanup.
    loop {
        SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, None).unwrap();
    }
}

fn child_wait(metrics: &Metrics, mode: &str) -> bool {
    let fault = mode.starts_with("fault");
    let driver = (mode == "system-fault").then(|| Child::new("system", true));
    let child = Child::new(mode, !fault);
    if let Some(driver) = &driver {
        child
            .control()
            .driver_pid
            .store(driver.pid, Ordering::Release);
    }
    let debug = SysRay::dbg_attach(child.pid).unwrap();
    // A newer None victim supplies recovery for a fault or System shortage.
    let victim = if matches!(mode, "cancel" | "fault-kill") {
        None
    } else {
        let space =
            SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=oom-recovery").unwrap();
        let victim = SysObj::create(space, 0, "process:entry_point=4096;capabilities=0").unwrap();
        // Small pages keep cleanup concurrent with the System allocation;
        // one huge-page release alone would immediately pass recovery.
        SysMem::map(
            victim,
            RW | SysMem::F_GUARDED,
            u64::MAX,
            u64::MAX,
            PAGE_SIZE_SMALL,
            8192,
        )
        .unwrap();
        SysObj::put(space).unwrap();
        Some(victim)
    };
    let mut small_victims = Vec::with_capacity(4);
    if mode.starts_with("system") {
        let before = moto_sys::free_pages();
        for _ in 0..4 {
            let space =
                SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=oom-small").unwrap();
            small_victims
                .push(SysObj::create(space, 0, "process:entry_point=4096;capabilities=0").unwrap());
            SysObj::put(space).unwrap();
        }
        // Even their complete footprint plus the post-rollback free count
        // stays below recovery. Only the older 32 MiB victim can end the run.
        assert!(before.saturating_sub(moto_sys::free_pages()) < 128);
    }
    let metric = if fault || mode == "system-fault" {
        metrics.faults
    } else {
        metrics.parks
    };
    let before = metrics.read(metric, child.pid);
    let runs = metrics.read(metrics.runs, PID_SYSTEM);
    let kills = metrics.read(metrics.kills, PID_SYSTEM);
    in_map(debug, child.control().ready.load(Ordering::Acquire)); // Warm observation before pressure.
    let mut pressure = Pressure::new();
    pressure.drain_to(if mode.starts_with("system") { 576 } else { 640 });
    child.control().go.store(true, Ordering::Release);
    if let Some(driver) = &driver {
        driver.control().go.store(true, Ordering::Release);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut parked = false;
    while Instant::now() < deadline {
        if let Some(driver) = &driver {
            child.control().driver_done.store(
                driver.control().done.load(Ordering::Acquire),
                Ordering::Release,
            );
        }
        if matches!(mode, "cancel" | "system") {
            parked |= metrics.read(metric, child.pid) > before
                && in_map(debug, child.control().ready.load(Ordering::Acquire));
            if mode == "cancel" && parked {
                break;
            }
        }
        if (child.control().done.load(Ordering::Acquire)
            && driver
                .as_ref()
                .is_none_or(|d| d.control().done.load(Ordering::Acquire)))
            || (mode == "fault-kill" && SysRay::process_status(child.handle).unwrap().is_some())
        {
            break;
        }
        SysCpu::sched_yield();
    }
    let completed = child.control().done.load(Ordering::Acquire)
        && driver
            .as_ref()
            .is_none_or(|d| d.control().done.load(Ordering::Acquire));
    let waited = metrics.read(metric, child.pid) > before;
    let missed = mode == "system-fault"
        && !waited
        && completed
        && child
            .control()
            .recovered_before_fault
            .load(Ordering::Acquire);
    let killed = SysRay::process_status(child.handle).unwrap().is_some();
    if mode == "cancel" && parked {
        // Kill while pressure remains, proving suspension holds no MM resources.
        SysCpu::kill(child.handle).unwrap();
        crate::raw_spawn::wait_exit(child.handle, "parked syscall cancellation");
    }
    drop(pressure);
    SysRay::dbg_detach(debug).unwrap();
    if let Some(victim) = victim {
        crate::raw_spawn::wait_exit(victim, "fault/System recovery victim");
        SysObj::put(victim).unwrap();
    }
    for victim in small_victims {
        crate::raw_spawn::wait_exit(victim, "insufficient OOM victim");
        SysObj::put(victim).unwrap();
    }
    if mode.starts_with("system") {
        assert_eq!(metrics.read(metrics.kills, PID_SYSTEM), kills + 5);
        assert_eq!(
            metrics.read(metrics.runs, PID_SYSTEM),
            runs + 1,
            "the small cleanups must not reach recovery before the large victim"
        );
    }
    drop(child);
    drop(driver);
    if missed {
        println!(
            "oom: System fault window missed: allocation succeeded, >=768 free pages before fault entry"
        );
        return false;
    }
    assert!(waited, "{mode}: tested child did not register an OOM wait");
    assert!(
        if mode == "cancel" {
            parked && !completed
        } else if mode == "fault-kill" {
            killed && !completed
        } else if mode == "system" {
            parked && completed
        } else {
            completed
        },
        "{mode}: wrong waiter outcome"
    );
    println!("oom: {mode} waiter and reclamation PASS");
    true
}

pub fn run_all_tests() {
    assert_eq!(
        moto_sys::caps::ProcessRole::from_caps(moto_sys::ProcessStaticPage::get().capabilities),
        moto_sys::caps::ProcessRole::System
    );
    let metrics = Metrics::new();
    spawn_refusal();
    large_rollback();
    victims(&metrics);
    syscall_wait(&metrics, false);
    syscall_wait(&metrics, true);
    child_wait(&metrics, "fault");
    child_wait(&metrics, "fault-kill");
    child_wait(&metrics, "system");
    assert!(
        (1..=3).any(|attempt| {
            let observed = child_wait(&metrics, "system-fault");
            if !observed {
                println!("oom: System fault attempt {attempt}/3 missed");
            }
            observed
        }),
        "all three System fault windows were missed"
    );
    child_wait(&metrics, "cancel");
    println!("oom::run_all_tests PASS");
}
