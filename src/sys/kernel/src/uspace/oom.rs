//! Scheduler-driven OOM selection. The physical allocator owns count/phase/
//! generation; this lock owns job, exit-continuation and waiter bookkeeping.
//! Runtime policy stays unarmed until syscall and fault waits are installed.

use super::process::{Process, ProcessStatus, Thread};
use crate::{mm::phys, util::SpinLock};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use moto_sys::caps::ProcessRole;

pub(crate) mod wait;
use crate::mm::WaitReason;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Disposition {
    Eligible(u8),
    Exiting,
    Ineligible,
}

// Bootstrap protection uses public PIDs, which are never reused for sys-io.
pub(super) fn classify(
    user_pid: u64,
    parent_pid: Option<u64>,
    grandparent_pid: Option<u64>,
    role: ProcessRole,
    status: ProcessStatus,
    paused: bool,
    threads_empty: bool,
) -> Disposition {
    if paused || status == ProcessStatus::PausedDebuggee {
        return Disposition::Ineligible;
    }
    if matches!(status, ProcessStatus::Exiting(_))
        || (status == ProcessStatus::Running && threads_empty)
    {
        return Disposition::Exiting;
    }
    let sys_io = moto_sys::stats::PID_SYS_IO;
    if !matches!(status, ProcessStatus::Created | ProcessStatus::Running)
        || user_pid == sys_io
        || parent_pid == Some(sys_io)
        || grandparent_pid == Some(sys_io)
    {
        return Disposition::Ineligible;
    }
    match role {
        ProcessRole::None => Disposition::Eligible(0),
        ProcessRole::Interactive => Disposition::Eligible(1),
        ProcessRole::System => Disposition::Ineligible,
    }
}

fn preferred(role: u8, kernel_pid: u64, best_role: u8, best_kernel_pid: u64) -> bool {
    role < best_role || (role == best_role && kernel_pid > best_kernel_pid)
}

#[derive(Default)]
struct WorkState {
    observed_generation: u64,
    observed_run: Option<u64>,
    job: Option<u64>,
    // Kept across recovery/new runs until this exact victim finishes cleanup.
    pending_victim: Option<(u64, u64)>,
    waiting_for_exits: Option<u64>,
    // Parked faults resume through the pager's status-checked path, parked
    // syscalls through Thread::oom_resume(). Removal owns the resume.
    fault_waiters: Vec<(Weak<Thread>, WaitReason)>,
    syscall_waiters: Vec<(Weak<Thread>, WaitReason)>,
}

impl WorkState {
    fn observe(&mut self, generation: u64, killing: bool) -> (Option<u64>, Option<u64>) {
        if self.observed_generation >= generation {
            return (None, None);
        }
        self.observed_generation = generation;
        self.waiting_for_exits = None;
        let ended = self.observed_run.take();
        self.observed_run = killing.then_some(generation);
        (ended, self.observed_run)
    }

    fn schedule(&mut self, generation: u64, killing: bool) -> bool {
        if self.observed_generation != generation
            || !killing
            || self.job.is_some()
            || self.pending_victim.is_some()
            || self.waiting_for_exits == Some(generation)
        {
            return false;
        }
        self.job = Some(generation);
        true
    }

    fn commit(&mut self, generation: u64, pid: u64, validate: impl FnOnce() -> bool) -> bool {
        if self.job != Some(generation) || self.pending_victim.is_some() || !validate() {
            return false;
        }
        self.waiting_for_exits = None;
        self.pending_victim = Some((generation, pid));
        true
    }

    fn wait_for_exits(&mut self, generation: u64) -> bool {
        // A delayed scan cannot reinstall interest cleared by a newer run.
        if self.job != Some(generation) || self.observed_generation != generation {
            return false;
        }
        self.waiting_for_exits = Some(generation);
        true
    }

    fn finish(&mut self, generation: u64, wait: bool) -> bool {
        if self.job != Some(generation) {
            return false;
        }
        self.job = None;
        if !wait && self.waiting_for_exits == Some(generation) {
            self.waiting_for_exits = None;
        }
        // If exit notification raced the scan, its attention may have been
        // consumed while this job occupied the slot. Supply it again.
        !wait || self.waiting_for_exits != Some(generation)
    }

    fn exited(&mut self, pid: u64) -> bool {
        let progress = self.waiting_for_exits.take().is_some();
        if self.pending_victim.is_some_and(|(_, victim)| victim == pid) {
            self.pending_victim = None;
            true
        } else {
            progress
        }
    }
}

pub(crate) struct OomState {
    work: SpinLock<WorkState>,
}

impl OomState {
    pub(crate) fn new() -> Self {
        Self {
            work: SpinLock::new(WorkState::default()),
        }
    }
}

fn state() -> &'static OomState {
    crate::mm::virt::oom_state()
}

/// Called beside process_wake_events(), with no scheduler/MM lock held.
pub(crate) fn attend() {
    while phys::take_oom_attention() {
        let (generation, free, ended, started, post, faults, syscalls) = {
            let mut work = state().work.lock(line!());
            let (snapshot, free) = phys::oom_snapshot();
            if !snapshot.armed() {
                return;
            }
            let generation = snapshot.generation();
            let (ended, started) = work.observe(generation, snapshot.killing());
            let post = work.schedule(generation, snapshot.killing());
            let faults = wait::take_ready(&mut work.fault_waiters, snapshot);
            let syscalls = wait::take_ready(&mut work.syscall_waiters, snapshot);
            (generation, free, ended, started, post, faults, syscalls)
        };
        for thread in faults {
            resume_fault(thread);
        }
        for thread in syscalls {
            if let Some(thread) = thread.upgrade() {
                thread.oom_resume();
            }
        }
        if let Some(ended) = ended {
            crate::raw_log!("OOM: end generation {ended}, {free} free pages");
        }
        if let Some(started) = started {
            crate::raw_log!("OOM: start generation {started}, {free} free pages");
        }
        if post {
            crate::sched::post(crate::sched::Job::new(
                run,
                Weak::new(),
                generation,
                crate::config::uCpus::MAX,
            ));
        }
    }
}

fn count_park(thread: &Thread, metric: crate::xray::stats::MetricType) {
    thread.process_stats.adjust_metric(metric, 1);
    crate::xray::stats::system_stats_ref().adjust_metric(metric, 1);
}

fn resume_fault(thread: Weak<Thread>) {
    if let Some(thread) = thread.upgrade() {
        thread.resume_file_fault(false, true);
    }
}

/// The caller has unwound MM and published Preempted, without a resume job.
/// Removal from this queue is the sole owner of a successful resume. A kill
/// uses the normal Preempted exit path; resume_file_fault skips killed threads.
pub(super) fn on_fault(thread: &Thread, failure: crate::mm::AllocationFailure) -> bool {
    let crate::mm::AllocationFailure::Pressure { class, .. } = failure else {
        return false;
    };
    let reason = match wait::resolve(failure, true) {
        Ok(reason) => reason.unwrap_or_else(|| WaitReason::gate(class)),
        Err(_) => return false,
    };
    count_park(thread, crate::xray::stats::MetricType::OomParkedFaults);
    let ready = {
        let mut work = state().work.lock(line!());
        // Read under the same lock as removal, after the entry is present.
        wait::register(&mut work.fault_waiters, thread.get_weak(), reason, || {
            phys::oom_snapshot().0
        })
    };
    if let Some(thread) = ready {
        resume_fault(thread);
    }
    true
}

fn finish(generation: u64, wait: bool) {
    let attention = state().work.lock(line!()).finish(generation, wait);
    if attention {
        phys::request_oom_attention();
    }
}

/// Exit publication and the post-kill completion check share one claim. All
/// process/MM locks have been released before an exit calls this hook.
pub(super) fn on_process_exited(pid: u64) {
    if !phys::oom_snapshot().0.armed() {
        return;
    }
    let attention = state().work.lock(line!()).exited(pid);
    if attention {
        phys::request_oom_attention();
    }
}

fn select() -> (Option<Arc<Process>>, bool) {
    let mut best: Option<Arc<Process>> = None;
    let mut best_role = u8::MAX;
    let mut exiting = false;
    crate::xray::stats::KProcessStats::for_each_process(|stats| {
        let Some(process) = stats.owner.upgrade() else {
            return;
        };
        match process.oom_disposition() {
            Disposition::Eligible(role) => {
                if best.as_ref().is_none_or(|old| {
                    preferred(role, process.kernel_pid(), best_role, old.kernel_pid())
                }) {
                    best = Some(process);
                    best_role = role;
                }
            }
            Disposition::Exiting => exiting = true,
            Disposition::Ineligible => {}
        }
    });
    (best, exiting)
}

fn run(_: Weak<Thread>, generation: u64) {
    if !phys::still_killing(generation) {
        finish(generation, false);
        return;
    }
    let (mut victim, _) = select();
    if victim.is_none() {
        // Publish interest BEFORE the final status scan. An exit racing it
        // either clears this interest or is already visible to that scan.
        let waiting = state().work.lock(line!()).wait_for_exits(generation);
        if !waiting {
            finish(generation, false);
            return;
        }
        let (candidate, exiting) = select();
        victim = candidate;
        if victim.is_none() && exiting {
            finish(generation, true);
            return;
        }
    }
    if let Some(victim) = victim {
        if !matches!(victim.oom_disposition(), Disposition::Eligible(_)) {
            finish(generation, false);
            return;
        }
        let committed = state()
            .work
            .lock(line!())
            .commit(generation, victim.kernel_pid(), || {
                phys::still_killing(generation)
            });
        if committed {
            crate::xray::stats::system_stats_ref()
                .adjust_metric(crate::xray::stats::MetricType::OomKills, 1);
            let free = phys::available_small_pages();
            crate::raw_log!(
                "OOM: generation {generation}, {free} free pages, kill '{}' pid={} kernel_pid={}",
                victim.debug_name(),
                victim.pid().as_u64(),
                victim.kernel_pid()
            );
            victim.die();
            let complete = victim.oom_exit_complete();
            let pid = victim.kernel_pid();
            drop(victim);
            if complete {
                on_process_exited(pid);
            }
        }
        finish(generation, false);
        return;
    }
    let (snapshot, free) = phys::oom_snapshot();
    if snapshot.killing() && snapshot.generation() == generation {
        if free >= 512 {
            if phys::latch_oom(generation) {
                crate::raw_log!("OOM: no victims, stopping below 768 pages ({free} free)");
            }
        } else {
            report();
            // Reporting may span recovery or a rise to 512 in this same run.
            let (snapshot, free) = phys::oom_snapshot();
            if snapshot.killing() && snapshot.generation() == generation && free < 512 {
                panic!("OOM: no eligible victims or pending reclamation below 512 free pages");
            }
        }
    }
    finish(generation, false);
}

fn report() {
    crate::raw_log!(
        "OOM: remaining processes, {} free physical pages",
        phys::available_small_pages()
    );
    crate::xray::stats::KProcessStats::for_each_process(|stats| {
        let (user, kernel) = stats.memory_usage();
        crate::raw_log!(
            "OOM: '{}' pid={} kernel_pid={} user_bytes={user} kernel_bytes={kernel}",
            stats.debug_name(),
            stats.pid().as_u64(),
            stats.kernel_pid()
        );
    });
}

#[cfg(debug_assertions)]
pub(crate) fn test() {
    wait::test();
    use Disposition::*;
    use ProcessRole::*;
    use ProcessStatus::{Created, Exited, Exiting as ProcessExiting, PausedDebuggee, Running};
    let classify = |role, status, paused, empty, parent, grandparent| {
        self::classify(100, parent, grandparent, role, status, paused, empty)
    };
    assert_eq!(
        classify(None, Running, false, false, Some(10), Some(3)),
        Eligible(0)
    );
    assert_eq!(
        classify(Interactive, Running, false, false, Some(10), Some(3)),
        Eligible(1)
    );
    assert_eq!(
        classify(System, Running, false, false, Some(10), Some(3)),
        Ineligible
    );
    assert_eq!(
        classify(None, Running, false, false, Some(2), Some(1)),
        Ineligible
    );
    assert_eq!(
        classify(Interactive, Created, false, true, Some(3), Some(2)),
        Ineligible
    );
    assert_eq!(
        classify(None, Created, false, true, Some(10), Some(3)),
        Eligible(0)
    );
    assert_eq!(
        classify(None, PausedDebuggee, true, false, Some(10), Some(3)),
        Ineligible
    );
    assert_eq!(
        classify(None, ProcessExiting(0), true, false, Some(10), Some(3)),
        Ineligible
    );
    assert_eq!(
        classify(System, ProcessExiting(0), false, false, Some(2), Some(1)),
        Exiting
    );
    assert_eq!(
        classify(None, Running, false, true, Some(10), Some(3)),
        Exiting
    );
    assert_eq!(
        classify(None, Exited(0), false, true, Some(10), Some(3)),
        Ineligible
    );
    assert_eq!(
        self::classify(2, Some(1), Option::None, None, Running, false, false),
        Ineligible
    );
    assert!(preferred(0, 10, 1, u64::MAX));
    assert!(!preferred(1, u64::MAX, 0, 10));
    assert!(preferred(0, crate::xray::stats::PID_MAX + 1, 0, 10));

    let mut work = WorkState::default();
    assert_eq!(work.observe(1, true), (Option::None, Some(1)));
    assert!(work.schedule(1, true));
    assert!(!work.schedule(1, true));
    assert!(!work.commit(1, 100, || false)); // Recovery preceded the final load.
    assert!(work.commit(1, 100, || true));
    assert!(!work.commit(1, 101, || true));
    work.observe(2, false);
    assert!(work.finish(1, false));
    work.observe(3, true);
    assert!(!work.schedule(3, true)); // Still owns the OLD victim's cleanup.
    assert_eq!(work.pending_victim, Some((1, 100)));
    assert!(!work.exited(101));
    assert!(work.exited(100));
    assert!(!work.exited(100)); // Hook and post-kill check claim exactly once.
    assert!(work.schedule(3, true));
    assert!(!work.finish(1, false)); // Old work cannot clear the new slot.
    assert_eq!(work.job, Some(3));

    assert!(work.wait_for_exits(3));
    assert!(work.exited(200)); // Notification races the final status scan.
    assert!(!work.schedule(3, true)); // Dispatcher consumes attention meanwhile.
    assert!(work.finish(3, true)); // Worker must request that attention AGAIN.
    assert!(work.schedule(3, true));
    assert!(work.wait_for_exits(3));
    assert!(!work.finish(3, true)); // No progress: wait without polling/reposting.
    assert!(!work.schedule(3, true));
    assert!(work.exited(201));
    assert!(work.schedule(3, true));
    work.observe(4, false);
    work.observe(3, true); // A delayed scheduler snapshot must not regress state.
    assert_eq!(work.observed_generation, 4);
    assert!(!work.schedule(3, true));
    assert!(work.finish(3, true)); // Recovery cleared the old exit interest.
    assert!(!work.schedule(4, false));
    work.observe(5, true);
    assert!(work.schedule(5, true));
    work.observe(6, false);
    work.observe(7, true);
    assert!(!work.wait_for_exits(5)); // Old scan cannot reinstall its interest.
    assert_eq!(work.waiting_for_exits, Option::None);
    assert!(work.finish(5, false));
    assert!(work.schedule(7, true));
    crate::raw_log!("OOM dispatch tests PASS");
}
