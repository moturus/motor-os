// The scheduler.
//
// As the kernel supports wait/wake/swap, and no blocking in the kernel
// other than wait, any kind of more sophisticated scheduling policy
// can be implemented in the userspace (in theory; maybe tweaks are needed
// to make things perform well in practive).
//
// So the default scheduler here is rather simple, but should work
// for a lot of use cases.
//
// Priorities: see enum Priority
// Cpu affinity: a single CPU hint
// Sched groups: none: everything within a priority is round robin, so
// a process with many threads will negatively affect a process with few threads.
//
// This should be OK for most situations: if there is a need for isolation,
// just use another VM.

use crate::arch::current_cpu;
use crate::uspace::process::Thread;
use crate::uspace::SysObject;
use alloc::borrow::ToOwned;
use alloc::collections::VecDeque;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::*;

use alloc::boxed::Box;

use crate::arch::time::Instant;
use crate::config::uCpus;
use crate::util::StaticRef;
use crate::util::{SpinLock, StaticPerCpu};
use moto_sys::ErrorCode;

use super::timers::Timers;
use super::Timer;

const INITIAL_QUEUE_SIZE: usize = 64;

static PERCPU_SCHEDULERS: StaticRef<StaticPerCpu<Scheduler>> = StaticRef::default_const();
static USER_IRQ_WAITERS: StaticRef<alloc::vec::Vec<Arc<SysObject>>> = StaticRef::default_const();

// Currently set timers.
static PERCPU_TIMERS: StaticRef<StaticPerCpu<Instant>> = StaticRef::default_const();

static GLOBAL_READY_QUEUE_NORMAL: StaticRef<crate::util::SpinLock<VecDeque<Job>>> =
    StaticRef::default_const();

// The number of jobs in GLOBAL_READY_QUEUE_NORMAL, maintained on push/pop.
// Lets sched-loop iterations skip taking the global spinlock when the queue
// is empty (the common case): an unlocked read of a rarely-written line stays
// shared in all caches instead of bouncing the lock cacheline between CPUs.
static GLOBAL_QUEUE_LENGTH: AtomicU32 = AtomicU32::new(0);

// Raw TSC of the last update_system_time() call (BSP only). An atomic (not a
// sched_loop local) so the timer-IRQ fast path can tell when the BSP owes a
// housekeeping pass and must enter its sched loop instead of fast-returning.
static LAST_SYSTEM_TIME_UPDATE: AtomicU64 = AtomicU64::new(0);
const SYSTEM_TIME_UPDATE_TSC: u64 = 1_000_000_000;

/*
pub enum Priority {
    High,   // Always picked; may starve lower-priority jobs.
    Normal, // Normal jobs (most user jobs).
    Low,    // Low priority jobs. Will run eventually (unless high priority jobs starve the rest).
    Idle,   // Jobs for when there is nothing else to do. May never run.
}
*/

pub type SchedulerJobFn = fn(Weak<Thread>, u64);

pub struct Job {
    job_fn: SchedulerJobFn,
    thread: Weak<Thread>,
    pub arg: u64,
    pub cpu: uCpus, // uCpus::MAX => not set.
}

unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    fn new_detached(job_fn: SchedulerJobFn, cpu: uCpus) -> Self {
        Job {
            job_fn,
            thread: Weak::default(),
            arg: 0,
            cpu,
        }
    }

    pub fn new(job_fn: SchedulerJobFn, thread: Weak<Thread>, arg: u64, cpu: uCpus) -> Self {
        Job {
            job_fn,
            thread,
            arg,
            cpu,
        }
    }

    fn run(self) {
        let Self {
            job_fn,
            thread,
            arg,
            cpu: _,
        } = self;
        job_fn(thread, arg);
    }
}

// LocalAgent manages cooperative execution of jobs on a CPU.
struct Scheduler {
    cpu: uCpus, // The CPU of this queue. Never changes.

    // If a concurrent (a different CPU or an interrupt) wants to wake this scheduler,
    // it must set wake to true before sending the IPI or within the interrupt handler.
    wake: AtomicBool,

    queue_length: AtomicU32,
    idle: AtomicBool,

    local_queue: SpinLock<VecDeque<Job>>,

    timers: Timers,

    // Stats.
    load_tick: Instant,
    load_prev: AtomicU64,
    load_curr: u64,

    timer_irq_tick: AtomicBool,

    #[cfg(debug_assertions)]
    die_on_next_wake: AtomicBool,

    #[cfg(debug_assertions)]
    last_alive_check: AtomicU64,
}

impl Scheduler {
    const LOAD_PERIOD: u64 = 1u64 << 24; // Units are tscs on x64.

    fn new() -> Self {
        Scheduler {
            cpu: crate::arch::current_cpu(),
            wake: AtomicBool::new(false),
            queue_length: AtomicU32::new(0),
            idle: AtomicBool::new(false),
            local_queue: SpinLock::new(VecDeque::with_capacity(INITIAL_QUEUE_SIZE)),
            timers: Timers::new(),

            load_tick: Instant::now(),

            load_prev: AtomicU64::new(0),
            load_curr: 0,
            timer_irq_tick: AtomicBool::new(false),

            #[cfg(debug_assertions)]
            die_on_next_wake: AtomicBool::new(false),
            #[cfg(debug_assertions)]
            last_alive_check: AtomicU64::new(0),
        }
    }

    #[inline]
    fn update_load(&mut self, was_running: bool) {
        let now = Instant::now();
        assert!(self.load_tick <= now);
        if self.load_tick == now {
            return;
        }

        if (now.as_u64() - self.load_tick.as_u64()) > 24 * Self::LOAD_PERIOD {
            // The VM was preempted or sleeping.
            self.load_tick = now;
            self.load_prev.store(0, Ordering::Relaxed);
            self.load_curr = 0;
            return;
        }
        let mut load_prev = self.load_prev.load(Ordering::Relaxed);

        let mut iter = 0_u64;
        loop {
            iter += 1;
            if iter > 1_000 {
                // panic!("update_load looping");
                log::error!("update_load looping");
                return;
            }
            let period_end =
                (self.load_tick.as_u64() + Self::LOAD_PERIOD) & !(Self::LOAD_PERIOD - 1);
            if period_end > now.as_u64() {
                if was_running {
                    self.load_curr += now.as_u64() - self.load_tick.as_u64();
                }
                break;
            }

            let interval = self.load_curr
                + if was_running {
                    period_end - self.load_tick.as_u64()
                } else {
                    0
                };
            self.load_tick = Instant::from_u64(period_end);
            self.load_curr = 0;

            load_prev += interval;

            if self.load_tick == now {
                break;
            }
            load_prev >>= 1;
        }

        self.load_prev.store(load_prev, Ordering::Release);
        self.load_tick = now;
    }

    #[inline]
    fn idle_start(&mut self) {
        self.update_load(true);
    }

    #[inline]
    fn idle_stop(&mut self) {
        self.update_load(false);
    }

    fn load(&self) -> u64 {
        self.load_prev.load(Ordering::Acquire)
    }

    pub fn load_pct(&self) -> f32 {
        let load = self.load();
        if load > Self::LOAD_PERIOD {
            log::warn!("load overflow: 0x{:x} vs 0x{:x}", load, Self::LOAD_PERIOD);
            1.0
        } else {
            (load as f32) / (Self::LOAD_PERIOD as f32)
        }
    }

    fn wake(&self) {
        if self.cpu == crate::arch::current_cpu() {
            self.local_wake();
            return;
        }
        self.wake.store(true, Ordering::Release);
        crate::arch::irq::wake_remote_cpu(self.cpu); // Will send an IPI that will call local_wake().
    }

    fn local_wake(&self) {
        self.wake.store(true, Ordering::Release);

        #[cfg(debug_assertions)]
        if self.die_on_next_wake.load(Ordering::Acquire) {
            panic!("DEBUG DEATH.")
        }
    }

    #[cfg(debug_assertions)]
    fn die(&self) {
        self.die_on_next_wake.store(true, Ordering::Release);
        crate::arch::irq::wake_remote_cpu(self.cpu); // Will send an IPI that will call local_wake().
    }

    #[cfg(debug_assertions)]
    fn dying(&self) -> bool {
        self.die_on_next_wake.load(Ordering::Acquire)
    }

    #[cfg(debug_assertions)]
    fn alive(&self) {
        let now = crate::arch::time::Instant::now().as_u64();
        self.last_alive_check.store(now, Ordering::Release);

        let mut check = |cpu: uCpus, scheduler: &Scheduler| -> bool {
            if scheduler.idle.load(Ordering::Acquire) {
                // Idle CPUs quiesce completely (no timer ticks), so they may
                // legitimately not update last_alive_check for a long time.
                return false;
            }
            let last_check = scheduler.last_alive_check.load(Ordering::Acquire);
            if now > (last_check + 10_000_000_000) && !scheduler.dying() {
                log::error!(
                    "CPU {cpu} dead: now: {now}; last check: {last_check}; idle: {} OOPS.",
                    scheduler.idle.load(Ordering::Acquire)
                );
                crate::xray::tracing::dump();
                scheduler.die(); // Will print stack if can wake.
                true
            } else {
                false
            }
        };
        PERCPU_SCHEDULERS.for_each_cpu(&mut check);
    }

    // Called when this CPU is about to go idle: non-BSP CPUs quiesce
    // completely when idle, so arm the APIC timer for the earliest pending
    // software timer, or disarm it if there are none. The BSP is exempt:
    // it keeps its periodic tick to drive system time updates (and alive
    // checks in debug builds).
    //
    // Note: it is OK if a stale timer IRQ (one that became pending just
    // before the timer was reprogrammed here) wakes this CPU right up:
    // on_timer_irq() re-arms a tick, the sched loop runs, and the next call
    // here re-programs the timer from self.timers, the ground truth.
    // Over-waking is fine; sleeping through a deadline is not, and cannot
    // happen: PERCPU_TIMERS may only hold a future deadline if the hardware
    // timer is actually armed for it.
    fn program_idle_timer(&self) {
        if self.cpu == crate::arch::bsp() {
            return;
        }

        let percpu_timer = PERCPU_TIMERS.get_per_cpu();
        // Instant::nan() is raw TSC zero, and writing zero to the TSC-deadline
        // MSR disarms the timer, so set_timer(nan) means "no timer IRQs at all".
        let deadline = self.timers.next_deadline().unwrap_or(Instant::nan());
        if *percpu_timer != deadline {
            crate::arch::irq::set_timer(deadline);
            *percpu_timer = deadline;
        }
    }

    fn sched_loop(&mut self) -> ! {
        let nosleep = crate::config::get().nosleep;

        let mut curr_iteration = 0_u64;
        let mut last_job_iter = 0_u64;

        let now_tsc = crate::arch::time::Instant::now().as_u64();
        let percpu_stats = crate::xray::stats::kernel_stats_ref().get_percpu_stats_entry(self.cpu);
        percpu_stats.cpu_kernel.store(now_tsc, Ordering::Relaxed);
        percpu_stats.started_k.store(now_tsc, Ordering::Relaxed);

        #[cfg(debug_assertions)]
        self.last_alive_check.store(
            crate::arch::time::Instant::now().as_u64(),
            Ordering::Release,
        );

        LAST_SYSTEM_TIME_UPDATE.store(now_tsc, Ordering::Relaxed);

        loop {
            #[cfg(debug_assertions)]
            self.alive();

            self.wake.store(false, Ordering::Relaxed);

            if self.cpu == 0 {
                // TODO: should we do this more often? less often?
                let now_tsc = crate::arch::time::Instant::now().as_u64();
                if now_tsc - LAST_SYSTEM_TIME_UPDATE.load(Ordering::Relaxed)
                    > SYSTEM_TIME_UPDATE_TSC
                {
                    LAST_SYSTEM_TIME_UPDATE.store(now_tsc, Ordering::Relaxed);
                    update_system_time();
                }
            }

            crate::uspace::process_wake_events(); // May add jobs to queues.

            curr_iteration += 1;

            if self.timer_irq_tick.swap(false, Ordering::Relaxed) {
                self.update_load(true);
            }

            // Round robit between queues.
            //
            // Both queues are peeked via their (atomic) length counters before
            // taking the spinlock: other CPUs push to both queues, and locking
            // an empty queue on every iteration bounces the lock cacheline
            // across CPUs for nothing. A job pushed right after the peek is
            // not lost: the pusher either wakes this CPU (local queue) or
            // keeps polling itself (global queue), and the next iteration
            // sees the counter.
            if curr_iteration.is_multiple_of(3)
                && self.queue_length.load(Ordering::Acquire) != 0
            {
                // Note: we cannot combine the two statements below into one, like this:
                //     if let Some(job) = self.normal_queue.lock().pop_front() {
                //         job.run();
                //         continue;
                //     }
                // because job.run() will be called with the lock held, leading
                // to a deadlock.
                let maybe_job = self.local_queue.lock(line!()).pop_front();
                if let Some(job) = maybe_job {
                    self.queue_length.fetch_sub(1, Ordering::Relaxed);
                    job.run();
                    last_job_iter = curr_iteration;
                    continue;
                }
            }

            if curr_iteration % 3 == 1 && GLOBAL_QUEUE_LENGTH.load(Ordering::Acquire) != 0 {
                let maybe_job = { GLOBAL_READY_QUEUE_NORMAL.lock(line!()).pop_front() };
                if let Some(job) = maybe_job {
                    GLOBAL_QUEUE_LENGTH.fetch_sub(1, Ordering::Relaxed);
                    job.run();
                    last_job_iter = curr_iteration;
                    continue;
                }
            }

            if curr_iteration % 3 == 2 {
                let now = Instant::now();
                let mut timers_iter = 0_u64;
                loop {
                    timers_iter += 1;
                    if timers_iter > 1_000_000 {
                        panic!("timers_iter looping.");
                    }
                    match self.timers.pop(now) {
                        Ok(timer) => {
                            timer.job().run();
                            last_job_iter = curr_iteration;
                            continue;
                        }
                        Err(next) => {
                            maybe_program_timer(next);
                            break;
                        }
                    }
                }
            }

            // If HALT_POLLING_ITERS is very small (e.g. two), there are noticeable delays.
            const HALT_POLLING_ITERS: u64 = 5;
            if curr_iteration - last_job_iter < HALT_POLLING_ITERS {
                continue;
            }

            self.idle_start();
            if nosleep {
                self.program_idle_timer();
                self.idle.store(true, Ordering::Release);
                while !self.wake.load(Ordering::Relaxed) {
                    core::hint::spin_loop();
                }
                self.idle.store(false, Ordering::Release);
            } else {
                use x86_64::instructions::interrupts;

                interrupts::disable();
                if self.wake.load(Ordering::Acquire) {
                    interrupts::enable();
                } else {
                    self.idle.store(true, Ordering::Release);

                    // Check again.
                    if self.wake.load(Ordering::Acquire) {
                        interrupts::enable();
                        self.idle.store(false, Ordering::Release);
                    } else {
                        // Go to sleep. Interrupts are disabled, so the timer
                        // can be reprogrammed without racing on_timer_irq().
                        self.program_idle_timer();
                        crate::xray::tracing::trace("scheduler hlt", 0, 0, 0);
                        crate::xray::stats::system_stats_ref().start_cpu_usage_kernel();
                        interrupts::enable_and_hlt();
                        #[cfg(debug_assertions)]
                        self.last_alive_check.store(
                            crate::arch::time::Instant::now().as_u64(),
                            Ordering::Release,
                        );
                        self.idle.store(false, Ordering::Release);
                        crate::xray::stats::system_stats_ref().stop_cpu_usage_kernel();
                        crate::xray::tracing::trace("scheduler hlt wake", 0, 0, 0);
                    }
                }
            }
            self.idle_stop();
            curr_iteration = 0; // Prevent overflows.
            last_job_iter = curr_iteration; // Reset the interval.
        }
    }
}

pub fn start() -> ! {
    crate::util::full_fence();
    let cpu = crate::arch::current_cpu();
    assert_eq!(crate::arch::apic_cpu_id_32() as uCpus, cpu);

    if cpu == crate::arch::bsp() {
        let mut vec: Box<alloc::vec::Vec<Arc<SysObject>>> = Box::new(
            alloc::vec::Vec::with_capacity(crate::config::get().custom_irqs as usize),
        );
        for idx in 0..crate::config::get().custom_irqs {
            let mut url = "irq_wait:".to_owned();
            url.push_str(
                (idx + crate::arch::irq::IRQ_CUSTOM_START)
                    .to_string()
                    .as_str(),
            );
            vec.push(SysObject::new(Arc::new(url)));
        }
        USER_IRQ_WAITERS.set(Box::leak(vec));

        GLOBAL_READY_QUEUE_NORMAL.set(Box::leak(Box::new(crate::util::SpinLock::new(
            VecDeque::with_capacity(INITIAL_QUEUE_SIZE),
        ))));

        PERCPU_TIMERS.set(Box::leak(Box::new(StaticPerCpu::init())));

        PERCPU_SCHEDULERS.set(Box::leak(Box::new(StaticPerCpu::init())));
    } else {
        // Wait until BSP initializes SCHEDULERS.
        PERCPU_SCHEDULERS.spin_until_set();
    }

    PERCPU_TIMERS.set_per_cpu(Box::leak(Box::new(Instant::nan())));
    PERCPU_SCHEDULERS.set_per_cpu(Box::leak(Box::new(Scheduler::new())));

    if cpu == crate::arch::bsp() {
        PERCPU_SCHEDULERS.spin_until_all_set();

        core::sync::atomic::fence(Ordering::Acquire);
        {
            // Safe because we have proper memory fences around and are calling this after
            // the bootup has completed.
            let shared_page = crate::mm::virt::get_kernel_static_page_mut();
            shared_page.version = 0;
            shared_page.num_cpus = crate::arch::num_cpus() as u32;
            update_system_time();
        }
        core::sync::atomic::fence(Ordering::Release);

        fn start_init(_: Weak<Thread>, _: u64) {
            crate::init::start_userspace_processes();
        }

        post(Job::new_detached(start_init, cpu));
    }

    // Start the initial sched timer. Timer IRQ auto-restarts.
    on_timer_irq();

    let queue = PERCPU_SCHEDULERS.get_per_cpu();
    queue.sched_loop();
}

fn update_system_time() {
    let shared_page = crate::mm::virt::get_kernel_static_page_mut();
    crate::arch::time::populate_kernel_static_page(shared_page);
}

pub fn post(job: Job) {
    if job.cpu == uCpus::MAX {
        // Placement policy (W2): prefer the CPU the thread last ran on — its
        // caches are warm there, and without PCID a migration means a fully
        // cold TLB after the first CR3 load.
        //
        // Hand the job directly to an idle CPU if there is one (pushing it to
        // the global queue and waking an idle CPU is racy: any CPU may pop the
        // job, and in a request-response lockstep between two processes the
        // poster's CPU always wins, so both processes end up sharing one CPU
        // while the woken CPU finds the queue empty and goes back to sleep),
        // scanning from last_cpu so the home CPU wins ties.
        //
        // If nothing is idle the job MUST go to the global queue: it is the
        // only stealable place. Queueing it on last_cpu instead (tried, badly
        // regressed) is not work-conserving — a CPU that goes idle a moment
        // after the scan can never steal from another CPU's local queue, so
        // convoys form on one CPU (one 10ms tick per queued thread) while
        // the rest of the machine sleeps; RR latency went 0.2ms -> 55ms.
        let hint = job.thread.upgrade().and_then(|t| t.last_cpu());
        let num_cpus = crate::arch::num_cpus() as usize;
        let start = hint.unwrap_or(0) as usize;
        for i in 0..num_cpus {
            let cpu = ((start + i) % num_cpus) as uCpus;
            let scheduler = PERCPU_SCHEDULERS.get_for_cpu(cpu);
            if scheduler.idle.load(Ordering::Acquire) {
                scheduler.local_queue.lock(line!()).push_back(job);
                scheduler.queue_length.fetch_add(1, Ordering::Relaxed);
                scheduler.wake();
                crate::xray::stats::kernel_stats().adjust_metric(
                    if hint == Some(cpu) {
                        crate::xray::stats::MetricType::PlacementHintIdle
                    } else {
                        crate::xray::stats::MetricType::PlacementOtherIdle
                    },
                    1,
                );
                return;
            }
        }

        // No idle CPUs: post to the global queue. It's OK that nobody is
        // woken, because _this_ cpu, the cpu on which this code is currently
        // running, is not sleeping and will eventually pop the job.
        GLOBAL_READY_QUEUE_NORMAL.lock(line!()).push_back(job);
        GLOBAL_QUEUE_LENGTH.fetch_add(1, Ordering::Release);
        crate::xray::stats::kernel_stats()
            .adjust_metric(crate::xray::stats::MetricType::PlacementQueueGlobal, 1);
    } else {
        assert!(job.cpu < crate::arch::num_cpus());
        let scheduler = PERCPU_SCHEDULERS.get_for_cpu(job.cpu);
        scheduler.local_queue.lock(line!()).push_back(job);
        scheduler.queue_length.fetch_add(1, Ordering::Relaxed);
        scheduler.wake();
    }
}

pub fn post_timer(timer: Timer) {
    let when = timer.when();

    debug_assert_eq!(timer.cpu(), current_cpu());

    // Timers are per-cpu, so that wait/timeout are serialized; otherwise
    // races may happen (e.g. in yield()) that need careful resolution, but why?
    let scheduler = PERCPU_SCHEDULERS.get_for_cpu(timer.cpu());

    scheduler.timers.add_timer(timer);
    maybe_program_timer(when);
    scheduler.wake();
}

pub fn cancel_timer(timer_id: u64, cpu: uCpus) {
    PERCPU_SCHEDULERS
        .get_for_cpu(cpu)
        .timers
        .remove_timer(timer_id);
}

// Called by IRQ.
pub fn local_wake() {
    PERCPU_SCHEDULERS.get_per_cpu().local_wake();
}

// Queues the SysObject wake for a userspace IRQ waiter. Unlike the wake
// itself, what happens to the interrupted context is the caller's decision:
// fast-return, or local_wake() + preempt (see irq_wake_fast_path_ok()).
pub fn queue_custom_irq_wake(irq: u8) {
    // This is called from an IRQ context: don't do anything dangerous.
    SysObject::wake_irq(&USER_IRQ_WAITERS[(irq - crate::arch::irq::IRQ_CUSTOM_START) as usize]);
}

pub fn get_irq_wait_handle(
    process: &crate::uspace::process::Process,
    irq: u8,
) -> Result<Arc<SysObject>, ErrorCode> {
    // Only the IO Manager can wait on IRQs.
    if process.capabilities() & moto_sys::caps::CAP_IO_MANAGER == 0 {
        return Err(moto_rt::E_NOT_ALLOWED);
    }

    if irq < crate::arch::irq::IRQ_CUSTOM_START {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let idx = irq - crate::arch::irq::IRQ_CUSTOM_START;
    if idx >= crate::config::get().custom_irqs {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    Ok(USER_IRQ_WAITERS[idx as usize].clone())
}

const SCHED_TICK_MILLIS: u64 = 10;

// Note: may be called from IRQ. Always called, exactly once, when a timer IRQ happens:
// if the timer IRQ happens in the kernel context, on_timer_irq() is called
// from the IRQ handler directly; if the timer IRQ happens in the user context,
// the user thread is preempted and then on_timer_irq() is called when the
// context switches to the kernel (in syscall.rs).
pub fn on_timer_irq() {
    let scheduler = PERCPU_SCHEDULERS.get_per_cpu();
    scheduler.timer_irq_tick.store(true, Ordering::Relaxed);

    let when =
        crate::arch::time::Instant::now() + core::time::Duration::from_millis(SCHED_TICK_MILLIS);

    // Unlike the conditional vs curr_timer in maybe_program_timer() below, we set the timer
    // unconditionally here, because on_timer_irq() is called from the irq, that is the current timer
    // has fired.
    //
    // Re-arming here (rather than only when userspace work is present) is what
    // guarantees preemption: a thread in user mode always has a live deadline
    // armed, because the chain can only be broken in program_idle_timer(),
    // when no thread is on this CPU. If the tick fired mid-syscall, this
    // re-arm is what the thread returns to userspace with.
    crate::arch::irq::set_timer(when);
    *PERCPU_TIMERS.get_per_cpu() = when;

    scheduler.local_wake();
}

// Called before (re)entering userspace: makes sure the preemption tick is
// armed. It may be disarmed (non-BSP CPUs kill the tick chain when they go
// idle, see program_idle_timer()), or armed for a software timer too far in
// the future to bound this thread's timeslice. In the common case (the armed
// deadline is at most a tick away) this costs a load and rdtsc, no wrmsr.
pub fn ensure_preemption_timer() {
    let percpu_timer = PERCPU_TIMERS.get_per_cpu();
    let curr = *percpu_timer;
    let deadline =
        crate::arch::time::Instant::now() + core::time::Duration::from_millis(SCHED_TICK_MILLIS);
    if curr.is_nan() || curr > deadline {
        crate::arch::irq::set_timer(deadline);
        *percpu_timer = deadline;
    }
}

// ---- IRQ fast-return (W1, scheduler-work.md). Everything below is called
// ---- from IRQ context and must be lock-free.

// True if the timer IRQ that interrupted a userspace thread may return
// straight to it: nothing is runnable on this CPU, no software timer is due,
// and no BSP housekeeping is owed. The caller must re-arm the tick via
// rearm_tick_from_irq() before returning to userspace (Round 0 invariant:
// thread in user mode => live deadline armed).
pub fn timer_irq_fast_path_ok() -> bool {
    let scheduler = PERCPU_SCHEDULERS.get_per_cpu();

    // A pending wake means someone posted work for this CPU, or a kill /
    // debugger-pause poked it: enter the scheduler.
    if scheduler.wake.load(Ordering::Acquire) {
        return false;
    }
    if scheduler.queue_length.load(Ordering::Acquire) != 0 {
        return false;
    }
    if GLOBAL_QUEUE_LENGTH.load(Ordering::Acquire) != 0 {
        return false;
    }
    let now = crate::arch::time::Instant::now().as_u64();
    // A software timer on this CPU is due: the sched loop must pop it.
    if scheduler.timers.next_deadline_tsc() <= now {
        return false;
    }
    // The BSP updates system time from its sched loop about once a second;
    // don't starve that (or, in debug builds, the watchdog's alive() scan).
    if scheduler.cpu == 0
        && now - LAST_SYSTEM_TIME_UPDATE.load(Ordering::Relaxed) > 3 * SYSTEM_TIME_UPDATE_TSC
    {
        return false;
    }
    true
}

// Re-arms the preemption timer from the timer-IRQ fast path: the earliest
// pending software timer, or the next tick, whichever is sooner. Unlike
// on_timer_irq() this does NOT set the wake flag - doing so would make the
// next tick preempt, halving the fast path.
pub fn rearm_tick_from_irq() {
    let scheduler = PERCPU_SCHEDULERS.get_per_cpu();
    scheduler.timer_irq_tick.store(true, Ordering::Relaxed);

    let tick =
        crate::arch::time::Instant::now() + core::time::Duration::from_millis(SCHED_TICK_MILLIS);
    // Without the sched loop's maybe_program_timer() pass, an armed-early
    // software deadline must be preserved here, or a wait-timeout could
    // silently stretch to the next tick.
    let soft_tsc = scheduler.timers.next_deadline_tsc();
    let when = if soft_tsc < tick.as_u64() {
        Instant::from_u64(soft_tsc)
    } else {
        tick
    };
    crate::arch::irq::set_timer(when);
    *PERCPU_TIMERS.get_per_cpu() = when;

    // The debug watchdog tracks liveness via sched-loop iterations; a CPU
    // fast-returning for a long time is alive but never iterates.
    #[cfg(debug_assertions)]
    scheduler
        .last_alive_check
        .store(Instant::now().as_u64(), Ordering::Release);
}

// After a device IRQ queued its wake, decides whether the interrupted
// userspace thread may keep this CPU: only if nothing else is runnable here
// AND an idle CPU exists to process the wake queue promptly - that CPU is
// woken here. Otherwise the caller preempts, and this CPU's sched loop
// drains the wake queue itself.
pub fn irq_wake_fast_path_ok() -> bool {
    let scheduler = PERCPU_SCHEDULERS.get_per_cpu();
    if scheduler.wake.load(Ordering::Acquire) {
        return false;
    }
    if scheduler.queue_length.load(Ordering::Acquire) != 0 {
        return false;
    }
    if GLOBAL_QUEUE_LENGTH.load(Ordering::Acquire) != 0 {
        return false;
    }

    let mut woken = false;
    let mut wake_idle = |_cpu: uCpus, sched: &Scheduler| -> bool {
        if sched.idle.load(Ordering::Acquire) {
            sched.wake();
            woken = true;
            true
        } else {
            false
        }
    };
    PERCPU_SCHEDULERS.for_each_cpu(&mut wake_idle);
    woken
}

// Wakes a CPU's scheduler so its next tick preempts whatever userspace
// thread runs there. Used by the kill and debugger-pause paths: they set
// state that a running thread only notices when it passes through the
// scheduler, and with IRQ fast-return a busy thread on an otherwise empty
// CPU never enters the kernel on its own.
pub fn poke_cpu(cpu: u32) {
    if (cpu as usize) < (crate::arch::num_cpus() as usize) {
        PERCPU_SCHEDULERS.get_for_cpu(cpu as uCpus).wake();
    }
}

pub fn poke_all_cpus() {
    let mut poke = |_cpu: uCpus, sched: &Scheduler| -> bool {
        sched.wake();
        false
    };
    PERCPU_SCHEDULERS.for_each_cpu(&mut poke);
}

fn maybe_program_timer(when: Instant) {
    if when.is_nan() {
        return;
    }
    if when <= Instant::now() {
        local_wake();
        return;
    }
    let percpu_timer = PERCPU_TIMERS.get_per_cpu();
    let curr_timer = *percpu_timer;
    if curr_timer.is_nan() || curr_timer > when {
        crate::arch::irq::set_timer(when);
        *percpu_timer = when;
    }
}

pub fn get_usage(buf: &mut [f32]) {
    let num_cpus = crate::arch::num_cpus() as usize;
    assert_eq!(buf.len(), num_cpus);

    #[allow(clippy::needless_range_loop)]
    for cpu in 0..num_cpus {
        let scheduler = PERCPU_SCHEDULERS.get_for_cpu(cpu as uCpus);
        buf[cpu] = scheduler.load_pct();
    }
}

#[cfg(debug_assertions)]
pub fn print_stack_trace_and_die(cpu: uCpus) {
    PERCPU_SCHEDULERS.get_for_cpu(cpu).die()
}
