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

#[derive(Clone)]
pub enum Priority {
    High,   // Always picked; may starve lower-priority jobs.
    Normal, // Normal jobs (most user jobs).
    Low,    // Low priority jobs. Will run eventually (unless high priority jobs starve the rest).
    Idle,   // Jobs for when there is nothing else to do. May never run.
}

pub type SchedulerJobFn = fn(&Weak<Thread>, u64);

fn empty_job(_: &Weak<Thread>, _: u64) {}

pub struct Job {
    job_fn: SchedulerJobFn,
    thread: Weak<Thread>,
    pub arg: u64,
    pub prio: Priority,
    pub cpu: uCpus, // uCpus::MAX => not set.
}

unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Default for Job {
    fn default() -> Self {
        Self {
            job_fn: empty_job,
            thread: Weak::default(),
            arg: 0,
            prio: Priority::Idle,
            cpu: uCpus::MAX,
        }
    }
}

impl Job {
    fn new_detached(job_fn: SchedulerJobFn, cpu: uCpus) -> Self {
        Job {
            job_fn,
            thread: Weak::default(),
            arg: 0,
            prio: Priority::Normal,
            cpu,
        }
    }

    pub fn new_with_arg(job_fn: SchedulerJobFn, arg: u64) -> Self {
        Job {
            job_fn,
            thread: Weak::default(),
            arg,
            prio: Priority::Normal,
            cpu: uCpus::MAX,
        }
    }

    pub fn new(job_fn: SchedulerJobFn, thread: &Thread) -> Self {
        Job {
            job_fn,
            thread: thread.get_weak(),
            arg: 0,
            prio: Priority::Normal,
            cpu: thread.get_cpu_affinity(),
        }
    }

    pub fn new_on_current_cpu(job_fn: SchedulerJobFn, thread: &Thread) -> Self {
        let affined_to = thread.get_cpu_affinity();
        if affined_to != uCpus::MAX {
            Job::new(job_fn, thread)
        } else {
            Job {
                job_fn,
                thread: thread.get_weak(),
                arg: 0,
                prio: Priority::Normal,
                cpu: crate::arch::current_cpu(),
            }
        }
    }

    fn run(&self) {
        (self.job_fn)(&self.thread, self.arg);
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

    normal_queue: SpinLock<VecDeque<Job>>,

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
            normal_queue: SpinLock::new(VecDeque::with_capacity(INITIAL_QUEUE_SIZE)),
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
        self.wake();
    }

    #[cfg(debug_assertions)]
    fn alive(&self) {
        let now = crate::arch::time::Instant::now().as_u64();
        self.last_alive_check.store(now, Ordering::Relaxed);
        let mut check = |_: uCpus, scheduler: &Scheduler| -> bool {
            let last_check = scheduler.last_alive_check.load(Ordering::Relaxed);
            if now > (last_check + 10_000_000_000) {
                scheduler.die();
                return true;
            }
            false
        };
        PERCPU_SCHEDULERS.for_each_cpu(&mut check);
    }

    fn sched_loop(&mut self) -> ! {
        use x86_64::instructions::interrupts;

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
            Ordering::Relaxed,
        );

        let mut last_system_time_update = now_tsc;

        loop {
            #[cfg(debug_assertions)]
            self.alive();

            self.wake.store(false, Ordering::Relaxed);

            if self.cpu == 0 {
                // TODO: should we do this more often? less often?
                let now_tsc = crate::arch::time::Instant::now().as_u64();
                if now_tsc - last_system_time_update > 1_000_000_000 {
                    last_system_time_update = now_tsc;
                    update_system_time();
                }
            }

            crate::uspace::process_wake_events(); // May add jobs to queues.

            curr_iteration += 1;

            if self.timer_irq_tick.swap(false, Ordering::Relaxed) {
                self.update_load(true);
            }

            // Round robit between queues.
            if curr_iteration % 3 == 0 {
                // Note: we cannot combine the two statements below into one, like this:
                //     if let Some(job) = self.normal_queue.lock().pop_front() {
                //         job.run();
                //         continue;
                //     }
                // because job.run() will be called with the lock held, leading
                // to a deadlock.
                let maybe_job = self.normal_queue.lock(line!()).pop_front();
                if let Some(job) = maybe_job {
                    job.run();
                    self.queue_length.fetch_sub(1, Ordering::Relaxed);
                    last_job_iter = curr_iteration;
                    continue;
                }
            }

            if curr_iteration % 3 == 1 {
                let maybe_job = { GLOBAL_READY_QUEUE_NORMAL.lock(102).pop_front() };
                if let Some(job) = maybe_job {
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
                self.idle.store(true, Ordering::Release);
                while !self.wake.load(Ordering::Relaxed) {
                    core::hint::spin_loop();
                }
                self.idle.store(false, Ordering::Release);
            } else {
                interrupts::disable();
                if self.wake.load(Ordering::Acquire) {
                    interrupts::enable();
                } else {
                    crate::xray::tracing::trace("scheduler hlt", 0, 0, 0);
                    crate::xray::stats::system_stats_ref().start_cpu_usage_kernel();
                    self.idle.store(true, Ordering::Release);
                    interrupts::enable_and_hlt();
                    self.idle.store(false, Ordering::Release);
                    crate::xray::stats::system_stats_ref().stop_cpu_usage_kernel();
                    crate::xray::tracing::trace("scheduler hlt wake", 0, 0, 0);
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

        PERCPU_TIMERS.set(Box::leak(Box::new(StaticPerCpu::new())));

        PERCPU_SCHEDULERS.set(Box::leak(Box::new(StaticPerCpu::new())));
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

        fn start_init(_: &Weak<Thread>, _: u64) {
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
        GLOBAL_READY_QUEUE_NORMAL.lock(line!()).push_back(job);
        let mut wake = |_: uCpus, scheduler: &Scheduler| -> bool {
            if scheduler.idle.load(Ordering::Acquire) {
                scheduler.wake();
                return true;
            }
            false
        };
        PERCPU_SCHEDULERS.for_each_cpu(&mut wake);
    } else {
        assert!(job.cpu < crate::arch::num_cpus());
        let scheduler = PERCPU_SCHEDULERS.get_for_cpu(job.cpu);
        scheduler.normal_queue.lock(line!()).push_back(job);
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

pub fn on_custom_irq(irq: u8) {
    // This is called from an IRQ context: don't do anything dangerous.
    SysObject::wake_irq(&USER_IRQ_WAITERS[(irq - crate::arch::irq::IRQ_CUSTOM_START) as usize]);
    local_wake();
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

// Note: may be called from IRQ. Always called, exactly once, when a timer IRQ happens:
// if the timer IRQ happens in the kernel context, on_timer_irq() is called
// from the IRQ handler directly; if the timer IRQ happens in the user context,
// the user thread is preempted and then on_timer_irq() is called when the
// context switches to the kernel (in syscall.rs).
pub fn on_timer_irq() {
    let scheduler = PERCPU_SCHEDULERS.get_per_cpu();
    scheduler.timer_irq_tick.store(true, Ordering::Relaxed);

    const SCHED_TICK_MILLIS: u64 = 20;
    let when =
        crate::arch::time::Instant::now() + core::time::Duration::from_millis(SCHED_TICK_MILLIS);

    // Unlike the conditional vs curr_timer in maybe_program_timer() below, we set the timer
    // unconditionally here, because on_timer_irq() is called from the irq, that is the current timer
    // has fired.
    crate::arch::irq::set_timer(when);
    *PERCPU_TIMERS.get_per_cpu() = when;

    scheduler.local_wake();
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
