// This is THE place to keep stats, so that they are not spread around
// the kernel but are all in one place (here).

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::arch::current_cpu;
use crate::arch::num_cpus;
use crate::config::uCpus;
use crate::mm::PAGE_SIZE_SMALL_LOG2;
use crate::uspace::process::ProcessId;
use crate::util::SpinLock;
use crate::util::StaticRef;
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::sync::Weak;

use moto_sys::stats::*;

/// The kernel's metric catalog and the source of truth for its metric set.
/// `repr(u32)` so the discriminant is the metric's stable wire id (emitted
/// directly into `MetricEntry::metric` / `MetricDescWire`).
///
/// This lives in the kernel — not moto-sys — because it drives the per-cpu
/// counter array (`adjust_metric`/`get_metric`). Userspace never references it:
/// it discovers metric ids and names dynamically via the SysRay describe op, so
/// new metrics can be added here without recompiling any consumer.
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum MetricType {
    /// Memory usage in bytes.
    MemoryUsage = 0,
    /// CPU usage in tsc.
    CpuUsage = 1,

    ThreadsCreated = 2,
    ActiveThreads = 3,

    /// Total SysMem calls.
    SysMemCalls = 4,
    /// Memory allocations.
    SysMemMaps = 5,
    /// Memory deallocations.
    SysMemUnmaps = 6,

    /// Total SysCpu calls.
    SysCpuCalls = 7,
    /// SysCpu::wait() calls.
    SysCpuWaits = 8,
    /// SysCpu::wake() calls.
    SysCpuWakes = 9,

    /// Total SysObj calls.
    SysObjCalls = 10,
    /// Active system objects.
    SysObjects = 11,
    /// Active shared objects.
    SharedObjects = 12,
    /// Total objects created.
    TotalObjects = 13,

    /// Total SysRay calls.
    SysRayCalls = 14,

    TlbInvp = 15,

    IrqFired = 16, // Total.
    IrqTimerFired = 17,
    IrqWakeupFired = 18,
    IrqTlbShootdownFired = 19,
    IrqPfFired = 20,

    IrqCustom0Fired = 21,
    IrqCustom1Fired = 22,
    IrqCustom2Fired = 23,
    IrqCustom3Fired = 24,
    IrqCustom4Fired = 25,
    IrqCustom5Fired = 26,
    IrqCustom6Fired = 27,
    IrqCustom7Fired = 28,

    // Per-process stats sourced from dedicated KProcessStats fields (the same
    // ones `sysbox ps` reports).
    TotalChildren = 29,
    ActiveChildren = 30,
    PagesUser = 31,
    PagesKernel = 32,

    // System-wide memory metrics, reported only at the PID_SYSTEM scope.
    MemAvailable = 33,
    MemUsed = 34,
    MemHeapTotal = 35,
    MemUsedPages = 36,

    // IRQ fast-return (W1): userspace interrupts that returned straight to
    // the interrupted thread vs those that preempted it.
    IrqFastReturnTimer = 37,
    IrqFastReturnWake = 38,
    IrqPreemptTimer = 39,
    IrqPreemptWake = 40,

    // Job placement (W2): where unaffined resume/wake jobs landed.
    PlacementHintIdle = 41,    // The thread's last CPU was idle (best case).
    PlacementOtherIdle = 42,   // Migrated to some other idle CPU.
    PlacementQueueGlobal = 43, // No idle CPU: global queue (stealable).

    // sys_wait (W5): waits that returned pending wakes without descheduling
    // vs waits that paused. (IO-manager non-blocking polls count as
    // WaitFastPath only when they had pending wakes.)
    WaitFastPath = 44,
    WaitPaused = 45,

    // Swap waits (W7): F_SWAP_TARGET handoffs that context-switched
    // directly to the wakee vs falling back to the queue path (wakee not
    // InWait, object already woken, etc.).
    DirectSwitch = 46,
    DirectSwitchMiss = 47,

    // User-copy engagement (S2/W6b part 2 gate): syscall-path copies
    // between user and kernel memory (read_from_user_into/copy_to_user,
    // including the loader's writes into a child's address space).
    UserCopyRead = 48,
    UserCopyReadBytes = 49,
    UserCopyWrite = 50,
    UserCopyWriteBytes = 51,

    // Count of user allocations refused by the soft-OOM reserve
    // (mm::oom_for_user returning true): the small-page pool came within the
    // system reserve of empty and a user stack/heap/process allocation was
    // denied with E_OUT_OF_MEMORY. System-wide, reported at PID_SYSTEM.
    SoftOomUser = 52,

    // Count of TLB-shootdown waits that spun past the 1e9 "slow" mark before
    // the peer acked (arch::tlb) -- almost always a peer vCPU the host
    // descheduled long enough to notice. System-wide, reported at PID_SYSTEM.
    TlbShootdownSlow = 53,

    TotalMetricTypes = 54,
}

impl MetricType {
    pub fn from_custom_irq(irq_num: u8) -> Self {
        // Only 8 custom vectors have dedicated metrics; index 8 would
        // silently transmute into TotalChildren.
        assert!(irq_num < 8);
        // SAFETY: safe by construction.
        unsafe { core::mem::transmute(Self::IrqCustom0Fired as u32 + (irq_num as u32)) }
    }

    pub fn from_idx(idx: usize) -> Self {
        assert!(idx < Self::TotalMetricTypes as usize);
        // SAFETY: safe by construction (repr(u32), idx in range).
        unsafe { core::mem::transmute(idx as u32) }
    }

    /// A stable, machine-friendly name for this metric (the federated-stats
    /// "name at the edge"). The kernel ships these over the SysRay describe op,
    /// so tools never hardcode the metric set.
    pub fn name(&self) -> &'static str {
        match self {
            MetricType::MemoryUsage => "memory_usage",
            MetricType::CpuUsage => "cpu_usage",
            MetricType::ThreadsCreated => "threads_created",
            MetricType::ActiveThreads => "active_threads",
            MetricType::SysMemCalls => "sys_mem_calls",
            MetricType::SysMemMaps => "sys_mem_maps",
            MetricType::SysMemUnmaps => "sys_mem_unmaps",
            MetricType::SysCpuCalls => "sys_cpu_calls",
            MetricType::SysCpuWaits => "sys_cpu_waits",
            MetricType::SysCpuWakes => "sys_cpu_wakes",
            MetricType::SysObjCalls => "sys_obj_calls",
            MetricType::SysObjects => "sys_objects",
            MetricType::SharedObjects => "shared_objects",
            MetricType::TotalObjects => "total_objects",
            MetricType::SysRayCalls => "sys_ray_calls",
            MetricType::TlbInvp => "tlb_invp",
            MetricType::IrqFired => "irq_fired",
            MetricType::IrqTimerFired => "irq_timer_fired",
            MetricType::IrqWakeupFired => "irq_wakeup_fired",
            MetricType::IrqTlbShootdownFired => "irq_tlb_shootdown_fired",
            MetricType::IrqPfFired => "irq_pf_fired",
            MetricType::IrqCustom0Fired => "irq_custom0_fired",
            MetricType::IrqCustom1Fired => "irq_custom1_fired",
            MetricType::IrqCustom2Fired => "irq_custom2_fired",
            MetricType::IrqCustom3Fired => "irq_custom3_fired",
            MetricType::IrqCustom4Fired => "irq_custom4_fired",
            MetricType::IrqCustom5Fired => "irq_custom5_fired",
            MetricType::IrqCustom6Fired => "irq_custom6_fired",
            MetricType::IrqCustom7Fired => "irq_custom7_fired",
            MetricType::TotalChildren => "total_children",
            MetricType::ActiveChildren => "active_children",
            MetricType::PagesUser => "pages_user",
            MetricType::PagesKernel => "pages_kernel",
            MetricType::MemAvailable => "mem.available",
            MetricType::MemUsed => "mem.used",
            MetricType::MemHeapTotal => "mem.heap_total",
            MetricType::MemUsedPages => "mem.used_pages",
            MetricType::IrqFastReturnTimer => "irq_fast_return_timer",
            MetricType::IrqFastReturnWake => "irq_fast_return_wake",
            MetricType::IrqPreemptTimer => "irq_preempt_timer",
            MetricType::IrqPreemptWake => "irq_preempt_wake",
            MetricType::PlacementHintIdle => "placement_hint_idle",
            MetricType::PlacementOtherIdle => "placement_other_idle",
            MetricType::PlacementQueueGlobal => "placement_queue_global",
            MetricType::WaitFastPath => "wait_fast_path",
            MetricType::WaitPaused => "wait_paused",
            MetricType::DirectSwitch => "direct_switch",
            MetricType::DirectSwitchMiss => "direct_switch_miss",
            MetricType::UserCopyRead => "user_copy_read",
            MetricType::UserCopyReadBytes => "user_copy_read_bytes",
            MetricType::UserCopyWrite => "user_copy_write",
            MetricType::UserCopyWriteBytes => "user_copy_write_bytes",
            MetricType::SoftOomUser => "mem.soft_oom_user",
            MetricType::TlbShootdownSlow => "cpu.tlb_shootdown_slow",
            MetricType::TotalMetricTypes => "total_metric_types",
        }
    }
}

#[derive(Debug)]
pub struct MemStats {
    pages_used: AtomicU64,
    user_stats: bool,
}

impl Drop for MemStats {
    fn drop(&mut self) {
        // assert_eq!(0, self.total());
        if self.total() != 0 {
            log::error!("Non-empty MemStats dropped: {self:?}.");
        }
    }
}

impl MemStats {
    const fn new(user_stats: bool) -> Self {
        Self {
            pages_used: AtomicU64::new(0),
            user_stats,
        }
    }

    pub const fn new_user() -> Self {
        Self::new(true)
    }

    pub const fn new_kernel() -> Self {
        Self::new(false)
    }

    pub fn total(&self) -> u64 {
        self.pages_used.load(Ordering::Relaxed) << PAGE_SIZE_SMALL_LOG2
    }

    pub fn add(&self, num_pages: u64) {
        self.add_simple(num_pages);

        if self.user_stats {
            SYSTEM_STATS.mem_stats_user.add_simple(num_pages);
        } else if core::intrinsics::likely(SYSTEM_STATS.is_set()) {
            SYSTEM_STATS.mem_stats_kernel.add_simple(num_pages);
        }
    }

    #[inline]
    fn add_simple(&self, num_pages: u64) {
        self.pages_used.fetch_add(num_pages, Ordering::Relaxed);
    }

    pub fn sub(&self, num_pages: u64) {
        self.sub_simple(num_pages);

        if self.user_stats {
            SYSTEM_STATS.mem_stats_user.sub_simple(num_pages);
        } else if core::intrinsics::likely(SYSTEM_STATS.is_set()) {
            SYSTEM_STATS.mem_stats_kernel.sub_simple(num_pages);
        }
    }

    #[inline]
    fn sub_simple(&self, num_pages: u64) {
        self.pages_used.fetch_sub(num_pages, Ordering::Relaxed);
    }
}

const PCPU_STATS_CNT: usize = 60; // struct is 8 * (N + 4) bytes; see the size assert below.

#[repr(C, align(64))]
pub struct PerCpuStatsEntry {
    pub cpu_kernel: AtomicU64, // as TSC
    pub cpu_uspace: AtomicU64, // as TSC
    pub started_k: AtomicU64,  // if running, indicates when cpu_kernel started, otherwise zero
    pub started_u: AtomicU64,  // if running, indicates when cpu_uspace started, otherwise zero
    metrics: [AtomicU64; PCPU_STATS_CNT],
}

const _: () = assert!(PCPU_STATS_CNT >= MetricType::TotalMetricTypes as usize);

const _: () = assert!(512 == core::mem::size_of::<PerCpuStatsEntry>()); // 64 * 8

impl PerCpuStatsEntry {
    const fn new() -> Self {
        Self {
            cpu_uspace: AtomicU64::new(0),
            cpu_kernel: AtomicU64::new(0),
            started_k: AtomicU64::new(0),
            started_u: AtomicU64::new(0),
            metrics: [const { AtomicU64::new(0) }; PCPU_STATS_CNT],
        }
    }

    fn usage_kernel(&self, now: u64) -> u64 {
        let started_k = self.started_k.load(Ordering::Relaxed);
        let cpu_kernel = self.cpu_kernel.load(Ordering::Relaxed);
        if started_k > 0 && now > started_k {
            cpu_kernel + now - started_k
        } else {
            cpu_kernel
        }
    }

    fn usage_uspace(&self, now: u64) -> u64 {
        let started_u = self.started_u.load(Ordering::Relaxed);
        let cpu_uspace = self.cpu_uspace.load(Ordering::Relaxed);
        if started_u > 0 && now > started_u {
            cpu_uspace + now - started_u
        } else {
            cpu_uspace
        }
    }
}

pub struct PerCpuStats {
    data: alloc::vec::Vec<PerCpuStatsEntry>,
}

impl PerCpuStats {
    fn new() -> Self {
        let mut data = alloc::vec::Vec::new();
        data.reserve_exact(num_cpus() as usize);
        for _ in 0..num_cpus() {
            data.push(PerCpuStatsEntry::new());
        }

        Self { data }
    }

    fn get_metric(&self, metric_idx: usize) -> u64 {
        let mut result = 0;
        for cpu in 0..num_cpus() {
            result += self.data[cpu as usize].metrics[metric_idx].load(Ordering::Relaxed);
        }

        result
    }
}

pub struct CpuUsageScopeKernel {
    stats: Arc<KProcessStats>,
}

impl Drop for CpuUsageScopeKernel {
    fn drop(&mut self) {
        self.stats.stop_cpu_usage_kernel()
    }
}

// Process stats are held in a tree.
pub struct KProcessStats {
    pid: ProcessId,
    debug_name: String,
    total_threads: AtomicU64,
    active_threads: AtomicU64,
    parent: Option<Arc<KProcessStats>>,
    total_children: AtomicU64,
    active_children: AtomicU64,
    children: SpinLock<BTreeMap<ProcessId, Weak<KProcessStats>>>,
    active: AtomicBool,
    detached: bool,

    mem_stats_user: Arc<MemStats>,
    mem_stats_kernel: Arc<MemStats>,
    pub owner: Weak<crate::uspace::Process>,

    per_cpu_stats: PerCpuStats,
}

impl Drop for KProcessStats {
    fn drop(&mut self) {
        if let Some(parent) = self.parent.as_ref() {
            assert!(parent.children.lock(line!()).remove(&self.pid).is_some());
        } else {
            panic!("impossible");
        }
        assert!(SYSTEM_STATS
            .children
            .lock(line!())
            .remove(&self.pid)
            .is_some());
    }
}

impl KProcessStats {
    pub fn new(
        parent: Arc<KProcessStats>,
        pid: ProcessId,
        debug_name: String,
        detached: bool,
        mem_stats_user: Arc<MemStats>,
        mem_stats_kernel: Arc<MemStats>,
        owner: Weak<crate::uspace::Process>,
    ) -> Arc<Self> {
        Self::new_impl(
            Some(parent),
            pid,
            debug_name,
            detached,
            mem_stats_user,
            mem_stats_kernel,
            owner,
        )
    }

    fn new_impl(
        parent: Option<Arc<KProcessStats>>,
        pid: ProcessId,
        debug_name: String,
        detached: bool,
        mem_stats_user: Arc<MemStats>,
        mem_stats_kernel: Arc<MemStats>,
        owner: Weak<crate::uspace::Process>,
    ) -> Arc<Self> {
        let self_ = Arc::new(Self {
            pid,
            debug_name,
            total_threads: AtomicU64::new(0),
            active_threads: AtomicU64::new(0),
            parent,
            total_children: AtomicU64::new(0),
            active_children: AtomicU64::new(0),
            children: SpinLock::new(BTreeMap::new()),
            active: AtomicBool::new(true),
            detached,
            mem_stats_user,
            mem_stats_kernel,
            owner,
            per_cpu_stats: PerCpuStats::new(),
        });

        match self_.parent.as_ref() {
            Some(parent) => {
                assert!(parent
                    .children
                    .lock(line!())
                    .insert(self_.pid, Arc::downgrade(&self_))
                    .is_none());
                parent.total_children.fetch_add(1, Ordering::Relaxed);
                parent.active_children.fetch_add(1, Ordering::Relaxed);
            }
            None => assert_eq!(self_.pid.as_u64(), PID_SYSTEM),
        }

        if self_.pid.as_u64() > PID_KERNEL {
            // This is a userspace process.
            assert!(SYSTEM_STATS
                .children
                .lock(line!())
                .insert(self_.pid, Arc::downgrade(&self_))
                .is_none());
            SYSTEM_STATS.total_children.fetch_add(1, Ordering::Relaxed);
            SYSTEM_STATS.active_children.fetch_add(1, Ordering::Relaxed);
        }

        self_
    }

    pub fn process_dropped(&self) {
        if self.active_threads() != 0 {
            // This has triggered a couple of times.
            log::error!(
                "stats: process dropped with {} active threads.",
                self.active_threads()
            );
        }

        if let Some(parent) = self.parent.as_ref() {
            parent.active_children.fetch_sub(1, Ordering::Relaxed);
            SYSTEM_STATS.active_children.fetch_sub(1, Ordering::Relaxed);
        } else {
            panic!("impossible");
        }
        self.active.store(false, Ordering::Relaxed);

        // Kill child processes. Do it asynchronously to avoid stack overflow.
        // Do it here because this is the only place where child processes
        // are tracked.
        //
        // Detached children are the exception: they are owned by the kernel and
        // outlive us on purpose (CAP_SPAWN_DETACHED), so they are left running.
        let children = self.children.lock(line!());
        for (pid, weak) in children.iter() {
            if let Some(child) = weak.upgrade() {
                if child.detached {
                    continue;
                }
            }
            crate::uspace::process::post_kill_by_pid(pid.as_u64());
        }
    }

    pub fn active_threads(&self) -> u64 {
        self.active_threads.load(Ordering::Relaxed)
    }

    pub fn debug_name(&self) -> &str {
        self.debug_name.as_str()
    }

    pub fn parent(&self) -> Option<Arc<KProcessStats>> {
        self.parent.clone()
    }

    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    pub fn on_thread_added(&self) {
        self.active_threads.fetch_add(1, Ordering::Relaxed);
        self.total_threads.fetch_add(1, Ordering::Relaxed);
        SYSTEM_STATS.active_threads.fetch_add(1, Ordering::Relaxed);
        SYSTEM_STATS.total_threads.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_thread_exited(&self) {
        self.active_threads.fetch_sub(1, Ordering::Relaxed);
        SYSTEM_STATS.active_threads.fetch_sub(1, Ordering::Relaxed);
    }

    /// Snapshot the process's identity into `dest`. Counters and measurements
    /// are intentionally NOT here — they are the kernel's `MetricType` catalog,
    /// fetched per process via the federated query ([`collect_metrics`]).
    ///
    /// [`collect_metrics`]: KProcessStats::collect_metrics
    pub fn into_v1(&self, dest: &mut ProcessInfoV1) {
        dest.pid = self.pid.as_u64();
        dest.parent_pid = self.parent.as_ref().map_or(0, |p| p.pid.as_u64());

        dest.system_process = 0;
        if let Some(proc) = self.owner.upgrade() {
            if proc.capabilities() & moto_sys::caps::CAP_SYS != 0 {
                dest.system_process = 1
            }
        };

        let debug_name = if self.debug_name.len() > 32 {
            &self.debug_name.as_bytes()[0..32]
        } else {
            self.debug_name.as_bytes()
        };
        unsafe {
            core::intrinsics::copy_nonoverlapping(
                debug_name.as_ptr(),
                dest.debug_name_bytes.as_mut_ptr(),
                debug_name.len(),
            );
        }
        dest.debug_name_len = debug_name.len() as u8;

        dest.active = if self.active.load(Ordering::Relaxed) {
            1
        } else {
            0
        };
    }

    /// Emit a `MetricEntry` for every metric this process exposes, at `scope`.
    /// This — not `ProcessStatsV1` — is the federated-stats source of truth, so
    /// the metric set can grow without touching any shared wire struct. Per-cpu
    /// counters come from the per-cpu array; per-process stats (cpu/memory/
    /// threads/children) from dedicated atomics; system-wide memory metrics are
    /// filled only for the `PID_SYSTEM` aggregate.
    pub fn collect_metrics(&self, scope: u64, now: u64, out: &mut alloc::vec::Vec<MetricEntry>) {
        let n = MetricType::TotalMetricTypes as usize;
        let mut vals = alloc::vec![0u64; n];

        // Per-cpu counters (SysMem*/SysCpu*/Irq*), straight from the array.
        #[allow(clippy::needless_range_loop)]
        for idx in 0..n {
            vals[idx] = self.per_cpu_stats.get_metric(idx);
        }

        // Per-process stats held in dedicated atomics override their slots.
        let small_log2 = moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2;
        let pages_user = self.mem_stats_user.pages_used.load(Ordering::Relaxed);
        let pages_kernel = self.mem_stats_kernel.pages_used.load(Ordering::Relaxed);
        vals[MetricType::CpuUsage as usize] = self.cpu_usage(now);
        vals[MetricType::MemoryUsage as usize] = (pages_user + pages_kernel) << small_log2;
        vals[MetricType::ThreadsCreated as usize] = self.total_threads.load(Ordering::Relaxed);
        vals[MetricType::ActiveThreads as usize] = self.active_threads.load(Ordering::Relaxed);
        vals[MetricType::TotalChildren as usize] = self.total_children.load(Ordering::Relaxed);
        vals[MetricType::ActiveChildren as usize] = self.active_children.load(Ordering::Relaxed);
        vals[MetricType::PagesUser as usize] = pages_user;
        vals[MetricType::PagesKernel as usize] = pages_kernel;

        // System-wide memory metrics live at the aggregate (PID_SYSTEM) scope.
        if self.pid.as_u64() == PID_SYSTEM {
            let phys = crate::mm::phys::PhysStats::get();
            vals[MetricType::MemAvailable as usize] = phys.total_size;
            vals[MetricType::MemUsed as usize] = phys.small_pages_used << small_log2;
            vals[MetricType::MemHeapTotal as usize] =
                crate::mm::kheap::heap_stats().total_in_heap as u64;
            vals[MetricType::MemUsedPages as usize] = phys.small_pages_used;
            vals[MetricType::SoftOomUser as usize] =
                crate::mm::SOFT_OOM_USER_COUNT.load(Ordering::Relaxed);
            vals[MetricType::TlbShootdownSlow as usize] =
                crate::arch::x64::tlb::TLB_SHOOTDOWN_SLOW_COUNT.load(Ordering::Relaxed);
        }

        out.reserve(n);
        #[allow(clippy::needless_range_loop)]
        for idx in 0..n {
            out.push(MetricEntry::new(idx as u32, scope, vals[idx]));
        }
    }

    pub fn iterate<F>(start: ProcessId, flat: bool, mut func: F)
    where
        F: FnMut(&Self) -> bool,
    {
        if flat {
            if start.as_u64() == PID_SYSTEM && !func(SYSTEM_STATS.as_ref()) {
                return;
            }
            let child_lock = SYSTEM_STATS.children.lock(line!());
            for entry in child_lock.range(start..) {
                if let Some(e) = entry.1.upgrade() {
                    if !func(e.as_ref()) {
                        return;
                    }
                }
            }
        } else {
            let entry = {
                let child_lock = SYSTEM_STATS.children.lock(line!());
                if let Some(entry) = child_lock.get(&start) {
                    entry.clone()
                } else {
                    return;
                }
            };

            if let Some(entry) = entry.upgrade() {
                let child_lock = entry.children.lock(line!());
                for entry in child_lock.iter() {
                    if let Some(e) = entry.1.upgrade() {
                        if !func(e.as_ref()) {
                            return;
                        }
                    }
                }
            }
        }
    }

    fn cpu_usage(&self, now: u64) -> u64 {
        let mut res = 0;
        for entry in &self.per_cpu_stats.data {
            res += entry.usage_kernel(now) + entry.usage_uspace(now);
        }

        res
    }

    pub fn get_percpu_stats_entry(&self, cpu: uCpus) -> &PerCpuStatsEntry {
        &self.per_cpu_stats.data[cpu as usize]
    }

    #[inline]
    pub fn start_cpu_usage_kernel(&self) {
        let now = crate::arch::time::Instant::now().as_u64();
        let cpu = current_cpu() as usize;

        // Stop kernel.
        let kernel_entry = &KERNEL_STATS.per_cpu_stats.data[cpu];
        let prev = kernel_entry.started_k.swap(0, Ordering::Relaxed);
        assert_ne!(prev, 0);
        if now > prev {
            kernel_entry
                .cpu_kernel
                .fetch_add(now - prev, Ordering::Relaxed);
        }

        // Start self.
        let entry = &self.per_cpu_stats.data[cpu];
        assert_eq!(0, entry.started_k.swap(now, Ordering::Relaxed));
    }

    #[inline]
    pub fn stop_cpu_usage_kernel(&self) {
        let now = crate::arch::time::Instant::now().as_u64();
        let cpu = current_cpu() as usize;

        // Stop self.
        let entry = &self.per_cpu_stats.data[cpu];
        let prev = entry.started_k.swap(0, Ordering::Relaxed);
        assert_ne!(prev, 0);
        if now > prev {
            entry.cpu_kernel.fetch_add(now - prev, Ordering::Relaxed);
        }

        // Start kernel.
        let kernel_entry = &KERNEL_STATS.per_cpu_stats.data[cpu];
        assert_eq!(0, kernel_entry.started_k.swap(now, Ordering::Relaxed));
    }

    #[inline]
    pub fn start_cpu_usage_uspace(&self) {
        let now = crate::arch::time::Instant::now().as_u64();
        let cpu = current_cpu() as usize;

        // Stop kernel.
        let kernel_entry = &KERNEL_STATS.per_cpu_stats.data[cpu];
        let prev = kernel_entry.started_k.swap(0, Ordering::Relaxed);
        assert_ne!(prev, 0);
        if now > prev {
            kernel_entry
                .cpu_kernel
                .fetch_add(now - prev, Ordering::Relaxed);
        }

        // Start self.
        let entry = &self.per_cpu_stats.data[cpu];
        assert_eq!(0, entry.started_u.swap(now, Ordering::Relaxed));
    }

    #[inline]
    pub fn stop_cpu_usage_uspace(&self) {
        let now = crate::arch::time::Instant::now().as_u64();
        let cpu = current_cpu() as usize;

        // Stop self.
        let entry = &self.per_cpu_stats.data[cpu];
        let prev = entry.started_u.swap(0, Ordering::Relaxed);
        assert_ne!(prev, 0);
        if now > prev {
            entry.cpu_uspace.fetch_add(now - prev, Ordering::Relaxed);
        }

        // Start kernel.
        let kernel_entry = &KERNEL_STATS.per_cpu_stats.data[cpu];
        assert_eq!(0, kernel_entry.started_k.swap(now, Ordering::Relaxed));
    }

    pub fn cpu_usage_scope_kernel(self: &Arc<Self>) -> CpuUsageScopeKernel {
        self.start_cpu_usage_kernel();
        CpuUsageScopeKernel {
            stats: self.clone(),
        }
    }

    #[inline]
    pub fn adjust_metric(&self, metric: MetricType, val: i64) {
        let cpu = current_cpu() as usize;
        let entry = &self.per_cpu_stats.data[cpu];

        if val > 0 {
            entry.metrics[metric as usize].fetch_add(val as u64, Ordering::Relaxed);
        } else {
            entry.metrics[metric as usize].fetch_sub(-val as u64, Ordering::Relaxed);
        }
    }
}

static SYSTEM_STATS: StaticRef<Arc<KProcessStats>> = StaticRef::default_const();
static KERNEL_STATS: StaticRef<Arc<KProcessStats>> = StaticRef::default_const();

pub fn init() {
    use alloc::boxed::Box;
    SYSTEM_STATS.set(Box::leak(Box::new(KProcessStats::new_impl(
        None,
        ProcessId::from_u64(PID_SYSTEM),
        "(total)".to_owned(),
        false,
        Arc::new(MemStats::new_user()),
        Arc::new(MemStats::new_kernel()),
        Weak::new(),
    ))));

    KERNEL_STATS.set(Box::leak(Box::new(KProcessStats::new_impl(
        Some(system_stats()),
        ProcessId::from_u64(PID_KERNEL),
        "kernel".to_owned(),
        false,
        Arc::new(MemStats::new_user()),
        crate::mm::virt::kernel_mem_stats(),
        Weak::new(),
    ))));

    let num_cpus = crate::config::num_cpus() as u64;
    KERNEL_STATS
        .active_threads
        .store(num_cpus, Ordering::Relaxed);
    KERNEL_STATS
        .total_threads
        .store(num_cpus, Ordering::Relaxed);
    SYSTEM_STATS
        .active_threads
        .store(num_cpus, Ordering::Relaxed);
    SYSTEM_STATS
        .total_threads
        .store(num_cpus, Ordering::Relaxed);

    // The kernel may have allocated a bunch of memory by this time.
    SYSTEM_STATS.mem_stats_kernel.pages_used.fetch_add(
        KERNEL_STATS
            .mem_stats_kernel
            .pages_used
            .load(Ordering::Acquire),
        Ordering::Relaxed,
    );
}

fn system_stats() -> Arc<KProcessStats> {
    SYSTEM_STATS.clone()
}

pub fn kernel_stats() -> Arc<KProcessStats> {
    KERNEL_STATS.clone()
}

pub fn stats_from_pid(pid: u64) -> Option<Arc<KProcessStats>> {
    SYSTEM_STATS
        .children
        .lock(line!())
        .get(&ProcessId::from_u64(pid))
        .map(|w| w.upgrade())?
}

pub fn system_stats_ref() -> &'static KProcessStats {
    &SYSTEM_STATS
}

pub fn kernel_stats_ref() -> &'static KProcessStats {
    &KERNEL_STATS
}

pub fn fill_percpu_stats_entry(
    page_addr: usize,
    num_cpus: usize,
    entry_idx: usize,
    now: u64,
    stats: &KProcessStats,
) -> bool {
    unsafe {
        let entry_sz = 8 + num_cpus * 16;
        let addr_offset = entry_sz * entry_idx;
        if (addr_offset + entry_sz) > crate::mm::PAGE_SIZE_SMALL as usize {
            return false;
        }
        *((page_addr + addr_offset) as *mut u64) = stats.pid.as_u64();
        let percpu_entries = core::slice::from_raw_parts_mut(
            (page_addr + addr_offset + 8) as *mut moto_sys::stats::CpuStatsPerCpuEntryV1,
            num_cpus,
        );

        #[allow(clippy::needless_range_loop)]
        for cpu in 0..num_cpus {
            let entry_here = stats.get_percpu_stats_entry(cpu as uCpus);
            let entry_there = &mut percpu_entries[cpu];
            entry_there.kernel = entry_here.usage_kernel(now);
            entry_there.uspace = entry_here.usage_uspace(now);
        }
    }

    true
}

pub fn fill_percpu_stats_page(page_addr: usize) -> usize {
    let num_cpus = num_cpus() as usize;

    let processes = {
        let mut processes = alloc::vec::Vec::new();
        let lock = SYSTEM_STATS.children.lock(line!());
        processes.reserve_exact(lock.len());

        for stats in lock.values() {
            processes.push(stats.clone());
        }

        processes
    };

    let now = crate::arch::time::Instant::now().as_u64();
    fill_percpu_stats_entry(page_addr, num_cpus, 0, now, SYSTEM_STATS.as_ref());

    let mut curr_entry = 1_usize;
    for stats in &processes {
        if let Some(stats) = stats.upgrade() {
            if !(fill_percpu_stats_entry(page_addr, num_cpus, curr_entry, now, stats.as_ref())) {
                break;
            }
            curr_entry += 1
        }
    }

    curr_entry
}
