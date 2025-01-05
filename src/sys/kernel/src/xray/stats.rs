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

#[derive(Debug)]
pub struct MemStats {
    pages_used: AtomicU64,
    user_stats: bool,
}

impl Drop for MemStats {
    fn drop(&mut self) {
        // assert_eq!(0, self.total());
        if self.total() != 0 {
            log::error!("Non-empty MemStats dropped: {:?}.", self);
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

#[repr(C, align(64))]
pub struct PerCpuStatsEntry {
    pub cpu_kernel: AtomicU64, // as TSC
    pub cpu_uspace: AtomicU64, // as TSC
    pub started_k: AtomicU64,  // if running, indicates when cpu_kernel started, otherwise zero
    pub started_u: AtomicU64,  // if running, indicates when cpu_uspace started, otherwise zero
    _pad: [u64; 4],
}

const _: () = assert!(64 == core::mem::size_of::<PerCpuStatsEntry>());

impl PerCpuStatsEntry {
    const fn new() -> Self {
        Self {
            cpu_uspace: AtomicU64::new(0),
            cpu_kernel: AtomicU64::new(0),
            started_k: AtomicU64::new(0),
            started_u: AtomicU64::new(0),
            _pad: [0; 4],
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
        mem_stats_user: Arc<MemStats>,
        mem_stats_kernel: Arc<MemStats>,
        owner: Weak<crate::uspace::Process>,
    ) -> Arc<Self> {
        Self::new_impl(
            Some(parent),
            pid,
            debug_name,
            mem_stats_user,
            mem_stats_kernel,
            owner,
        )
    }

    fn new_impl(
        parent: Option<Arc<KProcessStats>>,
        pid: ProcessId,
        debug_name: String,
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
        // TODO: the assertion below has triggered once.
        // Should we make active_threads ops less relaxed? Or remove
        // the assertion? Or do nothing, as the assertion might
        // have been triggered by an error that has since been fixed?
        debug_assert_eq!(0, self.active_threads());

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
        let children = self.children.lock(line!());
        for pid in children.keys() {
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

    pub fn into_v1(&self, dest: &mut ProcessStatsV1, now: u64) {
        dest.pid = self.pid.as_u64();
        dest.parent_pid = self.parent.as_ref().map_or(0, |p| p.pid.as_u64());
        dest.total_threads = self.total_threads.load(Ordering::Relaxed);
        dest.total_children = self.total_children.load(Ordering::Relaxed);
        dest.active_threads = self.active_threads.load(Ordering::Relaxed);
        dest.active_children = self.active_children.load(Ordering::Relaxed);
        dest.pages_user = self.mem_stats_user.pages_used.load(Ordering::Relaxed);
        dest.pages_kernel = self.mem_stats_kernel.pages_used.load(Ordering::Relaxed);
        dest.cpu_usage = self.cpu_usage(now);

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
}

static SYSTEM_STATS: StaticRef<Arc<KProcessStats>> = StaticRef::default_const();
static KERNEL_STATS: StaticRef<Arc<KProcessStats>> = StaticRef::default_const();

pub fn init() {
    use alloc::boxed::Box;
    SYSTEM_STATS.set(Box::leak(Box::new(KProcessStats::new_impl(
        None,
        ProcessId::from_u64(PID_SYSTEM),
        "(total)".to_owned(),
        Arc::new(MemStats::new_user()),
        Arc::new(MemStats::new_kernel()),
        Weak::new(),
    ))));

    KERNEL_STATS.set(Box::leak(Box::new(KProcessStats::new_impl(
        Some(system_stats()),
        ProcessId::from_u64(PID_KERNEL),
        "kernel".to_owned(),
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
