// Various statistics, best effort (never precise).

#[cfg(feature = "userspace")]
use crate::sys_mem;
#[cfg(feature = "userspace")]
use crate::ErrorCode;
#[cfg(feature = "userspace")]
use crate::SysMem;

pub const PID_SYSTEM: u64 = 0; // Used for aggregate (System) stats.
pub const PID_KERNEL: u64 = 1;
pub const PID_SYS_IO: u64 = 2;

// Instead of having a version field and mutate the struct,
// which is unsafe/brittle, we will just be adding new structs.
#[repr(C)]
#[derive(Default)]
pub struct ProcessStatsV1 {
    pub pid: u64, // PID_SYSTEM, PID_KERNEL, or actual process ID.
    pub parent_pid: u64,
    pub pages_user: u64,
    pub pages_kernel: u64,
    pub total_threads: u64,   // All threads created by this process.
    pub total_children: u64,  // All direct child processes spawned.
    pub active_threads: u64,  // Threads still running.
    pub active_children: u64, // Children still running.
    pub cpu_usage: u64,       // Total, in TSC.
    pub debug_name_bytes: [u8; 32],
    pub debug_name_len: u8,
    pub active: u8,         // 0 => zombie; 1 => active.
    pub system_process: u8, // 1 => system; 0 => normal.
}

#[cfg(feature = "userspace")]
impl ProcessStatsV1 {
    // List processes, in PID order. Completed processes without running
    // descendants may not be listed. @start will be included, if present.
    pub fn list(start: u64, buf: &mut [ProcessStatsV1]) -> Result<usize, ErrorCode> {
        crate::SysRay::list_processes_v1(start, true, buf)
    }

    // List direct children of the process. @parent will not be included.
    pub fn list_children(parent: u64, buf: &mut [ProcessStatsV1]) -> Result<usize, ErrorCode> {
        crate::SysRay::list_processes_v1(parent, false, buf)
    }

    pub fn debug_name(&self) -> &str {
        core::str::from_utf8(&self.debug_name_bytes[0..(self.debug_name_len as usize)])
            .unwrap_or("~")
    }

    pub fn total_bytes(&self) -> u64 {
        (self.pages_user + self.pages_kernel) << sys_mem::PAGE_SIZE_SMALL_LOG2
    }
}

#[repr(C)]
pub struct CpuStatsPerCpuEntryV1 {
    pub kernel: u64,
    pub uspace: u64,
}

#[repr(C)]
pub struct CpuStatsEntryV1<'a> {
    pub pid: u64,
    pub percpu_entries: &'a [CpuStatsPerCpuEntryV1], // The number of entries == num_cpus
}

#[cfg(feature = "userspace")]
pub struct CpuStatsV1 {
    num_entries: u32,
    num_cpus: u32,
    page_addr: u64,
}

#[cfg(feature = "userspace")]
impl Drop for CpuStatsV1 {
    fn drop(&mut self) {
        crate::SysMem::free(self.page_addr).unwrap();
    }
}

#[cfg(feature = "userspace")]
impl Default for CpuStatsV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "userspace")]
impl CpuStatsV1 {
    pub fn new() -> Self {
        let page_addr = crate::SysMem::alloc(sys_mem::PAGE_SIZE_SMALL, 1).unwrap();
        let num_entries = crate::SysCpu::get_percpu_stats_v1(page_addr).unwrap();
        let num_cpus = crate::shared_mem::KernelStaticPage::get().num_cpus;

        assert!((num_entries * (8 + num_cpus * 16)) as u64 <= sys_mem::PAGE_SIZE_SMALL);

        Self {
            num_entries,
            num_cpus,
            page_addr,
        }
    }

    pub fn tick(&mut self) {
        self.num_entries = crate::SysCpu::get_percpu_stats_v1(self.page_addr).unwrap();
    }

    pub fn num_cpus(&self) -> u32 {
        self.num_cpus
    }

    pub fn num_entries(&self) -> u32 {
        self.num_entries
    }

    pub fn entry(&self, pos: usize) -> CpuStatsEntryV1<'_> {
        assert!(pos < (self.num_entries as usize));

        unsafe {
            let entry_sz = (8 + self.num_cpus * 16) as usize;

            let addr = self.page_addr as usize + entry_sz * pos;
            let pid = *(addr as *const u64);
            let percpu_entries = core::slice::from_raw_parts(
                (addr + 8) as *const CpuStatsPerCpuEntryV1,
                self.num_entries as usize,
            );

            CpuStatsEntryV1 {
                pid,
                percpu_entries,
            }
        }
    }
}

// Physical memory stats.
#[repr(C)]
#[derive(Default)]
pub struct MemoryStats {
    pub available: u64,  // Total physical memory.
    pub used_pages: u64, // Physical pages mapped.
    pub heap_total: u64, // Total memory in the kernel heap.
}

#[cfg(feature = "userspace")]
impl MemoryStats {
    pub fn get() -> Result<MemoryStats, ErrorCode> {
        SysMem::query_stats()
    }

    pub fn used(&self) -> u64 {
        self.used_pages << sys_mem::PAGE_SIZE_SMALL_LOG2
    }
}

#[cfg(feature = "userspace")]
pub fn get_cpu_usage(buf: &mut [f32]) -> Result<(), ErrorCode> {
    crate::SysCpu::query_stats(buf)
}

#[repr(u16)]
#[derive(Debug, Default, Clone, Copy)]
pub enum ThreadStatus {
    #[default]
    Unknown = 0,
    Created = 1,
    LiveRunning,
    LivePreempted,
    LiveRunnable,
    LiveSyscall,
    LiveInWait,
    Dead,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct ThreadDataV1 {
    pub tid: u64,
    pub status: ThreadStatus, // u16
    pub syscall_num: u8,
    pub syscall_op: u8,
    pub paused_debuggee: u8,
    pub name_len: u8,
    pub _pad: [u8; 2],
    pub ip: u64,  // Instruction pointer.
    pub rbp: u64, // The value of the RBP register.
    pub name_bytes: [u8; crate::MAX_THREAD_NAME_LEN],
}

impl ThreadDataV1 {
    pub fn thread_name(&self) -> &str {
        assert!(self.name_len as usize <= crate::MAX_THREAD_NAME_LEN);
        core::str::from_utf8(&self.name_bytes[0..(self.name_len as usize)]).unwrap()
    }
}
