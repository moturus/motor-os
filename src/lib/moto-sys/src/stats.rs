// Various statistics, best effort (never precise).

#[cfg(feature = "userspace")]
use crate::syscalls::SysMem;
#[cfg(feature = "userspace")]
use crate::ErrorCode;

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
        super::syscalls::SysCtl::list_processes_v1(start, true, buf)
    }

    // List direct children of the process. @parent will not be included.
    pub fn list_children(parent: u64, buf: &mut [ProcessStatsV1]) -> Result<usize, ErrorCode> {
        super::syscalls::SysCtl::list_processes_v1(parent, false, buf)
    }

    pub fn debug_name(&self) -> &str {
        core::str::from_utf8(&self.debug_name_bytes[0..(self.debug_name_len as usize)])
            .unwrap_or("~")
    }

    pub fn total_bytes(&self) -> u64 {
        (self.pages_user + self.pages_kernel) << SysMem::PAGE_SIZE_SMALL_LOG2
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
        self.used_pages << SysMem::PAGE_SIZE_SMALL_LOG2
    }
}

#[cfg(feature = "userspace")]
pub fn get_cpu_usage(buf: &mut [f32]) -> Result<(), ErrorCode> {
    crate::syscalls::SysCpu::query_stats(buf)
}
