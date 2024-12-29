use std::sync::atomic::AtomicU64;

use moto_ipc::io_channel;
use moto_sys::SysHandle;

pub mod internal_queue;
pub mod io_stats;
mod io_thread;

pub struct PendingCompletion {
    pub msg: io_channel::Msg,
    pub endpoint_handle: SysHandle,
}

// Either net or (later) fs.
pub trait IoSubsystem {
    fn wait_handles(&self) -> Vec<SysHandle>;
    fn process_wakeup(&mut self, handle: SysHandle);
    fn process_sqe(
        &mut self,
        conn: &std::rc::Rc<io_channel::ServerConnection>,
        sqe: io_channel::Msg,
    ) -> Result<Option<io_channel::Msg>, ()>;

    // Returns a completion for a process. If none, the device has nothing
    // to do and the IO thread may sleep.
    fn poll(&mut self) -> Option<PendingCompletion>;

    fn on_connection_drop(&mut self, conn: SysHandle);

    // For how long the IO thread may sleep without calling poll.
    // This is particularly useful in networking, where TCP have various timers.
    fn wait_timeout(&mut self) -> Option<core::time::Duration>;

    fn get_stats(&mut self, msg: &internal_queue::Msg);

    #[allow(unused)]
    fn dump_state(&mut self);
}

pub static STARTED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn start() {
    io_thread::start();
    while STARTED.load(std::sync::atomic::Ordering::Relaxed) == 0 {
        moto_rt::futex::futex_wait(&STARTED, 0, None);
    }
    io_stats::spawn_stats_service();
}

// A single 2M page used for VirtIO/MMIO.
// It's a hack, but we don't need anything more complicated for now.
pub static MMIO_PAGE: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    assert_eq!(0, MMIO_PAGE.load(std::sync::atomic::Ordering::Relaxed));
    MMIO_PAGE.store(
        moto_sys::SysMem::alloc(moto_sys::sys_mem::PAGE_SIZE_MID, 1)
            .expect("Failed to allocate a 2M page."),
        std::sync::atomic::Ordering::Relaxed,
    );
}

// Return (phys_addr, virt_addr).
pub fn alloc_mmio_region(size: u64) -> (u64, u64) {
    use moto_sys::sys_mem;

    static BUMP: AtomicU64 = AtomicU64::new(0);

    let size = moto_sys::align_up(size, sys_mem::PAGE_SIZE_SMALL);
    assert_eq!(0, size & (sys_mem::PAGE_SIZE_SMALL - 1));
    let start = BUMP.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
    assert!(start + size < sys_mem::PAGE_SIZE_MID);

    let virt_addr = MMIO_PAGE.load(std::sync::atomic::Ordering::Relaxed) + start;
    let phys_addr = moto_sys::SysMem::virt_to_phys(virt_addr).unwrap();

    (phys_addr, virt_addr)
}

fn conn_name(handle: SysHandle) -> String {
    let pid = if let Ok(pid) = moto_sys::SysObj::get_pid(handle) {
        pid
    } else {
        return "<unknown>".to_owned();
    };
    let mut stats = [moto_sys::stats::ProcessStatsV1::default()];
    if let Ok(1) = moto_sys::stats::ProcessStatsV1::list(pid, &mut stats) {
        format!("{}: `{}`", pid, stats[0].debug_name()).to_owned()
    } else {
        "<unknown>".to_owned()
    }
}
