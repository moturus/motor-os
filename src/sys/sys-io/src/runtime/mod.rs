#![allow(unused)]

use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
};

use moto_ipc::io_channel;
use moto_sys::SysHandle;
use std::io::Result as IoResult;

mod fs;
pub mod internal_queue;
pub mod io_stats;
mod io_thread;
// pub use fs::smoke_test as fs_smoke_test;

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

// ----------------------- Async Runtime ---------------------------- //
struct Mapper {
    virt_to_phys_map: std::sync::Mutex<BTreeMap<u64, u64>>,
    map_requests: AtomicU64,
    next_irq_num: AtomicU8,
}
static MAPPER: Mapper = Mapper {
    virt_to_phys_map: std::sync::Mutex::new(BTreeMap::new()),
    map_requests: AtomicU64::new(0),
    next_irq_num: AtomicU8::new(64),
};

impl virtio_async::KernelAdapter for Mapper {
    fn virt_to_phys(&self, virt_addr: u64) -> IoResult<u64> {
        let page_addr = virt_addr & !(moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);
        let offset = virt_addr & (moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);
        if let Some(phys_addr) = self.virt_to_phys_map.lock().unwrap().get(&page_addr) {
            return Ok(offset + *phys_addr);
        }

        let requests = self
            .map_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // We don't want to do the syscall too often. But We also don't want
        // to force copying data all the time: our flatfs adapter (fs_flatfs.rs)
        // reads its bytes into a buffer and doesn't do any copying, and this
        // is a good thing: it is faster to call virt_to_phys() than to
        // copy 512 bytes. So the number below should be not too small, not too
        // large.
        assert!(requests < 1_000_000);

        let phys_addr = moto_sys::SysMem::virt_to_phys(page_addr).unwrap();
        self.virt_to_phys_map
            .lock()
            .unwrap()
            .insert(page_addr, phys_addr);

        Ok(offset + phys_addr)
    }

    fn mmio_map(&self, phys_addr: u64, sz: u64) -> IoResult<u64> {
        Ok(moto_sys::SysMem::mmio_map(phys_addr, sz).unwrap())
    }

    fn alloc_contiguous_pages(&self, sz: u64) -> IoResult<u64> {
        let (_, addr) = crate::runtime::alloc_mmio_region(sz);
        Ok(addr)
    }

    // Register a custom IRQ and an associated wait handle; the library will then use
    // the wait handle with wait() below.
    fn create_irq_wait_handle(&self) -> IoResult<(SysHandle, u8)> {
        let next_irq_num = self.next_irq_num.fetch_add(1, Ordering::AcqRel);
        assert!(next_irq_num < 70);

        moto_sys::SysObj::get(
            SysHandle::KERNEL,
            0,
            format!("irq_wait:{next_irq_num}").as_str(),
        )
        .map(|handle| (handle, next_irq_num))
        .map_err(|code| std::io::Error::from_raw_os_error(code as i32))
    }
}

// ----------------------- Async Runtime ---------------------------- //
enum RuntimeMsg {}

static RUNTIME_QUEUE: std::sync::Mutex<VecDeque<RuntimeMsg>> =
    std::sync::Mutex::new(VecDeque::new());
static RUNTIME_IPC_HANDLE: AtomicU64 = AtomicU64::new(0);

/// Spawn the async runtime.
pub fn spawn_async() {
    let (handle_here, handle_there) =
        moto_sys::SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0).unwrap();
    RUNTIME_IPC_HANDLE.store(handle_here.as_u64(), std::sync::atomic::Ordering::Release);

    let (tx, rx) = moto_async::oneshot();

    let _runtime_thread = std::thread::Builder::new()
        .name("sys-io:runtime".to_owned())
        .spawn(move || {
            // I/O IRQs are affined to CPU 0.
            moto_sys::SysCpu::affine_to_cpu(Some(0)).unwrap();
            moto_async::LocalRuntime::new().block_on(async move {
                async_runtime(handle_there, tx).await;
            });
        });

    moto_async::LocalRuntime::new().block_on(async move {
        let _ = rx.await;
    });
}

async fn async_runtime(q_handle: SysHandle, started: moto_async::oneshot::Sender<()>) {
    log::debug!("async runtime starting");
    let queue_joiner = moto_async::LocalRuntime::spawn(global_queue_listener(q_handle));

    let Ok(devices) = virtio_async::init_virtio_devices(&MAPPER) else {
        panic!("VirtIO initialization failed.");
    };

    let mut block_device = None;

    for device in devices {
        match device {
            virtio_async::Device::Block(bd) => {
                assert!(
                    block_device.is_none(),
                    "Multiple block devices are not supported yet."
                );
                block_device = Some(bd);
            }
        }
    }

    let Some(block_device) = block_device else {
        panic!("No block devices found")
    };

    let Ok(filesystem) = fs::init(block_device).await else {
        panic!("Cannot proceed without a filesystem.");
    };

    log::debug!("Runtime initialized.");
    let _ = started.send(());

    queue_joiner.await; // Never actually returns.
    unreachable!()
}

async fn global_queue_listener(queue_handle: SysHandle) {
    use moto_async::AsFuture;

    loop {
        queue_handle.as_future().await.unwrap();
        let Some(msg) = RUNTIME_QUEUE.lock().unwrap().pop_back() else {
            continue;
        };

        match msg {}
    }
}

/*
async fn block_device_listener(
    bd: Rc<moto_async::LocalMutex<virtio_async::BlockDevice>>,
    started_futex: Arc<AtomicU32>,
) {
    use moto_async::AsFuture;

    let wait_handle = bd.lock().await.wait_handle();
    started_futex.store(RUNTIME_STARTED, Ordering::Release);
    let _ = moto_rt::futex_wake(std::ops::Deref::deref(&started_futex));
    loop {
        wait_handle.as_future().await.unwrap();
        todo!("Block device interrupt!")
    }
}
*/
