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

pub mod fs;
mod net;

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
    let mut stats = [moto_sys::stats::ProcessInfoV1::default()];
    if let Ok(1) = moto_sys::stats::ProcessInfoV1::list(pid, &mut stats) {
        format!("{}: `{}`", pid, stats[0].debug_name()).to_owned()
    } else {
        "<unknown>".to_owned()
    }
}

// ----------------------- Async Runtime ---------------------------- //
struct Mapper {
    next_irq_num: AtomicU8,
}
static MAPPER: Mapper = Mapper {
    next_irq_num: AtomicU8::new(64),
};

impl virtio_async::KernelAdapter for Mapper {
    fn virt_to_phys(&self, virt_addr: u64) -> IoResult<u64> {
        let page_addr = virt_addr & !(moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);
        let offset = virt_addr & (moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);

        let phys_addr = moto_sys::SysMem::virt_to_phys(page_addr).unwrap();

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

/// Spawn the async runtime.
pub fn spawn_async() {
    let (tx, rx) = moto_async::oneshot();

    let _runtime_thread = std::thread::Builder::new()
        .name("sys-io:runtime".to_owned())
        .spawn(move || {
            // I/O IRQs are affined to CPU 0.
            moto_sys::SysCpu::affine_to_cpu(Some(0)).unwrap();
            moto_async::LocalRuntime::new().block_on(async move {
                async_runtime(tx).await;
            });
        });

    moto_async::LocalRuntime::new().block_on(async move {
        let _ = rx.await;
    });
}

async fn async_runtime(started: moto_async::oneshot::Sender<()>) {
    log::debug!("async runtime starting");

    let Ok(devices) = virtio_async::discover_virtio_devices(&MAPPER) else {
        panic!("VirtIO initialization failed.");
    };

    let mut block_device = None;
    let mut net_devices = vec![];

    for device in devices {
        match device.kind() {
            virtio_async::VirtioDeviceKind::Block => {
                assert!(
                    block_device.is_none(),
                    "Multiple block devices are not supported yet."
                );
                block_device = Some(device);
            }
            virtio_async::VirtioDeviceKind::Net => {
                match virtio_async::virtio_net::NetDevice::from(device) {
                    Ok(device) => net_devices.push(device),
                    Err(err) => log::error!("Failed to initialize VirtioNet device: {err:?}."),
                }
            }
            _ => log::warn!("Unsupported VirtIO device {:?}", device.kind()),
        }
    }

    let Some(block_device) = block_device else {
        panic!("No block devices found")
    };

    let Ok(fs) = fs::init(block_device).await else {
        panic!("Cannot proceed without a filesystem.");
    };

    if let Err(err) = net::init(net_devices, fs).await {
        log::error!("Network initialization failed: {err:?}.");
    }

    log::debug!("Runtime initialized.");
    let _ = started.send(());

    // Sleep forever, so that the current thread has a live async runtime.
    loop {
        moto_async::sleep(std::time::Duration::from_secs(60 * 60 * 24 * 365)).await;
        log::warn!("sys-io async runtime slept for a full year?");
    }

    unreachable!()
}
