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

pub(crate) mod channel_budget;
pub mod fs;
pub(crate) mod net;
mod virtio_capacity;
pub(crate) mod vsock;

/// The guest's RAM in MiB as sizing policy sees it. The kernel reports less
/// than the configured RAM (firmware and boot reservations), so 10 MiB is
/// added to its figure.
pub(crate) fn guest_ram_mib() -> u64 {
    static RAM_MIB: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *RAM_MIB.get_or_init(|| {
        let available = moto_sys::stats::MemoryStats::get()
            .expect("the memory-stats query cannot fail on a live kernel")
            .available;
        (available >> 20) + 10
    })
}

/// Guests with less RAM get a smaller block cache, smaller default TCP
/// buffers, and lower connection limits.
pub(crate) const SMALL_GUEST_MIB: u64 = 256;

// A single 2M page used for VirtIO/MMIO.
// It's a hack, but we don't need anything more complicated for now.
pub static MMIO_PAGE: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    // Route io_channel peer-misbehavior (e.g. a client double-freeing a TX
    // page) to on_channel_error instead of letting the library panic sys-io.
    io_channel::set_error_handler(on_channel_error);

    assert_eq!(0, MMIO_PAGE.load(std::sync::atomic::Ordering::Relaxed));
    MMIO_PAGE.store(
        moto_sys::SysMem::alloc(moto_sys::sys_mem::PAGE_SIZE_MID, 1)
            .expect("Failed to allocate a 2M page."),
        std::sync::atomic::Ordering::Relaxed,
    );
}

// Return (phys_addr, virt_addr).
pub fn alloc_mmio_region(size: u64) -> IoResult<(u64, u64)> {
    use moto_sys::sys_mem;

    static BUMP: AtomicU64 = AtomicU64::new(0);

    const _: () = {
        assert!(virtio_capacity::MMIO_PAGE_SIZE == sys_mem::PAGE_SIZE_SMALL);
        assert!(virtio_capacity::MMIO_POOL_SIZE == sys_mem::PAGE_SIZE_MID);
    };
    let (start, size) = virtio_capacity::reserve_mmio(&BUMP, size)?;

    let virt_addr = MMIO_PAGE.load(std::sync::atomic::Ordering::Relaxed) + start;
    let phys_addr = moto_sys::SysMem::virt_to_phys(virt_addr).unwrap();

    // The kernel maps the 2M page without zeroing it (see
    // alloc_user_mid_pages); virtqueues expect zeroed rings.
    unsafe { core::ptr::write_bytes(virt_addr as usize as *mut u8, 0, size as usize) };

    Ok((phys_addr, virt_addr))
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

/// Process-wide io_channel error handler (installed in [`init`]). The library
/// calls this from `IoPage::drop` when a channel operation detects peer
/// misbehavior, so sys-io stays up instead of panicking. A client page
/// double-free means a misbehaving or corrupt client named an already-recovered
/// TX page twice: drop that one connection. A server page double-free is a bug
/// in sys-io itself, not the peer, so keep the historical panic to surface it.
fn on_channel_error(remote: SysHandle, error: io_channel::ChannelError) {
    log::warn!(
        "io_channel error from conn 0x{:x} ({}): \n\t{error:?}; dropping connection.",
        remote.as_u64(),
        conn_name(remote)
    );
    let _ = moto_sys::SysCpu::kill_remote(remote);
}

// ----------------------- Async Runtime ---------------------------- //
struct Mapper {
    next_irq_num: AtomicU8,
}
static MAPPER: Mapper = Mapper {
    next_irq_num: AtomicU8::new(virtio_capacity::IRQ_START),
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
        let (_, addr) = crate::runtime::alloc_mmio_region(sz)?;
        Ok(addr)
    }

    // Register a custom IRQ and an associated wait handle; the library will then use
    // the wait handle with wait() below.
    fn create_irq_wait_handle(&self) -> IoResult<(SysHandle, u8)> {
        let next_irq_num = virtio_capacity::reserve_irq(&self.next_irq_num)?;

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
    let channel_budget = Rc::new(channel_budget::ChannelBudget::default());

    let Ok(devices) = virtio_async::discover_virtio_devices(&MAPPER) else {
        panic!("VirtIO initialization failed.");
    };

    let mut block_device = None;
    let mut net_devices = vec![];
    let mut vsock_device = None;

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
            virtio_async::VirtioDeviceKind::Vsock => {
                if vsock_device.is_none() {
                    vsock_device = Some(device);
                } else {
                    log::warn!("Ignoring additional VirtioVsock device.");
                }
            }
            _ => log::debug!("Unsupported VirtIO device {:?}", device.kind()),
        }
    }

    let Some(block_device) = block_device else {
        panic!("No block devices found")
    };

    let Ok(fs) = fs::init(block_device, channel_budget.clone()).await else {
        panic!("Cannot proceed without a filesystem.");
    };

    // Config may ignore an initialized NIC, whose running queue tasks still
    // require its device-owned PCI metadata for their lifetime.
    let _unused_net_devices = net::init(net_devices, vsock_device, fs, channel_budget)
        .await
        .unwrap_or_else(|err| panic!("Cannot proceed without networking: {err:?}."));

    log::debug!("Runtime initialized.");
    let _ = started.send(());

    // Sleep forever, so that the current thread has a live async runtime.
    loop {
        moto_async::sleep(std::time::Duration::from_secs(60 * 60 * 24 * 365)).await;
        log::warn!("sys-io async runtime slept for a full year?");
    }

    unreachable!()
}
