use moto_sys::syscalls::*;
use std::{collections::BTreeMap, sync::atomic::AtomicU64};

struct Mapper {
    virt_to_phys_map: moto_runtime::mutex::Mutex<BTreeMap<u64, u64>>,
    map_requests: AtomicU64,
}
static MAPPER: Mapper = Mapper {
    virt_to_phys_map: moto_runtime::mutex::Mutex::new(BTreeMap::new()),
    map_requests: AtomicU64::new(0),
};

impl moto_virtio::KernelAdapter for Mapper {
    fn virt_to_phys(&self, virt_addr: u64) -> Result<u64, ()> {
        let page_addr = virt_addr & !(SysMem::PAGE_SIZE_SMALL - 1);
        let offset = virt_addr & (SysMem::PAGE_SIZE_SMALL - 1);
        if let Some(phys_addr) = self.virt_to_phys_map.lock().get(&page_addr) {
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

        let phys_addr = SysMem::virt_to_phys(page_addr).unwrap();
        self.virt_to_phys_map.lock().insert(page_addr, phys_addr);

        Ok(offset + phys_addr)
    }

    fn mmio_map(&self, phys_addr: u64, sz: u64) -> Result<u64, ()> {
        Ok(SysMem::mmio_map(phys_addr, sz).unwrap())
    }

    fn alloc_contiguous_pages(&self, sz: u64) -> Result<u64, ()> {
        let (_, addr) = crate::runtime::alloc_mmio_region(sz);
        Ok(addr)
    }

    // Register a custom IRQ and an associated wait handle; the library will then use
    // the wait handle with wait() below.
    fn create_irq_wait_handle(&self) -> Result<(moto_virtio::WaitHandle, u8), ()> {
        let handle = SysCtl::get(SysHandle::KERNEL, 0, "irq_wait:64").unwrap();
        Ok((handle.as_u64(), 64))
    }

    // Block until an associated IRQ fires. Takes a number of wait handles;
    // if the result is OK, handles will contain handles whose IRQs fired
    // (may be more than one).
    fn wait(&self, handles: &mut [moto_virtio::WaitHandle]) -> Result<(), ()> {
        const MAX_HANDLES: usize = 8;
        assert!(handles.len() < MAX_HANDLES);

        let mut sys_handles = [SysHandle::NONE; MAX_HANDLES];
        for idx in 0..handles.len() {
            sys_handles[idx] = SysHandle::from_u64(handles[idx]);
        }

        if let Err(err) = SysCpu::wait(
            &mut sys_handles[0..handles.len()],
            SysHandle::NONE,
            SysHandle::NONE,
            None,
        ) {
            log::error!("KernelAdapter::wait() failed: {:?}", err);
            Err(())
        } else {
            Ok(())
        }
    }
}

pub fn init() {
    moto_virtio::init_virtio_devices(&MAPPER);
}
