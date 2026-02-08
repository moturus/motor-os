#![allow(internal_features)]
#![feature(core_intrinsics)]
#![feature(local_waker)]
#![allow(unused)]

use std::cell::RefCell;
use std::io::Result;

mod pci;
mod virtio_blk;
mod virtio_device;
// pub mod virtio_net;
mod virtio_queue;
// mod virtio_rng;

use moto_sys::SysHandle;
pub use pci::le16;
pub use pci::le32;
pub use pci::le64;

pub use virtio_blk::BlockDevice;
pub use virtio_device::{Device, init_virtio_devices};
pub use virtio_queue::WriteCompletion;

pub(crate) use virtio_device::mapper;

pub const fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

// This is the kernel/syscall interface consumed by the library:
// see crate::init_virtio_devices().
#[allow(clippy::result_unit_err)]
pub trait KernelAdapter {
    fn virt_to_phys(&self, virt_addr: u64) -> Result<u64>;
    fn mmio_map(&self, phys_addr: u64, sz: u64) -> Result<u64>;

    // Allocate one or more contiguous physical pages with total size of at least sz;
    // map them into a contigous virtual memory area and return the virt start of it.
    fn alloc_contiguous_pages(&self, sz: u64) -> Result<u64>;

    // Register a custom IRQ and an associated wait handle; the library will then use
    // the wait handle with wait() below.
    fn create_irq_wait_handle(&self) -> Result<(SysHandle, u8)>;
}

#[allow(unused)]
fn log_to_cloud_hypervisor(c: u8) {
    unsafe {
        core::arch::asm!(
            "out 0x80, al",
            in("al") c,
            options(nomem, nostack, preserves_flags)
        )
    };
}
