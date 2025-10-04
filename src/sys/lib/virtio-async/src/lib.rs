#![allow(internal_features)]
#![feature(core_intrinsics)]
#![allow(unused)]

mod pci;
mod virtio_blk;
mod virtio_device;
pub mod virtio_net;
mod virtio_queue;
// mod virtio_rng;

pub use pci::le16;
pub use pci::le32;
pub use pci::le64;

pub use virtio_blk::BlockDevice;
pub use virtio_device::{Device, init_virtio_devices};

pub(crate) use virtio_device::mapper;

pub const fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

pub fn nop() {
    unsafe {
        core::arch::asm!("nop", "pause");
    }
}

pub const BLOCK_SIZE: usize = 512;
pub const BLOCK_SIZE_LOG2: usize = 9;

/*
// This is the block device interface exposed by the library: see crate::lsblk().
#[allow(clippy::result_unit_err)]
pub trait BlockDevice {
    // buf must be aligned at BLOCK_SIZE.
    fn read(&self, buf: &mut [u8], address: u64, number_of_blocks: usize) -> Result<(), ()>;
    fn write(&self, buf: &[u8], address: u64, number_of_blocks: usize) -> Result<(), ()>;
    fn capacity(&self) -> u64; // In blocks.
}
*/

pub type WaitHandle = u64;

// This is the kernel/syscall interface consumed by the library:
// see crate::init_virtio_devices().
#[allow(clippy::result_unit_err)]
pub trait KernelAdapter {
    fn virt_to_phys(&self, virt_addr: u64) -> Result<u64, ()>;
    fn mmio_map(&self, phys_addr: u64, sz: u64) -> Result<u64, ()>;

    // Allocate one or more contiguous physical pages with total size of at least sz;
    // map them into a contigous virtual memory area and return the virt start of it.
    fn alloc_contiguous_pages(&self, sz: u64) -> Result<u64, ()>;

    // Register a custom IRQ and an associated wait handle; the library will then use
    // the wait handle with wait() below.
    fn create_irq_wait_handle(&self) -> Result<(WaitHandle, u8), ()>;
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
