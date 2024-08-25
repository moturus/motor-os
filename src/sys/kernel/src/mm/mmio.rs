use super::*;
use moto_sys::ErrorCode;

pub struct MmioMapping {
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub num_pages: u64,
}

pub fn mmio_map(phys_addr: u64, num_pages: u64) -> Result<MmioMapping, ErrorCode> {
    assert_eq!(0, phys_addr & (PAGE_SIZE_SMALL - 1));

    let vmem = virt::vmem_allocate_pages(virt::VmemKind::KernelMMIO, num_pages)?;
    super::virt::KERNEL_ADDRESS_SPACE.mmio_map(phys_addr, vmem.start)?;

    Ok(MmioMapping {
        phys_addr,
        virt_addr: vmem.start,
        num_pages,
    })
}

#[allow(dead_code)]
pub fn mmio_unmap(_mmio_mapping: &MmioMapping) {
    todo!("VmemSegment is leaked in mmio_map");
}

pub fn mmio_map_region(phys_addr: u64, size: u64) -> Result<MmioMapping, ErrorCode> {
    let size = align_up(size, PAGE_SIZE_SMALL);
    let num_pages = size >> PAGE_SIZE_SMALL_LOG2;
    mmio_map(phys_addr, num_pages)
}
