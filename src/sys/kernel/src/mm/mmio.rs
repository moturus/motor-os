use super::*;
use moto_sys::ErrorCode;

pub struct MmioMapping {
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub num_pages: u64,
}

pub fn mmio_map(phys_addr: u64, num_pages: u64) -> Result<MmioMapping, ErrorCode> {
    phys::validate_mmio(phys_addr, num_pages)?;

    let vmem = virt::KERNEL_ADDRESS_SPACE.mmio_map(phys_addr, num_pages)?;

    Ok(MmioMapping {
        phys_addr,
        virt_addr: vmem.start,
        num_pages,
    })
}

#[allow(dead_code)]
pub fn mmio_unmap(mmio_mapping: &MmioMapping) {
    virt::vmem_free(mmio_mapping.virt_addr, virt::VmemKind::KernelMMIO);
}

pub fn mmio_map_region(phys_addr: u64, size: u64) -> Result<MmioMapping, ErrorCode> {
    let size = size
        .checked_add(PAGE_SIZE_SMALL - 1)
        .ok_or(moto_rt::E_INVALID_ARGUMENT)?
        & !(PAGE_SIZE_SMALL - 1);
    let num_pages = size >> PAGE_SIZE_SMALL_LOG2;
    mmio_map(phys_addr, num_pages)
}
