use crate::uCpus;

// pub fn application_processors() -> alloc::vec::Vec<uCpus> {
pub fn application_processors(maybe_rdsp: u64) -> uCpus {
    // helpers to detect RSDP and work with ACPI
    // TODO: the external crates used here are way overenineered. Bring this code inside.
    #[derive(Clone)]
    struct HkernelAcpiMapper;
    impl rsdp::handler::AcpiHandler for HkernelAcpiMapper {
        unsafe fn map_physical_region<T>(
            &self,
            physical_address: usize,
            size: usize,
        ) -> rsdp::handler::PhysicalMapping<Self, T> {
            let virt_addr = physical_address + crate::mm::PAGING_DIRECT_MAP_OFFSET as usize;
            rsdp::handler::PhysicalMapping::new(
                physical_address,
                core::ptr::NonNull::new(virt_addr as *mut _).unwrap(),
                size,
                size,
                Self,
            )
        }

        fn unmap_physical_region<T>(_region: &rsdp::handler::PhysicalMapping<Self, T>) {
            // Do nothing: we didn't map anything for this.
        }
    }

    let acpi_tables: acpi::AcpiTables<HkernelAcpiMapper> = {
        fn detect_rsdp() -> Option<x86_64::PhysAddr> {
            unsafe {
                rsdp::Rsdp::search_for_on_bios(HkernelAcpiMapper)
                    .ok()
                    .map(|mapping| x86_64::PhysAddr::new(mapping.physical_start() as u64))
            }
        }

        // Find RSDP.
        let rsdp_addr: u64 = if maybe_rdsp != 0 {
            maybe_rdsp
        } else {
            detect_rsdp().unwrap().as_u64()
        };
        assert!(rsdp_addr != 0u64);

        unsafe { acpi::AcpiTables::from_rsdp(HkernelAcpiMapper, rsdp_addr as usize).unwrap() }
    };

    let processors = acpi::platform::PlatformInfo::new(&acpi_tables)
        .unwrap()
        .processor_info
        .unwrap()
        .application_processors;

    let mut processors: alloc::vec::Vec<_> = processors
        .into_iter()
        .map(|x| x.local_apic_id as uCpus)
        .collect();
    assert!(processors.len() <= (uCpus::MAX as usize));

    // We assume that all logical CPUs are in [1..num_cpus).
    processors.sort();

    #[allow(clippy::needless_range_loop)]
    for idx in 0..processors.len() {
        assert_eq!(idx + 1, processors[idx] as usize);
    }

    (processors.len() + 1) as uCpus
}
