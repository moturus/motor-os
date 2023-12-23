use crate::TagType;
use core::marker::PhantomData;

/// This tag provides an initial host memory map.
///
/// The map provided is guaranteed to list all standard RAM that should be
/// available for normal use. This type however includes the regions occupied
/// by kernel, mbi, segments and modules. Kernel must take care not to
/// overwrite these regions.
///
/// This tag may not be provided by some boot loaders on EFI platforms if EFI
/// boot services are enabled and available for the loaded image (The EFI boot
/// services tag may exist in the Multiboot2 boot information structure).
#[derive(Debug)]
#[repr(C)]
pub struct MemoryMapTag {
    typ: TagType,
    size: u32,
    entry_size: u32,
    entry_version: u32,
    first_area: MemoryArea,
}

impl MemoryMapTag {
    /// Return an iterator over all AVAILABLE marked memory areas.
    pub fn memory_areas(&self) -> impl Iterator<Item = &MemoryArea> {
        self.all_memory_areas()
            .filter(|entry| matches!(entry.typ, MemoryAreaType::Available))
    }

    /// Return an iterator over all marked memory areas.
    pub fn all_memory_areas(&self) -> impl Iterator<Item = &MemoryArea> {
        let self_ptr = self as *const MemoryMapTag;
        let start_area = (&self.first_area) as *const MemoryArea;
        MemoryAreaIter {
            current_area: start_area as u64,
            last_area: (self_ptr as u64 + (self.size - self.entry_size) as u64),
            entry_size: self.entry_size,
            phantom: PhantomData,
        }
    }
}

/// A memory area entry descriptor.
#[derive(Debug)]
#[repr(C)]
pub struct MemoryArea {
    base_addr: u64,
    length: u64,
    typ: MemoryAreaType,
    _reserved: u32,
}

impl MemoryArea {
    /// The start address of the memory region.
    pub fn start_address(&self) -> u64 {
        self.base_addr
    }

    /// The end address of the memory region.
    pub fn end_address(&self) -> u64 {
        self.base_addr + self.length
    }

    /// The size, in bytes, of the memory region.
    pub fn size(&self) -> u64 {
        self.length
    }

    /// The type of the memory region.
    pub fn typ(&self) -> MemoryAreaType {
        self.typ
    }
}

/// An enum of possible reported region types.
/// Inside the Multiboot2 spec this is kind of hidden
/// inside the implementation of `struct multiboot_mmap_entry`.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[repr(u32)]
pub enum MemoryAreaType {
    /// Available memory free to be used by the OS.
    Available = 1,

    /// A reserved area that must not be used.
    Reserved = 2,

    /// Usable memory holding ACPI information.
    AcpiAvailable = 3,

    /// Reserved memory which needs to be preserved on hibernation.
    /// Also called NVS in spec, which stands for "Non-Volatile Sleep/Storage",
    /// which is part of ACPI specification.
    ReservedHibernate = 4,

    /// Memory which is occupied by defective RAM modules.
    Defective = 5,
}

/// An iterator over all memory areas
#[derive(Clone, Debug)]
pub struct MemoryAreaIter<'a> {
    current_area: u64,
    last_area: u64,
    entry_size: u32,
    phantom: PhantomData<&'a MemoryArea>,
}

impl<'a> Iterator for MemoryAreaIter<'a> {
    type Item = &'a MemoryArea;
    fn next(&mut self) -> Option<&'a MemoryArea> {
        if self.current_area > self.last_area {
            None
        } else {
            let area = unsafe { &*(self.current_area as *const MemoryArea) };
            self.current_area += self.entry_size as u64;
            Some(area)
        }
    }
}

/// EFI memory map as per EFI specification.
#[derive(Debug)]
#[repr(C)]
pub struct EFIMemoryMapTag {
    typ: TagType,
    size: u32,
    desc_size: u32,
    desc_version: u32,
    first_desc: EFIMemoryDesc,
}

impl EFIMemoryMapTag {
    /// Return an iterator over ALL marked memory areas.
    ///
    /// This differs from `MemoryMapTag` as for UEFI, the OS needs some non-
    /// available memory areas for tables and such.
    pub fn memory_areas(&self) -> EFIMemoryAreaIter {
        let self_ptr = self as *const EFIMemoryMapTag;
        let start_area = (&self.first_desc) as *const EFIMemoryDesc;
        EFIMemoryAreaIter {
            current_area: start_area as u64,
            last_area: (self_ptr as u64 + self.size as u64),
            entry_size: self.desc_size,
            phantom: PhantomData,
        }
    }
}

/// EFI Boot Memory Map Descriptor
#[derive(Debug)]
#[repr(C)]
pub struct EFIMemoryDesc {
    typ: u32,
    _padding: u32,
    phys_addr: u64,
    virt_addr: u64,
    num_pages: u64,
    attr: u64,
}

/// An enum of possible reported region types.
#[derive(Debug, PartialEq, Eq)]
pub enum EFIMemoryAreaType {
    /// Unusable.
    EfiReservedMemoryType,
    /// Code area of a UEFI application.
    EfiLoaderCode,
    /// Data area of a UEFI application.
    EfiLoaderData,
    /// Code area of a UEFI Boot Service Driver.
    EfiBootServicesCode,
    /// Data area of a UEFI Boot Service Driver.
    EfiBootServicesData,
    /// Code area of a UEFI Runtime Driver.
    ///
    /// Must be preserved in working and ACPI S1-S3 states.
    EfiRuntimeServicesCode,
    /// Data area of a UEFI Runtime Driver.
    ///
    /// Must be preserved in working and ACPI S1-S3 states.
    EfiRuntimeServicesData,
    /// Available memory.
    EfiConventionalMemory,
    /// Memory with errors, treat as unusable.
    EfiUnusableMemory,
    /// Memory containing the ACPI tables.
    ///
    /// Must be preserved in working and ACPI S1-S3 states.
    EfiACPIReclaimMemory,
    /// Memory reserved by firmware.
    ///
    /// Must be preserved in working and ACPI S1-S3 states.
    EfiACPIMemoryNVS,
    /// Memory used by firmware for requesting memory mapping of IO.
    ///
    /// Should not be used by the OS. Use the ACPI tables for memory mapped IO
    /// information.
    EfiMemoryMappedIO,
    /// Memory used to translate memory cycles to IO cycles.
    ///
    /// Should not be used by the OS. Use the ACPI tables for memory mapped IO
    /// information.
    EfiMemoryMappedIOPortSpace,
    /// Memory used by the processor.
    ///
    /// Must be preserved in working and ACPI S1-S4 states. Processor defined
    /// otherwise.
    EfiPalCode,
    /// Available memory supporting byte-addressable non-volatility.
    EfiPersistentMemory,
    /// Unknown region type, treat as unusable.
    EfiUnknown,
}

impl EFIMemoryDesc {
    /// The physical address of the memory region.
    pub fn physical_address(&self) -> u64 {
        self.phys_addr
    }

    /// The virtual address of the memory region.
    pub fn virtual_address(&self) -> u64 {
        self.virt_addr
    }

    /// The size in bytes of the memory region.
    pub fn size(&self) -> u64 {
        // Spec says this is number of 4KiB pages.
        self.num_pages * 4096
    }

    /// The type of the memory region.
    pub fn typ(&self) -> EFIMemoryAreaType {
        match self.typ {
            0 => EFIMemoryAreaType::EfiReservedMemoryType,
            1 => EFIMemoryAreaType::EfiLoaderCode,
            2 => EFIMemoryAreaType::EfiLoaderData,
            3 => EFIMemoryAreaType::EfiBootServicesCode,
            4 => EFIMemoryAreaType::EfiBootServicesData,
            5 => EFIMemoryAreaType::EfiRuntimeServicesCode,
            6 => EFIMemoryAreaType::EfiRuntimeServicesData,
            7 => EFIMemoryAreaType::EfiConventionalMemory,
            8 => EFIMemoryAreaType::EfiUnusableMemory,
            9 => EFIMemoryAreaType::EfiACPIReclaimMemory,
            10 => EFIMemoryAreaType::EfiACPIMemoryNVS,
            11 => EFIMemoryAreaType::EfiMemoryMappedIO,
            12 => EFIMemoryAreaType::EfiMemoryMappedIOPortSpace,
            13 => EFIMemoryAreaType::EfiPalCode,
            14 => EFIMemoryAreaType::EfiPersistentMemory,
            _ => EFIMemoryAreaType::EfiUnknown,
        }
    }
}

/// EFI ExitBootServices was not called
#[derive(Debug)]
#[repr(C)]
pub struct EFIBootServicesNotExited {
    typ: u32,
    size: u32,
}

/// An iterator over ALL EFI memory areas.
#[derive(Clone, Debug)]
pub struct EFIMemoryAreaIter<'a> {
    current_area: u64,
    last_area: u64,
    entry_size: u32,
    phantom: PhantomData<&'a EFIMemoryDesc>,
}

impl<'a> Iterator for EFIMemoryAreaIter<'a> {
    type Item = &'a EFIMemoryDesc;
    fn next(&mut self) -> Option<&'a EFIMemoryDesc> {
        if self.current_area > self.last_area {
            None
        } else {
            let area = unsafe { &*(self.current_area as *const EFIMemoryDesc) };
            self.current_area += self.entry_size as u64;
            Some(area)
        }
    }
}
