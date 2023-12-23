//! All MBI tags related to (U)EFI.

use crate::TagType;

/// EFI system table in 32 bit mode
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)] // only repr(C) would add unwanted padding before first_section
pub struct EFISdt32 {
    typ: TagType,
    size: u32,
    pointer: u32,
}

impl EFISdt32 {
    /// The physical address of a i386 EFI system table.
    pub fn sdt_address(&self) -> usize {
        self.pointer as usize
    }
}

/// EFI system table in 64 bit mode
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EFISdt64 {
    typ: TagType,
    size: u32,
    pointer: u64,
}

impl EFISdt64 {
    /// The physical address of a x86_64 EFI system table.
    pub fn sdt_address(&self) -> usize {
        self.pointer as usize
    }
}

/// Contains pointer to boot loader image handle.
#[derive(Debug)]
#[repr(C)]
pub struct EFIImageHandle32 {
    typ: TagType,
    size: u32,
    pointer: u32,
}

impl EFIImageHandle32 {
    /// Returns the physical address of the EFI image handle.
    pub fn image_handle(&self) -> usize {
        self.pointer as usize
    }
}

/// Contains pointer to boot loader image handle.
#[derive(Debug)]
#[repr(C)]
pub struct EFIImageHandle64 {
    typ: TagType,
    size: u32,
    pointer: u64,
}

impl EFIImageHandle64 {
    /// Returns the physical address of the EFI image handle.
    pub fn image_handle(&self) -> usize {
        self.pointer as usize
    }
}
