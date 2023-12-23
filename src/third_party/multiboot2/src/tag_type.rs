//! Module for [`TagType`].

use core::fmt::{Debug, Formatter};
use core::hash::Hash;
use core::marker::PhantomData;

/// Possible types of a Tag in the Multiboot2 Information Structure (MBI), therefore the value
/// of the the `typ` property. The names and values are taken from the example C code
/// at the bottom of the Multiboot2 specification.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, Ord, PartialOrd, PartialEq, Hash)]
pub enum TagType {
    /// Marks the end of the tags.
    End = 0,
    /// Additional command line string.
    /// For example `''` or `'--my-custom-option foo --provided by_grub`, if your GRUB config
    /// contains `multiboot2 /boot/multiboot2-binary.elf --my-custom-option foo --provided by_grub`
    Cmdline = 1,
    /// Name of the bootloader, e.g. 'GRUB 2.04-1ubuntu44.2'
    BootLoaderName = 2,
    /// Additional Multiboot modules, which are BLOBs provided in memory. For example an initial
    /// ram disk with essential drivers.
    Module = 3,
    /// ‘mem_lower’ and ‘mem_upper’ indicate the amount of lower and upper memory, respectively,
    /// in kilobytes. Lower memory starts at address 0, and upper memory starts at address 1
    /// megabyte. The maximum possible value for lower memory is 640 kilobytes. The value returned
    /// for upper memory is maximally the address of the first upper memory hole minus 1 megabyte.
    /// It is not guaranteed to be this value.
    ///
    /// This tag may not be provided by some boot loaders on EFI platforms if EFI boot services are
    /// enabled and available for the loaded image (EFI boot services not terminated tag exists in
    /// Multiboot2 information structure).
    BasicMeminfo = 4,
    /// This tag indicates which BIOS disk device the boot loader loaded the OS image from. If the
    /// OS image was not loaded from a BIOS disk, then this tag must not be present. The operating
    /// system may use this field as a hint for determining its own root device, but is not
    /// required to.
    Bootdev = 5,
    /// Memory map. The map provided is guaranteed to list all standard RAM that should be
    /// available for normal use. This type however includes the regions occupied by kernel, mbi,
    /// segments and modules. Kernel must take care not to overwrite these regions.
    //
    // This tag may not be provided by some boot loaders on EFI platforms if EFI boot services are
    // enabled and available for the loaded image (EFI boot services not terminated tag exists in
    // Multiboot2 information structure).
    Mmap = 6,
    /// Contains the VBE control information returned by the VBE Function 00h and VBE mode
    /// information returned by the VBE Function 01h, respectively. Note that VBE 3.0 defines
    /// another protected mode interface which is incompatible with the old one. If you want to use the new protected mode interface, you will have to find the table yourself.
    Vbe = 7,
    /// Framebuffer.
    Framebuffer = 8,
    /// This tag contains section header table from an ELF kernel, the size of each entry, number
    /// of entries, and the string table used as the index of names. They correspond to the
    /// ‘shdr_*’ entries (‘shdr_num’, etc.) in the Executable and Linkable Format (ELF)
    /// specification in the program header.
    ElfSections = 9,
    /// APM table. See Advanced Power Management (APM) BIOS Interface Specification, for more
    /// information.
    Apm = 10,
    /// This tag contains pointer to i386 EFI system table.
    Efi32 = 11,
    /// This tag contains pointer to amd64 EFI system table.
    Efi64 = 12,
    /// This tag contains a copy of SMBIOS tables as well as their version.
    Smbios = 13,
    /// Also called "AcpiOld" in other multiboot2 implementations.
    AcpiV1 = 14,
    /// Refers to version 2 and later of Acpi.
    /// Also called "AcpiNew" in other multiboot2 implementations.
    AcpiV2 = 15,
    /// This tag contains network information in the format specified as DHCP. It may be either a
    /// real DHCP reply or just the configuration info in the same format. This tag appears once
    /// per card.
    Network = 16,
    /// This tag contains EFI memory map as per EFI specification.
    /// This tag may not be provided by some boot loaders on EFI platforms if EFI boot services are
    /// enabled and available for the loaded image (EFI boot services not terminated tag exists in Multiboot2 information structure).
    EfiMmap = 17,
    /// This tag indicates ExitBootServices wasn't called.
    EfiBs = 18,
    /// This tag contains pointer to EFI i386 image handle. Usually it is boot loader image handle.
    Efi32Ih = 19,
    /// This tag contains pointer to EFI amd64 image handle. Usually it is boot loader image handle.
    Efi64Ih = 20,
    /// This tag contains image load base physical address. The spec tells
    /// "It is provided only if image has relocatable header tag." but experience showed
    /// that this is not true for at least GRUB 2.
    LoadBaseAddr = 21,
}

// each compare/equal direction must be implemented manually
impl PartialEq<u32> for TagType {
    fn eq(&self, other: &u32) -> bool {
        *self as u32 == *other
    }
}

// each compare/equal direction must be implemented manually
impl PartialEq<TagType> for u32 {
    fn eq(&self, other: &TagType) -> bool {
        *self == *other as u32
    }
}

/// All tags that could passed via the Multiboot2 information structure to a payload/program/kernel.
/// Better not confuse this with the Multiboot2 header tags. They are something different.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Tag {
    // u32 value
    pub typ: TagType,
    pub size: u32,
    // tag specific fields
}

impl Debug for Tag {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tag")
            .field("typ", &self.typ)
            .field("typ (numeric)", &(self.typ as u32))
            .field("size", &(self.size))
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct TagIter<'a> {
    pub current: *const Tag,
    phantom: PhantomData<&'a Tag>,
}

impl<'a> TagIter<'a> {
    pub fn new(first: *const Tag) -> Self {
        TagIter {
            current: first,
            phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for TagIter<'a> {
    type Item = &'a Tag;

    fn next(&mut self) -> Option<&'a Tag> {
        match unsafe { &*self.current } {
            &Tag {
                typ: TagType::End,
                size: 8,
            } => None, // end tag
            tag => {
                // go to next tag
                let mut tag_addr = self.current as usize;
                tag_addr += ((tag.size + 7) & !7) as usize; //align at 8 byte
                self.current = tag_addr as *const _;

                Some(tag)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashset() {
        let mut set = std::collections::HashSet::new();
        set.insert(TagType::Cmdline);
        set.insert(TagType::ElfSections);
        set.insert(TagType::BootLoaderName);
        set.insert(TagType::LoadBaseAddr);
        set.insert(TagType::LoadBaseAddr);
        assert_eq!(set.len(), 4);
        println!("{:#?}", set);
    }

    #[test]
    fn test_btreeset() {
        let mut set = std::collections::BTreeSet::new();
        set.insert(TagType::Cmdline);
        set.insert(TagType::ElfSections);
        set.insert(TagType::BootLoaderName);
        set.insert(TagType::LoadBaseAddr);
        set.insert(TagType::LoadBaseAddr);
        assert_eq!(set.len(), 4);
        for (current, next) in set.iter().zip(set.iter().skip(1)) {
            assert!(current < next);
        }
        println!("{:#?}", set);
    }

    /// Tests for equality when one type is u32 and the other the enum representation.
    #[test]
    fn test_partial_eq_u32() {
        assert_eq!(21, TagType::LoadBaseAddr);
        assert_eq!(TagType::LoadBaseAddr, 21);
    }
}
