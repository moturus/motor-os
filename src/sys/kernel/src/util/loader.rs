use moto_sys::ErrorCode;

use crate::mm::{MappingOptions, PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};

struct Loader<'a> {
    address_space: &'a crate::mm::user::UserAddressSpace,
}

impl<'a> elfloader::ElfLoader for Loader<'a> {
    fn allocate(
        &mut self,
        load_headers: elfloader::LoadableHeaders,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        for header in load_headers {
            let vaddr_start = crate::mm::align_down(header.virtual_addr(), PAGE_SIZE_SMALL);
            let vaddr_end =
                crate::mm::align_up(header.virtual_addr() + header.mem_size(), PAGE_SIZE_SMALL);

            // log::debug!(
            //     "ElfLoader: Allocate:: ELF: 0x{:x} sz 0x{:x} => MEM: 0x{:x} sz 0x:{:x}",
            //     header.virtual_addr(),
            //     header.mem_size(),
            //     vaddr_start,
            //     vaddr_end - vaddr_start
            // );

            let mut mapping_options = MappingOptions::USER_ACCESSIBLE;
            if header.flags().is_read() {
                mapping_options |= MappingOptions::READABLE;
            }
            if header.flags().is_write() {
                mapping_options |= MappingOptions::WRITABLE;
            }

            let num_pages = (vaddr_end - vaddr_start) >> PAGE_SIZE_SMALL_LOG2;
            self.address_space
                .allocate_user_fixed(vaddr_start, num_pages, mapping_options)
                .map_err(|_| elfloader::ElfLoaderErr::OutOfMemory)?;
        }
        Ok(())
    }

    fn load(
        &mut self,
        _flags: elfloader::Flags,
        base: elfloader::VAddr,
        region: &[u8],
    ) -> Result<(), elfloader::ElfLoaderErr> {
        self.address_space.copy_to_user(region, base).unwrap();
        Ok(())
    }

    fn relocate(
        &mut self,
        entry: elfloader::RelocationEntry,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        use elfloader::arch::x86_64::RelocationTypes::*;
        use elfloader::RelocationType::x86_64;

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                panic!("elf loader: relocation not supported");
            }
            x86_64(R_AMD64_NONE) => Ok(()),
            _ => {
                panic!("elf loader: unrecognized entry type: {:#?}", entry.rtype);
            }
        }
    }
}

// Loads the elf file at zero offset; returns the entry point address.
pub fn load_elf(
    elf_bytes: &[u8],
    address_space: &crate::mm::user::UserAddressSpace,
) -> Result<u64, ErrorCode> {
    let elf_binary = elfloader::ElfBinary::new(elf_bytes).map_err(|_| -> ErrorCode {
        log::error!("ELF parsing failed.");
        moto_rt::E_INVALID_ARGUMENT
    })?;

    if elf_binary.get_arch() != elfloader::Machine::X86_64 {
        log::error!("The ELF binary not X86_64.");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    if elf_binary.interpreter().is_some() {
        log::error!("The ELF binary has a dynamic interpreter.");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let mut elf_loader = Loader { address_space };
    elf_binary.load(&mut elf_loader).map_err(|_| -> ErrorCode {
        log::error!("Could not load the kernel ELF binary.");
        moto_rt::E_INVALID_ARGUMENT
    })?;

    Ok(elf_binary.entry_point())
}
